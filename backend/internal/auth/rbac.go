package auth

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/yilmazerhan/ssl-manager/backend/internal/apikey"
	"github.com/yilmazerhan/ssl-manager/backend/internal/user"
)

type Scope string

const (
	ScopeCertsRead   Scope = "certs:read"
	ScopeCertsExport Scope = "certs:export"
	ScopeCertsIssue  Scope = "certs:issue"
	ScopeCertsAdmin  Scope = "certs:admin"
)

// RoleScopes is the fixed role -> scope mapping from docs/plan.html section
// 08. API-only identities don't go through this at all — their scopes are
// whatever was granted to that specific key (see apikey.Store).
func RoleScopes(role user.Role) []string {
	switch role {
	case user.RoleViewer:
		return []string{string(ScopeCertsRead)}
	case user.RoleCertManager:
		return []string{string(ScopeCertsRead), string(ScopeCertsExport), string(ScopeCertsIssue)}
	case user.RoleAdmin:
		return []string{string(ScopeCertsRead), string(ScopeCertsExport), string(ScopeCertsIssue), string(ScopeCertsAdmin)}
	default:
		return nil
	}
}

// Identity is what every authenticated request carries in its context,
// regardless of whether it came from a browser session or an API key.
type Identity struct {
	UserID string
	Email  string
	Role   user.Role
	Team   string
	Scopes []string
}

func (i Identity) HasScope(scope Scope) bool {
	return slices.Contains(i.Scopes, string(scope))
}

// CanAccessTeam reports whether this identity may act on a resource owned
// by team. Admins and API-only keys (already scoped at creation time) are
// not team-restricted; everyone else only touches their own team's
// certificates, per docs/plan.html section 09 ("least privilege by
// default").
func (i Identity) CanAccessTeam(team string) bool {
	return i.Role == user.RoleAdmin || i.Role == user.RoleAPIOnly || i.Team == team
}

type contextKey struct{}

func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

func IdentityFromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(contextKey{}).(Identity)
	return id, ok
}

// Middleware authenticates every request via either a session JWT or an
// API key, both passed the same way: "Authorization: Bearer <token>".
func Middleware(sessions *SessionManager, users user.Store, keys apikey.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := bearerToken(r)
			if raw == "" {
				unauthorized(w, "missing bearer token")
				return
			}

			if claims, err := sessions.Parse(raw); err == nil {
				next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), Identity{
					UserID: claims.Subject,
					Email:  claims.Email,
					Role:   user.Role(claims.Role),
					Team:   claims.Team,
					Scopes: RoleScopes(user.Role(claims.Role)),
				})))
				return
			}

			if strings.HasPrefix(raw, "sslmgr_") {
				verified, err := keys.Verify(r.Context(), raw)
				if err != nil {
					unauthorized(w, "invalid API key")
					return
				}
				u, err := users.GetByID(r.Context(), verified.UserID)
				if err != nil {
					unauthorized(w, "invalid API key")
					return
				}
				next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), Identity{
					UserID: u.ID,
					Email:  u.Email,
					Role:   u.Role,
					Team:   u.Team,
					Scopes: verified.Scopes,
				})))
				return
			}

			unauthorized(w, "invalid session token")
		})
	}
}

// RequireScope must run after Middleware. It's a 403, not a 401 — the
// caller is authenticated, just not permitted.
func RequireScope(scope Scope) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, ok := IdentityFromContext(r.Context())
			if !ok || !identity.HasScope(scope) {
				http.Error(w, `{"error":"insufficient scope"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimPrefix(h, prefix)
}

func unauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"error":"` + message + `"}`))
}
