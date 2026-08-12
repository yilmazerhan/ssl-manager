package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yilmazerhan/ssl-manager/backend/internal/apikey"
	"github.com/yilmazerhan/ssl-manager/backend/internal/user"
)

type fakeUserStore struct {
	users map[string]user.User
}

func (f *fakeUserStore) GetByID(_ context.Context, id string) (user.User, error) {
	u, ok := f.users[id]
	if !ok {
		return user.User{}, user.ErrNotFound
	}
	return u, nil
}
func (f *fakeUserStore) GetByEmail(context.Context, string) (user.User, error) {
	return user.User{}, user.ErrNotFound
}
func (f *fakeUserStore) GetByUsername(context.Context, string) (user.User, error) {
	return user.User{}, user.ErrNotFound
}
func (f *fakeUserStore) GetOrCreateByOIDCSubject(context.Context, string, string) (user.User, error) {
	return user.User{}, nil
}
func (f *fakeUserStore) List(context.Context) ([]user.User, error) { return nil, nil }
func (f *fakeUserStore) SetRoleAndTeam(_ context.Context, id string, role user.Role, team string) error {
	u := f.users[id]
	u.Role, u.Team = role, team
	f.users[id] = u
	return nil
}
func (f *fakeUserStore) CountLocalUsers(context.Context) (int, error) { return 0, nil }
func (f *fakeUserStore) EnsureLocalAdmin(context.Context, string, string, string, user.Role) error {
	return nil
}
func (f *fakeUserStore) SetPassword(_ context.Context, id string, passwordHash string, mustChange bool) error {
	u := f.users[id]
	u.PasswordHash, u.MustChangePassword = passwordHash, mustChange
	f.users[id] = u
	return nil
}
func (f *fakeUserStore) RecordFailedLogin(context.Context, string, int, *time.Time) error { return nil }
func (f *fakeUserStore) ResetFailedLogins(context.Context, string) error                  { return nil }

type noAPIKeys struct{}

func (noAPIKeys) Create(context.Context, string, string, []string) (string, error) { return "", nil }
func (noAPIKeys) Verify(context.Context, string) (apikey.Verified, error) {
	return apikey.Verified{}, apikey.ErrInvalid
}

// TestMiddleware_SessionReflectsCurrentDBState_NotStaleClaims proves a
// session JWT's Role/Team are only as fresh as the DB row they came from
// — not whatever was baked into the token at login. Without this, a
// demoted or reassigned user would keep acting on their old privileges
// until the token naturally expired (up to SessionTTL, 12h by default).
func TestMiddleware_SessionReflectsCurrentDBState_NotStaleClaims(t *testing.T) {
	users := &fakeUserStore{users: map[string]user.User{
		"u1": {ID: "u1", Email: "a@example.com", Role: user.RoleAdmin, Team: "platform"},
	}}
	sessions := NewSessionManager("test-secret-not-the-insecure-default", time.Hour)
	token, err := sessions.Issue(users.users["u1"])
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	var gotIdentity Identity
	mw := Middleware(sessions, users, noAPIKeys{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIdentity, _ = IdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	doRequest := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		return rec
	}

	if rec := doRequest(); rec.Code != http.StatusOK || gotIdentity.Role != user.RoleAdmin {
		t.Fatalf("expected admin role on first use, got status %d role %q", rec.Code, gotIdentity.Role)
	}

	// Demote the same user in the "database" without touching the token
	// at all — it's the same JWT from here on.
	if err := users.SetRoleAndTeam(context.Background(), "u1", user.RoleViewer, "other-team"); err != nil {
		t.Fatalf("SetRoleAndTeam: %v", err)
	}

	rec := doRequest()
	if rec.Code != http.StatusOK {
		t.Fatalf("expected the still-valid token to still authenticate, got %d", rec.Code)
	}
	if gotIdentity.Role != user.RoleViewer {
		t.Errorf("expected the demotion to take effect immediately, got role %q (stale claims would show %q)", gotIdentity.Role, user.RoleAdmin)
	}
	if gotIdentity.Team != "other-team" {
		t.Errorf("expected the team reassignment to take effect immediately, got %q", gotIdentity.Team)
	}
	wantScopes := RoleScopes(user.RoleViewer)
	if len(gotIdentity.Scopes) != len(wantScopes) {
		t.Errorf("expected scopes to be recomputed for the new role, got %v want %v", gotIdentity.Scopes, wantScopes)
	}
}

// TestMiddleware_SessionForDeletedUser_FailsClosed proves that if the user
// a valid, unexpired token was issued for no longer exists in the
// database, the request is rejected rather than falling back to trusting
// the token's own (now orphaned) claims.
func TestMiddleware_SessionForDeletedUser_FailsClosed(t *testing.T) {
	users := &fakeUserStore{users: map[string]user.User{
		"u1": {ID: "u1", Email: "a@example.com", Role: user.RoleAdmin, Team: "platform"},
	}}
	sessions := NewSessionManager("test-secret-not-the-insecure-default", time.Hour)
	token, err := sessions.Issue(users.users["u1"])
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	delete(users.users, "u1") // the account is gone, but the token is still cryptographically valid

	mw := Middleware(sessions, users, noAPIKeys{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a token whose user no longer exists, got %d", rec.Code)
	}
}

// TestRequirePasswordChange_BlocksUntilCleared proves an account with
// MustChangePassword set is locked out of every route wrapped by it —
// re-derived fresh from the DB via Middleware on each request, the same
// as Role/Team above — and that clearing the flag in the "database"
// immediately unblocks the very next request on the same still-valid
// token, with no need to log in again.
func TestRequirePasswordChange_BlocksUntilCleared(t *testing.T) {
	users := &fakeUserStore{users: map[string]user.User{
		"u1": {ID: "u1", Email: "admin@local.ssl-manager", Role: user.RoleAdmin, MustChangePassword: true},
	}}
	sessions := NewSessionManager("test-secret-not-the-insecure-default", time.Hour)
	token, err := sessions.Issue(users.users["u1"])
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	reached := false
	mw := Middleware(sessions, users, noAPIKeys{})(RequirePasswordChange(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})))

	doRequest := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		return rec
	}

	if rec := doRequest(); rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 while must_change_password is set, got %d", rec.Code)
	}
	if reached {
		t.Errorf("expected the wrapped handler to never run while must_change_password is set")
	}

	if err := users.SetPassword(context.Background(), "u1", "some-hash", false); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if rec := doRequest(); rec.Code != http.StatusOK {
		t.Fatalf("expected the same still-valid token to pass through once must_change_password is cleared, got %d", rec.Code)
	}
	if !reached {
		t.Errorf("expected the wrapped handler to run once must_change_password is cleared")
	}
}
