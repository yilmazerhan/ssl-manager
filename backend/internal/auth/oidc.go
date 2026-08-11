package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/yilmazerhan/ssl-manager/backend/internal/user"
)

type OIDCConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// FrontendURL is where the browser lands after login, with the new
	// session token appended as a query parameter.
	FrontendURL string
}

// OIDCHandler drives the standard authorization-code flow: Login sends the
// browser to the provider, Callback exchanges the code, verifies the ID
// token's signature and claims, links or creates this app's own user
// record, and issues our session JWT (see session.go) — the OIDC
// provider's tokens are never handed to the frontend.
type OIDCHandler struct {
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
	sessions     *SessionManager
	users        user.Store
	stateSecret  []byte
	frontendURL  string
}

func NewOIDCHandler(ctx context.Context, cfg OIDCConfig, sessions *SessionManager, users user.Store, stateSecret string) (*OIDCHandler, error) {
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("auth: discover OIDC provider %q: %w", cfg.IssuerURL, err)
	}

	return &OIDCHandler{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth2Config: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
		},
		sessions:    sessions,
		users:       users,
		stateSecret: []byte(stateSecret),
		frontendURL: cfg.FrontendURL,
	}, nil
}

func (h *OIDCHandler) Login(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, h.oauth2Config.AuthCodeURL(h.signState(time.Now())), http.StatusFound)
}

func (h *OIDCHandler) Callback(w http.ResponseWriter, r *http.Request) {
	if err := h.verifyState(r.URL.Query().Get("state")); err != nil {
		http.Error(w, "invalid or expired login attempt, please try again", http.StatusBadRequest)
		return
	}

	oauth2Token, err := h.oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "could not complete login with the identity provider", http.StatusBadGateway)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "identity provider did not return an ID token", http.StatusBadGateway)
		return
	}
	idToken, err := h.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "could not verify the identity provider's token", http.StatusBadGateway)
		return
	}

	var claims struct {
		Email string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil || claims.Email == "" {
		http.Error(w, "identity provider did not return an email address", http.StatusBadGateway)
		return
	}

	u, err := h.users.GetOrCreateByOIDCSubject(r.Context(), idToken.Subject, claims.Email)
	if err != nil {
		http.Error(w, "could not create or load your account", http.StatusInternalServerError)
		return
	}

	sessionToken, err := h.sessions.Issue(u)
	if err != nil {
		http.Error(w, "could not issue a session", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, h.frontendURL+"?token="+url.QueryEscape(sessionToken), http.StatusFound)
}

// signState avoids needing server-side storage for the OAuth2 state
// parameter: it's a timestamp plus an HMAC over that timestamp, so
// Callback can verify it wasn't forged and hasn't expired without
// remembering anything between the two requests.
func (h *OIDCHandler) signState(now time.Time) string {
	ts := strconv.FormatInt(now.Unix(), 10)
	mac := hmac.New(sha256.New, h.stateSecret)
	mac.Write([]byte(ts))
	sig := hex.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(ts)) + "." + sig
}

func (h *OIDCHandler) verifyState(state string) error {
	dot := -1
	for i, c := range state {
		if c == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return fmt.Errorf("malformed state")
	}
	tsBytes, err := base64.RawURLEncoding.DecodeString(state[:dot])
	if err != nil {
		return fmt.Errorf("malformed state: %w", err)
	}

	mac := hmac.New(sha256.New, h.stateSecret)
	mac.Write(tsBytes)
	expected := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(expected), []byte(state[dot+1:])) != 1 {
		return fmt.Errorf("signature mismatch")
	}

	ts, err := strconv.ParseInt(string(tsBytes), 10, 64)
	if err != nil {
		return fmt.Errorf("malformed timestamp: %w", err)
	}
	if time.Since(time.Unix(ts, 0)) > 10*time.Minute {
		return fmt.Errorf("login attempt expired")
	}
	return nil
}

// DevLoginHandler issues a session for any email/role without going
// through an identity provider at all. It exists purely so this app is
// runnable and testable without a real OIDC tenant, and it must only ever
// be registered when the operator has explicitly opted into dev auth (see
// cmd/api/main.go) — never in a real deployment.
func DevLoginHandler(sessions *SessionManager, users user.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email string    `json:"email"`
			Role  user.Role `json:"role"`
			Team  string    `json:"team"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
			http.Error(w, `{"error":"email is required"}`, http.StatusBadRequest)
			return
		}
		if req.Role == "" {
			req.Role = user.RoleViewer
		}

		u, err := users.GetOrCreateByOIDCSubject(r.Context(), "dev:"+req.Email, req.Email)
		if err != nil {
			http.Error(w, `{"error":"could not create account"}`, http.StatusInternalServerError)
			return
		}
		if u.Role != req.Role || u.Team != req.Team {
			if err := users.SetRoleAndTeam(r.Context(), u.ID, req.Role, req.Team); err != nil {
				http.Error(w, `{"error":"could not update account"}`, http.StatusInternalServerError)
				return
			}
			u.Role, u.Team = req.Role, req.Team
		}

		token, err := sessions.Issue(u)
		if err != nil {
			http.Error(w, `{"error":"could not issue session"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": token})
	}
}
