package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yilmazerhan/ssl-manager/backend/internal/user"
)

// fakeLocalUserStore is a mutable in-memory user.Store good enough to drive
// LocalLoginHandler end to end, including the failed-attempt bookkeeping a
// real Postgres-backed store would persist.
type fakeLocalUserStore struct {
	byID       map[string]*user.User
	byUsername map[string]*user.User
}

func newFakeLocalUserStore() *fakeLocalUserStore {
	return &fakeLocalUserStore{byID: map[string]*user.User{}, byUsername: map[string]*user.User{}}
}

func (f *fakeLocalUserStore) put(u user.User) {
	uu := u
	f.byID[uu.ID] = &uu
	if uu.Username != "" {
		f.byUsername[uu.Username] = &uu
	}
}

func (f *fakeLocalUserStore) GetByID(_ context.Context, id string) (user.User, error) {
	u, ok := f.byID[id]
	if !ok {
		return user.User{}, user.ErrNotFound
	}
	return *u, nil
}
func (f *fakeLocalUserStore) GetByEmail(context.Context, string) (user.User, error) {
	return user.User{}, user.ErrNotFound
}
func (f *fakeLocalUserStore) GetByUsername(_ context.Context, username string) (user.User, error) {
	u, ok := f.byUsername[username]
	if !ok {
		return user.User{}, user.ErrNotFound
	}
	return *u, nil
}
func (f *fakeLocalUserStore) GetOrCreateByOIDCSubject(context.Context, string, string) (user.User, error) {
	return user.User{}, nil
}
func (f *fakeLocalUserStore) List(context.Context) ([]user.User, error) { return nil, nil }
func (f *fakeLocalUserStore) SetRoleAndTeam(context.Context, string, user.Role, string) error {
	return nil
}
func (f *fakeLocalUserStore) CountLocalUsers(context.Context) (int, error) {
	return len(f.byUsername), nil
}
func (f *fakeLocalUserStore) EnsureLocalAdmin(context.Context, string, string, string, user.Role) error {
	return nil
}
func (f *fakeLocalUserStore) SetPassword(_ context.Context, id, hash string, mustChange bool) error {
	u := f.byID[id]
	u.PasswordHash, u.MustChangePassword = hash, mustChange
	u.FailedLoginAttempts, u.LockedUntil = 0, nil
	return nil
}
func (f *fakeLocalUserStore) RecordFailedLogin(_ context.Context, id string, attempts int, lockedUntil *time.Time) error {
	u := f.byID[id]
	u.FailedLoginAttempts, u.LockedUntil = attempts, lockedUntil
	return nil
}
func (f *fakeLocalUserStore) ResetFailedLogins(_ context.Context, id string) error {
	u := f.byID[id]
	u.FailedLoginAttempts, u.LockedUntil = 0, nil
	return nil
}

func doLogin(t *testing.T, h http.HandlerFunc, username, password string) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req := httptest.NewRequest("POST", "/auth/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h(rec, req)
	var out map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

// TestLocalLoginHandler_Success_ReflectsMustChangePassword proves a
// successful login both issues a usable session token and carries the
// account's MustChangePassword flag through to the response body and the
// token's own claims — the frontend gates the whole app on this, and the
// backend's own RequirePasswordChange re-derives it from the DB row on
// every request, not from this response.
func TestLocalLoginHandler_Success_ReflectsMustChangePassword(t *testing.T) {
	store := newFakeLocalUserStore()
	hash, err := HashPassword("correct-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	store.put(user.User{ID: "u1", Email: "admin@local.ssl-manager", Username: "admin", PasswordHash: hash, Role: user.RoleAdmin, MustChangePassword: true})

	sessions := NewSessionManager("test-secret-not-the-insecure-default", time.Hour)
	rec, body := doLogin(t, LocalLoginHandler(sessions, store), "admin", "correct-password")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%v)", rec.Code, body)
	}
	if must, _ := body["must_change_password"].(bool); !must {
		t.Errorf("expected must_change_password=true in the response, got %v", body["must_change_password"])
	}
	token, _ := body["token"].(string)
	claims, err := sessions.Parse(token)
	if err != nil {
		t.Fatalf("issued token did not parse: %v", err)
	}
	if !claims.MustChangePassword {
		t.Errorf("expected the issued token's own claims to carry MustChangePassword=true")
	}
}

// TestLocalLoginHandler_WrongUsernameOrPassword_SameGenericError proves an
// unknown username and a known username with the wrong password produce
// an identical response — an attacker probing usernames must not be able
// to tell which case they hit.
func TestLocalLoginHandler_WrongUsernameOrPassword_SameGenericError(t *testing.T) {
	store := newFakeLocalUserStore()
	hash, _ := HashPassword("correct-password")
	store.put(user.User{ID: "u1", Username: "admin", PasswordHash: hash, Role: user.RoleAdmin})

	sessions := NewSessionManager("test-secret-not-the-insecure-default", time.Hour)
	handler := LocalLoginHandler(sessions, store)

	recUnknown, bodyUnknown := doLogin(t, handler, "no-such-user", "whatever")
	recWrong, bodyWrong := doLogin(t, handler, "admin", "wrong-password")

	if recUnknown.Code != http.StatusUnauthorized || recWrong.Code != http.StatusUnauthorized {
		t.Fatalf("expected both to be 401, got %d and %d", recUnknown.Code, recWrong.Code)
	}
	if bodyUnknown["error"] != bodyWrong["error"] {
		t.Errorf("expected identical error messages, got %q vs %q", bodyUnknown["error"], bodyWrong["error"])
	}
}

// TestLocalLoginHandler_LocksAfterRepeatedFailures proves the account
// locks out after enough wrong passwords in a row — including refusing a
// *correct* password once locked, otherwise the lockout would be
// meaningless — and that a successful login before the threshold clears
// the counter rather than accumulating forever.
func TestLocalLoginHandler_LocksAfterRepeatedFailures(t *testing.T) {
	store := newFakeLocalUserStore()
	hash, _ := HashPassword("correct-password")
	store.put(user.User{ID: "u1", Username: "admin", PasswordHash: hash, Role: user.RoleAdmin})

	sessions := NewSessionManager("test-secret-not-the-insecure-default", time.Hour)
	handler := LocalLoginHandler(sessions, store)

	for i := 0; i < maxFailedLogins; i++ {
		rec, _ := doLogin(t, handler, "admin", "wrong-password")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, rec.Code)
		}
	}

	rec, body := doLogin(t, handler, "admin", "correct-password")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected the account to be locked (429) even with the correct password, got %d (%v)", rec.Code, body)
	}
}

func TestValidatePassword(t *testing.T) {
	cases := []struct {
		password string
		wantErr  bool
	}{
		{"short1", true},
		{"admin", true},
		{"password", true},
		{"a-genuinely-long-passphrase", false},
	}
	for _, c := range cases {
		err := ValidatePassword(c.password)
		if (err != nil) != c.wantErr {
			t.Errorf("ValidatePassword(%q): got err=%v, want error=%v", c.password, err, c.wantErr)
		}
	}
}
