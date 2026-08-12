package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/yilmazerhan/ssl-manager/backend/internal/user"
)

const (
	// maxFailedLogins is how many wrong passwords in a row lock a local
	// account out, so a password can't be brute-forced by just retrying
	// forever.
	maxFailedLogins = 5
	lockoutDuration = 15 * time.Minute
	// bcryptCost matches bcrypt's own recommended default — strong enough
	// to be expensive to brute-force offline, cheap enough not to make
	// every login noticeably slow.
	bcryptCost = bcrypt.DefaultCost
	// MinPasswordLength is enforced on every password this app ever
	// stores a hash of (a changed password, or an admin-assigned one) —
	// short passwords are the one property purely mechanical validation
	// can actually catch, unlike overall "strength".
	MinPasswordLength = 8
)

// ValidatePassword rejects a new password too short or too obviously
// guessable to be worth hashing and storing. It does not attempt anything
// like a real strength estimator — that's a UX feature, not a security
// boundary this backend can enforce meaningfully server-side.
func ValidatePassword(pw string) error {
	if len(pw) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	for _, bad := range []string{"admin", "password", "12345678", "letmein", "qwertyui"} {
		if pw == bad {
			return fmt.Errorf("that password is too common to be secure — choose another one")
		}
	}
	return nil
}

// HashPassword and VerifyPassword wrap bcrypt so the rest of this package
// (and callers in internal/api) never reach for golang.org/x/crypto/bcrypt
// directly, and never risk picking a weaker cost by accident.
func HashPassword(pw string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("auth: hash password: %w", err)
	}
	return string(hash), nil
}

func VerifyPassword(hash, pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

// dummyPasswordHash is compared against on every login attempt for a
// username that doesn't exist, so a request for an unknown username takes
// roughly the same time as one for a real username with a wrong password
// — the response body is already identical either way (see
// genericInvalidCredentials), this just narrows the remaining timing gap.
var dummyPasswordHash, _ = HashPassword("not-a-real-password-just-for-timing")

// LocalLoginHandler authenticates a username+password pair against the
// bcrypt hash stored on the account, issuing the same kind of session
// token OIDC login and dev-login already do. Unlike DevLoginHandler, this
// is registered unconditionally: a password is only as strong as the
// password itself, which is exactly why every account that goes through
// here (starting with the seeded default admin account, see cmd/api's
// startup seeding) carries MustChangePassword until a real password is
// chosen, and why repeated failures lock the account out below.
func LocalLoginHandler(sessions *SessionManager, users user.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
			writeAuthError(w, http.StatusBadRequest, "username and password are required")
			return
		}

		u, err := users.GetByUsername(r.Context(), req.Username)
		if err != nil || u.PasswordHash == "" {
			// Same work, same response, whether the username doesn't exist
			// or exists but has no local password (OIDC-only account) — an
			// attacker learns nothing about which case it was.
			bcrypt.CompareHashAndPassword([]byte(dummyPasswordHash), []byte(req.Password))
			genericInvalidCredentials(w)
			return
		}

		if u.LockedUntil != nil && time.Now().Before(*u.LockedUntil) {
			writeAuthError(w, http.StatusTooManyRequests, "too many failed attempts — try again later")
			return
		}

		if !VerifyPassword(u.PasswordHash, req.Password) {
			attempts := u.FailedLoginAttempts + 1
			var lockedUntil *time.Time
			if attempts >= maxFailedLogins {
				t := time.Now().Add(lockoutDuration)
				lockedUntil = &t
			}
			_ = users.RecordFailedLogin(r.Context(), u.ID, attempts, lockedUntil)
			genericInvalidCredentials(w)
			return
		}

		_ = users.ResetFailedLogins(r.Context(), u.ID)
		token, err := sessions.Issue(u)
		if err != nil {
			writeAuthError(w, http.StatusInternalServerError, "could not issue session")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"token":                token,
			"must_change_password": u.MustChangePassword,
		})
	}
}

func genericInvalidCredentials(w http.ResponseWriter) {
	writeAuthError(w, http.StatusUnauthorized, "invalid username or password")
}

func writeAuthError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
