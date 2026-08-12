// Package user holds the application's own account records — one per
// person who has signed in via OIDC or a local username/password, plus
// API-only service accounts. It is deliberately separate from whatever
// identity an OIDC provider manages: this package only tracks the
// role/team mapping this app needs for RBAC, plus local-login state for
// accounts that don't have an OIDC identity at all.
package user

import "time"

type Role string

const (
	RoleViewer      Role = "viewer"
	RoleCertManager Role = "cert_manager"
	RoleAdmin       Role = "admin"
	RoleAPIOnly     Role = "api_only"
)

type User struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	OIDCSubject string `json:"oidc_subject,omitempty"`

	// Username/PasswordHash are set only for accounts that can log in with
	// a local password rather than (or in addition to) OIDC. PasswordHash
	// is never serialized — it must never leave this process, not even to
	// an admin-only endpoint.
	Username     string `json:"username,omitempty"`
	PasswordHash string `json:"-"`
	// MustChangePassword forces a password change before anything else is
	// allowed — set whenever a password was assigned to the account rather
	// than chosen by the person using it (the seeded default admin account
	// above all).
	MustChangePassword bool `json:"must_change_password,omitempty"`
	// FailedLoginAttempts/LockedUntil implement a simple lockout after
	// repeated bad passwords, so a local account can't be brute-forced.
	FailedLoginAttempts int        `json:"-"`
	LockedUntil         *time.Time `json:"-"`

	Role      Role      `json:"role"`
	Team      string    `json:"team,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}
