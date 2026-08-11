// Package user holds the application's own account records — one per
// person who has signed in via OIDC, plus API-only service accounts. It is
// deliberately separate from whatever identity the OIDC provider manages:
// this package only tracks the role/team mapping this app needs for RBAC.
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
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	OIDCSubject string    `json:"oidc_subject,omitempty"`
	Role        Role      `json:"role"`
	Team        string    `json:"team,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}
