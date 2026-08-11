// Package auth issues and verifies this backend's own session tokens,
// drives the OIDC login flow that creates them, and enforces the
// role/scope model from docs/plan.html section 08.
package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/yilmazerhan/ssl-manager/backend/internal/user"
)

type Claims struct {
	jwt.RegisteredClaims
	Email string `json:"email"`
	Role  string `json:"role"`
	Team  string `json:"team"`
}

// SessionManager issues the JWT a browser holds after completing OIDC
// login. It is deliberately not the OIDC provider's own ID token — this
// token is ours, scoped to what this app needs, and short-lived.
type SessionManager struct {
	secret []byte
	ttl    time.Duration
}

func NewSessionManager(secret string, ttl time.Duration) *SessionManager {
	if ttl == 0 {
		ttl = 12 * time.Hour
	}
	return &SessionManager{secret: []byte(secret), ttl: ttl}
}

func (m *SessionManager) Issue(u user.User) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   u.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.ttl)),
		},
		Email: u.Email,
		Role:  string(u.Role),
		Team:  u.Team,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(m.secret)
	if err != nil {
		return "", fmt.Errorf("auth: sign session token: %w", err)
	}
	return signed, nil
}

func (m *SessionManager) Parse(raw string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (interface{}, error) {
		return m.secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return nil, fmt.Errorf("auth: parse session token: %w", err)
	}
	return claims, nil
}
