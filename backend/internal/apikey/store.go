// Package apikey verifies machine credentials for the "API-only" role
// described in docs/plan.html section 08. Keys are stored as a salted
// hash, never in plaintext, and each carries its own scope list — a
// service account's access is whatever was granted when the key was
// created, independent of any role.
package apikey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrInvalid = errors.New("apikey: invalid or unknown key")

type Verified struct {
	UserID string
	Scopes []string
}

type Store interface {
	// Create mints a new key for userID and returns the raw secret — this
	// is the only time it is ever available; only its hash is stored.
	Create(ctx context.Context, userID, name string, scopes []string) (rawKey string, err error)
	Verify(ctx context.Context, rawKey string) (Verified, error)
}

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) Create(ctx context.Context, userID, name string, scopes []string) (string, error) {
	raw, err := randomKey()
	if err != nil {
		return "", err
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO api_key (user_id, name, key_hash, scopes)
		VALUES ($1, $2, $3, $4)
	`, userID, name, hash(raw), scopes)
	if err != nil {
		return "", fmt.Errorf("apikey: create: %w", err)
	}
	return raw, nil
}

func (s *PostgresStore) Verify(ctx context.Context, rawKey string) (Verified, error) {
	var v Verified
	err := s.pool.QueryRow(ctx, `
		UPDATE api_key SET last_used_at = now()
		WHERE key_hash = $1
		RETURNING user_id, scopes
	`, hash(rawKey)).Scan(&v.UserID, &v.Scopes)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Verified{}, ErrInvalid
		}
		return Verified{}, fmt.Errorf("apikey: verify: %w", err)
	}
	return v, nil
}

func randomKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("apikey: generate: %w", err)
	}
	return "sslmgr_" + hex.EncodeToString(buf), nil
}

func hash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
