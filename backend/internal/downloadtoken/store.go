// Package downloadtoken implements the short-lived, single-use tokens
// docs/plan.html requires for exporting certificate key material (sections
// 07 and 09): a client asks for one after re-confirming in the UI, then
// redeems it exactly once, within a short window, for exactly one
// certificate.
package downloadtoken

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrInvalid = errors.New("downloadtoken: invalid, expired, or already-used token")
)

const TTL = 5 * time.Minute

type Redeemed struct {
	CertificateID string
	UserID        string
}

type Store interface {
	Issue(ctx context.Context, certificateID, userID string) (rawToken string, expiresAt time.Time, err error)
	// Redeem atomically marks the token used; a token can never be
	// redeemed twice, even under concurrent requests.
	Redeem(ctx context.Context, rawToken string) (Redeemed, error)
}

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) Issue(ctx context.Context, certificateID, userID string) (string, time.Time, error) {
	raw, err := randomToken()
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := time.Now().Add(TTL)

	_, err = s.pool.Exec(ctx, `
		INSERT INTO download_token (certificate_id, user_id, token_hash, expires_at)
		VALUES ($1, $2, $3, $4)
	`, certificateID, userID, hash(raw), expiresAt)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("downloadtoken: issue: %w", err)
	}
	return raw, expiresAt, nil
}

func (s *PostgresStore) Redeem(ctx context.Context, rawToken string) (Redeemed, error) {
	var r Redeemed
	err := s.pool.QueryRow(ctx, `
		UPDATE download_token
		SET used_at = now()
		WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
		RETURNING certificate_id, user_id
	`, hash(rawToken)).Scan(&r.CertificateID, &r.UserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Redeemed{}, ErrInvalid
		}
		return Redeemed{}, fmt.Errorf("downloadtoken: redeem: %w", err)
	}
	return r, nil
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("downloadtoken: generate: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func hash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
