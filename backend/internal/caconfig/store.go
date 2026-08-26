package caconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store persists one JSON settings document per provider. Get/Set are
// deliberately untyped (out/in are any of the *Settings structs above,
// passed by pointer/value respectively) rather than ten near-identical
// GetLetsEncrypt/SetLetsEncrypt-style methods — every caller already knows
// which struct it wants, so the type assertion happens for free at the
// call site via json.Unmarshal/Marshal instead of being duplicated here.
type Store interface {
	// Get reports (false, nil) — not an error — when no settings have ever
	// been saved for provider, so callers can distinguish "never
	// configured" from a real database failure and fall back to a
	// startup-time default (see cmd/api's loadOrSeed helpers).
	Get(ctx context.Context, provider string, out interface{}) (bool, error)
	Set(ctx context.Context, provider string, in interface{}) error
}

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) Get(ctx context.Context, provider string, out interface{}) (bool, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT settings FROM ca_integration_settings WHERE provider = $1`, provider).Scan(&raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("caconfig: get %s: %w", provider, err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return false, fmt.Errorf("caconfig: unmarshal %s: %w", provider, err)
	}
	return true, nil
}

func (s *PostgresStore) Set(ctx context.Context, provider string, in interface{}) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("caconfig: marshal %s: %w", provider, err)
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO ca_integration_settings (provider, settings, updated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (provider) DO UPDATE SET settings = EXCLUDED.settings, updated_at = now()
	`, provider, raw)
	if err != nil {
		return fmt.Errorf("caconfig: set %s: %w", provider, err)
	}
	return nil
}
