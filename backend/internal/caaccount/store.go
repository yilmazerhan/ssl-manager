// Package caaccount persists the one durable fact an ACME account has once
// it's registered: its account URL (the "kid" every subsequent request must
// be signed with). The account's private key lives in Vault
// (secrets.SecretStore), never here.
package caaccount

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("caaccount: not found")

type Account struct {
	Provider     string
	Environment  string
	AccountRef   string
	DirectoryURL string
}

type Store interface {
	Get(ctx context.Context, provider, environment string) (Account, error)
	Upsert(ctx context.Context, a Account) error
}

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) Get(ctx context.Context, provider, environment string) (Account, error) {
	var a Account
	err := s.pool.QueryRow(ctx, `
		SELECT provider, environment, account_ref, coalesce(directory_url, '')
		FROM ca_account WHERE provider = $1 AND environment = $2
	`, provider, environment).Scan(&a.Provider, &a.Environment, &a.AccountRef, &a.DirectoryURL)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Account{}, ErrNotFound
		}
		return Account{}, fmt.Errorf("caaccount: get: %w", err)
	}
	return a, nil
}

func (s *PostgresStore) Upsert(ctx context.Context, a Account) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ca_account (provider, environment, account_ref, directory_url)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (provider, environment) DO UPDATE
			SET account_ref = EXCLUDED.account_ref, directory_url = EXCLUDED.directory_url
	`, a.Provider, a.Environment, a.AccountRef, a.DirectoryURL)
	if err != nil {
		return fmt.Errorf("caaccount: upsert: %w", err)
	}
	return nil
}
