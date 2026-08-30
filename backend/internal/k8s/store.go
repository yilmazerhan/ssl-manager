package k8s

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = fmt.Errorf("k8s: not found")

type Store interface {
	Create(ctx context.Context, t Target) (Target, error)
	Update(ctx context.Context, t Target) error
	Get(ctx context.Context, id string) (Target, error)
	ListByCertificate(ctx context.Context, certificateID string) ([]Target, error)
	Delete(ctx context.Context, id string) error
}

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

const targetColumns = `
	id, certificate_id, name, cluster_url, namespace, secret_name, insecure_skip_verify, enabled,
	last_synced_at, coalesce(last_sync_error, ''), created_at, updated_at
`

func (s *PostgresStore) Create(ctx context.Context, t Target) (Target, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO certificate_k8s_target
			(certificate_id, name, cluster_url, namespace, secret_name, insecure_skip_verify, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING `+targetColumns, t.CertificateID, t.Name, t.ClusterURL, t.Namespace, t.SecretName, t.InsecureSkipVerify, t.Enabled)
	return scanTarget(row)
}

func (s *PostgresStore) Update(ctx context.Context, t Target) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE certificate_k8s_target SET
			name = $2, cluster_url = $3, namespace = $4, secret_name = $5, insecure_skip_verify = $6, enabled = $7,
			last_synced_at = $8, last_sync_error = $9, updated_at = now()
		WHERE id = $1
	`, t.ID, t.Name, t.ClusterURL, t.Namespace, t.SecretName, t.InsecureSkipVerify, t.Enabled, t.LastSyncedAt, t.LastSyncError)
	if err != nil {
		return fmt.Errorf("k8s: update target: %w", err)
	}
	return nil
}

func (s *PostgresStore) Get(ctx context.Context, id string) (Target, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+targetColumns+` FROM certificate_k8s_target WHERE id = $1`, id)
	return scanTarget(row)
}

func (s *PostgresStore) ListByCertificate(ctx context.Context, certificateID string) ([]Target, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+targetColumns+` FROM certificate_k8s_target WHERE certificate_id = $1 ORDER BY created_at ASC
	`, certificateID)
	if err != nil {
		return nil, fmt.Errorf("k8s: list targets: %w", err)
	}
	defer rows.Close()

	out := []Target{}
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *PostgresStore) Delete(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM certificate_k8s_target WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("k8s: delete target: %w", err)
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanTarget(row rowScanner) (Target, error) {
	var t Target
	err := row.Scan(&t.ID, &t.CertificateID, &t.Name, &t.ClusterURL, &t.Namespace, &t.SecretName, &t.InsecureSkipVerify,
		&t.Enabled, &t.LastSyncedAt, &t.LastSyncError, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Target{}, ErrNotFound
		}
		return Target{}, fmt.Errorf("k8s: scan target: %w", err)
	}
	return t, nil
}
