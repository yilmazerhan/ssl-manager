package certificate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store interface {
	Create(ctx context.Context, c Certificate) (Certificate, error)
	Get(ctx context.Context, id string) (Certificate, error)
	List(ctx context.Context, filter Filter) ([]Certificate, error)
	UpdateAfterRenewal(ctx context.Context, id string, notBefore, notAfter time.Time, caReference string) error
	Revoke(ctx context.Context, id string) error
	// DueForRenewal returns every auto-renewing certificate whose expiry is
	// within its own renew_before_days window as of asOf.
	DueForRenewal(ctx context.Context, asOf time.Time) ([]Certificate, error)

	AddVersion(ctx context.Context, v Version) (Version, error)
	Versions(ctx context.Context, certificateID string) ([]Version, error)
	LatestVersion(ctx context.Context, certificateID string) (Version, error)
}

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) Create(ctx context.Context, c Certificate) (Certificate, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO certificate
			(common_name, sans, ca_provider, validation_method, status, not_before, not_after,
			 key_algorithm, key_ref, ca_reference, owning_team, auto_renew, renew_before_days)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING id, common_name, sans, ca_provider, validation_method, status, not_before, not_after,
			key_algorithm, key_ref, coalesce(ca_reference, ''), owning_team, auto_renew, renew_before_days, created_at, updated_at
	`, c.CommonName, c.SANs, c.CAProvider, c.ValidationMethod, c.Status, c.NotBefore, c.NotAfter,
		c.KeyAlgorithm, c.KeyRef, nullableString(c.CAReference), c.OwningTeam, c.AutoRenew, c.RenewBeforeDays)
	return scanCertificate(row)
}

func (s *PostgresStore) Get(ctx context.Context, id string) (Certificate, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, common_name, sans, ca_provider, validation_method, status, not_before, not_after,
			key_algorithm, key_ref, coalesce(ca_reference, ''), owning_team, auto_renew, renew_before_days, created_at, updated_at
		FROM certificate WHERE id = $1
	`, id)
	return scanCertificate(row)
}

func (s *PostgresStore) List(ctx context.Context, filter Filter) ([]Certificate, error) {
	query := `
		SELECT id, common_name, sans, ca_provider, validation_method, status, not_before, not_after,
			key_algorithm, key_ref, coalesce(ca_reference, ''), owning_team, auto_renew, renew_before_days, created_at, updated_at
		FROM certificate WHERE 1=1
	`
	args := []interface{}{}
	if filter.Team != "" {
		args = append(args, filter.Team)
		query += fmt.Sprintf(" AND owning_team = $%d", len(args))
	}
	if filter.Status != "" {
		args = append(args, filter.Status)
		query += fmt.Sprintf(" AND status = $%d", len(args))
	}
	if filter.CAProvider != "" {
		args = append(args, filter.CAProvider)
		query += fmt.Sprintf(" AND ca_provider = $%d", len(args))
	}
	if filter.ExpiringWithinDays > 0 {
		args = append(args, filter.ExpiringWithinDays)
		query += fmt.Sprintf(" AND not_after <= now() + make_interval(days => $%d)", len(args))
	}
	query += " ORDER BY not_after ASC"

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("certificate: list: %w", err)
	}
	defer rows.Close()

	var out []Certificate
	for rows.Next() {
		c, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpdateAfterRenewal(ctx context.Context, id string, notBefore, notAfter time.Time, caReference string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE certificate
		SET not_before = $2, not_after = $3, ca_reference = $4, status = 'active', updated_at = now()
		WHERE id = $1
	`, id, notBefore, notAfter, nullableString(caReference))
	if err != nil {
		return fmt.Errorf("certificate: update after renewal: %w", err)
	}
	return nil
}

func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func (s *PostgresStore) Revoke(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE certificate SET status = 'revoked', updated_at = now() WHERE id = $1
	`, id)
	if err != nil {
		return fmt.Errorf("certificate: revoke: %w", err)
	}
	return nil
}

func (s *PostgresStore) DueForRenewal(ctx context.Context, asOf time.Time) ([]Certificate, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, common_name, sans, ca_provider, validation_method, status, not_before, not_after,
			key_algorithm, key_ref, coalesce(ca_reference, ''), owning_team, auto_renew, renew_before_days, created_at, updated_at
		FROM certificate
		WHERE auto_renew
		  AND status IN ('active', 'expiring')
		  AND not_after <= $1::timestamptz + make_interval(days => renew_before_days)
		ORDER BY not_after ASC
	`, asOf)
	if err != nil {
		return nil, fmt.Errorf("certificate: due for renewal: %w", err)
	}
	defer rows.Close()

	var out []Certificate
	for rows.Next() {
		c, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PostgresStore) AddVersion(ctx context.Context, v Version) (Version, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO certificate_version
			(certificate_id, serial_number, fingerprint_sha256, pem_cert, pem_chain, issued_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, certificate_id, serial_number, fingerprint_sha256, pem_cert, pem_chain, issued_at
	`, v.CertificateID, v.SerialNumber, v.FingerprintSHA256, v.PEMCert, v.PEMChain, v.IssuedAt)
	return scanVersion(row)
}

func (s *PostgresStore) Versions(ctx context.Context, certificateID string) ([]Version, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, certificate_id, serial_number, fingerprint_sha256, pem_cert, pem_chain, issued_at
		FROM certificate_version WHERE certificate_id = $1 ORDER BY issued_at ASC
	`, certificateID)
	if err != nil {
		return nil, fmt.Errorf("certificate: versions: %w", err)
	}
	defer rows.Close()

	var out []Version
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) LatestVersion(ctx context.Context, certificateID string) (Version, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, certificate_id, serial_number, fingerprint_sha256, pem_cert, pem_chain, issued_at
		FROM certificate_version WHERE certificate_id = $1 ORDER BY issued_at DESC LIMIT 1
	`, certificateID)
	return scanVersion(row)
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanCertificate(row rowScanner) (Certificate, error) {
	var c Certificate
	err := row.Scan(&c.ID, &c.CommonName, &c.SANs, &c.CAProvider, &c.ValidationMethod, &c.Status, &c.NotBefore, &c.NotAfter,
		&c.KeyAlgorithm, &c.KeyRef, &c.CAReference, &c.OwningTeam, &c.AutoRenew, &c.RenewBeforeDays, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Certificate{}, ErrNotFound
		}
		return Certificate{}, fmt.Errorf("certificate: scan: %w", err)
	}
	return c, nil
}

func scanVersion(row rowScanner) (Version, error) {
	var v Version
	err := row.Scan(&v.ID, &v.CertificateID, &v.SerialNumber, &v.FingerprintSHA256, &v.PEMCert, &v.PEMChain, &v.IssuedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Version{}, ErrNotFound
		}
		return Version{}, fmt.Errorf("certificate: scan version: %w", err)
	}
	return v, nil
}

var ErrNotFound = fmt.Errorf("certificate: not found")
