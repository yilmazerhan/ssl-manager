package discovery

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = fmt.Errorf("discovery: not found")

type Store interface {
	CreateScan(ctx context.Context, s Scan) (Scan, error)
	UpdateScan(ctx context.Context, s Scan) error
	GetScan(ctx context.Context, id string) (Scan, error)
	ListScans(ctx context.Context) ([]Scan, error)

	AddResult(ctx context.Context, r Result) (Result, error)
	ListResults(ctx context.Context, scanID string) ([]Result, error)
	// ListMismatches returns the most recent results across every scan
	// whose match_status is "mismatched" or "not_in_inventory" — the
	// reconciliation report: endpoints inventory doesn't know about, and
	// endpoints serving a different certificate than what's on file.
	ListMismatches(ctx context.Context, limit int) ([]Result, error)

	// MarkInterruptedScansFailed marks every scan left in a non-terminal
	// status as failed with reason — called once at startup, since no
	// goroutine survives a process restart to finish them (see
	// service.go's RecoverInterruptedScans).
	MarkInterruptedScansFailed(ctx context.Context, reason string) error
}

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) CreateScan(ctx context.Context, sc Scan) (Scan, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO discovery_scan
			(name, description, targets, ports, timeout_ms, concurrency, status, created_by, total_targets)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, name, description, targets, ports, timeout_ms, concurrency, status, coalesce(created_by::text, ''),
			total_targets, scanned_count, matched_count, mismatch_count, new_count, coalesce(error, ''),
			created_at, started_at, completed_at
	`, sc.Name, sc.Description, sc.Targets, sc.Ports, sc.TimeoutMS, sc.Concurrency, sc.Status, nullableString(sc.CreatedBy), sc.TotalTargets)
	return scanScan(row)
}

func (s *PostgresStore) UpdateScan(ctx context.Context, sc Scan) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE discovery_scan SET
			status = $2, scanned_count = $3, matched_count = $4, mismatch_count = $5,
			new_count = $6, error = $7, started_at = $8, completed_at = $9
		WHERE id = $1
	`, sc.ID, sc.Status, sc.ScannedCount, sc.MatchedCount, sc.MismatchCount, sc.NewCount,
		nullableString(sc.Error), sc.StartedAt, sc.CompletedAt)
	if err != nil {
		return fmt.Errorf("discovery: update scan: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetScan(ctx context.Context, id string) (Scan, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, name, description, targets, ports, timeout_ms, concurrency, status, coalesce(created_by::text, ''),
			total_targets, scanned_count, matched_count, mismatch_count, new_count, coalesce(error, ''),
			created_at, started_at, completed_at
		FROM discovery_scan WHERE id = $1
	`, id)
	return scanScan(row)
}

func (s *PostgresStore) ListScans(ctx context.Context) ([]Scan, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, description, targets, ports, timeout_ms, concurrency, status, coalesce(created_by::text, ''),
			total_targets, scanned_count, matched_count, mismatch_count, new_count, coalesce(error, ''),
			created_at, started_at, completed_at
		FROM discovery_scan ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("discovery: list scans: %w", err)
	}
	defer rows.Close()

	out := []Scan{}
	for rows.Next() {
		sc, err := scanScan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

func (s *PostgresStore) AddResult(ctx context.Context, r Result) (Result, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO discovery_result
			(scan_id, host, port, reachable, tls_version, common_name, sans, issuer, serial_number,
			 fingerprint_sha256, not_before, not_after, match_status, matched_certificate_id, error)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		RETURNING id, scan_id, host, port, reachable, coalesce(tls_version, ''), coalesce(common_name, ''),
			coalesce(sans, '{}'), coalesce(issuer, ''), coalesce(serial_number, ''), coalesce(fingerprint_sha256, ''),
			not_before, not_after, match_status, coalesce(matched_certificate_id::text, ''), coalesce(error, ''), discovered_at
	`, r.ScanID, r.Host, r.Port, r.Reachable, nullableString(r.TLSVersion), nullableString(r.CommonName), r.SANs,
		nullableString(r.Issuer), nullableString(r.SerialNumber), nullableString(r.FingerprintSHA256),
		r.NotBefore, r.NotAfter, r.MatchStatus, nullableString(r.MatchedCertID), nullableString(r.Error))
	return scanResult(row)
}

func (s *PostgresStore) ListResults(ctx context.Context, scanID string) ([]Result, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, scan_id, host, port, reachable, coalesce(tls_version, ''), coalesce(common_name, ''),
			coalesce(sans, '{}'), coalesce(issuer, ''), coalesce(serial_number, ''), coalesce(fingerprint_sha256, ''),
			not_before, not_after, match_status, coalesce(matched_certificate_id::text, ''), coalesce(error, ''), discovered_at
		FROM discovery_result WHERE scan_id = $1 ORDER BY host, port
	`, scanID)
	if err != nil {
		return nil, fmt.Errorf("discovery: list results: %w", err)
	}
	defer rows.Close()

	out := []Result{}
	for rows.Next() {
		r, err := scanResult(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ListMismatches(ctx context.Context, limit int) ([]Result, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, scan_id, host, port, reachable, coalesce(tls_version, ''), coalesce(common_name, ''),
			coalesce(sans, '{}'), coalesce(issuer, ''), coalesce(serial_number, ''), coalesce(fingerprint_sha256, ''),
			not_before, not_after, match_status, coalesce(matched_certificate_id::text, ''), coalesce(error, ''), discovered_at
		FROM discovery_result
		WHERE match_status IN ('mismatched', 'not_in_inventory')
		ORDER BY discovered_at DESC LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("discovery: list mismatches: %w", err)
	}
	defer rows.Close()

	out := []Result{}
	for rows.Next() {
		r, err := scanResult(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *PostgresStore) MarkInterruptedScansFailed(ctx context.Context, reason string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE discovery_scan SET status = 'failed', error = $1, completed_at = now()
		WHERE status IN ('pending', 'running')
	`, reason)
	if err != nil {
		return fmt.Errorf("discovery: mark interrupted scans failed: %w", err)
	}
	return nil
}

func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanScan(row rowScanner) (Scan, error) {
	var sc Scan
	err := row.Scan(&sc.ID, &sc.Name, &sc.Description, &sc.Targets, &sc.Ports, &sc.TimeoutMS, &sc.Concurrency, &sc.Status,
		&sc.CreatedBy, &sc.TotalTargets, &sc.ScannedCount, &sc.MatchedCount, &sc.MismatchCount, &sc.NewCount, &sc.Error,
		&sc.CreatedAt, &sc.StartedAt, &sc.CompletedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Scan{}, ErrNotFound
		}
		return Scan{}, fmt.Errorf("discovery: scan scan: %w", err)
	}
	return sc, nil
}

func scanResult(row rowScanner) (Result, error) {
	var r Result
	err := row.Scan(&r.ID, &r.ScanID, &r.Host, &r.Port, &r.Reachable, &r.TLSVersion, &r.CommonName, &r.SANs, &r.Issuer,
		&r.SerialNumber, &r.FingerprintSHA256, &r.NotBefore, &r.NotAfter, &r.MatchStatus, &r.MatchedCertID, &r.Error, &r.DiscoveredAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Result{}, ErrNotFound
		}
		return Result{}, fmt.Errorf("discovery: scan result: %w", err)
	}
	return r, nil
}
