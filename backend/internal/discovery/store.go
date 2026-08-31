package discovery

import (
	"context"
	"errors"
	"fmt"
	"time"

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
	// VulnerabilitySummary aggregates the latest result per host:port —
	// not every historical row — into fleet-wide counts per vulnerability
	// tag, for the crypto/TLS posture dashboard.
	VulnerabilitySummary(ctx context.Context) (VulnerabilitySummary, error)

	// MarkInterruptedScansFailed marks every scan left in a non-terminal
	// status as failed with reason — called once at startup, since no
	// goroutine survives a process restart to finish them (see
	// service.go's RecoverInterruptedScans).
	MarkInterruptedScansFailed(ctx context.Context, reason string) error

	CreateSchedule(ctx context.Context, s Schedule) (Schedule, error)
	UpdateSchedule(ctx context.Context, s Schedule) error
	// RecordScheduleRun updates only the bookkeeping columns the
	// scheduler itself owns (last_run_at/last_scan_id/next_run_at) — see
	// Service.fireSchedule's own comment on why a full-row UpdateSchedule
	// there would risk clobbering a concurrent admin edit to the
	// schedule's actual configuration (name/targets/enabled/etc).
	RecordScheduleRun(ctx context.Context, id string, lastRunAt, nextRunAt time.Time, lastScanID string) error
	GetSchedule(ctx context.Context, id string) (Schedule, error)
	ListSchedules(ctx context.Context) ([]Schedule, error)
	DeleteSchedule(ctx context.Context, id string) error
	// DueSchedules returns every enabled schedule whose next_run_at has
	// passed as of asOf.
	DueSchedules(ctx context.Context, asOf time.Time) ([]Schedule, error)
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

// resultColumns is shared by AddResult/ListResults/ListMismatches so the
// SELECT list and scanResult's Scan() order can't silently drift apart.
const resultColumns = `
	id, scan_id, host, port, reachable, coalesce(tls_version, ''), coalesce(common_name, ''),
	coalesce(sans, '{}'), coalesce(issuer, ''), coalesce(serial_number, ''), coalesce(fingerprint_sha256, ''),
	coalesce(signature_algorithm, ''), coalesce(cipher_suite, ''), coalesce(vulnerabilities, '{}'),
	not_before, not_after, match_status, coalesce(matched_certificate_id::text, ''), coalesce(error, ''), discovered_at
`

func (s *PostgresStore) AddResult(ctx context.Context, r Result) (Result, error) {
	// vulnerabilities is NOT NULL — unlike sans (nullable), a probe with no
	// findings must store an empty array, not SQL NULL, so nullableStringSlice
	// (which turns "empty" into nil/NULL) doesn't apply here.
	vulnerabilities := r.Vulnerabilities
	if vulnerabilities == nil {
		vulnerabilities = []string{}
	}
	row := s.pool.QueryRow(ctx, `
		INSERT INTO discovery_result
			(scan_id, host, port, reachable, tls_version, common_name, sans, issuer, serial_number,
			 fingerprint_sha256, signature_algorithm, cipher_suite, vulnerabilities,
			 not_before, not_after, match_status, matched_certificate_id, error)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
		RETURNING `+resultColumns, r.ScanID, r.Host, r.Port, r.Reachable, nullableString(r.TLSVersion), nullableString(r.CommonName), r.SANs,
		nullableString(r.Issuer), nullableString(r.SerialNumber), nullableString(r.FingerprintSHA256),
		nullableString(r.SignatureAlgorithm), nullableString(r.CipherSuite), vulnerabilities,
		r.NotBefore, r.NotAfter, r.MatchStatus, nullableString(r.MatchedCertID), nullableString(r.Error))
	return scanResult(row)
}

func (s *PostgresStore) ListResults(ctx context.Context, scanID string) ([]Result, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+resultColumns+`
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
		SELECT `+resultColumns+`
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

// VulnerabilitySummary aggregates over the latest discovery_result row per
// host:port (DISTINCT ON), not every historical row — otherwise a host
// rescanned repeatedly (especially once schedules exist) would inflate the
// counts every time it's probed again, rather than reflecting its current
// state.
func (s *PostgresStore) VulnerabilitySummary(ctx context.Context) (VulnerabilitySummary, error) {
	var summary VulnerabilitySummary
	err := s.pool.QueryRow(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (host, port) vulnerabilities
			FROM discovery_result
			ORDER BY host, port, discovered_at DESC
		)
		SELECT
			count(*),
			count(*) FILTER (WHERE 'weak_tls_version' = ANY(vulnerabilities)),
			count(*) FILTER (WHERE 'weak_signature_algorithm' = ANY(vulnerabilities)),
			count(*) FILTER (WHERE 'expired_certificate' = ANY(vulnerabilities))
		FROM latest
	`).Scan(&summary.TotalEndpoints, &summary.WeakTLSVersion, &summary.WeakSignatureAlgorithm, &summary.ExpiredCertificate)
	if err != nil {
		return VulnerabilitySummary{}, fmt.Errorf("discovery: vulnerability summary: %w", err)
	}
	return summary, nil
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
		&r.SerialNumber, &r.FingerprintSHA256, &r.SignatureAlgorithm, &r.CipherSuite, &r.Vulnerabilities,
		&r.NotBefore, &r.NotAfter, &r.MatchStatus, &r.MatchedCertID, &r.Error, &r.DiscoveredAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Result{}, ErrNotFound
		}
		return Result{}, fmt.Errorf("discovery: scan result: %w", err)
	}
	return r, nil
}

// scheduleColumns is shared by every query returning a full Schedule row.
const scheduleColumns = `
	id, name, description, targets, ports, timeout_ms, concurrency, interval_minutes, enabled,
	coalesce(created_by::text, ''), last_run_at, coalesce(last_scan_id::text, ''), next_run_at, created_at, updated_at
`

func (s *PostgresStore) CreateSchedule(ctx context.Context, sch Schedule) (Schedule, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO discovery_schedule
			(name, description, targets, ports, timeout_ms, concurrency, interval_minutes, enabled, created_by, next_run_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING `+scheduleColumns, sch.Name, sch.Description, sch.Targets, sch.Ports, sch.TimeoutMS, sch.Concurrency,
		sch.IntervalMinutes, sch.Enabled, nullableString(sch.CreatedBy), sch.NextRunAt)
	return scanSchedule(row)
}

func (s *PostgresStore) UpdateSchedule(ctx context.Context, sch Schedule) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE discovery_schedule SET
			name = $2, description = $3, targets = $4, ports = $5, timeout_ms = $6, concurrency = $7,
			interval_minutes = $8, enabled = $9, last_run_at = $10, last_scan_id = $11, next_run_at = $12, updated_at = now()
		WHERE id = $1
	`, sch.ID, sch.Name, sch.Description, sch.Targets, sch.Ports, sch.TimeoutMS, sch.Concurrency,
		sch.IntervalMinutes, sch.Enabled, sch.LastRunAt, nullableString(sch.LastScanID), sch.NextRunAt)
	if err != nil {
		return fmt.Errorf("discovery: update schedule: %w", err)
	}
	return nil
}

func (s *PostgresStore) RecordScheduleRun(ctx context.Context, id string, lastRunAt, nextRunAt time.Time, lastScanID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE discovery_schedule SET last_run_at = $2, last_scan_id = $3, next_run_at = $4, updated_at = now()
		WHERE id = $1
	`, id, lastRunAt, nullableString(lastScanID), nextRunAt)
	if err != nil {
		return fmt.Errorf("discovery: record schedule run: %w", err)
	}
	return nil
}

func (s *PostgresStore) GetSchedule(ctx context.Context, id string) (Schedule, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+scheduleColumns+` FROM discovery_schedule WHERE id = $1`, id)
	return scanSchedule(row)
}

func (s *PostgresStore) ListSchedules(ctx context.Context) ([]Schedule, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+scheduleColumns+` FROM discovery_schedule ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("discovery: list schedules: %w", err)
	}
	defer rows.Close()

	out := []Schedule{}
	for rows.Next() {
		sch, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sch)
	}
	return out, rows.Err()
}

func (s *PostgresStore) DeleteSchedule(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM discovery_schedule WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("discovery: delete schedule: %w", err)
	}
	return nil
}

func (s *PostgresStore) DueSchedules(ctx context.Context, asOf time.Time) ([]Schedule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+scheduleColumns+`
		FROM discovery_schedule WHERE enabled AND next_run_at <= $1
		ORDER BY next_run_at ASC
	`, asOf)
	if err != nil {
		return nil, fmt.Errorf("discovery: due schedules: %w", err)
	}
	defer rows.Close()

	out := []Schedule{}
	for rows.Next() {
		sch, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sch)
	}
	return out, rows.Err()
}

func scanSchedule(row rowScanner) (Schedule, error) {
	var sch Schedule
	err := row.Scan(&sch.ID, &sch.Name, &sch.Description, &sch.Targets, &sch.Ports, &sch.TimeoutMS, &sch.Concurrency,
		&sch.IntervalMinutes, &sch.Enabled, &sch.CreatedBy, &sch.LastRunAt, &sch.LastScanID, &sch.NextRunAt,
		&sch.CreatedAt, &sch.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Schedule{}, ErrNotFound
		}
		return Schedule{}, fmt.Errorf("discovery: scan schedule: %w", err)
	}
	return sch, nil
}
