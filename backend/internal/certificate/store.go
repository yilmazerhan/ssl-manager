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
	UpdateNotifyEmails(ctx context.Context, id string, emails []string) error
	// DueForRenewal returns every auto-renewing certificate whose expiry is
	// within its own renew_before_days window as of asOf.
	DueForRenewal(ctx context.Context, asOf time.Time) ([]Certificate, error)

	AddVersion(ctx context.Context, v Version) (Version, error)
	Versions(ctx context.Context, certificateID string) ([]Version, error)
	LatestVersion(ctx context.Context, certificateID string) (Version, error)

	// FinalizeNewCertificate and FinalizeRenewal each wrap two writes
	// (create-or-update the certificate row, then insert its new version)
	// in a single transaction — see their own doc comments on why a
	// caller (order.Service.Validate) must never do these as two separate
	// unguarded calls.
	FinalizeNewCertificate(ctx context.Context, c Certificate, v Version) (Certificate, Version, error)
	FinalizeRenewal(ctx context.Context, id string, notBefore, notAfter time.Time, caReference string, v Version) (Version, error)

	// Stats aggregates the inventory for the dashboard/reports — real SQL
	// GROUP BY, not counting an in-memory List() result, so it stays cheap
	// regardless of inventory size. team scopes every breakdown to one
	// team's certificates; empty means every team (the admin view).
	Stats(ctx context.Context, team string) (Stats, error)
}

// Stats is the certificate inventory's shape for reporting: how many, and
// how they break down by the dimensions docs/plan.html section 08 (and the
// RFP's reporting section) call out — status, issuer, and owning team.
type Stats struct {
	Total         int            `json:"total"`
	ByStatus      map[string]int `json:"by_status"`
	ByCAProvider  map[string]int `json:"by_ca_provider"`
	ByTeam        map[string]int `json:"by_team"`
	ExpiringIn7d  int            `json:"expiring_in_7d"`
	ExpiringIn30d int            `json:"expiring_in_30d"`
}

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// certificateColumns is shared by every query that returns a full
// Certificate row (Create/Get/List/DueForRenewal) so the SELECT list and
// scanCertificate's Scan() order can't silently drift apart from each
// other.
const certificateColumns = `
	id, common_name, sans, ca_provider, validation_method, status, not_before, not_after,
	key_algorithm, key_ref, key_exportable, coalesce(ca_reference, ''), owning_team, auto_renew, renew_before_days,
	coalesce(notify_emails, '{}'), coalesce(organization, ''), coalesce(organizational_unit, ''),
	coalesce(country, ''), coalesce(state, ''), coalesce(locality, ''), created_at, updated_at
`

func (s *PostgresStore) Create(ctx context.Context, c Certificate) (Certificate, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO certificate
			(common_name, sans, ca_provider, validation_method, status, not_before, not_after,
			 key_algorithm, key_ref, key_exportable, ca_reference, owning_team, auto_renew, renew_before_days,
			 organization, organizational_unit, country, state, locality)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
		RETURNING `+certificateColumns, c.CommonName, c.SANs, c.CAProvider, c.ValidationMethod, c.Status, c.NotBefore, c.NotAfter,
		c.KeyAlgorithm, c.KeyRef, c.KeyExportable, nullableString(c.CAReference), c.OwningTeam, c.AutoRenew, c.RenewBeforeDays,
		nullableString(c.Organization), nullableString(c.OrganizationalUnit), nullableString(c.Country),
		nullableString(c.State), nullableString(c.Locality))
	return scanCertificate(row)
}

func (s *PostgresStore) Get(ctx context.Context, id string) (Certificate, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+certificateColumns+` FROM certificate WHERE id = $1`, id)
	return scanCertificate(row)
}

func (s *PostgresStore) List(ctx context.Context, filter Filter) ([]Certificate, error) {
	query := `SELECT ` + certificateColumns + ` FROM certificate WHERE 1=1`
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

	// Never a nil slice: this is serialized straight to JSON as the
	// frontend's certificate list, which — on a freshly installed, still
	// empty inventory — would otherwise encode as `null` instead of `[]`
	// and crash the dashboard's `certs.filter(...)`.
	out := []Certificate{}
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

func (s *PostgresStore) UpdateNotifyEmails(ctx context.Context, id string, emails []string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE certificate SET notify_emails = $2, updated_at = now() WHERE id = $1
	`, id, nullableStringSlice(emails))
	if err != nil {
		return fmt.Errorf("certificate: update notify emails: %w", err)
	}
	return nil
}

func nullableStringSlice(s []string) interface{} {
	if len(s) == 0 {
		return nil
	}
	return s
}

func (s *PostgresStore) DueForRenewal(ctx context.Context, asOf time.Time) ([]Certificate, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+certificateColumns+`
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

	out := []Certificate{}
	for rows.Next() {
		c, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// FinalizeNewCertificate stores a freshly-issued certificate and its first
// version atomically. order.Service.Validate used to call Create and
// AddVersion as two separate, unguarded writes — if AddVersion failed
// after Create had already committed, the order would correctly report
// failure, but an orphaned "active" certificate with no version would be
// left behind: LatestVersion, posture, download, and K8s/WinRM sync all
// break for it from then on, with nothing in the UI revealing why.
// Wrapping both in one transaction means either both land or neither does.
func (s *PostgresStore) FinalizeNewCertificate(ctx context.Context, c Certificate, v Version) (Certificate, Version, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Certificate{}, Version{}, fmt.Errorf("certificate: begin finalize new certificate: %w", err)
	}
	defer tx.Rollback(ctx)

	row := tx.QueryRow(ctx, `
		INSERT INTO certificate
			(common_name, sans, ca_provider, validation_method, status, not_before, not_after,
			 key_algorithm, key_ref, key_exportable, ca_reference, owning_team, auto_renew, renew_before_days,
			 organization, organizational_unit, country, state, locality)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
		RETURNING `+certificateColumns, c.CommonName, c.SANs, c.CAProvider, c.ValidationMethod, c.Status, c.NotBefore, c.NotAfter,
		c.KeyAlgorithm, c.KeyRef, c.KeyExportable, nullableString(c.CAReference), c.OwningTeam, c.AutoRenew, c.RenewBeforeDays,
		nullableString(c.Organization), nullableString(c.OrganizationalUnit), nullableString(c.Country),
		nullableString(c.State), nullableString(c.Locality))
	created, err := scanCertificate(row)
	if err != nil {
		return Certificate{}, Version{}, err
	}

	v.CertificateID = created.ID
	versionRow := tx.QueryRow(ctx, `
		INSERT INTO certificate_version
			(certificate_id, serial_number, fingerprint_sha256, pem_cert, pem_chain, issued_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, certificate_id, serial_number, fingerprint_sha256, pem_cert, pem_chain, issued_at
	`, v.CertificateID, v.SerialNumber, v.FingerprintSHA256, v.PEMCert, v.PEMChain, v.IssuedAt)
	createdVersion, err := scanVersion(versionRow)
	if err != nil {
		return Certificate{}, Version{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Certificate{}, Version{}, fmt.Errorf("certificate: commit finalize new certificate: %w", err)
	}
	return created, createdVersion, nil
}

// FinalizeRenewal updates a renewed certificate's validity/CA reference
// and stores its new version atomically — the renewal-path counterpart to
// FinalizeNewCertificate, and for the same reason: UpdateAfterRenewal and
// AddVersion used to be two separate writes, so a failure in the second
// could leave the certificate row claiming a fresh expiry date while the
// actually-stored certificate material is still the old, soon-to-expire
// one — DueForRenewal would then never flag it again, silently.
func (s *PostgresStore) FinalizeRenewal(ctx context.Context, id string, notBefore, notAfter time.Time, caReference string, v Version) (Version, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Version{}, fmt.Errorf("certificate: begin finalize renewal: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		UPDATE certificate
		SET not_before = $2, not_after = $3, ca_reference = $4, status = 'active', updated_at = now()
		WHERE id = $1
	`, id, notBefore, notAfter, nullableString(caReference)); err != nil {
		return Version{}, fmt.Errorf("certificate: update after renewal: %w", err)
	}

	v.CertificateID = id
	row := tx.QueryRow(ctx, `
		INSERT INTO certificate_version
			(certificate_id, serial_number, fingerprint_sha256, pem_cert, pem_chain, issued_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, certificate_id, serial_number, fingerprint_sha256, pem_cert, pem_chain, issued_at
	`, v.CertificateID, v.SerialNumber, v.FingerprintSHA256, v.PEMCert, v.PEMChain, v.IssuedAt)
	createdVersion, err := scanVersion(row)
	if err != nil {
		return Version{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Version{}, fmt.Errorf("certificate: commit finalize renewal: %w", err)
	}
	return createdVersion, nil
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

	out := []Version{}
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

func (s *PostgresStore) Stats(ctx context.Context, team string) (Stats, error) {
	stats := Stats{ByStatus: map[string]int{}, ByCAProvider: map[string]int{}, ByTeam: map[string]int{}}

	teamFilter := ""
	args := []interface{}{}
	if team != "" {
		args = append(args, team)
		teamFilter = " WHERE owning_team = $1"
	}

	if err := s.aggregateInto(ctx, stats.ByStatus, "SELECT status, count(*) FROM certificate"+teamFilter+" GROUP BY status", args...); err != nil {
		return Stats{}, err
	}
	if err := s.aggregateInto(ctx, stats.ByCAProvider, "SELECT ca_provider, count(*) FROM certificate"+teamFilter+" GROUP BY ca_provider", args...); err != nil {
		return Stats{}, err
	}
	// The team breakdown itself only makes sense unscoped (an admin's
	// all-teams view) — scoping it by team would just be a single row.
	if team == "" {
		if err := s.aggregateInto(ctx, stats.ByTeam, "SELECT owning_team, count(*) FROM certificate GROUP BY owning_team"); err != nil {
			return Stats{}, err
		}
	}

	for _, n := range stats.ByStatus {
		stats.Total += n
	}

	windowQuery := `
		SELECT count(*) FROM certificate
		WHERE status NOT IN ('revoked', 'expired') AND not_after <= now() + make_interval(days => $1)
	`
	if team != "" {
		windowQuery += " AND owning_team = $2"
	}
	windowArgs := []interface{}{7}
	if team != "" {
		windowArgs = append(windowArgs, team)
	}
	if err := s.pool.QueryRow(ctx, windowQuery, windowArgs...).Scan(&stats.ExpiringIn7d); err != nil {
		return Stats{}, fmt.Errorf("certificate: stats (7d): %w", err)
	}
	windowArgs[0] = 30
	if err := s.pool.QueryRow(ctx, windowQuery, windowArgs...).Scan(&stats.ExpiringIn30d); err != nil {
		return Stats{}, fmt.Errorf("certificate: stats (30d): %w", err)
	}

	return stats, nil
}

func (s *PostgresStore) aggregateInto(ctx context.Context, into map[string]int, query string, args ...interface{}) error {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("certificate: stats query: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var count int
		if err := rows.Scan(&key, &count); err != nil {
			return fmt.Errorf("certificate: stats scan: %w", err)
		}
		into[key] = count
	}
	return rows.Err()
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanCertificate(row rowScanner) (Certificate, error) {
	var c Certificate
	err := row.Scan(&c.ID, &c.CommonName, &c.SANs, &c.CAProvider, &c.ValidationMethod, &c.Status, &c.NotBefore, &c.NotAfter,
		&c.KeyAlgorithm, &c.KeyRef, &c.KeyExportable, &c.CAReference, &c.OwningTeam, &c.AutoRenew, &c.RenewBeforeDays,
		&c.NotifyEmails, &c.Organization, &c.OrganizationalUnit, &c.Country, &c.State, &c.Locality,
		&c.CreatedAt, &c.UpdatedAt)
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
