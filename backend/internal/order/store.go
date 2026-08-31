package order

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yilmazerhan/ssl-manager/backend/internal/ca"
)

var ErrNotFound = errors.New("order: not found")

type Store interface {
	Create(ctx context.Context, o Order) (Order, error)
	Get(ctx context.Context, id string) (Order, error)
	Update(ctx context.Context, o Order) error
	// UpdateIfStatus writes o only if the row's current status still
	// equals expected, atomically (a single conditional UPDATE) — the
	// guard Validate uses to claim an order before issuing, so two
	// concurrent Validate calls on the same order can't both pass the
	// check and both submit the CSR to the CA. Returns whether the write
	// actually happened; false means someone else already claimed it.
	UpdateIfStatus(ctx context.Context, o Order, expected Status) (bool, error)
}

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

// orderColumns is shared by Create/Get so their column list and
// scanOrder's Scan() order stay in lockstep.
const orderColumns = `
	id, requested_by, owning_team, domains, ca_provider, validation_method,
	key_algorithm, status, challenge_details, coalesce(key_ref, ''), coalesce(csr, ''),
	coalesce(certificate_id::text, ''), coalesce(error, ''), attempt_count, created_at, completed_at,
	coalesce(organization, ''), coalesce(organizational_unit, ''), coalesce(country, ''),
	coalesce(state, ''), coalesce(locality, ''), key_exportable
`

func (s *PostgresStore) Create(ctx context.Context, o Order) (Order, error) {
	challengeJSON, err := json.Marshal(o.Challenges)
	if err != nil {
		return Order{}, fmt.Errorf("order: marshal challenges: %w", err)
	}

	row := s.pool.QueryRow(ctx, `
		INSERT INTO certificate_order
			(requested_by, owning_team, domains, ca_provider, validation_method,
			 key_algorithm, status, challenge_details, key_ref, csr, certificate_id,
			 organization, organizational_unit, country, state, locality, key_exportable)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
		RETURNING `+orderColumns, o.RequestedBy, o.OwningTeam, o.Domains, o.CAProvider, o.ValidationMethod,
		o.KeyAlgorithm, o.Status, challengeJSON, nullableString(o.KeyRef), nullableString(o.CSRPEM), nullableUUID(o.CertificateID),
		nullableString(o.Organization), nullableString(o.OrganizationalUnit), nullableString(o.Country),
		nullableString(o.State), nullableString(o.Locality), o.KeyExportable)
	return scanOrder(row)
}

func (s *PostgresStore) Get(ctx context.Context, id string) (Order, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+orderColumns+` FROM certificate_order WHERE id = $1`, id)
	return scanOrder(row)
}

func (s *PostgresStore) Update(ctx context.Context, o Order) error {
	challengeJSON, err := json.Marshal(o.Challenges)
	if err != nil {
		return fmt.Errorf("order: marshal challenges: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		UPDATE certificate_order
		SET status = $2, challenge_details = $3, certificate_id = $4,
			error = $5, attempt_count = $6, completed_at = $7
		WHERE id = $1
	`, o.ID, o.Status, challengeJSON, nullableUUID(o.CertificateID),
		nullableString(o.Error), o.AttemptCount, o.CompletedAt)
	if err != nil {
		return fmt.Errorf("order: update: %w", err)
	}
	return nil
}

func (s *PostgresStore) UpdateIfStatus(ctx context.Context, o Order, expected Status) (bool, error) {
	challengeJSON, err := json.Marshal(o.Challenges)
	if err != nil {
		return false, fmt.Errorf("order: marshal challenges: %w", err)
	}

	tag, err := s.pool.Exec(ctx, `
		UPDATE certificate_order
		SET status = $2, challenge_details = $3, certificate_id = $4,
			error = $5, attempt_count = $6, completed_at = $7
		WHERE id = $1 AND status = $8
	`, o.ID, o.Status, challengeJSON, nullableUUID(o.CertificateID),
		nullableString(o.Error), o.AttemptCount, o.CompletedAt, expected)
	if err != nil {
		return false, fmt.Errorf("order: update if status: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func nullableUUID(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanOrder(row rowScanner) (Order, error) {
	var o Order
	var challengeJSON []byte
	var completedAt *time.Time

	err := row.Scan(&o.ID, &o.RequestedBy, &o.OwningTeam, &o.Domains, &o.CAProvider, &o.ValidationMethod,
		&o.KeyAlgorithm, &o.Status, &challengeJSON, &o.KeyRef, &o.CSRPEM, &o.CertificateID, &o.Error, &o.AttemptCount,
		&o.CreatedAt, &completedAt, &o.Organization, &o.OrganizationalUnit, &o.Country, &o.State, &o.Locality, &o.KeyExportable)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Order{}, ErrNotFound
		}
		return Order{}, fmt.Errorf("order: scan: %w", err)
	}
	o.CompletedAt = completedAt

	if len(challengeJSON) > 0 {
		var po ca.ProviderOrder
		if err := json.Unmarshal(challengeJSON, &po); err != nil {
			return Order{}, fmt.Errorf("order: unmarshal challenges: %w", err)
		}
		o.Challenges = po
	}
	return o, nil
}
