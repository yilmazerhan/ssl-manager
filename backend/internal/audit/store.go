// Package audit is the append-only trail docs/plan.html requires in
// sections 07-09: who did what to which resource, and with what scope.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Entry struct {
	Actor      string
	Action     string
	Resource   string
	ResourceID string
	Scope      string
	Metadata   map[string]interface{}
}

type Record struct {
	Entry
	CreatedAt time.Time
}

// ListFilter narrows the system-wide audit feed (audit page, not a single
// certificate's own trail). Resource/Action are exact matches; either may
// be left blank to not filter on it.
type ListFilter struct {
	Resource string
	Action   string
	Limit    int
}

type Store interface {
	Write(ctx context.Context, e Entry) error
	ForResource(ctx context.Context, resource, resourceID string) ([]Record, error)
	List(ctx context.Context, filter ListFilter) ([]Record, error)
}

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) Write(ctx context.Context, e Entry) error {
	metadata := e.Metadata
	if metadata == nil {
		metadata = map[string]interface{}{}
	}
	metaJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("audit: marshal metadata: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO audit_log (actor, action, resource, resource_id, scope, metadata)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, e.Actor, e.Action, e.Resource, nullable(e.ResourceID), nullable(e.Scope), metaJSON)
	if err != nil {
		return fmt.Errorf("audit: write: %w", err)
	}
	return nil
}

func (s *PostgresStore) ForResource(ctx context.Context, resource, resourceID string) ([]Record, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT actor, action, resource, coalesce(resource_id, ''), coalesce(scope, ''), metadata, created_at
		FROM audit_log WHERE resource = $1 AND resource_id = $2
		ORDER BY created_at DESC
	`, resource, resourceID)
	if err != nil {
		return nil, fmt.Errorf("audit: query: %w", err)
	}
	defer rows.Close()

	out := []Record{}
	for rows.Next() {
		var r Record
		var metaJSON []byte
		if err := rows.Scan(&r.Actor, &r.Action, &r.Resource, &r.ResourceID, &r.Scope, &metaJSON, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("audit: scan: %w", err)
		}
		if len(metaJSON) > 0 {
			_ = json.Unmarshal(metaJSON, &r.Metadata)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *PostgresStore) List(ctx context.Context, filter ListFilter) ([]Record, error) {
	limit := filter.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}

	// Action is matched as a substring (ILIKE), not exact — action names
	// like "k8s_sync_failed" and "winrm_sync_failed" share a meaningful
	// suffix, and letting an admin filter on "sync_failed" across both
	// (or "renewal" across renewal_succeeded/renewal_failed) is far more
	// useful than requiring the exact string.
	query := `
		SELECT actor, action, resource, coalesce(resource_id, ''), coalesce(scope, ''), metadata, created_at
		FROM audit_log
		WHERE ($1 = '' OR resource = $1) AND ($2 = '' OR action ILIKE '%' || $2 || '%')
		ORDER BY created_at DESC
		LIMIT $3
	`
	rows, err := s.pool.Query(ctx, query, filter.Resource, filter.Action, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: list: %w", err)
	}
	defer rows.Close()

	out := []Record{}
	for rows.Next() {
		var r Record
		var metaJSON []byte
		if err := rows.Scan(&r.Actor, &r.Action, &r.Resource, &r.ResourceID, &r.Scope, &metaJSON, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("audit: scan: %w", err)
		}
		if len(metaJSON) > 0 {
			_ = json.Unmarshal(metaJSON, &r.Metadata)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func nullable(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
