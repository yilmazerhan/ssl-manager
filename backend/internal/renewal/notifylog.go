package renewal

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NotificationLogEntry records one attempt to send an expiry reminder for
// a certificate at a specific threshold — the history an operator sees,
// and (via NotifyLogStore.HasSent) the record that stops the same
// certificate+threshold pair from ever being notified twice.
type NotificationLogEntry struct {
	ID            string    `json:"id"`
	CertificateID string    `json:"certificate_id"`
	ThresholdDays int       `json:"threshold_days"`
	SentAt        time.Time `json:"sent_at"`
	Status        string    `json:"status"` // "sent" or "failed"
	Error         string    `json:"error,omitempty"`
	Recipients    []string  `json:"recipients"`
}

type NotifyLogStore interface {
	// HasSent reports whether a *successful* reminder was already recorded
	// for this certificate at this threshold — a failed attempt does not
	// count, so a transient SMTP outage gets retried on the next tick
	// instead of silently never notifying anyone.
	HasSent(ctx context.Context, certificateID string, thresholdDays int) (bool, error)
	Record(ctx context.Context, entry NotificationLogEntry) error
	ForCertificate(ctx context.Context, certificateID string) ([]NotificationLogEntry, error)
	Recent(ctx context.Context, limit int) ([]NotificationLogEntry, error)
	// Stats counts sent vs. failed notifications since since — the
	// operational health question ("is anything actually getting through")
	// separate from the per-certificate history.
	Stats(ctx context.Context, since time.Time) (sent, failed int, err error)
}

type PostgresNotifyLogStore struct {
	pool *pgxpool.Pool
}

func NewPostgresNotifyLogStore(pool *pgxpool.Pool) *PostgresNotifyLogStore {
	return &PostgresNotifyLogStore{pool: pool}
}

func (s *PostgresNotifyLogStore) HasSent(ctx context.Context, certificateID string, thresholdDays int) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM notification_log
			WHERE certificate_id = $1 AND threshold_days = $2 AND status = 'sent'
		)
	`, certificateID, thresholdDays).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("renewal: check notification log: %w", err)
	}
	return exists, nil
}

func (s *PostgresNotifyLogStore) Record(ctx context.Context, entry NotificationLogEntry) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO notification_log (certificate_id, threshold_days, status, error, recipients)
		VALUES ($1, $2, $3, $4, $5)
	`, entry.CertificateID, entry.ThresholdDays, entry.Status, nullableString(entry.Error), entry.Recipients)
	if err != nil {
		return fmt.Errorf("renewal: record notification log: %w", err)
	}
	return nil
}

func (s *PostgresNotifyLogStore) ForCertificate(ctx context.Context, certificateID string) ([]NotificationLogEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, certificate_id, threshold_days, sent_at, status, coalesce(error, ''), coalesce(recipients, '{}')
		FROM notification_log WHERE certificate_id = $1 ORDER BY sent_at DESC
	`, certificateID)
	if err != nil {
		return nil, fmt.Errorf("renewal: list notification log for certificate: %w", err)
	}
	defer rows.Close()
	return scanNotificationLogRows(rows)
}

func (s *PostgresNotifyLogStore) Stats(ctx context.Context, since time.Time) (sent, failed int, err error) {
	rows, err := s.pool.Query(ctx, `
		SELECT status, count(*) FROM notification_log WHERE sent_at >= $1 GROUP BY status
	`, since)
	if err != nil {
		return 0, 0, fmt.Errorf("renewal: notification log stats: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var status string
		var count int
		if err := rows.Scan(&status, &count); err != nil {
			return 0, 0, fmt.Errorf("renewal: scan notification log stats: %w", err)
		}
		switch status {
		case "sent":
			sent = count
		case "failed":
			failed = count
		}
	}
	return sent, failed, rows.Err()
}

func (s *PostgresNotifyLogStore) Recent(ctx context.Context, limit int) ([]NotificationLogEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, certificate_id, threshold_days, sent_at, status, coalesce(error, ''), coalesce(recipients, '{}')
		FROM notification_log ORDER BY sent_at DESC LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("renewal: list recent notification log: %w", err)
	}
	defer rows.Close()
	return scanNotificationLogRows(rows)
}

type rowsScanner interface {
	Next() bool
	Scan(dest ...interface{}) error
	Err() error
}

func scanNotificationLogRows(rows rowsScanner) ([]NotificationLogEntry, error) {
	out := []NotificationLogEntry{}
	for rows.Next() {
		var e NotificationLogEntry
		if err := rows.Scan(&e.ID, &e.CertificateID, &e.ThresholdDays, &e.SentAt, &e.Status, &e.Error, &e.Recipients); err != nil {
			return nil, fmt.Errorf("renewal: scan notification log: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
