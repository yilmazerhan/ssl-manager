package renewal

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ReminderSettings configures the expiry-reminder side of the renewal
// engine: which day-thresholds trigger a reminder, how the email is
// rendered (Go text/template syntax over reminderTemplateData — see
// template.go), and who receives it by default. There is exactly one row
// of this app-wide (id=1 in notification_settings), not one per team.
type ReminderSettings struct {
	ThresholdDays        []int    `json:"threshold_days"`
	EmailSubjectTemplate string   `json:"email_subject_template"`
	EmailBodyTemplate    string   `json:"email_body_template"`
	DefaultRecipients    []string `json:"default_recipients"`
	// EscalationRecipients receive every reminder in addition to the usual
	// recipients once a certificate reaches the most urgent configured
	// threshold (the smallest value in ThresholdDays) — e.g. pulling in a
	// manager or on-call list only when things are truly about to expire.
	EscalationRecipients []string `json:"escalation_recipients"`
}

type SettingsStore interface {
	Get(ctx context.Context) (ReminderSettings, error)
	Update(ctx context.Context, s ReminderSettings) error
}

type PostgresSettingsStore struct {
	pool *pgxpool.Pool
}

func NewPostgresSettingsStore(pool *pgxpool.Pool) *PostgresSettingsStore {
	return &PostgresSettingsStore{pool: pool}
}

func (s *PostgresSettingsStore) Get(ctx context.Context) (ReminderSettings, error) {
	var settings ReminderSettings
	err := s.pool.QueryRow(ctx, `
		SELECT threshold_days, email_subject_template, email_body_template, default_recipients, escalation_recipients
		FROM notification_settings WHERE id = 1
	`).Scan(&settings.ThresholdDays, &settings.EmailSubjectTemplate, &settings.EmailBodyTemplate,
		&settings.DefaultRecipients, &settings.EscalationRecipients)
	if err != nil {
		return ReminderSettings{}, fmt.Errorf("renewal: load notification settings: %w", err)
	}
	return settings, nil
}

func (s *PostgresSettingsStore) Update(ctx context.Context, settings ReminderSettings) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE notification_settings SET
			threshold_days = $1, email_subject_template = $2, email_body_template = $3,
			default_recipients = $4, escalation_recipients = $5, updated_at = now()
		WHERE id = 1
	`, settings.ThresholdDays, settings.EmailSubjectTemplate, settings.EmailBodyTemplate,
		settings.DefaultRecipients, settings.EscalationRecipients)
	if err != nil {
		return fmt.Errorf("renewal: update notification settings: %w", err)
	}
	return nil
}
