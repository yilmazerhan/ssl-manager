-- Configurable expiry-reminder thresholds/templates/recipients (a single
-- row this app always reads/writes as id=1 — there is exactly one set of
-- notification settings, not one per team), plus a log of what was
-- actually sent so the same certificate+threshold is never notified twice
-- and so there's a history to show an operator.
CREATE TABLE notification_settings (
    id                     int PRIMARY KEY DEFAULT 1,
    threshold_days         int[] NOT NULL DEFAULT ARRAY[30, 15, 7, 1],
    email_subject_template text NOT NULL DEFAULT '[SSL Sentry] {{.CommonName}} expires in {{.DaysRemaining}} day(s)',
    email_body_template    text NOT NULL DEFAULT '{{.CommonName}} (team {{.OwningTeam}}, issuer {{.CAProvider}}) expires on {{.NotAfter}} -- {{.DaysRemaining}} day(s) remaining.',
    default_recipients     text[] NOT NULL DEFAULT '{}',
    escalation_recipients  text[] NOT NULL DEFAULT '{}',
    updated_at             timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT notification_settings_singleton CHECK (id = 1)
);
INSERT INTO notification_settings (id) VALUES (1);

CREATE TABLE notification_log (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    certificate_id uuid NOT NULL REFERENCES certificate(id) ON DELETE CASCADE,
    threshold_days int NOT NULL,
    sent_at        timestamptz NOT NULL DEFAULT now(),
    status         text NOT NULL CHECK (status IN ('sent', 'failed')),
    error          text,
    recipients     text[] NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_notification_log_certificate ON notification_log(certificate_id);

-- Per-certificate distribution list override — falls back to
-- notification_settings.default_recipients when empty.
ALTER TABLE certificate ADD COLUMN notify_emails text[];
