-- discovery_schedule is a recurring template that periodically fires a real
-- one-off scan through the same code path CreateScan uses — see
-- discovery.Service.Run. vulnerabilities on discovery_result records what
-- classifyVulnerabilities found on that probe (weak TLS version, weak
-- signature algorithm, expired certificate), so the fleet-wide posture
-- dashboard can aggregate without re-probing anything.
CREATE TABLE discovery_schedule (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name             text NOT NULL,
    description      text NOT NULL DEFAULT '',
    targets          text[] NOT NULL,
    ports            int[] NOT NULL,
    timeout_ms       int NOT NULL,
    concurrency      int NOT NULL,
    interval_minutes int NOT NULL,
    enabled          boolean NOT NULL DEFAULT true,
    created_by       uuid REFERENCES app_user(id),
    last_run_at      timestamptz,
    last_scan_id     uuid REFERENCES discovery_scan(id),
    next_run_at      timestamptz NOT NULL DEFAULT now(),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_discovery_schedule_due ON discovery_schedule (next_run_at) WHERE enabled;

ALTER TABLE discovery_result
    ADD COLUMN signature_algorithm text,
    ADD COLUMN cipher_suite text,
    ADD COLUMN vulnerabilities text[] NOT NULL DEFAULT '{}';
