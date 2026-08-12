-- Network discovery: a scan probes TLS endpoints across the ranges/ports
-- it's given and reconciles what it finds against the certificate
-- inventory. discovery_scan is the scan's own config/lifecycle;
-- discovery_result is one row per host:port probed.
CREATE TABLE discovery_scan (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name           text NOT NULL,
    description    text NOT NULL DEFAULT '',
    targets        text[] NOT NULL,
    ports          int[] NOT NULL,
    timeout_ms     int NOT NULL,
    concurrency    int NOT NULL,
    status         text NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'partially_completed', 'failed', 'canceled')),
    created_by     uuid REFERENCES app_user(id),
    total_targets  int NOT NULL DEFAULT 0,
    scanned_count  int NOT NULL DEFAULT 0,
    matched_count  int NOT NULL DEFAULT 0,
    mismatch_count int NOT NULL DEFAULT 0,
    new_count      int NOT NULL DEFAULT 0,
    error          text,
    created_at     timestamptz NOT NULL DEFAULT now(),
    started_at     timestamptz,
    completed_at   timestamptz
);

CREATE TABLE discovery_result (
    id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id                uuid NOT NULL REFERENCES discovery_scan(id) ON DELETE CASCADE,
    host                   text NOT NULL,
    port                   int NOT NULL,
    reachable              boolean NOT NULL,
    tls_version            text,
    common_name            text,
    sans                   text[],
    issuer                 text,
    serial_number          text,
    fingerprint_sha256     text,
    not_before             timestamptz,
    not_after              timestamptz,
    match_status           text NOT NULL,
    matched_certificate_id uuid REFERENCES certificate(id),
    error                  text,
    discovered_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_discovery_result_scan ON discovery_result(scan_id);
CREATE INDEX idx_discovery_result_match_status ON discovery_result(match_status);
