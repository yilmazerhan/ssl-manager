-- Schema for the data model in docs/plan.html, section 03.
-- Not wired up yet: internal/certificate.MemoryStore is the store used by
-- the API today. This migration is the target shape for the Postgres-backed
-- store that replaces it (roadmap Phase 1).

CREATE TABLE certificate (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    common_name       text NOT NULL,
    sans              text[] NOT NULL DEFAULT '{}',
    ca_provider       text NOT NULL CHECK (ca_provider IN ('letsencrypt', 'zerossl', 'manual')),
    status            text NOT NULL CHECK (status IN ('active', 'expiring', 'expired', 'revoked')),
    not_before        timestamptz NOT NULL,
    not_after         timestamptz NOT NULL,
    key_algorithm     text NOT NULL,
    owning_team       text NOT NULL,
    auto_renew        boolean NOT NULL DEFAULT true,
    renew_before_days integer NOT NULL DEFAULT 30,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE certificate_version (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    certificate_id      uuid NOT NULL REFERENCES certificate(id) ON DELETE CASCADE,
    serial_number       text NOT NULL,
    fingerprint_sha256  text NOT NULL,
    pem_cert            text NOT NULL,
    pem_chain           text NOT NULL,
    private_key_ref     text NOT NULL,
    issued_at           timestamptz NOT NULL
);

CREATE TABLE certificate_order (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    requested_by       text NOT NULL,
    owning_team        text NOT NULL,
    domains            text[] NOT NULL,
    ca_provider        text NOT NULL CHECK (ca_provider IN ('letsencrypt', 'zerossl')),
    validation_method  text NOT NULL,
    status             text NOT NULL CHECK (status IN ('draft', 'awaiting_validation', 'issuing', 'issued', 'failed')),
    challenge_details  jsonb NOT NULL DEFAULT '{}',
    csr                text,
    key_ref            text,
    certificate_id     uuid REFERENCES certificate(id),
    error              text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    completed_at       timestamptz
);

CREATE TABLE ca_account (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    provider      text NOT NULL CHECK (provider IN ('letsencrypt', 'zerossl')),
    environment   text NOT NULL,
    account_ref   text NOT NULL,
    directory_url text
);

CREATE TABLE app_user (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email      text NOT NULL UNIQUE,
    role       text NOT NULL CHECK (role IN ('viewer', 'cert_manager', 'admin', 'api_only')),
    team       text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id    uuid REFERENCES app_user(id),
    action      text NOT NULL,
    resource    text NOT NULL,
    resource_id uuid,
    metadata    jsonb NOT NULL DEFAULT '{}',
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_certificate_not_after ON certificate (not_after);
CREATE INDEX idx_certificate_version_certificate_id ON certificate_version (certificate_id);
CREATE INDEX idx_audit_log_resource ON audit_log (resource, resource_id);
