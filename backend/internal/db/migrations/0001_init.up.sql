-- Schema for the data model in docs/plan.html, section 03, plus the
-- authn/authz tables needed to enforce section 07/08 (scoped API access,
-- RBAC, single-use MFA-gated download tokens).

CREATE TABLE app_user (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email        text NOT NULL UNIQUE,
    oidc_subject text UNIQUE,
    role         text NOT NULL CHECK (role IN ('viewer', 'cert_manager', 'admin', 'api_only')),
    team         text,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE api_key (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    name         text NOT NULL,
    key_hash     text NOT NULL UNIQUE,
    scopes       text[] NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz
);

CREATE TABLE certificate (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    common_name       text NOT NULL,
    sans              text[] NOT NULL DEFAULT '{}',
    ca_provider       text NOT NULL CHECK (ca_provider IN ('letsencrypt', 'zerossl', 'manual')),
    validation_method text NOT NULL,
    status            text NOT NULL CHECK (status IN ('active', 'expiring', 'expired', 'revoked')),
    not_before        timestamptz NOT NULL,
    not_after         timestamptz NOT NULL,
    key_algorithm     text NOT NULL,
    key_ref           text NOT NULL,
    owning_team       text NOT NULL,
    auto_renew        boolean NOT NULL DEFAULT true,
    renew_before_days integer NOT NULL DEFAULT 30,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

-- The private key itself is never stored here or anywhere else in Postgres:
-- certificate.key_ref names a Vault Transit key that signs CSRs remotely
-- and never exports its private material, so there is nothing per-version
-- to reference — every version of a certificate is signed by the same
-- Vault-held key unless a policy explicitly rotates it.
CREATE TABLE certificate_version (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    certificate_id      uuid NOT NULL REFERENCES certificate(id) ON DELETE CASCADE,
    serial_number       text NOT NULL,
    fingerprint_sha256  text NOT NULL,
    pem_cert            text NOT NULL,
    pem_chain           text NOT NULL,
    issued_at           timestamptz NOT NULL
);

CREATE TABLE certificate_order (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    requested_by       uuid NOT NULL REFERENCES app_user(id),
    owning_team        text NOT NULL,
    domains            text[] NOT NULL,
    ca_provider        text NOT NULL CHECK (ca_provider IN ('letsencrypt', 'zerossl')),
    validation_method  text NOT NULL,
    key_algorithm      text NOT NULL,
    status             text NOT NULL CHECK (status IN ('draft', 'awaiting_validation', 'issuing', 'issued', 'failed')),
    challenge_details  jsonb NOT NULL DEFAULT '{}',
    key_ref            text,
    csr                text,
    certificate_id     uuid REFERENCES certificate(id),
    error              text,
    attempt_count      integer NOT NULL DEFAULT 0,
    created_at         timestamptz NOT NULL DEFAULT now(),
    completed_at       timestamptz
);

CREATE TABLE ca_account (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    provider      text NOT NULL CHECK (provider IN ('letsencrypt', 'zerossl')),
    environment   text NOT NULL,
    account_ref   text NOT NULL,
    directory_url text,
    UNIQUE (provider, environment)
);

CREATE TABLE download_token (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    certificate_id  uuid NOT NULL REFERENCES certificate(id) ON DELETE CASCADE,
    user_id         uuid NOT NULL REFERENCES app_user(id),
    token_hash      text NOT NULL UNIQUE,
    used_at         timestamptz,
    expires_at      timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor       text NOT NULL,
    action      text NOT NULL,
    resource    text NOT NULL,
    resource_id text,
    scope       text,
    metadata    jsonb NOT NULL DEFAULT '{}',
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_certificate_not_after ON certificate (not_after);
CREATE INDEX idx_certificate_owning_team ON certificate (owning_team);
CREATE INDEX idx_certificate_version_certificate_id ON certificate_version (certificate_id);
CREATE INDEX idx_certificate_order_status ON certificate_order (status);
CREATE INDEX idx_download_token_expires_at ON download_token (expires_at);
CREATE INDEX idx_audit_log_resource ON audit_log (resource, resource_id);
