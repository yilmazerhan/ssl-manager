-- key_exportable records whether a certificate's Vault Transit key was
-- created with exportable=true — a one-time, immutable choice made at
-- issuance (see secrets.KeyManager.EnsureKey) because Vault Transit itself
-- won't let a key's exportable flag change after creation. A certificate_
-- k8s_target can only be attached to a certificate where this is true: the
-- Kubernetes Secret it syncs needs the raw private key, which a
-- non-exportable Transit key can never produce.
ALTER TABLE certificate ADD COLUMN key_exportable boolean NOT NULL DEFAULT false;
-- certificate_order.key_exportable carries the same choice from order
-- creation through to Validate (a later, possibly much later, request) —
-- see order.Order.KeyExportable.
ALTER TABLE certificate_order ADD COLUMN key_exportable boolean NOT NULL DEFAULT false;

CREATE TABLE certificate_k8s_target (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    certificate_id       uuid NOT NULL REFERENCES certificate(id) ON DELETE CASCADE,
    name                 text NOT NULL,
    cluster_url          text NOT NULL,
    namespace            text NOT NULL,
    secret_name          text NOT NULL,
    insecure_skip_verify boolean NOT NULL DEFAULT false,
    enabled              boolean NOT NULL DEFAULT true,
    last_synced_at       timestamptz,
    last_sync_error      text NOT NULL DEFAULT '',
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_certificate_k8s_target_cert ON certificate_k8s_target (certificate_id);
