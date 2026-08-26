-- Editable CA/DNS integration settings, one row per provider. Non-secret
-- fields only (contact email, directory URL, base URL, template,
-- username, DNS provider name) — API keys and passwords stay in Vault
-- (internal/secrets), the same place every other operational secret in
-- this app lives. Before this table existed, all of this was environment
-- variables read once at process startup; see internal/caconfig.
CREATE TABLE ca_integration_settings (
    provider   text PRIMARY KEY,
    settings   jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
