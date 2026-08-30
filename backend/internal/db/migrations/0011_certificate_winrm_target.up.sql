-- certificate_winrm_target is the WinRM-remoting counterpart to
-- certificate_k8s_target: after issuance/renewal, the platform connects
-- directly to host over WinRM (using stored credentials) and runs a
-- PowerShell script that imports the cert/key into the machine's
-- certificate store and, per service_type, rebinds the service to it —
-- see internal/winrm. It shares certificate.key_exportable's gate with
-- Kubernetes targets: both need the raw private key out of Vault.
CREATE TABLE certificate_winrm_target (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    certificate_id       uuid NOT NULL REFERENCES certificate(id) ON DELETE CASCADE,
    name                 text NOT NULL,
    host                 text NOT NULL,
    port                 int NOT NULL,
    use_https            boolean NOT NULL DEFAULT true,
    insecure_skip_verify boolean NOT NULL DEFAULT false,
    username             text NOT NULL,
    service_type         text NOT NULL CHECK (service_type IN ('winrm_https', 'ldaps')),
    enabled              boolean NOT NULL DEFAULT true,
    last_synced_at       timestamptz,
    last_sync_error      text NOT NULL DEFAULT '',
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_certificate_winrm_target_cert ON certificate_winrm_target (certificate_id);
