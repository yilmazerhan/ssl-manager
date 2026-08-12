import { useEffect, useState } from "react";
import { api, IntegrationsStatus } from "../api/client";

function StatusBadge({ ok, label }: { ok: boolean; label: string }) {
  return <span className={`pill ${ok ? "ok" : "warn"}`}>{label}</span>;
}

export default function Integrations() {
  const [status, setStatus] = useState<IntegrationsStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.getIntegrations().then(setStatus).catch((e) => setError(e.message));
  }, []);

  if (error) return <div className="card">Could not load integrations: {error}</div>;
  if (!status) return <p>Loading…</p>;

  return (
    <>
      <h1>Integrations</h1>
      <p className="page-lede">Certificate authorities and DNS automation this platform is connected to.</p>

      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 10 }}>
          <h3 style={{ margin: 0 }}>Let's Encrypt</h3>
          <StatusBadge ok={status.letsencrypt.account_registered} label={status.letsencrypt.account_registered ? "Connected" : "Not registered"} />
        </div>
        <p>
          <strong>Environment:</strong> {status.letsencrypt.environment}
        </p>
        <p>
          <strong>Directory URL:</strong> <code>{status.letsencrypt.directory_url}</code>
        </p>
        <p>
          <strong>Contact email:</strong> {status.letsencrypt.contact_email}
        </p>
        <p style={{ color: "var(--muted)", fontSize: 13, marginBottom: 0 }}>
          The ACME account is registered automatically on first use and its key is stored in Vault — there's nothing to configure here beyond
          the directory URL and contact email (environment variables on the backend).
        </p>
      </div>

      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 10 }}>
          <h3 style={{ margin: 0 }}>ZeroSSL</h3>
          <StatusBadge ok={status.zerossl.configured} label={status.zerossl.configured ? "Connected" : "Not configured"} />
        </div>
        <p>
          <strong>API base URL:</strong> <code>{status.zerossl.base_url}</code>
        </p>
        {!status.zerossl.configured && (
          <p style={{ color: "var(--muted)", fontSize: 13, marginBottom: 0 }}>
            Set <code>ZEROSSL_API_KEY</code> on the backend to enable ZeroSSL as a certificate authority.
          </p>
        )}
      </div>

      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 10 }}>
          <h3 style={{ margin: 0 }}>DNS-01 automation</h3>
          <StatusBadge ok={status.dns01.configured} label={status.dns01.configured ? "Automated" : "Manual"} />
        </div>
        {status.dns01.configured ? (
          <p style={{ marginBottom: 0 }}>
            DNS-01 challenges are published and cleaned up automatically through <strong>{status.dns01.provider}</strong>. No one needs to
            publish a TXT record by hand.
          </p>
        ) : (
          <p style={{ color: "var(--muted)", fontSize: 13, marginBottom: 0 }}>
            No DNS provider is configured — DNS-01 challenges show manual instructions, the same as HTTP-01. Set <code>DNS01_PROVIDER</code>{" "}
            (currently supports <code>cloudflare</code>) plus its credentials on the backend to automate this.
          </p>
        )}
      </div>
    </>
  );
}
