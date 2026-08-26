import { useEffect, useState } from "react";
import { api, IntegrationsStatus } from "../api/client";
import { PlugIcon, AlertTriangleIcon } from "../components/Icons";

function StatusBadge({ ok, label }: { ok: boolean; label: string }) {
  return <span className={`pill ${ok ? "ok" : "warn"}`}>{label}</span>;
}

export default function Integrations() {
  const [status, setStatus] = useState<IntegrationsStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  function load() {
    api.getIntegrations().then(setStatus).catch((e) => setError(e.message));
  }
  useEffect(load, []);

  if (error) return <div className="card">Could not load integrations: {error}</div>;
  if (!status) return <p>Loading…</p>;

  return (
    <>
      <div className="page-header">
        <div className="page-icon">
          <PlugIcon />
        </div>
        <div>
          <h1>Integrations</h1>
          <p className="page-lede" style={{ margin: 0 }}>
            Certificate authorities and DNS automation this platform is connected to — edit any of these below. Changes take effect
            immediately, with no restart needed.
          </p>
        </div>
      </div>

      <LetsEncryptCard status={status.letsencrypt} onSaved={load} />
      <ZeroSSLCard status={status.zerossl} onSaved={load} />
      <SelfSignedCard status={status.selfsigned} onSaved={load} />
      <ADCSCard status={status.adcs} onSaved={load} />
      <DNS01Card status={status.dns01} onSaved={load} />
    </>
  );
}

function SaveResult({ error, notice }: { error: string | null; notice: string | null }) {
  return (
    <>
      {error && <div className="error-banner">{error}</div>}
      {notice && (
        <div className="callout accent" style={{ marginTop: 0, marginBottom: 16 }}>
          {notice}
        </div>
      )}
    </>
  );
}

function LetsEncryptCard({ status, onSaved }: { status: IntegrationsStatus["letsencrypt"]; onSaved: () => void }) {
  const [editing, setEditing] = useState(false);
  const [environment, setEnvironment] = useState(status.environment);
  const [directoryURL, setDirectoryURL] = useState(status.directory_url);
  const [contactEmail, setContactEmail] = useState(status.contact_email);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save() {
    setSaving(true);
    setError(null);
    try {
      await api.updateLetsEncrypt({ environment, directory_url: directoryURL, contact_email: contactEmail });
      setEditing(false);
      onSaved();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 10 }}>
        <h3 style={{ margin: 0 }}>Let's Encrypt</h3>
        <StatusBadge ok={status.account_registered} label={status.account_registered ? "Connected" : "Not registered"} />
      </div>

      {!editing ? (
        <>
          <p>
            <strong>Environment:</strong> {status.environment}
          </p>
          <p>
            <strong>Directory URL:</strong> <code>{status.directory_url}</code>
          </p>
          <p>
            <strong>Contact email:</strong> {status.contact_email}
          </p>
          <button className="secondary" onClick={() => setEditing(true)}>
            Edit
          </button>
        </>
      ) : (
        <>
          <SaveResult error={error} notice={null} />
          <div className="field">
            <label>Environment</label>
            <select value={environment} onChange={(e) => setEnvironment(e.target.value)}>
              <option value="staging">Staging (test certificates, not trusted by browsers)</option>
              <option value="production">Production</option>
            </select>
          </div>
          <div className="field">
            <label>Directory URL</label>
            <input value={directoryURL} onChange={(e) => setDirectoryURL(e.target.value)} placeholder="https://acme-v02.api.letsencrypt.org/directory" />
          </div>
          <div className="field">
            <label>Contact email</label>
            <input value={contactEmail} onChange={(e) => setContactEmail(e.target.value)} placeholder="ops@example.com" />
          </div>
          <div className="callout accent">
            <AlertTriangleIcon width={14} height={14} />
            <span>Saving actually registers (or re-uses) an ACME account with this directory — a bad email or unreachable URL is rejected here, not silently accepted.</span>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="primary" disabled={saving} onClick={save}>
              {saving ? "Saving…" : "Save"}
            </button>
            <button className="secondary" disabled={saving} onClick={() => setEditing(false)}>
              Cancel
            </button>
          </div>
        </>
      )}
    </div>
  );
}

function ZeroSSLCard({ status, onSaved }: { status: IntegrationsStatus["zerossl"]; onSaved: () => void }) {
  const [editing, setEditing] = useState(false);
  const [baseURL, setBaseURL] = useState(status.base_url);
  const [apiKey, setApiKey] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save() {
    setSaving(true);
    setError(null);
    try {
      await api.updateZeroSSL({ base_url: baseURL, api_key: apiKey || undefined });
      setApiKey("");
      setEditing(false);
      onSaved();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 10 }}>
        <h3 style={{ margin: 0 }}>ZeroSSL</h3>
        <StatusBadge ok={status.configured} label={status.configured ? "Connected" : "Not configured"} />
      </div>

      {!editing ? (
        <>
          <p>
            <strong>API base URL:</strong> <code>{status.base_url}</code>
          </p>
          <p style={{ color: "var(--muted)", fontSize: 13 }}>API key: {status.api_key_set ? "set" : "not set"}</p>
          <button className="secondary" onClick={() => setEditing(true)}>
            Edit
          </button>
        </>
      ) : (
        <>
          <SaveResult error={error} notice={null} />
          <div className="field">
            <label>API base URL</label>
            <input value={baseURL} onChange={(e) => setBaseURL(e.target.value)} placeholder="https://api.zerossl.com" />
          </div>
          <div className="field">
            <label>API key</label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={status.api_key_set ? "•••••••• (leave blank to keep the current key)" : "paste your ZeroSSL API key"}
            />
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="primary" disabled={saving} onClick={save}>
              {saving ? "Saving…" : "Save"}
            </button>
            <button className="secondary" disabled={saving} onClick={() => setEditing(false)}>
              Cancel
            </button>
          </div>
        </>
      )}
    </div>
  );
}

function SelfSignedCard({ status, onSaved }: { status: IntegrationsStatus["selfsigned"]; onSaved: () => void }) {
  const [editing, setEditing] = useState(false);
  const [days, setDays] = useState(status.validity_days);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save() {
    setSaving(true);
    setError(null);
    try {
      await api.updateSelfSigned({ validity_days: days });
      setEditing(false);
      onSaved();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 10 }}>
        <h3 style={{ margin: 0 }}>Self-signed</h3>
        <StatusBadge ok={status.available} label="Available" />
      </div>

      {!editing ? (
        <>
          <p style={{ marginBottom: 12 }}>
            Always available — there's no external account to configure. Certificates are signed by their own Vault-backed key and
            valid for <strong>{status.validity_period}</strong>. Nothing outside this platform trusts them, so they're best used for
            internal or test endpoints.
          </p>
          <button className="secondary" onClick={() => setEditing(true)}>
            Edit
          </button>
        </>
      ) : (
        <>
          <SaveResult error={error} notice={null} />
          <div className="field">
            <label>Validity period (days)</label>
            <input type="number" min={1} max={3650} value={days} onChange={(e) => setDays(Number(e.target.value))} style={{ width: 120 }} />
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="primary" disabled={saving} onClick={save}>
              {saving ? "Saving…" : "Save"}
            </button>
            <button className="secondary" disabled={saving} onClick={() => setEditing(false)}>
              Cancel
            </button>
          </div>
        </>
      )}
    </div>
  );
}

function ADCSCard({ status, onSaved }: { status: IntegrationsStatus["adcs"]; onSaved: () => void }) {
  const [editing, setEditing] = useState(false);
  const [baseURL, setBaseURL] = useState(status.base_url);
  const [template, setTemplate] = useState(status.template);
  const [username, setUsername] = useState(status.username);
  const [password, setPassword] = useState("");
  const [allowBasicAuth, setAllowBasicAuth] = useState(status.allow_basic_auth);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function save() {
    setSaving(true);
    setError(null);
    try {
      await api.updateADCS({ base_url: baseURL, template, username, password: password || undefined, allow_basic_auth: allowBasicAuth });
      setPassword("");
      setEditing(false);
      onSaved();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 10 }}>
        <h3 style={{ margin: 0 }}>Active Directory CS</h3>
        <StatusBadge ok={status.configured} label={status.configured ? "Configured" : "Not configured"} />
      </div>

      {!editing ? (
        <>
          {status.configured ? (
            <>
              <p>
                <strong>CA server:</strong> <code>{status.base_url}</code>
              </p>
              <p>
                <strong>Template:</strong> {status.template || "(CA default)"}
              </p>
              <p style={{ marginBottom: 12 }}>
                <strong>Username:</strong> {status.username || "—"} · Password: {status.password_set ? "set" : "not set"}
              </p>
            </>
          ) : (
            <p style={{ color: "var(--muted)", fontSize: 13, marginBottom: 12 }}>
              Not configured — set your certsrv server URL plus credentials to enroll certificates from your internal Domain
              Controller CA. Revocation isn't available through this path — certsrv's web enrollment interface has no revoke
              endpoint, so a revoked AD CS certificate needs <code>certutil -revoke</code> on the CA server as well.
            </p>
          )}
          <button className="secondary" onClick={() => setEditing(true)}>
            Edit
          </button>
        </>
      ) : (
        <>
          <SaveResult error={error} notice={null} />
          <div className="field">
            <label>CA server URL (certsrv)</label>
            <input value={baseURL} onChange={(e) => setBaseURL(e.target.value)} placeholder="https://ca.corp.example.com/certsrv" />
            <span style={{ fontSize: 12, color: "var(--muted)" }}>Leave blank to unconfigure AD CS entirely.</span>
          </div>
          <div className="field">
            <label>Certificate template</label>
            <input value={template} onChange={(e) => setTemplate(e.target.value)} placeholder="WebServer (leave blank for the CA default)" />
          </div>
          <div className="field">
            <label>Username</label>
            <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="DOMAIN\\svc-account" />
          </div>
          <div className="field">
            <label>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={status.password_set ? "•••••••• (leave blank to keep the current password)" : "password"}
            />
          </div>
          <div className="field" style={{ flexDirection: "row", alignItems: "center", gap: 8 }}>
            <input type="checkbox" id="adcs-basic-auth" checked={allowBasicAuth} onChange={(e) => setAllowBasicAuth(e.target.checked)} style={{ width: "auto" }} />
            <label htmlFor="adcs-basic-auth" style={{ marginBottom: 0 }}>
              Allow HTTP Basic auth fallback (requires an https:// server URL — sends credentials in the clear otherwise)
            </label>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="primary" disabled={saving} onClick={save}>
              {saving ? "Saving…" : "Save"}
            </button>
            <button className="secondary" disabled={saving} onClick={() => setEditing(false)}>
              Cancel
            </button>
          </div>
        </>
      )}
    </div>
  );
}

function DNS01Card({ status, onSaved }: { status: IntegrationsStatus["dns01"]; onSaved: () => void }) {
  const [editing, setEditing] = useState(false);
  const [provider, setProvider] = useState(status.provider);
  const [token, setToken] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function save() {
    setSaving(true);
    setError(null);
    setNotice(null);
    try {
      const result = await api.updateDNS01({ provider, token: token || undefined });
      setToken("");
      setEditing(false);
      if (result.warning) setNotice(result.warning);
      onSaved();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 10 }}>
        <h3 style={{ margin: 0 }}>DNS-01 automation</h3>
        <StatusBadge ok={status.configured} label={status.configured ? "Automated" : "Manual"} />
      </div>

      <SaveResult error={null} notice={notice} />

      {!editing ? (
        <>
          {status.configured ? (
            <p style={{ marginBottom: 12 }}>
              DNS-01 challenges are published and cleaned up automatically through <strong>{status.provider}</strong>. No one needs
              to publish a TXT record by hand.
            </p>
          ) : (
            <p style={{ color: "var(--muted)", fontSize: 13, marginBottom: 12 }}>
              No DNS provider is configured — DNS-01 challenges show manual instructions, the same as HTTP-01.
            </p>
          )}
          <button className="secondary" onClick={() => setEditing(true)}>
            Edit
          </button>
        </>
      ) : (
        <>
          <SaveResult error={error} notice={null} />
          <div className="field">
            <label>DNS provider</label>
            <select value={provider} onChange={(e) => setProvider(e.target.value)}>
              <option value="">None — manual TXT record instructions</option>
              <option value="cloudflare">Cloudflare</option>
            </select>
          </div>
          {provider === "cloudflare" && (
            <div className="field">
              <label>API token</label>
              <input
                type="password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder={status.token_set ? "•••••••• (leave blank to keep the current token)" : "Cloudflare API token"}
              />
            </div>
          )}
          <div className="callout accent">
            <AlertTriangleIcon width={14} height={14} />
            <span>Let's Encrypt is refreshed to use this automatically once saved — if that refresh fails, you'll see a warning here but this DNS-01 change is still saved.</span>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="primary" disabled={saving} onClick={save}>
              {saving ? "Saving…" : "Save"}
            </button>
            <button className="secondary" disabled={saving} onClick={() => setEditing(false)}>
              Cancel
            </button>
          </div>
        </>
      )}
    </div>
  );
}
