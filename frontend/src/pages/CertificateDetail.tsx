import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import {
  api,
  AuditEntry,
  Certificate,
  CertificatePosture,
  CertificateVersion,
  NotificationLogEntry,
  downloadPEM,
} from "../api/client";
import StatusPill from "../components/StatusPill";
import { useAuth } from "../auth/AuthContext";

const WEAK_SIGNATURE_ALGORITHMS = ["SHA1", "MD5", "MD2"];
const WEAK_TLS_VERSIONS = ["TLS 1.0", "TLS 1.1"];

export default function CertificateDetail() {
  const { id } = useParams<{ id: string }>();
  const { hasScope } = useAuth();
  const [cert, setCert] = useState<Certificate | null>(null);
  const [history, setHistory] = useState<CertificateVersion[]>([]);
  const [auditLog, setAuditLog] = useState<AuditEntry[]>([]);
  const [notifyLog, setNotifyLog] = useState<NotificationLogEntry[]>([]);
  const [notifyEmailsInput, setNotifyEmailsInput] = useState("");
  const [posture, setPosture] = useState<CertificatePosture | null>(null);
  const [postureLoading, setPostureLoading] = useState(false);
  const [postureError, setPostureError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function load() {
    if (!id) return;
    Promise.all([api.getCertificate(id), api.getHistory(id), api.getAudit(id), api.getCertificateNotifications(id)])
      .then(([c, h, a, n]) => {
        setCert(c);
        setHistory(h);
        setAuditLog(a ?? []);
        setNotifyLog(n ?? []);
        setNotifyEmailsInput((c.notify_emails ?? []).join(", "));
      })
      .catch((e) => setError(e.message));
  }

  useEffect(load, [id]);

  useEffect(() => {
    if (!id) return;
    setPostureLoading(true);
    setPostureError(null);
    api
      .getCertificatePosture(id)
      .then(setPosture)
      .catch((e) => setPostureError(e.message))
      .finally(() => setPostureLoading(false));
  }, [id]);

  async function handleSaveNotifyEmails() {
    if (!id) return;
    setBusy(true);
    setNotice(null);
    try {
      const emails = notifyEmailsInput
        .split(",")
        .map((e) => e.trim())
        .filter(Boolean);
      await api.updateNotifyEmails(id, emails);
      setNotice("Notification recipients updated.");
      load();
    } catch (e) {
      setNotice((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function handleDownload() {
    if (!id || !cert) return;
    setBusy(true);
    setNotice(null);
    try {
      const { token } = await api.issueDownloadToken(id);
      const version = await api.downloadCertificate(id, token);
      downloadPEM(`${cert.common_name}-fullchain.pem`, version);
    } catch (e) {
      setNotice((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function handleRenew() {
    if (!id) return;
    setBusy(true);
    setNotice(null);
    try {
      const order = await api.renewCertificate(id);
      setNotice(
        order.status === "issued"
          ? "Renewed successfully."
          : `Renewal started (status: ${order.status}) — domain validation may still need to be satisfied.`
      );
      load();
    } catch (e) {
      setNotice((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function handleRevoke() {
    if (!id) return;
    if (!window.confirm("Revoke this certificate? This cannot be undone.")) return;
    setBusy(true);
    setNotice(null);
    try {
      await api.revokeCertificate(id);
      load();
    } catch (e) {
      setNotice((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (error) return <div className="card">Could not load this certificate: {error}</div>;
  if (!cert) return <p>Loading…</p>;

  return (
    <>
      <h1>{cert.common_name}</h1>
      <p className="page-lede">
        <StatusPill status={cert.status} /> · issued by {cert.ca_provider} · owned by {cert.owning_team}
      </p>

      {notice && <div className="card">{notice}</div>}

      <div className="card">
        <p>
          <strong>SANs:</strong> {cert.sans.join(", ")}
        </p>
        <p>
          <strong>Valid:</strong> {new Date(cert.not_before).toLocaleDateString()} –{" "}
          {new Date(cert.not_after).toLocaleDateString()}
        </p>
        <p>
          <strong>Key algorithm:</strong> {cert.key_algorithm} (held in Vault — never exportable)
        </p>
        <p>
          <strong>Validation method:</strong> {cert.validation_method}
        </p>
        <p>
          <strong>Auto-renew:</strong> {cert.auto_renew ? `yes, ${cert.renew_before_days} days before expiry` : "no"}
        </p>
        {(cert.organization || cert.organizational_unit || cert.locality || cert.state || cert.country) && (
          <p>
            <strong>Subject:</strong>{" "}
            {[cert.organization, cert.organizational_unit, cert.locality, cert.state, cert.country].filter(Boolean).join(", ")}
          </p>
        )}

        <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
          {hasScope("certs:export") && (
            <button className="secondary" disabled={busy} onClick={handleDownload}>
              Download certificate
            </button>
          )}
          {hasScope("certs:issue") && (
            <button className="secondary" disabled={busy} onClick={handleRenew}>
              Renew now
            </button>
          )}
          {hasScope("certs:admin") && cert.status !== "revoked" && (
            <button className="secondary" disabled={busy} onClick={handleRevoke}>
              Revoke
            </button>
          )}
        </div>
      </div>

      {hasScope("certs:issue") && (
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Expiry notification recipients</h3>
          <p style={{ fontSize: 13, color: "var(--muted)" }}>
            Overrides the default recipients in notification settings for this certificate only. Leave empty to use the defaults.
          </p>
          <div className="field">
            <label>Recipients (comma-separated)</label>
            <input
              value={notifyEmailsInput}
              onChange={(e) => setNotifyEmailsInput(e.target.value)}
              placeholder="team@example.com"
            />
          </div>
          <button className="secondary" disabled={busy} onClick={handleSaveNotifyEmails}>
            Save
          </button>
        </div>
      )}

      <h3>Crypto &amp; protocol posture</h3>
      <div className="card">
        {postureLoading && !posture && <p>Checking the certificate and probing the live TLS endpoint…</p>}
        {postureError && <p>Could not compute posture: {postureError}</p>}
        {posture && (
          <>
            <p>
              <strong>Signature algorithm:</strong> {posture.signature_algorithm}{" "}
              {WEAK_SIGNATURE_ALGORITHMS.some((w) => posture.signature_algorithm.toUpperCase().includes(w)) && (
                <span className="pill critical">weak</span>
              )}
            </p>
            <p>
              <strong>Key usage:</strong> {posture.key_usage.join(", ") || "—"}
            </p>
            {posture.ext_key_usage.length > 0 && (
              <p>
                <strong>Extended key usage:</strong> {posture.ext_key_usage.join(", ")}
              </p>
            )}
            <p>
              <strong>TLS versions observed:</strong>{" "}
              {posture.reachable ? (
                posture.tls_versions_supported.map((v) => (
                  <span key={v} className={`pill ${WEAK_TLS_VERSIONS.includes(v) ? "critical" : "ok"}`} style={{ marginRight: 6 }}>
                    {v}
                  </span>
                ))
              ) : (
                <span className="pill warn">{posture.probe_error || "not reachable"}</span>
              )}
            </p>
            {posture.reachable && (
              <>
                <p>
                  <strong>Cipher suite:</strong> {posture.cipher_suite || "—"}
                </p>
                <p>
                  <strong>OCSP stapling:</strong>{" "}
                  <span className={`pill ${posture.ocsp_stapled ? "ok" : "warn"}`}>
                    {posture.ocsp_stapled ? "stapled" : "not stapled"}
                  </span>
                </p>
              </>
            )}
            <p style={{ fontSize: 12, color: "var(--muted)" }}>Probed {new Date(posture.probed_at).toLocaleString()}</p>
          </>
        )}
      </div>

      <h3>Version history</h3>
      <table>
        <thead>
          <tr>
            <th>Issued</th>
            <th>Serial</th>
            <th>Fingerprint (SHA-256)</th>
          </tr>
        </thead>
        <tbody>
          {history.map((v) => (
            <tr key={v.id}>
              <td>{new Date(v.issued_at).toLocaleString()}</td>
              <td>{v.serial_number}</td>
              <td>{v.fingerprint_sha256.slice(0, 16)}…</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3>Notification history</h3>
      <table>
        <thead>
          <tr>
            <th>Sent</th>
            <th>Threshold</th>
            <th>Status</th>
            <th>Recipients</th>
          </tr>
        </thead>
        <tbody>
          {notifyLog.map((n) => (
            <tr key={n.id}>
              <td>{new Date(n.sent_at).toLocaleString()}</td>
              <td>{n.threshold_days}d</td>
              <td>
                <StatusPill status={n.status} />
              </td>
              <td>{n.recipients.join(", ") || "—"}</td>
            </tr>
          ))}
          {notifyLog.length === 0 && (
            <tr>
              <td colSpan={4}>No reminders sent yet.</td>
            </tr>
          )}
        </tbody>
      </table>

      <h3>Audit trail</h3>
      <table>
        <thead>
          <tr>
            <th>When</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Scope</th>
          </tr>
        </thead>
        <tbody>
          {auditLog.map((e, i) => (
            <tr key={i}>
              <td>{new Date(e.CreatedAt).toLocaleString()}</td>
              <td>{e.Actor}</td>
              <td>{e.Action}</td>
              <td>{e.Scope}</td>
            </tr>
          ))}
          {auditLog.length === 0 && (
            <tr>
              <td colSpan={4}>No audit events yet.</td>
            </tr>
          )}
        </tbody>
      </table>
    </>
  );
}
