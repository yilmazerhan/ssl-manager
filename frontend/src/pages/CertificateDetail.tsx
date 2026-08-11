import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api, AuditEntry, Certificate, CertificateVersion, downloadPEM } from "../api/client";
import StatusPill from "../components/StatusPill";
import { useAuth } from "../auth/AuthContext";

export default function CertificateDetail() {
  const { id } = useParams<{ id: string }>();
  const { hasScope } = useAuth();
  const [cert, setCert] = useState<Certificate | null>(null);
  const [history, setHistory] = useState<CertificateVersion[]>([]);
  const [auditLog, setAuditLog] = useState<AuditEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function load() {
    if (!id) return;
    Promise.all([api.getCertificate(id), api.getHistory(id), api.getAudit(id)])
      .then(([c, h, a]) => {
        setCert(c);
        setHistory(h);
        setAuditLog(a ?? []);
      })
      .catch((e) => setError(e.message));
  }

  useEffect(load, [id]);

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
