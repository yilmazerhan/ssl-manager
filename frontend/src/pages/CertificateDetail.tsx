import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import {
  api,
  AuditEntry,
  Certificate,
  CertificatePosture,
  CertificateVersion,
  K8sTarget,
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

  const [k8sTargets, setK8sTargets] = useState<K8sTarget[]>([]);
  const [k8sError, setK8sError] = useState<string | null>(null);
  const [showK8sForm, setShowK8sForm] = useState(false);
  const [editingTargetID, setEditingTargetID] = useState<string | null>(null);
  const [k8sName, setK8sName] = useState("");
  const [k8sClusterURL, setK8sClusterURL] = useState("");
  const [k8sToken, setK8sToken] = useState("");
  const [k8sNamespace, setK8sNamespace] = useState("");
  const [k8sSecretName, setK8sSecretName] = useState("");
  const [k8sInsecureSkipVerify, setK8sInsecureSkipVerify] = useState(false);
  const [k8sBusy, setK8sBusy] = useState(false);

  function refreshK8sTargets() {
    if (!id) return;
    api
      .listK8sTargets(id)
      .then((t) => setK8sTargets(t ?? []))
      .catch((e) => setK8sError(e.message));
  }

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

  useEffect(refreshK8sTargets, [id]);

  function resetK8sForm() {
    setEditingTargetID(null);
    setK8sName("");
    setK8sClusterURL("");
    setK8sToken("");
    setK8sNamespace("");
    setK8sSecretName("");
    setK8sInsecureSkipVerify(false);
    setShowK8sForm(false);
  }

  function editK8sTarget(t: K8sTarget) {
    setEditingTargetID(t.id);
    setK8sName(t.name);
    setK8sClusterURL(t.cluster_url);
    setK8sToken("");
    setK8sNamespace(t.namespace);
    setK8sSecretName(t.secret_name);
    setK8sInsecureSkipVerify(t.insecure_skip_verify);
    setShowK8sForm(true);
  }

  async function submitK8sTarget() {
    if (!id) return;
    setK8sError(null);
    setK8sBusy(true);
    try {
      const req = {
        name: k8sName,
        cluster_url: k8sClusterURL,
        token: k8sToken || undefined,
        namespace: k8sNamespace,
        secret_name: k8sSecretName,
        insecure_skip_verify: k8sInsecureSkipVerify,
        enabled: true,
      };
      if (editingTargetID) {
        await api.updateK8sTarget(id, editingTargetID, req);
      } else {
        await api.createK8sTarget(id, req);
      }
      resetK8sForm();
      refreshK8sTargets();
    } catch (e) {
      setK8sError((e as Error).message);
    } finally {
      setK8sBusy(false);
    }
  }

  async function deleteK8sTarget(targetId: string) {
    if (!id) return;
    try {
      await api.deleteK8sTarget(id, targetId);
      refreshK8sTargets();
    } catch (e) {
      setK8sError((e as Error).message);
    }
  }

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
          <strong>Key algorithm:</strong> {cert.key_algorithm} (held in Vault —{" "}
          {cert.key_exportable ? "exportable, for Kubernetes sync only" : "never exportable"})
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

      <h3>Kubernetes sync targets</h3>
      <div className="card">
        {!cert.key_exportable ? (
          <p style={{ fontSize: 13, color: "var(--muted)" }}>
            This certificate's key isn't exportable, so it can't be synced to a Kubernetes Secret — a Secret needs the raw private key,
            and this platform's Vault key was created non-exportable (the default). Re-issue this certificate with "Sync to Kubernetes"
            checked to enable this.
          </p>
        ) : (
          <>
            {k8sError && <p style={{ color: "var(--danger, #c0392b)" }}>{k8sError}</p>}
            {hasScope("certs:admin") && !showK8sForm && (
              <button className="secondary" onClick={() => setShowK8sForm(true)} style={{ marginBottom: 12 }}>
                Add target
              </button>
            )}
            {showK8sForm && (
              <div style={{ marginBottom: 16 }}>
                <div className="field">
                  <label>Name</label>
                  <input value={k8sName} onChange={(e) => setK8sName(e.target.value)} placeholder="prod-cluster" />
                </div>
                <div className="field">
                  <label>Cluster API URL</label>
                  <input value={k8sClusterURL} onChange={(e) => setK8sClusterURL(e.target.value)} placeholder="https://10.0.0.1:6443" />
                </div>
                <div className="field">
                  <label>Bearer token{editingTargetID ? " (leave blank to keep the current one)" : ""}</label>
                  <input type="password" value={k8sToken} onChange={(e) => setK8sToken(e.target.value)} />
                </div>
                <div style={{ display: "flex", gap: 16 }}>
                  <div className="field" style={{ flex: 1 }}>
                    <label>Namespace</label>
                    <input value={k8sNamespace} onChange={(e) => setK8sNamespace(e.target.value)} placeholder="default" />
                  </div>
                  <div className="field" style={{ flex: 1 }}>
                    <label>Secret name</label>
                    <input value={k8sSecretName} onChange={(e) => setK8sSecretName(e.target.value)} placeholder="app-tls" />
                  </div>
                </div>
                <label style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 13, marginBottom: 12 }}>
                  <input type="checkbox" checked={k8sInsecureSkipVerify} onChange={(e) => setK8sInsecureSkipVerify(e.target.checked)} />
                  Skip TLS verification when connecting to this cluster's API server
                </label>
                <div style={{ display: "flex", gap: 8 }}>
                  <button
                    className="primary"
                    disabled={!k8sName || !k8sClusterURL || !k8sNamespace || !k8sSecretName || (!editingTargetID && !k8sToken) || k8sBusy}
                    onClick={submitK8sTarget}
                  >
                    {k8sBusy ? "Saving…" : editingTargetID ? "Save changes" : "Add target"}
                  </button>
                  <button className="secondary" onClick={resetK8sForm}>
                    Cancel
                  </button>
                </div>
              </div>
            )}
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Namespace / Secret</th>
                  <th>Status</th>
                  <th>Last synced</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {k8sTargets.map((t) => (
                  <tr key={t.id}>
                    <td>{t.name}</td>
                    <td>
                      {t.namespace}/{t.secret_name}
                    </td>
                    <td>
                      {!t.enabled ? (
                        <span className="pill warn">paused</span>
                      ) : t.last_sync_error ? (
                        <span className="pill critical" title={t.last_sync_error}>
                          error
                        </span>
                      ) : t.last_synced_at ? (
                        <span className="pill ok">synced</span>
                      ) : (
                        <span className="pill accent">pending</span>
                      )}
                    </td>
                    <td>{t.last_synced_at ? new Date(t.last_synced_at).toLocaleString() : "never"}</td>
                    <td style={{ display: "flex", gap: 6 }}>
                      {hasScope("certs:admin") && (
                        <>
                          <button className="secondary" onClick={() => editK8sTarget(t)}>
                            Edit
                          </button>
                          <button className="secondary" onClick={() => deleteK8sTarget(t.id)}>
                            Delete
                          </button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
                {k8sTargets.length === 0 && (
                  <tr>
                    <td colSpan={5}>No Kubernetes sync targets yet.</td>
                  </tr>
                )}
              </tbody>
            </table>
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
