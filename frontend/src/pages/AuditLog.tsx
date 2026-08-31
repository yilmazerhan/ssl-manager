import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, AuditEntry } from "../api/client";
import { summarizeAuditMetadata } from "../lib/auditFormat";

const RESOURCES = [
  { value: "", label: "All resources" },
  { value: "certificate", label: "Certificates (issuance, renewal, K8s/WinRM sync)" },
  { value: "certificate_order", label: "Certificate orders" },
  { value: "discovery_scan", label: "SSL discovery scans" },
  { value: "discovery_schedule", label: "SSL discovery schedules" },
  { value: "user", label: "Users & API keys" },
  { value: "notification_settings", label: "Notification settings" },
];

const LIMITS = [50, 100, 200, 500];

export default function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [resource, setResource] = useState("");
  const [action, setAction] = useState("");
  const [limit, setLimit] = useState(200);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  function load() {
    setLoading(true);
    setError(null);
    api
      .listAuditLog({ resource: resource || undefined, action: action.trim() || undefined, limit })
      .then((e) => setEntries(e ?? []))
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }

  useEffect(load, [resource, limit]);

  return (
    <>
      <h1>Audit log</h1>
      <p className="page-lede">
        Every recorded action across the platform — certificate issuance and renewal, which servers/services got a certificate pushed to
        them (and whether it worked), SSL discovery scans, and administrative changes.
      </p>

      <div className="card">
        <div style={{ display: "flex", gap: 16, flexWrap: "wrap", alignItems: "flex-end" }}>
          <div className="field" style={{ minWidth: 260 }}>
            <label>Resource</label>
            <select value={resource} onChange={(e) => setResource(e.target.value)}>
              {RESOURCES.map((r) => (
                <option key={r.value} value={r.value}>
                  {r.label}
                </option>
              ))}
            </select>
          </div>
          <div className="field" style={{ minWidth: 220 }}>
            <label>Action contains</label>
            <input
              value={action}
              onChange={(e) => setAction(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && load()}
              placeholder="e.g. sync_failed, renewal, issued"
            />
          </div>
          <div className="field">
            <label>Show</label>
            <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
              {LIMITS.map((l) => (
                <option key={l} value={l}>
                  last {l}
                </option>
              ))}
            </select>
          </div>
          <button className="secondary" onClick={load} disabled={loading}>
            {loading ? "Loading…" : "Refresh"}
          </button>
        </div>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <table>
        <thead>
          <tr>
            <th>When</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Resource</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((e, i) => (
            <tr key={i}>
              <td>{new Date(e.CreatedAt).toLocaleString()}</td>
              <td>{e.Actor}</td>
              <td>{e.Action}</td>
              <td>
                {e.Resource === "certificate" && e.ResourceID ? (
                  <Link to={`/certificates/${e.ResourceID}`}>certificate</Link>
                ) : (
                  e.Resource
                )}
              </td>
              <td>{summarizeAuditMetadata(e)}</td>
            </tr>
          ))}
          {entries.length === 0 && !loading && (
            <tr>
              <td colSpan={5}>No matching audit events.</td>
            </tr>
          )}
        </tbody>
      </table>
    </>
  );
}
