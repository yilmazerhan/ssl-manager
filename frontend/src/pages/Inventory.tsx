import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, BulkImportItemResult, BulkItemResult, Certificate, CertificateFilter } from "../api/client";
import StatusPill from "../components/StatusPill";
import { useAuth } from "../auth/AuthContext";

const STATUSES = ["", "active", "expiring", "expired", "revoked"];
const PROVIDERS = ["", "letsencrypt", "zerossl", "manual"];

// Splits a textarea's worth of pasted PEM into individual certificate
// blocks — a bulk import is one or more `-----BEGIN CERTIFICATE-----`
// blocks concatenated, exactly how most CAs/tools already hand back a
// bundle.
function splitPEMCertificates(text: string): string[] {
  const matches = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
  return matches ?? [];
}

export default function Inventory() {
  const { identity, hasScope } = useAuth();
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState<CertificateFilter>({});
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkBusy, setBulkBusy] = useState(false);
  const [bulkNotice, setBulkNotice] = useState<string | null>(null);

  const [showImport, setShowImport] = useState(false);
  const [importPEM, setImportPEM] = useState("");
  const [importTeam, setImportTeam] = useState("");
  const [importResults, setImportResults] = useState<BulkImportItemResult[] | null>(null);
  const [importBusy, setImportBusy] = useState(false);

  const canFilterByTeam = identity?.role === "admin" || identity?.role === "api_only";
  const canRenew = hasScope("certs:issue");
  const canRevoke = hasScope("certs:admin");
  const canImport = hasScope("certs:issue");

  function refresh() {
    setLoading(true);
    api
      .listCertificates(filter)
      .then((c) => {
        setCerts(c);
        setError(null);
        setSelected(new Set());
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }

  useEffect(refresh, [filter]);

  function update<K extends keyof CertificateFilter>(key: K, value: CertificateFilter[K]) {
    setFilter((prev) => ({ ...prev, [key]: value || undefined }));
  }

  const hasActiveFilter = Object.values(filter).some((v) => v !== undefined && v !== "");

  function exportCSV() {
    const header = ["common_name", "sans", "ca_provider", "status", "not_after", "owning_team", "auto_renew"];
    const rows = certs.map((c) => [
      c.common_name,
      c.sans.join(";"),
      c.ca_provider,
      c.status,
      c.not_after,
      c.owning_team,
      String(c.auto_renew),
    ]);
    const csv = [header, ...rows].map((r) => r.map((v) => `"${v.replace(/"/g, '""')}"`).join(",")).join("\r\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `certificate-inventory-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function toggleSelected(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleSelectAll() {
    setSelected((prev) => (prev.size === certs.length ? new Set() : new Set(certs.map((c) => c.id))));
  }

  function summarizeBulkResults(action: string, results: BulkItemResult[]) {
    const failed = results.filter((r) => !r.success);
    if (failed.length === 0) {
      setBulkNotice(`${action}: all ${results.length} certificate(s) succeeded.`);
    } else {
      setBulkNotice(`${action}: ${results.length - failed.length} succeeded, ${failed.length} failed — ${failed.map((f) => f.error).join("; ")}`);
    }
  }

  async function bulkRenew() {
    setBulkBusy(true);
    setBulkNotice(null);
    try {
      const results = await api.bulkRenewCertificates([...selected]);
      summarizeBulkResults("Renew", results);
      refresh();
    } catch (e) {
      setBulkNotice((e as Error).message);
    } finally {
      setBulkBusy(false);
    }
  }

  async function bulkRevoke() {
    if (!window.confirm(`Revoke ${selected.size} certificate(s)? This cannot be undone.`)) return;
    setBulkBusy(true);
    setBulkNotice(null);
    try {
      const results = await api.bulkRevokeCertificates([...selected]);
      summarizeBulkResults("Revoke", results);
      refresh();
    } catch (e) {
      setBulkNotice((e as Error).message);
    } finally {
      setBulkBusy(false);
    }
  }

  async function submitImport() {
    setImportBusy(true);
    setImportResults(null);
    try {
      const certificates = splitPEMCertificates(importPEM).map((pem_cert) => ({ pem_cert, owning_team: importTeam }));
      const results = await api.bulkImportCertificates(certificates);
      setImportResults(results);
      refresh();
    } catch (e) {
      setImportResults([{ success: false, error: (e as Error).message }]);
    } finally {
      setImportBusy(false);
    }
  }

  const pemCount = splitPEMCertificates(importPEM).length;

  return (
    <>
      <h1>Certificate inventory</h1>
      <p className="page-lede">Every certificate the platform knows about.</p>

      {canImport && (
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
            <h3 style={{ margin: 0 }}>Bulk import</h3>
            {!showImport && (
              <button className="secondary" onClick={() => setShowImport(true)}>
                Import certificates
              </button>
            )}
          </div>
          {showImport && (
            <div style={{ marginTop: 12 }}>
              <p style={{ fontSize: 13, color: "var(--muted)" }}>
                Paste one or more PEM certificates (already issued elsewhere). They're tracked for expiry/inventory only — with no CA
                account behind them, this platform can't auto-renew them.
              </p>
              <div className="field">
                <label>Owning team</label>
                <input value={importTeam} onChange={(e) => setImportTeam(e.target.value)} placeholder="platform" />
              </div>
              <div className="field">
                <label>Certificates (PEM)</label>
                <textarea
                  rows={8}
                  value={importPEM}
                  onChange={(e) => setImportPEM(e.target.value)}
                  placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                  style={{ width: "100%", fontFamily: "monospace", fontSize: 12 }}
                />
                <p style={{ fontSize: 12, color: "var(--muted)" }}>{pemCount} certificate(s) detected.</p>
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <button className="primary" disabled={pemCount === 0 || !importTeam || importBusy} onClick={submitImport}>
                  {importBusy ? "Importing…" : `Import ${pemCount || ""}`.trim()}
                </button>
                <button
                  className="secondary"
                  onClick={() => {
                    setShowImport(false);
                    setImportPEM("");
                    setImportTeam("");
                    setImportResults(null);
                  }}
                >
                  Close
                </button>
              </div>
              {importResults && (
                <ul style={{ marginTop: 12, fontSize: 13 }}>
                  {importResults.map((r, i) => (
                    <li key={i} style={{ color: r.success ? "var(--ok, #2f8f5b)" : "var(--danger, #c0392b)" }}>
                      {r.success ? `Imported ${r.common_name ?? r.certificate_id}` : `Failed${r.common_name ? ` (${r.common_name})` : ""}: ${r.error}`}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>
      )}

      <div className="card" style={{ display: "flex", gap: 16, flexWrap: "wrap", alignItems: "flex-end" }}>
        {canFilterByTeam && (
          <div className="field" style={{ marginBottom: 0 }}>
            <label>Team</label>
            <input
              value={filter.team ?? ""}
              onChange={(e) => update("team", e.target.value)}
              placeholder="all teams"
            />
          </div>
        )}
        <div className="field" style={{ marginBottom: 0 }}>
          <label>Status</label>
          <select value={filter.status ?? ""} onChange={(e) => update("status", e.target.value)}>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {s === "" ? "All" : s}
              </option>
            ))}
          </select>
        </div>
        <div className="field" style={{ marginBottom: 0 }}>
          <label>Certificate authority</label>
          <select value={filter.ca_provider ?? ""} onChange={(e) => update("ca_provider", e.target.value)}>
            {PROVIDERS.map((p) => (
              <option key={p} value={p}>
                {p === "" ? "All" : p}
              </option>
            ))}
          </select>
        </div>
        <div className="field" style={{ marginBottom: 0 }}>
          <label>Expiring within (days)</label>
          <input
            type="number"
            min={0}
            value={filter.expiring_within_days ?? ""}
            onChange={(e) => update("expiring_within_days", e.target.value ? Number(e.target.value) : undefined)}
            placeholder="any"
            style={{ width: 100 }}
          />
        </div>
        {hasActiveFilter && (
          <button className="secondary" onClick={() => setFilter({})}>
            Clear filters
          </button>
        )}
        <button className="secondary" onClick={exportCSV} disabled={certs.length === 0}>
          Export CSV
        </button>
      </div>

      {error && <div className="card">Could not reach the API: {error}</div>}

      {selected.size > 0 && (canRenew || canRevoke) && (
        <div className="card" style={{ display: "flex", gap: 12, alignItems: "center" }}>
          <span>{selected.size} selected</span>
          {canRenew && (
            <button className="secondary" disabled={bulkBusy} onClick={bulkRenew}>
              {bulkBusy ? "Working…" : "Renew selected"}
            </button>
          )}
          {canRevoke && (
            <button className="secondary" disabled={bulkBusy} onClick={bulkRevoke}>
              {bulkBusy ? "Working…" : "Revoke selected"}
            </button>
          )}
        </div>
      )}
      {bulkNotice && <div className="card">{bulkNotice}</div>}

      <table>
        <thead>
          <tr>
            {(canRenew || canRevoke) && (
              <th>
                <input type="checkbox" checked={certs.length > 0 && selected.size === certs.length} onChange={toggleSelectAll} />
              </th>
            )}
            <th>Domain</th>
            <th>Issuer</th>
            <th>Status</th>
            <th>Expires</th>
            <th>Owning team</th>
          </tr>
        </thead>
        <tbody>
          {certs.map((c) => (
            <tr key={c.id}>
              {(canRenew || canRevoke) && (
                <td>
                  <input type="checkbox" checked={selected.has(c.id)} onChange={() => toggleSelected(c.id)} />
                </td>
              )}
              <td>
                <Link to={`/certificates/${c.id}`}>{c.common_name}</Link>
              </td>
              <td>{c.ca_provider}</td>
              <td>
                <StatusPill status={c.status} />
              </td>
              <td>{new Date(c.not_after).toLocaleDateString()}</td>
              <td>{c.owning_team}</td>
            </tr>
          ))}
          {!loading && certs.length === 0 && (
            <tr>
              <td colSpan={canRenew || canRevoke ? 6 : 5}>{hasActiveFilter ? "No certificates match these filters." : "No certificates yet — create one to get started."}</td>
            </tr>
          )}
        </tbody>
      </table>
    </>
  );
}
