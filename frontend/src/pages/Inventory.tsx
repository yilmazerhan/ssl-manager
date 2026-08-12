import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, Certificate, CertificateFilter } from "../api/client";
import StatusPill from "../components/StatusPill";
import { useAuth } from "../auth/AuthContext";

const STATUSES = ["", "active", "expiring", "expired", "revoked"];
const PROVIDERS = ["", "letsencrypt", "zerossl", "manual"];

export default function Inventory() {
  const { identity } = useAuth();
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState<CertificateFilter>({});

  const canFilterByTeam = identity?.role === "admin" || identity?.role === "api_only";

  useEffect(() => {
    setLoading(true);
    api
      .listCertificates(filter)
      .then((c) => {
        setCerts(c);
        setError(null);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [filter]);

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

  return (
    <>
      <h1>Certificate inventory</h1>
      <p className="page-lede">Every certificate the platform knows about.</p>

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

      <table>
        <thead>
          <tr>
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
              <td colSpan={5}>{hasActiveFilter ? "No certificates match these filters." : "No certificates yet — create one to get started."}</td>
            </tr>
          )}
        </tbody>
      </table>
    </>
  );
}
