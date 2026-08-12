import { useEffect, useState } from "react";
import { api, DiscoveryResult, DiscoveryScan } from "../api/client";
import StatusPill from "../components/StatusPill";

export default function Discovery() {
  const [scans, setScans] = useState<DiscoveryScan[]>([]);
  const [selected, setSelected] = useState<DiscoveryScan | null>(null);
  const [results, setResults] = useState<DiscoveryResult[]>([]);
  const [error, setError] = useState<string | null>(null);

  const [name, setName] = useState("");
  const [targets, setTargets] = useState("");
  const [ports, setPorts] = useState("443");
  const [timeoutMs, setTimeoutMs] = useState(3000);
  const [submitting, setSubmitting] = useState(false);

  function refreshScans() {
    api
      .listScans()
      .then((s) => setScans(s ?? []))
      .catch((e) => setError(e.message));
  }

  useEffect(() => {
    refreshScans();
  }, []);

  // While any scan is still running, poll — a scan can take a while and
  // there's no push channel to tell us when it's done.
  useEffect(() => {
    if (!scans.some((s) => s.status === "pending" || s.status === "running")) return;
    const id = setInterval(refreshScans, 2000);
    return () => clearInterval(id);
  }, [scans]);

  useEffect(() => {
    if (!selected) return;
    const id = selected.id;
    api.getScan(id).then(setSelected).catch(() => {});
    api
      .listScanResults(id)
      .then((r) => setResults(r ?? []))
      .catch((e) => setError(e.message));
    const interval = setInterval(() => {
      api.getScan(id).then(setSelected).catch(() => {});
      api
        .listScanResults(id)
        .then((r) => setResults(r ?? []))
        .catch(() => {});
    }, 2000);
    return () => clearInterval(interval);
    // Re-run only when a different scan is selected — the effect's own
    // interval keeps that scan's rows fresh without re-subscribing.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected?.id]);

  async function submitScan() {
    setError(null);
    setSubmitting(true);
    try {
      const targetList = targets
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);
      const portList = ports
        .split(",")
        .map((p) => Number(p.trim()))
        .filter((p) => !Number.isNaN(p) && p > 0);
      const scan = await api.createScan({ name, targets: targetList, ports: portList, timeout_ms: timeoutMs });
      setName("");
      setTargets("");
      refreshScans();
      setSelected(scan);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSubmitting(false);
    }
  }

  async function cancelScan(id: string) {
    try {
      await api.cancelScan(id);
      refreshScans();
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <>
      <h1>Network discovery</h1>
      <p className="page-lede">
        Probe a bounded set of hosts/CIDRs and ports for live TLS endpoints, and reconcile what's actually being served against the inventory.
        This only performs a TLS handshake — no vulnerability scanning, no HTTP requests.
      </p>

      {error && <div className="card">{error}</div>}

      <div className="card">
        <h3 style={{ marginTop: 0 }}>New scan</h3>
        <div className="field">
          <label>Name</label>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Prod DMZ sweep" />
        </div>
        <div className="field">
          <label>Targets (comma-separated hosts, IPs, or CIDRs)</label>
          <input value={targets} onChange={(e) => setTargets(e.target.value)} placeholder="10.0.1.0/28, app.kron.com.tr" />
        </div>
        <div style={{ display: "flex", gap: 16 }}>
          <div className="field" style={{ flex: 1 }}>
            <label>Ports</label>
            <input value={ports} onChange={(e) => setPorts(e.target.value)} placeholder="443, 8443" />
          </div>
          <div className="field" style={{ width: 140 }}>
            <label>Timeout (ms)</label>
            <input type="number" min={200} max={30000} value={timeoutMs} onChange={(e) => setTimeoutMs(Number(e.target.value))} />
          </div>
        </div>
        <button className="primary" disabled={!name || !targets || submitting} onClick={submitScan}>
          {submitting ? "Starting…" : "Start scan"}
        </button>
      </div>

      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Status</th>
            <th>Progress</th>
            <th>Matched</th>
            <th>Mismatched</th>
            <th>Not in inventory</th>
            <th>Started</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {scans.map((s) => (
            <tr key={s.id} style={{ cursor: "pointer" }} onClick={() => setSelected(s)}>
              <td>{s.name}</td>
              <td>
                <StatusPill status={s.status} />
              </td>
              <td>
                {s.scanned_count}/{s.total_targets}
              </td>
              <td>{s.matched_count}</td>
              <td>{s.mismatch_count}</td>
              <td>{s.new_count}</td>
              <td>{s.started_at ? new Date(s.started_at).toLocaleString() : "—"}</td>
              <td>
                {(s.status === "pending" || s.status === "running") && (
                  <button
                    className="secondary"
                    onClick={(e) => {
                      e.stopPropagation();
                      cancelScan(s.id);
                    }}
                  >
                    Cancel
                  </button>
                )}
              </td>
            </tr>
          ))}
          {scans.length === 0 && (
            <tr>
              <td colSpan={8}>No scans yet.</td>
            </tr>
          )}
        </tbody>
      </table>

      {selected && (
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
            <h3 style={{ margin: 0 }}>{selected.name}</h3>
            <StatusPill status={selected.status} />
          </div>
          {selected.error && <p style={{ color: "var(--danger, #c0392b)" }}>{selected.error}</p>}
          <table>
            <thead>
              <tr>
                <th>Host</th>
                <th>Port</th>
                <th>Match</th>
                <th>Common name</th>
                <th>Issuer</th>
                <th>Expires</th>
                <th>TLS</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r) => (
                <tr key={r.id}>
                  <td>{r.host}</td>
                  <td>{r.port}</td>
                  <td>
                    <StatusPill status={r.match_status} />
                  </td>
                  <td>{r.common_name ?? "—"}</td>
                  <td>{r.issuer ?? "—"}</td>
                  <td>{r.not_after ? new Date(r.not_after).toLocaleDateString() : "—"}</td>
                  <td>{r.tls_version ?? "—"}</td>
                </tr>
              ))}
              {results.length === 0 && (
                <tr>
                  <td colSpan={7}>No results yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
