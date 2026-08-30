import { useEffect, useState } from "react";
import { api, DiscoveryResult, DiscoverySchedule, DiscoveryScan, ScheduleRequest } from "../api/client";
import StatusPill from "../components/StatusPill";

const INTERVAL_PRESETS = [
  { label: "Every 15 minutes", minutes: 15 },
  { label: "Every hour", minutes: 60 },
  { label: "Every 6 hours", minutes: 6 * 60 },
  { label: "Daily", minutes: 24 * 60 },
  { label: "Weekly", minutes: 7 * 24 * 60 },
];

function intervalLabel(minutes: number): string {
  const preset = INTERVAL_PRESETS.find((p) => p.minutes === minutes);
  if (preset) return preset.label;
  if (minutes % (24 * 60) === 0) return `Every ${minutes / (24 * 60)} day(s)`;
  if (minutes % 60 === 0) return `Every ${minutes / 60} hour(s)`;
  return `Every ${minutes} minute(s)`;
}

const VULN_LABELS: Record<string, string> = {
  weak_tls_version: "weak TLS version",
  weak_signature_algorithm: "weak signature",
  expired_certificate: "expired",
};

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

  const [schedules, setSchedules] = useState<DiscoverySchedule[]>([]);
  const [scheduleError, setScheduleError] = useState<string | null>(null);
  const [showScheduleForm, setShowScheduleForm] = useState(false);
  const [editingScheduleID, setEditingScheduleID] = useState<string | null>(null);
  const [schName, setSchName] = useState("");
  const [schTargets, setSchTargets] = useState("");
  const [schPorts, setSchPorts] = useState("443");
  const [schIntervalMinutes, setSchIntervalMinutes] = useState(60);
  const [schSubmitting, setSchSubmitting] = useState(false);

  function refreshScans() {
    api
      .listScans()
      .then((s) => setScans(s ?? []))
      .catch((e) => setError(e.message));
  }

  function refreshSchedules() {
    api
      .listSchedules()
      .then((s) => setSchedules(s ?? []))
      .catch((e) => setScheduleError(e.message));
  }

  useEffect(() => {
    refreshScans();
    refreshSchedules();
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

  function resetScheduleForm() {
    setEditingScheduleID(null);
    setSchName("");
    setSchTargets("");
    setSchPorts("443");
    setSchIntervalMinutes(60);
    setShowScheduleForm(false);
  }

  function editSchedule(s: DiscoverySchedule) {
    setEditingScheduleID(s.id);
    setSchName(s.name);
    setSchTargets(s.targets.join(", "));
    setSchPorts(s.ports.join(", "));
    setSchIntervalMinutes(s.interval_minutes);
    setShowScheduleForm(true);
  }

  function scheduleRequestFromForm(enabled: boolean): ScheduleRequest {
    return {
      name: schName,
      targets: schTargets
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean),
      ports: schPorts
        .split(",")
        .map((p) => Number(p.trim()))
        .filter((p) => !Number.isNaN(p) && p > 0),
      interval_minutes: schIntervalMinutes,
      enabled,
    };
  }

  async function submitSchedule() {
    setScheduleError(null);
    setSchSubmitting(true);
    try {
      const req = scheduleRequestFromForm(true);
      if (editingScheduleID) {
        await api.updateSchedule(editingScheduleID, req);
      } else {
        await api.createSchedule(req);
      }
      resetScheduleForm();
      refreshSchedules();
    } catch (e) {
      setScheduleError((e as Error).message);
    } finally {
      setSchSubmitting(false);
    }
  }

  async function toggleSchedule(s: DiscoverySchedule) {
    try {
      await api.updateSchedule(s.id, {
        name: s.name,
        targets: s.targets,
        ports: s.ports,
        timeout_ms: s.timeout_ms,
        concurrency: s.concurrency,
        interval_minutes: s.interval_minutes,
        enabled: !s.enabled,
      });
      refreshSchedules();
    } catch (e) {
      setScheduleError((e as Error).message);
    }
  }

  async function deleteSchedule(id: string) {
    try {
      await api.deleteSchedule(id);
      refreshSchedules();
    } catch (e) {
      setScheduleError((e as Error).message);
    }
  }

  return (
    <>
      <h1>Network discovery</h1>
      <p className="page-lede">
        Probe a bounded set of hosts/CIDRs and ports for live TLS endpoints, and reconcile what's actually being served against the inventory.
        Every probe also classifies what the handshake itself reveals — a weak signature algorithm, a deprecated TLS version, an expired
        certificate — without making any HTTP request.
      </p>

      {scheduleError && <div className="card">{scheduleError}</div>}

      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
          <h3 style={{ margin: 0 }}>Scheduled scans</h3>
          {!showScheduleForm && (
            <button className="secondary" onClick={() => setShowScheduleForm(true)}>
              New schedule
            </button>
          )}
        </div>

        {showScheduleForm && (
          <div style={{ marginTop: 12 }}>
            <div className="field">
              <label>Name</label>
              <input value={schName} onChange={(e) => setSchName(e.target.value)} placeholder="Weekly DMZ sweep" />
            </div>
            <div className="field">
              <label>Targets (comma-separated hosts, IPs, or CIDRs)</label>
              <input value={schTargets} onChange={(e) => setSchTargets(e.target.value)} placeholder="10.0.1.0/28, app.kron.com.tr" />
            </div>
            <div style={{ display: "flex", gap: 16 }}>
              <div className="field" style={{ flex: 1 }}>
                <label>Ports</label>
                <input value={schPorts} onChange={(e) => setSchPorts(e.target.value)} placeholder="443, 8443" />
              </div>
              <div className="field" style={{ flex: 1 }}>
                <label>Interval</label>
                <select value={schIntervalMinutes} onChange={(e) => setSchIntervalMinutes(Number(e.target.value))}>
                  {INTERVAL_PRESETS.map((p) => (
                    <option key={p.minutes} value={p.minutes}>
                      {p.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button className="primary" disabled={!schName || !schTargets || schSubmitting} onClick={submitSchedule}>
                {schSubmitting ? "Saving…" : editingScheduleID ? "Save changes" : "Create schedule"}
              </button>
              <button className="secondary" onClick={resetScheduleForm}>
                Cancel
              </button>
            </div>
          </div>
        )}

        <table style={{ marginTop: showScheduleForm ? 20 : 12 }}>
          <thead>
            <tr>
              <th>Name</th>
              <th>Interval</th>
              <th>Status</th>
              <th>Last run</th>
              <th>Next run</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {schedules.map((s) => (
              <tr key={s.id}>
                <td style={{ whiteSpace: "nowrap" }}>{s.name}</td>
                <td style={{ whiteSpace: "nowrap" }}>{intervalLabel(s.interval_minutes)}</td>
                <td>
                  <span className={`pill ${s.enabled ? "ok" : "warn"}`}>{s.enabled ? "active" : "paused"}</span>
                </td>
                <td>{s.last_run_at ? new Date(s.last_run_at).toLocaleString() : "never"}</td>
                <td>{s.enabled ? new Date(s.next_run_at).toLocaleString() : "—"}</td>
                <td style={{ display: "flex", gap: 6 }}>
                  <button className="secondary" onClick={() => toggleSchedule(s)}>
                    {s.enabled ? "Pause" : "Resume"}
                  </button>
                  <button className="secondary" onClick={() => editSchedule(s)}>
                    Edit
                  </button>
                  <button className="secondary" onClick={() => deleteSchedule(s.id)}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
            {schedules.length === 0 && (
              <tr>
                <td colSpan={6}>No scheduled scans yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

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

      <h3>Scan history</h3>
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
                <th>Vulnerabilities</th>
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
                  <td>
                    {!r.reachable || r.match_status === "no_tls" ? (
                      "—"
                    ) : r.vulnerabilities && r.vulnerabilities.length > 0 ? (
                      r.vulnerabilities.map((v) => (
                        <span key={v} className="pill critical" style={{ marginRight: 6 }}>
                          {VULN_LABELS[v] ?? v}
                        </span>
                      ))
                    ) : (
                      <span className="pill ok">clean</span>
                    )}
                  </td>
                </tr>
              ))}
              {results.length === 0 && (
                <tr>
                  <td colSpan={8}>No results yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
