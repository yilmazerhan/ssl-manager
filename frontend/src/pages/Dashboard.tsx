import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, Certificate, DiscoveryResult, Stats } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import StatusPill from "../components/StatusPill";

function daysUntil(iso: string): number {
  return Math.ceil((new Date(iso).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
}

export default function Dashboard() {
  const { identity } = useAuth();
  const isAdmin = identity?.role === "admin";
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [mismatches, setMismatches] = useState<DiscoveryResult[]>([]);
  const [notifications, setNotifications] = useState<{ sent: number; failed: number } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listCertificates().then(setCerts).catch((e) => setError(e.message));
    api
      .getSummaryReport()
      .then((r) => {
        setStats(r.certificates);
        if (r.discovery_mismatches !== undefined) setMismatches(r.discovery_mismatches ?? []);
        if (r.notifications_sent_30d !== undefined || r.notifications_failed_30d !== undefined) {
          setNotifications({ sent: r.notifications_sent_30d ?? 0, failed: r.notifications_failed_30d ?? 0 });
        }
      })
      .catch((e) => setError(e.message));
  }, []);

  const expiringSoon = certs.filter((c) => daysUntil(c.not_after) <= 30 && c.status !== "revoked");

  return (
    <>
      <h1>Dashboard</h1>
      <p className="page-lede">What's about to expire, how the inventory breaks down, and what discovery has found that doesn't match.</p>
      {error && <div className="card">Could not reach the API: {error}</div>}

      {stats && (
        <div className="stat-grid">
          <div className="stat-tile">
            <div className="stat-value">{stats.total}</div>
            <div className="stat-label">Total certificates</div>
          </div>
          <div className="stat-tile warn">
            <div className="stat-value">{stats.expiring_in_7d}</div>
            <div className="stat-label">Expiring within 7 days</div>
          </div>
          <div className="stat-tile warn">
            <div className="stat-value">{stats.expiring_in_30d}</div>
            <div className="stat-label">Expiring within 30 days</div>
          </div>
          <div className="stat-tile critical">
            <div className="stat-value">{stats.by_status.expired ?? 0}</div>
            <div className="stat-label">Expired</div>
          </div>
          <div className="stat-tile critical">
            <div className="stat-value">{stats.by_status.revoked ?? 0}</div>
            <div className="stat-label">Revoked</div>
          </div>
          {isAdmin && mismatches.length > 0 && (
            <div className="stat-tile warn">
              <div className="stat-value">{mismatches.length}</div>
              <div className="stat-label">Discovery mismatches</div>
            </div>
          )}
        </div>
      )}

      {stats && (
        <div className="card" style={{ display: "flex", gap: 32, flexWrap: "wrap" }}>
          <div style={{ minWidth: 180 }}>
            <h3 style={{ marginTop: 0, fontSize: 14 }}>By certificate authority</h3>
            <div className="breakdown-list">
              {Object.entries(stats.by_ca_provider).map(([provider, count]) => (
                <div className="breakdown-row" key={provider}>
                  <span>{provider}</span>
                  <span className="breakdown-count">{count}</span>
                </div>
              ))}
            </div>
          </div>
          {isAdmin && Object.keys(stats.by_team).length > 0 && (
            <div style={{ minWidth: 180 }}>
              <h3 style={{ marginTop: 0, fontSize: 14 }}>By team</h3>
              <div className="breakdown-list">
                {Object.entries(stats.by_team).map(([team, count]) => (
                  <div className="breakdown-row" key={team}>
                    <span>{team}</span>
                    <span className="breakdown-count">{count}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          {isAdmin && notifications && (
            <div style={{ minWidth: 180 }}>
              <h3 style={{ marginTop: 0, fontSize: 14 }}>Notifications (30d)</h3>
              <div className="breakdown-list">
                <div className="breakdown-row">
                  <span>Sent</span>
                  <span className="breakdown-count">{notifications.sent}</span>
                </div>
                <div className="breakdown-row">
                  <span>Failed</span>
                  <span className="breakdown-count">{notifications.failed}</span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      <h3>Expiring within 30 days</h3>
      <table>
        <thead>
          <tr>
            <th>Domain</th>
            <th>Issuer</th>
            <th>Expires</th>
            <th>Owning team</th>
          </tr>
        </thead>
        <tbody>
          {expiringSoon.map((c) => (
            <tr key={c.id}>
              <td>
                <Link to={`/certificates/${c.id}`}>{c.common_name}</Link>
              </td>
              <td>{c.ca_provider}</td>
              <td>{daysUntil(c.not_after)} days</td>
              <td>{c.owning_team}</td>
            </tr>
          ))}
          {expiringSoon.length === 0 && (
            <tr>
              <td colSpan={4}>Nothing expiring soon.</td>
            </tr>
          )}
        </tbody>
      </table>

      {isAdmin && mismatches.length > 0 && (
        <>
          <h3>Discovery mismatches</h3>
          <p className="page-lede">Endpoints found by network discovery that don't match, or aren't in, the certificate inventory.</p>
          <table>
            <thead>
              <tr>
                <th>Host</th>
                <th>Port</th>
                <th>Match</th>
                <th>Common name</th>
                <th>Discovered</th>
              </tr>
            </thead>
            <tbody>
              {mismatches.slice(0, 10).map((m) => (
                <tr key={m.id}>
                  <td>{m.host}</td>
                  <td>{m.port}</td>
                  <td>
                    <StatusPill status={m.match_status} />
                  </td>
                  <td>{m.common_name ?? "—"}</td>
                  <td>{new Date(m.discovered_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="page-lede" style={{ marginTop: 8 }}>
            <Link to="/admin/discovery">See the full discovery history →</Link>
          </p>
        </>
      )}
    </>
  );
}
