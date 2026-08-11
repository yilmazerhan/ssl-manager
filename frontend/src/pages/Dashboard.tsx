import { useEffect, useState } from "react";
import { api, Certificate } from "../api/client";

function daysUntil(iso: string): number {
  return Math.ceil((new Date(iso).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
}

export default function Dashboard() {
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listCertificates().then(setCerts).catch((e) => setError(e.message));
  }, []);

  const expiringSoon = certs.filter((c) => daysUntil(c.not_after) <= 30);

  return (
    <>
      <h1>Dashboard</h1>
      <p className="page-lede">What's about to expire, and how the inventory breaks down by issuer.</p>
      {error && <div className="card">Could not reach the API: {error}</div>}

      <div className="card">
        <strong>{expiringSoon.length}</strong> certificate{expiringSoon.length === 1 ? "" : "s"} expiring within 30 days
      </div>

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
              <td>{c.common_name}</td>
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
    </>
  );
}
