import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, Certificate } from "../api/client";
import StatusPill from "../components/StatusPill";

export default function Inventory() {
  const [certs, setCerts] = useState<Certificate[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listCertificates().then(setCerts).catch((e) => setError(e.message));
  }, []);

  return (
    <>
      <h1>Certificate inventory</h1>
      <p className="page-lede">Every certificate the platform knows about.</p>
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
          {certs.length === 0 && (
            <tr>
              <td colSpan={5}>No certificates yet — create one to get started.</td>
            </tr>
          )}
        </tbody>
      </table>
    </>
  );
}
