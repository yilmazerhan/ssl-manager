import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api, Certificate, CertificateVersion } from "../api/client";
import StatusPill from "../components/StatusPill";

export default function CertificateDetail() {
  const { id } = useParams<{ id: string }>();
  const [cert, setCert] = useState<Certificate | null>(null);
  const [history, setHistory] = useState<CertificateVersion[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    Promise.all([api.getCertificate(id), api.getHistory(id)])
      .then(([c, h]) => {
        setCert(c);
        setHistory(h);
      })
      .catch((e) => setError(e.message));
  }, [id]);

  if (error) return <div className="card">Could not load this certificate: {error}</div>;
  if (!cert) return <p>Loading…</p>;

  return (
    <>
      <h1>{cert.common_name}</h1>
      <p className="page-lede">
        <StatusPill status={cert.status} /> · issued by {cert.ca_provider} · owned by {cert.owning_team}
      </p>

      <div className="card">
        <p>
          <strong>SANs:</strong> {cert.sans.join(", ")}
        </p>
        <p>
          <strong>Valid:</strong> {new Date(cert.not_before).toLocaleDateString()} –{" "}
          {new Date(cert.not_after).toLocaleDateString()}
        </p>
        <p>
          <strong>Key algorithm:</strong> {cert.key_algorithm}
        </p>
        <p>
          <strong>Auto-renew:</strong> {cert.auto_renew ? `yes, ${cert.renew_before_days} days before expiry` : "no"}
        </p>
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
    </>
  );
}
