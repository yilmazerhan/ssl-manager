import { useState } from "react";
import { useAuth } from "../auth/AuthContext";
import { api } from "../api/client";

export default function Login() {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("cert_manager");
  const [team, setTeam] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function devLogin() {
    setLoading(true);
    setError(null);
    try {
      const { token } = await api.devLogin(email, role, team);
      login(token);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ maxWidth: 420, margin: "80px auto", padding: "0 20px" }}>
      <h1 style={{ marginBottom: 6 }}>SSL Sentry</h1>
      <p className="page-lede">Sign in to manage certificates.</p>

      <div className="card">
        <a href="/auth/login" className="secondary" style={{ display: "inline-block", textDecoration: "none" }}>
          <button className="primary">Sign in with SSO</button>
        </a>
      </div>

      <p style={{ color: "var(--muted)", fontSize: 13, margin: "20px 0 8px" }}>
        No identity provider configured yet? Sign in directly (only works if the backend has dev auth enabled):
      </p>
      <div className="card">
        {error && <p style={{ color: "var(--critical)" }}>{error}</p>}
        <div className="field">
          <label>Email</label>
          <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" />
        </div>
        <div className="field">
          <label>Role</label>
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="viewer">Viewer</option>
            <option value="cert_manager">Cert Manager</option>
            <option value="admin">Admin</option>
          </select>
        </div>
        <div className="field">
          <label>Team</label>
          <input value={team} onChange={(e) => setTeam(e.target.value)} placeholder="platform" />
        </div>
        <button className="primary" disabled={!email || loading} onClick={devLogin}>
          {loading ? "Signing in…" : "Sign in"}
        </button>
      </div>
    </div>
  );
}
