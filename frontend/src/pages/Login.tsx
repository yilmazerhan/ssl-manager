import { useState } from "react";
import { useAuth } from "../auth/AuthContext";
import { api } from "../api/client";

export default function Login() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const [devEmail, setDevEmail] = useState("");
  const [devRole, setDevRole] = useState("cert_manager");
  const [devTeam, setDevTeam] = useState("");
  const [devError, setDevError] = useState<string | null>(null);
  const [devLoading, setDevLoading] = useState(false);

  async function localLogin(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const { token } = await api.login(username, password);
      login(token);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  async function devLogin() {
    setDevLoading(true);
    setDevError(null);
    try {
      const { token } = await api.devLogin(devEmail, devRole, devTeam);
      login(token);
    } catch (e) {
      setDevError((e as Error).message);
    } finally {
      setDevLoading(false);
    }
  }

  return (
    <div style={{ maxWidth: 420, margin: "80px auto", padding: "0 20px" }}>
      <h1 style={{ marginBottom: 6 }}>SSL Sentry</h1>
      <p className="page-lede">Sign in to manage certificates.</p>

      <form className="card" onSubmit={localLogin}>
        {error && <p style={{ color: "var(--critical)" }}>{error}</p>}
        <div className="field">
          <label>Username</label>
          <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="admin" autoFocus />
        </div>
        <div className="field">
          <label>Password</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" />
        </div>
        <button className="primary" type="submit" disabled={!username || !password || loading}>
          {loading ? "Signing in…" : "Sign in"}
        </button>
        <p style={{ color: "var(--muted)", fontSize: 12.5, marginTop: 10, marginBottom: 0 }}>
          Default account is <code>admin</code> / <code>admin</code> — you'll be asked to change the password immediately.
        </p>
      </form>

      <div className="card">
        <a href="/auth/login" className="secondary" style={{ display: "inline-block", textDecoration: "none" }}>
          <button className="primary" type="button">
            Sign in with SSO
          </button>
        </a>
      </div>

      <p style={{ color: "var(--muted)", fontSize: 13, margin: "20px 0 8px" }}>
        No identity provider configured yet? Sign in directly (only works if the backend has dev auth enabled):
      </p>
      <div className="card">
        {devError && <p style={{ color: "var(--critical)" }}>{devError}</p>}
        <div className="field">
          <label>Email</label>
          <input value={devEmail} onChange={(e) => setDevEmail(e.target.value)} placeholder="you@example.com" />
        </div>
        <div className="field">
          <label>Role</label>
          <select value={devRole} onChange={(e) => setDevRole(e.target.value)}>
            <option value="viewer">Viewer</option>
            <option value="cert_manager">Cert Manager</option>
            <option value="admin">Admin</option>
          </select>
        </div>
        <div className="field">
          <label>Team</label>
          <input value={devTeam} onChange={(e) => setDevTeam(e.target.value)} placeholder="platform" />
        </div>
        <button className="primary" type="button" disabled={!devEmail || devLoading} onClick={devLogin}>
          {devLoading ? "Signing in…" : "Sign in"}
        </button>
      </div>
    </div>
  );
}
