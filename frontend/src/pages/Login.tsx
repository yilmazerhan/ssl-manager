import { useState } from "react";
import { useAuth } from "../auth/AuthContext";
import { api } from "../api/client";
import { ShieldCheckIcon, AlertTriangleIcon, PlugIcon } from "../components/Icons";

export default function Login() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const [showDevLogin, setShowDevLogin] = useState(false);
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
    <div className="auth-shell">
      <div className="auth-column">
        <div className="auth-brand">
          <span className="brand-mark">
            <ShieldCheckIcon width={20} height={20} />
          </span>
          <h1>SSL Sentry</h1>
        </div>
        <p className="page-lede" style={{ marginTop: -14 }}>
          Sign in to manage certificates.
        </p>

        <form className="card" onSubmit={localLogin}>
          {error && <div className="error-banner">{error}</div>}
          <div className="field">
            <label>Username</label>
            <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="admin" autoFocus />
          </div>
          <div className="field">
            <label>Password</label>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" />
          </div>
          <button className="primary" type="submit" disabled={!username || !password || loading} style={{ width: "100%", justifyContent: "center" }}>
            {loading ? "Signing in…" : "Sign in"}
          </button>
          <div className="callout warn">
            <AlertTriangleIcon width={14} height={14} />
            <span>
              Default account is <code>admin</code> / <code>admin</code> — you'll be asked to change the password immediately.
            </span>
          </div>
        </form>

        <div className="auth-divider">or</div>

        <a href="/auth/login" style={{ display: "block", textDecoration: "none" }}>
          <button className="primary" type="button" style={{ width: "100%", justifyContent: "center" }}>
            <PlugIcon width={16} height={16} />
            Sign in with SSO
          </button>
        </a>

        <div className="auth-alt">
          <button className="auth-alt-toggle" type="button" onClick={() => setShowDevLogin((v) => !v)}>
            {showDevLogin ? "Hide developer sign-in" : "No identity provider yet? Use developer sign-in"}
          </button>
          {showDevLogin && (
            <div className="card" style={{ marginTop: 12 }}>
              <p className="page-lede" style={{ marginTop: 0, fontSize: 13 }}>
                Only works if the backend has dev auth enabled.
              </p>
              {devError && <div className="error-banner">{devError}</div>}
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
              <button className="secondary" type="button" disabled={!devEmail || devLoading} onClick={devLogin}>
                {devLoading ? "Signing in…" : "Sign in"}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
