import { useState } from "react";
import { useAuth } from "../auth/AuthContext";
import { api } from "../api/client";
import { ShieldCheckIcon, AlertTriangleIcon } from "../components/Icons";

// Rendered instead of the whole app (see App.tsx) whenever the signed-in
// account still has must_change_password set — most importantly, right
// after the very first login to the seeded default admin/admin account.
// There is no "skip" or "later": the backend itself refuses every other
// endpoint until this succeeds (see rbac.go RequirePasswordChange), so a
// skip button here would just be a dead end, not a real option.
export default function ChangePassword() {
  const { login, logout, identity } = useAuth();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (newPassword !== confirmPassword) {
      setError("the new password and confirmation don't match");
      return;
    }
    if (newPassword.length < 8) {
      setError("password must be at least 8 characters");
      return;
    }
    setLoading(true);
    try {
      const { token } = await api.changePassword(currentPassword, newPassword);
      login(token);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="auth-shell">
      <div className="auth-column">
        <div className="auth-brand">
          <span className="brand-mark">
            <ShieldCheckIcon width={20} height={20} />
          </span>
          <h1>Choose a new password</h1>
        </div>
        <p className="page-lede" style={{ marginTop: -14 }}>
          {identity?.email ?? "This account"} is still using an assigned password and must set its own before continuing.
        </p>

        <form className="card" onSubmit={submit}>
          {error && <div className="error-banner">{error}</div>}
          <div className="field">
            <label>Current password</label>
            <input type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} autoFocus />
          </div>
          <div className="field">
            <label>New password</label>
            <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="at least 8 characters" />
          </div>
          <div className="field">
            <label>Confirm new password</label>
            <input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} />
          </div>
          <button className="primary" type="submit" disabled={!currentPassword || !newPassword || loading} style={{ width: "100%", justifyContent: "center" }}>
            {loading ? "Updating…" : "Update password"}
          </button>
          <button className="secondary" type="button" style={{ marginTop: 8, width: "100%", justifyContent: "center" }} onClick={logout}>
            Sign out instead
          </button>
          <div className="callout accent">
            <AlertTriangleIcon width={14} height={14} />
            <span>This step is enforced by the server, not just this screen — there's no way to skip it.</span>
          </div>
        </form>
      </div>
    </div>
  );
}
