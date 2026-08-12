import { useState } from "react";
import { useAuth } from "../auth/AuthContext";
import { api } from "../api/client";

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
    <div style={{ maxWidth: 420, margin: "80px auto", padding: "0 20px" }}>
      <h1 style={{ marginBottom: 6 }}>Choose a new password</h1>
      <p className="page-lede">
        {identity?.email ?? "This account"} is still using an assigned password and must set its own before continuing.
      </p>

      <form className="card" onSubmit={submit}>
        {error && <p style={{ color: "var(--critical)" }}>{error}</p>}
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
        <button className="primary" type="submit" disabled={!currentPassword || !newPassword || loading}>
          {loading ? "Updating…" : "Update password"}
        </button>
        <button className="secondary" type="button" style={{ marginTop: 8, width: "100%" }} onClick={logout}>
          Sign out instead
        </button>
      </form>
    </div>
  );
}
