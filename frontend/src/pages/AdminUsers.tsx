import { useEffect, useState } from "react";
import { api, AppUser } from "../api/client";

const ROLES = ["viewer", "cert_manager", "admin", "api_only"];

export default function AdminUsers() {
  const [users, setUsers] = useState<AppUser[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [newKey, setNewKey] = useState<{ userId: string; key: string } | null>(null);
  const [keyName, setKeyName] = useState("");
  const [keyScopes, setKeyScopes] = useState<string[]>(["certs:read"]);
  const [creatingKeyFor, setCreatingKeyFor] = useState<string | null>(null);

  function load() {
    api.listUsers().then(setUsers).catch((e) => setError(e.message));
  }
  useEffect(load, []);

  async function updateUser(user: AppUser, role: string, team: string) {
    setBusyId(user.id);
    setError(null);
    try {
      await api.setUserRole(user.id, role, team);
      load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusyId(null);
    }
  }

  async function submitAPIKey(userId: string) {
    setError(null);
    try {
      const { key } = await api.createAPIKey(userId, keyName || "api key", keyScopes);
      setNewKey({ userId, key });
      setCreatingKeyFor(null);
      setKeyName("");
    } catch (e) {
      setError((e as Error).message);
    }
  }

  function toggleScope(scope: string) {
    setKeyScopes((prev) => (prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope]));
  }

  return (
    <>
      <h1>Users</h1>
      <p className="page-lede">Roles, teams, and API keys.</p>

      {error && <div className="card">{error}</div>}

      {newKey && (
        <div className="card">
          <p>
            <strong>API key created.</strong> Copy it now — it won't be shown again.
          </p>
          <code className="challenge-value">{newKey.key}</code>
          <button className="secondary" onClick={() => setNewKey(null)}>
            Done
          </button>
        </div>
      )}

      <table>
        <thead>
          <tr>
            <th>Email</th>
            <th>Role</th>
            <th>Team</th>
            <th>Since</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id}>
              <td>{u.email}</td>
              <td>
                <select
                  value={u.role}
                  disabled={busyId === u.id}
                  onChange={(e) => updateUser(u, e.target.value, u.team ?? "")}
                >
                  {ROLES.map((r) => (
                    <option key={r} value={r}>
                      {r}
                    </option>
                  ))}
                </select>
              </td>
              <td>
                <input
                  defaultValue={u.team ?? ""}
                  disabled={busyId === u.id}
                  onBlur={(e) => {
                    if (e.target.value !== (u.team ?? "")) updateUser(u, u.role, e.target.value);
                  }}
                  style={{ width: 120 }}
                />
              </td>
              <td>{new Date(u.created_at).toLocaleDateString()}</td>
              <td>
                {creatingKeyFor === u.id ? (
                  <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                    <input
                      placeholder="key name"
                      value={keyName}
                      onChange={(e) => setKeyName(e.target.value)}
                      style={{ width: 100 }}
                    />
                    {["certs:read", "certs:export", "certs:issue"].map((scope) => (
                      <label key={scope} style={{ fontSize: 12, display: "flex", gap: 3, alignItems: "center" }}>
                        <input type="checkbox" checked={keyScopes.includes(scope)} onChange={() => toggleScope(scope)} />
                        {scope.replace("certs:", "")}
                      </label>
                    ))}
                    <button className="primary" onClick={() => submitAPIKey(u.id)}>
                      Create
                    </button>
                    <button className="secondary" onClick={() => setCreatingKeyFor(null)}>
                      Cancel
                    </button>
                  </div>
                ) : (
                  <button className="secondary" onClick={() => setCreatingKeyFor(u.id)}>
                    New API key
                  </button>
                )}
              </td>
            </tr>
          ))}
          {users.length === 0 && (
            <tr>
              <td colSpan={5}>No users yet.</td>
            </tr>
          )}
        </tbody>
      </table>
    </>
  );
}
