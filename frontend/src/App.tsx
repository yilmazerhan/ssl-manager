import { NavLink, Route, Routes } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Inventory from "./pages/Inventory";
import CertificateDetail from "./pages/CertificateDetail";
import NewCertificateWizard from "./pages/NewCertificateWizard";
import Login from "./pages/Login";
import ChangePassword from "./pages/ChangePassword";
import Integrations from "./pages/Integrations";
import AdminUsers from "./pages/AdminUsers";
import Discovery from "./pages/Discovery";
import NotificationSettings from "./pages/NotificationSettings";
import { useAuth } from "./auth/AuthContext";

export default function App() {
  const { identity, logout } = useAuth();

  if (!identity) {
    return <Login />;
  }

  // A still-assigned password blocks everything else — the backend
  // enforces this on every request too (RequirePasswordChange), this just
  // avoids a round trip of 403s before landing here anyway.
  if (identity.mustChangePassword) {
    return <ChangePassword />;
  }

  const isAdmin = identity.role === "admin";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">SSL Sentry</div>
        <nav>
          <NavLink to="/" end>
            Dashboard
          </NavLink>
          <NavLink to="/inventory">Inventory</NavLink>
          {identity.role !== "viewer" && <NavLink to="/certificates/new">New certificate</NavLink>}
          {isAdmin && <NavLink to="/admin/integrations">Integrations</NavLink>}
          {isAdmin && <NavLink to="/admin/users">Users</NavLink>}
          {isAdmin && <NavLink to="/admin/discovery">Discovery</NavLink>}
          {isAdmin && <NavLink to="/admin/notifications">Notifications</NavLink>}
        </nav>
        <div style={{ marginTop: "auto", paddingTop: 24, fontSize: 12.5, color: "var(--muted)" }}>
          <div>{identity.email}</div>
          <div>
            {identity.role}
            {identity.team ? ` · ${identity.team}` : ""}
          </div>
          <button className="secondary" style={{ marginTop: 10, width: "100%" }} onClick={logout}>
            Sign out
          </button>
        </div>
      </aside>
      <main className="content">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/inventory" element={<Inventory />} />
          <Route path="/certificates/new" element={<NewCertificateWizard />} />
          <Route path="/certificates/:id" element={<CertificateDetail />} />
          {isAdmin && <Route path="/admin/integrations" element={<Integrations />} />}
          {isAdmin && <Route path="/admin/users" element={<AdminUsers />} />}
          {isAdmin && <Route path="/admin/discovery" element={<Discovery />} />}
          {isAdmin && <Route path="/admin/notifications" element={<NotificationSettings />} />}
        </Routes>
      </main>
    </div>
  );
}
