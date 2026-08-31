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
import AuditLog from "./pages/AuditLog";
import { useAuth } from "./auth/AuthContext";
import {
  ShieldCheckIcon,
  GridIcon,
  ListIcon,
  PlusCircleIcon,
  PlugIcon,
  UsersIcon,
  RadarIcon,
  BellIcon,
  ScrollTextIcon,
  LogoutIcon,
} from "./components/Icons";

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
  const initial = (identity.email || "?").trim().charAt(0).toUpperCase();

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">
            <ShieldCheckIcon width={17} height={17} />
          </span>
          SSL Sentry
        </div>
        <nav>
          <NavLink to="/" end>
            <GridIcon />
            Dashboard
          </NavLink>
          <NavLink to="/inventory">
            <ListIcon />
            Inventory
          </NavLink>
          {identity.role !== "viewer" && (
            <NavLink to="/certificates/new">
              <PlusCircleIcon />
              New certificate
            </NavLink>
          )}

          {isAdmin && (
            <>
              <div className="nav-section-label">Administration</div>
              <NavLink to="/admin/integrations">
                <PlugIcon />
                Integrations
              </NavLink>
              <NavLink to="/admin/users">
                <UsersIcon />
                Users
              </NavLink>
              <NavLink to="/admin/discovery">
                <RadarIcon />
                Discovery
              </NavLink>
              <NavLink to="/admin/notifications">
                <BellIcon />
                Notifications
              </NavLink>
              <NavLink to="/admin/audit">
                <ScrollTextIcon />
                Audit log
              </NavLink>
            </>
          )}
        </nav>
        <div className="sidebar-footer">
          <div className="user-chip">
            <div className="avatar">{initial}</div>
            <div className="user-meta">
              <div className="user-email">{identity.email}</div>
              <div className="user-role">
                {identity.role.replace(/_/g, " ")}
                {identity.team ? ` · ${identity.team}` : ""}
              </div>
            </div>
          </div>
          <button className="signout-btn" onClick={logout}>
            <LogoutIcon width={15} height={15} />
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
          {isAdmin && <Route path="/admin/audit" element={<AuditLog />} />}
        </Routes>
      </main>
    </div>
  );
}
