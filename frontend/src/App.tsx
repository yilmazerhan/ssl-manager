import { NavLink, Route, Routes } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Inventory from "./pages/Inventory";
import CertificateDetail from "./pages/CertificateDetail";
import NewCertificateWizard from "./pages/NewCertificateWizard";
import Login from "./pages/Login";
import { useAuth } from "./auth/AuthContext";

export default function App() {
  const { identity, logout } = useAuth();

  if (!identity) {
    return <Login />;
  }

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
        </Routes>
      </main>
    </div>
  );
}
