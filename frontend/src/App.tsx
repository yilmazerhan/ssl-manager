import { NavLink, Route, Routes } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import Inventory from "./pages/Inventory";
import CertificateDetail from "./pages/CertificateDetail";
import NewCertificateWizard from "./pages/NewCertificateWizard";

export default function App() {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">SSL Sentry</div>
        <nav>
          <NavLink to="/" end>
            Dashboard
          </NavLink>
          <NavLink to="/inventory">Inventory</NavLink>
          <NavLink to="/certificates/new">New certificate</NavLink>
        </nav>
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
