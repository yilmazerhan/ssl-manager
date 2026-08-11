import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, CertificateOrder } from "../api/client";
import { useAuth } from "../auth/AuthContext";

type Step = "domains" | "authority" | "validation" | "review" | "challenge" | "done";

const STEPS: { key: Step; label: string }[] = [
  { key: "domains", label: "1. Domains" },
  { key: "authority", label: "2. Authority" },
  { key: "validation", label: "3. Validation" },
  { key: "review", label: "4. Review" },
  { key: "challenge", label: "5. Prove control" },
  { key: "done", label: "6. Ready" },
];

const VALIDATION_METHODS: Record<string, { value: string; label: string }[]> = {
  letsencrypt: [
    { value: "http-01", label: "HTTP-01 (host a token file)" },
    { value: "dns-01", label: "DNS-01 (create a TXT record — required for wildcards)" },
  ],
  zerossl: [
    { value: "http-file", label: "HTTP file check" },
    { value: "cname", label: "CNAME record" },
  ],
};

export default function NewCertificateWizard() {
  const navigate = useNavigate();
  const { identity } = useAuth();
  const [step, setStep] = useState<Step>("domains");
  const [domainsInput, setDomainsInput] = useState("");
  const [caProvider, setCaProvider] = useState("letsencrypt");
  const [validationMethod, setValidationMethod] = useState("http-01");
  const [owningTeam, setOwningTeam] = useState(identity?.team ?? "");
  const [order, setOrder] = useState<CertificateOrder | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);

  const canPickTeam = identity?.role === "admin";
  const domains = domainsInput
    .split(",")
    .map((d) => d.trim())
    .filter(Boolean);

  async function submitOrder() {
    setError(null);
    try {
      const created = await api.createOrder({
        owning_team: owningTeam || identity?.team || "unassigned",
        domains,
        ca_provider: caProvider,
        validation_method: validationMethod,
      });
      setOrder(created);
      setStep("challenge");
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function checkNow() {
    if (!order) return;
    setChecking(true);
    setError(null);
    try {
      const updated = await api.validateOrder(order.id);
      setOrder(updated);
      if (updated.status === "issued") setStep("done");
      if (updated.status === "failed") setError(updated.error ?? "validation failed");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setChecking(false);
    }
  }

  const challenges = order?.challenges?.challenges ?? [];

  return (
    <>
      <h1>New certificate</h1>
      <p className="page-lede">Request a certificate from scratch — from domains to an issued, tracked certificate.</p>

      <div className="step-row">
        {STEPS.map((s) => (
          <span key={s.key} className={`step ${s.key === step ? "active" : ""}`}>
            {s.label}
          </span>
        ))}
      </div>

      {error && <div className="card">{error}</div>}

      {step === "domains" && (
        <div className="card">
          <div className="field">
            <label>Domains (comma-separated, wildcards allowed)</label>
            <input
              value={domainsInput}
              onChange={(e) => setDomainsInput(e.target.value)}
              placeholder="app.kron.com.tr, *.kron.com.tr"
            />
          </div>
          <div className="field">
            <label>Owning team</label>
            <input
              value={owningTeam}
              onChange={(e) => setOwningTeam(e.target.value)}
              placeholder="platform"
              disabled={!canPickTeam}
            />
            {!canPickTeam && (
              <span style={{ fontSize: 12, color: "var(--muted)" }}>Certificates you request belong to your own team.</span>
            )}
          </div>
          <button className="primary" disabled={domains.length === 0} onClick={() => setStep("authority")}>
            Continue
          </button>
        </div>
      )}

      {step === "authority" && (
        <div className="card">
          <div className="field">
            <label>Certificate authority</label>
            <select
              value={caProvider}
              onChange={(e) => {
                setCaProvider(e.target.value);
                setValidationMethod(VALIDATION_METHODS[e.target.value][0].value);
              }}
            >
              <option value="letsencrypt">Let's Encrypt — free, 90-day certs</option>
              <option value="zerossl">ZeroSSL — free tier, paid multi-year available</option>
            </select>
          </div>
          <button className="secondary" onClick={() => setStep("domains")} style={{ marginRight: 8 }}>
            Back
          </button>
          <button className="primary" onClick={() => setStep("validation")}>
            Continue
          </button>
        </div>
      )}

      {step === "validation" && (
        <div className="card">
          <div className="field">
            <label>Validation method</label>
            <select value={validationMethod} onChange={(e) => setValidationMethod(e.target.value)}>
              {VALIDATION_METHODS[caProvider].map((m) => (
                <option key={m.value} value={m.value}>
                  {m.label}
                </option>
              ))}
            </select>
          </div>
          <button className="secondary" onClick={() => setStep("authority")} style={{ marginRight: 8 }}>
            Back
          </button>
          <button className="primary" onClick={() => setStep("review")}>
            Continue
          </button>
        </div>
      )}

      {step === "review" && (
        <div className="card">
          <p>
            <strong>Domains:</strong> {domains.join(", ")}
          </p>
          <p>
            <strong>Authority:</strong> {caProvider}
          </p>
          <p>
            <strong>Validation:</strong> {validationMethod}
          </p>
          <p>
            <strong>Owning team:</strong> {owningTeam || identity?.team || "unassigned"}
          </p>
          <p style={{ color: "var(--muted)", fontSize: 13 }}>
            A key pair is generated for this certificate in Vault when you submit — it never leaves the server, not even to us.
          </p>
          <button className="secondary" onClick={() => setStep("validation")} style={{ marginRight: 8 }}>
            Back
          </button>
          <button className="primary" onClick={submitOrder}>
            Submit request
          </button>
        </div>
      )}

      {step === "challenge" && challenges.length > 0 && (
        <div className="card">
          <p>Prove you control {challenges.length === 1 ? "this domain" : "these domains"} by publishing the following before checking again:</p>
          {challenges.map((c) => (
            <div key={c.domain} style={{ marginBottom: 12 }}>
              <p style={{ fontSize: 13, color: "var(--muted)", marginBottom: 4 }}>
                {c.domain} · {c.type} {c.verified ? "· verified" : ""}
              </p>
              <code className="challenge-value">{c.resource_name}</code>
              <code className="challenge-value">{c.value}</code>
            </div>
          ))}
          <button className="primary" onClick={checkNow} disabled={checking}>
            {checking ? "Checking…" : "Check now"}
          </button>
        </div>
      )}

      {step === "done" && order?.certificate_id && (
        <div className="card">
          <p>Certificate issued and added to inventory.</p>
          <button className="primary" onClick={() => navigate(`/certificates/${order.certificate_id}`)}>
            View certificate
          </button>
        </div>
      )}
    </>
  );
}
