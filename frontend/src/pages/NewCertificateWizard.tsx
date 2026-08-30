import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, CertificateOrder } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { getChallengeInstructions } from "../lib/challengeInstructions";

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
  selfsigned: [{ value: "none", label: "None — issued instantly, trusted only by this platform" }],
  adcs: [{ value: "adcs-enroll", label: "AD CS enrollment (certsrv)" }],
};

export default function NewCertificateWizard() {
  const navigate = useNavigate();
  const { identity } = useAuth();
  const [step, setStep] = useState<Step>("domains");
  const [domainsInput, setDomainsInput] = useState("");
  const [caProvider, setCaProvider] = useState("letsencrypt");
  const [validationMethod, setValidationMethod] = useState("http-01");
  const [owningTeam, setOwningTeam] = useState(identity?.team ?? "");
  const [showSubjectFields, setShowSubjectFields] = useState(false);
  const [organization, setOrganization] = useState("");
  const [organizationalUnit, setOrganizationalUnit] = useState("");
  const [country, setCountry] = useState("");
  const [state, setStateField] = useState("");
  const [locality, setLocality] = useState("");
  const [exportableKey, setExportableKey] = useState(false);
  const [order, setOrder] = useState<CertificateOrder | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);

  const canPickTeam = identity?.role === "admin";
  const domains = domainsInput
    .split(",")
    .map((d) => d.trim())
    .filter(Boolean);

  const subjectSummary = [organization, organizationalUnit, locality, state, country].filter(Boolean).join(", ");

  async function submitOrder() {
    setError(null);
    try {
      const created = await api.createOrder({
        owning_team: owningTeam || identity?.team || "unassigned",
        domains,
        ca_provider: caProvider,
        validation_method: validationMethod,
        organization: organization || undefined,
        organizational_unit: organizationalUnit || undefined,
        country: country || undefined,
        state: state || undefined,
        locality: locality || undefined,
        exportable_key: exportableKey,
      });
      // "none" (selfsigned) has nothing for anyone to publish or approve —
      // it's already verified at creation time, so skip straight to
      // issuing instead of showing an empty "prove you control" screen.
      if (validationMethod === "none") {
        const validated = await api.validateOrder(created.id);
        setOrder(validated);
        if (validated.status === "issued") {
          setStep("done");
          return;
        }
        if (validated.status === "failed") {
          setError(validated.error ?? "issuance failed");
          return;
        }
      }
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

      {error && <div className="error-banner">{error}</div>}

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

          <button
            type="button"
            className="auth-alt-toggle"
            style={{ marginBottom: showSubjectFields ? 16 : 4 }}
            onClick={() => setShowSubjectFields((v) => !v)}
          >
            {showSubjectFields
              ? "Hide subject details"
              : subjectSummary
              ? `Subject details: ${subjectSummary}`
              : "Add organization, unit, country… (optional)"}
          </button>

          {showSubjectFields && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0 16px" }}>
              <div className="field">
                <label>Organization (O)</label>
                <input value={organization} onChange={(e) => setOrganization(e.target.value)} placeholder="Acme Corp" />
              </div>
              <div className="field">
                <label>Organizational unit (OU)</label>
                <input value={organizationalUnit} onChange={(e) => setOrganizationalUnit(e.target.value)} placeholder="Platform Engineering" />
              </div>
              <div className="field">
                <label>Locality / city (L)</label>
                <input value={locality} onChange={(e) => setLocality(e.target.value)} placeholder="Istanbul" />
              </div>
              <div className="field">
                <label>State / province (ST)</label>
                <input value={state} onChange={(e) => setStateField(e.target.value)} placeholder="Istanbul" />
              </div>
              <div className="field">
                <label>Country (C)</label>
                <input
                  value={country}
                  onChange={(e) => setCountry(e.target.value.toUpperCase().slice(0, 2))}
                  placeholder="TR"
                  maxLength={2}
                  style={{ width: 90 }}
                />
                <span style={{ fontSize: 12, color: "var(--muted)" }}>2-letter ISO code, e.g. TR, US, DE</span>
              </div>
            </div>
          )}

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
              <option value="selfsigned">Self-signed — instant, trusted only by this platform</option>
              <option value="adcs">Active Directory CS — issued by your internal Domain Controller CA</option>
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
          {subjectSummary && (
            <p>
              <strong>Subject:</strong> {subjectSummary}
              {country ? `, ${country}` : ""}
            </p>
          )}
          <p style={{ color: "var(--muted)", fontSize: 13 }}>
            A key pair is generated for this certificate in Vault when you submit — it never leaves the server, not even to us.
          </p>
          <label style={{ display: "flex", gap: 8, alignItems: "center", fontSize: 13 }}>
            <input type="checkbox" checked={exportableKey} onChange={(e) => setExportableKey(e.target.checked)} />
            Sync to Kubernetes as a Secret
          </label>
          {exportableKey && (
            <p style={{ color: "var(--muted)", fontSize: 12, marginTop: 4 }}>
              This makes an exception to the note above: this certificate's key can be exported to build a Kubernetes TLS Secret. This is a
              one-time choice — it can't be turned on later without re-issuing the certificate.
            </p>
          )}
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
          {challenges.every((c) => c.automated) ? (
            <p>
              Nothing to publish yourself — {caProvider === "adcs" ? "your AD CS server" : "this provider"} handles validation automatically. If a
              certificate template requires manager approval, approve the pending request in the CA's console, then check again.
            </p>
          ) : (
            <p>Prove you control {challenges.length === 1 ? "this domain" : "these domains"} before checking again — follow the steps below for each:</p>
          )}
          {challenges.map((c) => {
            const instructions = getChallengeInstructions(caProvider, c.type);
            return (
              <div key={c.domain} className="card" style={{ background: "var(--surface-2)", marginBottom: 14 }}>
                <p style={{ fontSize: 13, color: "var(--muted)", marginBottom: 4 }}>
                  <strong style={{ color: "var(--text)" }}>{c.domain}</strong> · {c.type} {c.verified ? "· verified ✓" : ""}
                </p>
                {c.error && <div className="error-banner">{c.error}</div>}
                {c.automated ? (
                  c.resource_name && <p style={{ fontSize: 13, color: "var(--muted)" }}>{c.resource_name}</p>
                ) : (
                  <>
                    <p style={{ fontSize: 13.5, marginBottom: 10 }}>{instructions.summary}</p>
                    <ol style={{ fontSize: 13.5, paddingLeft: 20, margin: "0 0 12px" }}>
                      {instructions.steps.map((step, i) => (
                        <li key={i} style={{ marginBottom: 4 }}>
                          {step}
                        </li>
                      ))}
                    </ol>
                    <label style={{ fontSize: 12, color: "var(--muted)", fontWeight: 600 }}>{instructions.valueLabels[0]}</label>
                    <code className="challenge-value">{c.resource_name}</code>
                    <label style={{ fontSize: 12, color: "var(--muted)", fontWeight: 600 }}>{instructions.valueLabels[1]}</label>
                    <code className="challenge-value">{c.value}</code>
                  </>
                )}
              </div>
            );
          })}
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
