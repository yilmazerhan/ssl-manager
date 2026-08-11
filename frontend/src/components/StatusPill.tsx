const TONE: Record<string, string> = {
  active: "ok",
  issued: "ok",
  expiring: "warn",
  awaiting_validation: "warn",
  issuing: "warn",
  expired: "critical",
  revoked: "critical",
  failed: "critical",
};

export default function StatusPill({ status }: { status: string }) {
  const tone = TONE[status] ?? "accent";
  return <span className={`pill ${tone}`}>{status.replace(/_/g, " ")}</span>;
}
