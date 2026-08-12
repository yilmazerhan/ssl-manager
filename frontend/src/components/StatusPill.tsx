const TONE: Record<string, string> = {
  active: "ok",
  issued: "ok",
  expiring: "warn",
  awaiting_validation: "warn",
  issuing: "warn",
  expired: "critical",
  revoked: "critical",
  failed: "critical",
  // discovery scan statuses
  pending: "warn",
  running: "warn",
  completed: "ok",
  partially_completed: "warn",
  canceled: "critical",
  // notification log statuses
  sent: "ok",
  // discovery result match statuses
  matched: "ok",
  mismatched: "warn",
  not_in_inventory: "warn",
  no_tls: "accent",
  unreachable: "critical",
};

export default function StatusPill({ status }: { status: string }) {
  const tone = TONE[status] ?? "accent";
  return <span className={`pill ${tone}`}>{status.replace(/_/g, " ")}</span>;
}
