import { AuditEntry } from "../api/client";

// Renders an audit entry's metadata as one readable line — "target_name:
// dc1, host: dc1.example.internal, error: dial tcp: connection refused" —
// rather than a raw JSON blob, since the fields vary by action (a sync
// entry names a server/service, a scan entry names result counts, etc).
export function summarizeAuditMetadata(e: AuditEntry): string {
  const meta = e.Metadata || {};
  return Object.entries(meta)
    .filter(([, v]) => v !== undefined && v !== null && v !== "")
    .map(([k, v]) => `${k}: ${formatMetadataValue(v)}`)
    .join(", ");
}

function formatMetadataValue(v: unknown): string {
  if (Array.isArray(v)) return v.join(", ");
  if (typeof v === "boolean") return v ? "yes" : "no";
  return String(v);
}
