export interface Certificate {
  id: string;
  common_name: string;
  sans: string[];
  ca_provider: string;
  validation_method: string;
  status: string;
  not_before: string;
  not_after: string;
  key_algorithm: string;
  owning_team: string;
  auto_renew: boolean;
  renew_before_days: number;
  notify_emails?: string[];
  organization?: string;
  organizational_unit?: string;
  country?: string;
  state?: string;
  locality?: string;
  created_at: string;
  updated_at: string;
}

export interface CertificateVersion {
  id: string;
  certificate_id: string;
  serial_number: string;
  fingerprint_sha256: string;
  pem_cert: string;
  pem_chain: string;
  issued_at: string;
}

export interface Challenge {
  domain: string;
  type: string;
  resource_name: string;
  value: string;
  verified: boolean;
  error?: string;
  automated?: boolean;
}

export interface CertificateOrder {
  id: string;
  requested_by: string;
  owning_team: string;
  domains: string[];
  ca_provider: string;
  validation_method: string;
  status: "draft" | "awaiting_validation" | "issuing" | "issued" | "failed";
  challenges: { challenges: Challenge[] };
  certificate_id?: string;
  error?: string;
  attempt_count: number;
  organization?: string;
  organizational_unit?: string;
  country?: string;
  state?: string;
  locality?: string;
  created_at: string;
  completed_at?: string;
}

export interface CreateOrderRequest {
  owning_team: string;
  domains: string[];
  ca_provider: string;
  validation_method: string;
  key_algorithm?: string;
  organization?: string;
  organizational_unit?: string;
  country?: string;
  state?: string;
  locality?: string;
}

export interface AuditEntry {
  Actor: string;
  Action: string;
  Resource: string;
  ResourceID: string;
  Scope: string;
  Metadata: Record<string, unknown>;
  CreatedAt: string;
}

export interface AppUser {
  id: string;
  email: string;
  role: string;
  team?: string;
  created_at: string;
}

export interface CertificateFilter {
  team?: string;
  status?: string;
  ca_provider?: string;
  expiring_within_days?: number;
}

export interface IntegrationsStatus {
  letsencrypt: {
    environment: string;
    directory_url: string;
    contact_email: string;
    account_registered: boolean;
  };
  zerossl: {
    configured: boolean;
    base_url: string;
    api_key_set: boolean;
  };
  dns01: {
    provider: string;
    configured: boolean;
    token_set: boolean;
  };
  selfsigned: {
    available: boolean;
    validity_period: string;
    validity_days: number;
  };
  adcs: {
    configured: boolean;
    base_url: string;
    template: string;
    username: string;
    allow_basic_auth: boolean;
    password_set: boolean;
  };
}

export interface DiscoveryScan {
  id: string;
  name: string;
  description: string;
  targets: string[];
  ports: number[];
  timeout_ms: number;
  concurrency: number;
  status: "pending" | "running" | "completed" | "partially_completed" | "failed" | "canceled";
  created_by: string;
  total_targets: number;
  scanned_count: number;
  matched_count: number;
  mismatch_count: number;
  new_count: number;
  error?: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
}

export interface DiscoveryResult {
  id: string;
  scan_id: string;
  host: string;
  port: number;
  reachable: boolean;
  tls_version?: string;
  common_name?: string;
  sans?: string[];
  issuer?: string;
  serial_number?: string;
  fingerprint_sha256?: string;
  not_before?: string;
  not_after?: string;
  match_status: "matched" | "mismatched" | "not_in_inventory" | "no_tls" | "unreachable";
  matched_certificate_id?: string;
  error?: string;
  discovered_at: string;
}

export interface CreateScanRequest {
  name: string;
  description?: string;
  targets: string[];
  ports?: number[];
  timeout_ms?: number;
  concurrency?: number;
}

export interface Stats {
  total: number;
  by_status: Record<string, number>;
  by_ca_provider: Record<string, number>;
  by_team: Record<string, number>;
  expiring_in_7d: number;
  expiring_in_30d: number;
}

export interface SummaryReport {
  certificates: Stats;
  discovery_mismatches?: DiscoveryResult[];
  notifications_sent_30d?: number;
  notifications_failed_30d?: number;
}

export interface ReminderSettings {
  threshold_days: number[];
  email_subject_template: string;
  email_body_template: string;
  default_recipients: string[];
  escalation_recipients: string[];
}

export interface NotificationLogEntry {
  id: string;
  certificate_id: string;
  threshold_days: number;
  sent_at: string;
  status: "sent" | "failed";
  error?: string;
  recipients: string[];
}

const TOKEN_KEY = "ssl-sentry.token";

class ApiError extends Error {}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = localStorage.getItem(TOKEN_KEY);
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`/api/v1${path}`, { headers, ...init });

  if (res.status === 401) {
    localStorage.removeItem(TOKEN_KEY);
    window.location.reload();
    throw new ApiError("session expired");
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new ApiError(body.error ?? `request failed with ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

function toQuery(params: Record<string, string | number | undefined>): string {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === "") continue;
    parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(value)}`);
  }
  return parts.length ? `?${parts.join("&")}` : "";
}

export const api = {
  listCertificates: (filter: CertificateFilter = {}) =>
    request<Certificate[]>(
      `/certificates${toQuery({
        team: filter.team,
        status: filter.status,
        ca_provider: filter.ca_provider,
        expiring_within_days: filter.expiring_within_days,
      })}`
    ),
  getCertificate: (id: string) => request<Certificate>(`/certificates/${id}`),
  getHistory: (id: string) => request<CertificateVersion[]>(`/certificates/${id}/history`),
  getAudit: (id: string) => request<AuditEntry[]>(`/certificates/${id}/audit`),
  renewCertificate: (id: string) => request<CertificateOrder>(`/certificates/${id}/renew`, { method: "POST" }),
  revokeCertificate: (id: string) => request<{ status: string }>(`/certificates/${id}/revoke`, { method: "POST" }),

  issueDownloadToken: (id: string) =>
    request<{ token: string; expires_at: string }>(`/certificates/${id}/download-token`, { method: "POST" }),
  downloadCertificate: (id: string, token: string) =>
    request<CertificateVersion>(`/certificates/${id}/download?token=${encodeURIComponent(token)}`),

  createOrder: (body: CreateOrderRequest) =>
    request<CertificateOrder>("/certificate-orders", { method: "POST", body: JSON.stringify(body) }),
  getOrder: (id: string) => request<CertificateOrder>(`/certificate-orders/${id}`),
  validateOrder: (id: string) => request<CertificateOrder>(`/certificate-orders/${id}/validate`, { method: "POST" }),

  listUsers: () => request<AppUser[]>("/users"),
  setUserRole: (id: string, role: string, team: string) =>
    request<{ status: string }>(`/users/${id}/role`, { method: "POST", body: JSON.stringify({ role, team }) }),
  createAPIKey: (id: string, name: string, scopes: string[]) =>
    request<{ key: string }>(`/users/${id}/api-keys`, { method: "POST", body: JSON.stringify({ name, scopes }) }),

  getIntegrations: () => request<IntegrationsStatus>("/integrations"),
  updateLetsEncrypt: (body: { environment: string; directory_url: string; contact_email: string }) =>
    request<{ status: string }>("/integrations/letsencrypt", { method: "PUT", body: JSON.stringify(body) }),
  updateZeroSSL: (body: { base_url: string; api_key?: string }) =>
    request<{ status: string }>("/integrations/zerossl", { method: "PUT", body: JSON.stringify(body) }),
  updateADCS: (body: { base_url: string; template?: string; username?: string; password?: string; allow_basic_auth: boolean }) =>
    request<{ status: string }>("/integrations/adcs", { method: "PUT", body: JSON.stringify(body) }),
  updateDNS01: (body: { provider: string; token?: string }) =>
    request<{ status: string; warning?: string }>("/integrations/dns01", { method: "PUT", body: JSON.stringify(body) }),
  updateSelfSigned: (body: { validity_days: number }) =>
    request<{ status: string }>("/integrations/selfsigned", { method: "PUT", body: JSON.stringify(body) }),
  getSummaryReport: () => request<SummaryReport>("/reports/summary"),

  createScan: (body: CreateScanRequest) => request<DiscoveryScan>("/discovery/scans", { method: "POST", body: JSON.stringify(body) }),
  listScans: () => request<DiscoveryScan[]>("/discovery/scans"),
  getScan: (id: string) => request<DiscoveryScan>(`/discovery/scans/${id}`),
  listScanResults: (id: string) => request<DiscoveryResult[]>(`/discovery/scans/${id}/results`),
  cancelScan: (id: string) => request<{ status: string }>(`/discovery/scans/${id}/cancel`, { method: "POST" }),

  getNotificationSettings: () => request<ReminderSettings>("/notification-settings"),
  updateNotificationSettings: (s: ReminderSettings) =>
    request<ReminderSettings>("/notification-settings", { method: "PUT", body: JSON.stringify(s) }),
  listRecentNotifications: (limit = 50) => request<NotificationLogEntry[]>(`/notifications?limit=${limit}`),
  getCertificateNotifications: (id: string) => request<NotificationLogEntry[]>(`/certificates/${id}/notifications`),
  updateNotifyEmails: (id: string, emails: string[]) =>
    request<{ status: string }>(`/certificates/${id}/notify-emails`, { method: "POST", body: JSON.stringify({ emails }) }),

  login: (username: string, password: string) =>
    fetch("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    }).then(async (res) => {
      const body = await res.json().catch(() => ({ error: res.statusText }));
      if (!res.ok) throw new ApiError(body.error ?? "sign in failed");
      return body as { token: string; must_change_password: boolean };
    }),
  // Deliberately not routed through request(): a wrong *current* password
  // here is a 401 too, but it must show an inline error, not trigger
  // request()'s "session expired, log out and reload" handling.
  changePassword: (currentPassword: string, newPassword: string) =>
    fetch("/api/v1/auth/change-password", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${localStorage.getItem(TOKEN_KEY) ?? ""}` },
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    }).then(async (res) => {
      const body = await res.json().catch(() => ({ error: res.statusText }));
      if (!res.ok) throw new ApiError(body.error ?? "could not change password");
      return body as { status: string; token: string };
    }),

  devLogin: (email: string, role: string, team: string) =>
    fetch("/auth/dev-login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, role, team }),
    }).then(async (res) => {
      if (!res.ok) throw new ApiError("dev login is not enabled on this backend");
      return res.json() as Promise<{ token: string }>;
    }),
};

export function downloadPEM(filename: string, version: CertificateVersion) {
  const blob = new Blob([version.pem_cert, version.pem_chain], { type: "application/x-pem-file" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
