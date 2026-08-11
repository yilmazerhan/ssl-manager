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
  created_at: string;
  completed_at?: string;
}

export interface CreateOrderRequest {
  owning_team: string;
  domains: string[];
  ca_provider: string;
  validation_method: string;
  key_algorithm?: string;
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

export const api = {
  listCertificates: () => request<Certificate[]>("/certificates"),
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
