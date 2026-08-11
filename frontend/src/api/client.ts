export interface Certificate {
  id: string;
  common_name: string;
  sans: string[];
  ca_provider: string;
  status: string;
  not_before: string;
  not_after: string;
  key_algorithm: string;
  owning_team: string;
  auto_renew: boolean;
  renew_before_days: number;
}

export interface CertificateVersion {
  id: string;
  certificate_id: string;
  serial_number: string;
  fingerprint_sha256: string;
  pem_cert: string;
  pem_chain: string;
  private_key_ref: string;
  issued_at: string;
}

export interface Challenge {
  type: string;
  resource_name: string;
  value: string;
  verified: boolean;
}

export interface CertificateOrder {
  id: string;
  requested_by: string;
  owning_team: string;
  domains: string[];
  ca_provider: string;
  validation_method: string;
  status: "draft" | "awaiting_validation" | "issuing" | "issued" | "failed";
  challenge?: Challenge;
  certificate_id?: string;
  error?: string;
  created_at: string;
  completed_at?: string;
}

export interface CreateOrderRequest {
  requested_by: string;
  owning_team: string;
  domains: string[];
  ca_provider: string;
  validation_method: string;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api/v1${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(body.error ?? `request failed with ${res.status}`);
  }
  return res.json();
}

export const api = {
  listCertificates: () => request<Certificate[]>("/certificates"),
  getCertificate: (id: string) => request<Certificate>(`/certificates/${id}`),
  getHistory: (id: string) => request<CertificateVersion[]>(`/certificates/${id}/history`),
  createOrder: (body: CreateOrderRequest) =>
    request<CertificateOrder>("/certificate-orders", { method: "POST", body: JSON.stringify(body) }),
  getOrder: (id: string) => request<CertificateOrder>(`/certificate-orders/${id}`),
  validateOrder: (id: string) => request<CertificateOrder>(`/certificate-orders/${id}/validate`, { method: "POST" }),
};
