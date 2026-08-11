# SSL Sentry

A certificate lifecycle management platform: inventory, encrypted storage,
Let's Encrypt/ZeroSSL issuance, automated renewal, an API, and a web UI.

The full architecture and delivery plan is in [`docs/plan.html`](docs/plan.html)
— open it in a browser for the readable version. This repo currently holds
the scaffold described in that plan's Phase 1: an in-memory backend and a
working UI for the inventory and from-scratch certificate creation flow,
ahead of the real Postgres/Vault/ACME integrations.

## What's implemented

- **Backend** (`backend/`, Go, stdlib only): a `CertificateAuthority`
  interface with stub Let's Encrypt and ZeroSSL implementations, a
  `certificate_order` state machine (`draft` → `awaiting_validation` →
  `issuing` → `issued`/`failed`) driving the from-scratch creation flow, and
  a REST API matching `docs/plan.html` section 07. Storage is in-memory —
  `backend/migrations/` has the target Postgres schema.
- **Frontend** (`frontend/`, React + TypeScript + Vite): a dashboard,
  certificate inventory, certificate detail page, and a step-by-step new
  certificate wizard (domains → CA → validation method → review → prove
  domain control → issued).

## What's not implemented yet

Auth (OIDC/RBAC), Postgres persistence, Vault-backed key storage, real ACME
clients for Let's Encrypt/ZeroSSL, the renewal scheduler, and notifications
— see the roadmap in `docs/plan.html` section 12.

## Running it locally

```bash
# backend — http://localhost:8080
cd backend
go run ./cmd/api

# frontend — http://localhost:5173, proxies /api to the backend above
cd frontend
npm install
npm run dev
```
