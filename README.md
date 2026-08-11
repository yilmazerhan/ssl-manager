# SSL Sentry

A certificate lifecycle management platform: inventory, encrypted storage,
Let's Encrypt/ZeroSSL issuance, automated renewal, an API, and a web UI.

The full architecture and delivery plan is in [`docs/plan.html`](docs/plan.html)
— open it in a browser for the readable version.

## What's implemented

- **Postgres persistence** (`backend/internal/db`, `certificate`, `order`,
  `user`, `caaccount`, `apikey`, `downloadtoken`, `audit`) — real schema,
  migrations applied automatically on startup.
- **Vault-backed keys** (`backend/internal/secrets`) — every certificate's
  private key lives in Vault's Transit engine as a non-exportable key. CSRs
  are produced by asking Vault to sign a digest remotely
  (`crypto.Signer` backed by a Transit key); the private key never exists
  in this process, in Postgres, or on the wire to a browser. ACME account
  keys and CA API credentials are separate, plain Vault KV secrets, per
  `docs/plan.html` section 09.
- **Real Let's Encrypt client** (`backend/internal/ca/letsencrypt.go`) — a
  genuine ACME v2 implementation (order → authorization → HTTP-01/DNS-01
  challenge → finalize → download) built on `go-acme/lego`'s low-level
  `acme/api` package, split across `RequestValidation`/`CheckChallenge`/
  `Issue` to match the wizard's steps. Integration-tested end-to-end
  against [Pebble](https://github.com/letsencrypt/pebble), the ACME v2 test
  server Let's Encrypt itself uses — see
  `backend/internal/ca/letsencrypt_test.go`.
- **Real ZeroSSL client** (`backend/internal/ca/zerossl.go`) — implements
  their documented CSR-upload + trigger-validation + poll + download REST
  flow. Unit-tested against a mock server reproducing their documented
  shapes (`zerossl_test.go`); *not* exercised against the live API, since
  that needs an account API key this environment doesn't have — re-verify
  field names against current ZeroSSL docs before pointing it at
  production.
- **Auth** (`backend/internal/auth`) — OIDC login (`go-oidc` + `oauth2`)
  issuing this app's own short-lived JWT session, API keys for
  machine/API-only access, and RBAC (`viewer` / `cert_manager` / `admin` /
  `api_only`) enforced per-request, with certificate access additionally
  scoped to the caller's team unless they're an admin.
- **Download tokens** (`backend/internal/downloadtoken`) — short-lived,
  single-use tokens gate every certificate export, per `docs/plan.html`
  sections 07/09.
- **Renewal engine** (`backend/internal/renewal`) — scans for certificates
  due for renewal, reuses the existing Vault key and validation method,
  retries with backoff, and reports success/failure to both the audit log
  and notifications. The same engine backs the manual "renew now" endpoint.
- **Notifications** (`backend/internal/notify`) — console (zero-config
  default), SMTP, and Slack/Teams-compatible incoming webhook senders.
- **Audit log** (`backend/internal/audit`) — every issuance, renewal,
  download, and role change is recorded with actor, scope, and resource.
- **Frontend** (`frontend/`, React + TypeScript + Vite) — dashboard,
  certificate inventory, certificate detail, and the from-scratch
  certificate wizard, now wired to real auth and the download-token flow.

### A deliberate deviation from the plan's literal wording

`docs/plan.html` describes the download endpoint as returning "PEM / chain
/ key bundle." Because every private key lives in Vault as a
non-exportable Transit key, there is no key file to include, ever — not
behind a download token, not for an admin, not for a backup job. What
`GET /certificates/{id}/download` actually returns is the certificate and
its chain. This is stricter than the plan's literal text and is the
correct reading of its own security section ("the private key never
leaves it").

## What's not implemented

- **DNS-01 automation.** The Let's Encrypt client supports DNS-01, but no
  DNS provider (Cloudflare, Route 53, ...) is wired up to publish the TXT
  record automatically — today it's a "here's the record, publish it
  yourself" instruction, same as manual HTTP-01. Automated DNS-01 is what
  makes unattended renewal work for domains you don't personally control
  the origin server for; wiring a real provider via `lego`'s
  `challenge/dns01` providers is the natural next step.
- **Live ZeroSSL verification** — see above.
- **Live OIDC verification** — the login flow is a standard, real
  implementation, but this environment has no OIDC tenant to test it
  against end-to-end.

## Running it locally

### Docker Compose (Postgres + Vault + backend + frontend)

```bash
docker compose up --build
```

This starts Postgres, a Vault dev server (with the Transit engine enabled
by `vault-init`), the backend on `:8080`, and the frontend on `:5173`. By
default `DEV_AUTH_ENABLED=true`, so you can sign in without a real OIDC
provider — see below. Let's Encrypt defaults to the **staging** directory
so a stray `docker compose up` never touches production rate limits.

*(This has not been run inside the sandbox this was built in — no Docker
daemon was available there. Every piece it wires together — the backend,
the migrations, Vault, Pebble standing in for Let's Encrypt — was run and
verified individually and in combination via `go run`/`go test`; see
below.)*

### Manual local dev

```bash
# Postgres and Vault however you'd normally run them locally, e.g.:
createdb ssl_manager
vault server -dev -dev-root-token-id=dev-root-token   # then: vault secrets enable transit

cd backend
DATABASE_URL="postgres://user:pass@localhost:5432/ssl_manager" \
VAULT_ADDR="http://127.0.0.1:8200" VAULT_TOKEN="dev-root-token" \
DEV_AUTH_ENABLED=true \
go run ./cmd/api

cd frontend
npm install
npm run dev   # http://localhost:5173, proxies /api to the backend above
```

Sign in without a real identity provider:

```bash
curl -X POST localhost:8080/auth/dev-login \
  -d '{"email":"you@example.com","role":"cert_manager","team":"platform"}'
# -> {"token": "..."}
```

`DEV_AUTH_ENABLED` must be false (the default) in any real deployment —
configure `OIDC_ISSUER_URL`/`OIDC_CLIENT_ID`/`OIDC_CLIENT_SECRET` instead.

### Testing against a real ACME v2 exchange without a real CA

The Let's Encrypt integration test drives the actual protocol against
[Pebble](https://github.com/letsencrypt/pebble):

```bash
go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
pebble -config test/config/pebble-config.json   # from the pebble repo, or see letsencrypt_test.go

ACME_TEST_DIRECTORY_URL="https://127.0.0.1:14000/dir" \
VAULT_ADDR="http://127.0.0.1:8200" VAULT_TOKEN="dev-root-token" \
go test ./internal/ca/... -run TestLetsEncrypt_FullFlow_HTTP01 -v
```

### Configuration

Every setting is an environment variable with a working local default —
see `backend/internal/config/config.go` for the full list (database and
Vault connection, Let's Encrypt directory/environment/email, ZeroSSL API
key, session secret, OIDC settings, SMTP/webhook notification settings,
renewal interval).
