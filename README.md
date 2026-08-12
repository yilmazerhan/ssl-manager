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
- **Automated DNS-01** (`backend/internal/ca/dns.go`) — when `DNS01_PROVIDER`
  is set (currently `cloudflare`), the TXT record is published through the
  provider's real API and this process waits for its own DNS lookups to
  see it before telling the CA to check — no human ever sees a "please
  publish this record" instruction. Leaving `DNS01_PROVIDER` unset falls
  back to manual instructions, same as HTTP-01. Integration-tested
  end-to-end against Pebble with Present/CleanUp driven through
  `pebble-challtestsrv`'s real management API (see
  `backend/internal/ca/dns_test.go`) — the automation path itself is
  proven, independent of which concrete provider is configured.
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
- **Revocation reaches the CA.** `POST /certificates/{id}/revoke` calls
  Let's Encrypt's real ACME revoke endpoint or ZeroSSL's revoke endpoint
  *before* marking the certificate revoked in our own database — a
  certificate we think is revoked but the CA still considers valid would
  be a much worse failure mode than the reverse. Verified live against
  Pebble, including confirming Pebble itself rejects revoking an
  already-revoked certificate (`alreadyRevoked`) rather than silently
  succeeding twice.
- **Admin frontend**: an Integrations page reporting live connection
  status for each CA and DNS-01 automation, a Users page for role/team
  changes and minting API keys, a Discovery page, and a Notifications
  page.
- **Inventory filters**: team (admin/API-only only — everyone else is
  already scoped to their own team server-side), status, CA provider,
  and expiring-within-days. Filtered results export to CSV client-side.
- **Self-signed certificates** (`backend/internal/ca/selfsigned.go`) — a
  fourth `Authority` alongside Let's Encrypt/ZeroSSL/AD CS: no domain
  validation, no CA round trip, the leaf is signed by the same
  Vault-backed key its CSR carries the public half of and is its own
  trust anchor. Issues instantly (the wizard skips straight to "done"),
  which makes it the one provider that's fully live-tested in this
  sandbox with no external dependency at all — see
  `backend/internal/ca/selfsigned_test.go`.
- **Active Directory Certificate Services (AD CS)**
  (`backend/internal/ca/adcs.go`) — enrolls against a Windows CA's
  certsrv web-enrollment pages (`certfnsh.asp`/`certnew.cer`), the same
  interface `certreq`/PowerShell's `Get-Certificate` use, with NTLM auth
  via `github.com/Azure/go-ntlmssp`. Handles both immediate issuance and
  templates that require a CA administrator's manual approval (polled the
  same way an unmet HTTP-01 challenge is). Unit-tested against a mock
  certsrv server (`adcs_test.go`); *not* exercised against a real AD CS
  server or the NTLM handshake itself, since this environment has no
  Windows domain to test against. Revocation is refused, honestly —
  certsrv's web pages have no revoke endpoint; that needs `certutil
  -revoke` on the CA server itself.
- **Network discovery** (`backend/internal/discovery`) — scans a bounded
  set of hosts/CIDRs/ports for live TLS endpoints (a TCP connect + TLS
  handshake, nothing else — no HTTP requests, no vulnerability probing)
  and reconciles each one against the certificate inventory: matched,
  serving a different certificate than what's on file (`mismatched`),
  or not tracked at all (`not_in_inventory`). Runs in the background per
  scan with cancel support; every scan is bounded (20,000 expanded
  targets, 32 ports, 64 workers) so it can't be pointed at an unbounded
  range. Live-tested against real local TLS listeners
  (`scanner_test.go`, `service_test.go`) and, in this session, against
  Pebble's own management ports — which correctly turned up as
  `mismatched` against a stale inventory record once Pebble had
  regenerated its certificate on a restart.
- **Richer expiry-reminder engine** (`backend/internal/renewal`) —
  threshold days, the email subject/body, and default/escalation
  recipients are all editable via `GET`/`PUT /notification-settings`
  (backed by a real Go `text/template`, validated at save time) instead
  of being hardcoded. A certificate's own distribution list (`POST
  /certificates/{id}/notify-emails`) overrides the defaults; the most
  urgent threshold also reaches the escalation list. Every attempt is
  logged (`notification_log`) so the same certificate+threshold is never
  notified twice and so there's a history — per certificate and
  platform-wide — to show an operator.
- **Reporting/dashboard breadth** — the dashboard now shows real
  aggregate counts (by status, CA provider, team, and expiry window) from
  a SQL `GROUP BY`, not an in-memory scan, plus (for admins) discovery
  mismatches and 30-day notification send/fail counts.
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

- **DNS-01 automation only covers Cloudflare.** Adding another provider
  (Route 53, etc.) is a few lines in `ca.NewDNSAutomation` — `lego` ships
  providers for most registrars — but only Cloudflare is wired up today.
- **Live ZeroSSL verification** — see above.
- **Live AD CS / NTLM verification** — see above; the certsrv protocol
  handling is real, the NTLM handshake against an actual Windows CA is
  not exercised here.
- **Live OIDC verification** — the login flow is a standard, real
  implementation, but this environment has no OIDC tenant to test it
  against end-to-end.
- **AD CS certificate chains** — `Issue` returns the leaf only; the chain
  comes back from certsrv as a PKCS#7 blob (`certnew.p7b`) and parsing
  PKCS#7 isn't worth a new dependency until this is pointed at a real CA.

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

The Let's Encrypt integration tests drive the actual protocol against
[Pebble](https://github.com/letsencrypt/pebble):

```bash
go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest

# challtestsrv provides a mock DNS server for the DNS-01 test below, and
# needs its own AAAA answers turned off — this sandbox (and some CI
# runners) has no IPv6 loopback, and Pebble tries AAAA first otherwise.
pebble-challtestsrv -http01 "" -https01 "" -tlsalpn01 "" -doh "" -defaultIPv6 ""

# Point Pebble's own validation at that mock DNS server so DNS-01 lookups
# resolve without touching the real internet.
pebble -config test/config/pebble-config.json -dnsserver 127.0.0.1:8053

ACME_TEST_DIRECTORY_URL="https://127.0.0.1:14000/dir" \
VAULT_ADDR="http://127.0.0.1:8200" VAULT_TOKEN="dev-root-token" \
CHALLTESTSRV_MANAGEMENT_URL="http://127.0.0.1:8055" \
CHALLTESTSRV_DNS_ADDR="127.0.0.1:8053" \
go test ./internal/ca/... -run TestLetsEncrypt_FullFlow -v
```

`TestLetsEncrypt_FullFlow_HTTP01` hosts the challenge response itself (it's
acting as "the customer's origin server"); `TestLetsEncrypt_FullFlow_DNS01_Automated`
drives `DNSAutomation.Present`/`CleanUp` through `pebble-challtestsrv`'s
real management API instead of Cloudflare's, so it proves the automation
mechanism itself without needing a real DNS account.

### Configuration

Every setting is an environment variable with a working local default —
see `backend/internal/config/config.go` for the full list (database and
Vault connection, Let's Encrypt directory/environment/email, ZeroSSL API
key, session secret, OIDC settings, SMTP/webhook notification settings,
renewal interval).

To automate DNS-01 with Cloudflare, set `DNS01_PROVIDER=cloudflare` plus
whichever of `CLOUDFLARE_DNS_API_TOKEN` (recommended — scope it to
Zone:Read + DNS:Edit) or `CLOUDFLARE_EMAIL`/`CLOUDFLARE_API_KEY` your
account uses. Those are read directly by `lego`'s Cloudflare provider, not
by this app's own config — see its docs for the full variable list.

To enable AD CS, set `ADCS_BASE_URL` (the certsrv virtual directory, e.g.
`https://ca.corp.example.com/certsrv`) plus `ADCS_USERNAME`/`ADCS_PASSWORD`
and, optionally, `ADCS_TEMPLATE`. `ADCS_ALLOW_BASIC_AUTH=true` lets the
client fall back to HTTP Basic if the server asks for it instead of
NTLM/Negotiate — only ever set that behind TLS. `SELFSIGNED_VALIDITY`
(a Go duration, default `8760h`/365 days) controls how long a
self-signed certificate is valid for; there's nothing else to configure
for it.

### Network discovery safety bounds

`backend/internal/discovery/scanner.go` hard-caps every scan so it can't
become a network-hammering tool by accident: at most 20,000 expanded
targets (a CIDR that would expand past that is rejected outright, not
silently truncated), 32 ports, and 64 concurrent workers, with timeouts
clamped to 200ms–30s. These aren't configurable via environment variable
on purpose — they're safety rails, not tuning knobs.
