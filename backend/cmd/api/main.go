package main

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/yilmazerhan/ssl-manager/backend/internal/api"
	"github.com/yilmazerhan/ssl-manager/backend/internal/apikey"
	"github.com/yilmazerhan/ssl-manager/backend/internal/audit"
	"github.com/yilmazerhan/ssl-manager/backend/internal/auth"
	"github.com/yilmazerhan/ssl-manager/backend/internal/ca"
	"github.com/yilmazerhan/ssl-manager/backend/internal/caaccount"
	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
	"github.com/yilmazerhan/ssl-manager/backend/internal/config"
	"github.com/yilmazerhan/ssl-manager/backend/internal/db"
	"github.com/yilmazerhan/ssl-manager/backend/internal/discovery"
	"github.com/yilmazerhan/ssl-manager/backend/internal/downloadtoken"
	"github.com/yilmazerhan/ssl-manager/backend/internal/notify"
	"github.com/yilmazerhan/ssl-manager/backend/internal/order"
	"github.com/yilmazerhan/ssl-manager/backend/internal/renewal"
	"github.com/yilmazerhan/ssl-manager/backend/internal/secrets"
	"github.com/yilmazerhan/ssl-manager/backend/internal/user"
)

func main() {
	cfg := config.Load()

	// Refuse to run with a forgeable session secret unless this is
	// unmistakably a dev/test deployment (DevAuthEnabled is itself an
	// explicit "not production" flag). Anyone who reads this repo's source
	// knows the default string; on a real deployment where an operator
	// forgot to set SESSION_SECRET, that would mean anyone can forge a
	// valid admin session JWT with no credentials at all.
	if !cfg.DevAuthEnabled && (cfg.SessionSecret == "" || cfg.SessionSecret == config.InsecureDefaultSessionSecret) {
		log.Fatal("SESSION_SECRET is unset (or still the insecure default) and DEV_AUTH_ENABLED is false — refusing to start with a forgeable session secret in what looks like a production configuration")
	}
	// DevAuthEnabled itself is the bigger risk this check leans on: it
	// registers POST /auth/dev-login, which mints a real session for any
	// email/role/team with zero credential check. Being the escape hatch
	// for the check above doesn't make it safe — a deployment could set
	// this specifically to sail past that check while still being fully
	// exposed. Warn loudly every time it's on, the same as the
	// InsecureSkipVerify flags below, so it can't go unnoticed in a
	// deployment's own startup logs.
	if cfg.DevAuthEnabled {
		log.Println("SECURITY WARNING: DEV_AUTH_ENABLED is true — POST /auth/dev-login will mint a real session for ANY email/role/team with no credential check at all. This must never be true on anything reachable outside local development.")
	}
	if cfg.ADCSAllowBasicAuth && !strings.HasPrefix(cfg.ADCSBaseURL, "https://") {
		log.Fatal("ADCS_ALLOW_BASIC_AUTH is set but ADCS_BASE_URL is not https:// — refusing to start, since that would send credentials in cleartext")
	}
	if cfg.LetsEncryptInsecureSkipVerify {
		log.Println("SECURITY WARNING: LETSENCRYPT_INSECURE_SKIP_VERIFY is true — TLS verification against the ACME directory is disabled. This must never be set against a real CA, only a local test server like Pebble.")
	}
	if cfg.ADCSInsecureSkipVerify {
		log.Println("SECURITY WARNING: ADCS_INSECURE_SKIP_VERIFY is true — TLS verification against the AD CS server is disabled. Only use this against a CA whose certificate you can't otherwise validate for a known-good reason.")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("connect to database: %v", err)
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		log.Fatalf("run migrations: %v", err)
	}

	keyManager, err := secrets.NewVaultKeyManager(cfg.VaultAddr, cfg.VaultToken, cfg.VaultTransitMount)
	if err != nil {
		log.Fatalf("connect to vault (transit): %v", err)
	}
	secretStore, err := secrets.NewVaultSecretStore(cfg.VaultAddr, cfg.VaultToken, cfg.VaultKVMount)
	if err != nil {
		log.Fatalf("connect to vault (kv): %v", err)
	}

	certs := certificate.NewPostgresStore(pool)
	orders := order.NewPostgresStore(pool)
	users := user.NewPostgresStore(pool)
	seedDefaultAdmin(ctx, users)
	accounts := caaccount.NewPostgresStore(pool)
	apiKeys := apikey.NewPostgresStore(pool)
	downloadTokens := downloadtoken.NewPostgresStore(pool)
	auditStore := audit.NewPostgresStore(pool)
	discoveryService := discovery.NewService(discovery.NewPostgresStore(pool), certs)
	if err := discoveryService.RecoverInterruptedScans(ctx); err != nil {
		log.Printf("discovery: recover interrupted scans: %v", err)
	}

	dnsAutomation, err := ca.NewDNSAutomation(cfg.DNS01Provider)
	if err != nil {
		log.Fatalf("initialize DNS-01 automation: %v", err)
	}
	if dnsAutomation == nil {
		log.Println("DNS-01 automation is not configured (DNS01_PROVIDER unset) — DNS-01 falls back to manual instructions")
	}

	letsEncrypt, err := ca.NewLetsEncrypt(ctx, ca.LetsEncryptConfig{
		Environment:        cfg.LetsEncryptEnvironment,
		DirectoryURL:       cfg.LetsEncryptDirectoryURL,
		ContactEmail:       cfg.LetsEncryptEmail,
		InsecureSkipVerify: cfg.LetsEncryptInsecureSkipVerify,
	}, secretStore, accounts, dnsAutomation)
	if err != nil {
		log.Fatalf("initialize Let's Encrypt client: %v", err)
	}
	zeroSSL := ca.NewZeroSSL(ca.ZeroSSLConfig{APIKey: cfg.ZeroSSLAPIKey, BaseURL: cfg.ZeroSSLBaseURL})
	selfSigned := ca.NewSelfSigned(cfg.SelfSignedValidity)
	authorities := ca.Registry(letsEncrypt, zeroSSL, selfSigned)
	if cfg.ADCSBaseURL != "" {
		authorities["adcs"] = ca.NewADCS(ca.ADCSConfig{
			BaseURL:            cfg.ADCSBaseURL,
			Template:           cfg.ADCSTemplate,
			Username:           cfg.ADCSUsername,
			Password:           cfg.ADCSPassword,
			AllowBasicAuth:     cfg.ADCSAllowBasicAuth,
			InsecureSkipVerify: cfg.ADCSInsecureSkipVerify,
		})
	} else {
		log.Println("AD CS is not configured (ADCS_BASE_URL unset) — the adcs certificate authority is unavailable")
	}

	integrationsStatus := buildIntegrationsStatus(ctx, cfg, accounts, dnsAutomation != nil)
	integrationsStatus.SelfSigned.Available = true
	integrationsStatus.SelfSigned.ValidityPeriod = cfg.SelfSignedValidity.String()
	integrationsStatus.ADCS.Configured = cfg.ADCSBaseURL != ""
	integrationsStatus.ADCS.BaseURL = stripURLCredentials(cfg.ADCSBaseURL)
	integrationsStatus.ADCS.Template = cfg.ADCSTemplate

	orderService := order.NewService(orders, certs, keyManager, authorities)

	notifier := buildNotifier(cfg)
	reminderSettings := renewal.NewPostgresSettingsStore(pool)
	notifyLog := renewal.NewPostgresNotifyLogStore(pool)

	systemUser, err := users.GetOrCreateByOIDCSubject(ctx, "system:renewal-engine", "system@ssl-sentry.local")
	if err != nil {
		log.Fatalf("bootstrap system user: %v", err)
	}
	renewalEngine := renewal.NewEngine(certs, orderService, auditStore, notifier, reminderSettings, notifyLog, renewal.Config{
		Interval:     cfg.RenewalInterval,
		SystemUserID: systemUser.ID,
	})
	go renewalEngine.Run(ctx)

	sessions := auth.NewSessionManager(cfg.SessionSecret, cfg.SessionTTL)
	var oidcHandler *auth.OIDCHandler
	if cfg.OIDCEnabled {
		oidcHandler, err = auth.NewOIDCHandler(ctx, auth.OIDCConfig{
			IssuerURL:    cfg.OIDCIssuerURL,
			ClientID:     cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret,
			RedirectURL:  cfg.OIDCRedirectURL,
			FrontendURL:  cfg.FrontendURL,
		}, sessions, users, cfg.SessionSecret)
		if err != nil {
			log.Fatalf("initialize OIDC: %v", err)
		}
	} else {
		log.Println("OIDC is not configured (OIDC_ISSUER_URL unset) — only dev-login/API keys will work")
	}

	router := api.NewRouter(api.Dependencies{
		Certs:                certs,
		Orders:               orderService,
		Renewal:              renewalEngine,
		Users:                users,
		Sessions:             sessions,
		APIKeys:              apiKeys,
		DownloadTokens:       downloadTokens,
		Audit:                auditStore,
		OIDC:                 oidcHandler,
		DevAuthEnabled:       cfg.DevAuthEnabled,
		Authorities:          authorities,
		Integrations:         integrationsStatus,
		Discovery:            discoveryService,
		NotificationSettings: reminderSettings,
		NotifyLog:            notifyLog,
	})

	server := &http.Server{Addr: cfg.Addr, Handler: router}
	go func() {
		log.Printf("ssl-manager api listening on %s", cfg.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

// seedDefaultAdmin creates the well-known "admin"/"admin" local account
// the very first time this app ever runs against a given database — and
// never again, so deleting or renaming it afterward sticks. It's the only
// way in without configuring OIDC first, which is exactly what makes it
// dangerous: MustChangePassword forces the password away from "admin" on
// first login (enforced server-side by auth.RequirePasswordChange, not
// just the frontend), and this prints a warning every time the account is
// created so it can't seed silently in a deployment's own startup logs.
func seedDefaultAdmin(ctx context.Context, users *user.PostgresStore) {
	n, err := users.CountLocalUsers(ctx)
	if err != nil {
		log.Printf("check for existing local accounts: %v", err)
		return
	}
	if n > 0 {
		return
	}
	hash, err := auth.HashPassword("admin")
	if err != nil {
		log.Fatalf("hash default admin password: %v", err)
	}
	if err := users.EnsureLocalAdmin(ctx, "admin", "admin@local.ssl-manager", hash, user.RoleAdmin); err != nil {
		log.Printf("seed default admin account: %v", err)
		return
	}
	log.Println("SECURITY WARNING: no local account existed yet, so a default account was seeded — username \"admin\", password \"admin\", role admin. It must change its password on first login (enforced server-side). Change it immediately if this instance is reachable by anyone you don't trust with admin access.")
}

// buildIntegrationsStatus is a one-time snapshot for the admin-facing
// "is this connected" page (docs/plan.html section 08) — it never handles
// a request itself, so a stale AccountRegistered flag after a mid-run
// re-registration isn't a concern in practice (that only happens once,
// at startup, before this snapshot is even taken).
func buildIntegrationsStatus(ctx context.Context, cfg config.Config, accounts caaccount.Store, dnsConfigured bool) api.IntegrationsStatus {
	var status api.IntegrationsStatus

	status.LetsEncrypt.Environment = cfg.LetsEncryptEnvironment
	status.LetsEncrypt.DirectoryURL = stripURLCredentials(cfg.LetsEncryptDirectoryURL)
	status.LetsEncrypt.ContactEmail = cfg.LetsEncryptEmail
	if account, err := accounts.Get(ctx, "letsencrypt", cfg.LetsEncryptEnvironment); err == nil {
		status.LetsEncrypt.AccountRegistered = account.AccountRef != ""
	}

	status.ZeroSSL.Configured = cfg.ZeroSSLAPIKey != ""
	status.ZeroSSL.BaseURL = cfg.ZeroSSLBaseURL

	status.DNS01.Provider = cfg.DNS01Provider
	status.DNS01.Configured = dnsConfigured

	return status
}

// stripURLCredentials removes any embedded userinfo (https://user:pass@…)
// before a configured CA URL is echoed back through GET /api/v1/integrations
// — an admin-only endpoint, but there's no reason for it to ever repeat a
// credential an operator (mis)configured directly into a URL rather than
// its own dedicated username/password field. Falls back to the raw string
// if it doesn't parse as a URL at all, since this is a display value, not
// something anything else depends on.
func stripURLCredentials(rawURL string) string {
	if rawURL == "" {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.User = nil
	return u.String()
}

func buildNotifier(cfg config.Config) notify.Sender {
	senders := notify.MultiSender{notify.ConsoleSender{}}
	if cfg.SMTPAddr != "" && len(cfg.SMTPTo) > 0 {
		senders = append(senders, &notify.SMTPSender{
			Addr: cfg.SMTPAddr, Username: cfg.SMTPUsername, Password: cfg.SMTPPassword,
			From: cfg.SMTPFrom, To: cfg.SMTPTo,
		})
	}
	if cfg.WebhookURL != "" {
		senders = append(senders, notify.NewWebhookSender(cfg.WebhookURL))
	}
	return senders
}
