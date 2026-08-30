package main

import (
	"context"
	"log"
	"net/http"
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
	"github.com/yilmazerhan/ssl-manager/backend/internal/caconfig"
	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
	"github.com/yilmazerhan/ssl-manager/backend/internal/config"
	"github.com/yilmazerhan/ssl-manager/backend/internal/db"
	"github.com/yilmazerhan/ssl-manager/backend/internal/discovery"
	"github.com/yilmazerhan/ssl-manager/backend/internal/downloadtoken"
	"github.com/yilmazerhan/ssl-manager/backend/internal/k8s"
	"github.com/yilmazerhan/ssl-manager/backend/internal/notify"
	"github.com/yilmazerhan/ssl-manager/backend/internal/order"
	"github.com/yilmazerhan/ssl-manager/backend/internal/renewal"
	"github.com/yilmazerhan/ssl-manager/backend/internal/secrets"
	"github.com/yilmazerhan/ssl-manager/backend/internal/user"
	"github.com/yilmazerhan/ssl-manager/backend/internal/winrm"
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
	go discoveryService.Run(ctx)

	// CA/DNS integration settings are editable at runtime from here on
	// (see internal/api's integration handlers) — the database, not the
	// environment, is the source of truth for them. Environment variables
	// only matter on the very first run against a given database, seeding
	// initial values exactly once, the same pattern seedDefaultAdmin above
	// already uses for the local admin account.
	caSettings := caconfig.NewPostgresStore(pool)
	seedCASettingsFromEnv(ctx, caSettings, secretStore, cfg)

	var leSettings caconfig.LetsEncryptSettings
	if _, err := caSettings.Get(ctx, "letsencrypt", &leSettings); err != nil {
		log.Fatalf("load Let's Encrypt settings: %v", err)
	}
	var zsSettings caconfig.ZeroSSLSettings
	if _, err := caSettings.Get(ctx, "zerossl", &zsSettings); err != nil {
		log.Fatalf("load ZeroSSL settings: %v", err)
	}
	var adcsSettings caconfig.ADCSSettings
	if _, err := caSettings.Get(ctx, "adcs", &adcsSettings); err != nil {
		log.Fatalf("load AD CS settings: %v", err)
	}
	var dnsSettings caconfig.DNS01Settings
	if _, err := caSettings.Get(ctx, "dns01", &dnsSettings); err != nil {
		log.Fatalf("load DNS-01 settings: %v", err)
	}
	var selfSignedSettings caconfig.SelfSignedSettings
	if _, err := caSettings.Get(ctx, "selfsigned", &selfSignedSettings); err != nil {
		log.Fatalf("load self-signed settings: %v", err)
	}

	// The same safety check the ADCS PUT handler re-enforces on every
	// future edit (integrations.go) — checked here too since this
	// particular value can come straight from the environment on a first
	// run, before any edit has ever gone through that handler.
	if adcsSettings.AllowBasicAuth && !strings.HasPrefix(adcsSettings.BaseURL, "https://") {
		log.Fatal("AD CS is configured with allow_basic_auth set but a non-https base_url — refusing to start, since that would send credentials in cleartext")
	}

	dnsAutomation, err := ca.NewDNSAutomationWithToken(dnsSettings.Provider, vaultSecretString(ctx, secretStore, caconfig.SecretPathDNS01, "token"))
	if err != nil {
		log.Fatalf("initialize DNS-01 automation: %v", err)
	}
	dnsHolder := ca.NewDNSHolder(dnsAutomation)
	if dnsAutomation == nil {
		log.Println("DNS-01 automation is not configured — DNS-01 falls back to manual instructions")
	}

	// A Let's Encrypt account registration failure — a bad contact email, a
	// directory outage, a rate limit — is an environment problem, not a
	// reason to refuse to serve anything at all: certificate inventory,
	// discovery, notifications, and the other three CA integrations have
	// nothing to do with it. Log it and leave "letsencrypt" out of the
	// registry, the same way ADCS is left out below when unconfigured, so
	// an order that actually requests it fails with a clear "provider not
	// available" instead of the whole backend refusing to start.
	letsEncrypt, err := ca.NewLetsEncrypt(ctx, ca.LetsEncryptConfig{
		Environment:        leSettings.Environment,
		DirectoryURL:       leSettings.DirectoryURL,
		ContactEmail:       leSettings.ContactEmail,
		InsecureSkipVerify: cfg.LetsEncryptInsecureSkipVerify,
	}, secretStore, accounts, dnsAutomation)
	if err != nil {
		log.Printf("Let's Encrypt is not available: %v — certificate orders requesting ca_provider=letsencrypt will fail until this is fixed from the Integrations screen (or the backend is restarted after fixing it)", err)
	}
	zeroSSL := ca.NewZeroSSL(ca.ZeroSSLConfig{
		APIKey:  vaultSecretString(ctx, secretStore, caconfig.SecretPathZeroSSL, "api_key"),
		BaseURL: zsSettings.BaseURL,
	})
	selfSignedValidity := time.Duration(selfSignedSettings.ValidityDays) * 24 * time.Hour
	selfSigned := ca.NewSelfSigned(selfSignedValidity)
	var authorities *ca.Registry
	if letsEncrypt != nil {
		authorities = ca.NewRegistry(letsEncrypt, zeroSSL, selfSigned)
	} else {
		authorities = ca.NewRegistry(zeroSSL, selfSigned)
	}
	if adcsSettings.BaseURL != "" {
		authorities.Set("adcs", ca.NewADCS(ca.ADCSConfig{
			BaseURL:            adcsSettings.BaseURL,
			Template:           adcsSettings.Template,
			Username:           adcsSettings.Username,
			Password:           vaultSecretString(ctx, secretStore, caconfig.SecretPathADCS, "password"),
			AllowBasicAuth:     adcsSettings.AllowBasicAuth,
			InsecureSkipVerify: cfg.ADCSInsecureSkipVerify,
		}))
	} else {
		log.Println("AD CS is not configured — the adcs certificate authority is unavailable")
	}

	orderService := order.NewService(orders, certs, keyManager, authorities)

	k8sService := k8s.NewService(k8s.NewPostgresStore(pool), certs, secretStore, keyManager)
	winrmService := winrm.NewService(winrm.NewPostgresStore(pool), certs, secretStore, keyManager)
	orderService.SetOnIssued(func(_ context.Context, certificateID string) {
		// Both run detached from the issuance/renewal request's own
		// context — an unreachable cluster/host must never hold up or
		// fail the request that triggered it (see each Service's own
		// SyncCertificate doc comment).
		go k8sService.SyncCertificate(context.Background(), certificateID)
		go winrmService.SyncCertificate(context.Background(), certificateID)
	})

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
		Certs:                         certs,
		Orders:                        orderService,
		Renewal:                       renewalEngine,
		K8s:                           k8sService,
		WinRM:                         winrmService,
		Users:                         users,
		Sessions:                      sessions,
		APIKeys:                       apiKeys,
		DownloadTokens:                downloadTokens,
		Audit:                         auditStore,
		OIDC:                          oidcHandler,
		DevAuthEnabled:                cfg.DevAuthEnabled,
		Authorities:                   authorities,
		Discovery:                     discoveryService,
		NotificationSettings:          reminderSettings,
		NotifyLog:                     notifyLog,
		CASettings:                    caSettings,
		Secrets:                       secretStore,
		CAAccounts:                    accounts,
		DNSAutomation:                 dnsHolder,
		LetsEncryptInsecureSkipVerify: cfg.LetsEncryptInsecureSkipVerify,
		ADCSInsecureSkipVerify:        cfg.ADCSInsecureSkipVerify,
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

// seedCASettingsFromEnv copies each CA/DNS integration's environment-variable
// configuration into caconfig — but only the very first time this app runs
// against a given database, exactly once per provider, the same "env seeds
// DB, DB wins forever after" pattern seedDefaultAdmin uses. Once an admin
// edits a provider from the Integrations screen (see internal/api's
// integration handlers), its environment variables are never consulted
// again, even across restarts — the whole point of making these editable.
func seedCASettingsFromEnv(ctx context.Context, caSettings caconfig.Store, secretStore secrets.SecretStore, cfg config.Config) {
	var le caconfig.LetsEncryptSettings
	if found, err := caSettings.Get(ctx, "letsencrypt", &le); err != nil {
		log.Printf("check existing Let's Encrypt settings: %v", err)
	} else if !found {
		seed := caconfig.LetsEncryptSettings{Environment: cfg.LetsEncryptEnvironment, DirectoryURL: cfg.LetsEncryptDirectoryURL, ContactEmail: cfg.LetsEncryptEmail}
		if err := caSettings.Set(ctx, "letsencrypt", seed); err != nil {
			log.Printf("seed Let's Encrypt settings from environment: %v", err)
		}
	}

	var zs caconfig.ZeroSSLSettings
	if found, err := caSettings.Get(ctx, "zerossl", &zs); err != nil {
		log.Printf("check existing ZeroSSL settings: %v", err)
	} else if !found {
		if err := caSettings.Set(ctx, "zerossl", caconfig.ZeroSSLSettings{BaseURL: cfg.ZeroSSLBaseURL}); err != nil {
			log.Printf("seed ZeroSSL settings from environment: %v", err)
		}
		if cfg.ZeroSSLAPIKey != "" {
			if err := secretStore.Put(ctx, caconfig.SecretPathZeroSSL, map[string]interface{}{"api_key": cfg.ZeroSSLAPIKey}); err != nil {
				log.Printf("seed ZeroSSL API key from environment: %v", err)
			}
		}
	}

	var adcs caconfig.ADCSSettings
	if found, err := caSettings.Get(ctx, "adcs", &adcs); err != nil {
		log.Printf("check existing AD CS settings: %v", err)
	} else if !found {
		seed := caconfig.ADCSSettings{BaseURL: cfg.ADCSBaseURL, Template: cfg.ADCSTemplate, Username: cfg.ADCSUsername, AllowBasicAuth: cfg.ADCSAllowBasicAuth}
		if err := caSettings.Set(ctx, "adcs", seed); err != nil {
			log.Printf("seed AD CS settings from environment: %v", err)
		}
		if cfg.ADCSPassword != "" {
			if err := secretStore.Put(ctx, caconfig.SecretPathADCS, map[string]interface{}{"password": cfg.ADCSPassword}); err != nil {
				log.Printf("seed AD CS password from environment: %v", err)
			}
		}
	}

	var dns caconfig.DNS01Settings
	if found, err := caSettings.Get(ctx, "dns01", &dns); err != nil {
		log.Printf("check existing DNS-01 settings: %v", err)
	} else if !found {
		if err := caSettings.Set(ctx, "dns01", caconfig.DNS01Settings{Provider: cfg.DNS01Provider}); err != nil {
			log.Printf("seed DNS-01 settings from environment: %v", err)
		}
		if cfg.CloudflareDNSAPIToken != "" {
			if err := secretStore.Put(ctx, caconfig.SecretPathDNS01, map[string]interface{}{"token": cfg.CloudflareDNSAPIToken}); err != nil {
				log.Printf("seed DNS-01 token from environment: %v", err)
			}
		}
	}

	var ss caconfig.SelfSignedSettings
	if found, err := caSettings.Get(ctx, "selfsigned", &ss); err != nil {
		log.Printf("check existing self-signed settings: %v", err)
	} else if !found {
		days := int(cfg.SelfSignedValidity / (24 * time.Hour))
		if days <= 0 {
			days = 365
		}
		if err := caSettings.Set(ctx, "selfsigned", caconfig.SelfSignedSettings{ValidityDays: days}); err != nil {
			log.Printf("seed self-signed settings from environment: %v", err)
		}
	}
}

// vaultSecretString fetches a single string field from a Vault secret,
// returning "" if the secret (or that field within it) doesn't exist —
// used to load the current value of a CA credential that lives in Vault
// rather than caconfig's Postgres-backed settings.
func vaultSecretString(ctx context.Context, store secrets.SecretStore, path, field string) string {
	data, err := store.Get(ctx, path)
	if err != nil || data == nil {
		return ""
	}
	v, _ := data[field].(string)
	return v
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
