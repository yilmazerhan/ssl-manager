package main

import (
	"context"
	"log"
	"net/http"
	"os/signal"
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
	"github.com/yilmazerhan/ssl-manager/backend/internal/downloadtoken"
	"github.com/yilmazerhan/ssl-manager/backend/internal/notify"
	"github.com/yilmazerhan/ssl-manager/backend/internal/order"
	"github.com/yilmazerhan/ssl-manager/backend/internal/renewal"
	"github.com/yilmazerhan/ssl-manager/backend/internal/secrets"
	"github.com/yilmazerhan/ssl-manager/backend/internal/user"
)

func main() {
	cfg := config.Load()

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
	accounts := caaccount.NewPostgresStore(pool)
	apiKeys := apikey.NewPostgresStore(pool)
	downloadTokens := downloadtoken.NewPostgresStore(pool)
	auditStore := audit.NewPostgresStore(pool)

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
	authorities := ca.Registry(letsEncrypt, zeroSSL)

	integrationsStatus := buildIntegrationsStatus(ctx, cfg, accounts, dnsAutomation != nil)

	orderService := order.NewService(orders, certs, keyManager, authorities)

	notifier := buildNotifier(cfg)

	systemUser, err := users.GetOrCreateByOIDCSubject(ctx, "system:renewal-engine", "system@ssl-sentry.local")
	if err != nil {
		log.Fatalf("bootstrap system user: %v", err)
	}
	renewalEngine := renewal.NewEngine(certs, orderService, auditStore, notifier, renewal.Config{
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
		Certs:          certs,
		Orders:         orderService,
		Renewal:        renewalEngine,
		Users:          users,
		Sessions:       sessions,
		APIKeys:        apiKeys,
		DownloadTokens: downloadTokens,
		Audit:          auditStore,
		OIDC:           oidcHandler,
		DevAuthEnabled: cfg.DevAuthEnabled,
		Authorities:    authorities,
		Integrations:   integrationsStatus,
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

// buildIntegrationsStatus is a one-time snapshot for the admin-facing
// "is this connected" page (docs/plan.html section 08) — it never handles
// a request itself, so a stale AccountRegistered flag after a mid-run
// re-registration isn't a concern in practice (that only happens once,
// at startup, before this snapshot is even taken).
func buildIntegrationsStatus(ctx context.Context, cfg config.Config, accounts caaccount.Store, dnsConfigured bool) api.IntegrationsStatus {
	var status api.IntegrationsStatus

	status.LetsEncrypt.Environment = cfg.LetsEncryptEnvironment
	status.LetsEncrypt.DirectoryURL = cfg.LetsEncryptDirectoryURL
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
