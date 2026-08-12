// Package config loads every setting the backend needs from the
// environment, with defaults that make `go run ./cmd/api` work against a
// local Postgres and Vault dev server out of the box. Nothing here is
// secret by itself — actual secrets (Vault token, OIDC client secret,
// SMTP password) are expected to arrive the same way in any real
// deployment: environment variables injected by the orchestrator, not
// checked into the repo.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr string

	DatabaseURL string

	VaultAddr         string
	VaultToken        string
	VaultTransitMount string
	VaultKVMount      string

	LetsEncryptDirectoryURL       string
	LetsEncryptEnvironment        string
	LetsEncryptEmail              string
	LetsEncryptInsecureSkipVerify bool
	// DNS01Provider names a real DNS provider (currently "cloudflare") to
	// automate DNS-01 TXT records; empty means DNS-01 falls back to manual
	// instructions, same as HTTP-01.
	DNS01Provider string

	ZeroSSLAPIKey  string
	ZeroSSLBaseURL string

	// SelfSignedValidity is how long a selfsigned-provider certificate is
	// valid for. It's always available — there's no external account to
	// configure — unlike every other provider here.
	SelfSignedValidity time.Duration

	// ADCS* configure the Active Directory Certificate Services provider.
	// Leaving ADCSBaseURL empty disables it — there's no sensible default
	// certsrv URL to fall back to.
	ADCSBaseURL            string
	ADCSTemplate           string
	ADCSUsername           string
	ADCSPassword           string
	ADCSAllowBasicAuth     bool
	ADCSInsecureSkipVerify bool

	SessionSecret string
	SessionTTL    time.Duration

	OIDCIssuerURL    string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
	FrontendURL      string
	OIDCEnabled      bool

	// DevAuthEnabled turns on POST /auth/dev-login, which issues a session
	// for any email/role with no identity provider at all. It exists only
	// for local development and must never be true in a real deployment.
	DevAuthEnabled bool

	SMTPAddr     string
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string
	SMTPTo       []string

	WebhookURL string

	RenewalInterval time.Duration
}

func Load() Config {
	return Config{
		Addr: getEnv("SSL_MANAGER_ADDR", ":8080"),

		DatabaseURL: getEnv("DATABASE_URL", "postgres://ssl_manager:ssl_manager_dev@localhost:5432/ssl_manager"),

		VaultAddr:         getEnv("VAULT_ADDR", "http://127.0.0.1:8200"),
		VaultToken:        getEnv("VAULT_TOKEN", ""),
		VaultTransitMount: getEnv("VAULT_TRANSIT_MOUNT", "transit"),
		VaultKVMount:      getEnv("VAULT_KV_MOUNT", "secret"),

		LetsEncryptDirectoryURL:       getEnv("LETSENCRYPT_DIRECTORY_URL", "https://acme-staging-v02.api.letsencrypt.org/directory"),
		LetsEncryptEnvironment:        getEnv("LETSENCRYPT_ENVIRONMENT", "staging"),
		LetsEncryptEmail:              getEnv("LETSENCRYPT_EMAIL", "admin@example.com"),
		LetsEncryptInsecureSkipVerify: getBool("LETSENCRYPT_INSECURE_SKIP_VERIFY", false),
		DNS01Provider:                 getEnv("DNS01_PROVIDER", ""),

		ZeroSSLAPIKey:  getEnv("ZEROSSL_API_KEY", ""),
		ZeroSSLBaseURL: getEnv("ZEROSSL_BASE_URL", "https://api.zerossl.com"),

		SelfSignedValidity: getDuration("SELFSIGNED_VALIDITY", 365*24*time.Hour),

		ADCSBaseURL:            getEnv("ADCS_BASE_URL", ""),
		ADCSTemplate:           getEnv("ADCS_TEMPLATE", ""),
		ADCSUsername:           getEnv("ADCS_USERNAME", ""),
		ADCSPassword:           getEnv("ADCS_PASSWORD", ""),
		ADCSAllowBasicAuth:     getBool("ADCS_ALLOW_BASIC_AUTH", false),
		ADCSInsecureSkipVerify: getBool("ADCS_INSECURE_SKIP_VERIFY", false),

		SessionSecret: getEnv("SESSION_SECRET", "insecure-dev-secret-change-me"),
		SessionTTL:    getDuration("SESSION_TTL", 12*time.Hour),

		OIDCIssuerURL:    getEnv("OIDC_ISSUER_URL", ""),
		OIDCClientID:     getEnv("OIDC_CLIENT_ID", ""),
		OIDCClientSecret: getEnv("OIDC_CLIENT_SECRET", ""),
		OIDCRedirectURL:  getEnv("OIDC_REDIRECT_URL", "http://localhost:8080/auth/callback"),
		FrontendURL:      getEnv("FRONTEND_URL", "http://localhost:5173"),
		OIDCEnabled:      getEnv("OIDC_ISSUER_URL", "") != "",

		DevAuthEnabled: getBool("DEV_AUTH_ENABLED", false),

		SMTPAddr:     getEnv("SMTP_ADDR", ""),
		SMTPUsername: getEnv("SMTP_USERNAME", ""),
		SMTPPassword: getEnv("SMTP_PASSWORD", ""),
		SMTPFrom:     getEnv("SMTP_FROM", "ssl-sentry@example.com"),
		SMTPTo:       getList("SMTP_TO"),

		WebhookURL: getEnv("NOTIFY_WEBHOOK_URL", ""),

		RenewalInterval: getDuration("RENEWAL_INTERVAL", 24*time.Hour),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func getDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func getList(key string) []string {
	v := os.Getenv(key)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
