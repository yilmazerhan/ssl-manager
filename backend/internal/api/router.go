// Package api implements the REST surface from docs/plan.html (section 07):
// versioned endpoints, scoped by RBAC (internal/auth), with certificate
// metadata and certificate material on separate scopes.
package api

import (
	"net/http"

	"github.com/yilmazerhan/ssl-manager/backend/internal/apikey"
	"github.com/yilmazerhan/ssl-manager/backend/internal/audit"
	"github.com/yilmazerhan/ssl-manager/backend/internal/auth"
	"github.com/yilmazerhan/ssl-manager/backend/internal/ca"
	"github.com/yilmazerhan/ssl-manager/backend/internal/caaccount"
	"github.com/yilmazerhan/ssl-manager/backend/internal/caconfig"
	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
	"github.com/yilmazerhan/ssl-manager/backend/internal/discovery"
	"github.com/yilmazerhan/ssl-manager/backend/internal/downloadtoken"
	"github.com/yilmazerhan/ssl-manager/backend/internal/k8s"
	"github.com/yilmazerhan/ssl-manager/backend/internal/order"
	"github.com/yilmazerhan/ssl-manager/backend/internal/renewal"
	"github.com/yilmazerhan/ssl-manager/backend/internal/secrets"
	"github.com/yilmazerhan/ssl-manager/backend/internal/user"
	"github.com/yilmazerhan/ssl-manager/backend/internal/winrm"
)

type Dependencies struct {
	Certs                certificate.Store
	Orders               *order.Service
	Renewal              *renewal.Engine
	Users                user.Store
	Sessions             *auth.SessionManager
	APIKeys              apikey.Store
	DownloadTokens       downloadtoken.Store
	Audit                audit.Store
	OIDC                 *auth.OIDCHandler // nil if OIDC isn't configured
	DevAuthEnabled       bool
	Authorities          *ca.Registry
	Discovery            *discovery.Service
	K8s                  *k8s.Service
	WinRM                *winrm.Service
	NotificationSettings renewal.SettingsStore
	NotifyLog            renewal.NotifyLogStore

	// The fields below back the editable integrations screens (GET/PUT
	// /api/v1/integrations*, see integrations.go): CASettings/Secrets/
	// CAAccounts let a handler read the current live configuration and
	// persist+hot-swap an edit into Authorities; DNSAutomation is the same
	// kind of hot-swappable holder for the one piece of CA config that
	// isn't itself a ca.Authority. The two InsecureSkipVerify flags are
	// environment-only escape hatches, never exposed for editing (see
	// caconfig.LetsEncryptSettings' and ADCSSettings' doc comments), but
	// still needed to rebuild an authority faithfully after an edit.
	CASettings                    caconfig.Store
	Secrets                       secrets.SecretStore
	CAAccounts                    caaccount.Store
	DNSAutomation                 *ca.DNSHolder
	LetsEncryptInsecureSkipVerify bool
	ADCSInsecureSkipVerify        bool
}

// IntegrationsStatus is what GET /api/v1/integrations returns — computed
// fresh on every call (not a startup snapshot: integration settings are
// now editable at runtime, see integrations.go) from the current
// caconfig-stored settings, Vault secret presence, and what's actually
// live in the Authorities registry. It answers "is this connected", the
// admin-facing question from docs/plan.html section 08, without exposing
// the credentials themselves — secret fields only ever appear as a
// "*Set bool" flag.
type IntegrationsStatus struct {
	LetsEncrypt struct {
		Environment       string `json:"environment"`
		DirectoryURL      string `json:"directory_url"`
		ContactEmail      string `json:"contact_email"`
		AccountRegistered bool   `json:"account_registered"`
	} `json:"letsencrypt"`
	ZeroSSL struct {
		Configured bool   `json:"configured"`
		BaseURL    string `json:"base_url"`
		APIKeySet  bool   `json:"api_key_set"`
	} `json:"zerossl"`
	DNS01 struct {
		Provider   string `json:"provider"`
		Configured bool   `json:"configured"`
		TokenSet   bool   `json:"token_set"`
	} `json:"dns01"`
	SelfSigned struct {
		Available      bool   `json:"available"`
		ValidityPeriod string `json:"validity_period"`
		ValidityDays   int    `json:"validity_days"`
	} `json:"selfsigned"`
	ADCS struct {
		Configured     bool   `json:"configured"`
		BaseURL        string `json:"base_url"`
		Template       string `json:"template"`
		Username       string `json:"username"`
		AllowBasicAuth bool   `json:"allow_basic_auth"`
		PasswordSet    bool   `json:"password_set"`
	} `json:"adcs"`
}

func NewRouter(deps Dependencies) http.Handler {
	h := &handlers{deps: deps}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", h.health)

	if deps.OIDC != nil {
		mux.HandleFunc("GET /auth/login", deps.OIDC.Login)
		mux.HandleFunc("GET /auth/callback", deps.OIDC.Callback)
	}
	mux.HandleFunc("POST /auth/login", auth.LocalLoginHandler(deps.Sessions, deps.Users))
	if deps.DevAuthEnabled {
		mux.HandleFunc("POST /auth/dev-login", auth.DevLoginHandler(deps.Sessions, deps.Users))
	}

	// authedOnly is plain authentication with no further gate — used only
	// by change-password, since that's the one endpoint an account with
	// MustChangePassword set must still be able to reach. Every other
	// authed route goes through `authed`, which additionally blocks until
	// that password has actually been changed.
	authedOnly := auth.Middleware(deps.Sessions, deps.Users, deps.APIKeys)
	authed := func(next http.Handler) http.Handler {
		return authedOnly(auth.RequirePasswordChange(next))
	}

	mux.Handle("POST /api/v1/auth/change-password", authedOnly(http.HandlerFunc(h.changePassword)))

	mux.Handle("GET /api/v1/certificates", authed(auth.RequireScope(auth.ScopeCertsRead)(http.HandlerFunc(h.listCertificates))))
	mux.Handle("GET /api/v1/certificates/{id}", authed(auth.RequireScope(auth.ScopeCertsRead)(http.HandlerFunc(h.getCertificate))))
	mux.Handle("GET /api/v1/certificates/{id}/history", authed(auth.RequireScope(auth.ScopeCertsRead)(http.HandlerFunc(h.certificateHistory))))
	mux.Handle("GET /api/v1/certificates/{id}/audit", authed(auth.RequireScope(auth.ScopeCertsRead)(http.HandlerFunc(h.certificateAudit))))
	mux.Handle("GET /api/v1/audit", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.listAuditLog))))
	mux.Handle("GET /api/v1/certificates/{id}/posture", authed(auth.RequireScope(auth.ScopeCertsRead)(http.HandlerFunc(h.certificatePosture))))
	mux.Handle("POST /api/v1/certificates/{id}/download-token", authed(auth.RequireScope(auth.ScopeCertsExport)(http.HandlerFunc(h.issueDownloadToken))))
	mux.Handle("GET /api/v1/certificates/{id}/download", authed(auth.RequireScope(auth.ScopeCertsExport)(http.HandlerFunc(h.downloadCertificate))))
	mux.Handle("POST /api/v1/certificates/{id}/renew", authed(auth.RequireScope(auth.ScopeCertsIssue)(http.HandlerFunc(h.renewCertificate))))
	mux.Handle("POST /api/v1/certificates/{id}/revoke", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.revokeCertificate))))

	mux.Handle("POST /api/v1/certificates/bulk-import", authed(auth.RequireScope(auth.ScopeCertsIssue)(http.HandlerFunc(h.bulkImportCertificates))))
	mux.Handle("POST /api/v1/certificates/bulk-renew", authed(auth.RequireScope(auth.ScopeCertsIssue)(http.HandlerFunc(h.bulkRenewCertificates))))
	mux.Handle("POST /api/v1/certificates/bulk-revoke", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.bulkRevokeCertificates))))

	mux.Handle("GET /api/v1/certificates/{id}/k8s-targets", authed(auth.RequireScope(auth.ScopeCertsRead)(http.HandlerFunc(h.listK8sTargets))))
	mux.Handle("POST /api/v1/certificates/{id}/k8s-targets", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.createK8sTarget))))
	mux.Handle("PUT /api/v1/certificates/{id}/k8s-targets/{targetId}", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.updateK8sTarget))))
	mux.Handle("DELETE /api/v1/certificates/{id}/k8s-targets/{targetId}", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.deleteK8sTarget))))
	mux.Handle("POST /api/v1/certificates/{id}/k8s-targets/{targetId}/sync", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.syncK8sTarget))))

	mux.Handle("GET /api/v1/certificates/{id}/winrm-targets", authed(auth.RequireScope(auth.ScopeCertsRead)(http.HandlerFunc(h.listWinRMTargets))))
	mux.Handle("POST /api/v1/certificates/{id}/winrm-targets", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.createWinRMTarget))))
	mux.Handle("PUT /api/v1/certificates/{id}/winrm-targets/{targetId}", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.updateWinRMTarget))))
	mux.Handle("DELETE /api/v1/certificates/{id}/winrm-targets/{targetId}", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.deleteWinRMTarget))))
	mux.Handle("POST /api/v1/certificates/{id}/winrm-targets/{targetId}/sync", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.syncWinRMTarget))))

	mux.Handle("POST /api/v1/certificate-orders", authed(auth.RequireScope(auth.ScopeCertsIssue)(http.HandlerFunc(h.createOrder))))
	mux.Handle("GET /api/v1/certificate-orders/{id}", authed(auth.RequireScope(auth.ScopeCertsRead)(http.HandlerFunc(h.getOrder))))
	mux.Handle("POST /api/v1/certificate-orders/{id}/validate", authed(auth.RequireScope(auth.ScopeCertsIssue)(http.HandlerFunc(h.validateOrder))))

	mux.Handle("GET /api/v1/integrations", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.getIntegrations))))
	mux.Handle("PUT /api/v1/integrations/letsencrypt", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.updateLetsEncryptSettings))))
	mux.Handle("PUT /api/v1/integrations/zerossl", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.updateZeroSSLSettings))))
	mux.Handle("PUT /api/v1/integrations/adcs", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.updateADCSSettings))))
	mux.Handle("PUT /api/v1/integrations/dns01", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.updateDNS01Settings))))
	mux.Handle("PUT /api/v1/integrations/selfsigned", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.updateSelfSignedSettings))))

	mux.Handle("POST /api/v1/discovery/scans", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.createDiscoveryScan))))
	mux.Handle("GET /api/v1/discovery/scans", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.listDiscoveryScans))))
	mux.Handle("GET /api/v1/discovery/scans/{id}", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.getDiscoveryScan))))
	mux.Handle("GET /api/v1/discovery/scans/{id}/results", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.listDiscoveryResults))))
	mux.Handle("POST /api/v1/discovery/scans/{id}/cancel", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.cancelDiscoveryScan))))

	mux.Handle("POST /api/v1/discovery/schedules", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.createDiscoverySchedule))))
	mux.Handle("GET /api/v1/discovery/schedules", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.listDiscoverySchedules))))
	mux.Handle("PUT /api/v1/discovery/schedules/{id}", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.updateDiscoverySchedule))))
	mux.Handle("DELETE /api/v1/discovery/schedules/{id}", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.deleteDiscoverySchedule))))

	mux.Handle("GET /api/v1/notification-settings", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.getNotificationSettings))))
	mux.Handle("PUT /api/v1/notification-settings", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.updateNotificationSettings))))
	mux.Handle("GET /api/v1/notifications", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.listRecentNotifications))))
	mux.Handle("GET /api/v1/certificates/{id}/notifications", authed(auth.RequireScope(auth.ScopeCertsRead)(http.HandlerFunc(h.certificateNotifications))))
	mux.Handle("POST /api/v1/certificates/{id}/notify-emails", authed(auth.RequireScope(auth.ScopeCertsIssue)(http.HandlerFunc(h.updateCertificateNotifyEmails))))

	mux.Handle("GET /api/v1/reports/summary", authed(auth.RequireScope(auth.ScopeCertsRead)(http.HandlerFunc(h.getSummaryReport))))

	mux.Handle("GET /api/v1/users", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.listUsers))))
	mux.Handle("POST /api/v1/users/{id}/role", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.setUserRole))))
	mux.Handle("POST /api/v1/users/{id}/api-keys", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.createAPIKey))))

	return withCORS(withMaxBody(mux))
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// maxRequestBodyBytes caps every request body before any handler-level
// validation runs — otherwise a caller could send a multi-gigabyte JSON
// array (a discovery scan's targets/ports, a certificate's notify_emails)
// and exhaust server memory during json.Decode, before length checks like
// MaxTargetsExpanded or maxDomainsPerOrder ever get a chance to reject it.
// 4MB is generous for anything this API legitimately accepts.
const maxRequestBodyBytes = 4 << 20

func withMaxBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		next.ServeHTTP(w, r)
	})
}
