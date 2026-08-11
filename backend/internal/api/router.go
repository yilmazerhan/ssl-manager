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
	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
	"github.com/yilmazerhan/ssl-manager/backend/internal/downloadtoken"
	"github.com/yilmazerhan/ssl-manager/backend/internal/order"
	"github.com/yilmazerhan/ssl-manager/backend/internal/renewal"
	"github.com/yilmazerhan/ssl-manager/backend/internal/user"
)

type Dependencies struct {
	Certs          certificate.Store
	Orders         *order.Service
	Renewal        *renewal.Engine
	Users          user.Store
	Sessions       *auth.SessionManager
	APIKeys        apikey.Store
	DownloadTokens downloadtoken.Store
	Audit          audit.Store
	OIDC           *auth.OIDCHandler // nil if OIDC isn't configured
	DevAuthEnabled bool
	Authorities    map[string]ca.Authority
}

func NewRouter(deps Dependencies) http.Handler {
	h := &handlers{deps: deps}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", h.health)

	if deps.OIDC != nil {
		mux.HandleFunc("GET /auth/login", deps.OIDC.Login)
		mux.HandleFunc("GET /auth/callback", deps.OIDC.Callback)
	}
	if deps.DevAuthEnabled {
		mux.HandleFunc("POST /auth/dev-login", auth.DevLoginHandler(deps.Sessions, deps.Users))
	}

	authed := auth.Middleware(deps.Sessions, deps.Users, deps.APIKeys)

	mux.Handle("GET /api/v1/certificates", authed(auth.RequireScope(auth.ScopeCertsRead)(http.HandlerFunc(h.listCertificates))))
	mux.Handle("GET /api/v1/certificates/{id}", authed(auth.RequireScope(auth.ScopeCertsRead)(http.HandlerFunc(h.getCertificate))))
	mux.Handle("GET /api/v1/certificates/{id}/history", authed(auth.RequireScope(auth.ScopeCertsRead)(http.HandlerFunc(h.certificateHistory))))
	mux.Handle("GET /api/v1/certificates/{id}/audit", authed(auth.RequireScope(auth.ScopeCertsRead)(http.HandlerFunc(h.certificateAudit))))
	mux.Handle("POST /api/v1/certificates/{id}/download-token", authed(auth.RequireScope(auth.ScopeCertsExport)(http.HandlerFunc(h.issueDownloadToken))))
	mux.Handle("GET /api/v1/certificates/{id}/download", authed(auth.RequireScope(auth.ScopeCertsExport)(http.HandlerFunc(h.downloadCertificate))))
	mux.Handle("POST /api/v1/certificates/{id}/renew", authed(auth.RequireScope(auth.ScopeCertsIssue)(http.HandlerFunc(h.renewCertificate))))
	mux.Handle("POST /api/v1/certificates/{id}/revoke", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.revokeCertificate))))

	mux.Handle("POST /api/v1/certificate-orders", authed(auth.RequireScope(auth.ScopeCertsIssue)(http.HandlerFunc(h.createOrder))))
	mux.Handle("GET /api/v1/certificate-orders/{id}", authed(auth.RequireScope(auth.ScopeCertsRead)(http.HandlerFunc(h.getOrder))))
	mux.Handle("POST /api/v1/certificate-orders/{id}/validate", authed(auth.RequireScope(auth.ScopeCertsIssue)(http.HandlerFunc(h.validateOrder))))

	mux.Handle("GET /api/v1/users", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.listUsers))))
	mux.Handle("POST /api/v1/users/{id}/role", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.setUserRole))))
	mux.Handle("POST /api/v1/users/{id}/api-keys", authed(auth.RequireScope(auth.ScopeCertsAdmin)(http.HandlerFunc(h.createAPIKey))))

	return withCORS(mux)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
