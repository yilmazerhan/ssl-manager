// Package api implements the REST surface from docs/plan.html (section 07).
// Auth (API keys / OAuth2 client-credentials, scopes such as certs:read vs
// certs:export) is not wired in yet — every handler is reachable
// unauthenticated, which is fine for local development but must not ship.
package api

import (
	"net/http"

	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
	"github.com/yilmazerhan/ssl-manager/backend/internal/order"
)

func NewRouter(certs certificate.Store, orders *order.Service) http.Handler {
	h := &handlers{certs: certs, orders: orders}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", h.health)

	mux.HandleFunc("GET /api/v1/certificates", h.listCertificates)
	mux.HandleFunc("GET /api/v1/certificates/{id}", h.getCertificate)
	mux.HandleFunc("GET /api/v1/certificates/{id}/download", h.downloadCertificate)
	mux.HandleFunc("GET /api/v1/certificates/{id}/history", h.certificateHistory)
	mux.HandleFunc("POST /api/v1/certificates/{id}/renew", h.renewCertificate)

	mux.HandleFunc("POST /api/v1/certificate-orders", h.createOrder)
	mux.HandleFunc("GET /api/v1/certificate-orders/{id}", h.getOrder)
	mux.HandleFunc("POST /api/v1/certificate-orders/{id}/validate", h.validateOrder)

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
