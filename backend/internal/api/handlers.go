package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/yilmazerhan/ssl-manager/backend/internal/audit"
	"github.com/yilmazerhan/ssl-manager/backend/internal/auth"
	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
	"github.com/yilmazerhan/ssl-manager/backend/internal/downloadtoken"
	"github.com/yilmazerhan/ssl-manager/backend/internal/order"
	"github.com/yilmazerhan/ssl-manager/backend/internal/user"
)

type handlers struct {
	deps Dependencies
}

func (h *handlers) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *handlers) getIntegrations(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.deps.Integrations)
}

func (h *handlers) listCertificates(w http.ResponseWriter, r *http.Request) {
	identity, _ := auth.IdentityFromContext(r.Context())

	filter := certificate.Filter{
		Status:     certificate.Status(r.URL.Query().Get("status")),
		CAProvider: r.URL.Query().Get("ca_provider"),
	}
	if days := r.URL.Query().Get("expiring_within_days"); days != "" {
		if n, err := strconv.Atoi(days); err == nil {
			filter.ExpiringWithinDays = n
		}
	}
	if identity.Role == user.RoleAdmin || identity.Role == user.RoleAPIOnly {
		filter.Team = r.URL.Query().Get("team")
	} else {
		filter.Team = identity.Team
	}

	certs, err := h.deps.Certs.List(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list certificates")
		return
	}
	writeJSON(w, http.StatusOK, certs)
}

func (h *handlers) getCertificate(w http.ResponseWriter, r *http.Request) {
	cert, ok := h.loadCertificateForTeam(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, cert)
}

func (h *handlers) certificateHistory(w http.ResponseWriter, r *http.Request) {
	cert, ok := h.loadCertificateForTeam(w, r)
	if !ok {
		return
	}
	versions, err := h.deps.Certs.Versions(r.Context(), cert.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load certificate history")
		return
	}
	writeJSON(w, http.StatusOK, versions)
}

func (h *handlers) certificateAudit(w http.ResponseWriter, r *http.Request) {
	cert, ok := h.loadCertificateForTeam(w, r)
	if !ok {
		return
	}
	entries, err := h.deps.Audit.ForResource(r.Context(), "certificate", cert.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load audit history")
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// issueDownloadToken is the "explicit UI confirmation" docs/plan.html
// section 07 requires before key material can be exported: a short-lived,
// single-use token that downloadCertificate then redeems exactly once.
func (h *handlers) issueDownloadToken(w http.ResponseWriter, r *http.Request) {
	identity, _ := auth.IdentityFromContext(r.Context())
	cert, ok := h.loadCertificateForTeam(w, r)
	if !ok {
		return
	}

	token, expiresAt, err := h.deps.DownloadTokens.Issue(r.Context(), cert.ID, identity.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue a download token")
		return
	}
	h.audit(r, "download_token_issued", "certificate", cert.ID, string(auth.ScopeCertsExport), nil)
	writeJSON(w, http.StatusCreated, map[string]interface{}{"token": token, "expires_at": expiresAt})
}

func (h *handlers) downloadCertificate(w http.ResponseWriter, r *http.Request) {
	identity, _ := auth.IdentityFromContext(r.Context())
	id := r.PathValue("id")

	rawToken := r.URL.Query().Get("token")
	if rawToken == "" {
		writeError(w, http.StatusBadRequest, "a download token is required; POST /certificates/{id}/download-token first")
		return
	}

	redeemed, err := h.deps.DownloadTokens.Redeem(r.Context(), rawToken)
	if err != nil {
		if err == downloadtoken.ErrInvalid {
			writeError(w, http.StatusForbidden, "invalid, expired, or already-used download token")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not redeem download token")
		return
	}
	if redeemed.CertificateID != id || redeemed.UserID != identity.UserID {
		writeError(w, http.StatusForbidden, "download token does not match this certificate and user")
		return
	}

	version, err := h.deps.Certs.LatestVersion(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "no issued version for this certificate")
		return
	}

	h.audit(r, "download", "certificate", id, string(auth.ScopeCertsExport), nil)
	writeJSON(w, http.StatusOK, version)
}

func (h *handlers) renewCertificate(w http.ResponseWriter, r *http.Request) {
	identity, _ := auth.IdentityFromContext(r.Context())
	cert, ok := h.loadCertificateForTeam(w, r)
	if !ok {
		return
	}

	o, err := h.deps.Renewal.RenewNow(r.Context(), cert, identity.UserID)
	if err != nil {
		writeError(w, http.StatusBadGateway, "could not start renewal: "+err.Error())
		return
	}
	h.audit(r, "renew_requested", "certificate", cert.ID, string(auth.ScopeCertsIssue), nil)
	writeJSON(w, http.StatusAccepted, o.Public())
}

func (h *handlers) revokeCertificate(w http.ResponseWriter, r *http.Request) {
	cert, ok := h.loadCertificateForTeam(w, r)
	if !ok {
		return
	}
	if err := h.deps.Certs.Revoke(r.Context(), cert.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not revoke certificate")
		return
	}
	h.audit(r, "revoke", "certificate", cert.ID, string(auth.ScopeCertsAdmin), nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (h *handlers) createOrder(w http.ResponseWriter, r *http.Request) {
	identity, _ := auth.IdentityFromContext(r.Context())

	var req order.CreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.RequestedBy = identity.UserID
	if identity.Role != user.RoleAdmin {
		req.OwningTeam = identity.Team
	}

	o, err := h.deps.Orders.Create(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "order_created", "certificate_order", o.ID, string(auth.ScopeCertsIssue), map[string]interface{}{"domains": req.Domains})
	writeJSON(w, http.StatusCreated, o.Public())
}

func (h *handlers) getOrder(w http.ResponseWriter, r *http.Request) {
	identity, _ := auth.IdentityFromContext(r.Context())
	o, err := h.deps.Orders.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "order not found")
		return
	}
	if !identity.CanAccessTeam(o.OwningTeam) {
		writeError(w, http.StatusForbidden, "not permitted to view this order")
		return
	}
	writeJSON(w, http.StatusOK, o.Public())
}

func (h *handlers) validateOrder(w http.ResponseWriter, r *http.Request) {
	identity, _ := auth.IdentityFromContext(r.Context())
	id := r.PathValue("id")

	existing, err := h.deps.Orders.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "order not found")
		return
	}
	if !identity.CanAccessTeam(existing.OwningTeam) {
		writeError(w, http.StatusForbidden, "not permitted to act on this order")
		return
	}

	o, err := h.deps.Orders.Validate(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if o.Status == order.StatusIssued {
		h.audit(r, "issued", "certificate", o.CertificateID, string(auth.ScopeCertsIssue), map[string]interface{}{"order_id": o.ID})
	}
	writeJSON(w, http.StatusOK, o.Public())
}

func (h *handlers) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.deps.Users.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list users")
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (h *handlers) setUserRole(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Role user.Role `json:"role"`
		Team string    `json:"team"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	id := r.PathValue("id")
	if err := h.deps.Users.SetRoleAndTeam(r.Context(), id, req.Role, req.Team); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update user")
		return
	}
	h.audit(r, "role_changed", "user", id, string(auth.ScopeCertsAdmin), map[string]interface{}{"role": req.Role, "team": req.Team})
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *handlers) createAPIKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	id := r.PathValue("id")

	raw, err := h.deps.APIKeys.Create(r.Context(), id, req.Name, req.Scopes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create API key")
		return
	}
	h.audit(r, "api_key_created", "user", id, string(auth.ScopeCertsAdmin), map[string]interface{}{"name": req.Name, "scopes": req.Scopes})
	writeJSON(w, http.StatusCreated, map[string]string{"key": raw})
}

// loadCertificateForTeam fetches the path {id} certificate and enforces
// team scoping in one place — every handler that acts on a specific
// certificate goes through it.
func (h *handlers) loadCertificateForTeam(w http.ResponseWriter, r *http.Request) (certificate.Certificate, bool) {
	identity, _ := auth.IdentityFromContext(r.Context())
	cert, err := h.deps.Certs.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "certificate not found")
		return certificate.Certificate{}, false
	}
	if !identity.CanAccessTeam(cert.OwningTeam) {
		writeError(w, http.StatusForbidden, "not permitted to access this certificate")
		return certificate.Certificate{}, false
	}
	return cert, true
}

func (h *handlers) audit(r *http.Request, action, resource, resourceID, scope string, metadata map[string]interface{}) {
	identity, _ := auth.IdentityFromContext(r.Context())
	_ = h.deps.Audit.Write(r.Context(), audit.Entry{
		Actor: identity.Email, Action: action, Resource: resource,
		ResourceID: resourceID, Scope: scope, Metadata: metadata,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
