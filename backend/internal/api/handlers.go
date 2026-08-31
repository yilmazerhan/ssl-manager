package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/yilmazerhan/ssl-manager/backend/internal/audit"
	"github.com/yilmazerhan/ssl-manager/backend/internal/auth"
	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
	"github.com/yilmazerhan/ssl-manager/backend/internal/discovery"
	"github.com/yilmazerhan/ssl-manager/backend/internal/downloadtoken"
	"github.com/yilmazerhan/ssl-manager/backend/internal/k8s"
	"github.com/yilmazerhan/ssl-manager/backend/internal/order"
	"github.com/yilmazerhan/ssl-manager/backend/internal/renewal"
	"github.com/yilmazerhan/ssl-manager/backend/internal/user"
	"github.com/yilmazerhan/ssl-manager/backend/internal/winrm"
)

type handlers struct {
	deps Dependencies
}

func (h *handlers) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
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

// certificatePosture serves the crypto/TLS detail panel on the certificate
// detail page: signature algorithm and key usage are parsed from the
// current issued cert, and TLS versions/cipher/OCSP-stapling come from a
// live handshake probe against the certificate's own primary domain.
func (h *handlers) certificatePosture(w http.ResponseWriter, r *http.Request) {
	cert, ok := h.loadCertificateForTeam(w, r)
	if !ok {
		return
	}
	version, err := h.deps.Certs.LatestVersion(r.Context(), cert.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load the current certificate version")
		return
	}
	posture, err := certificate.ComputePosture(r.Context(), version.PEMCert, cert.CommonName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not compute certificate posture")
		return
	}
	writeJSON(w, http.StatusOK, posture)
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

// listAuditLog is the system-wide audit feed (admin-only): every action
// this platform records, not just one certificate's own trail — server/
// service sync results, SSL discovery scans, certificate issuance and
// renewal, user and API key management, and so on. resource/action query
// params narrow it; both are exact matches, left blank to not filter.
func (h *handlers) listAuditLog(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := h.deps.Audit.List(r.Context(), audit.ListFilter{
		Resource: r.URL.Query().Get("resource"), Action: r.URL.Query().Get("action"), Limit: limit,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load audit log")
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

// revokeCertificate revokes at the certificate authority first, then marks
// our own record revoked — a certificate this app still thinks is "active"
// but the CA has already revoked would be a much worse failure mode than
// the reverse, so the CA call runs first and any failure there stops the
// whole request.
func (h *handlers) revokeCertificate(w http.ResponseWriter, r *http.Request) {
	cert, ok := h.loadCertificateForTeam(w, r)
	if !ok {
		return
	}

	if authority, ok := h.deps.Authorities.Get(cert.CAProvider); ok {
		version, err := h.deps.Certs.LatestVersion(r.Context(), cert.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "could not load certificate material to revoke")
			return
		}
		if err := authority.Revoke(r.Context(), version.PEMCert, cert.CAReference); err != nil {
			writeError(w, http.StatusBadGateway, "could not revoke at the certificate authority: "+err.Error())
			return
		}
	}

	if err := h.revokeOne(r.Context(), cert); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	h.audit(r, "revoke", "certificate", cert.ID, string(auth.ScopeCertsAdmin), nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// revokeOne is revokeCertificate's actual work, split out so bulkRevoke can
// drive the same CA-then-database order over a whole list of certificates
// without duplicating it.
func (h *handlers) revokeOne(ctx context.Context, cert certificate.Certificate) error {
	if authority, ok := h.deps.Authorities.Get(cert.CAProvider); ok {
		version, err := h.deps.Certs.LatestVersion(ctx, cert.ID)
		if err != nil {
			return fmt.Errorf("could not load certificate material to revoke")
		}
		if err := authority.Revoke(ctx, version.PEMCert, cert.CAReference); err != nil {
			return fmt.Errorf("could not revoke at the certificate authority: %w", err)
		}
	}
	if err := h.deps.Certs.Revoke(ctx, cert.ID); err != nil {
		return fmt.Errorf("could not revoke certificate")
	}
	return nil
}

// maxBulkItems bounds every bulk endpoint below — a single request that
// tries to import/revoke/renew thousands of certificates would tie up this
// handler (and, for renew, kick off that many real CA round trips) for far
// longer than an HTTP request should reasonably run.
const maxBulkItems = 500

// loadCertificateForTeamByID is loadCertificateForTeam's check without the
// http.Request coupling, so bulk handlers can apply the same team-scoping
// to every id in a request body, not just one from the URL path.
func (h *handlers) loadCertificateForTeamByID(ctx context.Context, identity auth.Identity, id string) (certificate.Certificate, error) {
	cert, err := h.deps.Certs.Get(ctx, id)
	if err != nil {
		return certificate.Certificate{}, fmt.Errorf("not found")
	}
	if !identity.CanAccessTeam(cert.OwningTeam) {
		return certificate.Certificate{}, fmt.Errorf("not permitted to access this certificate")
	}
	return cert, nil
}

// bulkItemResult is every bulk endpoint's per-item outcome shape — a bulk
// request only ever entirely succeeds or reports exactly which items
// failed and why; it never fails the whole request for one bad id.
type bulkItemResult struct {
	ID      string `json:"id,omitempty"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

func (h *handlers) bulkRevokeCertificates(w http.ResponseWriter, r *http.Request) {
	identity, _ := auth.IdentityFromContext(r.Context())

	var req struct {
		CertificateIDs []string `json:"certificate_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.CertificateIDs) == 0 {
		writeError(w, http.StatusBadRequest, "at least one certificate_id is required")
		return
	}
	if len(req.CertificateIDs) > maxBulkItems {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("at most %d certificates per bulk request, got %d", maxBulkItems, len(req.CertificateIDs)))
		return
	}

	results := make([]bulkItemResult, 0, len(req.CertificateIDs))
	for _, id := range req.CertificateIDs {
		cert, err := h.loadCertificateForTeamByID(r.Context(), identity, id)
		if err != nil {
			results = append(results, bulkItemResult{ID: id, Error: err.Error()})
			continue
		}
		if err := h.revokeOne(r.Context(), cert); err != nil {
			results = append(results, bulkItemResult{ID: id, Error: err.Error()})
			continue
		}
		h.audit(r, "revoke", "certificate", cert.ID, string(auth.ScopeCertsAdmin), map[string]interface{}{"bulk": true})
		results = append(results, bulkItemResult{ID: id, Success: true})
	}
	writeJSON(w, http.StatusOK, results)
}

func (h *handlers) bulkRenewCertificates(w http.ResponseWriter, r *http.Request) {
	identity, _ := auth.IdentityFromContext(r.Context())

	var req struct {
		CertificateIDs []string `json:"certificate_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.CertificateIDs) == 0 {
		writeError(w, http.StatusBadRequest, "at least one certificate_id is required")
		return
	}
	if len(req.CertificateIDs) > maxBulkItems {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("at most %d certificates per bulk request, got %d", maxBulkItems, len(req.CertificateIDs)))
		return
	}

	results := make([]bulkItemResult, 0, len(req.CertificateIDs))
	for _, id := range req.CertificateIDs {
		cert, err := h.loadCertificateForTeamByID(r.Context(), identity, id)
		if err != nil {
			results = append(results, bulkItemResult{ID: id, Error: err.Error()})
			continue
		}
		o, err := h.deps.Renewal.RenewNow(r.Context(), cert, identity.UserID)
		if err != nil {
			results = append(results, bulkItemResult{ID: id, Error: err.Error()})
			continue
		}
		if o.Status == order.StatusFailed {
			results = append(results, bulkItemResult{ID: id, Error: o.Error})
			continue
		}
		h.audit(r, "renew_requested", "certificate", cert.ID, string(auth.ScopeCertsIssue), map[string]interface{}{"bulk": true})
		results = append(results, bulkItemResult{ID: id, Success: true})
	}
	writeJSON(w, http.StatusOK, results)
}

// bulkImportItemResult echoes back which input item a result belongs to —
// bulkItemResult's ID is a certificate id, which doesn't exist yet for a
// failed import, so this identifies by common_name instead.
type bulkImportItemResult struct {
	CommonName    string `json:"common_name,omitempty"`
	CertificateID string `json:"certificate_id,omitempty"`
	Success       bool   `json:"success"`
	Error         string `json:"error,omitempty"`
}

func (h *handlers) bulkImportCertificates(w http.ResponseWriter, r *http.Request) {
	identity, _ := auth.IdentityFromContext(r.Context())

	var req struct {
		Certificates []struct {
			PEMCert    string `json:"pem_cert"`
			PEMChain   string `json:"pem_chain"`
			OwningTeam string `json:"owning_team"`
		} `json:"certificates"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Certificates) == 0 {
		writeError(w, http.StatusBadRequest, "at least one certificate is required")
		return
	}
	if len(req.Certificates) > maxBulkItems {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("at most %d certificates per bulk request, got %d", maxBulkItems, len(req.Certificates)))
		return
	}

	results := make([]bulkImportItemResult, 0, len(req.Certificates))
	for _, item := range req.Certificates {
		// Same team-scoping createOrder enforces: a non-admin (e.g.
		// cert_manager, who also holds certs:issue) can only ever import
		// into their own team, no matter what owning_team they send —
		// otherwise a team's cert_manager could plant a certificate that
		// appears owned by a team they have no access to.
		owningTeam := item.OwningTeam
		if identity.Role != user.RoleAdmin {
			owningTeam = identity.Team
		}
		cert, version, err := certificate.ImportFromPEM(item.PEMCert, item.PEMChain, owningTeam)
		if err != nil {
			results = append(results, bulkImportItemResult{Error: err.Error()})
			continue
		}
		// Create+version in one transaction (FinalizeNewCertificate) —
		// two separate writes here would risk the same orphaned-
		// certificate-with-no-version problem order.Service.Validate
		// used to have if the second write failed after the first
		// committed.
		created, _, err := h.deps.Certs.FinalizeNewCertificate(r.Context(), cert, version)
		if err != nil {
			results = append(results, bulkImportItemResult{CommonName: cert.CommonName, Error: "could not store certificate"})
			continue
		}
		h.audit(r, "imported", "certificate", created.ID, string(auth.ScopeCertsIssue), map[string]interface{}{"bulk": true})
		results = append(results, bulkImportItemResult{CommonName: cert.CommonName, CertificateID: created.ID, Success: true})
	}
	writeJSON(w, http.StatusOK, results)
}

func (h *handlers) listK8sTargets(w http.ResponseWriter, r *http.Request) {
	cert, ok := h.loadCertificateForTeam(w, r)
	if !ok {
		return
	}
	targets, err := h.deps.K8s.ListTargets(r.Context(), cert.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list Kubernetes sync targets")
		return
	}
	writeJSON(w, http.StatusOK, targets)
}

func (h *handlers) createK8sTarget(w http.ResponseWriter, r *http.Request) {
	cert, ok := h.loadCertificateForTeam(w, r)
	if !ok {
		return
	}
	var req k8s.TargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	target, err := h.deps.K8s.CreateTarget(r.Context(), cert.ID, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "k8s_target_created", "certificate", cert.ID, string(auth.ScopeCertsAdmin), map[string]interface{}{
		"target_id": target.ID, "cluster_url": req.ClusterURL, "namespace": req.Namespace, "secret_name": req.SecretName,
	})
	writeJSON(w, http.StatusCreated, target)
}

func (h *handlers) updateK8sTarget(w http.ResponseWriter, r *http.Request) {
	cert, ok := h.loadCertificateForTeam(w, r)
	if !ok {
		return
	}
	var req k8s.TargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	target, err := h.deps.K8s.UpdateTarget(r.Context(), r.PathValue("targetId"), req)
	if err != nil {
		if errors.Is(err, k8s.ErrNotFound) {
			writeError(w, http.StatusNotFound, "Kubernetes sync target not found")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "k8s_target_updated", "certificate", cert.ID, string(auth.ScopeCertsAdmin), map[string]interface{}{"target_id": target.ID})
	writeJSON(w, http.StatusOK, target)
}

func (h *handlers) deleteK8sTarget(w http.ResponseWriter, r *http.Request) {
	cert, ok := h.loadCertificateForTeam(w, r)
	if !ok {
		return
	}
	targetID := r.PathValue("targetId")
	if err := h.deps.K8s.DeleteTarget(r.Context(), targetID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete Kubernetes sync target")
		return
	}
	h.audit(r, "k8s_target_deleted", "certificate", cert.ID, string(auth.ScopeCertsAdmin), map[string]interface{}{"target_id": targetID})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *handlers) syncK8sTarget(w http.ResponseWriter, r *http.Request) {
	cert, ok := h.loadCertificateForTeam(w, r)
	if !ok {
		return
	}
	targetID := r.PathValue("targetId")
	if err := h.deps.K8s.SyncTarget(r.Context(), targetID); err != nil {
		if errors.Is(err, k8s.ErrNotFound) {
			writeError(w, http.StatusNotFound, "Kubernetes sync target not found")
			return
		}
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	h.audit(r, "k8s_target_synced", "certificate", cert.ID, string(auth.ScopeCertsAdmin), map[string]interface{}{"target_id": targetID})
	writeJSON(w, http.StatusOK, map[string]string{"status": "synced"})
}

func (h *handlers) listWinRMTargets(w http.ResponseWriter, r *http.Request) {
	cert, ok := h.loadCertificateForTeam(w, r)
	if !ok {
		return
	}
	targets, err := h.deps.WinRM.ListTargets(r.Context(), cert.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list WinRM sync targets")
		return
	}
	writeJSON(w, http.StatusOK, targets)
}

func (h *handlers) createWinRMTarget(w http.ResponseWriter, r *http.Request) {
	cert, ok := h.loadCertificateForTeam(w, r)
	if !ok {
		return
	}
	var req winrm.TargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	target, err := h.deps.WinRM.CreateTarget(r.Context(), cert.ID, req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "winrm_target_created", "certificate", cert.ID, string(auth.ScopeCertsAdmin), map[string]interface{}{
		"target_id": target.ID, "host": req.Host, "port": req.Port, "service_type": string(req.ServiceType),
	})
	writeJSON(w, http.StatusCreated, target)
}

func (h *handlers) updateWinRMTarget(w http.ResponseWriter, r *http.Request) {
	cert, ok := h.loadCertificateForTeam(w, r)
	if !ok {
		return
	}
	var req winrm.TargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	target, err := h.deps.WinRM.UpdateTarget(r.Context(), r.PathValue("targetId"), req)
	if err != nil {
		if errors.Is(err, winrm.ErrNotFound) {
			writeError(w, http.StatusNotFound, "WinRM sync target not found")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "winrm_target_updated", "certificate", cert.ID, string(auth.ScopeCertsAdmin), map[string]interface{}{"target_id": target.ID})
	writeJSON(w, http.StatusOK, target)
}

func (h *handlers) deleteWinRMTarget(w http.ResponseWriter, r *http.Request) {
	cert, ok := h.loadCertificateForTeam(w, r)
	if !ok {
		return
	}
	targetID := r.PathValue("targetId")
	if err := h.deps.WinRM.DeleteTarget(r.Context(), targetID); err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete WinRM sync target")
		return
	}
	h.audit(r, "winrm_target_deleted", "certificate", cert.ID, string(auth.ScopeCertsAdmin), map[string]interface{}{"target_id": targetID})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *handlers) syncWinRMTarget(w http.ResponseWriter, r *http.Request) {
	cert, ok := h.loadCertificateForTeam(w, r)
	if !ok {
		return
	}
	targetID := r.PathValue("targetId")
	if err := h.deps.WinRM.SyncTarget(r.Context(), targetID); err != nil {
		if errors.Is(err, winrm.ErrNotFound) {
			writeError(w, http.StatusNotFound, "WinRM sync target not found")
			return
		}
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	h.audit(r, "winrm_target_synced", "certificate", cert.ID, string(auth.ScopeCertsAdmin), map[string]interface{}{"target_id": targetID})
	writeJSON(w, http.StatusOK, map[string]string{"status": "synced"})
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

func (h *handlers) createDiscoveryScan(w http.ResponseWriter, r *http.Request) {
	identity, _ := auth.IdentityFromContext(r.Context())

	var req discovery.CreateScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	sc, err := h.deps.Discovery.CreateScan(r.Context(), req, identity.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "discovery_scan_started", "discovery_scan", sc.ID, string(auth.ScopeCertsAdmin), map[string]interface{}{
		"targets": req.Targets, "ports": sc.Ports, "total_targets": sc.TotalTargets,
	})
	writeJSON(w, http.StatusCreated, sc)
}

func (h *handlers) listDiscoveryScans(w http.ResponseWriter, r *http.Request) {
	scans, err := h.deps.Discovery.ListScans(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list scans")
		return
	}
	writeJSON(w, http.StatusOK, scans)
}

func (h *handlers) getDiscoveryScan(w http.ResponseWriter, r *http.Request) {
	sc, err := h.deps.Discovery.GetScan(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	writeJSON(w, http.StatusOK, sc)
}

func (h *handlers) listDiscoveryResults(w http.ResponseWriter, r *http.Request) {
	results, err := h.deps.Discovery.ListResults(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list scan results")
		return
	}
	writeJSON(w, http.StatusOK, results)
}

func (h *handlers) cancelDiscoveryScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.deps.Discovery.CancelScan(r.Context(), id); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	h.audit(r, "discovery_scan_canceled", "discovery_scan", id, string(auth.ScopeCertsAdmin), nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "canceling"})
}

func (h *handlers) createDiscoverySchedule(w http.ResponseWriter, r *http.Request) {
	identity, _ := auth.IdentityFromContext(r.Context())

	var req discovery.ScheduleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	sch, err := h.deps.Discovery.CreateSchedule(r.Context(), req, identity.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "discovery_schedule_created", "discovery_schedule", sch.ID, string(auth.ScopeCertsAdmin), map[string]interface{}{
		"targets": req.Targets, "interval_minutes": req.IntervalMinutes,
	})
	writeJSON(w, http.StatusCreated, sch)
}

func (h *handlers) listDiscoverySchedules(w http.ResponseWriter, r *http.Request) {
	schedules, err := h.deps.Discovery.ListSchedules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list schedules")
		return
	}
	writeJSON(w, http.StatusOK, schedules)
}

func (h *handlers) updateDiscoverySchedule(w http.ResponseWriter, r *http.Request) {
	var req discovery.ScheduleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	sch, err := h.deps.Discovery.UpdateSchedule(r.Context(), r.PathValue("id"), req)
	if err != nil {
		if errors.Is(err, discovery.ErrNotFound) {
			writeError(w, http.StatusNotFound, "schedule not found")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "discovery_schedule_updated", "discovery_schedule", sch.ID, string(auth.ScopeCertsAdmin), map[string]interface{}{
		"interval_minutes": req.IntervalMinutes, "enabled": req.Enabled,
	})
	writeJSON(w, http.StatusOK, sch)
}

func (h *handlers) deleteDiscoverySchedule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.deps.Discovery.DeleteSchedule(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "could not delete schedule")
		return
	}
	h.audit(r, "discovery_schedule_deleted", "discovery_schedule", id, string(auth.ScopeCertsAdmin), nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *handlers) getNotificationSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := h.deps.NotificationSettings.Get(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load notification settings")
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (h *handlers) updateNotificationSettings(w http.ResponseWriter, r *http.Request) {
	var req renewal.ReminderSettings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.ThresholdDays) == 0 {
		writeError(w, http.StatusBadRequest, "at least one threshold day is required")
		return
	}
	if err := validateEmails(req.DefaultRecipients); err != nil {
		writeError(w, http.StatusBadRequest, "default_recipients: "+err.Error())
		return
	}
	if err := validateEmails(req.EscalationRecipients); err != nil {
		writeError(w, http.StatusBadRequest, "escalation_recipients: "+err.Error())
		return
	}
	if err := renewal.ValidateTemplates(req.EmailSubjectTemplate, req.EmailBodyTemplate); err != nil {
		writeError(w, http.StatusBadRequest, "invalid template: "+err.Error())
		return
	}
	if err := h.deps.NotificationSettings.Update(r.Context(), req); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update notification settings")
		return
	}
	h.audit(r, "notification_settings_updated", "notification_settings", "1", string(auth.ScopeCertsAdmin), nil)
	writeJSON(w, http.StatusOK, req)
}

func (h *handlers) listRecentNotifications(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	entries, err := h.deps.NotifyLog.Recent(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list notifications")
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

func (h *handlers) certificateNotifications(w http.ResponseWriter, r *http.Request) {
	cert, ok := h.loadCertificateForTeam(w, r)
	if !ok {
		return
	}
	entries, err := h.deps.NotifyLog.ForCertificate(r.Context(), cert.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list notifications for this certificate")
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

func (h *handlers) updateCertificateNotifyEmails(w http.ResponseWriter, r *http.Request) {
	cert, ok := h.loadCertificateForTeam(w, r)
	if !ok {
		return
	}
	var req struct {
		Emails []string `json:"emails"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateEmails(req.Emails); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.deps.Certs.UpdateNotifyEmails(r.Context(), cert.ID, req.Emails); err != nil {
		writeError(w, http.StatusInternalServerError, "could not update notification emails")
		return
	}
	h.audit(r, "notify_emails_updated", "certificate", cert.ID, string(auth.ScopeCertsIssue), map[string]interface{}{"emails": req.Emails})
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// summaryReport is the dashboard/reports payload. Discovery and
// notification breakdowns are admin-only concerns (the same scope that
// gates the Discovery and Notifications pages themselves), so they're left
// nil for a team-scoped viewer rather than leaking cross-team activity.
type summaryReport struct {
	Certificates           certificate.Stats               `json:"certificates"`
	DiscoveryMismatches    []discovery.Result              `json:"discovery_mismatches,omitempty"`
	Vulnerabilities        *discovery.VulnerabilitySummary `json:"vulnerabilities,omitempty"`
	NotificationsSent30d   int                             `json:"notifications_sent_30d,omitempty"`
	NotificationsFailed30d int                             `json:"notifications_failed_30d,omitempty"`
}

func (h *handlers) getSummaryReport(w http.ResponseWriter, r *http.Request) {
	identity, _ := auth.IdentityFromContext(r.Context())

	team := identity.Team
	if identity.Role == user.RoleAdmin || identity.Role == user.RoleAPIOnly {
		team = ""
	}

	stats, err := h.deps.Certs.Stats(r.Context(), team)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load certificate statistics")
		return
	}
	report := summaryReport{Certificates: stats}

	if team == "" {
		if mismatches, err := h.deps.Discovery.ListMismatches(r.Context(), 50); err == nil {
			report.DiscoveryMismatches = mismatches
		}
		if vulns, err := h.deps.Discovery.VulnerabilitySummary(r.Context()); err == nil {
			report.Vulnerabilities = &vulns
		}
		if sent, failed, err := h.deps.NotifyLog.Stats(r.Context(), time.Now().Add(-30*24*time.Hour)); err == nil {
			report.NotificationsSent30d = sent
			report.NotificationsFailed30d = failed
		}
	}

	writeJSON(w, http.StatusOK, report)
}

func (h *handlers) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.deps.Users.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list users")
		return
	}
	writeJSON(w, http.StatusOK, users)
}

var validRoles = map[user.Role]bool{
	user.RoleViewer: true, user.RoleCertManager: true, user.RoleAdmin: true, user.RoleAPIOnly: true,
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
	if !validRoles[req.Role] {
		writeError(w, http.StatusBadRequest, "unknown role")
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

// createAPIKey never grants a scope beyond what the target user's own role
// already earns — otherwise a key holder whose scopes happen to exceed
// their role (e.g. an over-provisioned earlier key) could mint themselves a
// fresh, durable key at the wider scope and outlive any correction to the
// original mismatch. Role, not scope, is the source of truth for how much
// a user is allowed to grant.
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

	target, err := h.deps.Users.GetByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	// api_only is the deliberate exception: its whole purpose is a service
	// account whose permissions are entirely defined by the keys minted for
	// it rather than a fixed role->scope mapping (RoleScopes returns nil for
	// it), so any of the four known scopes is legitimate there.
	allowed := auth.RoleScopes(target.Role)
	if target.Role == user.RoleAPIOnly {
		allowed = []string{string(auth.ScopeCertsRead), string(auth.ScopeCertsExport), string(auth.ScopeCertsIssue), string(auth.ScopeCertsAdmin)}
	}
	for _, s := range req.Scopes {
		if !slices.Contains(allowed, s) {
			writeError(w, http.StatusBadRequest, "scope "+s+" exceeds what this user's role permits")
			return
		}
	}

	raw, err := h.deps.APIKeys.Create(r.Context(), id, req.Name, req.Scopes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create API key")
		return
	}
	h.audit(r, "api_key_created", "user", id, string(auth.ScopeCertsAdmin), map[string]interface{}{"name": req.Name, "scopes": req.Scopes})
	writeJSON(w, http.StatusCreated, map[string]string{"key": raw})
}

// changePassword lets the currently authenticated identity replace its
// own local password. It's the one endpoint reachable while
// MustChangePassword is still set (see router.go's authedOnly vs authed),
// since it's exactly what clears that flag. It reissues a fresh session
// token so the client's decoded must_change_password claim goes stale
// immediately, rather than the browser needing to log in again for that
// to take effect.
func (h *handlers) changePassword(w http.ResponseWriter, r *http.Request) {
	identity, _ := auth.IdentityFromContext(r.Context())

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	u, err := h.deps.Users.GetByID(r.Context(), identity.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load account")
		return
	}
	if u.PasswordHash == "" {
		writeError(w, http.StatusBadRequest, "this account has no local password to change — it signs in via SSO")
		return
	}
	if !auth.VerifyPassword(u.PasswordHash, req.CurrentPassword) {
		writeError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}
	if err := auth.ValidatePassword(req.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.NewPassword == req.CurrentPassword {
		writeError(w, http.StatusBadRequest, "new password must be different from the current password")
		return
	}

	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not set new password")
		return
	}
	if err := h.deps.Users.SetPassword(r.Context(), u.ID, hash, false); err != nil {
		writeError(w, http.StatusInternalServerError, "could not set new password")
		return
	}
	u.PasswordHash, u.MustChangePassword = hash, false

	token, err := h.deps.Sessions.Issue(u)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "password changed, but could not issue a new session — please log in again")
		return
	}
	h.audit(r, "password_changed", "user", u.ID, "", nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated", "token": token})
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

// emailPattern is deliberately permissive about what counts as an email
// address — its job isn't RFC 5322 validation, it's rejecting whitespace
// and control characters (CR/LF above all) before a value that's headed
// for a raw SMTP "To:"/"Bcc:" header line ever gets there. A crafted
// recipient containing "\r\nBcc: attacker@evil.com" would otherwise inject
// an extra header into every reminder email sent for that certificate.
var emailPattern = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

func validateEmails(emails []string) error {
	for _, e := range emails {
		if !emailPattern.MatchString(e) {
			return fmt.Errorf("invalid email address %q", e)
		}
	}
	return nil
}
