package api

import (
	"encoding/json"
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
	"github.com/yilmazerhan/ssl-manager/backend/internal/order"
	"github.com/yilmazerhan/ssl-manager/backend/internal/renewal"
	"github.com/yilmazerhan/ssl-manager/backend/internal/user"
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
	Certificates           certificate.Stats  `json:"certificates"`
	DiscoveryMismatches    []discovery.Result `json:"discovery_mismatches,omitempty"`
	NotificationsSent30d   int                `json:"notifications_sent_30d,omitempty"`
	NotificationsFailed30d int                `json:"notifications_failed_30d,omitempty"`
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
