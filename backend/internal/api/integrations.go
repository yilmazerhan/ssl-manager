// Integrations screens: what used to be environment variables read once
// at process startup (Let's Encrypt's contact email, ZeroSSL's API key,
// AD CS's server/credentials, the DNS-01 provider) are now editable here,
// admin-only. Every PUT handler follows the same shape: build a candidate
// config, actually construct the ca.Authority from it (which is also the
// validation — a bad Let's Encrypt contact email fails exactly the same
// way it would have failed cmd/api's startup registration), and only on
// success persist the settings and hot-swap the new Authority into the
// live registry. A bad edit therefore returns a 400 with the real error
// and leaves whatever was working before completely untouched — no
// restart-to-find-out, and no chance of the bad edit taking down the
// running server the way an unvalidated startup config once did (see the
// Let's Encrypt fix in this repo's history).
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yilmazerhan/ssl-manager/backend/internal/auth"
	"github.com/yilmazerhan/ssl-manager/backend/internal/ca"
	"github.com/yilmazerhan/ssl-manager/backend/internal/caconfig"
)

// stripURLCredentials removes any embedded userinfo (https://user:pass@…)
// before a configured CA URL is echoed back through GET
// /api/v1/integrations — an admin-only endpoint, but there's no reason for
// it to ever repeat a credential an operator (mis)configured directly into
// a URL rather than its own dedicated username/password field. Falls back
// to the raw string if it doesn't parse as a URL at all, since this is a
// display value, not something anything else depends on.
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

func (h *handlers) getIntegrations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var status IntegrationsStatus

	var le caconfig.LetsEncryptSettings
	if _, err := h.deps.CASettings.Get(ctx, "letsencrypt", &le); err != nil {
		writeError(w, http.StatusInternalServerError, "could not load Let's Encrypt settings")
		return
	}
	status.LetsEncrypt.Environment = le.Environment
	status.LetsEncrypt.DirectoryURL = stripURLCredentials(le.DirectoryURL)
	status.LetsEncrypt.ContactEmail = le.ContactEmail
	if account, err := h.deps.CAAccounts.Get(ctx, "letsencrypt", le.Environment); err == nil {
		status.LetsEncrypt.AccountRegistered = account.AccountRef != ""
	}

	var zs caconfig.ZeroSSLSettings
	if _, err := h.deps.CASettings.Get(ctx, "zerossl", &zs); err != nil {
		writeError(w, http.StatusInternalServerError, "could not load ZeroSSL settings")
		return
	}
	status.ZeroSSL.BaseURL = zs.BaseURL
	status.ZeroSSL.APIKeySet = h.secretFieldSet(ctx, caconfig.SecretPathZeroSSL, "api_key")
	status.ZeroSSL.Configured = status.ZeroSSL.APIKeySet

	var adcs caconfig.ADCSSettings
	if _, err := h.deps.CASettings.Get(ctx, "adcs", &adcs); err != nil {
		writeError(w, http.StatusInternalServerError, "could not load AD CS settings")
		return
	}
	status.ADCS.BaseURL = stripURLCredentials(adcs.BaseURL)
	status.ADCS.Template = adcs.Template
	status.ADCS.Username = adcs.Username
	status.ADCS.AllowBasicAuth = adcs.AllowBasicAuth
	status.ADCS.PasswordSet = h.secretFieldSet(ctx, caconfig.SecretPathADCS, "password")
	status.ADCS.Configured = adcs.BaseURL != ""

	var dns caconfig.DNS01Settings
	if _, err := h.deps.CASettings.Get(ctx, "dns01", &dns); err != nil {
		writeError(w, http.StatusInternalServerError, "could not load DNS-01 settings")
		return
	}
	status.DNS01.Provider = dns.Provider
	status.DNS01.TokenSet = dns.Provider != "" && h.secretFieldSet(ctx, caconfig.SecretPathDNS01, "token")
	status.DNS01.Configured = dns.Provider != ""

	var ss caconfig.SelfSignedSettings
	if _, err := h.deps.CASettings.Get(ctx, "selfsigned", &ss); err != nil {
		writeError(w, http.StatusInternalServerError, "could not load self-signed settings")
		return
	}
	status.SelfSigned.Available = true
	status.SelfSigned.ValidityDays = ss.ValidityDays
	status.SelfSigned.ValidityPeriod = (time.Duration(ss.ValidityDays) * 24 * time.Hour).String()

	writeJSON(w, http.StatusOK, status)
}

func (h *handlers) secretFieldSet(ctx context.Context, path, field string) bool {
	data, err := h.deps.Secrets.Get(ctx, path)
	if err != nil || data == nil {
		return false
	}
	v, ok := data[field].(string)
	return ok && v != ""
}

// secretString fetches a single string field from a Vault secret, ""/false
// if it isn't set — used everywhere a PUT handler needs "the previously
// saved value" for a secret the request left blank (see each handler's
// blank-means-unchanged handling).
func (h *handlers) secretString(ctx context.Context, path, field string) string {
	data, err := h.deps.Secrets.Get(ctx, path)
	if err != nil || data == nil {
		return ""
	}
	v, _ := data[field].(string)
	return v
}

func (h *handlers) updateLetsEncryptSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Environment  string `json:"environment"`
		DirectoryURL string `json:"directory_url"`
		ContactEmail string `json:"contact_email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Environment == "" || req.DirectoryURL == "" {
		writeError(w, http.StatusBadRequest, "environment and directory_url are required")
		return
	}
	if err := validateEmails([]string{req.ContactEmail}); err != nil {
		writeError(w, http.StatusBadRequest, "contact_email: "+err.Error())
		return
	}
	if u, err := url.Parse(req.DirectoryURL); err != nil || u.Host == "" {
		writeError(w, http.StatusBadRequest, "directory_url must be a valid URL")
		return
	}

	ctx := r.Context()
	newAuthority, err := ca.NewLetsEncrypt(ctx, ca.LetsEncryptConfig{
		Environment:        req.Environment,
		DirectoryURL:       req.DirectoryURL,
		ContactEmail:       req.ContactEmail,
		InsecureSkipVerify: h.deps.LetsEncryptInsecureSkipVerify,
	}, h.deps.Secrets, h.deps.CAAccounts, h.deps.DNSAutomation.Get())
	if err != nil {
		writeError(w, http.StatusBadGateway, "could not connect to Let's Encrypt with these settings: "+err.Error())
		return
	}

	settings := caconfig.LetsEncryptSettings{Environment: req.Environment, DirectoryURL: req.DirectoryURL, ContactEmail: req.ContactEmail}
	if err := h.deps.CASettings.Set(ctx, "letsencrypt", settings); err != nil {
		writeError(w, http.StatusInternalServerError, "settings verified but could not be saved")
		return
	}
	h.deps.Authorities.Set("letsencrypt", newAuthority)
	h.audit(r, "integration_updated", "integration", "letsencrypt", string(auth.ScopeCertsAdmin), map[string]interface{}{"environment": req.Environment})
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *handlers) updateZeroSSLSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BaseURL string `json:"base_url"`
		APIKey  string `json:"api_key"` // blank = leave the currently stored key unchanged
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ctx := r.Context()
	apiKey := req.APIKey
	if apiKey == "" {
		apiKey = h.secretString(ctx, caconfig.SecretPathZeroSSL, "api_key")
	}

	newAuthority := ca.NewZeroSSL(ca.ZeroSSLConfig{APIKey: apiKey, BaseURL: req.BaseURL})

	if err := h.deps.CASettings.Set(ctx, "zerossl", caconfig.ZeroSSLSettings{BaseURL: req.BaseURL}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save settings")
		return
	}
	if req.APIKey != "" {
		if err := h.deps.Secrets.Put(ctx, caconfig.SecretPathZeroSSL, map[string]interface{}{"api_key": req.APIKey}); err != nil {
			writeError(w, http.StatusInternalServerError, "settings saved but the API key could not be stored")
			return
		}
	}
	h.deps.Authorities.Set("zerossl", newAuthority)
	h.audit(r, "integration_updated", "integration", "zerossl", string(auth.ScopeCertsAdmin), map[string]interface{}{"api_key_changed": req.APIKey != ""})
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *handlers) updateADCSSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BaseURL        string `json:"base_url"`
		Template       string `json:"template"`
		Username       string `json:"username"`
		Password       string `json:"password"` // blank = leave the currently stored password unchanged
		AllowBasicAuth bool   `json:"allow_basic_auth"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ctx := r.Context()

	// An empty base_url means "unconfigure AD CS" — mirrors the original
	// ADCS_BASE_URL-unset behavior, rather than trying to construct a
	// client against nothing.
	if req.BaseURL == "" {
		if err := h.deps.CASettings.Set(ctx, "adcs", caconfig.ADCSSettings{}); err != nil {
			writeError(w, http.StatusInternalServerError, "could not save settings")
			return
		}
		h.deps.Authorities.Delete("adcs")
		h.audit(r, "integration_updated", "integration", "adcs", string(auth.ScopeCertsAdmin), map[string]interface{}{"configured": false})
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
		return
	}

	if req.AllowBasicAuth && !strings.HasPrefix(req.BaseURL, "https://") {
		writeError(w, http.StatusBadRequest, "allow_basic_auth requires an https:// base_url — Basic auth sends credentials in the clear otherwise")
		return
	}

	password := req.Password
	if password == "" {
		password = h.secretString(ctx, caconfig.SecretPathADCS, "password")
	}

	newAuthority := ca.NewADCS(ca.ADCSConfig{
		BaseURL:            req.BaseURL,
		Template:           req.Template,
		Username:           req.Username,
		Password:           password,
		AllowBasicAuth:     req.AllowBasicAuth,
		InsecureSkipVerify: h.deps.ADCSInsecureSkipVerify,
	})

	settings := caconfig.ADCSSettings{BaseURL: req.BaseURL, Template: req.Template, Username: req.Username, AllowBasicAuth: req.AllowBasicAuth}
	if err := h.deps.CASettings.Set(ctx, "adcs", settings); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save settings")
		return
	}
	if req.Password != "" {
		if err := h.deps.Secrets.Put(ctx, caconfig.SecretPathADCS, map[string]interface{}{"password": req.Password}); err != nil {
			writeError(w, http.StatusInternalServerError, "settings saved but the password could not be stored")
			return
		}
	}
	h.deps.Authorities.Set("adcs", newAuthority)
	h.audit(r, "integration_updated", "integration", "adcs", string(auth.ScopeCertsAdmin), map[string]interface{}{"base_url": req.BaseURL, "password_changed": req.Password != ""})
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *handlers) updateDNS01Settings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider string `json:"provider"` // "" or "cloudflare"
		Token    string `json:"token"`    // blank = leave the currently stored token unchanged
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ctx := r.Context()

	if req.Provider == "" {
		if err := h.deps.CASettings.Set(ctx, "dns01", caconfig.DNS01Settings{}); err != nil {
			writeError(w, http.StatusInternalServerError, "could not save settings")
			return
		}
		h.deps.DNSAutomation.Set(nil)
		warning := h.refreshLetsEncryptDNS(ctx, nil)
		h.audit(r, "integration_updated", "integration", "dns01", string(auth.ScopeCertsAdmin), map[string]interface{}{"provider": ""})
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "updated", "warning": warning})
		return
	}

	token := req.Token
	if token == "" {
		token = h.secretString(ctx, caconfig.SecretPathDNS01, "token")
	}
	newAutomation, err := ca.NewDNSAutomationWithToken(req.Provider, token)
	if err != nil {
		writeError(w, http.StatusBadGateway, "could not configure DNS-01 automation: "+err.Error())
		return
	}

	if err := h.deps.CASettings.Set(ctx, "dns01", caconfig.DNS01Settings{Provider: req.Provider}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save settings")
		return
	}
	if req.Token != "" {
		if err := h.deps.Secrets.Put(ctx, caconfig.SecretPathDNS01, map[string]interface{}{"token": req.Token}); err != nil {
			writeError(w, http.StatusInternalServerError, "settings saved but the token could not be stored")
			return
		}
	}
	h.deps.DNSAutomation.Set(newAutomation)
	warning := h.refreshLetsEncryptDNS(ctx, newAutomation)
	h.audit(r, "integration_updated", "integration", "dns01", string(auth.ScopeCertsAdmin), map[string]interface{}{"provider": req.Provider, "token_changed": req.Token != ""})
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "updated", "warning": warning})
}

// refreshLetsEncryptDNS rebuilds the live Let's Encrypt authority so it
// picks up a just-changed DNS-01 automation — Let's Encrypt holds its
// *ca.DNSAutomation by value at construction time, not by reference to
// DNSAutomation, so a DNS-01 settings edit alone wouldn't otherwise reach
// it. Best-effort: if Let's Encrypt isn't configured yet, or the rebuild
// itself fails, the DNS-01 settings just saved are still kept — they're
// independently valid — and this returns a non-empty warning string
// instead of failing the whole request over a provider that isn't even
// the one being edited.
func (h *handlers) refreshLetsEncryptDNS(ctx context.Context, dnsAutomation *ca.DNSAutomation) string {
	var le caconfig.LetsEncryptSettings
	found, err := h.deps.CASettings.Get(ctx, "letsencrypt", &le)
	if err != nil || !found || le.DirectoryURL == "" {
		return ""
	}
	newLE, err := ca.NewLetsEncrypt(ctx, ca.LetsEncryptConfig{
		Environment:        le.Environment,
		DirectoryURL:       le.DirectoryURL,
		ContactEmail:       le.ContactEmail,
		InsecureSkipVerify: h.deps.LetsEncryptInsecureSkipVerify,
	}, h.deps.Secrets, h.deps.CAAccounts, dnsAutomation)
	if err != nil {
		return fmt.Sprintf("DNS-01 settings saved, but Let's Encrypt could not be refreshed with them: %v — it will keep using its previous DNS-01 configuration until this is fixed and Let's Encrypt's own settings are re-saved", err)
	}
	h.deps.Authorities.Set("letsencrypt", newLE)
	return ""
}

func (h *handlers) updateSelfSignedSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ValidityDays int `json:"validity_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ValidityDays <= 0 || req.ValidityDays > 3650 {
		writeError(w, http.StatusBadRequest, "validity_days must be between 1 and 3650")
		return
	}

	ctx := r.Context()
	newAuthority := ca.NewSelfSigned(time.Duration(req.ValidityDays) * 24 * time.Hour)
	if err := h.deps.CASettings.Set(ctx, "selfsigned", caconfig.SelfSignedSettings{ValidityDays: req.ValidityDays}); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save settings")
		return
	}
	h.deps.Authorities.Set("selfsigned", newAuthority)
	h.audit(r, "integration_updated", "integration", "selfsigned", string(auth.ScopeCertsAdmin), map[string]interface{}{"validity_days": req.ValidityDays})
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}
