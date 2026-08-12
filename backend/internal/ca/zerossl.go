package ca

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ZeroSSL implements the Authority interface against ZeroSSL's REST API
// (https://developer.zerossl.com). Unlike Let's Encrypt, ZeroSSL wants the
// CSR up front when the certificate is created, validates domain control
// against it asynchronously, and issues automatically once validation
// passes — there is no separate ACME-style "finalize" step.
//
// This has been unit-tested against a mock server that reproduces the
// documented request/response shapes (see zerossl_test.go); it has not
// been exercised against ZeroSSL's live API, since doing so needs an
// account API key this environment doesn't have. Re-verify field names
// against current ZeroSSL docs before pointing this at production.
type ZeroSSLConfig struct {
	APIKey      string
	BaseURL     string
	HTTPTimeout time.Duration
}

type ZeroSSL struct {
	cfg    ZeroSSLConfig
	client *http.Client
}

func NewZeroSSL(cfg ZeroSSLConfig) *ZeroSSL {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.zerossl.com"
	}
	timeout := cfg.HTTPTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &ZeroSSL{cfg: cfg, client: &http.Client{Timeout: timeout}}
}

func (z *ZeroSSL) Name() string { return "zerossl" }

func (z *ZeroSSL) SupportedValidationMethods() []string {
	return []string{"http-file", "cname"}
}

func zerosslValidationMethod(method string) (string, error) {
	switch method {
	case "http-file":
		return "HTTP_CSR_HASH", nil
	case "cname":
		return "CNAME_CSR_HASH", nil
	default:
		return "", fmt.Errorf("zerossl: unsupported validation method %q", method)
	}
}

type zerosslOtherMethod struct {
	FileValidationURLHTTP  string   `json:"file_validation_url_http"`
	FileValidationURLHTTPS string   `json:"file_validation_url_https"`
	FileValidationContent  []string `json:"file_validation_content"`
	CNAMEValidationP1      string   `json:"cname_validation_p1"`
	CNAMEValidationP2      string   `json:"cname_validation_p2"`
}

type zerosslCreateResponse struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	Validation struct {
		OtherMethods map[string]zerosslOtherMethod `json:"other_methods"`
	} `json:"validation"`
	Error *zerosslError `json:"error,omitempty"`
}

type zerosslError struct {
	Code int    `json:"code"`
	Type string `json:"type"`
}

func (e *zerosslError) Error() string {
	return fmt.Sprintf("zerossl API error %d: %s", e.Code, e.Type)
}

type zerosslState struct {
	CertificateID      string `json:"certificate_id"`
	ValidationMethod   string `json:"validation_method"`
	ChallengeTriggered bool   `json:"challenge_triggered"`
}

func (z *ZeroSSL) RequestValidation(ctx context.Context, domains []string, method, csrPEM string) (ProviderOrder, error) {
	validationMethod, err := zerosslValidationMethod(method)
	if err != nil {
		return ProviderOrder{}, err
	}
	if len(domains) == 0 {
		return ProviderOrder{}, fmt.Errorf("zerossl: at least one domain is required")
	}

	form := url.Values{
		"certificate_domains":       {strings.Join(domains, ",")},
		"certificate_csr":           {csrPEM},
		"certificate_validity_days": {"90"},
	}

	var resp zerosslCreateResponse
	if err := z.post(ctx, "/certificates", form, &resp); err != nil {
		return ProviderOrder{}, err
	}
	if resp.Error != nil {
		return ProviderOrder{}, resp.Error
	}

	challenges := make([]Challenge, 0, len(domains))
	for _, domain := range domains {
		other, ok := resp.Validation.OtherMethods[domain]
		if !ok {
			return ProviderOrder{}, fmt.Errorf("zerossl: no validation instructions returned for %s", domain)
		}
		var resourceName, value string
		switch method {
		case "http-file":
			resourceName = other.FileValidationURLHTTP
			value = strings.Join(other.FileValidationContent, "\n")
		case "cname":
			resourceName = other.CNAMEValidationP1
			value = other.CNAMEValidationP2
		}
		challenges = append(challenges, Challenge{
			Domain:       domain,
			Type:         method,
			ResourceName: resourceName,
			Value:        value,
		})
	}

	state, err := json.Marshal(zerosslState{CertificateID: resp.ID, ValidationMethod: validationMethod})
	if err != nil {
		return ProviderOrder{}, fmt.Errorf("zerossl: marshal state: %w", err)
	}
	return ProviderOrder{Challenges: challenges, State: string(state)}, nil
}

type zerosslCertStatusResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

func (z *ZeroSSL) CheckChallenge(ctx context.Context, po ProviderOrder) (ProviderOrder, error) {
	var state zerosslState
	if err := json.Unmarshal([]byte(po.State), &state); err != nil {
		return po, fmt.Errorf("zerossl: unmarshal state: %w", err)
	}

	if !state.ChallengeTriggered {
		form := url.Values{"validation_method": {state.ValidationMethod}}
		var triggerResp zerosslCertStatusResponse
		if err := z.post(ctx, fmt.Sprintf("/certificates/%s/challenges", state.CertificateID), form, &triggerResp); err != nil {
			return po, fmt.Errorf("zerossl: trigger validation: %w", err)
		}
		state.ChallengeTriggered = true
	}

	var status zerosslCertStatusResponse
	if err := z.get(ctx, fmt.Sprintf("/certificates/%s", state.CertificateID), &status); err != nil {
		return po, fmt.Errorf("zerossl: check status: %w", err)
	}

	switch status.Status {
	case "issued":
		for i := range po.Challenges {
			po.Challenges[i].Verified = true
		}
	case "cancelled", "expired":
		for i := range po.Challenges {
			po.Challenges[i].Error = fmt.Sprintf("zerossl certificate status: %s", status.Status)
		}
	}

	stateJSON, err := json.Marshal(state)
	if err != nil {
		return po, fmt.Errorf("zerossl: marshal state: %w", err)
	}
	po.State = string(stateJSON)
	return po, nil
}

type zerosslDownloadResponse struct {
	CertificateCrt string `json:"certificate.crt"`
	CABundleCrt    string `json:"ca_bundle.crt"`
}

func (z *ZeroSSL) Issue(ctx context.Context, po ProviderOrder, _ string, _ []string) (IssuedCertificate, error) {
	var state zerosslState
	if err := json.Unmarshal([]byte(po.State), &state); err != nil {
		return IssuedCertificate{}, fmt.Errorf("zerossl: unmarshal state: %w", err)
	}

	var dl zerosslDownloadResponse
	if err := z.get(ctx, fmt.Sprintf("/certificates/%s/download/return", state.CertificateID), &dl); err != nil {
		return IssuedCertificate{}, fmt.Errorf("zerossl: download certificate: %w", err)
	}

	leafBlock, _ := pem.Decode([]byte(dl.CertificateCrt))
	if leafBlock == nil {
		return IssuedCertificate{}, fmt.Errorf("zerossl: could not PEM-decode issued certificate")
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("zerossl: parse issued certificate: %w", err)
	}

	return IssuedCertificate{
		PEMCert:           dl.CertificateCrt,
		PEMChain:          dl.CABundleCrt,
		SerialNumber:      leaf.SerialNumber.String(),
		FingerprintSHA256: Fingerprint(leaf.Raw),
		NotBefore:         leaf.NotBefore,
		NotAfter:          leaf.NotAfter,
		CAReference:       state.CertificateID,
	}, nil
}

type zerosslRevokeResponse struct {
	Success bool `json:"success"`
}

// Revoke doesn't need certPEM — ZeroSSL revokes by certificate ID, unlike
// Let's Encrypt which needs the certificate body itself.
func (z *ZeroSSL) Revoke(ctx context.Context, _ string, caReference string) error {
	if caReference == "" {
		return fmt.Errorf("zerossl: no certificate id to revoke")
	}
	form := url.Values{"reason": {"unspecified"}}
	var resp zerosslRevokeResponse
	if err := z.post(ctx, fmt.Sprintf("/certificates/%s/revoke", caReference), form, &resp); err != nil {
		return fmt.Errorf("zerossl: revoke: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("zerossl: revoke request was not successful")
	}
	return nil
}

func (z *ZeroSSL) post(ctx context.Context, path string, form url.Values, out interface{}) error {
	endpoint := z.cfg.BaseURL + path + "?" + url.Values{"access_key": {z.cfg.APIKey}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return z.do(req, out)
}

func (z *ZeroSSL) get(ctx context.Context, path string, out interface{}) error {
	endpoint := z.cfg.BaseURL + path + "?" + url.Values{"access_key": {z.cfg.APIKey}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	return z.do(req, out)
}

func (z *ZeroSSL) do(req *http.Request, out interface{}) error {
	resp, err := z.client.Do(req)
	if err != nil {
		return fmt.Errorf("zerossl: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("zerossl: unexpected status %s", strconv.Itoa(resp.StatusCode))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("zerossl: decode response: %w", err)
	}
	return nil
}
