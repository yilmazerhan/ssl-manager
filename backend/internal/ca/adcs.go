package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/go-ntlmssp"
)

// ADCS talks to a Microsoft Active Directory Certificate Services CA
// through its HTTP web enrollment pages (certsrv) — the same interface
// `certreq`/PowerShell's Get-Certificate use against a Windows CA that
// isn't exposing MS-WCCE over DCOM/RPC to this process. There is no
// domain-control validation step; the CA either issues on submission (a
// template with no manager approval configured) or leaves the request
// pending until a CA administrator approves it, and CheckChallenge polls
// for either outcome the same way.
//
// This has been unit-tested against a mock server reproducing certsrv's
// documented request/response shapes (see adcs_test.go) with no
// authentication required, so it proves the request-building and
// response-parsing logic; it has not been exercised against a real AD CS
// server or its NTLM/Kerberos challenge (that handshake is go-ntlmssp's
// own, separately-tested responsibility) — no Windows domain exists in
// this environment to test against. Re-verify the exact form field names
// and response markup against your CA's certsrv pages (they vary slightly
// between Windows Server versions) before pointing this at production.
type ADCSConfig struct {
	// BaseURL is the certsrv virtual directory, e.g.
	// "https://ca.corp.example.com/certsrv".
	BaseURL string
	// Template is submitted as the CertAttrib CertificateTemplate value
	// (e.g. "WebServer"). Leave empty to let the CA apply its default.
	Template string
	Username string
	Password string
	// AllowBasicAuth lets the client fall back to HTTP Basic auth if the
	// server asks for it instead of NTLM/Negotiate. Only enable this over
	// TLS — Basic sends credentials in the clear otherwise.
	AllowBasicAuth     bool
	InsecureSkipVerify bool
	HTTPTimeout        time.Duration
}

type ADCS struct {
	cfg    ADCSConfig
	client *http.Client
}

func NewADCS(cfg ADCSConfig) *ADCS {
	timeout := cfg.HTTPTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	var transport http.RoundTripper = &http.Transport{}
	if cfg.InsecureSkipVerify {
		transport = insecureTransport()
	}
	return &ADCS{
		cfg: cfg,
		client: &http.Client{
			Timeout: timeout,
			Transport: ntlmssp.Negotiator{
				RoundTripper:   transport,
				AllowBasicAuth: cfg.AllowBasicAuth,
			},
		},
	}
}

func (a *ADCS) Name() string { return "adcs" }

func (a *ADCS) SupportedValidationMethods() []string { return []string{"adcs-enroll"} }

type adcsState struct {
	RequestID string `json:"request_id"`
}

func (a *ADCS) RequestValidation(ctx context.Context, domains []string, method, csrPEM string) (ProviderOrder, error) {
	if method != "adcs-enroll" {
		return ProviderOrder{}, fmt.Errorf("adcs: unsupported validation method %q", method)
	}
	if csrPEM == "" {
		return ProviderOrder{}, fmt.Errorf("adcs: a CSR is required to submit an enrollment request")
	}
	if len(domains) == 0 {
		return ProviderOrder{}, fmt.Errorf("adcs: at least one domain is required")
	}

	form := url.Values{
		"Mode":             {"newreq"},
		"CertRequest":      {csrPEM},
		"CertAttrib":       {adcsCertAttrib(a.cfg.Template)},
		"TargetStoreFlags": {"0"},
		"SaveCert":         {"yes"},
	}
	body, err := a.do(ctx, http.MethodPost, "/certfnsh.asp", strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	if err != nil {
		return ProviderOrder{}, fmt.Errorf("adcs: submit request: %w", err)
	}

	requestID, denyReason, err := parseCertsrvSubmitResponse(body)
	if err != nil {
		return ProviderOrder{}, fmt.Errorf("adcs: %w (check the CA's certsrv logs, or that %q is a valid template name)", err, a.cfg.Template)
	}

	stateJSON, err := json.Marshal(adcsState{RequestID: requestID})
	if err != nil {
		return ProviderOrder{}, fmt.Errorf("adcs: marshal state: %w", err)
	}

	challenge := Challenge{
		Domain:       domains[0],
		Type:         method,
		ResourceName: fmt.Sprintf("AD CS request #%s on %s", requestID, a.cfg.BaseURL),
		Automated:    true,
	}
	if denyReason != "" {
		challenge.Error = denyReason
	}
	return ProviderOrder{Challenges: []Challenge{challenge}, State: string(stateJSON)}, nil
}

func (a *ADCS) CheckChallenge(ctx context.Context, po ProviderOrder) (ProviderOrder, error) {
	var state adcsState
	if err := json.Unmarshal([]byte(po.State), &state); err != nil {
		return po, fmt.Errorf("adcs: unmarshal state: %w", err)
	}

	certPEM, issued, denyReason, err := a.fetchCertificate(ctx, state.RequestID)
	if err != nil {
		return po, fmt.Errorf("adcs: check request #%s: %w", state.RequestID, err)
	}
	switch {
	case issued && certPEM != "":
		for i := range po.Challenges {
			po.Challenges[i].Verified = true
		}
	case denyReason != "":
		for i := range po.Challenges {
			po.Challenges[i].Error = denyReason
		}
	}
	// Anything else (still pending / awaiting CA administrator approval)
	// is not a failure — po.AllVerified() stays false and a caller checks
	// again later, the same as an unpublished HTTP-01/DNS-01 record.
	return po, nil
}

func (a *ADCS) Issue(ctx context.Context, po ProviderOrder, _ string, _ []string, _ crypto.Signer) (IssuedCertificate, error) {
	var state adcsState
	if err := json.Unmarshal([]byte(po.State), &state); err != nil {
		return IssuedCertificate{}, fmt.Errorf("adcs: unmarshal state: %w", err)
	}

	certPEM, issued, denyReason, err := a.fetchCertificate(ctx, state.RequestID)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("adcs: download certificate: %w", err)
	}
	if denyReason != "" {
		return IssuedCertificate{}, fmt.Errorf("adcs: request #%s was denied: %s", state.RequestID, denyReason)
	}
	if !issued {
		return IssuedCertificate{}, fmt.Errorf("adcs: request #%s has not been issued yet", state.RequestID)
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return IssuedCertificate{}, fmt.Errorf("adcs: could not PEM-decode issued certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("adcs: parse issued certificate: %w", err)
	}

	return IssuedCertificate{
		PEMCert: certPEM,
		// PEMChain is intentionally empty: certsrv serves the chain as a
		// PKCS#7 blob (certnew.p7b), and extracting individual certificates
		// from PKCS#7 needs a parser this codebase doesn't otherwise
		// depend on. Fetch the CA's chain out-of-band (certsrv's own
		// "Download CA certificate" page) until this is worth adding.
		SerialNumber:      leaf.SerialNumber.String(),
		FingerprintSHA256: Fingerprint(leaf.Raw),
		NotBefore:         leaf.NotBefore,
		NotAfter:          leaf.NotAfter,
		CAReference:       state.RequestID,
	}, nil
}

// Revoke refuses rather than pretending to succeed: certsrv's web
// enrollment pages have no revoke endpoint — that action needs the CA's
// MMC console or `certutil -revoke <serial>` run against the CA server
// itself, neither of which is reachable over HTTP. Silently returning nil
// here would let a caller believe the CA had been told, when every other
// system still checking this CA's CRL/OCSP would keep trusting the
// certificate.
func (a *ADCS) Revoke(_ context.Context, _, caReference string) error {
	return fmt.Errorf("adcs: certsrv's web enrollment interface has no revoke endpoint — revoke request #%s via the CA's MMC console or `certutil -revoke`, then mark it revoked here", caReference)
}

func adcsCertAttrib(template string) string {
	if template == "" {
		return ""
	}
	return "CertificateTemplate:" + template
}

var (
	certsrvRequestIDPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)Request Id is (\d+)`),
		regexp.MustCompile(`(?i)ReqID=(\d+)`),
	}
	certsrvDeniedPattern = regexp.MustCompile(`(?i)(denied|not[- ]?permitted).{0,120}`)
)

// parseCertsrvSubmitResponse extracts the request ID certfnsh.asp embeds in
// its HTML response, whether the request was issued immediately or left
// pending a CA administrator's approval — both cases quote it the same way.
func parseCertsrvSubmitResponse(body string) (requestID, denyReason string, err error) {
	for _, re := range certsrvRequestIDPatterns {
		if m := re.FindStringSubmatch(body); m != nil {
			requestID = m[1]
			break
		}
	}
	if requestID == "" {
		if m := certsrvDeniedPattern.FindString(body); m != "" {
			return "", "", fmt.Errorf("request was denied by the CA: %s", strings.TrimSpace(m))
		}
		return "", "", fmt.Errorf("could not find a request ID in the CA's response")
	}
	if m := certsrvDeniedPattern.FindString(body); m != "" {
		denyReason = strings.TrimSpace(m)
	}
	return requestID, denyReason, nil
}

// fetchCertificate asks certsrv for the certificate behind requestID.
// certnew.cer returns the PEM-encoded leaf if it's been issued, or an HTML
// page saying the request is pending/denied/unknown otherwise — both are
// normal, not transport errors, so they're reported as return values, not
// as err.
func (a *ADCS) fetchCertificate(ctx context.Context, requestID string) (certPEM string, issued bool, denyReason string, err error) {
	body, err := a.do(ctx, http.MethodGet, fmt.Sprintf("/certnew.cer?ReqID=%s&Enc=b64", url.QueryEscape(requestID)), nil, "")
	if err != nil {
		return "", false, "", err
	}
	if strings.Contains(body, "-----BEGIN CERTIFICATE-----") {
		return body, true, "", nil
	}
	if m := certsrvDeniedPattern.FindString(body); m != "" {
		return "", false, strings.TrimSpace(m), nil
	}
	return "", false, "", nil
}

func (a *ADCS) do(ctx context.Context, method, path string, body io.Reader, contentType string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(a.cfg.BaseURL, "/")+path, body)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	// go-ntlmssp only performs the NTLM/Negotiate handshake for requests
	// that carry Basic credentials to convert — see its RoundTrip.
	if a.cfg.Username != "" {
		req.SetBasicAuth(a.cfg.Username, a.cfg.Password)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return string(data), nil
}
