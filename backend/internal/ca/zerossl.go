package ca

import (
	"fmt"
	"time"
)

// ZeroSSL is a stand-in for the real ZeroSSL REST API integration described
// in docs/plan.html (section 04). Same simulated behavior as LetsEncrypt,
// swapped in behind the same Authority interface.
type ZeroSSL struct{}

func NewZeroSSL() *ZeroSSL { return &ZeroSSL{} }

func (z *ZeroSSL) Name() string { return "zerossl" }

func (z *ZeroSSL) SupportedValidationMethods() []string {
	return []string{"http-file", "cname"}
}

func (z *ZeroSSL) RequestValidation(domains []string, method string) (Challenge, error) {
	if len(domains) == 0 {
		return Challenge{}, fmt.Errorf("zerossl: at least one domain is required")
	}
	switch method {
	case "http-file":
		return Challenge{
			Type:         method,
			ResourceName: fmt.Sprintf("http://%s/.well-known/pki-validation/%s.txt", domains[0], tokenFor(domains[0])),
			Value:        tokenFor(domains[0]),
		}, nil
	case "cname":
		return Challenge{
			Type:         method,
			ResourceName: fmt.Sprintf("_%s.%s", tokenFor(domains[0])[:8], domains[0]),
			Value:        fmt.Sprintf("%s.zerossl.com", tokenFor(domains[0])[:16]),
		}, nil
	default:
		return Challenge{}, fmt.Errorf("zerossl: unsupported validation method %q", method)
	}
}

func (z *ZeroSSL) CheckChallenge(challenge Challenge) (Challenge, error) {
	challenge.Verified = true
	return challenge, nil
}

func (z *ZeroSSL) Issue(csrPEM string, domains []string) (IssuedCertificate, error) {
	now := time.Now()
	return IssuedCertificate{
		PEMCert:           placeholderPEM("CERTIFICATE", domains[0]),
		PEMChain:          placeholderPEM("CERTIFICATE", "ZeroSSL RSA Domain Secure Site CA"),
		SerialNumber:      serialFor(domains[0], now),
		FingerprintSHA256: fingerprintFor(csrPEM),
		NotBefore:         now,
		NotAfter:          now.Add(90 * 24 * time.Hour),
	}, nil
}
