package ca

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// LetsEncrypt is a stand-in for a real ACME v2 client (e.g. go-acme/lego).
// It simulates the HTTP-01/DNS-01 challenge-and-issue flow synchronously so
// the API and order service have a working end-to-end path to build
// against; swapping in a real ACME client means implementing this same
// Authority interface, not changing any caller.
type LetsEncrypt struct{}

func NewLetsEncrypt() *LetsEncrypt { return &LetsEncrypt{} }

func (l *LetsEncrypt) Name() string { return "letsencrypt" }

func (l *LetsEncrypt) SupportedValidationMethods() []string {
	return []string{"http-01", "dns-01"}
}

func (l *LetsEncrypt) RequestValidation(domains []string, method string) (Challenge, error) {
	if len(domains) == 0 {
		return Challenge{}, fmt.Errorf("letsencrypt: at least one domain is required")
	}
	switch method {
	case "http-01":
		return Challenge{
			Type:         method,
			ResourceName: fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", domains[0], tokenFor(domains[0])),
			Value:        tokenFor(domains[0]),
		}, nil
	case "dns-01":
		return Challenge{
			Type:         method,
			ResourceName: fmt.Sprintf("_acme-challenge.%s", domains[0]),
			Value:        tokenFor(domains[0]),
		}, nil
	default:
		return Challenge{}, fmt.Errorf("letsencrypt: unsupported validation method %q", method)
	}
}

func (l *LetsEncrypt) CheckChallenge(challenge Challenge) (Challenge, error) {
	challenge.Verified = true
	return challenge, nil
}

func (l *LetsEncrypt) Issue(csrPEM string, domains []string) (IssuedCertificate, error) {
	now := time.Now()
	return IssuedCertificate{
		PEMCert:           placeholderPEM("CERTIFICATE", domains[0]),
		PEMChain:          placeholderPEM("CERTIFICATE", "R3 (Let's Encrypt)"),
		SerialNumber:      serialFor(domains[0], now),
		FingerprintSHA256: fingerprintFor(csrPEM),
		NotBefore:         now,
		NotAfter:          now.Add(90 * 24 * time.Hour),
	}, nil
}

func tokenFor(domain string) string {
	sum := sha256.Sum256([]byte("token:" + domain))
	return hex.EncodeToString(sum[:16])
}

func serialFor(domain string, at time.Time) string {
	sum := sha256.Sum256([]byte(domain + at.String()))
	return hex.EncodeToString(sum[:8])
}

func fingerprintFor(material string) string {
	sum := sha256.Sum256([]byte(material))
	return hex.EncodeToString(sum[:])
}

func placeholderPEM(block, subject string) string {
	return fmt.Sprintf("-----BEGIN %s-----\nplaceholder for %s, issued by a stub CA\n-----END %s-----\n", block, subject, block)
}
