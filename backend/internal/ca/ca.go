// Package ca defines the CertificateAuthority abstraction described in
// docs/plan.html (section 04) — one interface, one implementation per
// provider, so the order service and renewal worker never special-case
// Let's Encrypt or ZeroSSL directly.
package ca

import "time"

type Challenge struct {
	Type         string `json:"type"`
	ResourceName string `json:"resource_name"`
	Value        string `json:"value"`
	Verified     bool   `json:"verified"`
}

type IssuedCertificate struct {
	PEMCert           string
	PEMChain          string
	SerialNumber      string
	FingerprintSHA256 string
	NotBefore         time.Time
	NotAfter          time.Time
}

// Authority is implemented once per certificate authority. RequestValidation
// starts domain-control validation for the given domains using the named
// method (e.g. "http-01", "dns-01", "cname"); CheckChallenge polls whether
// the CA has observed proof; Issue submits the CSR once validation passes.
type Authority interface {
	Name() string
	SupportedValidationMethods() []string
	RequestValidation(domains []string, method string) (Challenge, error)
	CheckChallenge(challenge Challenge) (Challenge, error)
	Issue(csrPEM string, domains []string) (IssuedCertificate, error)
}

func Registry(authorities ...Authority) map[string]Authority {
	reg := make(map[string]Authority, len(authorities))
	for _, a := range authorities {
		reg[a.Name()] = a
	}
	return reg
}
