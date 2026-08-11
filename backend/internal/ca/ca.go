// Package ca defines the CertificateAuthority abstraction described in
// docs/plan.html (section 04) — one interface, one implementation per
// provider, so the order service and renewal worker never special-case
// Let's Encrypt or ZeroSSL directly.
//
// Real domain-control validation is inherently multi-step: request it,
// wait for a human or an automated DNS update to satisfy it, ask the CA to
// check, then finalize. RequestValidation/CheckChallenge/Issue map onto
// those steps; the opaque State field on ProviderOrder carries whatever a
// given provider needs to remember between them (ACME order/authorization
// URLs for Let's Encrypt, a certificate ID for ZeroSSL) without leaking
// provider-specific detail into the order service.
package ca

import (
	"context"
	"time"
)

type Challenge struct {
	Domain       string `json:"domain"`
	Type         string `json:"type"`
	ResourceName string `json:"resource_name"`
	Value        string `json:"value"`
	Verified     bool   `json:"verified"`
	Error        string `json:"error,omitempty"`
}

// ProviderOrder is what a CA implementation returns from RequestValidation
// and threads through CheckChallenge/Issue. Challenges is safe to show a
// user; State is provider-internal bookkeeping and should be stripped
// before any of this reaches an HTTP response.
type ProviderOrder struct {
	Challenges []Challenge `json:"challenges"`
	State      string      `json:"state,omitempty"`
}

func (p ProviderOrder) AllVerified() bool {
	if len(p.Challenges) == 0 {
		return false
	}
	for _, c := range p.Challenges {
		if !c.Verified {
			return false
		}
	}
	return true
}

type IssuedCertificate struct {
	PEMCert           string
	PEMChain          string
	SerialNumber      string
	FingerprintSHA256 string
	NotBefore         time.Time
	NotAfter          time.Time
}

// Authority is implemented once per certificate authority.
type Authority interface {
	Name() string
	SupportedValidationMethods() []string
	// RequestValidation starts domain-control validation for the given
	// domains using the named method (e.g. "http-01", "dns-01") and returns
	// what the user needs to publish. csrPEM is provided here (not only to
	// Issue) because some CAs — ZeroSSL among them — require the CSR at
	// certificate-creation time, before validation happens; providers that
	// don't need it yet (Let's Encrypt) simply ignore it until Issue.
	RequestValidation(ctx context.Context, domains []string, method, csrPEM string) (ProviderOrder, error)
	// CheckChallenge asks the CA whether it has observed proof for every
	// challenge in po, returning po with Verified flags (and State) updated.
	// An unmet challenge is not an error — it's po.AllVerified() == false.
	CheckChallenge(ctx context.Context, po ProviderOrder) (ProviderOrder, error)
	// Issue submits csrPEM once every challenge in po is verified.
	Issue(ctx context.Context, po ProviderOrder, csrPEM string, domains []string) (IssuedCertificate, error)
}

func Registry(authorities ...Authority) map[string]Authority {
	reg := make(map[string]Authority, len(authorities))
	for _, a := range authorities {
		reg[a.Name()] = a
	}
	return reg
}
