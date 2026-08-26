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
	"crypto"
	"sync"
	"time"
)

type Challenge struct {
	Domain       string `json:"domain"`
	Type         string `json:"type"`
	ResourceName string `json:"resource_name"`
	Value        string `json:"value"`
	Verified     bool   `json:"verified"`
	Error        string `json:"error,omitempty"`
	// Automated is true when a real DNS provider published this record —
	// there is nothing for a human to do, unlike a manual HTTP-01/DNS-01
	// challenge, which still needs someone to publish ResourceName/Value
	// themselves.
	Automated bool `json:"automated,omitempty"`
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
	// CAReference is whatever the provider needs to act on this
	// certificate again later without the CSR/order state around — for
	// ZeroSSL, its certificate ID; Let's Encrypt doesn't need one since
	// revoking there only needs the certificate body itself.
	CAReference string
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
	// Issue submits csrPEM once every challenge in po is verified. signer is
	// the Vault-backed key the CSR was built with — every real CA ignores
	// it and works from csrPEM alone, but a provider that signs locally
	// (selfsigned) has no CA round trip to get a certificate from and needs
	// it to produce one.
	Issue(ctx context.Context, po ProviderOrder, csrPEM string, domains []string, signer crypto.Signer) (IssuedCertificate, error)
	// Revoke tells the CA a previously issued certificate should no
	// longer be trusted. certPEM is the leaf certificate; caReference is
	// whatever Issue returned as IssuedCertificate.CAReference for it.
	Revoke(ctx context.Context, certPEM, caReference string) error
}

// Registry is the live set of configured CA authorities, keyed by
// Authority.Name(). It's a mutex-guarded map rather than a plain one
// because integration settings are now editable at runtime (see
// internal/api's integration handlers): an admin's edit rebuilds one
// provider's Authority and swaps it in while HTTP handlers and the
// renewal engine may be reading the registry concurrently. A plain Go map
// read concurrently with a write panics ("concurrent map read and map
// write") rather than just returning stale data, so this can't be skipped.
type Registry struct {
	mu     sync.RWMutex
	byName map[string]Authority
}

func NewRegistry(authorities ...Authority) *Registry {
	r := &Registry{byName: make(map[string]Authority, len(authorities))}
	for _, a := range authorities {
		r.byName[a.Name()] = a
	}
	return r
}

// Get reports (nil, false) for a provider that either was never configured
// or whose configuration was since removed (e.g. an admin cleared AD CS's
// base URL) — the same shape as a plain map index, so existing callers
// didn't need to change how they check for "not configured".
func (r *Registry) Get(name string) (Authority, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.byName[name]
	return a, ok
}

// Set installs (or replaces) the live Authority for a provider — this is
// what makes an integration-settings edit take effect immediately, with no
// restart, for every request that comes in after it returns.
func (r *Registry) Set(name string, a Authority) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byName[name] = a
}

// Delete removes a provider from the registry entirely — used when an
// admin clears an optional integration's configuration (e.g. AD CS's base
// URL) back to "not configured" rather than replacing it with something
// new.
func (r *Registry) Delete(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byName, name)
}

// Names lists every currently configured provider, sorted for stable
// output (used by the integrations status endpoint).
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.byName))
	for n := range r.byName {
		names = append(names, n)
	}
	return names
}
