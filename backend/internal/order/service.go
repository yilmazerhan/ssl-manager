// Package order implements the certificate creation flow from
// docs/plan.html (section 05): an order moves from draft through
// awaiting_validation and issuing to issued, mirroring the wizard steps
// rather than trying to issue a certificate in one blocking call.
package order

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"

	"github.com/yilmazerhan/ssl-manager/backend/internal/ca"
	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
	"github.com/yilmazerhan/ssl-manager/backend/internal/secrets"
)

// maxDomainsPerOrder bounds both the CSR's SAN list and, downstream, how
// much a range-over-domains reminder-email template can fan out to.
const maxDomainsPerOrder = 100

// domainPattern is deliberately permissive about DNS-label structure (it
// accepts single-label internal hostnames like "localhost", not just
// public-style FQDNs) but strict about the character set: only
// alphanumerics, hyphens, dots, and a single leading "*." wildcard. That's
// enough to keep a domain out of a raw SMTP header — CommonName ends up in
// the expiry-reminder email's subject — without rejecting any legitimate
// internal/test hostname.
var domainPattern = regexp.MustCompile(`^(\*\.)?[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*$`)

func validateDomains(domains []string) error {
	if len(domains) == 0 {
		return fmt.Errorf("at least one domain is required")
	}
	if len(domains) > maxDomainsPerOrder {
		return fmt.Errorf("at most %d domains are allowed per order, got %d", maxDomainsPerOrder, len(domains))
	}
	for _, d := range domains {
		if d == "" || len(d) > 253 || !domainPattern.MatchString(d) {
			return fmt.Errorf("invalid domain %q", d)
		}
	}
	return nil
}

// maxSubjectFieldLength bounds every free-text subject field (O/OU/ST/L) —
// generous for a real organization/unit/city name, but short enough that
// nothing absurd ends up baked into a CSR's Subject.
const maxSubjectFieldLength = 128

var countryCodePattern = regexp.MustCompile(`^[A-Z]{2}$`)

// validateSubject checks the optional certificate-subject fields
// (organization, organizational unit, country, state, locality) collected
// alongside domains. All are optional — many CAs only care about
// CommonName/SANs — but if given, country must be a real ISO 3166-1
// alpha-2 code (what X.509 and every CA expects there) rather than
// whatever a user happens to type, and none may be absurdly long.
func validateSubject(country, organization, organizationalUnit, state, locality string) error {
	if country != "" && !countryCodePattern.MatchString(country) {
		return fmt.Errorf("country must be a 2-letter ISO code (e.g. US, TR), got %q", country)
	}
	for name, v := range map[string]string{
		"organization":        organization,
		"organizational_unit": organizationalUnit,
		"state":               state,
		"locality":            locality,
	} {
		if len(v) > maxSubjectFieldLength {
			return fmt.Errorf("%s must be at most %d characters", name, maxSubjectFieldLength)
		}
	}
	return nil
}

type Service struct {
	orders      Store
	certs       certificate.Store
	keys        secrets.KeyManager
	authorities *ca.Registry
}

func NewService(orders Store, certs certificate.Store, keys secrets.KeyManager, authorities *ca.Registry) *Service {
	return &Service{orders: orders, certs: certs, keys: keys, authorities: authorities}
}

func (s *Service) Create(ctx context.Context, req CreateRequest) (Order, error) {
	authority, ok := s.authorities.Get(req.CAProvider)
	if !ok {
		return Order{}, fmt.Errorf("unknown ca_provider %q", req.CAProvider)
	}
	if err := validateDomains(req.Domains); err != nil {
		return Order{}, err
	}
	if err := validateSubject(req.Country, req.Organization, req.OrganizationalUnit, req.State, req.Locality); err != nil {
		return Order{}, err
	}
	if req.KeyAlgorithm == "" {
		req.KeyAlgorithm = "RSA-2048"
	}

	keyRef := "order-" + uuid.NewString()
	if err := s.keys.EnsureKey(ctx, keyRef, req.KeyAlgorithm); err != nil {
		return Order{}, fmt.Errorf("provision key: %w", err)
	}

	subject := buildSubject(req.Country, req.Organization, req.OrganizationalUnit, req.State, req.Locality)
	csrPEM, err := buildCSR(ctx, s.keys, keyRef, req.Domains, subject)
	if err != nil {
		return Order{}, fmt.Errorf("build CSR: %w", err)
	}

	po, err := authority.RequestValidation(ctx, req.Domains, req.ValidationMethod, csrPEM)
	if err != nil {
		return Order{}, fmt.Errorf("request validation: %w", err)
	}

	return s.orders.Create(ctx, Order{
		RequestedBy:        req.RequestedBy,
		OwningTeam:         req.OwningTeam,
		Domains:            req.Domains,
		CAProvider:         req.CAProvider,
		ValidationMethod:   req.ValidationMethod,
		KeyAlgorithm:       req.KeyAlgorithm,
		Status:             StatusAwaitingValidation,
		Challenges:         po,
		KeyRef:             keyRef,
		CSRPEM:             csrPEM,
		Organization:       req.Organization,
		OrganizationalUnit: req.OrganizationalUnit,
		Country:            req.Country,
		State:              req.State,
		Locality:           req.Locality,
	})
}

func (s *Service) Get(ctx context.Context, id string) (Order, error) {
	return s.orders.Get(ctx, id)
}

// CreateRenewal starts an order for an *existing* certificate rather than a
// new one: it reuses the certificate's Vault key and validation method
// (the renewal engine's "reuse the existing key" policy from
// docs/plan.html section 06) instead of provisioning anything new.
// Presetting CertificateID is what tells Validate this order renews a
// certificate in place rather than creating one.
func (s *Service) CreateRenewal(ctx context.Context, cert certificate.Certificate, requestedBy string) (Order, error) {
	authority, ok := s.authorities.Get(cert.CAProvider)
	if !ok {
		return Order{}, fmt.Errorf("unknown ca_provider %q", cert.CAProvider)
	}

	subject := buildSubject(cert.Country, cert.Organization, cert.OrganizationalUnit, cert.State, cert.Locality)
	csrPEM, err := buildCSR(ctx, s.keys, cert.KeyRef, cert.SANs, subject)
	if err != nil {
		return Order{}, fmt.Errorf("build CSR: %w", err)
	}

	po, err := authority.RequestValidation(ctx, cert.SANs, cert.ValidationMethod, csrPEM)
	if err != nil {
		return Order{}, fmt.Errorf("request validation: %w", err)
	}

	return s.orders.Create(ctx, Order{
		RequestedBy:        requestedBy,
		OwningTeam:         cert.OwningTeam,
		Domains:            cert.SANs,
		CAProvider:         cert.CAProvider,
		ValidationMethod:   cert.ValidationMethod,
		KeyAlgorithm:       cert.KeyAlgorithm,
		Status:             StatusAwaitingValidation,
		Challenges:         po,
		KeyRef:             cert.KeyRef,
		CSRPEM:             csrPEM,
		CertificateID:      cert.ID,
		Organization:       cert.Organization,
		OrganizationalUnit: cert.OrganizationalUnit,
		Country:            cert.Country,
		State:              cert.State,
		Locality:           cert.Locality,
	})
}

// Validate re-checks the domain-control challenge (step 5 of the wizard)
// and, once every challenge is verified, submits the CSR built at Create
// time and stores the resulting certificate (steps 6-7). A challenge that
// simply isn't observed yet is not a failure — the order stays
// awaiting_validation so the UI's "check now" button can be pressed again.
func (s *Service) Validate(ctx context.Context, id string) (Order, error) {
	o, err := s.orders.Get(ctx, id)
	if err != nil {
		return Order{}, err
	}
	if o.Status != StatusAwaitingValidation {
		return o, nil
	}

	authority, ok := s.authorities.Get(o.CAProvider)
	if !ok {
		// The provider that started this order was removed or reconfigured
		// out from under it (integration settings are editable at runtime —
		// see internal/api's integration handlers) — fail the order rather
		// than dereferencing a nil Authority.
		return s.fail(ctx, o, fmt.Sprintf("ca_provider %q is no longer configured", o.CAProvider))
	}
	po, err := authority.CheckChallenge(ctx, o.Challenges)
	o.Challenges = po
	o.AttemptCount++
	if err != nil {
		if updateErr := s.orders.Update(ctx, o); updateErr != nil {
			return Order{}, updateErr
		}
		return o, nil
	}

	if failure := firstChallengeError(po); failure != "" {
		return s.fail(ctx, o, failure)
	}
	if !po.AllVerified() {
		if err := s.orders.Update(ctx, o); err != nil {
			return Order{}, err
		}
		return o, nil
	}

	o.Status = StatusIssuing
	if err := s.orders.Update(ctx, o); err != nil {
		return Order{}, err
	}

	signer, err := s.keys.Signer(ctx, o.KeyRef)
	if err != nil {
		return s.fail(ctx, o, fmt.Sprintf("load signing key: %v", err))
	}
	issued, err := authority.Issue(ctx, po, o.CSRPEM, o.Domains, signer)
	if err != nil {
		return s.fail(ctx, o, fmt.Sprintf("issue certificate: %v", err))
	}

	isRenewal := o.CertificateID != ""
	if isRenewal {
		if err := s.certs.UpdateAfterRenewal(ctx, o.CertificateID, issued.NotBefore, issued.NotAfter, issued.CAReference); err != nil {
			return s.fail(ctx, o, fmt.Sprintf("update renewed certificate: %v", err))
		}
	} else {
		cert, err := s.certs.Create(ctx, certificate.Certificate{
			CommonName:         o.Domains[0],
			SANs:               o.Domains,
			CAProvider:         o.CAProvider,
			ValidationMethod:   o.ValidationMethod,
			Status:             certificate.StatusActive,
			NotBefore:          issued.NotBefore,
			NotAfter:           issued.NotAfter,
			KeyAlgorithm:       o.KeyAlgorithm,
			KeyRef:             o.KeyRef,
			CAReference:        issued.CAReference,
			OwningTeam:         o.OwningTeam,
			AutoRenew:          true,
			RenewBeforeDays:    30,
			Organization:       o.Organization,
			OrganizationalUnit: o.OrganizationalUnit,
			Country:            o.Country,
			State:              o.State,
			Locality:           o.Locality,
		})
		if err != nil {
			return s.fail(ctx, o, fmt.Sprintf("store certificate: %v", err))
		}
		o.CertificateID = cert.ID
	}

	if _, err := s.certs.AddVersion(ctx, certificate.Version{
		CertificateID:     o.CertificateID,
		SerialNumber:      issued.SerialNumber,
		FingerprintSHA256: issued.FingerprintSHA256,
		PEMCert:           issued.PEMCert,
		PEMChain:          issued.PEMChain,
		IssuedAt:          issued.NotBefore,
	}); err != nil {
		return s.fail(ctx, o, fmt.Sprintf("store certificate version: %v", err))
	}

	now := time.Now()
	o.Status = StatusIssued
	o.CompletedAt = &now
	if err := s.orders.Update(ctx, o); err != nil {
		return Order{}, err
	}
	return o, nil
}

// buildSubject turns the optional, flat Country/Organization/
// OrganizationalUnit/State/Locality strings into the []string-per-field
// shape pkix.Name expects, omitting any field that's empty rather than
// encoding it as an empty RDN.
func buildSubject(country, organization, organizationalUnit, state, locality string) pkix.Name {
	var subject pkix.Name
	if country != "" {
		subject.Country = []string{country}
	}
	if organization != "" {
		subject.Organization = []string{organization}
	}
	if organizationalUnit != "" {
		subject.OrganizationalUnit = []string{organizationalUnit}
	}
	if state != "" {
		subject.Province = []string{state}
	}
	if locality != "" {
		subject.Locality = []string{locality}
	}
	return subject
}

func buildCSR(ctx context.Context, keys secrets.KeyManager, keyRef string, domains []string, subject pkix.Name) (string, error) {
	signer, err := keys.Signer(ctx, keyRef)
	if err != nil {
		return "", fmt.Errorf("load signer: %w", err)
	}

	subject.CommonName = domains[0]
	template := &x509.CertificateRequest{
		Subject:  subject,
		DNSNames: domains,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return "", fmt.Errorf("create CSR: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

func firstChallengeError(po ca.ProviderOrder) string {
	for _, c := range po.Challenges {
		if c.Error != "" {
			return c.Error
		}
	}
	return ""
}

func (s *Service) fail(ctx context.Context, o Order, reason string) (Order, error) {
	now := time.Now()
	o.Status = StatusFailed
	o.Error = reason
	o.CompletedAt = &now
	if err := s.orders.Update(ctx, o); err != nil {
		return Order{}, err
	}
	return o, nil
}
