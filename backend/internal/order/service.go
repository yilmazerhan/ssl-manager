// Package order implements the certificate creation flow from
// docs/plan.html (section 05): an order moves from draft through
// awaiting_validation and issuing to issued, mirroring the wizard steps
// rather than trying to issue a certificate in one blocking call.
package order

import (
	"fmt"
	"sync"
	"time"

	"github.com/yilmazerhan/ssl-manager/backend/internal/ca"
	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
)

type Service struct {
	mu          sync.Mutex
	orders      map[string]*Order
	seq         int
	authorities map[string]ca.Authority
	certs       certificate.Store
}

func NewService(certs certificate.Store, authorities map[string]ca.Authority) *Service {
	return &Service{
		orders:      make(map[string]*Order),
		authorities: authorities,
		certs:       certs,
	}
}

func (s *Service) Create(req CreateRequest) (*Order, error) {
	authority, ok := s.authorities[req.CAProvider]
	if !ok {
		return nil, fmt.Errorf("unknown ca_provider %q", req.CAProvider)
	}
	if len(req.Domains) == 0 {
		return nil, fmt.Errorf("at least one domain is required")
	}

	challenge, err := authority.RequestValidation(req.Domains, req.ValidationMethod)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.seq++
	id := fmt.Sprintf("order_%04d", s.seq)
	o := &Order{
		ID:               id,
		RequestedBy:      req.RequestedBy,
		OwningTeam:       req.OwningTeam,
		Domains:          req.Domains,
		CAProvider:       req.CAProvider,
		ValidationMethod: req.ValidationMethod,
		Status:           StatusAwaitingValidation,
		Challenge: Challenge{
			Type:         challenge.Type,
			ResourceName: challenge.ResourceName,
			Value:        challenge.Value,
		},
		CreatedAt: time.Now(),
	}
	s.orders[id] = o
	s.mu.Unlock()

	return o, nil
}

func (s *Service) Get(id string) (*Order, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.orders[id]
	return o, ok
}

// Validate re-checks the domain-control challenge (step 5 of the wizard)
// and, once it passes, submits the CSR and stores the resulting
// certificate (steps 6-7).
func (s *Service) Validate(id string) (*Order, error) {
	s.mu.Lock()
	o, ok := s.orders[id]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("order %q not found", id)
	}
	if o.Status != StatusAwaitingValidation {
		return o, nil
	}

	authority := s.authorities[o.CAProvider]
	checked, err := authority.CheckChallenge(ca.Challenge{
		Type:         o.Challenge.Type,
		ResourceName: o.Challenge.ResourceName,
		Value:        o.Challenge.Value,
	})
	if err != nil || !checked.Verified {
		s.fail(o, "domain validation not yet observed by the CA")
		return o, nil
	}

	s.mu.Lock()
	o.Status = StatusIssuing
	o.Challenge.Verified = true
	s.mu.Unlock()

	issued, err := authority.Issue(csrPlaceholder(o.Domains), o.Domains)
	if err != nil {
		s.fail(o, err.Error())
		return o, nil
	}

	certID := fmt.Sprintf("cert_%s", o.ID)
	s.certs.Put(certificate.Certificate{
		ID:              certID,
		CommonName:      o.Domains[0],
		SANs:            o.Domains,
		CAProvider:      o.CAProvider,
		Status:          certificate.StatusActive,
		NotBefore:       issued.NotBefore,
		NotAfter:        issued.NotAfter,
		KeyAlgorithm:    "RSA-2048",
		OwningTeam:      o.OwningTeam,
		AutoRenew:       true,
		RenewBeforeDays: 30,
	})
	s.certs.AddVersion(certificate.Version{
		ID:                fmt.Sprintf("%s_v1", certID),
		CertificateID:     certID,
		SerialNumber:      issued.SerialNumber,
		FingerprintSHA256: issued.FingerprintSHA256,
		PEMCert:           issued.PEMCert,
		PEMChain:          issued.PEMChain,
		PrivateKeyRef:     fmt.Sprintf("vault:secret/ssl-manager/%s", certID),
		IssuedAt:          issued.NotBefore,
	})

	s.mu.Lock()
	o.Status = StatusIssued
	o.CertificateID = certID
	o.CompletedAt = time.Now()
	s.mu.Unlock()

	return o, nil
}

func (s *Service) fail(o *Order, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o.Status = StatusFailed
	o.Error = reason
	o.CompletedAt = time.Now()
}

func csrPlaceholder(domains []string) string {
	return fmt.Sprintf("-----BEGIN CERTIFICATE REQUEST-----\nCSR for %v\n-----END CERTIFICATE REQUEST-----\n", domains)
}
