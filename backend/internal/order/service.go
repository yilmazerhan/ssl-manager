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
	"time"

	"github.com/google/uuid"

	"github.com/yilmazerhan/ssl-manager/backend/internal/ca"
	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
	"github.com/yilmazerhan/ssl-manager/backend/internal/secrets"
)

type Service struct {
	orders      Store
	certs       certificate.Store
	keys        secrets.KeyManager
	authorities map[string]ca.Authority
}

func NewService(orders Store, certs certificate.Store, keys secrets.KeyManager, authorities map[string]ca.Authority) *Service {
	return &Service{orders: orders, certs: certs, keys: keys, authorities: authorities}
}

func (s *Service) Create(ctx context.Context, req CreateRequest) (Order, error) {
	authority, ok := s.authorities[req.CAProvider]
	if !ok {
		return Order{}, fmt.Errorf("unknown ca_provider %q", req.CAProvider)
	}
	if len(req.Domains) == 0 {
		return Order{}, fmt.Errorf("at least one domain is required")
	}
	if req.KeyAlgorithm == "" {
		req.KeyAlgorithm = "RSA-2048"
	}

	keyRef := "order-" + uuid.NewString()
	if err := s.keys.EnsureKey(ctx, keyRef, req.KeyAlgorithm); err != nil {
		return Order{}, fmt.Errorf("provision key: %w", err)
	}

	csrPEM, err := buildCSR(ctx, s.keys, keyRef, req.Domains)
	if err != nil {
		return Order{}, fmt.Errorf("build CSR: %w", err)
	}

	po, err := authority.RequestValidation(ctx, req.Domains, req.ValidationMethod, csrPEM)
	if err != nil {
		return Order{}, fmt.Errorf("request validation: %w", err)
	}

	return s.orders.Create(ctx, Order{
		RequestedBy:      req.RequestedBy,
		OwningTeam:       req.OwningTeam,
		Domains:          req.Domains,
		CAProvider:       req.CAProvider,
		ValidationMethod: req.ValidationMethod,
		KeyAlgorithm:     req.KeyAlgorithm,
		Status:           StatusAwaitingValidation,
		Challenges:       po,
		KeyRef:           keyRef,
		CSRPEM:           csrPEM,
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
	authority, ok := s.authorities[cert.CAProvider]
	if !ok {
		return Order{}, fmt.Errorf("unknown ca_provider %q", cert.CAProvider)
	}

	csrPEM, err := buildCSR(ctx, s.keys, cert.KeyRef, cert.SANs)
	if err != nil {
		return Order{}, fmt.Errorf("build CSR: %w", err)
	}

	po, err := authority.RequestValidation(ctx, cert.SANs, cert.ValidationMethod, csrPEM)
	if err != nil {
		return Order{}, fmt.Errorf("request validation: %w", err)
	}

	return s.orders.Create(ctx, Order{
		RequestedBy:      requestedBy,
		OwningTeam:       cert.OwningTeam,
		Domains:          cert.SANs,
		CAProvider:       cert.CAProvider,
		ValidationMethod: cert.ValidationMethod,
		KeyAlgorithm:     cert.KeyAlgorithm,
		Status:           StatusAwaitingValidation,
		Challenges:       po,
		KeyRef:           cert.KeyRef,
		CSRPEM:           csrPEM,
		CertificateID:    cert.ID,
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

	authority := s.authorities[o.CAProvider]
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

	issued, err := authority.Issue(ctx, po, o.CSRPEM, o.Domains)
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
			CommonName:       o.Domains[0],
			SANs:             o.Domains,
			CAProvider:       o.CAProvider,
			ValidationMethod: o.ValidationMethod,
			Status:           certificate.StatusActive,
			NotBefore:        issued.NotBefore,
			NotAfter:         issued.NotAfter,
			KeyAlgorithm:     o.KeyAlgorithm,
			KeyRef:           o.KeyRef,
			CAReference:      issued.CAReference,
			OwningTeam:       o.OwningTeam,
			AutoRenew:        true,
			RenewBeforeDays:  30,
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

func buildCSR(ctx context.Context, keys secrets.KeyManager, keyRef string, domains []string) (string, error) {
	signer, err := keys.Signer(ctx, keyRef)
	if err != nil {
		return "", fmt.Errorf("load signer: %w", err)
	}

	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
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
