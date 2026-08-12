package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// SelfSigned issues a certificate signed by its own key instead of by any
// external authority — there is no domain-control validation and no CA
// round trip, so it exists for internal/dev/test endpoints where nothing
// outside this platform needs to trust the result. It's also the one
// Authority that actually needs the signer Issue is handed: every other
// provider gets a certificate back from a CA and never touches the private
// key itself, but a self-signed leaf has to be signed by the same
// Vault-backed key its CSR carries the public half of.
type SelfSigned struct {
	validityPeriod time.Duration
}

func NewSelfSigned(validityPeriod time.Duration) *SelfSigned {
	if validityPeriod <= 0 {
		validityPeriod = 365 * 24 * time.Hour
	}
	return &SelfSigned{validityPeriod: validityPeriod}
}

func (s *SelfSigned) Name() string { return "selfsigned" }

func (s *SelfSigned) SupportedValidationMethods() []string { return []string{"none"} }

// RequestValidation returns a single, already-verified challenge — a
// self-signed certificate has no domain-control step for anyone to
// satisfy, but ProviderOrder.AllVerified() treats zero challenges as
// unverified, so the order flow needs one to see issuance as ready to go.
func (s *SelfSigned) RequestValidation(_ context.Context, domains []string, method, _ string) (ProviderOrder, error) {
	if method != "none" {
		return ProviderOrder{}, fmt.Errorf("selfsigned: unsupported validation method %q", method)
	}
	if len(domains) == 0 {
		return ProviderOrder{}, fmt.Errorf("selfsigned: at least one domain is required")
	}
	return ProviderOrder{Challenges: []Challenge{{
		Domain: domains[0], Type: method, Verified: true, Automated: true,
	}}}, nil
}

func (s *SelfSigned) CheckChallenge(_ context.Context, po ProviderOrder) (ProviderOrder, error) {
	return po, nil
}

func (s *SelfSigned) Issue(_ context.Context, _ ProviderOrder, csrPEM string, domains []string, signer crypto.Signer) (IssuedCertificate, error) {
	if signer == nil {
		return IssuedCertificate{}, fmt.Errorf("selfsigned: no signing key available")
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return IssuedCertificate{}, fmt.Errorf("selfsigned: could not PEM-decode CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("selfsigned: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return IssuedCertificate{}, fmt.Errorf("selfsigned: CSR signature invalid: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("selfsigned: generate serial: %w", err)
	}

	subject := csr.Subject
	if subject.CommonName == "" {
		subject.CommonName = domains[0]
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		DNSNames:              domains,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(s.validityPeriod),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Self-signed: issuer and subject are the same certificate, signed by
	// the same key whose public half the CSR carries.
	der, err := x509.CreateCertificate(rand.Reader, template, template, csr.PublicKey, signer)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("selfsigned: create certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("selfsigned: parse issued certificate: %w", err)
	}

	fingerprint := sha256.Sum256(der)
	return IssuedCertificate{
		PEMCert:           string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		SerialNumber:      leaf.SerialNumber.String(),
		FingerprintSHA256: hex.EncodeToString(fingerprint[:]),
		NotBefore:         leaf.NotBefore,
		NotAfter:          leaf.NotAfter,
	}, nil
}

// Revoke is a no-op that succeeds: unlike ADCS or a real external CA,
// there is no other party whose trust in this certificate needs revoking —
// the certificate's only trust anchor is itself, so marking it revoked in
// this system's own records (which the API handler does right after
// calling Revoke) is the complete action, not a partial one.
func (s *SelfSigned) Revoke(_ context.Context, _, _ string) error {
	return nil
}
