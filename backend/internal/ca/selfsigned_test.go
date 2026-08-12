package ca

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

// SelfSigned needs no external server and no Vault — it signs locally with
// whatever crypto.Signer Issue is handed — so this is a fast, fully live
// test of the real code path rather than a mock.
func TestSelfSigned_FullFlow(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	domain := "internal.example.test"
	csrPEM := mustBuildCSR(t, key, domain)

	s := NewSelfSigned(30 * 24 * time.Hour)
	ctx := context.Background()

	po, err := s.RequestValidation(ctx, []string{domain}, "none", csrPEM)
	if err != nil {
		t.Fatalf("RequestValidation: %v", err)
	}
	if !po.AllVerified() {
		t.Fatalf("expected a self-signed order to be verified immediately, got %+v", po.Challenges)
	}

	po, err = s.CheckChallenge(ctx, po)
	if err != nil {
		t.Fatalf("CheckChallenge: %v", err)
	}
	if !po.AllVerified() {
		t.Fatalf("expected CheckChallenge to leave the order verified")
	}

	issued, err := s.Issue(ctx, po, csrPEM, []string{domain}, key)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if issued.SerialNumber == "" {
		t.Errorf("expected a serial number")
	}
	if issued.FingerprintSHA256 == "" {
		t.Errorf("expected a fingerprint")
	}

	block, _ := pem.Decode([]byte(issued.PEMCert))
	if block == nil {
		t.Fatalf("issued certificate did not PEM-decode")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != domain {
		t.Errorf("unexpected SANs: %v", leaf.DNSNames)
	}

	// A self-signed certificate is its own trust anchor: it must verify
	// against a pool containing only itself.
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Errorf("issued certificate does not verify against itself: %v", err)
	}

	if err := s.Revoke(ctx, issued.PEMCert, ""); err != nil {
		t.Errorf("Revoke: expected no error, got %v", err)
	}
}

func TestSelfSigned_Issue_RequiresSigner(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrPEM := mustBuildCSR(t, key, "no-signer.example.test")

	s := NewSelfSigned(0)
	_, err = s.Issue(context.Background(), ProviderOrder{}, csrPEM, []string{"no-signer.example.test"}, nil)
	if err == nil {
		t.Fatal("expected an error when no signer is available")
	}
}

func TestSelfSigned_RequestValidation_RejectsUnsupportedMethod(t *testing.T) {
	s := NewSelfSigned(0)
	_, err := s.RequestValidation(context.Background(), []string{"x.example.test"}, "http-01", "")
	if err == nil {
		t.Fatal("expected an error for a non-'none' validation method")
	}
}
