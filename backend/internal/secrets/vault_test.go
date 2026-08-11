package secrets

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"testing"
)

// These are integration tests against a real Vault dev server, not mocks —
// run `vault server -dev` and export VAULT_ADDR/VAULT_TEST_TOKEN before
// running them; they're skipped otherwise.
func testKeyManager(t *testing.T) *VaultKeyManager {
	addr := os.Getenv("VAULT_ADDR")
	token := os.Getenv("VAULT_TEST_TOKEN")
	if token == "" {
		token = os.Getenv("VAULT_TOKEN")
	}
	if addr == "" || token == "" {
		t.Skip("VAULT_ADDR / VAULT_TOKEN not set; skipping Vault integration test")
	}
	km, err := NewVaultKeyManager(addr, token, "transit")
	if err != nil {
		t.Fatalf("NewVaultKeyManager: %v", err)
	}
	return km
}

func TestVaultSignedCSR_RSA(t *testing.T) {
	km := testKeyManager(t)
	ctx := context.Background()

	keyName := "test-rsa-" + t.Name()
	if err := km.EnsureKey(ctx, keyName, "RSA-2048"); err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}
	// Calling it twice must be a no-op, not an error (renewal reuses keys).
	if err := km.EnsureKey(ctx, keyName, "RSA-2048"); err != nil {
		t.Fatalf("EnsureKey (idempotent call): %v", err)
	}

	signer, err := km.Signer(ctx, keyName)
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "app.example.test"},
		DNSNames: []string{"app.example.test"},
	}, signer)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature does not verify against its own public key: %v", err)
	}
	if csr.Subject.CommonName != "app.example.test" {
		t.Fatalf("unexpected CN: %s", csr.Subject.CommonName)
	}
}

func TestVaultSignedCSR_ECDSA(t *testing.T) {
	km := testKeyManager(t)
	ctx := context.Background()

	keyName := "test-ecdsa-" + t.Name()
	if err := km.EnsureKey(ctx, keyName, "ECDSA-P256"); err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}

	signer, err := km.Signer(ctx, keyName)
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "ecdsa.example.test"},
		DNSNames: []string{"ecdsa.example.test"},
	}, signer)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature does not verify against its own public key: %v", err)
	}
}
