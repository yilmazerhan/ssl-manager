package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func mustSelfSignedPEM(t *testing.T, key interface{ Public() interface{} }, priv interface{}, cn string, sans []string, notAfter time.Time) string {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     sans,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// rsaKey/ecdsaKey wrap the standard library's key types just enough to
// satisfy mustSelfSignedPEM's tiny local interface without pulling in a
// bigger fake — Public() -> interface{} on each, mirroring crypto.Signer.
type rsaKey struct{ *rsa.PrivateKey }

func (k rsaKey) Public() interface{} { return &k.PublicKey }

type ecdsaKey struct{ *ecdsa.PrivateKey }

func (k ecdsaKey) Public() interface{} { return &k.PublicKey }

func TestImportFromPEM_RSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pemCert := mustSelfSignedPEM(t, rsaKey{priv}, priv, "imported.example.test", []string{"imported.example.test", "alt.example.test"}, time.Now().Add(365*24*time.Hour))

	cert, version, err := ImportFromPEM(pemCert, "", "platform-team")
	if err != nil {
		t.Fatalf("ImportFromPEM: %v", err)
	}
	if cert.CommonName != "imported.example.test" {
		t.Errorf("unexpected common name: %q", cert.CommonName)
	}
	if len(cert.SANs) != 2 {
		t.Errorf("expected 2 SANs, got %v", cert.SANs)
	}
	if cert.CAProvider != "manual" {
		t.Errorf("expected ca_provider manual, got %q", cert.CAProvider)
	}
	if cert.AutoRenew {
		t.Errorf("expected an imported certificate to default to auto_renew=false")
	}
	if cert.Status != StatusActive {
		t.Errorf("expected status active for a not-yet-expired cert, got %q", cert.Status)
	}
	if cert.KeyAlgorithm != "RSA-2048" {
		t.Errorf("expected KeyAlgorithm RSA-2048, got %q", cert.KeyAlgorithm)
	}
	if cert.KeyRef == "" {
		t.Errorf("expected a non-empty key_ref placeholder")
	}
	if version.PEMCert != pemCert {
		t.Errorf("expected the version to carry the original PEM through unchanged")
	}
	if version.FingerprintSHA256 == "" || version.SerialNumber == "" {
		t.Errorf("expected fingerprint and serial to be populated")
	}
}

func TestImportFromPEM_ECDSAAndExpired(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pemCert := mustSelfSignedPEM(t, ecdsaKey{priv}, priv, "expired.example.test", nil, time.Now().Add(-time.Hour))

	cert, _, err := ImportFromPEM(pemCert, "", "platform-team")
	if err != nil {
		t.Fatalf("ImportFromPEM: %v", err)
	}
	if cert.KeyAlgorithm != "ECDSA-P-256" {
		t.Errorf("expected KeyAlgorithm ECDSA-P-256, got %q", cert.KeyAlgorithm)
	}
	if cert.Status != StatusExpired {
		t.Errorf("expected status expired for a cert whose not_after has passed, got %q", cert.Status)
	}
}

func TestImportFromPEM_FallsBackToFirstSANWhenNoCommonName(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pemCert := mustSelfSignedPEM(t, rsaKey{priv}, priv, "", []string{"san-only.example.test"}, time.Now().Add(time.Hour))

	cert, _, err := ImportFromPEM(pemCert, "", "platform-team")
	if err != nil {
		t.Fatalf("ImportFromPEM: %v", err)
	}
	if cert.CommonName != "san-only.example.test" {
		t.Errorf("expected the first SAN to be used as common name, got %q", cert.CommonName)
	}
}

func TestImportFromPEM_RejectsMissingOwningTeam(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pemCert := mustSelfSignedPEM(t, rsaKey{priv}, priv, "cn.example.test", nil, time.Now().Add(time.Hour))

	if _, _, err := ImportFromPEM(pemCert, "", ""); err == nil {
		t.Fatalf("expected an error when owning_team is empty")
	}
}

func TestImportFromPEM_RejectsInvalidPEM(t *testing.T) {
	if _, _, err := ImportFromPEM("not a pem", "", "team"); err == nil {
		t.Fatalf("expected an error for invalid PEM input")
	}
}

func TestImportFromPEM_RejectsNoCommonNameOrSAN(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pemCert := mustSelfSignedPEM(t, rsaKey{priv}, priv, "", nil, time.Now().Add(time.Hour))

	if _, _, err := ImportFromPEM(pemCert, "", "team"); err == nil {
		t.Fatalf("expected an error when the cert has neither a common name nor any SAN")
	}
}
