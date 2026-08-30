package winrm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func mustSelfSignedPEM(t *testing.T, cn string, serial int64) (certPEM []byte, keyPEM []byte, cert *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, cert
}

func TestBuildPFX_RoundTrips(t *testing.T) {
	leafPEM, keyPEM, leaf := mustSelfSignedPEM(t, "host.example.test", 1)
	chainPEM, _, chainCert := mustSelfSignedPEM(t, "ca.example.test", 2)

	pfx, err := buildPFX(append(append([]byte{}, leafPEM...), chainPEM...), keyPEM, "test-password")
	if err != nil {
		t.Fatalf("buildPFX: %v", err)
	}

	gotKey, gotCert, gotChain, err := pkcs12.DecodeChain(pfx, "test-password")
	if err != nil {
		t.Fatalf("DecodeChain: %v", err)
	}
	if gotCert.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Errorf("expected the leaf certificate to round-trip, got serial %v want %v", gotCert.SerialNumber, leaf.SerialNumber)
	}
	if _, ok := gotKey.(*rsa.PrivateKey); !ok {
		t.Errorf("expected an RSA private key, got %T", gotKey)
	}
	if len(gotChain) != 1 || gotChain[0].SerialNumber.Cmp(chainCert.SerialNumber) != 0 {
		t.Errorf("expected the chain certificate to round-trip, got %v", gotChain)
	}
}

func TestBuildPFX_WrongPasswordFailsToDecode(t *testing.T) {
	leafPEM, keyPEM, _ := mustSelfSignedPEM(t, "host.example.test", 1)
	pfx, err := buildPFX(leafPEM, keyPEM, "right-password")
	if err != nil {
		t.Fatalf("buildPFX: %v", err)
	}
	if _, _, err := pkcs12.Decode(pfx, "wrong-password"); err == nil {
		t.Fatalf("expected decoding with the wrong password to fail")
	}
}

func TestBuildPFX_RejectsInvalidCertOrKey(t *testing.T) {
	_, keyPEM, _ := mustSelfSignedPEM(t, "host.example.test", 1)
	if _, err := buildPFX([]byte("not a cert"), keyPEM, "pw"); err == nil {
		t.Fatalf("expected an error for invalid certificate PEM")
	}

	certPEM, _, _ := mustSelfSignedPEM(t, "host.example.test", 1)
	if _, err := buildPFX(certPEM, []byte("not a key"), "pw"); err == nil {
		t.Fatalf("expected an error for invalid key PEM")
	}
}
