package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

// testLeafCertPEM/testIssuerCertPEM are real, self-signed certificates
// generated once at test-binary init, used wherever a test needs to feed a
// mock CA response through actual PEM/x509 parsing rather than a
// hand-typed fixture that might not round-trip correctly.
var testLeafCertPEM, testIssuerCertPEM = generateTestCertPair()

func generateTestCertPair() (leafPEM, issuerPEM string) {
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Issuer CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		panic(err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "app.example.test"},
		DNSNames:     []string{"app.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	issuerCert, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		panic(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuerCert, &leafKey.PublicKey, issuerKey)
	if err != nil {
		panic(err)
	}

	leafPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	issuerPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerDER}))
	return leafPEM, issuerPEM
}
