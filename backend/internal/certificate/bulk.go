package certificate

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ImportFromPEM turns an already-issued certificate (uploaded, not created
// through this platform's own CA integrations) into a Certificate+Version
// pair ready to store. It's tracked as ca_provider "manual" with
// auto_renew false: with no CA account behind it, this platform has
// nothing to renew it through — attempting to would fail the same way
// requesting any other unregistered ca_provider does.
//
// key_ref is still populated (the column is NOT NULL) but names no real
// Vault Transit key — an imported certificate's private key was never
// handled by this platform and never will be; nothing here ever calls
// Signer(ctx, this key_ref).
func ImportFromPEM(pemCert, pemChain, owningTeam string) (Certificate, Version, error) {
	if owningTeam == "" {
		return Certificate{}, Version{}, fmt.Errorf("owning_team is required")
	}

	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return Certificate{}, Version{}, fmt.Errorf("no PEM block found in pem_cert")
	}
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Certificate{}, Version{}, fmt.Errorf("parse certificate: %w", err)
	}

	commonName := x509Cert.Subject.CommonName
	if commonName == "" && len(x509Cert.DNSNames) > 0 {
		commonName = x509Cert.DNSNames[0]
	}
	if commonName == "" {
		return Certificate{}, Version{}, fmt.Errorf("certificate has neither a Subject CommonName nor any SAN to use as one")
	}

	status := StatusActive
	if time.Now().After(x509Cert.NotAfter) {
		status = StatusExpired
	}

	sum := sha256.Sum256(x509Cert.Raw)
	cert := Certificate{
		CommonName:       commonName,
		SANs:             x509Cert.DNSNames,
		CAProvider:       "manual",
		ValidationMethod: "manual",
		Status:           status,
		NotBefore:        x509Cert.NotBefore,
		NotAfter:         x509Cert.NotAfter,
		KeyAlgorithm:     describeKeyAlgorithm(x509Cert.PublicKey),
		KeyRef:           "imported-" + uuid.NewString(),
		OwningTeam:       owningTeam,
		AutoRenew:        false,
	}
	version := Version{
		SerialNumber:      x509Cert.SerialNumber.String(),
		FingerprintSHA256: hex.EncodeToString(sum[:]),
		PEMCert:           pemCert,
		PEMChain:          pemChain,
		IssuedAt:          x509Cert.NotBefore,
	}
	return cert, version, nil
}

func describeKeyAlgorithm(pub interface{}) string {
	switch p := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", p.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA-" + p.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return "unknown"
	}
}
