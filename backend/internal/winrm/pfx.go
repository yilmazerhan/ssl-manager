package winrm

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"software.sslmate.com/src/go-pkcs12"
)

// buildPFX bundles certPEM (leaf, optionally followed by chain) and keyPEM
// into a password-protected PKCS#12 file a Windows host can import with
// Import-PfxCertificate. It uses pkcs12.Encode's default (RC2/3DES)
// encryption rather than a more modern AES-based one — the whole point
// here is compatibility with Import-PfxCertificate across whatever
// Windows Server version a target host happens to be running, including
// older ones that don't understand a newer PFX encryption scheme.
func buildPFX(certPEM, keyPEM []byte, password string) ([]byte, error) {
	block, rest := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("winrm: no PEM block found in certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("winrm: parse certificate: %w", err)
	}

	var chain []*x509.Certificate
	for {
		var caBlock *pem.Block
		caBlock, rest = pem.Decode(rest)
		if caBlock == nil {
			break
		}
		ca, err := x509.ParseCertificate(caBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("winrm: parse chain certificate: %w", err)
		}
		chain = append(chain, ca)
	}

	key, err := parsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}

	pfx, err := pkcs12.Encode(rand.Reader, key, leaf, chain, password)
	if err != nil {
		return nil, fmt.Errorf("winrm: encode PKCS#12: %w", err)
	}
	return pfx, nil
}

// parsePrivateKeyPEM accepts whatever PEM shape a private key export comes
// back as — PKCS#8 ("PRIVATE KEY", what Vault Transit's export endpoint
// uses) or, defensively, the older algorithm-specific PKCS#1/SEC1 forms.
func parsePrivateKeyPEM(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("winrm: no PEM block found in private key")
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("winrm: PKCS#8 key is not a signing key")
		}
		return signer, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("winrm: could not parse private key (tried PKCS#8, PKCS#1, SEC1)")
}
