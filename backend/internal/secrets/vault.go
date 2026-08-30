// Package secrets holds the private key of every certificate this platform
// manages. It never returns the key: every certificate's private key lives
// in Vault's Transit engine as a non-exportable key, and CSRs are produced
// by asking Vault to sign a digest remotely (see Signer), so the key
// material never exists in this process's memory, let alone in Postgres or
// on the wire to a browser.
package secrets

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"strconv"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
)

type KeyManager interface {
	// EnsureKey creates the named Transit key if it doesn't already exist.
	// Calling it again for an existing key (the renewal "reuse the existing
	// key" policy from docs/plan.html section 06) is a no-op, not an error.
	// exportable is fixed permanently at creation — Vault Transit itself
	// won't let it change afterward — and only matters the first time a
	// given name is created; a later EnsureKey call for the same name with
	// a different exportable value has no effect on the existing key.
	EnsureKey(ctx context.Context, name, algorithm string, exportable bool) error
	// Signer returns a crypto.Signer backed by the named Transit key. Every
	// Sign call is a network round trip to Vault; the private key never
	// leaves it.
	Signer(ctx context.Context, name string) (crypto.Signer, error)
}

type VaultKeyManager struct {
	client *vaultapi.Client
	mount  string
}

func NewVaultKeyManager(addr, token, mount string) (*VaultKeyManager, error) {
	cfg := vaultapi.DefaultConfig()
	cfg.Address = addr
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("vault: new client: %w", err)
	}
	client.SetToken(token)
	return &VaultKeyManager{client: client, mount: strings.Trim(mount, "/")}, nil
}

func transitKeyType(algorithm string) (string, error) {
	switch algorithm {
	case "RSA-2048":
		return "rsa-2048", nil
	case "RSA-4096":
		return "rsa-4096", nil
	case "ECDSA-P256":
		return "ecdsa-p256", nil
	default:
		return "", fmt.Errorf("vault: unsupported key algorithm %q", algorithm)
	}
}

func (v *VaultKeyManager) EnsureKey(ctx context.Context, name, algorithm string, exportable bool) error {
	keyType, err := transitKeyType(algorithm)
	if err != nil {
		return err
	}

	existing, err := v.client.Logical().ReadWithContext(ctx, fmt.Sprintf("%s/keys/%s", v.mount, name))
	if err != nil {
		return fmt.Errorf("vault: read key %q: %w", name, err)
	}
	if existing != nil {
		return nil
	}

	_, err = v.client.Logical().WriteWithContext(ctx, fmt.Sprintf("%s/keys/%s", v.mount, name), map[string]interface{}{
		"type": keyType,
		// allow_plaintext_backup matches exportable: a key permanently
		// marked exportable can go out to a Kubernetes Secret (see
		// internal/k8s), so there's no separate reason to keep its backup
		// endpoint locked while its export endpoint is open.
		"exportable":             exportable,
		"allow_plaintext_backup": exportable,
	})
	if err != nil {
		return fmt.Errorf("vault: create key %q: %w", name, err)
	}
	return nil
}

// latestVersionOf reads a Transit key's metadata and returns its
// latest_version as a string — shared by Signer (which needs it to find
// the current public key) and ExportPrivateKey (which needs it to export
// the matching private key).
func (v *VaultKeyManager) latestVersionOf(ctx context.Context, name string) (map[string]interface{}, string, error) {
	secret, err := v.client.Logical().ReadWithContext(ctx, fmt.Sprintf("%s/keys/%s", v.mount, name))
	if err != nil {
		return nil, "", fmt.Errorf("vault: read key %q: %w", name, err)
	}
	if secret == nil {
		return nil, "", fmt.Errorf("vault: key %q does not exist", name)
	}

	latestVersion, ok := secret.Data["latest_version"].(json.Number)
	var versionStr string
	if ok {
		versionStr = latestVersion.String()
	} else if f, ok := secret.Data["latest_version"].(float64); ok {
		versionStr = strconv.Itoa(int(f))
	} else {
		return nil, "", fmt.Errorf("vault: key %q missing latest_version", name)
	}
	return secret.Data, versionStr, nil
}

func (v *VaultKeyManager) Signer(ctx context.Context, name string) (crypto.Signer, error) {
	data, versionStr, err := v.latestVersionOf(ctx, name)
	if err != nil {
		return nil, err
	}

	keys, ok := data["keys"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("vault: key %q missing keys map", name)
	}
	versionData, ok := keys[versionStr].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("vault: key %q missing version %s", name, versionStr)
	}
	publicKeyPEM, ok := versionData["public_key"].(string)
	if !ok || publicKeyPEM == "" {
		return nil, fmt.Errorf("vault: key %q has no public key (is it asymmetric?)", name)
	}

	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("vault: key %q: could not PEM-decode public key", name)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("vault: key %q: parse public key: %w", name, err)
	}

	return &transitSigner{client: v.client, mount: v.mount, name: name, public: pub}, nil
}

// ExportPrivateKey returns the named Transit key's current-version private
// key as PEM. It only ever succeeds for a key created with exportable=true
// (see EnsureKey) — Vault itself refuses the export endpoint otherwise.
// Deliberately not part of the KeyManager interface every CA-issuance path
// depends on: this exists solely for internal/k8s to build a Kubernetes TLS
// Secret, which is the one place in this platform a private key is
// allowed to leave Vault at all.
func (v *VaultKeyManager) ExportPrivateKey(ctx context.Context, name string) ([]byte, error) {
	_, versionStr, err := v.latestVersionOf(ctx, name)
	if err != nil {
		return nil, err
	}

	secret, err := v.client.Logical().ReadWithContext(ctx, fmt.Sprintf("%s/export/signing-key/%s/%s", v.mount, name, versionStr))
	if err != nil {
		return nil, fmt.Errorf("vault: export key %q: %w", name, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("vault: export key %q: not found, or not created with exportable=true", name)
	}
	keys, ok := secret.Data["keys"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("vault: export key %q: missing keys map", name)
	}
	pemKey, ok := keys[versionStr].(string)
	if !ok || pemKey == "" {
		return nil, fmt.Errorf("vault: export key %q: missing version %s", name, versionStr)
	}
	return []byte(pemKey), nil
}

type transitSigner struct {
	client *vaultapi.Client
	mount  string
	name   string
	public crypto.PublicKey
}

func (s *transitSigner) Public() crypto.PublicKey { return s.public }

// Sign asks Vault to sign a digest that x509.CreateCertificateRequest (or
// any other crypto/x509 caller) has already hashed. The raw private key
// never appears in this process.
func (s *transitSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashAlg, err := vaultHashAlgorithm(opts.HashFunc())
	if err != nil {
		return nil, err
	}

	data := map[string]interface{}{
		"input":          base64.StdEncoding.EncodeToString(digest),
		"prehashed":      true,
		"hash_algorithm": hashAlg,
	}
	if _, isRSA := s.public.(*rsa.PublicKey); isRSA {
		if _, isPSS := opts.(*rsa.PSSOptions); isPSS {
			data["signature_algorithm"] = "pss"
		} else {
			data["signature_algorithm"] = "pkcs1v15"
		}
	}

	secret, err := s.client.Logical().Write(fmt.Sprintf("%s/sign/%s", s.mount, s.name), data)
	if err != nil {
		return nil, fmt.Errorf("vault: sign with key %q: %w", s.name, err)
	}
	sigField, ok := secret.Data["signature"].(string)
	if !ok {
		return nil, fmt.Errorf("vault: sign with key %q: no signature in response", s.name)
	}

	// Vault's transit signature format is "vault:v<version>:<base64>".
	parts := strings.SplitN(sigField, ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("vault: sign with key %q: unexpected signature format %q", s.name, sigField)
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("vault: sign with key %q: decode signature: %w", s.name, err)
	}
	return raw, nil
}

func vaultHashAlgorithm(h crypto.Hash) (string, error) {
	switch h {
	case crypto.SHA256:
		return "sha2-256", nil
	case crypto.SHA384:
		return "sha2-384", nil
	case crypto.SHA512:
		return "sha2-512", nil
	default:
		return "", fmt.Errorf("vault: unsupported hash function %v", h)
	}
}

var _ crypto.Signer = (*transitSigner)(nil)
