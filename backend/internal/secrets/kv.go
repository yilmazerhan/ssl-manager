package secrets

import (
	"context"
	"fmt"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
)

// SecretStore is plain Vault KV v2 storage, for secrets the plan calls out
// by name in section 09: ACME account keys and CA API credentials. These
// are operational secrets the backend legitimately needs to read into
// memory to do its job (sign an ACME JWS, call ZeroSSL) — unlike customer
// certificate private keys, which never leave Vault at all (see KeyManager).
type SecretStore interface {
	Put(ctx context.Context, path string, data map[string]interface{}) error
	Get(ctx context.Context, path string) (map[string]interface{}, error)
}

type VaultSecretStore struct {
	client *vaultapi.Client
	mount  string
}

func NewVaultSecretStore(addr, token, mount string) (*VaultSecretStore, error) {
	cfg := vaultapi.DefaultConfig()
	cfg.Address = addr
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("vault: new client: %w", err)
	}
	client.SetToken(token)
	return &VaultSecretStore{client: client, mount: strings.Trim(mount, "/")}, nil
}

func (v *VaultSecretStore) Put(ctx context.Context, path string, data map[string]interface{}) error {
	_, err := v.client.Logical().WriteWithContext(ctx, fmt.Sprintf("%s/data/%s", v.mount, path), map[string]interface{}{
		"data": data,
	})
	if err != nil {
		return fmt.Errorf("vault: put secret %q: %w", path, err)
	}
	return nil
}

// Get returns (nil, nil) — not an error — when the path has no secret yet,
// so callers can distinguish "not created" from a real Vault failure.
func (v *VaultSecretStore) Get(ctx context.Context, path string) (map[string]interface{}, error) {
	secret, err := v.client.Logical().ReadWithContext(ctx, fmt.Sprintf("%s/data/%s", v.mount, path))
	if err != nil {
		return nil, fmt.Errorf("vault: get secret %q: %w", path, err)
	}
	if secret == nil {
		return nil, nil
	}
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, nil
	}
	return data, nil
}
