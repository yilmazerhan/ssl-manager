package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/yilmazerhan/ssl-manager/backend/internal/caaccount"
	"github.com/yilmazerhan/ssl-manager/backend/internal/secrets"
)

// LetsEncryptConfig configures one ACME v2 account/environment (matching a
// row in ca_account). InsecureSkipVerify exists only to talk to a local
// Pebble test server whose TLS chain isn't otherwise trusted — it must
// never be set true against a real CA.
type LetsEncryptConfig struct {
	Environment        string
	DirectoryURL       string
	ContactEmail       string
	InsecureSkipVerify bool
	HTTPTimeout        time.Duration
}

type LetsEncrypt struct {
	core *api.Core
	cfg  LetsEncryptConfig
}

// NewLetsEncrypt loads (or, on first use, generates and registers) the ACME
// account for cfg.Environment. The account's private key is stored in
// Vault as a plain secret (per docs/plan.html section 09); it is not the
// Transit-backed, never-exported kind used for customer certificates,
// because ACME account keys sign frequent local JWS requests rather than
// occasional remote CSR signatures.
func NewLetsEncrypt(ctx context.Context, cfg LetsEncryptConfig, secretStore secrets.SecretStore, accounts caaccount.Store) (*LetsEncrypt, error) {
	accountKey, err := loadOrCreateAccountKey(ctx, secretStore, cfg.Environment)
	if err != nil {
		return nil, fmt.Errorf("letsencrypt[%s]: account key: %w", cfg.Environment, err)
	}

	httpClient := &http.Client{Timeout: cfg.HTTPTimeout}
	if httpClient.Timeout == 0 {
		httpClient.Timeout = 30 * time.Second
	}
	if cfg.InsecureSkipVerify {
		httpClient.Transport = insecureTransport()
	}

	kid := ""
	existing, err := accounts.Get(ctx, "letsencrypt", cfg.Environment)
	if err == nil {
		kid = existing.AccountRef
	} else if err != caaccount.ErrNotFound {
		return nil, fmt.Errorf("letsencrypt[%s]: load account: %w", cfg.Environment, err)
	}

	core, err := api.New(httpClient, "ssl-manager", cfg.DirectoryURL, kid, accountKey)
	if err != nil {
		return nil, fmt.Errorf("letsencrypt[%s]: new ACME client: %w", cfg.Environment, err)
	}

	if kid == "" {
		account, err := core.Accounts.New(acme.Account{
			Contact:              []string{"mailto:" + cfg.ContactEmail},
			TermsOfServiceAgreed: true,
		})
		if err != nil {
			return nil, fmt.Errorf("letsencrypt[%s]: register account: %w", cfg.Environment, err)
		}
		if err := accounts.Upsert(ctx, caaccount.Account{
			Provider:     "letsencrypt",
			Environment:  cfg.Environment,
			AccountRef:   account.Location,
			DirectoryURL: cfg.DirectoryURL,
		}); err != nil {
			return nil, fmt.Errorf("letsencrypt[%s]: persist account: %w", cfg.Environment, err)
		}
	}

	return &LetsEncrypt{core: core, cfg: cfg}, nil
}

func (l *LetsEncrypt) Name() string { return "letsencrypt" }

func (l *LetsEncrypt) SupportedValidationMethods() []string {
	return []string{"http-01", "dns-01"}
}

type leAuthzState struct {
	Domain       string `json:"domain"`
	AuthzURL     string `json:"authz_url"`
	ChallengeURL string `json:"challenge_url"`
	Token        string `json:"token"`
	Triggered    bool   `json:"triggered"`
}

type leState struct {
	OrderURL    string         `json:"order_url"`
	FinalizeURL string         `json:"finalize_url"`
	Authz       []leAuthzState `json:"authz"`
}

func (l *LetsEncrypt) RequestValidation(ctx context.Context, domains []string, method, _ string) (ProviderOrder, error) {
	acmeType, err := acmeChallengeType(method)
	if err != nil {
		return ProviderOrder{}, err
	}

	order, err := l.core.Orders.New(domains)
	if err != nil {
		return ProviderOrder{}, fmt.Errorf("letsencrypt: create order: %w", err)
	}

	state := leState{OrderURL: order.Location, FinalizeURL: order.Finalize}
	challenges := make([]Challenge, 0, len(domains))

	for _, authzURL := range order.Authorizations {
		authz, err := l.core.Authorizations.Get(authzURL)
		if err != nil {
			return ProviderOrder{}, fmt.Errorf("letsencrypt: get authorization: %w", err)
		}

		acmeChallenge, err := findChallenge(authz.Challenges, acmeType)
		if err != nil {
			return ProviderOrder{}, err
		}

		keyAuth, err := l.core.GetKeyAuthorization(acmeChallenge.Token)
		if err != nil {
			return ProviderOrder{}, fmt.Errorf("letsencrypt: key authorization: %w", err)
		}

		domain := authz.Identifier.Value
		var resourceName, value string
		switch method {
		case "http-01":
			resourceName = fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", domain, acmeChallenge.Token)
			value = keyAuth
		case "dns-01":
			fqdn, val := dns01.GetRecord(domain, keyAuth)
			resourceName, value = fqdn, val
		}

		challenges = append(challenges, Challenge{
			Domain:       domain,
			Type:         method,
			ResourceName: resourceName,
			Value:        value,
		})
		state.Authz = append(state.Authz, leAuthzState{
			Domain:       domain,
			AuthzURL:     authzURL,
			ChallengeURL: acmeChallenge.URL,
			Token:        acmeChallenge.Token,
		})
	}

	stateJSON, err := json.Marshal(state)
	if err != nil {
		return ProviderOrder{}, fmt.Errorf("letsencrypt: marshal state: %w", err)
	}
	return ProviderOrder{Challenges: challenges, State: string(stateJSON)}, nil
}

func (l *LetsEncrypt) CheckChallenge(_ context.Context, po ProviderOrder) (ProviderOrder, error) {
	var state leState
	if err := json.Unmarshal([]byte(po.State), &state); err != nil {
		return po, fmt.Errorf("letsencrypt: unmarshal state: %w", err)
	}

	for i := range po.Challenges {
		if po.Challenges[i].Verified {
			continue
		}
		as := &state.Authz[i]

		if !as.Triggered {
			if _, err := l.core.Challenges.New(as.ChallengeURL); err != nil {
				return po, fmt.Errorf("letsencrypt: trigger validation for %s: %w", as.Domain, err)
			}
			as.Triggered = true
		}

		authz, err := pollAuthorization(l.core, as.AuthzURL)
		if err != nil {
			return po, fmt.Errorf("letsencrypt: check authorization for %s: %w", as.Domain, err)
		}

		switch authz.Status {
		case "valid":
			po.Challenges[i].Verified = true
		case "invalid":
			po.Challenges[i].Error = challengeError(authz.Challenges)
		}
	}

	stateJSON, err := json.Marshal(state)
	if err != nil {
		return po, fmt.Errorf("letsencrypt: marshal state: %w", err)
	}
	po.State = string(stateJSON)
	return po, nil
}

func (l *LetsEncrypt) Issue(_ context.Context, po ProviderOrder, csrPEM string, domains []string) (IssuedCertificate, error) {
	var state leState
	if err := json.Unmarshal([]byte(po.State), &state); err != nil {
		return IssuedCertificate{}, fmt.Errorf("letsencrypt: unmarshal state: %w", err)
	}

	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return IssuedCertificate{}, fmt.Errorf("letsencrypt: could not PEM-decode CSR")
	}

	if _, err := l.core.Orders.UpdateForCSR(state.FinalizeURL, block.Bytes); err != nil {
		return IssuedCertificate{}, fmt.Errorf("letsencrypt: finalize order: %w", err)
	}

	finalOrder, err := pollOrder(l.core, state.OrderURL)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("letsencrypt: poll order: %w", err)
	}
	if finalOrder.Status != "valid" {
		return IssuedCertificate{}, fmt.Errorf("letsencrypt: order ended in status %q", finalOrder.Status)
	}

	certPEM, chainPEM, err := l.core.Certificates.Get(finalOrder.Certificate, false)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("letsencrypt: download certificate: %w", err)
	}

	leafBlock, _ := pem.Decode(certPEM)
	if leafBlock == nil {
		return IssuedCertificate{}, fmt.Errorf("letsencrypt: could not PEM-decode issued certificate")
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("letsencrypt: parse issued certificate: %w", err)
	}

	return IssuedCertificate{
		PEMCert:           string(certPEM),
		PEMChain:          string(chainPEM),
		SerialNumber:      leaf.SerialNumber.String(),
		FingerprintSHA256: Fingerprint(leaf.Raw),
		NotBefore:         leaf.NotBefore,
		NotAfter:          leaf.NotAfter,
	}, nil
}

func acmeChallengeType(method string) (string, error) {
	switch method {
	case "http-01":
		return "http-01", nil
	case "dns-01":
		return "dns-01", nil
	default:
		return "", fmt.Errorf("letsencrypt: unsupported validation method %q", method)
	}
}

func findChallenge(challenges []acme.Challenge, acmeType string) (acme.Challenge, error) {
	for _, c := range challenges {
		if c.Type == acmeType {
			return c, nil
		}
	}
	return acme.Challenge{}, fmt.Errorf("letsencrypt: no %s challenge offered by the CA", acmeType)
}

func challengeError(challenges []acme.Challenge) string {
	for _, c := range challenges {
		if c.Error != nil {
			return c.Error.Detail
		}
	}
	return "validation failed"
}

// pollAuthorization gives an in-flight "processing" validation a brief
// window to settle before we report status back, since Present-then-check
// with zero delay routinely races a real CA's validator.
func pollAuthorization(core *api.Core, authzURL string) (acme.Authorization, error) {
	var authz acme.Authorization
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		authz, err = core.Authorizations.Get(authzURL)
		if err != nil {
			return acme.Authorization{}, err
		}
		if authz.Status != "pending" && authz.Status != "processing" {
			return authz, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return authz, nil
}

func pollOrder(core *api.Core, orderURL string) (acme.ExtendedOrder, error) {
	var order acme.ExtendedOrder
	var err error
	for attempt := 0; attempt < 10; attempt++ {
		order, err = core.Orders.Get(orderURL)
		if err != nil {
			return acme.ExtendedOrder{}, err
		}
		if order.Status != "processing" && order.Status != "pending" {
			return order, nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return order, nil
}

func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

const accountKeySecretPathPrefix = "acme-account/letsencrypt/"

func loadOrCreateAccountKey(ctx context.Context, store secrets.SecretStore, environment string) (crypto.Signer, error) {
	path := accountKeySecretPathPrefix + environment

	data, err := store.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if data != nil {
		pemStr, ok := data["private_key"].(string)
		if !ok {
			return nil, fmt.Errorf("stored account key at %q is malformed", path)
		}
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			return nil, fmt.Errorf("stored account key at %q could not be PEM-decoded", path)
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("stored account key at %q could not be parsed: %w", path, err)
		}
		return key, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate account key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal account key: %w", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))

	if err := store.Put(ctx, path, map[string]interface{}{"private_key": pemStr}); err != nil {
		return nil, fmt.Errorf("store account key: %w", err)
	}
	return key, nil
}
