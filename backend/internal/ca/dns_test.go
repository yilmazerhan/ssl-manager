package ca

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/go-acme/lego/v4/challenge/dns01"

	"github.com/yilmazerhan/ssl-manager/backend/internal/secrets"
)

// challtestsrvDNSProvider drives Pebble's own test DNS server
// (pebble-challtestsrv) through its management API, so
// TestLetsEncrypt_FullFlow_DNS01_Automated exercises the exact same
// Present/CleanUp contract a real provider (Cloudflare, Route53, ...)
// would — this proves the automation path itself, independent of which
// concrete provider is configured in production.
type challtestsrvDNSProvider struct {
	managementURL string
}

func (p *challtestsrvDNSProvider) Present(domain, _, keyAuth string) error {
	fqdn, value := dns01.GetRecord(domain, keyAuth)
	return p.call("/set-txt", map[string]string{"host": fqdn, "value": value})
}

func (p *challtestsrvDNSProvider) CleanUp(domain, _, keyAuth string) error {
	fqdn, _ := dns01.GetRecord(domain, keyAuth)
	return p.call("/clear-txt", map[string]string{"host": fqdn})
}

func (p *challtestsrvDNSProvider) call(path string, body map[string]string) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := http.Post(p.managementURL+path, "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("challtestsrv %s: unexpected status %d", path, resp.StatusCode)
	}
	return nil
}

// This is a real end-to-end test of automated DNS-01: Pebble is pointed at
// pebble-challtestsrv's mock DNS server (see README for how to run both),
// and DNSAutomation publishes/removes the TXT record through
// pebble-challtestsrv's management API exactly as it would through a real
// provider's API — no step of the automation is faked.
func TestLetsEncrypt_FullFlow_DNS01_Automated(t *testing.T) {
	directoryURL := os.Getenv("ACME_TEST_DIRECTORY_URL")
	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultToken := os.Getenv("VAULT_TOKEN")
	challtestsrvURL := os.Getenv("CHALLTESTSRV_MANAGEMENT_URL")
	if directoryURL == "" || vaultAddr == "" || vaultToken == "" || challtestsrvURL == "" {
		t.Skip("ACME_TEST_DIRECTORY_URL / VAULT_ADDR / VAULT_TOKEN / CHALLTESTSRV_MANAGEMENT_URL not set; skipping DNS-01 automation integration test")
	}

	ctx := context.Background()
	km, err := secrets.NewVaultKeyManager(vaultAddr, vaultToken, "transit")
	if err != nil {
		t.Fatalf("NewVaultKeyManager: %v", err)
	}

	keyName := "test-le-dns01-" + t.Name()
	if err := km.EnsureKey(ctx, keyName, "RSA-2048"); err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}
	signer, err := km.Signer(ctx, keyName)
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}

	dnsAddr := os.Getenv("CHALLTESTSRV_DNS_ADDR")
	if dnsAddr == "" {
		dnsAddr = "127.0.0.1:8053"
	}
	testResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return net.Dial(network, dnsAddr)
		},
	}
	dnsAutomation := &DNSAutomation{
		provider: &challtestsrvDNSProvider{managementURL: challtestsrvURL},
		resolver: testResolver,
	}

	le, err := NewLetsEncrypt(ctx, LetsEncryptConfig{
		Environment:        "pebble-test-dns01",
		DirectoryURL:       directoryURL,
		ContactEmail:       "test@example.test",
		InsecureSkipVerify: true,
	}, &fakeSecretStore{data: map[string]map[string]interface{}{}}, &fakeCAAccountStore{}, dnsAutomation)
	if err != nil {
		t.Fatalf("NewLetsEncrypt: %v", err)
	}

	domain := "dns01-automated.example.test"
	csrPEM := mustBuildCSR(t, signer, domain)

	po, err := le.RequestValidation(ctx, []string{domain}, "dns-01", csrPEM)
	if err != nil {
		t.Fatalf("RequestValidation: %v", err)
	}
	if len(po.Challenges) != 1 {
		t.Fatalf("expected 1 challenge, got %d", len(po.Challenges))
	}
	if !po.Challenges[0].Automated {
		t.Fatalf("expected the challenge to be marked automated")
	}

	// The TXT record should already be live and propagated (Present
	// blocks on that) — a single CheckChallenge call should be enough,
	// unlike the manual HTTP-01 test which needs its own responder set up
	// by the caller first.
	po, err = le.CheckChallenge(ctx, po)
	if err != nil {
		t.Fatalf("CheckChallenge: %v", err)
	}
	if !po.AllVerified() {
		t.Fatalf("expected the automated DNS-01 challenge to verify on the first check, got: %+v", po.Challenges)
	}

	issued, err := le.Issue(ctx, po, csrPEM, []string{domain})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if issued.SerialNumber == "" {
		t.Fatalf("expected a serial number")
	}
}
