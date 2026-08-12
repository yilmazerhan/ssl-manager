package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/yilmazerhan/ssl-manager/backend/internal/caaccount"
	"github.com/yilmazerhan/ssl-manager/backend/internal/secrets"
)

// This is a real end-to-end integration test against Pebble — the ACME v2
// test server Let's Encrypt itself uses — and a real Vault dev server. It
// proves the actual protocol exchange (order, authorization, HTTP-01
// challenge, finalize, download) against a real ACME implementation, not a
// mock. It's skipped unless both are reachable; see README for how to run
// a local Pebble + Vault for this.
func TestLetsEncrypt_FullFlow_HTTP01(t *testing.T) {
	directoryURL := os.Getenv("ACME_TEST_DIRECTORY_URL")
	vaultAddr := os.Getenv("VAULT_ADDR")
	vaultToken := os.Getenv("VAULT_TOKEN")
	if directoryURL == "" || vaultAddr == "" || vaultToken == "" {
		t.Skip("ACME_TEST_DIRECTORY_URL / VAULT_ADDR / VAULT_TOKEN not set; skipping Pebble integration test")
	}

	ctx := context.Background()
	km, err := secrets.NewVaultKeyManager(vaultAddr, vaultToken, "transit")
	if err != nil {
		t.Fatalf("NewVaultKeyManager: %v", err)
	}
	keyName := "test-le-" + t.Name()
	if err := km.EnsureKey(ctx, keyName, "RSA-2048"); err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}
	signer, err := km.Signer(ctx, keyName)
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}

	le, err := NewLetsEncrypt(ctx, LetsEncryptConfig{
		Environment:        "pebble-test",
		DirectoryURL:       directoryURL,
		ContactEmail:       "test@example.test",
		InsecureSkipVerify: true,
	}, &fakeSecretStore{data: map[string]map[string]interface{}{}}, &fakeCAAccountStore{}, nil)
	if err != nil {
		t.Fatalf("NewLetsEncrypt: %v", err)
	}

	domain := "localhost"
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}, signer)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))

	po, err := le.RequestValidation(ctx, []string{domain}, "http-01", csrPEM)
	if err != nil {
		t.Fatalf("RequestValidation: %v", err)
	}
	if len(po.Challenges) != 1 {
		t.Fatalf("expected 1 challenge, got %d", len(po.Challenges))
	}
	challenge := po.Challenges[0]

	challengeURL, err := url.Parse(challenge.ResourceName)
	if err != nil {
		t.Fatalf("parse challenge URL: %v", err)
	}
	stopResponder := serveHTTP01Response(t, challengeURL.Path, challenge.Value)
	defer stopResponder()

	deadline := time.Now().Add(15 * time.Second)
	for {
		po, err = le.CheckChallenge(ctx, po)
		if err != nil {
			t.Fatalf("CheckChallenge: %v", err)
		}
		if po.AllVerified() {
			break
		}
		if po.Challenges[0].Error != "" {
			t.Fatalf("challenge failed: %s", po.Challenges[0].Error)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for validation")
		}
		time.Sleep(500 * time.Millisecond)
	}

	issued, err := le.Issue(ctx, po, csrPEM, []string{domain})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if issued.SerialNumber == "" {
		t.Errorf("expected a serial number")
	}

	leafBlock, _ := pem.Decode([]byte(issued.PEMCert))
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatalf("parse issued leaf: %v", err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != domain {
		t.Errorf("unexpected SANs: %v", leaf.DNSNames)
	}

	// Pebble regenerates its issuing root/intermediate on every start, so
	// fetch this run's actual root from its management API rather than
	// trusting a static file (pebble.minica.pem signs Pebble's own HTTPS
	// listener, not the certificates it issues).
	if pebbleRootPEM, err := fetchPebbleRoot(); err == nil {
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(pebbleRootPEM)
		intermediates := x509.NewCertPool()
		intermediates.AppendCertsFromPEM([]byte(issued.PEMChain))
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates}); err != nil {
			t.Errorf("issued certificate does not chain to Pebble's root: %v", err)
		}
	} else {
		t.Logf("could not fetch Pebble root for chain verification: %v", err)
	}
}

func fetchPebbleRoot() ([]byte, error) {
	client := &http.Client{Transport: insecureTransport()}
	resp, err := client.Get("https://127.0.0.1:15000/roots/0")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	buf := make([]byte, 8192)
	n, _ := resp.Body.Read(buf)
	return buf[:n], nil
}

func serveHTTP01Response(t *testing.T, path, keyAuth string) func() {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, keyAuth)
	})
	server := &http.Server{Addr: ":5002", Handler: mux}
	go server.ListenAndServe()
	time.Sleep(100 * time.Millisecond)
	return func() { server.Close() }
}

type fakeSecretStore struct {
	data map[string]map[string]interface{}
}

func (f *fakeSecretStore) Put(_ context.Context, path string, data map[string]interface{}) error {
	f.data[path] = data
	return nil
}

func (f *fakeSecretStore) Get(_ context.Context, path string) (map[string]interface{}, error) {
	return f.data[path], nil
}

type fakeCAAccountStore struct {
	account caaccount.Account
	set     bool
}

func (f *fakeCAAccountStore) Get(_ context.Context, provider, environment string) (caaccount.Account, error) {
	if !f.set {
		return caaccount.Account{}, caaccount.ErrNotFound
	}
	return f.account, nil
}

func (f *fakeCAAccountStore) Upsert(_ context.Context, a caaccount.Account) error {
	f.account = a
	f.set = true
	return nil
}
