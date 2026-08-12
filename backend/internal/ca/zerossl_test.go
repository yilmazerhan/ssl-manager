package ca

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockZeroSSLServer reproduces the request/response shapes ZeroSSL's docs
// describe, closely enough to prove our client builds correct requests and
// parses responses correctly. It is not the real ZeroSSL API.
func mockZeroSSLServer(t *testing.T) *httptest.Server {
	t.Helper()
	triggered := false

	mux := http.NewServeMux()
	mux.HandleFunc("/certificates", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("access_key"); got != "test-api-key" {
			t.Errorf("expected access_key=test-api-key, got %q", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if r.FormValue("certificate_csr") == "" {
			t.Errorf("expected certificate_csr to be set")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":     "cert-123",
			"status": "draft",
			"validation": map[string]interface{}{
				"other_methods": map[string]interface{}{
					"app.example.test": map[string]interface{}{
						"file_validation_url_http": "http://app.example.test/.well-known/pki-validation/ABCDEF.txt",
						"file_validation_content":  []string{"line1", "line2"},
						"cname_validation_p1":      "_abc.app.example.test",
						"cname_validation_p2":      "def.zerossl.com",
					},
				},
			},
		})
	})

	mux.HandleFunc("/certificates/cert-123/challenges", func(w http.ResponseWriter, r *http.Request) {
		triggered = true
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"id": "cert-123", "status": "pending_validation"})
	})

	mux.HandleFunc("/certificates/cert-123", func(w http.ResponseWriter, r *http.Request) {
		status := "pending_validation"
		if triggered {
			status = "issued"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"id": "cert-123", "status": status})
	})

	mux.HandleFunc("/certificates/cert-123/download/return", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"certificate.crt": testLeafCertPEM,
			"ca_bundle.crt":   testIssuerCertPEM,
		})
	})

	mux.HandleFunc("/certificates/cert-123/revoke", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if r.FormValue("reason") == "" {
			t.Errorf("expected a revocation reason to be sent")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
	})

	return httptest.NewServer(mux)
}

func TestZeroSSL_FullFlow(t *testing.T) {
	server := mockZeroSSLServer(t)
	defer server.Close()

	z := NewZeroSSL(ZeroSSLConfig{APIKey: "test-api-key", BaseURL: server.URL})
	ctx := context.Background()

	po, err := z.RequestValidation(ctx, []string{"app.example.test"}, "http-file", "-----BEGIN CERTIFICATE REQUEST-----\nfake\n-----END CERTIFICATE REQUEST-----\n")
	if err != nil {
		t.Fatalf("RequestValidation: %v", err)
	}
	if len(po.Challenges) != 1 {
		t.Fatalf("expected 1 challenge, got %d", len(po.Challenges))
	}
	if po.Challenges[0].ResourceName != "http://app.example.test/.well-known/pki-validation/ABCDEF.txt" {
		t.Errorf("unexpected resource name: %s", po.Challenges[0].ResourceName)
	}
	if po.AllVerified() {
		t.Fatalf("expected not yet verified")
	}

	// First check triggers the challenge but the mock server only reports
	// "issued" after that — matching ZeroSSL's real asynchronous behavior.
	po, err = z.CheckChallenge(ctx, po)
	if err != nil {
		t.Fatalf("CheckChallenge: %v", err)
	}
	if !po.AllVerified() {
		t.Fatalf("expected verified after trigger, challenges: %+v", po.Challenges)
	}

	issued, err := z.Issue(ctx, po, "", nil, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if issued.SerialNumber == "" {
		t.Errorf("expected a serial number")
	}
	if issued.FingerprintSHA256 == "" {
		t.Errorf("expected a fingerprint")
	}
	if issued.CAReference != "cert-123" {
		t.Errorf("expected CAReference to be the ZeroSSL certificate id, got %q", issued.CAReference)
	}

	if err := z.Revoke(ctx, issued.PEMCert, issued.CAReference); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
}

func TestZeroSSL_Revoke_RequiresCAReference(t *testing.T) {
	z := NewZeroSSL(ZeroSSLConfig{APIKey: "test-api-key", BaseURL: "http://unused.invalid"})
	if err := z.Revoke(context.Background(), "irrelevant", ""); err == nil {
		t.Fatal("expected an error when no certificate id is available to revoke")
	}
}
