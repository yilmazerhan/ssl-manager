package k8s

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUpsertTLSSecret_CreatesWhenMissing(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody secretObject

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		gotMethod, gotPath = r.Method, r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer test-token" {
			t.Errorf("expected bearer token auth, got %q", auth)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client := New(server.URL, "test-token", false)
	if err := client.UpsertTLSSecret(t.Context(), "prod", "app-tls", []byte("cert-pem"), []byte("key-pem")); err != nil {
		t.Fatalf("UpsertTLSSecret: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("expected a POST to create a missing secret, got %s", gotMethod)
	}
	if gotPath != "/api/v1/namespaces/prod/secrets" {
		t.Errorf("unexpected path: %q", gotPath)
	}
	if gotBody.Type != "kubernetes.io/tls" {
		t.Errorf("expected type kubernetes.io/tls, got %q", gotBody.Type)
	}
	wantCert := base64.StdEncoding.EncodeToString([]byte("cert-pem"))
	if gotBody.Data["tls.crt"] != wantCert {
		t.Errorf("tls.crt not base64-encoded correctly: got %q want %q", gotBody.Data["tls.crt"], wantCert)
	}
	if gotBody.Metadata.ResourceVersion != "" {
		t.Errorf("expected no resourceVersion on a create, got %q", gotBody.Metadata.ResourceVersion)
	}
}

func TestUpsertTLSSecret_UpdatesWhenExisting(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody secretObject

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(secretObject{
				Metadata: secretMetadata{Name: "app-tls", Namespace: "prod", ResourceVersion: "42"},
			})
			return
		}
		gotMethod, gotPath = r.Method, r.URL.Path
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New(server.URL, "test-token", false)
	if err := client.UpsertTLSSecret(t.Context(), "prod", "app-tls", []byte("cert-pem"), []byte("key-pem")); err != nil {
		t.Fatalf("UpsertTLSSecret: %v", err)
	}

	if gotMethod != http.MethodPut {
		t.Errorf("expected a PUT to update an existing secret, got %s", gotMethod)
	}
	if gotPath != "/api/v1/namespaces/prod/secrets/app-tls" {
		t.Errorf("unexpected path: %q", gotPath)
	}
	if gotBody.Metadata.ResourceVersion != "42" {
		t.Errorf("expected the existing resourceVersion to be carried into the update, got %q", gotBody.Metadata.ResourceVersion)
	}
}

func TestUpsertTLSSecret_PropagatesServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"forbidden"}`))
	}))
	defer server.Close()

	client := New(server.URL, "test-token", false)
	if err := client.UpsertTLSSecret(t.Context(), "prod", "app-tls", []byte("cert-pem"), []byte("key-pem")); err == nil {
		t.Fatalf("expected an error when the API server rejects the request")
	}
}
