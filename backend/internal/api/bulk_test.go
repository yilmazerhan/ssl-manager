package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yilmazerhan/ssl-manager/backend/internal/apikey"
	"github.com/yilmazerhan/ssl-manager/backend/internal/audit"
	"github.com/yilmazerhan/ssl-manager/backend/internal/auth"
	"github.com/yilmazerhan/ssl-manager/backend/internal/ca"
	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
	"github.com/yilmazerhan/ssl-manager/backend/internal/db"
	"github.com/yilmazerhan/ssl-manager/backend/internal/user"
)

// testBulkServer wires just enough of Dependencies for the bulk-import and
// bulk-revoke handlers — Authorities is a genuinely empty registry, which
// exercises the real "no CA account behind this certificate" path bulkRevoke
// takes for every certificate.ImportFromPEM result, rather than a mock.
func testBulkServer(t *testing.T) (*httptest.Server, certificate.Store, string) {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping Postgres integration test")
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("db.Migrate: %v", err)
	}
	t.Cleanup(pool.Close)

	users := user.NewPostgresStore(pool)
	certs := certificate.NewPostgresStore(pool)
	sessions := auth.NewSessionManager("bulk-test-secret-not-the-insecure-default", time.Hour)

	email := "bulk-test-" + uuid.NewString() + "@example.com"
	var userID string
	if err := pool.QueryRow(ctx, `INSERT INTO app_user (email, role, team) VALUES ($1, 'admin', 'platform') RETURNING id`, email).Scan(&userID); err != nil {
		t.Fatalf("create test user: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM app_user WHERE id = $1`, userID) })

	u, err := users.GetByID(ctx, userID)
	if err != nil {
		t.Fatalf("load test user: %v", err)
	}
	token, err := sessions.Issue(u)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}

	router := NewRouter(Dependencies{
		Certs:       certs,
		Users:       users,
		Sessions:    sessions,
		APIKeys:     apikey.NewPostgresStore(pool),
		Audit:       audit.NewPostgresStore(pool),
		Authorities: ca.NewRegistry(),
	})
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	return server, certs, token
}

func doJSON(t *testing.T, server *httptest.Server, token, method, path string, body interface{}) (*http.Response, []byte) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode request body: %v", err)
		}
	}
	req, err := http.NewRequest(method, server.URL+path, &buf)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()
	respBody := make([]byte, 0, 4096)
	buf2 := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(buf2)
		respBody = append(respBody, buf2[:n]...)
		if readErr != nil {
			break
		}
	}
	return resp, respBody
}

func mustSelfSignedCertPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestBulkImportCertificates_MixedSuccessAndFailure(t *testing.T) {
	server, certs, token := testBulkServer(t)
	ctx := context.Background()

	goodPEM := mustSelfSignedCertPEM(t, "bulk-import-good.example.test")

	resp, body := doJSON(t, server, token, "POST", "/api/v1/certificates/bulk-import", map[string]interface{}{
		"certificates": []map[string]interface{}{
			{"pem_cert": goodPEM, "owning_team": "platform"},
			{"pem_cert": "not a pem", "owning_team": "platform"},
			{"pem_cert": goodPEM, "owning_team": ""},
		},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var results []bulkImportItemResult
	if err := json.Unmarshal(body, &results); err != nil {
		t.Fatalf("unmarshal response: %v (%s)", err, body)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if !results[0].Success || results[0].CertificateID == "" {
		t.Errorf("expected item 0 (valid cert) to succeed, got %+v", results[0])
	}
	if results[1].Success || results[1].Error == "" {
		t.Errorf("expected item 1 (invalid PEM) to fail with an error, got %+v", results[1])
	}
	if results[2].Success || results[2].Error == "" {
		t.Errorf("expected item 2 (missing owning_team) to fail with an error, got %+v", results[2])
	}

	t.Cleanup(func() { certs.Revoke(context.Background(), results[0].CertificateID) })

	stored, err := certs.Get(ctx, results[0].CertificateID)
	if err != nil {
		t.Fatalf("Get imported certificate: %v", err)
	}
	if stored.CAProvider != "manual" {
		t.Errorf("expected ca_provider manual, got %q", stored.CAProvider)
	}
	if stored.AutoRenew {
		t.Errorf("expected an imported certificate to default to auto_renew=false")
	}
}

func TestBulkImportCertificates_RejectsEmptyAndOversizedBatches(t *testing.T) {
	server, _, token := testBulkServer(t)

	resp, _ := doJSON(t, server, token, "POST", "/api/v1/certificates/bulk-import", map[string]interface{}{"certificates": []map[string]interface{}{}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for an empty batch, got %d", resp.StatusCode)
	}

	oversized := make([]map[string]interface{}, maxBulkItems+1)
	for i := range oversized {
		oversized[i] = map[string]interface{}{"pem_cert": "x", "owning_team": "platform"}
	}
	resp, _ = doJSON(t, server, token, "POST", "/api/v1/certificates/bulk-import", map[string]interface{}{"certificates": oversized})
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for a batch over maxBulkItems, got %d", resp.StatusCode)
	}
}

func TestBulkRevokeCertificates_RevokesKnownAndReportsUnknown(t *testing.T) {
	server, certs, token := testBulkServer(t)
	ctx := context.Background()

	pemCert := mustSelfSignedCertPEM(t, "bulk-revoke-target.example.test")
	cert, version, err := certificate.ImportFromPEM(pemCert, "", "platform")
	if err != nil {
		t.Fatalf("ImportFromPEM: %v", err)
	}
	created, err := certs.Create(ctx, cert)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	version.CertificateID = created.ID
	if _, err := certs.AddVersion(ctx, version); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	t.Cleanup(func() { certs.Revoke(context.Background(), created.ID) })

	resp, body := doJSON(t, server, token, "POST", "/api/v1/certificates/bulk-revoke", map[string]interface{}{
		"certificate_ids": []string{created.ID, "00000000-0000-0000-0000-000000000000"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var results []bulkItemResult
	if err := json.Unmarshal(body, &results); err != nil {
		t.Fatalf("unmarshal response: %v (%s)", err, body)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if !results[0].Success {
		t.Errorf("expected the real certificate to be revoked successfully, got %+v", results[0])
	}
	if results[1].Success || results[1].Error == "" {
		t.Errorf("expected the unknown id to fail with an error, got %+v", results[1])
	}

	reloaded, err := certs.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get after revoke: %v", err)
	}
	if reloaded.Status != certificate.StatusRevoked {
		t.Errorf("expected status revoked after bulk revoke, got %q", reloaded.Status)
	}
}
