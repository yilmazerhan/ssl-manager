package k8s

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
	"github.com/yilmazerhan/ssl-manager/backend/internal/db"
)

type fakeSecretStore struct {
	data map[string]map[string]interface{}
}

func newFakeSecretStore() *fakeSecretStore {
	return &fakeSecretStore{data: map[string]map[string]interface{}{}}
}

func (f *fakeSecretStore) Put(_ context.Context, path string, data map[string]interface{}) error {
	f.data[path] = data
	return nil
}

func (f *fakeSecretStore) Get(_ context.Context, path string) (map[string]interface{}, error) {
	d, ok := f.data[path]
	if !ok {
		return nil, fmt.Errorf("secret at %q not found", path)
	}
	return d, nil
}

type fakeKeyExporter struct {
	pem []byte
	err error
}

func (f *fakeKeyExporter) ExportPrivateKey(context.Context, string) ([]byte, error) {
	return f.pem, f.err
}

// testService wires a real Postgres-backed Store and certificate.Store
// with fake Vault-adjacent dependencies (SecretStore, KeyExporter) — this
// package's own logic (target CRUD, sync fan-out, per-target error
// recording) doesn't depend on Vault actually being Vault.
func testService(t *testing.T) (*Service, certificate.Store, *PostgresStore, *fakeSecretStore) {
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

	certs := certificate.NewPostgresStore(pool)
	store := NewPostgresStore(pool)
	secretStore := newFakeSecretStore()
	svc := NewService(store, certs, secretStore, &fakeKeyExporter{pem: []byte("fake-private-key-pem")})
	return svc, certs, store, secretStore
}

func mustExportableCert(t *testing.T, certs certificate.Store, exportable bool) certificate.Certificate {
	t.Helper()
	ctx := context.Background()
	cert, err := certs.Create(ctx, certificate.Certificate{
		CommonName: "k8s-test-" + fmt.Sprint(time.Now().UnixNano()) + ".example.test",
		SANs:       []string{"k8s-test.example.test"},
		CAProvider: "manual", ValidationMethod: "manual", Status: certificate.StatusActive,
		NotBefore: time.Now(), NotAfter: time.Now().Add(24 * time.Hour),
		KeyAlgorithm: "RSA-2048", KeyRef: "test-key-ref", KeyExportable: exportable, OwningTeam: "platform",
	})
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	t.Cleanup(func() { certs.Revoke(context.Background(), cert.ID) })
	return cert
}

func TestCreateTarget_RejectsNonExportableCertificate(t *testing.T) {
	svc, certs, _, _ := testService(t)
	cert := mustExportableCert(t, certs, false)

	_, err := svc.CreateTarget(context.Background(), cert.ID, TargetRequest{
		Name: "prod", ClusterURL: "https://cluster.example", Namespace: "default", SecretName: "app-tls", Token: "tok",
	})
	if err == nil {
		t.Fatalf("expected CreateTarget to reject a certificate whose key isn't exportable")
	}
}

func TestCreateTarget_StoresTokenInSecretStoreNotOnTarget(t *testing.T) {
	svc, certs, store, secretStore := testService(t)
	cert := mustExportableCert(t, certs, true)

	target, err := svc.CreateTarget(context.Background(), cert.ID, TargetRequest{
		Name: "prod", ClusterURL: "https://cluster.example", Namespace: "default", SecretName: "app-tls", Token: "super-secret-token",
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	t.Cleanup(func() { store.Delete(context.Background(), target.ID) })

	data, err := secretStore.Get(context.Background(), secretPath(target.ID))
	if err != nil {
		t.Fatalf("expected the token to be stored at secretPath(target.ID): %v", err)
	}
	if data["token"] != "super-secret-token" {
		t.Errorf("unexpected stored token: %v", data["token"])
	}
}

func TestUpdateTarget_BlankTokenKeepsExistingOne(t *testing.T) {
	svc, certs, store, secretStore := testService(t)
	cert := mustExportableCert(t, certs, true)

	target, err := svc.CreateTarget(context.Background(), cert.ID, TargetRequest{
		Name: "prod", ClusterURL: "https://cluster.example", Namespace: "default", SecretName: "app-tls", Token: "original-token",
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	t.Cleanup(func() { store.Delete(context.Background(), target.ID) })

	if _, err := svc.UpdateTarget(context.Background(), target.ID, TargetRequest{
		Name: "prod-renamed", ClusterURL: "https://cluster.example", Namespace: "default", SecretName: "app-tls", Enabled: true,
	}); err != nil {
		t.Fatalf("UpdateTarget (blank token): %v", err)
	}
	data, _ := secretStore.Get(context.Background(), secretPath(target.ID))
	if data["token"] != "original-token" {
		t.Errorf("expected the original token to survive a blank-token update, got %v", data["token"])
	}

	if _, err := svc.UpdateTarget(context.Background(), target.ID, TargetRequest{
		Name: "prod-renamed", ClusterURL: "https://cluster.example", Namespace: "default", SecretName: "app-tls", Token: "rotated-token", Enabled: true,
	}); err != nil {
		t.Fatalf("UpdateTarget (new token): %v", err)
	}
	data, _ = secretStore.Get(context.Background(), secretPath(target.ID))
	if data["token"] != "rotated-token" {
		t.Errorf("expected the token to be rotated, got %v", data["token"])
	}
}

func TestSyncCertificate_SyncsEnabledTargetsAndSkipsDisabled(t *testing.T) {
	svc, certs, store, _ := testService(t)
	ctx := context.Background()
	cert := mustExportableCert(t, certs, true)
	if _, err := certs.AddVersion(ctx, certificate.Version{
		CertificateID: cert.ID, SerialNumber: "1", FingerprintSHA256: "abc", PEMCert: "cert-pem", PEMChain: "chain-pem", IssuedAt: time.Now(),
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	var syncCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		syncCount++
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	enabled, err := svc.CreateTarget(ctx, cert.ID, TargetRequest{
		Name: "enabled-target", ClusterURL: server.URL, Namespace: "default", SecretName: "app-tls", Token: "tok", Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateTarget (enabled): %v", err)
	}
	t.Cleanup(func() { store.Delete(context.Background(), enabled.ID) })

	disabled, err := svc.CreateTarget(ctx, cert.ID, TargetRequest{
		Name: "disabled-target", ClusterURL: server.URL, Namespace: "default", SecretName: "app-tls-2", Token: "tok",
	})
	if err != nil {
		t.Fatalf("CreateTarget (disabled): %v", err)
	}
	t.Cleanup(func() { store.Delete(context.Background(), disabled.ID) })
	// CreateTarget always starts a target enabled; disable it explicitly.
	if _, err := svc.UpdateTarget(ctx, disabled.ID, TargetRequest{
		Name: "disabled-target", ClusterURL: server.URL, Namespace: "default", SecretName: "app-tls-2", Enabled: false,
	}); err != nil {
		t.Fatalf("UpdateTarget (disable): %v", err)
	}

	svc.SyncCertificate(ctx, cert.ID)

	if syncCount != 1 {
		t.Errorf("expected exactly 1 sync call (the enabled target only), got %d", syncCount)
	}

	reloadedEnabled, err := store.Get(ctx, enabled.ID)
	if err != nil {
		t.Fatalf("Get enabled target: %v", err)
	}
	if reloadedEnabled.LastSyncedAt == nil {
		t.Errorf("expected the enabled target's last_synced_at to be set")
	}
	if reloadedEnabled.LastSyncError != "" {
		t.Errorf("expected no sync error, got %q", reloadedEnabled.LastSyncError)
	}

	reloadedDisabled, err := store.Get(ctx, disabled.ID)
	if err != nil {
		t.Fatalf("Get disabled target: %v", err)
	}
	if reloadedDisabled.LastSyncedAt != nil {
		t.Errorf("expected the disabled target to be skipped entirely")
	}
}

func TestSyncCertificate_RecordsErrorWithoutPanicking(t *testing.T) {
	svc, certs, store, _ := testService(t)
	ctx := context.Background()
	cert := mustExportableCert(t, certs, true)
	if _, err := certs.AddVersion(ctx, certificate.Version{
		CertificateID: cert.ID, SerialNumber: "1", FingerprintSHA256: "abc", PEMCert: "cert-pem", PEMChain: "", IssuedAt: time.Now(),
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	target, err := svc.CreateTarget(ctx, cert.ID, TargetRequest{
		Name: "unreachable", ClusterURL: "http://127.0.0.1:1", Namespace: "default", SecretName: "app-tls", Token: "tok", Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	t.Cleanup(func() { store.Delete(context.Background(), target.ID) })

	svc.SyncCertificate(ctx, cert.ID)

	reloaded, err := store.Get(ctx, target.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if reloaded.LastSyncError == "" {
		t.Errorf("expected a sync error to be recorded for an unreachable cluster")
	}
}
