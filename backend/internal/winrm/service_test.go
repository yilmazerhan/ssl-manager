package winrm

import (
	"context"
	"fmt"
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
// with fake Vault-adjacent dependencies — this package's own logic
// (target CRUD, the exportable-key gate, per-target error recording)
// doesn't depend on Vault actually being Vault, only on WinRM itself
// which is exercised separately in client_test.go.
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
	_, keyPEM, _ := mustSelfSignedPEM(t, "winrm-target-key.example.test", 99)
	svc := NewService(store, certs, secretStore, &fakeKeyExporter{pem: keyPEM})
	return svc, certs, store, secretStore
}

func mustExportableCert(t *testing.T, certs certificate.Store, exportable bool) certificate.Certificate {
	t.Helper()
	ctx := context.Background()
	cert, err := certs.Create(ctx, certificate.Certificate{
		CommonName: "winrm-test-" + fmt.Sprint(time.Now().UnixNano()) + ".example.test",
		SANs:       []string{"winrm-test.example.test"},
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
		Name: "dc1", Host: "dc1.example.test", Port: 5986, Username: "admin", Password: "pw", ServiceType: ServiceLDAPS,
	})
	if err == nil {
		t.Fatalf("expected CreateTarget to reject a certificate whose key isn't exportable")
	}
}

func TestCreateTarget_RejectsUnknownServiceType(t *testing.T) {
	svc, certs, _, _ := testService(t)
	cert := mustExportableCert(t, certs, true)

	_, err := svc.CreateTarget(context.Background(), cert.ID, TargetRequest{
		Name: "dc1", Host: "dc1.example.test", Port: 5986, Username: "admin", Password: "pw", ServiceType: ServiceType("smtp"),
	})
	if err == nil {
		t.Fatalf("expected CreateTarget to reject an unknown service_type")
	}
}

func TestCreateTarget_StoresPasswordInSecretStoreNotOnTarget(t *testing.T) {
	svc, certs, store, secretStore := testService(t)
	cert := mustExportableCert(t, certs, true)

	target, err := svc.CreateTarget(context.Background(), cert.ID, TargetRequest{
		Name: "dc1", Host: "dc1.example.test", Port: 5986, Username: "admin", Password: "super-secret-password", ServiceType: ServiceLDAPS,
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	t.Cleanup(func() { store.Delete(context.Background(), target.ID) })

	data, err := secretStore.Get(context.Background(), secretPath(target.ID))
	if err != nil {
		t.Fatalf("expected the password to be stored at secretPath(target.ID): %v", err)
	}
	if data["password"] != "super-secret-password" {
		t.Errorf("unexpected stored password: %v", data["password"])
	}
}

func TestUpdateTarget_BlankPasswordKeepsExistingOne(t *testing.T) {
	svc, certs, store, secretStore := testService(t)
	cert := mustExportableCert(t, certs, true)

	target, err := svc.CreateTarget(context.Background(), cert.ID, TargetRequest{
		Name: "winrm1", Host: "host.example.test", Port: 5986, Username: "admin", Password: "original-password", ServiceType: ServiceWinRMHTTPS,
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	t.Cleanup(func() { store.Delete(context.Background(), target.ID) })

	if _, err := svc.UpdateTarget(context.Background(), target.ID, TargetRequest{
		Name: "winrm1-renamed", Host: "host.example.test", Port: 5986, Username: "admin", ServiceType: ServiceWinRMHTTPS, Enabled: true,
	}); err != nil {
		t.Fatalf("UpdateTarget (blank password): %v", err)
	}
	data, _ := secretStore.Get(context.Background(), secretPath(target.ID))
	if data["password"] != "original-password" {
		t.Errorf("expected the original password to survive a blank-password update, got %v", data["password"])
	}

	if _, err := svc.UpdateTarget(context.Background(), target.ID, TargetRequest{
		Name: "winrm1-renamed", Host: "host.example.test", Port: 5986, Username: "admin", Password: "rotated-password", ServiceType: ServiceWinRMHTTPS, Enabled: true,
	}); err != nil {
		t.Fatalf("UpdateTarget (new password): %v", err)
	}
	data, _ = secretStore.Get(context.Background(), secretPath(target.ID))
	if data["password"] != "rotated-password" {
		t.Errorf("expected the password to be rotated, got %v", data["password"])
	}
}

// TestSyncCertificate_RecordsErrorForUnreachableHost proves the whole
// pipeline (load cert, export key, build PFX, build script, attempt
// WinRM) runs end to end and records a clear per-target error rather than
// panicking or silently doing nothing when the target host doesn't exist.
func TestSyncCertificate_RecordsErrorForUnreachableHost(t *testing.T) {
	svc, certs, store, _ := testService(t)
	ctx := context.Background()
	cert := mustExportableCert(t, certs, true)
	certPEM, _, _ := mustSelfSignedPEM(t, cert.CommonName, 1)
	if _, err := certs.AddVersion(ctx, certificate.Version{
		CertificateID: cert.ID, SerialNumber: "1", FingerprintSHA256: "abc", PEMCert: string(certPEM), PEMChain: "", IssuedAt: time.Now(),
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	target, err := svc.CreateTarget(ctx, cert.ID, TargetRequest{
		Name: "unreachable", Host: "127.0.0.1", Port: 1, Username: "admin", Password: "pw", ServiceType: ServiceLDAPS, Enabled: true,
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
	if reloaded.LastSyncedAt == nil {
		t.Errorf("expected last_synced_at to be set even on failure")
	}
	if reloaded.LastSyncError == "" {
		t.Errorf("expected a sync error to be recorded for an unreachable host")
	}
}

func TestSyncCertificate_SkipsDisabledTargets(t *testing.T) {
	svc, certs, store, _ := testService(t)
	ctx := context.Background()
	cert := mustExportableCert(t, certs, true)
	certPEM, _, _ := mustSelfSignedPEM(t, cert.CommonName, 2)
	if _, err := certs.AddVersion(ctx, certificate.Version{
		CertificateID: cert.ID, SerialNumber: "1", FingerprintSHA256: "abc", PEMCert: string(certPEM), PEMChain: "", IssuedAt: time.Now(),
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	target, err := svc.CreateTarget(ctx, cert.ID, TargetRequest{
		Name: "disabled", Host: "127.0.0.1", Port: 1, Username: "admin", Password: "pw", ServiceType: ServiceLDAPS,
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	t.Cleanup(func() { store.Delete(context.Background(), target.ID) })
	if _, err := svc.UpdateTarget(ctx, target.ID, TargetRequest{
		Name: "disabled", Host: "127.0.0.1", Port: 1, Username: "admin", ServiceType: ServiceLDAPS, Enabled: false,
	}); err != nil {
		t.Fatalf("UpdateTarget (disable): %v", err)
	}

	// CreateTarget already attempted an immediate sync-on-create (recording
	// a failure, since the target is unreachable) before it was disabled;
	// capture that so we can prove SyncCertificate leaves it untouched.
	beforeResync, err := store.Get(ctx, target.ID)
	if err != nil {
		t.Fatalf("Get (before resync): %v", err)
	}
	if beforeResync.LastSyncedAt == nil {
		t.Fatalf("expected the target's immediate sync-on-create to have set last_synced_at")
	}

	svc.SyncCertificate(ctx, cert.ID)

	reloaded, err := store.Get(ctx, target.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !reloaded.LastSyncedAt.Equal(*beforeResync.LastSyncedAt) {
		t.Errorf("expected a disabled target to be skipped entirely by SyncCertificate, but its last_synced_at changed")
	}
}

// TestCreateTarget_SyncsImmediately proves a newly created WinRM target is
// pushed right away rather than waiting for the certificate's next
// issuance/renewal — the returned Target should already reflect that
// first attempt's outcome (here, a recorded failure, since there's no
// real WinRM host in this test to succeed against).
func TestCreateTarget_SyncsImmediately(t *testing.T) {
	svc, certs, store, _ := testService(t)
	ctx := context.Background()
	cert := mustExportableCert(t, certs, true)
	certPEM, _, _ := mustSelfSignedPEM(t, cert.CommonName, 3)
	if _, err := certs.AddVersion(ctx, certificate.Version{
		CertificateID: cert.ID, SerialNumber: "1", FingerprintSHA256: "abc", PEMCert: string(certPEM), PEMChain: "", IssuedAt: time.Now(),
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	target, err := svc.CreateTarget(ctx, cert.ID, TargetRequest{
		Name: "immediate", Host: "127.0.0.1", Port: 1, Username: "admin", Password: "pw", ServiceType: ServiceLDAPS, Enabled: true,
	})
	if err != nil {
		t.Fatalf("expected CreateTarget to succeed even though the immediate sync fails, got: %v", err)
	}
	t.Cleanup(func() { store.Delete(context.Background(), target.ID) })

	if target.LastSyncedAt == nil {
		t.Errorf("expected the target returned by CreateTarget to already have last_synced_at set")
	}
	if target.LastSyncError == "" {
		t.Errorf("expected the failed immediate sync's error to be recorded on the created target")
	}
}

func TestSyncTarget_ReturnsErrorMatchingRecordedFailure(t *testing.T) {
	svc, certs, store, _ := testService(t)
	ctx := context.Background()
	cert := mustExportableCert(t, certs, true)
	certPEM, _, _ := mustSelfSignedPEM(t, cert.CommonName, 4)
	if _, err := certs.AddVersion(ctx, certificate.Version{
		CertificateID: cert.ID, SerialNumber: "1", FingerprintSHA256: "abc", PEMCert: string(certPEM), PEMChain: "", IssuedAt: time.Now(),
	}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	target, err := svc.CreateTarget(ctx, cert.ID, TargetRequest{
		Name: "unreachable", Host: "127.0.0.1", Port: 1, Username: "admin", Password: "pw", ServiceType: ServiceLDAPS, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	t.Cleanup(func() { store.Delete(context.Background(), target.ID) })

	if err := svc.SyncTarget(ctx, target.ID); err == nil {
		t.Fatalf("expected SyncTarget to return an error for an unreachable host")
	}
}
