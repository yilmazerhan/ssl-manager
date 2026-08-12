package certificate

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/yilmazerhan/ssl-manager/backend/internal/db"
)

// These are integration tests against a real Postgres instance — set
// DATABASE_URL and run `go run ./cmd/api` once first (or call db.Migrate
// yourself) so the schema exists; skipped otherwise.
func testStore(t *testing.T) *PostgresStore {
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
	return NewPostgresStore(pool)
}

// cleanupCertificate deletes a certificate this test created — these
// tests run against a real, possibly shared, Postgres instance, and a
// stray auto_renew=true row left behind would have the live renewal
// engine trying (and failing) to renew a fake certificate forever.
func cleanupCertificate(t *testing.T, store *PostgresStore, id string) {
	t.Helper()
	t.Cleanup(func() {
		if _, err := store.pool.Exec(context.Background(), `DELETE FROM certificate WHERE id = $1`, id); err != nil {
			t.Logf("cleanup: delete certificate %s: %v", id, err)
		}
	})
}

func TestPostgresStore_CreateGetList(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	created, err := store.Create(ctx, Certificate{
		CommonName: "store-test.example.com", SANs: []string{"store-test.example.com"},
		CAProvider: "letsencrypt", ValidationMethod: "http-01", Status: StatusActive,
		NotBefore: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		KeyAlgorithm: "RSA-2048", KeyRef: "test-key-ref", OwningTeam: "platform-test",
		AutoRenew: true, RenewBeforeDays: 30,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	cleanupCertificate(t, store, created.ID)
	if created.ID == "" {
		t.Fatal("expected a generated ID")
	}

	fetched, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if fetched.CommonName != "store-test.example.com" || len(fetched.SANs) != 1 {
		t.Errorf("unexpected fetched certificate: %+v", fetched)
	}

	list, err := store.List(ctx, Filter{Team: "platform-test"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, c := range list {
		if c.ID == created.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("expected List(team) to include the created certificate")
	}

	expiring, err := store.List(ctx, Filter{ExpiringWithinDays: 30})
	if err != nil {
		t.Fatalf("List(ExpiringWithinDays): %v", err)
	}
	for _, c := range expiring {
		if c.ID == created.ID {
			t.Errorf("a certificate expiring in 90 days should not appear in a 30-day expiry filter")
		}
	}
}

func TestPostgresStore_UpdateAfterRenewalAndVersions(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	created, err := store.Create(ctx, Certificate{
		CommonName: "renew-test.example.com", SANs: []string{"renew-test.example.com"},
		CAProvider: "letsencrypt", ValidationMethod: "http-01", Status: StatusActive,
		NotBefore: time.Now().Add(-60 * 24 * time.Hour), NotAfter: time.Now().Add(5 * 24 * time.Hour),
		KeyAlgorithm: "RSA-2048", KeyRef: "test-key-ref-2", OwningTeam: "platform-test",
		AutoRenew: true, RenewBeforeDays: 30,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	cleanupCertificate(t, store, created.ID)

	due, err := store.DueForRenewal(ctx, time.Now())
	if err != nil {
		t.Fatalf("DueForRenewal: %v", err)
	}
	foundDue := false
	for _, c := range due {
		if c.ID == created.ID {
			foundDue = true
		}
	}
	if !foundDue {
		t.Fatalf("expected the freshly created (soon-to-expire) certificate to be due for renewal")
	}

	newNotAfter := time.Now().Add(90 * 24 * time.Hour)
	if err := store.UpdateAfterRenewal(ctx, created.ID, time.Now(), newNotAfter); err != nil {
		t.Fatalf("UpdateAfterRenewal: %v", err)
	}

	renewed, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if renewed.Status != StatusActive {
		t.Errorf("expected status active after renewal, got %s", renewed.Status)
	}
	if !renewed.NotAfter.After(time.Now().Add(80 * 24 * time.Hour)) {
		t.Errorf("expected NotAfter to be pushed out, got %v", renewed.NotAfter)
	}

	version, err := store.AddVersion(ctx, Version{
		CertificateID: created.ID, SerialNumber: "123", FingerprintSHA256: "abc",
		PEMCert: "cert-pem", PEMChain: "chain-pem", IssuedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	latest, err := store.LatestVersion(ctx, created.ID)
	if err != nil {
		t.Fatalf("LatestVersion: %v", err)
	}
	if latest.ID != version.ID {
		t.Errorf("expected LatestVersion to return the version just added")
	}

	if err := store.Revoke(ctx, created.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	revoked, err := store.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get after revoke: %v", err)
	}
	if revoked.Status != StatusRevoked {
		t.Errorf("expected status revoked, got %s", revoked.Status)
	}
}
