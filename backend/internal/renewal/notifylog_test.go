package renewal

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/yilmazerhan/ssl-manager/backend/internal/certificate"
	"github.com/yilmazerhan/ssl-manager/backend/internal/db"
)

func TestPostgresNotifyLogStore_RecordAndHasSent(t *testing.T) {
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
	cert, err := certs.Create(ctx, certificate.Certificate{
		CommonName: "notifylog-test.example.com", SANs: []string{"notifylog-test.example.com"},
		CAProvider: "letsencrypt", ValidationMethod: "http-01", Status: certificate.StatusActive,
		NotBefore: time.Now(), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		KeyAlgorithm: "RSA-2048", KeyRef: "notifylog-test-key", OwningTeam: "platform-test",
	})
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM certificate WHERE id = $1`, cert.ID) })

	store := NewPostgresNotifyLogStore(pool)

	sent, err := store.HasSent(ctx, cert.ID, 30)
	if err != nil {
		t.Fatalf("HasSent (before any record): %v", err)
	}
	if sent {
		t.Fatalf("expected HasSent to be false before any record exists")
	}

	if err := store.Record(ctx, NotificationLogEntry{
		CertificateID: cert.ID, ThresholdDays: 30, Status: "failed", Error: "smtp timeout", Recipients: []string{"a@example.com"},
	}); err != nil {
		t.Fatalf("Record (failed): %v", err)
	}
	sent, err = store.HasSent(ctx, cert.ID, 30)
	if err != nil {
		t.Fatalf("HasSent (after failed record): %v", err)
	}
	if sent {
		t.Fatalf("expected a failed send not to count as sent, so a retry can happen")
	}

	if err := store.Record(ctx, NotificationLogEntry{
		CertificateID: cert.ID, ThresholdDays: 30, Status: "sent", Recipients: []string{"a@example.com", "b@example.com"},
	}); err != nil {
		t.Fatalf("Record (sent): %v", err)
	}
	sent, err = store.HasSent(ctx, cert.ID, 30)
	if err != nil {
		t.Fatalf("HasSent (after sent record): %v", err)
	}
	if !sent {
		t.Fatalf("expected HasSent to be true after a successful record")
	}

	entries, err := store.ForCertificate(ctx, cert.ID)
	if err != nil {
		t.Fatalf("ForCertificate: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 log entries (one failed, one sent), got %d", len(entries))
	}

	recent, err := store.Recent(ctx, 10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	found := false
	for _, e := range recent {
		if e.CertificateID == cert.ID && e.Status == "sent" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Recent to include this certificate's successful send")
	}
}
