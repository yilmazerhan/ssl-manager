package caconfig

import (
	"context"
	"os"
	"testing"

	"github.com/yilmazerhan/ssl-manager/backend/internal/db"
)

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
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM ca_integration_settings WHERE provider LIKE 'test-%'`)
	})
	return NewPostgresStore(pool)
}

func TestStore_GetMissing_ReturnsFalseNotError(t *testing.T) {
	store := testStore(t)
	var out LetsEncryptSettings
	found, err := store.Get(context.Background(), "test-never-set", &out)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if found {
		t.Fatalf("expected found=false for a provider that was never set")
	}
}

func TestStore_SetThenGet_RoundTrips(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	in := LetsEncryptSettings{Environment: "production", DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory", ContactEmail: "ops@example.com"}
	if err := store.Set(ctx, "test-letsencrypt", in); err != nil {
		t.Fatalf("Set: %v", err)
	}

	var out LetsEncryptSettings
	found, err := store.Get(ctx, "test-letsencrypt", &out)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !found {
		t.Fatalf("expected found=true after Set")
	}
	if out != in {
		t.Fatalf("round-tripped settings don't match: got %+v, want %+v", out, in)
	}
}

func TestStore_Set_OverwritesPreviousValue(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()

	if err := store.Set(ctx, "test-adcs", ADCSSettings{BaseURL: "https://ca1.corp.test/certsrv"}); err != nil {
		t.Fatalf("Set (first): %v", err)
	}
	if err := store.Set(ctx, "test-adcs", ADCSSettings{BaseURL: "https://ca2.corp.test/certsrv", Template: "WebServer"}); err != nil {
		t.Fatalf("Set (second): %v", err)
	}

	var out ADCSSettings
	if _, err := store.Get(ctx, "test-adcs", &out); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if out.BaseURL != "https://ca2.corp.test/certsrv" || out.Template != "WebServer" {
		t.Fatalf("expected the second Set to win, got %+v", out)
	}
}
