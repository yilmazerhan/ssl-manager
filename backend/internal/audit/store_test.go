package audit

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
	return NewPostgresStore(pool)
}

// TestList_FiltersByResourceAndSubstringAction proves the system-wide
// audit feed (the admin Audit Log page, not a single certificate's own
// trail) can narrow by exact resource and a substring match on action —
// so "sync_failed" finds both k8s_sync_failed and winrm_sync_failed
// without the caller needing to know every exact action name.
//
// It writes to resource types that don't otherwise exist in this table
// (real code only ever writes "certificate", "discovery_scan", etc.) so
// counts here can't be thrown off by unrelated audit activity from other
// packages' tests sharing this same Postgres database.
func TestList_FiltersByResourceAndSubstringAction(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	resourceA := "audit-list-test-a-" + t.Name()
	resourceB := "audit-list-test-b-" + t.Name()

	// This table is append-only by design (see the package doc) — Store
	// exposes no Delete — so clean up directly through the pool this
	// white-box test already has access to. Without this, re-running the
	// test against the same persistent Postgres instance (this suite never
	// resets it between runs) would accumulate duplicate rows under the
	// same deterministic resource name every time.
	t.Cleanup(func() {
		s.pool.Exec(context.Background(), `DELETE FROM audit_log WHERE resource IN ($1, $2)`, resourceA, resourceB)
	})

	entries := []Entry{
		{Actor: "system:k8s-sync", Action: "k8s_sync_failed", Resource: resourceA, ResourceID: "1"},
		{Actor: "system:winrm-sync", Action: "winrm_sync_failed", Resource: resourceA, ResourceID: "2"},
		{Actor: "system:k8s-sync", Action: "k8s_sync_succeeded", Resource: resourceA, ResourceID: "3"},
		{Actor: "admin@example.com", Action: "discovery_scan_started", Resource: resourceB, ResourceID: "4"},
	}
	for _, e := range entries {
		if err := s.Write(ctx, e); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	syncFailed, err := s.List(ctx, ListFilter{Resource: resourceA, Action: "sync_failed"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(syncFailed) != 2 {
		t.Fatalf("expected 2 entries matching action substring %q, got %d: %+v", "sync_failed", len(syncFailed), syncFailed)
	}

	resourceAAll, err := s.List(ctx, ListFilter{Resource: resourceA})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(resourceAAll) != 3 {
		t.Fatalf("expected 3 entries for resource %q, got %d: %+v", resourceA, len(resourceAAll), resourceAAll)
	}

	resourceBAll, err := s.List(ctx, ListFilter{Resource: resourceB})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(resourceBAll) != 1 || resourceBAll[0].Action != "discovery_scan_started" {
		t.Fatalf("expected exactly the %q entry, got %+v", resourceB, resourceBAll)
	}
}
