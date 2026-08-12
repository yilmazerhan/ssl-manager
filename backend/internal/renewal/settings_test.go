package renewal

import (
	"context"
	"os"
	"testing"

	"github.com/yilmazerhan/ssl-manager/backend/internal/db"
)

func TestPostgresSettingsStore_GetDefaultsAndUpdate(t *testing.T) {
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

	store := NewPostgresSettingsStore(pool)

	defaults, err := store.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(defaults.ThresholdDays) == 0 {
		t.Fatalf("expected non-empty default thresholds, got %v", defaults.ThresholdDays)
	}
	// Restore whatever was there before this test touched it — this is a
	// singleton row shared with the live renewal engine if one is running
	// against the same database.
	t.Cleanup(func() { store.Update(context.Background(), defaults) })

	updated := ReminderSettings{
		ThresholdDays:        []int{45, 20, 3},
		EmailSubjectTemplate: "{{.CommonName}} custom subject",
		EmailBodyTemplate:    "{{.CommonName}} custom body",
		DefaultRecipients:    []string{"ops@example.com"},
		EscalationRecipients: []string{"oncall@example.com"},
	}
	if err := store.Update(ctx, updated); err != nil {
		t.Fatalf("Update: %v", err)
	}

	reloaded, err := store.Get(ctx)
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if len(reloaded.ThresholdDays) != 3 || reloaded.ThresholdDays[0] != 45 {
		t.Errorf("expected updated thresholds to round-trip, got %v", reloaded.ThresholdDays)
	}
	if reloaded.EmailSubjectTemplate != updated.EmailSubjectTemplate {
		t.Errorf("expected the subject template to round-trip, got %q", reloaded.EmailSubjectTemplate)
	}
	if len(reloaded.DefaultRecipients) != 1 || reloaded.DefaultRecipients[0] != "ops@example.com" {
		t.Errorf("expected default recipients to round-trip, got %v", reloaded.DefaultRecipients)
	}
}
