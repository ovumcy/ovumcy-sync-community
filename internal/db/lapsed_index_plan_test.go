package db

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestLapsedSweepListingUsesTheLapsedIndex pins migration 0013: the first
// page and a keyset page of ListLapsedManagedAccountIDs both seek the
// (julianday(lapsed_at), id) index between the cursor and the cutoff and take
// its order, never a full accounts scan, a walk from the oldest lapse, or a
// temp b-tree sort.
func TestLapsedSweepListingUsesTheLapsedIndex(t *testing.T) {
	store := openTestStore(t)
	cutoff := time.Now().UTC().Format(time.RFC3339Nano)
	after := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano)

	for _, tc := range []struct {
		name             string
		afterAt, afterID string
	}{
		{"first page", "", ""},
		{"keyset page", after, "account-id"},
	} {
		assertLapsedListingSeeksBothBounds(t, tc.name,
			queryPlan(t, store, listLapsedManagedAccountsSQL, cutoff, tc.afterAt, tc.afterID, DefaultLapsedAccountSweepLimit))
	}
}

// TestMigration0013BuildsOverPopulatedLapsedRows stops a database at 0012,
// seeds managed accounts lapsed past the cutoff (two at one instant), one in
// grace, one whose lapsed_at julianday cannot read, and a self-hosted account,
// then applies 0013: the index builds, and paging one row at a time returns
// exactly the eligible accounts in (instant, id) order.
func TestMigration0013BuildsOverPopulatedLapsedRows(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "pre-0013.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	applyMigrationsBelow(t, store, "0013")

	now := time.Now().UTC()
	lapses := map[string]time.Time{
		"managed-old-b": now.Add(-72 * time.Hour),
		"managed-old-a": now.Add(-72 * time.Hour),
		"managed-older": now.Add(-96 * time.Hour),
		"managed-grace": now.Add(-time.Hour),
	}
	for id, lapsedAt := range lapses {
		createLapseTestAccount(t, store, id, "managed")
		if err := store.SetAccountLapsed(ctx, id, lapsedAt); err != nil {
			t.Fatalf("lapse %s: %v", id, err)
		}
	}
	createLapseTestAccount(t, store, "managed-unreadable", "managed")
	if _, err := store.db.ExecContext(ctx,
		`UPDATE accounts SET lapsed_at = 'not-a-timestamp' WHERE id = 'managed-unreadable'`); err != nil {
		t.Fatalf("seed unreadable lapse: %v", err)
	}
	createLapseTestAccount(t, store, "self-hosted", "self_hosted")

	if err := store.ApplyMigrations(ctx); err != nil {
		t.Fatalf("apply 0013 over populated rows: %v", err)
	}
	if ready, err := store.SchemaReady(ctx); err != nil || !ready {
		t.Fatalf("expected the migrated database ready, got ready=%v err=%v", ready, err)
	}

	cutoff := now.Add(-24 * time.Hour)
	var got []string
	var cursor LapsedCandidate
	for {
		page, err := store.ListLapsedManagedAccountIDs(ctx, cutoff, cursor, 1)
		if err != nil {
			t.Fatalf("list lapsed: %v", err)
		}
		if len(page) == 0 {
			break
		}
		got = append(got, page[0].ID)
		cursor = page[0]
	}
	want := []string{"managed-older", "managed-old-a", "managed-old-b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func applyMigrationsBelow(t *testing.T, store *Store, stop string) {
	t.Helper()
	ctx := context.Background()
	if _, err := store.db.ExecContext(ctx,
		`CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	for _, entry := range entries {
		version := entry.Name()
		if version >= stop {
			continue
		}
		body, err := migrationFiles.ReadFile("migrations/" + version)
		if err != nil {
			t.Fatalf("read %s: %v", version, err)
		}
		if _, err := store.db.ExecContext(ctx, string(body)); err != nil {
			t.Fatalf("apply %s: %v", version, err)
		}
		if _, err := store.db.ExecContext(ctx,
			`INSERT INTO schema_migrations (version, applied_at) VALUES (?, CURRENT_TIMESTAMP)`, version); err != nil {
			t.Fatalf("record %s: %v", version, err)
		}
	}
}

func assertLapsedListingSeeksBothBounds(t *testing.T, name string, plan []string) {
	t.Helper()
	joined := strings.Join(plan, "\n")
	if strings.Contains(joined, "TEMP B-TREE") {
		t.Fatalf("%s: expected the index order, not a sort, plan:\n%s", name, joined)
	}
	assertExpirySweepSeeksIndex(t, "accounts", "idx_accounts_lapsed_julianday", plan)
	if !strings.Contains(joined, "idx_accounts_lapsed_julianday (<expr>>? AND <expr><?)") {
		t.Fatalf("%s: expected a seek bounded by the cursor and the cutoff, plan:\n%s", name, joined)
	}
}
