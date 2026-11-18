package db

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMigration0012BuildsOverPopulatedAndUnreadableExpiryRows stops a
// database at 0011, seeds sessions, reset tokens and TOTP challenges that are
// live, expired, and carry an expires_at julianday cannot read, then applies
// 0012: every row survives the index build, the sweeps find their batches
// through the new indexes, and each sweep removes the expired and the
// unreadable rows while keeping the live one.
func TestMigration0012BuildsOverPopulatedAndUnreadableExpiryRows(t *testing.T) {
	ctx := context.Background()
	store, err := Open(filepath.Join(t.TempDir(), "pre-0012.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

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
		if version >= "0012" {
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

	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	expiries := map[string]string{
		"live":       now.Add(time.Hour).Format(time.RFC3339Nano),
		"expired":    now.Add(-time.Hour).Format(time.RFC3339Nano),
		"unreadable": "not-a-timestamp",
	}
	for kind, expiresAt := range expiries {
		account := "account-" + kind
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO accounts (id, login, password_hash, created_at) VALUES (?, ?, 'hash', ?)`,
				[]any{account, kind + "@example.com", stamp}},
			{`INSERT INTO sessions (id, account_id, token_hash, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
				[]any{"session-" + kind, account, "session-hash-" + kind, stamp, stamp, expiresAt}},
			{`INSERT INTO password_reset_tokens (account_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)`,
				[]any{account, "reset-hash-" + kind, stamp, expiresAt}},
			{`INSERT INTO totp_challenges (challenge_id_hash, account_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
				[]any{"challenge-hash-" + kind, account, stamp, expiresAt}},
		} {
			if _, err := store.db.ExecContext(ctx, statement.sql, statement.args...); err != nil {
				t.Fatalf("seed %s rows: %v", kind, err)
			}
		}
	}

	if ready, err := store.SchemaReady(ctx); err != nil || ready {
		t.Fatalf("expected a 0011 database to be pending, got ready=%v err=%v", ready, err)
	}
	if err := store.ApplyMigrations(ctx); err != nil {
		t.Fatalf("apply 0012 over populated rows: %v", err)
	}
	if ready, err := store.SchemaReady(ctx); err != nil || !ready {
		t.Fatalf("expected the migrated database ready, got ready=%v err=%v", ready, err)
	}

	tables := []struct {
		table, index, statement string
		sweep                   func(context.Context, time.Time, int) (int64, error)
	}{
		{"sessions", "idx_sessions_expires_julianday", deleteExpiredSessionsSQL, store.DeleteExpiredSessions},
		{"password_reset_tokens", "idx_password_reset_tokens_expires_julianday", deleteExpiredPasswordResetTokensSQL, store.DeleteExpiredPasswordResetTokens},
		{"totp_challenges", "idx_totp_challenges_expires_julianday", deleteExpiredTOTPChallengesSQL, store.DeleteExpiredTOTPChallenges},
	}
	for _, tc := range tables {
		if count := countTableRows(t, store, tc.table); count != len(expiries) {
			t.Fatalf("%s: expected %d rows after 0012, got %d", tc.table, len(expiries), count)
		}
		assertExpirySweepSeeksIndex(t, tc.table, tc.index, queryPlan(t, store, tc.statement, stamp, DefaultExpiredRowsSweepLimit))

		deleted, err := tc.sweep(ctx, now, DefaultExpiredRowsSweepLimit)
		if err != nil {
			t.Fatalf("%s: sweep: %v", tc.table, err)
		}
		if deleted != 2 {
			t.Fatalf("%s: expected the expired and the unreadable row swept, got %d", tc.table, deleted)
		}
		if count := countTableRows(t, store, tc.table); count != 1 {
			t.Fatalf("%s: expected only the live row left, got %d", tc.table, count)
		}
	}

	var live int
	if err := store.db.QueryRowContext(ctx,
		`SELECT (SELECT COUNT(*) FROM sessions WHERE id = 'session-live')
		      + (SELECT COUNT(*) FROM password_reset_tokens WHERE account_id = 'account-live')
		      + (SELECT COUNT(*) FROM totp_challenges WHERE challenge_id_hash = 'challenge-hash-live')`).Scan(&live); err != nil {
		t.Fatalf("count live rows: %v", err)
	}
	if live != 3 {
		t.Fatalf("expected each live row kept, got %d of 3", live)
	}
}

func countTableRows(t *testing.T, store *Store, table string) int {
	t.Helper()
	var count int
	if err := store.db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM `+table, // #nosec G202 -- table is a test-fixture constant
	).Scan(&count); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return count
}

// assertExpirySweepSeeksIndex fails unless every plan step that reads the
// table seeks it through the expiry index or by rowid. A full scan of the
// table or of any of its indexes ("SCAN <table> USING ... INDEX") fails too:
// that still costs a pass over every row per batch.
func assertExpirySweepSeeksIndex(t *testing.T, table, index string, plan []string) {
	t.Helper()
	joined := strings.Join(plan, "\n")
	seeks := false
	for _, line := range plan {
		if strings.HasPrefix(line, "SCAN "+table) {
			t.Fatalf("%s: expected no full table or index scan, plan:\n%s", table, joined)
		}
		if strings.Contains(line, index) {
			if !strings.HasPrefix(line, "SEARCH "+table+" USING INDEX "+index+" (") {
				t.Fatalf("%s: expected %s used as a range seek, plan:\n%s", table, index, joined)
			}
			seeks = true
		}
	}
	if !seeks {
		t.Fatalf("%s: expected the sweep to seek %s, plan:\n%s", table, index, joined)
	}
}
