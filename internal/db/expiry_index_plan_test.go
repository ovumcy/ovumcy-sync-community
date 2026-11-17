package db

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestExpiredRowsSweepUsesTheExpiryIndexes pins migration 0012: each sweep
// statement finds its batch through the julianday(expires_at) index, never a
// full table scan.
func TestExpiredRowsSweepUsesTheExpiryIndexes(t *testing.T) {
	store := openTestStore(t)

	for _, tc := range []struct {
		table, index, statement string
	}{
		{"sessions", "idx_sessions_expires_julianday", deleteExpiredSessionsSQL},
		{"password_reset_tokens", "idx_password_reset_tokens_expires_julianday", deleteExpiredPasswordResetTokensSQL},
		{"totp_challenges", "idx_totp_challenges_expires_julianday", deleteExpiredTOTPChallengesSQL},
	} {
		rows, err := store.db.QueryContext(
			context.Background(),
			`EXPLAIN QUERY PLAN `+tc.statement,
			time.Now().UTC().Format(time.RFC3339Nano),
			DefaultExpiredRowsSweepLimit,
		)
		if err != nil {
			t.Fatalf("%s: explain: %v", tc.table, err)
		}
		var plan []string
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatalf("%s: scan plan: %v", tc.table, err)
			}
			plan = append(plan, detail)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("%s: plan rows: %v", tc.table, err)
		}
		_ = rows.Close()

		joined := strings.Join(plan, "\n")
		if !strings.Contains(joined, tc.index) {
			t.Fatalf("%s: expected the sweep to use %s, plan:\n%s", tc.table, tc.index, joined)
		}
		for _, line := range plan {
			if line == "SCAN "+tc.table {
				t.Fatalf("%s: expected no full scan, plan:\n%s", tc.table, joined)
			}
		}
	}
}
