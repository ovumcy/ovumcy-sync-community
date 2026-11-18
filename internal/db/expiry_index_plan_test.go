package db

import (
	"context"
	"strings"
	"testing"
	"time"
)

func queryPlan(t *testing.T, store *Store, statement string, args ...any) []string {
	t.Helper()
	rows, err := store.db.QueryContext(context.Background(), `EXPLAIN QUERY PLAN `+statement, args...)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatalf("scan plan: %v", err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("plan rows: %v", err)
	}
	return plan
}

// TestExpiredRowsSweepUsesTheExpiryIndexes pins migration 0012: each sweep
// statement finds its batch through the julianday(expires_at) index, never a
// full table scan.
func TestExpiredRowsSweepUsesTheExpiryIndexes(t *testing.T) {
	store := openTestStore(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)

	for _, tc := range []struct {
		table, index, statement string
	}{
		{"sessions", "idx_sessions_expires_julianday", deleteExpiredSessionsSQL},
		{"password_reset_tokens", "idx_password_reset_tokens_expires_julianday", deleteExpiredPasswordResetTokensSQL},
		{"totp_challenges", "idx_totp_challenges_expires_julianday", deleteExpiredTOTPChallengesSQL},
	} {
		plan := queryPlan(t, store, tc.statement, now, DefaultExpiredRowsSweepLimit)
		assertExpirySweepSeeksIndex(t, tc.table, tc.index, plan)
	}
}

// TestResetTokenClaimStillSeeksByTokenHash: the expiry index must not draw
// the reset-token claim away from its token_hash lookup.
func TestResetTokenClaimStillSeeksByTokenHash(t *testing.T) {
	store := openTestStore(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)

	joined := strings.Join(queryPlan(t, store, consumeResetTokenSQL, now, "token-hash", now), "\n")
	if !strings.Contains(joined, "(token_hash=?)") || strings.Contains(joined, "expires_julianday") {
		t.Fatalf("expected the claim to seek by token_hash, plan:\n%s", joined)
	}
}
