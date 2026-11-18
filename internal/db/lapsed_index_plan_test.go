package db

import (
	"strings"
	"testing"
	"time"
)

// TestLapsedSweepListingUsesTheLapsedIndex pins migration 0013: the first
// page and a keyset page of ListLapsedManagedAccountIDs both seek the
// (julianday(lapsed_at), id) index and take its order, never a full accounts
// scan or a temp b-tree sort.
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
		plan := queryPlan(t, store, listLapsedManagedAccountsSQL, cutoff, tc.afterAt, tc.afterID, DefaultLapsedAccountSweepLimit)
		joined := strings.Join(plan, "\n")
		if strings.Contains(joined, "TEMP B-TREE") {
			t.Fatalf("%s: expected the index order, not a sort, plan:\n%s", tc.name, joined)
		}
		assertExpirySweepSeeksIndex(t, "accounts", "idx_accounts_lapsed_julianday", plan)
	}
}
