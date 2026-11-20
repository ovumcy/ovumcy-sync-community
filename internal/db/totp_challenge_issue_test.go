package db

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestConcurrentChallengeIssueLeavesOneLiveChallenge pins that superseding
// the earlier challenges and inserting the new one is a single transaction:
// racing issues for one account end with exactly one challenge row.
func TestConcurrentChallengeIssueLeavesOneLiveChallenge(t *testing.T) {
	store, _ := newFileBackedTestStore(t)
	ctx := context.Background()
	seedGuardAccount(t, store, "race-account")
	if err := store.UpdateTOTPSecretAndEnabled(ctx, "race-account", "secret-ciphertext", true); err != nil {
		t.Fatalf("enable totp: %v", err)
	}

	const issuers = 12
	var wg sync.WaitGroup
	errs := make(chan error, issuers)
	for i := range issuers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- store.CreateTOTPChallengeForVerifiedPassword(
				ctx, guardChallenge("race-account", fmt.Sprintf("challenge-%d", i)), "verified-hash")
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
	}

	var live int
	if err := store.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM totp_challenges WHERE account_id = ?`, "race-account").Scan(&live); err != nil {
		t.Fatalf("count challenges: %v", err)
	}
	if live != 1 {
		t.Fatalf("expected exactly one live challenge after concurrent issue, got %d", live)
	}
}

// TestRefusedChallengeIssueKeepsTheEarlierChallenge pins the rollback half:
// an insert refused by the verified-hash guard must not have deleted the
// account's existing challenge.
func TestRefusedChallengeIssueKeepsTheEarlierChallenge(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	seedGuardAccount(t, store, "keep-account")
	if err := store.UpdateTOTPSecretAndEnabled(ctx, "keep-account", "secret-ciphertext", true); err != nil {
		t.Fatalf("enable totp: %v", err)
	}
	if err := store.CreateTOTPChallengeForVerifiedPassword(ctx, guardChallenge("keep-account", "first"), "verified-hash"); err != nil {
		t.Fatalf("first issue: %v", err)
	}
	if err := store.CreateTOTPChallengeForVerifiedPassword(ctx, guardChallenge("keep-account", "second"), "stale-hash"); err == nil {
		t.Fatal("expected a stale-hash issue to be refused")
	}
	if _, err := store.FindTOTPChallengeByHash(ctx, "first"); err != nil {
		t.Fatalf("earlier challenge lost to a refused issue: %v", err)
	}
}

func TestResetTokenUsableMatchesTheClaimPredicate(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedResetAccount(t, store, "usable", now.Add(time.Hour))

	if ok, err := store.ResetTokenUsable(ctx, "usable-token", now); err != nil || !ok {
		t.Fatalf("live token: ok=%v err=%v", ok, err)
	}
	if ok, err := store.ResetTokenUsable(ctx, "unknown-token", now); err != nil || ok {
		t.Fatalf("unknown token: ok=%v err=%v", ok, err)
	}
	if ok, err := store.ResetTokenUsable(ctx, "usable-token", now.Add(2*time.Hour)); err != nil || ok {
		t.Fatalf("expired token: ok=%v err=%v", ok, err)
	}
	if _, err := store.ConsumePasswordResetToken(ctx, "usable-token", now); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if ok, err := store.ResetTokenUsable(ctx, "usable-token", now); err != nil || ok {
		t.Fatalf("consumed token: ok=%v err=%v", ok, err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := store.ResetTokenUsable(ctx, "usable-token", now); err == nil {
		t.Fatal("expected a store error on a closed store")
	}
}
