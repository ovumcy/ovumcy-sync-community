package db

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

// expiredRowsFixtureAccount creates one account for the sweep tests. Tests
// that need rows straddling the cutoff put `expired` rows at cutoff-1h and
// `live` rows at cutoff+1h, so a sweep at `cutoff` must remove exactly the
// first group.
func expiredRowsFixtureAccount(t *testing.T, store *Store, suffix string) models.Account {
	t.Helper()

	account, err := store.CreateAccount(context.Background(), models.Account{
		ID:               "expired-rows-" + suffix,
		Login:            suffix + "@example.com",
		PasswordHash:     "not-a-real-hash",
		RecoveryCodeHash: "not-a-real-hash",
		Mode:             "community",
		CreatedAt:        time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	return account
}

func createSessionExpiringAt(t *testing.T, store *Store, accountID, id string, expiresAt time.Time) {
	t.Helper()

	now := time.Now().UTC()
	if _, err := store.CreateSession(context.Background(), models.Session{
		ID:         id,
		AccountID:  accountID,
		TokenHash:  "hash-" + id,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  expiresAt,
	}); err != nil {
		t.Fatalf("create session %s: %v", id, err)
	}
}

// TestDeleteExpiredSessionsDeletesOnlyExpiredRows pins the predicate: rows at
// or before the cutoff go, rows after it stay. The live row's survival is
// proven positively — a later sweep past its expiry finds and deletes it.
func TestDeleteExpiredSessionsDeletesOnlyExpiredRows(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	account := expiredRowsFixtureAccount(t, store, "owner")

	cutoff := time.Now().UTC()
	createSessionExpiringAt(t, store, account.ID, "expired-1", cutoff.Add(-time.Hour))
	createSessionExpiringAt(t, store, account.ID, "live-1", cutoff.Add(time.Hour))

	deleted, err := store.DeleteExpiredSessions(ctx, cutoff, 0)
	if err != nil {
		t.Fatalf("delete expired sessions: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected exactly the expired session deleted, got %d", deleted)
	}

	// Idempotent: nothing expired is left at this cutoff.
	deleted, err = store.DeleteExpiredSessions(ctx, cutoff, 0)
	if err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("expected an idempotent second run, got %d deletions", deleted)
	}

	// The live session survived the first sweep: a sweep past its expiry
	// still finds it.
	deleted, err = store.DeleteExpiredSessions(ctx, cutoff.Add(2*time.Hour), 0)
	if err != nil {
		t.Fatalf("third delete: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected the live session to have survived until its expiry, got %d", deleted)
	}
}

// TestDeleteExpiredSessionsHonorsLimit pins the per-run bound: a limit
// smaller than the expired set deletes exactly limit rows and leaves the
// remainder for the next run.
func TestDeleteExpiredSessionsHonorsLimit(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	account := expiredRowsFixtureAccount(t, store, "owner")

	cutoff := time.Now().UTC()
	for i := 0; i < 3; i++ {
		createSessionExpiringAt(t, store, account.ID, fmt.Sprintf("expired-%d", i), cutoff.Add(-time.Hour))
	}

	deleted, err := store.DeleteExpiredSessions(ctx, cutoff, 2)
	if err != nil {
		t.Fatalf("limited delete: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("expected the limit to bound the delete at 2, got %d", deleted)
	}

	deleted, err = store.DeleteExpiredSessions(ctx, cutoff, 2)
	if err != nil {
		t.Fatalf("follow-up delete: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected the remainder on the next run, got %d", deleted)
	}
}

// TestDeleteExpiredPasswordResetTokensDeletesOnlyExpiredRows mirrors the
// session predicate test for password_reset_tokens. One reset token per
// account (UpsertPasswordResetToken conflicts on account_id), so the expired
// and live tokens need two distinct accounts.
func TestDeleteExpiredPasswordResetTokensDeletesOnlyExpiredRows(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	expiredOwner := expiredRowsFixtureAccount(t, store, "expired-owner")
	liveOwner := expiredRowsFixtureAccount(t, store, "live-owner")

	cutoff := time.Now().UTC()
	if err := store.UpsertPasswordResetToken(ctx, models.PasswordResetToken{
		AccountID: expiredOwner.ID,
		TokenHash: "hash-expired",
		CreatedAt: cutoff.Add(-2 * time.Hour),
		ExpiresAt: cutoff.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("upsert expired reset token: %v", err)
	}
	if err := store.UpsertPasswordResetToken(ctx, models.PasswordResetToken{
		AccountID: liveOwner.ID,
		TokenHash: "hash-live",
		CreatedAt: cutoff.Add(-2 * time.Hour),
		ExpiresAt: cutoff.Add(time.Hour),
	}); err != nil {
		t.Fatalf("upsert live reset token: %v", err)
	}

	deleted, err := store.DeleteExpiredPasswordResetTokens(ctx, cutoff, 0)
	if err != nil {
		t.Fatalf("delete expired reset tokens: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected exactly the expired token deleted, got %d", deleted)
	}

	deleted, err = store.DeleteExpiredPasswordResetTokens(ctx, cutoff.Add(2*time.Hour), 0)
	if err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected the live token to have survived until its expiry, got %d", deleted)
	}
}

// TestDeleteExpiredTOTPChallengesDeletesOnlyExpiredRows mirrors the session
// predicate test for totp_challenges.
func TestDeleteExpiredTOTPChallengesDeletesOnlyExpiredRows(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	account := expiredRowsFixtureAccount(t, store, "owner")

	cutoff := time.Now().UTC()
	for name, expiresAt := range map[string]time.Time{
		"challenge-expired": cutoff.Add(-time.Hour),
		"challenge-live":    cutoff.Add(time.Hour),
	} {
		if err := store.UpsertTOTPChallenge(ctx, models.TOTPChallenge{
			ChallengeIDHash: name,
			AccountID:       account.ID,
			CreatedAt:       cutoff.Add(-2 * time.Hour),
			ExpiresAt:       expiresAt,
		}); err != nil {
			t.Fatalf("upsert totp challenge %s: %v", name, err)
		}
	}

	deleted, err := store.DeleteExpiredTOTPChallenges(ctx, cutoff, 0)
	if err != nil {
		t.Fatalf("delete expired totp challenges: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected exactly the expired challenge deleted, got %d", deleted)
	}

	deleted, err = store.DeleteExpiredTOTPChallenges(ctx, cutoff.Add(2*time.Hour), 0)
	if err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected the live challenge to have survived until its expiry, got %d", deleted)
	}
}

// TestDeleteExpiredRowsSurfaceStoreErrors drives each delete's failure
// branch through real fault injection (a dropped table), per the
// no-fake-driver testing rule.
func TestDeleteExpiredRowsSurfaceStoreErrors(t *testing.T) {
	for _, testCase := range []struct {
		table string
		call  func(*Store) error
	}{
		{"sessions", func(s *Store) error {
			_, err := s.DeleteExpiredSessions(context.Background(), time.Now(), 0)
			return err
		}},
		{"password_reset_tokens", func(s *Store) error {
			_, err := s.DeleteExpiredPasswordResetTokens(context.Background(), time.Now(), 0)
			return err
		}},
		{"totp_challenges", func(s *Store) error {
			_, err := s.DeleteExpiredTOTPChallenges(context.Background(), time.Now(), 0)
			return err
		}},
	} {
		t.Run(testCase.table, func(t *testing.T) {
			store, dbPath := newFileBackedTestStore(t)
			dropTable(t, dbPath, testCase.table)

			err := testCase.call(store)
			if err == nil {
				t.Fatalf("expected an error after dropping %s", testCase.table)
			}
			if !strings.Contains(err.Error(), "delete expired") {
				t.Fatalf("expected a delete-expired error, got %v", err)
			}
		})
	}
}
