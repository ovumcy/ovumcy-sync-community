package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

// TestInstantComparesHoldWithinOneSecond pins the SQL instant compares on a
// whole-second value ("…:05Z") against one later in the same second
// ("…:05.5Z"), the pair that sorts backwards as RFC3339Nano text.
func TestInstantComparesHoldWithinOneSecond(t *testing.T) {
	ctx := context.Background()
	whole := time.Date(2026, 11, 15, 10, 0, 5, 0, time.UTC)
	later := whole.Add(500 * time.Millisecond)

	t.Run("expired sessions sweep", func(t *testing.T) {
		store := openTestStore(t)
		account := expiredRowsFixtureAccount(t, store, "instant-sessions")
		createSessionExpiringAt(t, store, account.ID, "expired-at-whole", whole)
		createSessionExpiringAt(t, store, account.ID, "live-past-later", later.Add(250*time.Millisecond))

		deleted, err := store.DeleteExpiredSessions(ctx, later, 0)
		if err != nil {
			t.Fatalf("delete expired sessions: %v", err)
		}
		if deleted != 1 {
			t.Fatalf("expected only the session expired at %s deleted, got %d", whole, deleted)
		}
		if _, err := store.FindSessionByTokenHash(ctx, "hash-live-past-later"); err != nil {
			t.Fatalf("expected the live session kept, got %v", err)
		}
	})

	t.Run("reset token claim", func(t *testing.T) {
		store := openTestStore(t)
		account := expiredRowsFixtureAccount(t, store, "instant-reset")
		if err := store.UpsertPasswordResetToken(ctx, models.PasswordResetToken{
			AccountID: account.ID,
			TokenHash: "hash-instant-reset",
			CreatedAt: whole.Add(-time.Minute),
			ExpiresAt: whole,
		}, account.RecoveryCodeHash); err != nil {
			t.Fatalf("seed reset token: %v", err)
		}

		if _, err := store.ConsumePasswordResetToken(ctx, "hash-instant-reset", later); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected a token expired at %s refused at %s, got %v", whole, later, err)
		}
	})

	t.Run("lapsed account sweep", func(t *testing.T) {
		store := openTestStore(t)
		const accountID = "managed-lapsed-at-whole"
		createLapseTestAccount(t, store, accountID, "managed")
		if err := store.SetAccountLapsed(ctx, accountID, whole); err != nil {
			t.Fatalf("lapse account: %v", err)
		}

		ids, err := store.ListLapsedManagedAccountIDs(ctx, later, 0)
		if err != nil {
			t.Fatalf("list lapsed accounts: %v", err)
		}
		if len(ids) != 1 || ids[0] != accountID {
			t.Fatalf("expected %q past the cutoff, got %#v", accountID, ids)
		}
		if err := store.DeleteLapsedManagedAccount(ctx, accountID, later); err != nil {
			t.Fatalf("delete lapsed account: %v", err)
		}
	})
}
