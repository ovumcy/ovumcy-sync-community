package db

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

	t.Run("expired reset tokens and challenges sweep", func(t *testing.T) {
		store := openTestStore(t)
		for _, expiresAt := range []struct {
			suffix string
			at     time.Time
		}{{"expired", whole}, {"live", later.Add(250 * time.Millisecond)}} {
			account := expiredRowsFixtureAccount(t, store, "instant-sweep-"+expiresAt.suffix)
			if err := store.UpsertPasswordResetToken(ctx, models.PasswordResetToken{
				AccountID: account.ID,
				TokenHash: "hash-reset-" + expiresAt.suffix,
				CreatedAt: whole.Add(-time.Minute),
				ExpiresAt: expiresAt.at,
			}, account.RecoveryCodeHash); err != nil {
				t.Fatalf("seed reset token: %v", err)
			}
			if err := store.UpsertTOTPChallenge(ctx, models.TOTPChallenge{
				ChallengeIDHash: "hash-challenge-" + expiresAt.suffix,
				AccountID:       account.ID,
				CreatedAt:       whole.Add(-time.Minute),
				ExpiresAt:       expiresAt.at,
			}); err != nil {
				t.Fatalf("seed challenge: %v", err)
			}
		}

		if deleted, err := store.DeleteExpiredPasswordResetTokens(ctx, later, 0); err != nil || deleted != 1 {
			t.Fatalf("expected one reset token deleted, got %d, %v", deleted, err)
		}
		if deleted, err := store.DeleteExpiredTOTPChallenges(ctx, later, 0); err != nil || deleted != 1 {
			t.Fatalf("expected one challenge deleted, got %d, %v", deleted, err)
		}
		if _, err := store.FindTOTPChallengeByHash(ctx, "hash-challenge-live"); err != nil {
			t.Fatalf("expected the live challenge kept, got %v", err)
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

// TestNoTextInstantCompareInSQL keeps the next query from comparing or
// ordering a stored *_at column as text; wrap both sides in julianday().
func TestNoTextInstantCompareInSQL(t *testing.T) {
	textCompare := regexp.MustCompile(`\b\w+_at\s*(<=|>=|<|>)\s*\?|\?\s*(<=|>=|<|>)\s*\w+_at\b|ORDER BY\s+\w+_at\b`)
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob sources: %v", err)
	}
	for _, source := range sources {
		if strings.HasSuffix(source, "_test.go") {
			continue
		}
		body, err := os.ReadFile(source) // #nosec G304 -- names come from a glob of this package's own directory
		if err != nil {
			t.Fatalf("read %s: %v", source, err)
		}
		for _, match := range textCompare.FindAllString(string(body), -1) {
			t.Errorf("%s: instant compared as text: %q", source, match)
		}
	}
}
