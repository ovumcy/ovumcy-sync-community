package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

func seedGuardAccount(t *testing.T, store *Store, accountID string) {
	t.Helper()
	if _, err := store.CreateAccount(context.Background(), models.Account{
		ID:           accountID,
		Login:        accountID + "@example.com",
		PasswordHash: "verified-hash",
		Mode:         "self_hosted",
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create account: %v", err)
	}
}

func guardSession(accountID, tokenHash string) models.Session {
	now := time.Now().UTC()
	return models.Session{
		ID:         tokenHash + "-id",
		AccountID:  accountID,
		TokenHash:  tokenHash,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(time.Hour),
	}
}

func guardChallenge(accountID, hash string) models.TOTPChallenge {
	now := time.Now().UTC()
	return models.TOTPChallenge{
		ChallengeIDHash: hash,
		AccountID:       accountID,
		CreatedAt:       now,
		ExpiresAt:       now.Add(5 * time.Minute),
	}
}

func TestCreateSessionForVerifiedPasswordRequiresUnchangedHash(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	seedGuardAccount(t, store, "guard-account")

	if err := store.CreateSessionForVerifiedPassword(ctx, guardSession("guard-account", "fresh"), "verified-hash"); err != nil {
		t.Fatalf("insert with the current hash: %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, "fresh"); err != nil {
		t.Fatalf("expected the session stored: %v", err)
	}

	if err := store.UpdateAccountPasswordHash(ctx, "guard-account", "changed-hash"); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if err := store.CreateSessionForVerifiedPassword(ctx, guardSession("guard-account", "stale"), "verified-hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for a stale hash, got %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, "stale"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected no session from a stale hash, got %v", err)
	}
	if err := store.CreateSessionForVerifiedPassword(ctx, guardSession("missing", "nobody"), "verified-hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for a missing account, got %v", err)
	}
}

func TestCreateTOTPChallengeForVerifiedPasswordRequiresUnchangedHash(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	seedGuardAccount(t, store, "guard-account")

	if err := store.CreateTOTPChallengeForVerifiedPassword(ctx, guardChallenge("guard-account", "fresh"), "verified-hash"); err != nil {
		t.Fatalf("insert with the current hash: %v", err)
	}
	if _, err := store.FindTOTPChallengeByHash(ctx, "fresh"); err != nil {
		t.Fatalf("expected the challenge stored: %v", err)
	}

	if err := store.UpdateAccountPasswordHash(ctx, "guard-account", "changed-hash"); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if err := store.CreateTOTPChallengeForVerifiedPassword(ctx, guardChallenge("guard-account", "stale"), "verified-hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for a stale hash, got %v", err)
	}
	if _, err := store.FindTOTPChallengeByHash(ctx, "stale"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected no challenge from a stale hash, got %v", err)
	}
}

func TestConsumeTOTPChallengeAndCreateSessionYieldsOneSession(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	seedGuardAccount(t, store, "guard-account")
	seedGuardAccount(t, store, "other-account")
	if err := store.UpsertTOTPChallenge(ctx, guardChallenge("guard-account", "challenge")); err != nil {
		t.Fatalf("seed challenge: %v", err)
	}

	if err := store.ConsumeTOTPChallengeAndCreateSession(ctx, "challenge", guardSession("other-account", "foreign")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for another account's challenge, got %v", err)
	}
	if err := store.ConsumeTOTPChallengeAndCreateSession(ctx, "challenge", guardSession("guard-account", "first")); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if err := store.ConsumeTOTPChallengeAndCreateSession(ctx, "challenge", guardSession("guard-account", "second")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound on a consumed challenge, got %v", err)
	}

	if _, err := store.FindSessionByTokenHash(ctx, "first"); err != nil {
		t.Fatalf("expected the first session stored: %v", err)
	}
	for _, hash := range []string{"foreign", "second"} {
		if _, err := store.FindSessionByTokenHash(ctx, hash); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected no %q session, got %v", hash, err)
		}
	}
	if _, err := store.FindTOTPChallengeByHash(ctx, "challenge"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected the challenge consumed, got %v", err)
	}
}

func TestConsumeTOTPChallengeAndCreateSessionRollsBackOnInsertFailure(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	seedGuardAccount(t, store, "guard-account")
	if err := store.UpsertTOTPChallenge(ctx, guardChallenge("guard-account", "challenge")); err != nil {
		t.Fatalf("seed challenge: %v", err)
	}
	if _, err := store.CreateSession(ctx, guardSession("guard-account", "taken")); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	duplicate := guardSession("guard-account", "taken")
	duplicate.ID = "another-id"
	if err := store.ConsumeTOTPChallengeAndCreateSession(ctx, "challenge", duplicate); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("expected the duplicate token insert to fail, got %v", err)
	}
	if _, err := store.FindTOTPChallengeByHash(ctx, "challenge"); err != nil {
		t.Fatalf("expected the challenge kept after the rollback: %v", err)
	}
}
