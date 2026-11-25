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

	if err := store.CreateSessionForVerifiedPassword(ctx, guardSession("guard-account", "fresh"), "verified-hash", testMaxSessions); err != nil {
		t.Fatalf("insert with the current hash: %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, "fresh"); err != nil {
		t.Fatalf("expected the session stored: %v", err)
	}

	if err := store.UpdateAccountPasswordHash(ctx, "guard-account", "changed-hash"); err != nil {
		t.Fatalf("change password: %v", err)
	}
	if err := store.CreateSessionForVerifiedPassword(ctx, guardSession("guard-account", "stale"), "verified-hash", testMaxSessions); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for a stale hash, got %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, "stale"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected no session from a stale hash, got %v", err)
	}
	if err := store.CreateSessionForVerifiedPassword(ctx, guardSession("missing", "nobody"), "verified-hash", testMaxSessions); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for a missing account, got %v", err)
	}
}

func TestCreateSessionForVerifiedPasswordRefusesAnEnrolledAccount(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	seedGuardAccount(t, store, "guard-account")
	if err := store.UpdateTOTPSecretAndEnabled(ctx, "guard-account", "secret-ciphertext", true); err != nil {
		t.Fatalf("enable totp: %v", err)
	}

	if err := store.CreateSessionForVerifiedPassword(ctx, guardSession("guard-account", "single-factor"), "verified-hash", testMaxSessions); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound once TOTP is on, got %v", err)
	}
}

func TestCreateTOTPChallengeForVerifiedPasswordRequiresUnchangedHash(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	seedGuardAccount(t, store, "guard-account")

	if err := store.CreateTOTPChallengeForVerifiedPassword(ctx, guardChallenge("guard-account", "not-enrolled"), "verified-hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound while TOTP is off, got %v", err)
	}
	if err := store.UpdateTOTPSecretAndEnabled(ctx, "guard-account", "secret-ciphertext", true); err != nil {
		t.Fatalf("enable totp: %v", err)
	}

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

func TestCreateSessionForUnlapsedManagedAccountRefusesALapse(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	seedGuardAccount(t, store, "selfhosted-account")
	if _, err := store.UpsertManagedAccount(ctx, models.Account{
		ID:            "managedacct1234",
		Login:         "managed:managedacct1234",
		PasswordHash:  "managed_service_only",
		Mode:          "managed",
		PremiumActive: true,
		CreatedAt:     time.Now().UTC(),
	}); err != nil {
		t.Fatalf("upsert managed account: %v", err)
	}

	if err := store.CreateSessionForUnlapsedManagedAccount(ctx, guardSession("managedacct1234", "live"), testMaxSessions); err != nil {
		t.Fatalf("insert on an unlapsed account: %v", err)
	}
	if _, err := store.FindSessionByTokenHash(ctx, "live"); err != nil {
		t.Fatalf("expected the session stored: %v", err)
	}
	if err := store.CreateSessionForUnlapsedManagedAccount(ctx, guardSession("managedacct1234", "live"), testMaxSessions); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("expected a duplicate token insert to fail as a store error, got %v", err)
	}

	now := time.Now().UTC()
	if err := store.ApplyEntitlementSignal(ctx, "managedacct1234", EntitlementSignal{AsOf: now, ReceivedAt: now}); err != nil {
		t.Fatalf("lapse: %v", err)
	}
	for _, tc := range []struct{ accountID, hash string }{
		{"managedacct1234", "after-lapse"},
		{"selfhosted-account", "self-hosted"},
		{"missing", "nobody"},
	} {
		if err := store.CreateSessionForUnlapsedManagedAccount(ctx, guardSession(tc.accountID, tc.hash), testMaxSessions); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: expected ErrNotFound, got %v", tc.accountID, err)
		}
		if _, err := store.FindSessionByTokenHash(ctx, tc.hash); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: expected no session stored, got %v", tc.accountID, err)
		}
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

	if err := store.ConsumeTOTPChallengeAndCreateSession(ctx, "challenge", guardSession("other-account", "foreign"), testMaxSessions); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for another account's challenge, got %v", err)
	}
	if err := store.ConsumeTOTPChallengeAndCreateSession(ctx, "challenge", guardSession("guard-account", "first"), testMaxSessions); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if err := store.ConsumeTOTPChallengeAndCreateSession(ctx, "challenge", guardSession("guard-account", "second"), testMaxSessions); !errors.Is(err, ErrNotFound) {
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
	if err := store.ConsumeTOTPChallengeAndCreateSession(ctx, "challenge", duplicate, testMaxSessions); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("expected the duplicate token insert to fail, got %v", err)
	}
	if _, err := store.FindTOTPChallengeByHash(ctx, "challenge"); err != nil {
		t.Fatalf("expected the challenge kept after the rollback: %v", err)
	}
}
