package db

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestDisableTOTPClearsAndRevokesOnlyWhileVerifiedStateHolds(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	seedGuardAccount(t, store, "disable-account")
	if err := store.UpdateTOTPSecretAndEnabled(ctx, "disable-account", "secret-v1", true); err != nil {
		t.Fatalf("enable totp: %v", err)
	}
	if _, err := store.CreateSession(ctx, guardSession("disable-account", "owner")); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := store.UpsertTOTPChallenge(ctx, guardChallenge("disable-account", "pending")); err != nil {
		t.Fatalf("create challenge: %v", err)
	}

	for name, args := range map[string][2]string{
		"stale password hash": {"stale-hash", "secret-v1"},
		"stale secret":        {"verified-hash", "secret-v0"},
	} {
		if err := store.DisableTOTP(ctx, "disable-account", args[0], args[1]); !errors.Is(err, ErrConflict) {
			t.Fatalf("%s: expected ErrConflict, got %v", name, err)
		}
	}
	account, err := store.FindAccountByID(ctx, "disable-account")
	if err != nil {
		t.Fatalf("find account: %v", err)
	}
	if !account.TOTPEnabled {
		t.Fatal("expected a conflicting disable to change nothing")
	}
	if _, err := store.FindSessionByTokenHash(ctx, "owner"); err != nil {
		t.Fatalf("expected the session kept after a conflict: %v", err)
	}
	if _, err := store.FindTOTPChallengeByHash(ctx, "pending"); err != nil {
		t.Fatalf("expected the challenge kept after a conflict: %v", err)
	}

	if err := store.DisableTOTP(ctx, "disable-account", "verified-hash", "secret-v1"); err != nil {
		t.Fatalf("disable with the verified state: %v", err)
	}
	account, err = store.FindAccountByID(ctx, "disable-account")
	if err != nil {
		t.Fatalf("find account: %v", err)
	}
	if account.TOTPEnabled || account.TOTPSecretEncrypted != "" {
		t.Fatalf("expected TOTP cleared, got enabled=%v", account.TOTPEnabled)
	}
	if _, err := store.FindSessionByTokenHash(ctx, "owner"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected every session revoked, got %v", err)
	}
	if _, err := store.FindTOTPChallengeByHash(ctx, "pending"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected challenges deleted, got %v", err)
	}

	if err := store.DisableTOTP(ctx, "disable-account", "verified-hash", "secret-v1"); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected a repeat disable to conflict, got %v", err)
	}
	if err := store.DisableTOTP(ctx, "missing-account", "verified-hash", "secret-v1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for a missing account, got %v", err)
	}
}

func TestDisableTOTPSurfacesStoreFailures(t *testing.T) {
	t.Run("closed store", func(t *testing.T) {
		store := openTestStore(t)
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
		err := store.DisableTOTP(context.Background(), "account-target", "hash", "secret")
		if err == nil || !strings.Contains(err.Error(), "begin disable totp") {
			t.Fatalf("expected the begin error, got %v", err)
		}
	})

	t.Run("accounts table dropped", func(t *testing.T) {
		store, dbPath := newFileBackedTestStore(t)
		seedFaultInjectionAccount(t, store, "account-target")
		dropTable(t, dbPath, "accounts")
		err := store.DisableTOTP(context.Background(), "account-target", "hash", "secret")
		if err == nil || errors.Is(err, ErrNotFound) || errors.Is(err, ErrConflict) {
			t.Fatalf("expected a store failure, got %v", err)
		}
	})
}
