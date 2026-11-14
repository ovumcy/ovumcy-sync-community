package db

import (
	"context"
	"errors"
	"testing"
)

func TestUpgradeAccountPasswordHashSwapsOnlyTheVerifiedHash(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	target := seedFaultInjectionAccount(t, store, "account-target")
	bystander := seedFaultInjectionAccount(t, store, "account-bystander")

	if err := store.UpgradeAccountPasswordHash(ctx, target.ID, target.PasswordHash, "upgraded-hash"); err != nil {
		t.Fatalf("upgrade from the verified hash: %v", err)
	}
	upgraded, err := store.FindAccountByID(ctx, target.ID)
	if err != nil {
		t.Fatalf("find account after upgrade: %v", err)
	}
	if upgraded.PasswordHash != "upgraded-hash" {
		t.Fatalf("expected upgraded hash, got %q", upgraded.PasswordHash)
	}
	untouched, err := store.FindAccountByID(ctx, bystander.ID)
	if err != nil {
		t.Fatalf("find bystander account: %v", err)
	}
	if untouched.PasswordHash != bystander.PasswordHash {
		t.Fatalf("expected bystander hash untouched, got %q", untouched.PasswordHash)
	}
}

// A password change that landed after the caller verified the old hash must
// survive: the upgrade, computed from the stale read, is refused.
func TestUpgradeAccountPasswordHashRefusesAStaleVerifiedHash(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	target := seedFaultInjectionAccount(t, store, "account-target")
	staleHash := target.PasswordHash

	if err := store.UpdateAccountPasswordHash(ctx, target.ID, "changed-password-hash"); err != nil {
		t.Fatalf("concurrent password change: %v", err)
	}

	err := store.UpgradeAccountPasswordHash(ctx, target.ID, staleHash, "upgraded-old-password-hash")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for a stale verified hash, got %v", err)
	}
	current, err := store.FindAccountByID(ctx, target.ID)
	if err != nil {
		t.Fatalf("find account: %v", err)
	}
	if current.PasswordHash != "changed-password-hash" {
		t.Fatalf("expected the changed hash to survive, got %q", current.PasswordHash)
	}

	if err := store.UpgradeAccountPasswordHash(ctx, "missing-account", "hash", "any-hash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for a missing account, got %v", err)
	}
}

func TestUpgradeAccountPasswordHashReturnsErrorWhenAccountsTableIsDropped(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	ctx := context.Background()
	target := seedFaultInjectionAccount(t, store, "account-target")

	dropTable(t, dbPath, "accounts")

	err := store.UpgradeAccountPasswordHash(ctx, target.ID, target.PasswordHash, "any-hash")
	if err == nil {
		t.Fatal("expected error upgrading password hash after accounts table is dropped")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("expected a store-failure error, not ErrNotFound, got %v", err)
	}
}
