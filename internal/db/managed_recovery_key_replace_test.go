package db

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

func testRecoveryKeyPackage(accountID, fingerprint string) models.RecoveryKeyPackage {
	return models.RecoveryKeyPackage{
		AccountID:            accountID,
		Algorithm:            "xchacha20poly1305",
		KDF:                  "bip39_seed_hkdf_sha256",
		MnemonicWordCount:    12,
		WrapNonceHex:         strings.Repeat("a", 48),
		WrappedMasterKeyHex:  strings.Repeat("b", 96),
		PhraseFingerprintHex: fingerprint,
		UpdatedAt:            time.Now().UTC(),
	}
}

// TestReplaceManagedRecoveryKeyPackageScopesToManagedAccounts: the bridge
// re-key replaces a managed account's package (and stores a first one), while
// a self-hosted account and an absent one both answer ErrNotFound and write
// nothing.
func TestReplaceManagedRecoveryKeyPackageScopesToManagedAccounts(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	createLapseTestAccount(t, store, "managed-account", "managed")
	createLapseTestAccount(t, store, "managed-no-package", "managed")
	createLapseTestAccount(t, store, "self-hosted", "self_hosted")
	for _, id := range []string{"managed-account", "self-hosted"} {
		if _, err := store.UpsertRecoveryKeyPackage(ctx, testRecoveryKeyPackage(id, strings.Repeat("c", 16))); err != nil {
			t.Fatalf("seed %s package: %v", id, err)
		}
	}

	for _, id := range []string{"managed-account", "managed-no-package"} {
		if err := store.ReplaceManagedRecoveryKeyPackage(ctx, testRecoveryKeyPackage(id, strings.Repeat("d", 16))); err != nil {
			t.Fatalf("replace %s: %v", id, err)
		}
		stored, err := store.GetRecoveryKeyPackage(ctx, id)
		if err != nil || stored.PhraseFingerprintHex != strings.Repeat("d", 16) {
			t.Fatalf("%s: expected the replaced package, got %+v, %v", id, stored, err)
		}
	}

	for _, id := range []string{"self-hosted", "absent-account"} {
		if err := store.ReplaceManagedRecoveryKeyPackage(ctx, testRecoveryKeyPackage(id, strings.Repeat("d", 16))); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: expected ErrNotFound, got %v", id, err)
		}
	}
	if stored, err := store.GetRecoveryKeyPackage(ctx, "self-hosted"); err != nil || stored.PhraseFingerprintHex != strings.Repeat("c", 16) {
		t.Fatalf("expected the self-hosted package untouched, got %+v, %v", stored, err)
	}
	if _, err := store.GetRecoveryKeyPackage(ctx, "absent-account"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected no package for the absent account, got %v", err)
	}
}

func TestReplaceManagedRecoveryKeyPackageStoreFailures(t *testing.T) {
	ctx := context.Background()

	closed := openTestStore(t)
	_ = closed.Close()
	if err := closed.ReplaceManagedRecoveryKeyPackage(ctx, testRecoveryKeyPackage("managed-account", strings.Repeat("d", 16))); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("expected a begin error on a closed store, got %v", err)
	}

	store, dbPath := newFileBackedTestStore(t)
	createLapseTestAccount(t, store, "managed-account", "managed")
	dropTable(t, dbPath, "recovery_key_packages")
	if err := store.ReplaceManagedRecoveryKeyPackage(ctx, testRecoveryKeyPackage("managed-account", strings.Repeat("d", 16))); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("expected the upsert error to surface, got %v", err)
	}
}
