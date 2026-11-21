package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"
)

func fingerprintPtr(fingerprint string) *string {
	return &fingerprint
}

// TestReplaceManagedRecoveryKeyPackageExpectingIsACompareAndSwap: an expected
// fingerprint equal to the stored one commits; another one, or no stored
// package, answers ErrRecoveryKeyConflict and leaves the row (updated_at
// included) as it was; the stored package re-sent is a no-op nil whatever the
// expectation; an absent account still answers ErrNotFound.
func TestReplaceManagedRecoveryKeyPackageExpectingIsACompareAndSwap(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	createLapseTestAccount(t, store, "managed-account", "managed")
	createLapseTestAccount(t, store, "empty-managed-account", "managed")

	err := store.ReplaceManagedRecoveryKeyPackageExpecting(ctx,
		testRecoveryKeyPackage("empty-managed-account", strings.Repeat("d", 16)), fingerprintPtr(strings.Repeat("c", 16)))
	if !errors.Is(err, ErrRecoveryKeyConflict) {
		t.Fatalf("expected a conflict with no stored package, got %v", err)
	}
	if _, err := store.GetRecoveryKeyPackage(ctx, "empty-managed-account"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected the conflict to store nothing, got %v", err)
	}

	first := testRecoveryKeyPackage("managed-account", strings.Repeat("c", 16))
	first.UpdatedAt = time.Now().UTC().Add(-time.Hour)
	if err := store.ReplaceManagedRecoveryKeyPackage(ctx, first); err != nil {
		t.Fatalf("seed package: %v", err)
	}

	mismatch := testRecoveryKeyPackage("managed-account", strings.Repeat("d", 16))
	if err := store.ReplaceManagedRecoveryKeyPackageExpecting(ctx, mismatch, fingerprintPtr(strings.Repeat("e", 16))); !errors.Is(err, ErrRecoveryKeyConflict) {
		t.Fatalf("expected a conflict on a fingerprint mismatch, got %v", err)
	}
	stored, err := store.GetRecoveryKeyPackage(ctx, "managed-account")
	if err != nil || stored.PhraseFingerprintHex != first.PhraseFingerprintHex || !stored.UpdatedAt.Equal(first.UpdatedAt) {
		t.Fatalf("expected the mismatch to leave the row, got %+v, %v", stored, err)
	}

	rotated := testRecoveryKeyPackage("managed-account", strings.Repeat("d", 16))
	rotated.UpdatedAt = time.Now().UTC().Add(-time.Minute)
	if err := store.ReplaceManagedRecoveryKeyPackageExpecting(ctx, rotated, fingerprintPtr(first.PhraseFingerprintHex)); err != nil {
		t.Fatalf("expected the matched re-key to commit, got %v", err)
	}

	retry := rotated
	retry.UpdatedAt = time.Now().UTC()
	if err := store.ReplaceManagedRecoveryKeyPackageExpecting(ctx, retry, fingerprintPtr(first.PhraseFingerprintHex)); err != nil {
		t.Fatalf("expected the committed re-key's retry to succeed, got %v", err)
	}
	stored, err = store.GetRecoveryKeyPackage(ctx, "managed-account")
	if err != nil || stored.PhraseFingerprintHex != rotated.PhraseFingerprintHex || !stored.UpdatedAt.Equal(rotated.UpdatedAt) {
		t.Fatalf("expected the rotated row with its own updated_at, got %+v, %v", stored, err)
	}

	err = store.ReplaceManagedRecoveryKeyPackageExpecting(ctx,
		testRecoveryKeyPackage("absent-account", strings.Repeat("d", 16)), fingerprintPtr(strings.Repeat("c", 16)))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for an absent account, got %v", err)
	}
}

func TestReplaceManagedRecoveryKeyPackageExpectingStoreFailures(t *testing.T) {
	ctx := context.Background()
	expected := fingerprintPtr(strings.Repeat("c", 16))

	store, dbPath := newFileBackedTestStore(t)
	createLapseTestAccount(t, store, "managed-account", "managed")
	dropTable(t, dbPath, "recovery_key_packages")
	err := store.ReplaceManagedRecoveryKeyPackageExpecting(ctx, testRecoveryKeyPackage("managed-account", strings.Repeat("d", 16)), expected)
	if err == nil || errors.Is(err, ErrRecoveryKeyConflict) || !strings.Contains(err.Error(), "find identical") {
		t.Fatalf("expected the identical-package lookup error, got %v", err)
	}

	failing, failingPath := newFileBackedTestStore(t)
	createLapseTestAccount(t, failing, "managed-account", "managed")
	if err := failing.ReplaceManagedRecoveryKeyPackage(ctx, testRecoveryKeyPackage("managed-account", strings.Repeat("c", 16))); err != nil {
		t.Fatalf("seed package: %v", err)
	}
	raw, err := sql.Open("sqlite", failingPath)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	defer func() {
		_ = raw.Close()
	}()
	if _, err := raw.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		t.Fatalf("configure raw sqlite: %v", err)
	}
	if _, err := raw.Exec(`CREATE TRIGGER fail_recovery_update BEFORE UPDATE ON recovery_key_packages BEGIN SELECT RAISE(ABORT, 'injected recovery update failure'); END`); err != nil {
		t.Fatalf("install recovery update trigger: %v", err)
	}
	err = failing.ReplaceManagedRecoveryKeyPackageExpecting(ctx, testRecoveryKeyPackage("managed-account", strings.Repeat("d", 16)), expected)
	if err == nil || errors.Is(err, ErrRecoveryKeyConflict) || !strings.Contains(err.Error(), "at fingerprint") {
		t.Fatalf("expected the CAS update error, got %v", err)
	}
}
