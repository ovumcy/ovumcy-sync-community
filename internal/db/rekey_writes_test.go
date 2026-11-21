package db

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

func rekeyTestStore(t *testing.T) *Store {
	t.Helper()
	store := openTestStore(t)
	seedFaultInjectionAccount(t, store, "account-target")
	seedChangePasswordSession(t, store, "account-target", "caller")
	return store
}

func rekeyBlob(generation int64, ciphertext string) models.EncryptedBlob {
	blob := lateBodyBlob("account-target")
	blob.Generation = generation
	blob.Ciphertext = []byte(ciphertext)
	blob.CiphertextSize = len(ciphertext)
	return blob
}

func assertRekeyRows(t *testing.T, store *Store, fingerprint string, generation int64, ciphertext string) {
	t.Helper()
	ctx := context.Background()
	pkg, err := store.GetRecoveryKeyPackage(ctx, "account-target")
	switch {
	case fingerprint == "" && !errors.Is(err, ErrNotFound):
		t.Fatalf("expected no package, got %#v / %v", pkg, err)
	case fingerprint != "" && (err != nil || pkg.PhraseFingerprintHex != fingerprint):
		t.Fatalf("package fingerprint %q (err %v), want %q", pkg.PhraseFingerprintHex, err, fingerprint)
	}
	blob, err := store.GetEncryptedBlob(ctx, "account-target")
	switch {
	case generation == 0 && !errors.Is(err, ErrNotFound):
		t.Fatalf("expected no blob, got generation %d / %v", blob.Generation, err)
	case generation != 0 && (err != nil || blob.Generation != generation || string(blob.Ciphertext) != ciphertext):
		t.Fatalf("blob generation %d ciphertext %q (err %v), want %d %q", blob.Generation, blob.Ciphertext, err, generation, ciphertext)
	}
}

func TestReplaceRecoveryKeyAndBlobIsAllOrNothing(t *testing.T) {
	ctx := context.Background()
	store := rekeyTestStore(t)
	stepUp := RekeyGuard{Mode: RekeyStepUp, SessionTokenHash: "caller", VerifiedHash: "hash"}
	k1 := stepUpTestPackage("account-target")

	// First setup whose blob is refused stores no package either.
	if _, err := store.ReplaceRecoveryKeyAndBlobForSession(ctx, k1, rekeyBlob(10, "k1"), stepUp, noGenerationCeiling, 9); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("first setup with a positive expectation: expected ErrStaleGeneration, got %v", err)
	}
	assertRekeyRows(t, store, "", 0, "")

	if _, err := store.ReplaceRecoveryKeyAndBlobForSession(ctx, k1, rekeyBlob(10, "k1"), stepUp, noGenerationCeiling, 0); err != nil {
		t.Fatalf("first rekey: %v", err)
	}
	assertRekeyRows(t, store, k1.PhraseFingerprintHex, 10, "k1")

	k2 := k1
	k2.PhraseFingerprintHex = strings.Repeat("9", 16)
	for name, expected := range map[string]int64{"no-row expectation": 0, "mismatch": 9} {
		if _, err := store.ReplaceRecoveryKeyAndBlobForSession(ctx, k2, rekeyBlob(11, "k2"), stepUp, noGenerationCeiling, expected); !errors.Is(err, ErrStaleGeneration) {
			t.Fatalf("%s: expected ErrStaleGeneration, got %v", name, err)
		}
		assertRekeyRows(t, store, k1.PhraseFingerprintHex, 10, "k1")
	}

	for name, refusal := range map[string]struct {
		guard RekeyGuard
		pkg   models.RecoveryKeyPackage
		want  error
	}{
		"moved hash":      {RekeyGuard{Mode: RekeyStepUp, SessionTokenHash: "caller", VerifiedHash: "stale"}, k2, ErrConflict},
		"flipped totp":    {RekeyGuard{Mode: RekeyStepUp, SessionTokenHash: "caller", VerifiedHash: "hash", VerifiedTOTPEnabled: true}, k2, ErrTOTPStateChanged},
		"revoked step-up": {RekeyGuard{Mode: RekeyStepUp, SessionTokenHash: "gone", VerifiedHash: "hash"}, k2, ErrSessionRevoked},
		"revoked keep":    {RekeyGuard{Mode: RekeyKeepPackage, SessionTokenHash: "gone"}, k1, ErrSessionRevoked},
		"revoked managed": {RekeyGuard{Mode: RekeyFirstManaged, SessionTokenHash: "gone"}, k1, ErrSessionRevoked},
	} {
		if _, err := store.ReplaceRecoveryKeyAndBlobForSession(ctx, refusal.pkg, rekeyBlob(11, "k2"), refusal.guard, noGenerationCeiling, 10); !errors.Is(err, refusal.want) {
			t.Fatalf("%s: expected %v, got %v", name, refusal.want, err)
		}
		assertRekeyRows(t, store, k1.PhraseFingerprintHex, 10, "k1")
	}

	if _, err := store.ReplaceRecoveryKeyAndBlobForSession(ctx, k2, rekeyBlob(11, "k2"), stepUp, noGenerationCeiling, 10); err != nil {
		t.Fatalf("matching rekey: %v", err)
	}
	assertRekeyRows(t, store, k2.PhraseFingerprintHex, 11, "k2")
}

// A keep-package write judged against a package another writer has since
// replaced must not store a blob sealed under the old key.
func TestReplaceRecoveryKeyAndBlobKeepModeRefusesAChangedPackage(t *testing.T) {
	ctx := context.Background()
	store := rekeyTestStore(t)
	keep := RekeyGuard{Mode: RekeyKeepPackage, SessionTokenHash: "caller"}
	k1 := stepUpTestPackage("account-target")

	if _, err := store.ReplaceRecoveryKeyAndBlobForSession(ctx, k1, rekeyBlob(10, "k1"), keep, noGenerationCeiling, 0); !errors.Is(err, ErrRecoveryKeyChanged) {
		t.Fatalf("keep mode with no stored package: expected ErrRecoveryKeyChanged, got %v", err)
	}
	assertRekeyRows(t, store, "", 0, "")

	k2 := k1
	k2.PhraseFingerprintHex = strings.Repeat("9", 16)
	if _, err := store.UpsertRecoveryKeyPackageForSession(ctx, k2, "hash", false, "caller"); err != nil {
		t.Fatalf("seed k2: %v", err)
	}
	if _, err := store.ReplaceRecoveryKeyAndBlobForSession(ctx, k1, rekeyBlob(10, "k1"), keep, noGenerationCeiling, 0); !errors.Is(err, ErrRecoveryKeyChanged) {
		t.Fatalf("keep mode over a replaced package: expected ErrRecoveryKeyChanged, got %v", err)
	}
	assertRekeyRows(t, store, k2.PhraseFingerprintHex, 0, "")

	if _, err := store.ReplaceRecoveryKeyAndBlobForSession(ctx, k2, rekeyBlob(10, "k2"), keep, noGenerationCeiling, 0); err != nil {
		t.Fatalf("keep mode over the same package: %v", err)
	}
	assertRekeyRows(t, store, k2.PhraseFingerprintHex, 10, "k2")
}

func TestReplaceRecoveryKeyAndBlobFirstManagedNeverReplaces(t *testing.T) {
	ctx := context.Background()
	store := rekeyTestStore(t)
	first := RekeyGuard{Mode: RekeyFirstManaged, SessionTokenHash: "caller"}
	k1 := stepUpTestPackage("account-target")

	if _, err := store.ReplaceRecoveryKeyAndBlobForSession(ctx, k1, rekeyBlob(10, "k1"), first, noGenerationCeiling, 0); err != nil {
		t.Fatalf("first managed rekey: %v", err)
	}
	k2 := k1
	k2.PhraseFingerprintHex = strings.Repeat("9", 16)
	if _, err := store.ReplaceRecoveryKeyAndBlobForSession(ctx, k2, rekeyBlob(11, "k2"), first, noGenerationCeiling, 10); !errors.Is(err, ErrConflict) {
		t.Fatalf("managed replace: expected ErrConflict, got %v", err)
	}
	assertRekeyRows(t, store, k1.PhraseFingerprintHex, 10, "k1")
	if _, err := store.ReplaceRecoveryKeyAndBlobForSession(ctx, k1, rekeyBlob(11, "k1b"), first, noGenerationCeiling, 10); err != nil {
		t.Fatalf("managed re-put of the stored package: %v", err)
	}
	assertRekeyRows(t, store, k1.PhraseFingerprintHex, 11, "k1b")
}

// The T3-7 arm: a stored generation above the ceiling waives the advance,
// never the expected match.
func TestReplaceRecoveryKeyAndBlobOverBoundRow(t *testing.T) {
	ctx := context.Background()
	store := rekeyTestStore(t)
	stepUp := RekeyGuard{Mode: RekeyStepUp, SessionTokenHash: "caller", VerifiedHash: "hash"}
	k1 := stepUpTestPackage("account-target")
	const outlier = int64(1) << 60
	if _, err := store.ReplaceRecoveryKeyAndBlobForSession(ctx, k1, rekeyBlob(outlier, "k1"), stepUp, noGenerationCeiling, 0); err != nil {
		t.Fatalf("seed outlier: %v", err)
	}
	const ceiling = int64(1) << 50
	k2 := k1
	k2.PhraseFingerprintHex = strings.Repeat("9", 16)
	if _, err := store.ReplaceRecoveryKeyAndBlobForSession(ctx, k2, rekeyBlob(100, "k2"), stepUp, ceiling, outlier-1); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("over-bound row with a wrong expectation: expected ErrStaleGeneration, got %v", err)
	}
	assertRekeyRows(t, store, k1.PhraseFingerprintHex, outlier, "k1")
	if _, err := store.ReplaceRecoveryKeyAndBlobForSession(ctx, k2, rekeyBlob(100, "k2"), stepUp, ceiling, outlier); err != nil {
		t.Fatalf("over-bound row with the matching expectation: %v", err)
	}
	assertRekeyRows(t, store, k2.PhraseFingerprintHex, 100, "k2")
}
