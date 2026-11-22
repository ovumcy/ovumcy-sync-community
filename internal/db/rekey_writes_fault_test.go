package db

import (
	"context"
	"errors"
	"testing"
)

// Each store failure inside the re-key transaction surfaces as an error and
// commits nothing; none is mistaken for a refusal key.
func TestReplaceRecoveryKeyAndBlobSurfacesStoreFailures(t *testing.T) {
	ctx := context.Background()
	k1 := stepUpTestPackage("account-target")
	refusals := []error{ErrStaleGeneration, ErrRecoveryKeyChanged, ErrConflict, ErrSessionRevoked}

	for name, guard := range map[string]RekeyGuard{
		"step-up upsert":       {Mode: RekeyStepUp, SessionTokenHash: "caller", VerifiedHash: "hash"},
		"first managed insert": {Mode: RekeyFirstManaged, SessionTokenHash: "caller"},
		"keep package read":    {Mode: RekeyKeepPackage, SessionTokenHash: "caller"},
	} {
		t.Run(name, func(t *testing.T) {
			store := rekeyTestStore(t)
			if _, err := store.db.ExecContext(ctx, `DROP TABLE recovery_key_packages`); err != nil {
				t.Fatalf("drop recovery_key_packages: %v", err)
			}
			_, err := store.ReplaceRecoveryKeyAndBlobForSession(ctx, k1, rekeyBlob(10, "k1"), guard, noGenerationCeiling, 0)
			if err == nil {
				t.Fatal("expected a store error")
			}
			for _, refusal := range refusals {
				if errors.Is(err, refusal) {
					t.Fatalf("store failure mapped to refusal %v", refusal)
				}
			}
			if _, err := store.GetEncryptedBlob(ctx, "account-target"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("a failed rekey stored a blob: %v", err)
			}
		})
	}

	t.Run("begin", func(t *testing.T) {
		store := rekeyTestStore(t)
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
		guard := RekeyGuard{Mode: RekeyKeepPackage, SessionTokenHash: "caller"}
		if _, err := store.ReplaceRecoveryKeyAndBlobForSession(ctx, k1, rekeyBlob(10, "k1"), guard, noGenerationCeiling, 0); err == nil {
			t.Fatal("expected begin to fail on a closed store")
		}
	})
}

func TestEncryptedBlobGenerationReadsWithoutCiphertext(t *testing.T) {
	ctx := context.Background()
	store := rekeyTestStore(t)

	if _, found, err := store.EncryptedBlobGeneration(ctx, "account-target"); err != nil || found {
		t.Fatalf("no blob: found=%v err=%v", found, err)
	}
	guard := RekeyGuard{Mode: RekeyStepUp, SessionTokenHash: "caller", VerifiedHash: "hash"}
	if _, err := store.ReplaceRecoveryKeyAndBlobForSession(ctx, stepUpTestPackage("account-target"), rekeyBlob(10, "k1"), guard, noGenerationCeiling, 0); err != nil {
		t.Fatalf("seed rekey: %v", err)
	}
	if generation, found, err := store.EncryptedBlobGeneration(ctx, "account-target"); err != nil || !found || generation != 10 {
		t.Fatalf("stored blob: generation=%d found=%v err=%v", generation, found, err)
	}

	if _, err := store.db.ExecContext(ctx, `DROP TABLE encrypted_blobs`); err != nil {
		t.Fatalf("drop encrypted_blobs: %v", err)
	}
	if _, _, err := store.EncryptedBlobGeneration(ctx, "account-target"); err == nil {
		t.Fatal("expected a lookup error with the table gone")
	}
}
