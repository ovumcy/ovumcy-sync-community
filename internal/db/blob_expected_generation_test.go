package db

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestUpsertEncryptedBlobExpectingGuards(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	account := expiredRowsFixtureAccount(t, store, "expected-gen")
	createSessionExpiringAt(t, store, account.ID, "expected-gen", time.Now().UTC().Add(time.Hour))
	const tokenHash = "hash-expected-gen"
	expect := func(g int64) *int64 { return &g }

	first := lateBodyBlob(account.ID)
	first.Generation = 10
	if _, err := store.UpsertEncryptedBlobExpecting(ctx, tokenHash, noGenerationCeiling, first, expect(9)); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("expected generation with no stored row: want ErrStaleGeneration, got %v", err)
	}
	if _, err := store.GetEncryptedBlob(ctx, account.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("refused write inserted a row: %v", err)
	}

	if _, err := store.UpsertEncryptedBlobExpecting(ctx, tokenHash, noGenerationCeiling, first, nil); err != nil {
		t.Fatalf("absent expected generation inserts: %v", err)
	}

	mismatch := lateBodyBlob(account.ID)
	mismatch.Generation = 20
	mismatch.Ciphertext = []byte("other")
	mismatch.CiphertextSize = len("other")
	for _, expected := range []int64{9, 11} {
		if _, err := store.UpsertEncryptedBlobExpecting(ctx, tokenHash, noGenerationCeiling, mismatch, expect(expected)); !errors.Is(err, ErrStaleGeneration) {
			t.Fatalf("expected %d vs stored 10: want ErrStaleGeneration, got %v", expected, err)
		}
	}
	got, err := store.GetEncryptedBlob(ctx, account.ID)
	if err != nil || got.Generation != 10 || string(got.Ciphertext) != "ciphertext" {
		t.Fatalf("mismatch changed the row: generation %d ciphertext %q err %v", got.Generation, got.Ciphertext, err)
	}

	notAdvancing := lateBodyBlob(account.ID)
	notAdvancing.Generation = 10
	if _, err := store.UpsertEncryptedBlobExpecting(ctx, tokenHash, noGenerationCeiling, notAdvancing, expect(10)); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("matching expected but equal generation: want ErrStaleGeneration, got %v", err)
	}

	if _, err := store.UpsertEncryptedBlobExpecting(ctx, tokenHash, noGenerationCeiling, mismatch, expect(10)); err != nil {
		t.Fatalf("matching expected generation commits: %v", err)
	}
	got, err = store.GetEncryptedBlob(ctx, account.ID)
	if err != nil || got.Generation != 20 || string(got.Ciphertext) != "other" {
		t.Fatalf("match did not store the write: generation %d ciphertext %q err %v", got.Generation, got.Ciphertext, err)
	}
}

// Over a stored generation above the ceiling, the precondition still decides:
// a matching expected generation commits a lower generation, a mismatch is
// refused and leaves the row as it was.
func TestUpsertEncryptedBlobExpectingOverAStoredGenerationAboveTheCeiling(t *testing.T) {
	store, accountID, token := seedBlobAccount(t)
	ctx := context.Background()

	if _, err := store.UpsertEncryptedBlob(ctx, token, noGenerationCeiling, ceilingTestBlob(accountID, v030BlobGenerationCap, "old-ciphertext")); err != nil {
		t.Fatalf("seed outlier: %v", err)
	}
	ceiling := time.Now().UTC().Add(15 * time.Minute).UnixMilli()
	next := ceilingTestBlob(accountID, time.Now().UTC().UnixMilli(), "bnew-ciphertext")

	wrong := v030BlobGenerationCap - 1
	if _, err := store.UpsertEncryptedBlobExpecting(ctx, token, ceiling, next, &wrong); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("expected mismatch over an outlier: want ErrStaleGeneration, got %v", err)
	}
	got, err := store.GetEncryptedBlob(ctx, accountID)
	if err != nil || got.Generation != v030BlobGenerationCap || string(got.Ciphertext) != "old-ciphertext" {
		t.Fatalf("mismatch changed the outlier row: generation %d ciphertext %q err %v", got.Generation, got.Ciphertext, err)
	}

	match := v030BlobGenerationCap
	if _, err := store.UpsertEncryptedBlobExpecting(ctx, token, ceiling, next, &match); err != nil {
		t.Fatalf("matching expected over an outlier must commit, got %v", err)
	}
	got, err = store.GetEncryptedBlob(ctx, accountID)
	if err != nil || got.Generation != next.Generation || string(got.Ciphertext) != "bnew-ciphertext" {
		t.Fatalf("match did not replace the outlier: generation %d ciphertext %q err %v", got.Generation, got.Ciphertext, err)
	}
}

func TestUpsertEncryptedBlobExpectingNeedsTheCallersSession(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	account := expiredRowsFixtureAccount(t, store, "expected-gen-revoked")
	createSessionExpiringAt(t, store, account.ID, "expected-gen-revoked", time.Now().UTC().Add(time.Hour))
	const tokenHash = "hash-expected-gen-revoked"

	first := lateBodyBlob(account.ID)
	if _, err := store.UpsertEncryptedBlob(ctx, tokenHash, noGenerationCeiling, first); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if _, err := store.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash); err != nil {
		t.Fatalf("revoke session: %v", err)
	}

	next := lateBodyBlob(account.ID)
	next.Generation = 2
	expected := first.Generation
	if _, err := store.UpsertEncryptedBlobExpecting(ctx, tokenHash, noGenerationCeiling, next, &expected); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("revoked session: want ErrSessionRevoked, got %v", err)
	}
	got, err := store.GetEncryptedBlob(ctx, account.ID)
	if err != nil || got.Generation != 1 {
		t.Fatalf("revoked-session write changed the row: generation %d err %v", got.Generation, err)
	}
}
