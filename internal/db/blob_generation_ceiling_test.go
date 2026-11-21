package db

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

// noGenerationCeiling disables the stored-outlier replacement: no stored
// generation exceeds it, so only a strictly greater generation wins.
const noGenerationCeiling int64 = math.MaxInt64

// v030BlobGenerationCap is the constant ceiling v0.3.0 accepted.
const v030BlobGenerationCap int64 = math.MaxInt64 - (1 << 32)

func seedBlobAccount(t *testing.T) (*Store, string, string) {
	t.Helper()
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := store.CreateAccount(ctx, models.Account{
		ID: "blob-acct", Login: "blob@example.com", PasswordHash: "hash", CreatedAt: now,
	}); err != nil {
		t.Fatalf("create account: %v", err)
	}
	if _, err := store.CreateSession(ctx, models.Session{
		ID: "blob-session", AccountID: "blob-acct", TokenHash: "blob-token",
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}
	return store, "blob-acct", "blob-token"
}

func ceilingTestBlob(accountID string, generation int64, body string) models.EncryptedBlob {
	return models.EncryptedBlob{
		AccountID:      accountID,
		SchemaVersion:  3,
		Generation:     generation,
		ChecksumSHA256: strings.Repeat(body[:1], 64),
		Ciphertext:     []byte(body),
		CiphertextSize: len(body),
		UpdatedAt:      time.Now().UTC(),
	}
}

// A generation stored above the caller's ceiling (v0.3.0 accepted up to
// MaxInt64-2^32) must not strand the blob: the next valid write replaces the
// whole row, even though its generation is lower.
func TestUpsertEncryptedBlobReplacesAStoredGenerationAboveTheCeiling(t *testing.T) {
	store, accountID, token := seedBlobAccount(t)
	ctx := context.Background()

	if _, err := store.UpsertEncryptedBlob(ctx, token, noGenerationCeiling, ceilingTestBlob(accountID, v030BlobGenerationCap, "old-ciphertext")); err != nil {
		t.Fatalf("seed outlier: %v", err)
	}

	ceiling := time.Now().UTC().Add(15 * time.Minute).UnixMilli()
	next := ceilingTestBlob(accountID, time.Now().UTC().UnixMilli(), "bnew-ciphertext")
	if _, err := store.UpsertEncryptedBlob(ctx, token, ceiling, next); err != nil {
		t.Fatalf("write over a stored outlier must succeed, got %v", err)
	}

	got, err := store.GetEncryptedBlob(ctx, accountID)
	if err != nil {
		t.Fatalf("get blob: %v", err)
	}
	if got.Generation != next.Generation || string(got.Ciphertext) != "bnew-ciphertext" || got.ChecksumSHA256 != next.ChecksumSHA256 {
		t.Fatalf("row not replaced whole: generation=%d ciphertext=%q checksum=%s", got.Generation, got.Ciphertext, got.ChecksumSHA256)
	}

	// The escape fires once: the replaced row is inside the ceiling, so the
	// strict-greater CAS governs it again.
	stale := ceilingTestBlob(accountID, next.Generation, "cstale-ciphertext")
	if _, err := store.UpsertEncryptedBlob(ctx, token, ceiling, stale); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("equal generation after replacement: want ErrStaleGeneration, got %v", err)
	}
}

// A stored generation at or below the ceiling keeps the strict-greater CAS:
// a lower or equal write is stale and changes nothing.
func TestUpsertEncryptedBlobKeepsStaleRejectionWithinTheCeiling(t *testing.T) {
	store, accountID, token := seedBlobAccount(t)
	ctx := context.Background()

	ceiling := time.Now().UTC().Add(15 * time.Minute).UnixMilli()
	stored := ceilingTestBlob(accountID, ceiling, "aparked-ciphertext")
	if _, err := store.UpsertEncryptedBlob(ctx, token, ceiling, stored); err != nil {
		t.Fatalf("seed at the ceiling: %v", err)
	}

	for _, generation := range []int64{ceiling - 1, ceiling} {
		if _, err := store.UpsertEncryptedBlob(ctx, token, ceiling, ceilingTestBlob(accountID, generation, "blower-ciphertext")); !errors.Is(err, ErrStaleGeneration) {
			t.Fatalf("generation %d: want ErrStaleGeneration, got %v", generation, err)
		}
	}

	got, err := store.GetEncryptedBlob(ctx, accountID)
	if err != nil {
		t.Fatalf("get blob: %v", err)
	}
	if got.Generation != ceiling || string(got.Ciphertext) != "aparked-ciphertext" {
		t.Fatalf("stale writes changed the row: generation=%d ciphertext=%q", got.Generation, got.Ciphertext)
	}
}
