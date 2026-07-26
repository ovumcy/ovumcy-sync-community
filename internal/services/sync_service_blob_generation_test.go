package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"testing"
	"time"
)

func newBlobGenerationFixture(t *testing.T) (*SyncService, string, PutBlobInput) {
	t.Helper()

	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	sync := NewSyncService(store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 16 << 20})

	reg, err := auth.Register(context.Background(), "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	ciphertext := []byte("ciphertext-only-payload")
	sum := sha256.Sum256(ciphertext)
	return sync, reg.AccountID, PutBlobInput{
		SchemaVersion:  1,
		ChecksumSHA256: hex.EncodeToString(sum[:]),
		Ciphertext:     ciphertext,
	}
}

func TestPutBlobRejectsGenerationFarAheadOfServerTime(t *testing.T) {
	sync, accountID, input := newBlobGenerationFixture(t)

	for _, generation := range []int64{
		math.MaxInt64,
		// The previous fixed ceiling. It was accepted, and the CAS then
		// demanded a strictly greater value that validation refused, so this
		// single write bricked the blob permanently.
		math.MaxInt64 - (1 << 32),
		time.Now().UTC().Add(blobGenerationSkew + time.Hour).UnixMilli(),
	} {
		input.Generation = generation
		if _, err := sync.PutBlob(context.Background(), accountID, input); !errors.Is(err, ErrInvalidBlob) {
			t.Fatalf("generation %d: expected ErrInvalidBlob, got %v", generation, err)
		}
	}

	// None of the rejected writes may have left the account unwritable.
	input.Generation = time.Now().UTC().UnixMilli()
	if _, err := sync.PutBlob(context.Background(), accountID, input); err != nil {
		t.Fatalf("legitimate ms-timestamp generation must be accepted, got %v", err)
	}
}

// The property a fixed ceiling cannot have: whatever generation was accepted,
// a later write still beats it once the clock has moved on. Without this there
// is always some value that ends the blob's life.
func TestPutBlobHasNoTerminalGeneration(t *testing.T) {
	sync, accountID, input := newBlobGenerationFixture(t)

	base := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	sync.now = func() time.Time { return base }

	ceiling := maxAcceptableBlobGeneration(base)
	input.Generation = ceiling
	if _, err := sync.PutBlob(context.Background(), accountID, input); err != nil {
		t.Fatalf("generation at the ceiling must be accepted, got %v", err)
	}

	// Still at the same instant, one past the ceiling is refused.
	input.Generation = ceiling + 1
	if _, err := sync.PutBlob(context.Background(), accountID, input); !errors.Is(err, ErrInvalidBlob) {
		t.Fatalf("expected ErrInvalidBlob one past the ceiling, got %v", err)
	}

	// Move the clock a day on. The same value is now inside the bound, so the
	// blob written at the old ceiling is replaceable rather than frozen.
	sync.now = func() time.Time { return base.Add(24 * time.Hour) }
	if _, err := sync.PutBlob(context.Background(), accountID, input); err != nil {
		t.Fatalf("blob must be replaceable once the clock passes the old ceiling, got %v", err)
	}
}

func TestPutBlobStillRejectsStaleGenerationWithinTheBound(t *testing.T) {
	sync, accountID, input := newBlobGenerationFixture(t)

	input.Generation = time.Now().UTC().UnixMilli()
	if _, err := sync.PutBlob(context.Background(), accountID, input); err != nil {
		t.Fatalf("first write: %v", err)
	}

	// Widening the upper bound must not have loosened the CAS underneath it.
	input.Generation--
	if _, err := sync.PutBlob(context.Background(), accountID, input); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("expected ErrStaleGeneration for a regressing write, got %v", err)
	}
}
