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

func TestPutBlobRejectsGenerationNearInt64Ceiling(t *testing.T) {
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	sync := NewSyncService(store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 16 << 20})

	reg, err := auth.Register(context.Background(), "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	ciphertext := []byte("ciphertext-only-payload")
	sum := sha256.Sum256(ciphertext)
	input := PutBlobInput{
		SchemaVersion:  1,
		Generation:     math.MaxInt64,
		ChecksumSHA256: hex.EncodeToString(sum[:]),
		Ciphertext:     ciphertext,
	}

	// A maximal generation is rejected before it can strand the blob at a value
	// no future strictly-greater write could ever reach.
	if _, err := sync.PutBlob(context.Background(), reg.AccountID, input); !errors.Is(err, ErrInvalidBlob) {
		t.Fatalf("expected ErrInvalidBlob for MaxInt64 generation, got %v", err)
	}

	// A realistic millisecond-timestamp generation (what the client actually
	// sends) is far below the cap and must still be accepted.
	input.Generation = time.Now().UnixMilli()
	if _, err := sync.PutBlob(context.Background(), reg.AccountID, input); err != nil {
		t.Fatalf("legitimate ms-timestamp generation must be accepted, got %v", err)
	}
}
