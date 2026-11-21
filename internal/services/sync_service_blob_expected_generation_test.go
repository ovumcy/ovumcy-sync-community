package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func expectGeneration(generation int64) *int64 { return &generation }

func TestPutBlobExpectedGenerationMatchCommits(t *testing.T) {
	svc, accountID, sessionHash, input := newBlobGenerationFixture(t)
	ctx := context.Background()
	base := time.Now().UTC().UnixMilli()

	input.Generation = base
	if _, err := svc.PutBlob(ctx, accountID, sessionHash, input); err != nil {
		t.Fatalf("first write: %v", err)
	}

	input.Generation = base + 1
	input.ExpectedGeneration = expectGeneration(base)
	stored, err := svc.PutBlob(ctx, accountID, sessionHash, input)
	if err != nil {
		t.Fatalf("matching expected_generation must commit, got %v", err)
	}
	if stored.Generation != base+1 {
		t.Fatalf("stored generation = %d, want %d", stored.Generation, base+1)
	}

	got, err := svc.GetBlob(ctx, accountID)
	if err != nil || got.Generation != base+1 {
		t.Fatalf("read back generation = %d (err %v), want %d", got.Generation, err, base+1)
	}
}

func TestPutBlobExpectedGenerationMismatchChangesNothing(t *testing.T) {
	svc, accountID, sessionHash, input := newBlobGenerationFixture(t)
	ctx := context.Background()
	base := time.Now().UTC().UnixMilli()

	input.Generation = base
	if _, err := svc.PutBlob(ctx, accountID, sessionHash, input); err != nil {
		t.Fatalf("first write: %v", err)
	}
	before, err := svc.GetBlob(ctx, accountID)
	if err != nil {
		t.Fatalf("read before: %v", err)
	}

	other := []byte("a different device's ciphertext")
	sum := sha256.Sum256(other)
	stale := input
	stale.Ciphertext = other
	stale.ChecksumSHA256 = hex.EncodeToString(sum[:])
	stale.Generation = base + 10
	// The baseline this device last saw, not what is stored: another device
	// has written since, so the write would silently drop that update.
	stale.ExpectedGeneration = expectGeneration(base - 1)
	if _, err := svc.PutBlob(ctx, accountID, sessionHash, stale); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("mismatched expected_generation: expected ErrStaleGeneration, got %v", err)
	}

	after, err := svc.GetBlob(ctx, accountID)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if after.Generation != before.Generation ||
		after.ChecksumSHA256 != before.ChecksumSHA256 ||
		string(after.Ciphertext) != string(before.Ciphertext) ||
		!after.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("a refused write changed the blob: before %+v after %+v", before, after)
	}
}

// expected_generation names a stored row; with none stored there is nothing
// to match, so the write is refused rather than treated as a first write.
func TestPutBlobExpectedGenerationWithNoStoredBlobIsRefused(t *testing.T) {
	svc, accountID, sessionHash, input := newBlobGenerationFixture(t)
	ctx := context.Background()

	input.Generation = time.Now().UTC().UnixMilli()
	input.ExpectedGeneration = expectGeneration(input.Generation - 1)
	if _, err := svc.PutBlob(ctx, accountID, sessionHash, input); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("expected ErrStaleGeneration with no stored blob, got %v", err)
	}
	if _, err := svc.GetBlob(ctx, accountID); !errors.Is(err, ErrBlobNotFound) {
		t.Fatalf("a refused write stored a blob: %v", err)
	}
}

// A match is necessary, not sufficient: the generation must still advance.
func TestPutBlobExpectedGenerationStillRequiresAnAdvance(t *testing.T) {
	svc, accountID, sessionHash, input := newBlobGenerationFixture(t)
	ctx := context.Background()
	base := time.Now().UTC().UnixMilli()

	input.Generation = base
	if _, err := svc.PutBlob(ctx, accountID, sessionHash, input); err != nil {
		t.Fatalf("first write: %v", err)
	}
	input.ExpectedGeneration = expectGeneration(base)
	for _, generation := range []int64{base, base - 1} {
		input.Generation = generation
		if _, err := svc.PutBlob(ctx, accountID, sessionHash, input); !errors.Is(err, ErrStaleGeneration) {
			t.Fatalf("generation %d with matching expected: expected ErrStaleGeneration, got %v", generation, err)
		}
	}
}

func TestPutBlobExpectedGenerationMustBePositive(t *testing.T) {
	svc, accountID, sessionHash, input := newBlobGenerationFixture(t)
	input.Generation = time.Now().UTC().UnixMilli()
	for _, expected := range []int64{0, -1} {
		input.ExpectedGeneration = expectGeneration(expected)
		if _, err := svc.PutBlob(context.Background(), accountID, sessionHash, input); !errors.Is(err, ErrInvalidBlob) {
			t.Fatalf("expected_generation %d: expected ErrInvalidBlob, got %v", expected, err)
		}
	}
}

func TestPutBlobWithoutExpectedGenerationKeepsLastWriterWins(t *testing.T) {
	svc, accountID, sessionHash, input := newBlobGenerationFixture(t)
	ctx := context.Background()
	base := time.Now().UTC().UnixMilli()

	for _, generation := range []int64{base, base + 5, base + 7} {
		input.Generation = generation
		if _, err := svc.PutBlob(ctx, accountID, sessionHash, input); err != nil {
			t.Fatalf("generation %d without expected_generation: %v", generation, err)
		}
	}
	input.Generation = base + 6
	if _, err := svc.PutBlob(ctx, accountID, sessionHash, input); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("regressing generation without expected_generation: expected ErrStaleGeneration, got %v", err)
	}
}

// Two devices holding the same baseline race with different generations:
// without the precondition both would commit in turn (the higher one last);
// with it exactly one commits.
func TestPutBlobConcurrentWritersOnOneBaselineCommitOnce(t *testing.T) {
	svc, accountID, sessionHash, input := newBlobGenerationFixture(t)
	ctx := context.Background()
	base := time.Now().UTC().UnixMilli()

	input.Generation = base
	if _, err := svc.PutBlob(ctx, accountID, sessionHash, input); err != nil {
		t.Fatalf("first write: %v", err)
	}

	const writers = 8
	var wins, stale atomic.Int32
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func(offset int64) {
			defer wg.Done()
			w := input
			w.Generation = base + offset
			w.ExpectedGeneration = expectGeneration(base)
			_, err := svc.PutBlob(ctx, accountID, sessionHash, w)
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, ErrStaleGeneration):
				stale.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}(int64(i + 1))
	}
	wg.Wait()

	if wins.Load() != 1 || stale.Load() != writers-1 {
		t.Fatalf("wins = %d, stale = %d; want exactly one winner", wins.Load(), stale.Load())
	}
}
