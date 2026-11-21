package services

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

// TestLapsedAccountSweepCheckpointsOncePerErasingPage pins the WAL checkpoint
// cadence: one per page that erased something, none for a page that erased
// nothing, and one for a page a cap cut short.
func TestLapsedAccountSweepCheckpointsOncePerErasingPage(t *testing.T) {
	ctx := context.Background()

	t.Run("full pages", func(t *testing.T) {
		store := newScriptedSweepStore(7)
		for _, id := range []string{"scripted0004", "scripted0005", "scripted0006"} {
			store.outcomes[id] = db.ErrNotFound
		}
		if _, err := scriptedSweepService(store).Run(ctx, 3, false); err != nil {
			t.Fatalf("run: %v", err)
		}
		if want := []int{3, 7}; !slices.Equal(store.checkpoints, want) {
			t.Fatalf("checkpoints at deletes %v, want %v", store.checkpoints, want)
		}
	})

	t.Run("capped mid-page", func(t *testing.T) {
		store := newScriptedSweepStore(7)
		result, err := scriptedSweepService(store).WithMaxDeletesPerRun(2).Run(ctx, 3, false)
		if err != nil || !result.Capped {
			t.Fatalf("run: capped=%v err=%v", result.Capped, err)
		}
		if want := []int{2}; !slices.Equal(store.checkpoints, want) {
			t.Fatalf("checkpoints at deletes %v, want %v", store.checkpoints, want)
		}
	})

	t.Run("dry run", func(t *testing.T) {
		store := newScriptedSweepStore(7)
		if _, err := scriptedSweepService(store).Run(ctx, 3, true); err != nil {
			t.Fatalf("run: %v", err)
		}
		if len(store.checkpoints) != 0 {
			t.Fatalf("dry run checkpointed at %v", store.checkpoints)
		}
	})
}

// TestLapsedAccountSweepTruncatesTheWALAfterErasing runs the sweep on a real
// file-backed store: the lapsed-account delete no longer checkpoints by
// itself, so a non-empty -wal after the run means the sweep skipped it.
func TestLapsedAccountSweepTruncatesTheWALAfterErasing(t *testing.T) {
	store, dbPath := openFileBackedTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, id := range []string{"managedlapsed1", "managedlapsed2", "managedlapsed3"} {
		if _, err := store.CreateAccount(ctx, models.Account{
			ID: id, Login: "managed:" + id, PasswordHash: "x", RecoveryCodeHash: "y",
			Mode: "managed", CreatedAt: now,
		}); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
		if err := store.SetAccountLapsed(ctx, id, now.Add(-90*24*time.Hour)); err != nil {
			t.Fatalf("lapse %s: %v", id, err)
		}
	}

	result, err := NewLapsedAccountSweepService(store, lapsedSweepGracePeriod).Run(ctx, 2, false)
	if err != nil || result.Deleted != 3 {
		t.Fatalf("run: deleted=%d err=%v", result.Deleted, err)
	}
	info, err := os.Stat(dbPath + "-wal")
	if err != nil {
		t.Fatalf("stat wal: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("-wal holds %d bytes after the sweep, want 0 (truncated)", info.Size())
	}
}
