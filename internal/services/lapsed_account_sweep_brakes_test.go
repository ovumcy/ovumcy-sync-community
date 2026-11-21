package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
)

// scriptedSweepStore serves a fixed, keyset-ordered candidate list and scripts
// the outcome of each delete by account id, so the run-level brakes (the
// per-run delete cap, the consecutive-failure abort) are pinned without a
// database. A candidate absent from outcomes deletes successfully.
type scriptedSweepStore struct {
	candidates []db.LapsedCandidate
	outcomes   map[string]error
	deleteLog  []string
	// checkpoints holds len(deleteLog) at each CheckpointAfterErase call.
	checkpoints []int
}

func (s *scriptedSweepStore) CheckpointAfterErase(context.Context) {
	s.checkpoints = append(s.checkpoints, len(s.deleteLog))
}

func newScriptedSweepStore(n int) *scriptedSweepStore {
	store := &scriptedSweepStore{outcomes: map[string]error{}}
	for i := 1; i <= n; i++ {
		store.candidates = append(store.candidates, db.LapsedCandidate{
			ID:       fmt.Sprintf("scripted%04d", i),
			LapsedAt: fmt.Sprintf("2026-01-%02dT00:00:00Z", i),
		})
	}
	return store
}

func (s *scriptedSweepStore) ListLapsedManagedAccountIDs(_ context.Context, _ time.Time, after db.LapsedCandidate, limit int) ([]db.LapsedCandidate, error) {
	var page []db.LapsedCandidate
	for _, candidate := range s.candidates {
		if after.ID != "" && candidate.ID <= after.ID {
			continue
		}
		page = append(page, candidate)
		if len(page) == limit {
			break
		}
	}
	return page, nil
}

func (s *scriptedSweepStore) DeleteLapsedManagedAccount(_ context.Context, accountID string, _ time.Time) error {
	s.deleteLog = append(s.deleteLog, accountID)
	return s.outcomes[accountID]
}

func scriptedSweepService(store *scriptedSweepStore) *LapsedAccountSweepService {
	return &LapsedAccountSweepService{store: store, now: time.Now, gracePeriod: lapsedSweepGracePeriod}
}

// TestLapsedAccountSweepServiceStopsAtThePerRunDeleteCap pins the clock-jump
// brake: with a cap of 3 over 7 eligible accounts, one run erases exactly 3
// (across page boundaries) and reports Capped; a dry run is never capped; and
// the unset cap keeps the full drain.
func TestLapsedAccountSweepServiceStopsAtThePerRunDeleteCap(t *testing.T) {
	ctx := context.Background()

	store := newScriptedSweepStore(7)
	capped := scriptedSweepService(store).WithMaxDeletesPerRun(3)
	result, err := capped.Run(ctx, 2, false)
	if err != nil {
		t.Fatalf("run capped sweep: %v", err)
	}
	if result.Deleted != 3 || len(result.DeletedAccountIDs) != 3 || !result.Capped {
		t.Fatalf("expected exactly 3 deleted and Capped, got %#v", result)
	}
	if result.Examined != 3 || len(store.deleteLog) != 3 {
		t.Fatalf("expected the run to stop before examining past the cap, got examined=%d deletes=%d", result.Examined, len(store.deleteLog))
	}

	dry, err := capped.Run(ctx, 2, true)
	if err != nil {
		t.Fatalf("run capped dry run: %v", err)
	}
	if dry.Examined != 7 || dry.Deleted != 0 || dry.Capped {
		t.Fatalf("expected the dry run to report all 7 eligible uncapped, got %#v", dry)
	}

	unbounded := scriptedSweepService(newScriptedSweepStore(7))
	full, err := unbounded.Run(ctx, 2, false)
	if err != nil {
		t.Fatalf("run unbounded sweep: %v", err)
	}
	if full.Deleted != 7 || full.Capped {
		t.Fatalf("expected the default (no cap) to drain all 7, got %#v", full)
	}
}

// TestLapsedAccountSweepServiceCapEqualToEligibleCountIsNotCapped pins the
// boundary: a run that deletes exactly the cap with nothing left behind is a
// complete drain, not a truncated one.
func TestLapsedAccountSweepServiceCapEqualToEligibleCountIsNotCapped(t *testing.T) {
	store := newScriptedSweepStore(3)
	result, err := scriptedSweepService(store).WithMaxDeletesPerRun(3).Run(context.Background(), 2, false)
	if err != nil {
		t.Fatalf("run sweep: %v", err)
	}
	if result.Deleted != 3 || result.Capped {
		t.Fatalf("expected a complete drain at cap == eligible, got %#v", result)
	}
}

// TestLapsedAccountSweepServiceAbortsAfterConsecutiveDeleteFailures pins the
// persistent-fault brake: with every delete failing, the run stops after the
// fifth consecutive failure instead of walking all 20 candidates, joins
// ErrLapsedSweepAborted, and names no account id.
func TestLapsedAccountSweepServiceAbortsAfterConsecutiveDeleteFailures(t *testing.T) {
	store := newScriptedSweepStore(20)
	for _, candidate := range store.candidates {
		store.outcomes[candidate.ID] = errors.New("database is locked")
	}

	result, err := scriptedSweepService(store).Run(context.Background(), 4, false)
	if !errors.Is(err, ErrLapsedSweepAborted) {
		t.Fatalf("expected ErrLapsedSweepAborted, got %v", err)
	}
	if len(store.deleteLog) != maxConsecutiveLapsedDeleteFailures || result.Examined != maxConsecutiveLapsedDeleteFailures {
		t.Fatalf("expected %d delete attempts before the abort, got %d (examined %d)", maxConsecutiveLapsedDeleteFailures, len(store.deleteLog), result.Examined)
	}
	if result.Deleted != 0 || result.Capped {
		t.Fatalf("expected nothing deleted and no cap flag, got %#v", result)
	}
	if strings.Contains(err.Error(), "scripted") {
		t.Fatalf("the abort error must name no account id, got %v", err)
	}
}

// TestLapsedAccountSweepServiceDeleteFailureStreakResets proves the abort
// counts CONSECUTIVE failures: failures separated by a success or by the
// benign db.ErrNotFound skip never add up, so a few unlucky rows do not end a
// run that is otherwise healthy.
func TestLapsedAccountSweepServiceDeleteFailureStreakResets(t *testing.T) {
	store := newScriptedSweepStore(12)
	boom := errors.New("database is locked")
	for i, candidate := range store.candidates {
		switch i % 5 {
		case 4:
			// every fifth candidate succeeds (no outcome entry)
		case 3:
			store.outcomes[candidate.ID] = db.ErrNotFound
		default:
			store.outcomes[candidate.ID] = boom
		}
	}

	result, err := scriptedSweepService(store).Run(context.Background(), 5, false)
	if errors.Is(err, ErrLapsedSweepAborted) {
		t.Fatalf("a failure streak broken by a skip or a success must not abort, got %v", err)
	}
	if err == nil {
		t.Fatal("expected the scattered failures to still be reported")
	}
	if result.Examined != 12 || len(store.deleteLog) != 12 {
		t.Fatalf("expected every candidate attempted, got examined=%d deletes=%d", result.Examined, len(store.deleteLog))
	}
}

// TestLapsedAccountSweepServiceRowSpecificFailuresAtTheHeadDoNotShieldLaterRows
// pins the erasure guarantee: rows whose delete fails permanently with a
// row-specific error, more of them than the abort streak allows, are skipped,
// and every later lapsed account is still erased in the same run, no abort.
func TestLapsedAccountSweepServiceRowSpecificFailuresAtTheHeadDoNotShieldLaterRows(t *testing.T) {
	store := newScriptedSweepStore(20)
	stuck := 2 * maxConsecutiveLapsedDeleteFailures
	for _, candidate := range store.candidates[:stuck] {
		store.outcomes[candidate.ID] = errors.New("FOREIGN KEY constraint failed")
	}

	result, err := scriptedSweepService(store).Run(context.Background(), 4, false)
	if errors.Is(err, ErrLapsedSweepAborted) {
		t.Fatalf("row-specific failures must not abort the run, got %v", err)
	}
	if err == nil {
		t.Fatal("expected the skipped rows' failures to still be reported")
	}
	if result.Examined != 20 || result.Deleted != 20-stuck {
		t.Fatalf("expected 20 examined and %d erased past the stuck head, got %#v", 20-stuck, result)
	}
}

// TestLapsedAccountSweepServiceStoreWideFailureStreakStillAborts keeps the
// abort for every failure that is not row-specific: a streak of BUSY, LOCKED,
// READONLY, IOERR, FULL, a missing table, a closed store or a deadline error
// from the delete itself ends the run at the limit.
func TestLapsedAccountSweepServiceStoreWideFailureStreakStillAborts(t *testing.T) {
	for _, failure := range []error{
		errors.New("database is locked (5) (SQLITE_BUSY)"),
		errors.New("database table is locked (6) (SQLITE_LOCKED)"),
		errors.New("attempt to write a readonly database (8) (SQLITE_READONLY)"),
		errors.New("disk I/O error (10) (SQLITE_IOERR)"),
		errors.New("database or disk is full (13) (SQLITE_FULL)"),
		errors.New("no such table: accounts"),
		errors.New("sql: database is closed"),
		context.DeadlineExceeded,
	} {
		store := newScriptedSweepStore(20)
		for _, candidate := range store.candidates {
			store.outcomes[candidate.ID] = failure
		}
		_, err := scriptedSweepService(store).Run(context.Background(), 4, false)
		if !errors.Is(err, ErrLapsedSweepAborted) || len(store.deleteLog) != maxConsecutiveLapsedDeleteFailures {
			t.Fatalf("%v: expected an abort after %d attempts, got %d attempts, err %v", failure, maxConsecutiveLapsedDeleteFailures, len(store.deleteLog), err)
		}
	}
}

// TestLapsedAccountSweepServiceRowFaultsBetweenStoreFaultsStillAbort keeps the
// brake when store faults alternate with row-specific ones: a skipped row
// leaves the streak as it is instead of resetting it.
func TestLapsedAccountSweepServiceRowFaultsBetweenStoreFaultsStillAbort(t *testing.T) {
	store := newScriptedSweepStore(20)
	for i, candidate := range store.candidates {
		if i%2 == 0 {
			store.outcomes[candidate.ID] = errors.New("database is locked (5) (SQLITE_BUSY)")
		} else {
			store.outcomes[candidate.ID] = errors.New("FOREIGN KEY constraint failed")
		}
	}
	_, err := scriptedSweepService(store).Run(context.Background(), 4, false)
	want := 2*maxConsecutiveLapsedDeleteFailures - 1
	if !errors.Is(err, ErrLapsedSweepAborted) || len(store.deleteLog) != want {
		t.Fatalf("expected an abort after %d attempts, got %d attempts, err %v", want, len(store.deleteLog), err)
	}
}
