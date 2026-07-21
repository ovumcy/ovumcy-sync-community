package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/services"
)

// recordingSweeper stands in for *services.LapsedAccountSweepService so the
// loop can be driven through every run outcome without a database. It reports
// each call on a channel, which is what lets a test wait for a real tick
// instead of sleeping and hoping.
type recordingSweeper struct {
	mu     sync.Mutex
	calls  int
	limits []int
	dryRun []bool

	result services.LapsedAccountSweepResult
	err    error

	observed chan struct{}
}

func newRecordingSweeper(result services.LapsedAccountSweepResult, err error) *recordingSweeper {
	return &recordingSweeper{
		result:   result,
		err:      err,
		observed: make(chan struct{}, 8),
	}
}

func (s *recordingSweeper) Run(
	_ context.Context,
	limit int,
	dryRun bool,
) (services.LapsedAccountSweepResult, error) {
	s.mu.Lock()
	s.calls++
	s.limits = append(s.limits, limit)
	s.dryRun = append(s.dryRun, dryRun)
	result, err := s.result, s.err
	s.mu.Unlock()

	select {
	case s.observed <- struct{}{}:
	default:
	}
	return result, err
}

func (s *recordingSweeper) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// waitForRun blocks until the loop has run the sweep at least once, so the
// assertions below never depend on wall-clock timing.
func (s *recordingSweeper) waitForRun(t *testing.T) {
	t.Helper()
	select {
	case <-s.observed:
	case <-time.After(2 * time.Second):
		t.Fatal("the sweep never ran")
	}
}

// TestLapsedAccountSweepLoopRunsTheSweepForReal is the point of the whole
// change: with an interval configured, the purge happens on its own. It also
// pins that the loop never runs in dry-run mode — a loop that only reports
// would leave retention exactly as unenforced as no loop at all.
func TestLapsedAccountSweepLoopRunsTheSweepForReal(t *testing.T) {
	sweeper := newRecordingSweeper(services.LapsedAccountSweepResult{
		Examined:          3,
		Deleted:           1,
		DeletedAccountIDs: []string{"account-1"},
	}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runLapsedAccountSweepLoop(ctx, sweeper, time.Millisecond, 25)

	sweeper.waitForRun(t)
	cancel()

	sweeper.mu.Lock()
	defer sweeper.mu.Unlock()
	if sweeper.dryRun[0] {
		t.Fatal("the in-process loop must delete, not merely report")
	}
	if sweeper.limits[0] != 25 {
		t.Fatalf("expected the configured limit 25 to reach the sweep, got %d", sweeper.limits[0])
	}
}

// TestLapsedAccountSweepLoopStaysDisabledWithoutAnInterval covers the rollback
// lever. A non-positive interval must leave the purge to the subcommand
// entirely — an operator who turned the loop off after an incident needs it to
// stay off, and needs that to take effect from configuration alone.
func TestLapsedAccountSweepLoopStaysDisabledWithoutAnInterval(t *testing.T) {
	for name, interval := range map[string]time.Duration{
		"zero":     0,
		"negative": -time.Hour,
	} {
		t.Run(name, func(t *testing.T) {
			sweeper := newRecordingSweeper(services.LapsedAccountSweepResult{}, nil)

			// Returns rather than blocking: a disabled loop must not leak a
			// goroutine that wakes up later.
			runLapsedAccountSweepLoop(context.Background(), sweeper, interval, 0)

			if sweeper.callCount() != 0 {
				t.Fatalf("expected no sweep at all, got %d", sweeper.callCount())
			}
		})
	}
}

// TestLapsedAccountSweepLoopStaysDisabledWithoutASweeper is the nil-guard: a
// wiring regression that forgets the service must degrade to "no purge", never
// to a panic inside a background goroutine that would take the server with it.
func TestLapsedAccountSweepLoopStaysDisabledWithoutASweeper(t *testing.T) {
	runLapsedAccountSweepLoop(context.Background(), nil, time.Millisecond, 0)
}

// TestLapsedAccountSweepLoopKeepsRunningAfterAFailedRun pins the failure
// policy. A storage error is transient by nature — a locked database, a full
// disk — and a loop that gave up on the first one would silently stop
// enforcing retention for the lifetime of the process, which is the exact
// failure this change exists to remove.
func TestLapsedAccountSweepLoopKeepsRunningAfterAFailedRun(t *testing.T) {
	sweeper := newRecordingSweeper(
		services.LapsedAccountSweepResult{Examined: 2},
		errors.New("database is locked"),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runLapsedAccountSweepLoop(ctx, sweeper, time.Millisecond, 0)

	sweeper.waitForRun(t)
	sweeper.waitForRun(t)
	cancel()

	if sweeper.callCount() < 2 {
		t.Fatalf("expected the loop to survive a failed run, got %d calls", sweeper.callCount())
	}
}

// TestLapsedAccountSweepLoopStopsWithItsContext pins the lifetime bound: the
// signal that stops the server stops the purge too, so a terminating container
// never starts a delete it will not finish.
func TestLapsedAccountSweepLoopStopsWithItsContext(t *testing.T) {
	sweeper := newRecordingSweeper(services.LapsedAccountSweepResult{}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	go func() {
		runLapsedAccountSweepLoop(ctx, sweeper, time.Hour, 0)
		close(finished)
	}()

	cancel()

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("the loop ignored its cancelled context")
	}
}
