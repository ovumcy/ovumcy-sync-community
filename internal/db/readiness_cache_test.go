package db

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCheckReadyReusesItsAnswerWithinTheTTL(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)

	if err := store.CheckReady(context.Background()); err != nil {
		t.Fatalf("expected a migrated database to be ready, got %v", err)
	}

	recordAppliedMigration(t, dbPath, futureMigrationVersion)

	// Re-stamp the cached answer so a slow runner cannot outlast the TTL
	// between the two checks.
	store.ready.mu.Lock()
	store.ready.checkedAt = time.Now()
	store.ready.mu.Unlock()

	if err := store.CheckReady(context.Background()); err != nil {
		t.Fatalf("expected the cached ready answer within the TTL, got %v", err)
	}

	store.forgetReadiness()
	if err := store.CheckReady(context.Background()); err == nil {
		t.Fatal("expected a fresh check to refuse the schema-ahead database")
	}
}

func TestCheckReadyDoesNotCacheAnAnswerCutShortByTheCaller(t *testing.T) {
	store, _ := newFileBackedTestStore(t)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.CheckReady(cancelled); err == nil {
		t.Fatal("expected a cancelled check to fail")
	}

	if err := store.CheckReady(context.Background()); err != nil {
		t.Fatalf("expected the next caller to get a fresh answer, got %v", err)
	}
}

func TestCheckReadyFailsAtOnceAfterClose(t *testing.T) {
	store, _ := newFileBackedTestStore(t)

	if err := store.CheckReady(context.Background()); err != nil {
		t.Fatalf("expected a migrated database to be ready, got %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	if err := store.CheckReady(context.Background()); err == nil {
		t.Fatal("expected Close to drop the cached ready answer")
	}
}

// gateReadiness swaps the store's check for one that counts its runs and
// blocks until release is closed.
func gateReadiness(store *Store) (runs *atomic.Int32, started chan struct{}, release chan struct{}) {
	runs = &atomic.Int32{}
	started = make(chan struct{}, 64)
	release = make(chan struct{})
	store.ready.mu.Lock()
	store.ready.check = func(ctx context.Context) error {
		runs.Add(1)
		started <- struct{}{}
		<-release
		return store.checkReadyUncached(ctx)
	}
	store.ready.mu.Unlock()
	return runs, started, release
}

func TestConcurrentCheckReadyCallersShareOneCheck(t *testing.T) {
	store, _ := newFileBackedTestStore(t)
	runs, started, release := gateReadiness(store)
	// A goroutine scheduled late on a loaded runner must still land inside
	// the cache window of the completed check.
	store.ready.mu.Lock()
	store.ready.ttl = time.Hour
	store.ready.mu.Unlock()

	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- store.CheckReady(context.Background())
		}()
	}
	<-started
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("expected every concurrent caller to see ready, got %v", err)
		}
	}
	if got := runs.Load(); got != 1 {
		t.Fatalf("expected one shared check, got %d", got)
	}
}

// TestCheckReadyCallerGivingUpStillCachesTheAnswer: the caller that started
// the check cancels mid-query; the check finishes and its answer serves the
// next caller without a second run.
func TestCheckReadyCallerGivingUpStillCachesTheAnswer(t *testing.T) {
	store, _ := newFileBackedTestStore(t)
	runs, started, release := gateReadiness(store)

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- store.CheckReady(ctx) }()
	<-started
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected the cancelled caller to get context.Canceled, got %v", err)
	}

	close(release)
	if err := store.CheckReady(context.Background()); err != nil {
		t.Fatalf("expected the finished check's ready answer, got %v", err)
	}
	if got := runs.Load(); got != 1 {
		t.Fatalf("expected the cancelled caller's check to be reused, got %d runs", got)
	}
}

// TestCheckReadyWaiterKeepsItsOwnDeadline: a caller waiting on someone else's
// check returns when its own deadline passes, not when the check ends.
func TestCheckReadyWaiterKeepsItsOwnDeadline(t *testing.T) {
	store, _ := newFileBackedTestStore(t)
	_, started, release := gateReadiness(store)

	first := make(chan error, 1)
	go func() { first <- store.CheckReady(context.Background()) }()
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := store.CheckReady(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected the waiter's own deadline, got %v", err)
	}
	// The gated check finishes before the test's cleanup closes the store.
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("expected the started check to answer ready, got %v", err)
	}
}

func TestCheckReadyTurnsAPanickingCheckIntoNotReady(t *testing.T) {
	store, _ := newFileBackedTestStore(t)
	store.ready.mu.Lock()
	store.ready.check = func(context.Context) error { panic("driver bug") }
	store.ready.mu.Unlock()

	if err := store.CheckReady(context.Background()); err == nil {
		t.Fatal("expected a panicking check to answer not ready")
	}
}
