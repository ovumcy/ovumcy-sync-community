package db

import (
	"context"
	"sync"
	"testing"
)

func TestCheckReadyReusesItsAnswerWithinTheTTL(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)

	if err := store.CheckReady(context.Background()); err != nil {
		t.Fatalf("expected a migrated database to be ready, got %v", err)
	}

	recordAppliedMigration(t, dbPath, futureMigrationVersion)

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

func TestCheckReadyIsSafeUnderConcurrentCallers(t *testing.T) {
	store, _ := newFileBackedTestStore(t)

	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- store.CheckReady(context.Background())
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("expected every concurrent caller to see ready, got %v", err)
		}
	}
}
