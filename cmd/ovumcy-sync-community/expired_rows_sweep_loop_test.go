package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/services"
)

// recordingExpiredRowsSweeper stands in for
// *services.ExpiredRowsSweepService so the loop can be driven through every
// run outcome without a database, mirroring recordingSweeper.
type recordingExpiredRowsSweeper struct {
	mu     sync.Mutex
	calls  int
	limits []int

	result services.ExpiredRowsSweepResult
	err    error

	observed chan struct{}
}

func newRecordingExpiredRowsSweeper(result services.ExpiredRowsSweepResult, err error) *recordingExpiredRowsSweeper {
	return &recordingExpiredRowsSweeper{
		result:   result,
		err:      err,
		observed: make(chan struct{}, 8),
	}
}

func (s *recordingExpiredRowsSweeper) Run(
	_ context.Context,
	limit int,
) (services.ExpiredRowsSweepResult, error) {
	s.mu.Lock()
	s.calls++
	s.limits = append(s.limits, limit)
	result, err := s.result, s.err
	s.mu.Unlock()

	select {
	case s.observed <- struct{}{}:
	default:
	}
	return result, err
}

func (s *recordingExpiredRowsSweeper) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *recordingExpiredRowsSweeper) waitForRun(t *testing.T) {
	t.Helper()
	select {
	case <-s.observed:
	case <-time.After(2 * time.Second):
		t.Fatal("the sweep never ran")
	}
}

// TestExpiredRowsSweepLoopRunsTheSweep pins that a configured interval makes
// the sweep happen on its own, with the operator's limit passed through.
func TestExpiredRowsSweepLoopRunsTheSweep(t *testing.T) {
	sweeper := newRecordingExpiredRowsSweeper(services.ExpiredRowsSweepResult{
		Sessions:       2,
		ResetTokens:    1,
		TOTPChallenges: 1,
	}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runExpiredRowsSweepLoop(ctx, sweeper, time.Millisecond, 25)

	sweeper.waitForRun(t)
	cancel()

	sweeper.mu.Lock()
	defer sweeper.mu.Unlock()
	for _, limit := range sweeper.limits {
		if limit != 25 {
			t.Fatalf("expected the configured limit to pass through, got %v", sweeper.limits)
		}
	}
}

// TestExpiredRowsSweepLoopDisabledByNonPositiveInterval pins the rollback
// lever: interval <= 0 must mean no runs at all.
func TestExpiredRowsSweepLoopDisabledByNonPositiveInterval(t *testing.T) {
	sweeper := newRecordingExpiredRowsSweeper(services.ExpiredRowsSweepResult{}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		runExpiredRowsSweepLoop(ctx, sweeper, 0, 10)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("expected the disabled loop to return immediately")
	}
	if sweeper.callCount() != 0 {
		t.Fatalf("expected zero runs from a disabled loop, got %d", sweeper.callCount())
	}
}

// TestExpiredRowsSweepLoopContinuesAfterAnError pins the failure posture: a
// run that errors is logged and the loop keeps ticking — the next scheduled
// run is the retry, exactly like the lapsed-account loop.
func TestExpiredRowsSweepLoopContinuesAfterAnError(t *testing.T) {
	sweeper := newRecordingExpiredRowsSweeper(
		services.ExpiredRowsSweepResult{},
		errors.New("store down"),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runExpiredRowsSweepLoop(ctx, sweeper, time.Millisecond, 0)

	sweeper.waitForRun(t)
	sweeper.waitForRun(t) // a second tick proves the loop survived the error
	cancel()

	if sweeper.callCount() < 2 {
		t.Fatalf("expected the loop to keep running past an error, got %d runs", sweeper.callCount())
	}
}

// TestExpiredRowsSweepLoopStopsOnContextCancel pins the shutdown contract:
// cancelling the server's background context ends the loop.
func TestExpiredRowsSweepLoopStopsOnContextCancel(t *testing.T) {
	sweeper := newRecordingExpiredRowsSweeper(services.ExpiredRowsSweepResult{}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runExpiredRowsSweepLoop(ctx, sweeper, time.Millisecond, 0)
		close(done)
	}()

	sweeper.waitForRun(t)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("expected the loop to stop after context cancellation")
	}
}
