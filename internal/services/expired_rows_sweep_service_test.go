package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

// recordingExpiredRowsStore stands in for *db.Store so Run can be driven
// through every per-table outcome without a database.
type recordingExpiredRowsStore struct {
	cutoffs []time.Time
	limits  []int

	sessions          int64
	sessionsErr       error
	resetTokens       int64
	resetTokensErr    error
	totpChallenges    int64
	totpChallengesErr error
}

func (s *recordingExpiredRowsStore) DeleteExpiredSessions(_ context.Context, cutoff time.Time, limit int) (int64, error) {
	s.cutoffs = append(s.cutoffs, cutoff)
	s.limits = append(s.limits, limit)
	return s.sessions, s.sessionsErr
}

func (s *recordingExpiredRowsStore) DeleteExpiredPasswordResetTokens(_ context.Context, cutoff time.Time, limit int) (int64, error) {
	s.cutoffs = append(s.cutoffs, cutoff)
	s.limits = append(s.limits, limit)
	return s.resetTokens, s.resetTokensErr
}

func (s *recordingExpiredRowsStore) DeleteExpiredTOTPChallenges(_ context.Context, cutoff time.Time, limit int) (int64, error) {
	s.cutoffs = append(s.cutoffs, cutoff)
	s.limits = append(s.limits, limit)
	return s.totpChallenges, s.totpChallengesErr
}

// TestExpiredRowsSweepRunAggregatesCounts pins the happy path: all three
// tables run with the caller's limit and one shared cutoff, and the result
// carries each table's count.
func TestExpiredRowsSweepRunAggregatesCounts(t *testing.T) {
	store := &recordingExpiredRowsStore{sessions: 3, resetTokens: 2, totpChallenges: 1}
	service := &ExpiredRowsSweepService{
		store: store,
		now:   func() time.Time { return time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC) },
	}

	result, err := service.Run(context.Background(), 25)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Sessions != 3 || result.ResetTokens != 2 || result.TOTPChallenges != 1 {
		t.Fatalf("unexpected counts: %+v", result)
	}
	if result.Total() != 6 {
		t.Fatalf("expected total 6, got %d", result.Total())
	}

	if len(store.limits) != 3 {
		t.Fatalf("expected all three tables to run, got %d calls", len(store.limits))
	}
	for _, limit := range store.limits {
		if limit != 25 {
			t.Fatalf("expected the caller's limit to pass through, got %v", store.limits)
		}
	}
	for _, cutoff := range store.cutoffs {
		if !cutoff.Equal(store.cutoffs[0]) {
			t.Fatalf("expected one shared cutoff for all tables, got %v", store.cutoffs)
		}
	}
}

// TestExpiredRowsSweepRunContinuesPastAFailingTable pins the failure policy:
// one table failing never blocks the others, and the error still surfaces.
func TestExpiredRowsSweepRunContinuesPastAFailingTable(t *testing.T) {
	for name, build := range map[string]func() *recordingExpiredRowsStore{
		"sessions": func() *recordingExpiredRowsStore {
			return &recordingExpiredRowsStore{sessionsErr: errors.New("sessions table on fire"), resetTokens: 2, totpChallenges: 1}
		},
		"reset tokens": func() *recordingExpiredRowsStore {
			return &recordingExpiredRowsStore{resetTokensErr: errors.New("reset tokens table on fire"), sessions: 2, totpChallenges: 1}
		},
		"totp challenges": func() *recordingExpiredRowsStore {
			return &recordingExpiredRowsStore{totpChallengesErr: errors.New("totp challenges table on fire"), sessions: 2, resetTokens: 1}
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := build()
			service := &ExpiredRowsSweepService{store: store, now: time.Now}

			result, err := service.Run(context.Background(), 0)
			if err == nil || !strings.Contains(err.Error(), "table on fire") {
				t.Fatalf("expected the %s failure to surface, got %v", name, err)
			}
			if len(store.limits) != 3 {
				t.Fatalf("expected the remaining tables to still run, got %d calls", len(store.limits))
			}
			if result.Total() != 3 {
				t.Fatalf("expected the two healthy tables' counts (3) alongside the failure, got %+v", result)
			}
		})
	}
}

// backlogExpiredRowsStore holds a pending backlog per table and deletes at
// most limit rows per call, the way the bounded store statements do.
type backlogExpiredRowsStore struct {
	pending      map[string]int64
	calls        map[string][]int
	failOnCall   map[string]int
	cancel       context.CancelFunc
	cancelOnCall int
	totalCalls   int
}

func newBacklogExpiredRowsStore(sessions, resetTokens, totpChallenges int64) *backlogExpiredRowsStore {
	return &backlogExpiredRowsStore{
		pending:    map[string]int64{"sessions": sessions, "reset tokens": resetTokens, "totp challenges": totpChallenges},
		calls:      map[string][]int{},
		failOnCall: map[string]int{},
	}
}

func (s *backlogExpiredRowsStore) deleteBatch(table string, limit int) (int64, error) {
	s.calls[table] = append(s.calls[table], limit)
	s.totalCalls++
	if s.cancel != nil && s.totalCalls == s.cancelOnCall {
		s.cancel()
	}
	if s.failOnCall[table] == len(s.calls[table]) {
		return 0, errors.New(table + " table on fire")
	}
	deleted := min(s.pending[table], int64(limit))
	s.pending[table] -= deleted
	return deleted, nil
}

func (s *backlogExpiredRowsStore) DeleteExpiredSessions(_ context.Context, _ time.Time, limit int) (int64, error) {
	return s.deleteBatch("sessions", limit)
}

func (s *backlogExpiredRowsStore) DeleteExpiredPasswordResetTokens(_ context.Context, _ time.Time, limit int) (int64, error) {
	return s.deleteBatch("reset tokens", limit)
}

func (s *backlogExpiredRowsStore) DeleteExpiredTOTPChallenges(_ context.Context, _ time.Time, limit int) (int64, error) {
	return s.deleteBatch("totp challenges", limit)
}

// TestExpiredRowsSweepRunDrainsBacklog pins the drain: one Run clears a
// backlog larger than the batch limit, stopping each table at the first
// short batch — including the empty batch after an exact multiple.
func TestExpiredRowsSweepRunDrainsBacklog(t *testing.T) {
	store := newBacklogExpiredRowsStore(1201, 1000, 0)
	service := &ExpiredRowsSweepService{store: store, now: time.Now}

	result, err := service.Run(context.Background(), 500)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Sessions != 1201 || result.ResetTokens != 1000 || result.TOTPChallenges != 0 {
		t.Fatalf("expected the whole backlog drained, got %+v", result)
	}
	for table, want := range map[string]int{"sessions": 3, "reset tokens": 3, "totp challenges": 1} {
		if got := len(store.calls[table]); got != want {
			t.Fatalf("expected %d batches for %s, got %d", want, table, got)
		}
		for _, limit := range store.calls[table] {
			if limit != 500 {
				t.Fatalf("expected every %s batch at the caller's limit, got %v", table, store.calls[table])
			}
		}
	}
}

// TestExpiredRowsSweepRunDefaultsNonPositiveLimit pins that the drain's
// short-batch test uses the same page size the store falls back to.
func TestExpiredRowsSweepRunDefaultsNonPositiveLimit(t *testing.T) {
	store := newBacklogExpiredRowsStore(db.DefaultExpiredRowsSweepLimit+1, 0, 0)
	service := &ExpiredRowsSweepService{store: store, now: time.Now}

	result, err := service.Run(context.Background(), 0)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Sessions != db.DefaultExpiredRowsSweepLimit+1 {
		t.Fatalf("expected the default-limit drain to clear the backlog, got %+v", result)
	}
	if got := len(store.calls["sessions"]); got != 2 {
		t.Fatalf("expected two default-size batches, got %d", got)
	}
	for _, limit := range store.calls["sessions"] {
		if limit != db.DefaultExpiredRowsSweepLimit {
			t.Fatalf("expected the store default as the batch size, got %v", store.calls["sessions"])
		}
	}
}

// TestExpiredRowsSweepRunKeepsCountsOfAFailedDrain pins the mid-drain
// failure: batches already deleted still count, the failing table stops,
// and the other tables drain fully.
func TestExpiredRowsSweepRunKeepsCountsOfAFailedDrain(t *testing.T) {
	store := newBacklogExpiredRowsStore(25, 25, 25)
	store.failOnCall["reset tokens"] = 2
	service := &ExpiredRowsSweepService{store: store, now: time.Now}

	result, err := service.Run(context.Background(), 10)
	if err == nil || !strings.Contains(err.Error(), "reset tokens table on fire") {
		t.Fatalf("expected the reset-token failure to surface, got %v", err)
	}
	if result.Sessions != 25 || result.ResetTokens != 10 || result.TOTPChallenges != 25 {
		t.Fatalf("expected the first batch for the failed table and full drains elsewhere, got %+v", result)
	}
	if got := len(store.calls["reset tokens"]); got != 2 {
		t.Fatalf("expected the failed table to stop at its failing batch, got %d batches", got)
	}
}

// TestExpiredRowsSweepRunStopsOnCancelledContext pins shutdown: a cancelled
// ctx stops each drain before its next batch and surfaces the cancellation.
func TestExpiredRowsSweepRunStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := newBacklogExpiredRowsStore(100, 100, 100)
	store.cancel = cancel
	store.cancelOnCall = 1
	service := &ExpiredRowsSweepService{store: store, now: time.Now}

	result, err := service.Run(ctx, 10)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if store.totalCalls != 1 || result.Total() != 10 {
		t.Fatalf("expected only the in-flight batch before the cancel took effect, got %d calls and %+v", store.totalCalls, result)
	}
}

// TestExpiredRowsSweepServiceDrainsRealBacklog drives the wired constructor
// against a real store holding more expired sessions than one batch: one Run
// removes them all and leaves the live session.
func TestExpiredRowsSweepServiceDrainsRealBacklog(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	account, err := store.CreateAccount(ctx, models.Account{
		ID:               "sweep-backlog",
		Login:            "sweep-backlog@example.com",
		PasswordHash:     "not-a-real-hash",
		RecoveryCodeHash: "not-a-real-hash",
		Mode:             "community",
		CreatedAt:        now,
	})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	for i := range 7 {
		expiresAt := now.Add(-time.Hour)
		if i == 6 {
			expiresAt = now.Add(time.Hour)
		}
		id := fmt.Sprintf("sweep-backlog-session-%d", i)
		if _, err := store.CreateSession(ctx, models.Session{
			ID:         id,
			AccountID:  account.ID,
			TokenHash:  "hash-" + id,
			CreatedAt:  now,
			LastSeenAt: now,
			ExpiresAt:  expiresAt,
		}); err != nil {
			t.Fatalf("create session %s: %v", id, err)
		}
	}

	service := NewExpiredRowsSweepService(store)
	service.now = func() time.Time { return now }
	result, err := service.Run(ctx, 2)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Sessions != 6 {
		t.Fatalf("expected all six expired sessions drained in one run, got %+v", result)
	}

	service.now = func() time.Time { return now.Add(2 * time.Hour) }
	result, err = service.Run(ctx, 2)
	if err != nil {
		t.Fatalf("second Run returned error: %v", err)
	}
	if result.Sessions != 1 {
		t.Fatalf("expected the live session to survive the first run, got %+v on the second", result)
	}
}

// TestExpiredRowsSweepServiceOnEmptyStore drives the wired constructor
// against a real empty store: zero deletions, no error.
func TestExpiredRowsSweepServiceOnEmptyStore(t *testing.T) {
	service := NewExpiredRowsSweepService(openTestStore(t))

	result, err := service.Run(context.Background(), 0)
	if err != nil {
		t.Fatalf("Run on an empty store returned error: %v", err)
	}
	if result.Total() != 0 {
		t.Fatalf("expected nothing to delete on an empty store, got %+v", result)
	}
}
