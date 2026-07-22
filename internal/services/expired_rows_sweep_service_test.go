package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// recordingExpiredRowsStore stands in for *db.Store so Run can be driven
// through every per-table outcome without a database.
type recordingExpiredRowsStore struct {
	cutoffs []time.Time
	limits  []int

	sessions            int64
	sessionsErr         error
	resetTokens         int64
	resetTokensErr      error
	totpChallenges      int64
	totpChallengesErr   error
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
	if result.Sessions != 3 || result.PasswordResetTokens != 2 || result.TOTPChallenges != 1 {
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
	store := &recordingExpiredRowsStore{
		sessionsErr:    errors.New("sessions table on fire"),
		resetTokens:    2,
		totpChallenges: 1,
	}
	service := &ExpiredRowsSweepService{
		store: store,
		now:   time.Now,
	}

	result, err := service.Run(context.Background(), 0)
	if err == nil {
		t.Fatal("expected the sessions failure to surface")
	}
	if !strings.Contains(err.Error(), "sessions table on fire") {
		t.Fatalf("expected the underlying error to be joined, got %v", err)
	}
	if len(store.limits) != 3 {
		t.Fatalf("expected the remaining tables to still run, got %d calls", len(store.limits))
	}
	if result.Sessions != 0 || result.PasswordResetTokens != 2 || result.TOTPChallenges != 1 {
		t.Fatalf("unexpected counts alongside the failure: %+v", result)
	}
}
