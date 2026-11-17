package services

import (
	"context"
	"errors"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
)

// ExpiredRowsSweepResult totals one Run call per table. Counts only — no
// identifiers or token material of any kind — so the sweep's log line is
// trivially secret-free (see SECURITY.md's no-secret-in-logs contract).
// ResetTokens deliberately omits the "password" noun: heuristic
// secret-in-log scanners read an identifier named after the secret as the
// secret itself, and this field is an int64 row count, nothing else.
type ExpiredRowsSweepResult struct {
	Sessions       int64
	ResetTokens    int64
	TOTPChallenges int64
}

// Total is the sum a caller logs or branches on to decide whether the run
// did anything at all.
func (r ExpiredRowsSweepResult) Total() int64 {
	return r.Sessions + r.ResetTokens + r.TOTPChallenges
}

// expiredRowsStore is the persistence surface ExpiredRowsSweepService needs,
// satisfied by *db.Store. Consumer-side, mirroring lapsedSweepStore: tests
// drive every per-table failure combination without a database.
type expiredRowsStore interface {
	DeleteExpiredSessions(ctx context.Context, cutoff time.Time, limit int) (int64, error)
	DeleteExpiredPasswordResetTokens(ctx context.Context, cutoff time.Time, limit int) (int64, error)
	DeleteExpiredTOTPChallenges(ctx context.Context, cutoff time.Time, limit int) (int64, error)
}

// ExpiredRowsSweepService erases rows whose expiry has passed: sessions,
// password-reset tokens, and TOTP challenges. Every read path already
// enforces expiry at use time (Authenticate rejects an expired session,
// ConsumePasswordResetToken's CAS matches only unexpired rows, challenge
// verification checks expires_at), so an expired row is unreadable the
// moment its deadline passes — the sweep is pure data minimization for the
// only tables that otherwise grow without bound, not a security boundary.
//
// Unlike the lapsed-account sweep there is no delete-time re-check and no
// grace period: expiry is monotonic (an expired row can never become live
// again), so deleting strictly-expired rows cannot race any valid use by
// construction.
type ExpiredRowsSweepService struct {
	store expiredRowsStore
	now   func() time.Time
}

// NewExpiredRowsSweepService wires the service over the store. The per-batch
// row cap comes from the caller (config.Config.ExpiredRowsSweepLimit,
// EXPIRED_ROWS_SWEEP_LIMIT; non-positive = db.DefaultExpiredRowsSweepLimit).
func NewExpiredRowsSweepService(store *db.Store) *ExpiredRowsSweepService {
	return &ExpiredRowsSweepService{
		store: store,
		now:   time.Now,
	}
}

// Run drains every row that expired at or before one cutoff, computed once
// at the start so all three tables see the same clock. Each table is deleted
// in batches of limit rows until a batch comes back short: one bounded
// statement at a time leaves the single pooled connection free for requests
// between batches, while a once-a-day tick still clears a backlog instead of
// shaving one page off it. The drain terminates because the cutoff is fixed
// and rows are written with a future expiry, so the qualifying set only
// shrinks.
//
// Failure policy mirrors LapsedAccountSweepService.Run: a table's delete
// failing stops that table's drain and is collected via errors.Join, and the
// remaining tables still run — one uncooperative table must never block
// cleanup of the others, and nothing about a failed delete changes a row's
// eligibility for the next scheduled run. Batches deleted before the failure
// still count. A cancelled ctx stops each drain between batches.
func (s *ExpiredRowsSweepService) Run(ctx context.Context, limit int) (ExpiredRowsSweepResult, error) {
	if limit <= 0 {
		limit = db.DefaultExpiredRowsSweepLimit
	}
	cutoff := s.now().UTC()

	var result ExpiredRowsSweepResult
	var errs []error

	for _, table := range []struct {
		deleteBatch expiredRowsBatchDelete
		total       *int64
	}{
		{s.store.DeleteExpiredSessions, &result.Sessions},
		{s.store.DeleteExpiredPasswordResetTokens, &result.ResetTokens},
		{s.store.DeleteExpiredTOTPChallenges, &result.TOTPChallenges},
	} {
		deleted, err := drainExpiredRows(ctx, table.deleteBatch, cutoff, limit)
		*table.total = deleted
		if err != nil {
			errs = append(errs, err)
		}
	}

	return result, errors.Join(errs...)
}

type expiredRowsBatchDelete func(ctx context.Context, cutoff time.Time, limit int) (int64, error)

func drainExpiredRows(ctx context.Context, deleteBatch expiredRowsBatchDelete, cutoff time.Time, limit int) (int64, error) {
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		deleted, err := deleteBatch(ctx, cutoff, limit)
		if err != nil {
			return total, err
		}
		total += deleted
		if deleted < int64(limit) {
			return total, nil
		}
	}
}
