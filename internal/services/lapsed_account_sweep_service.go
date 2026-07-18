package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
)

// LapsedAccountSweepResult totals one Run call: how many candidate lapsed
// accounts were examined, how many were actually deleted (always 0 in
// dry-run mode), and the ids of the accounts actually deleted.
// DeletedAccountIDs holds account ids only — never any other field — so it
// is safe to log per the no-PII-in-logs convention (see SECURITY.md); the
// account id is the minimal identifier an operator needs to cross-reference
// a run against other signals.
type LapsedAccountSweepResult struct {
	Examined          int
	Deleted           int
	DeletedAccountIDs []string
}

// LapsedAccountSweepService is the sync-side half of the entitlement-lapse
// cleanup design: it erases managed accounts whose entitlement-lapse marker
// (accounts.lapsed_at, set only by ManagedBridgeService.SetAccountLapseSignal
// with active=false) has been recorded for at least its configured grace
// period. Explicit lapse signal is the ONLY purge trigger this service acts
// on — never inactivity — because the candidate query
// (db.Store.ListLapsedManagedAccountIDs) filters strictly on lapsed_at, a
// column no code path ever sets from anything other than that one signal.
//
// Deletion reuses db.Store.DeleteLapsedManagedAccount, which re-derives
// eligibility (mode='managed' AND lapsed_at set AND older than the same
// cutoff this Run call used) INSIDE its own delete transaction immediately
// before committing — so a session mint that races the sweep and clears
// lapsed_at (UpsertManagedAccount) always wins: the conditional DELETE
// affects zero rows, the whole transaction (including the already-issued
// child-table deletes) rolls back, and the account survives untouched. This
// is a stronger re-check than a plain "re-read right before acting" would
// give: there is no window between the re-check and the delete for a mint to
// land in, because they are the same SQL statement.
// lapsedSweepStore is the persistence surface LapsedAccountSweepService
// needs, satisfied by *db.Store. Consumer-side for the same reason as the
// managed peer's guestGCStore seam: a test can wrap the real store to
// stage the mint-races-sweep interleaving (clear the lapse marker after the
// candidate listing, before the delete) that cannot be produced from
// outside a single Run call, while the delete still exercises the real
// in-transaction re-check that refuses the no-longer-lapsed account.
type lapsedSweepStore interface {
	ListLapsedManagedAccountIDs(ctx context.Context, cutoff time.Time, limit int) ([]string, error)
	DeleteLapsedManagedAccount(ctx context.Context, accountID string, cutoff time.Time) error
}

type LapsedAccountSweepService struct {
	store       lapsedSweepStore
	now         func() time.Time
	gracePeriod time.Duration
}

// NewLapsedAccountSweepService wires the service over the store and the
// operator-configured grace period (config.Config.LapsedAccountGracePeriod,
// LAPSED_ACCOUNT_GRACE_PERIOD, default 60 days).
func NewLapsedAccountSweepService(store *db.Store, gracePeriod time.Duration) *LapsedAccountSweepService {
	return &LapsedAccountSweepService{
		store:       store,
		now:         time.Now,
		gracePeriod: gracePeriod,
	}
}

// Run lists up to limit candidate lapsed accounts (a non-positive limit
// defaults per db.Store.ListLapsedManagedAccountIDs) and deletes every one
// still eligible at the moment its own delete transaction runs. The cutoff
// (now - gracePeriod) is computed once at the start of Run and reused for
// both the candidate listing and every per-candidate delete-time re-check,
// so a run that takes a while never spuriously excludes a candidate purely
// because wall-clock time advanced during the run — only an intervening
// session mint (which clears lapsed_at outright) can do that, which is the
// intended race protection, not an accident of a moving cutoff.
//
// When dryRun is true, candidates are counted into Examined but never
// deleted, so Deleted stays 0 and DeletedAccountIDs stays empty.
//
// Failure policy: the initial listing failing is infrastructure trouble, so
// Run aborts immediately and returns the error with an empty result. A
// per-candidate delete that reports db.ErrNotFound is the benign, by-design
// outcome the delete-time re-check exists to produce (the account vanished,
// or a mint raced the sweep and made it ineligible again) — not a failure —
// so it is skipped and the batch continues. A per-candidate delete that
// fails for any other reason is collected via errors.Join and the batch
// continues past it, mirroring PartnerGuestGCService.Run in ovumcy-managed:
// one uncooperative row must never block cleanup of the rest of the batch,
// and nothing about a failed delete changes the candidate's eligibility for
// the next scheduled run.
func (s *LapsedAccountSweepService) Run(ctx context.Context, limit int, dryRun bool) (LapsedAccountSweepResult, error) {
	cutoff := s.now().UTC().Add(-s.gracePeriod)

	candidateIDs, err := s.store.ListLapsedManagedAccountIDs(ctx, cutoff, limit)
	if err != nil {
		return LapsedAccountSweepResult{}, fmt.Errorf("list lapsed account candidates: %w", err)
	}

	var result LapsedAccountSweepResult
	var deleteErrs []error

	for _, accountID := range candidateIDs {
		result.Examined++

		if dryRun {
			continue
		}

		if err := s.store.DeleteLapsedManagedAccount(ctx, accountID, cutoff); err != nil {
			if errors.Is(err, db.ErrNotFound) {
				continue
			}
			deleteErrs = append(deleteErrs, fmt.Errorf("delete lapsed account: %w", err))
			continue
		}
		result.Deleted++
		result.DeletedAccountIDs = append(result.DeletedAccountIDs, accountID)
	}

	return result, errors.Join(deleteErrs...)
}
