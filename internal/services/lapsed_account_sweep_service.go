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
	// Capped is true when the run stopped at the per-run delete cap with at
	// least one further candidate left unexamined for the next run.
	Capped bool
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
// before committing — so a reactivation that races the sweep and clears
// lapsed_at (db.Store.ApplyEntitlementSignal) always wins: the conditional
// DELETE affects zero rows, the whole transaction (including the
// already-issued child-table deletes) rolls back, and the account survives
// untouched. This is a stronger re-check than a plain "re-read right before
// acting" would give: there is no window between the re-check and the
// delete for a reactivation to land in, because they are the same SQL
// statement.
// lapsedSweepStore is the persistence surface LapsedAccountSweepService
// needs, satisfied by *db.Store. Consumer-side for the same reason as the
// managed peer's guestGCStore seam: a test can wrap the real store to
// stage the reactivation-races-sweep interleaving (clear the lapse marker after the
// candidate listing, before the delete) that cannot be produced from
// outside a single Run call, while the delete still exercises the real
// in-transaction re-check that refuses the no-longer-lapsed account.
type lapsedSweepStore interface {
	ListLapsedManagedAccountIDs(ctx context.Context, cutoff time.Time, after db.LapsedCandidate, limit int) ([]db.LapsedCandidate, error)
	DeleteLapsedManagedAccount(ctx context.Context, accountID string, cutoff time.Time) error
}

// maxConsecutiveLapsedDeleteFailures is how many delete failures in a row
// (a benign db.ErrNotFound or a success resets the count) end one run: a
// persistent storage fault — a locked or read-only database — would
// otherwise make the run walk every remaining candidate, each attempt
// possibly waiting out the busy timeout. The candidates stay eligible, so the
// next scheduled run retries them.
const maxConsecutiveLapsedDeleteFailures = 5

// MinLapsedAccountSweepPage is the smallest page an operator-set page size
// (LAPSED_ACCOUNT_SWEEP_LIMIT, purge-lapsed-accounts -limit) can ask for.
// Listing one page reads the accounts table in full, so a run costs one full
// scan per page: a page size of 1 would scan once per eligible account.
const MinLapsedAccountSweepPage = 100

// LapsedAccountSweepPageSize maps an operator-set page size to the one Run is
// given: 0 (or negative) keeps the store default, anything smaller than
// MinLapsedAccountSweepPage is raised to it.
func LapsedAccountSweepPageSize(n int) int {
	if n <= 0 {
		return 0
	}
	return max(n, MinLapsedAccountSweepPage)
}

// ErrLapsedSweepAborted is joined into the error Run returns when it stopped
// after maxConsecutiveLapsedDeleteFailures consecutive delete failures.
var ErrLapsedSweepAborted = errors.New("lapsed account sweep aborted after repeated delete failures")

type LapsedAccountSweepService struct {
	store       lapsedSweepStore
	now         func() time.Time
	gracePeriod time.Duration
	// maxDeletes caps the accounts one Run erases; 0 means unbounded.
	maxDeletes int
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

// WithMaxDeletesPerRun sets an optional brake: one Run erases at most n
// accounts and reports LapsedAccountSweepResult.Capped when more were still
// eligible. It exists because the drain erases every eligible account per run,
// so a host clock that jumps past the grace period would otherwise erase every
// in-grace lapsed account in a single run. n <= 0 (the default) is unbounded.
// The cap counts deletions only, so a dry run is never capped.
func (s *LapsedAccountSweepService) WithMaxDeletesPerRun(n int) *LapsedAccountSweepService {
	s.maxDeletes = max(n, 0)
	return s
}

// Run drains every lapsed account eligible at one cutoff: it lists candidates
// in pages of limit (a non-positive limit defaults per
// db.Store.ListLapsedManagedAccountIDs) and deletes every one still eligible
// at the moment its own delete transaction runs, until a page comes back
// short. Each page starts after the previous page's last candidate, so a
// candidate that was skipped (dry run, raced reactivation, delete error) is
// behind the cursor and never listed twice in one run. The drain ends once
// no eligible account is left ahead of the cursor; only lapses recorded
// during the run with an earlier instant than the cutoff can extend it. The cutoff
// (now - gracePeriod) is computed once at the start of Run and reused for
// both the candidate listing and every per-candidate delete-time re-check,
// so a run that takes a while never spuriously excludes a candidate purely
// because wall-clock time advanced during the run — only an intervening
// reactivation (which clears lapsed_at outright) can do that, which is the
// intended race protection, not an accident of a moving cutoff.
//
// When dryRun is true, candidates are counted into Examined but never
// deleted, so Deleted stays 0 and DeletedAccountIDs stays empty.
//
// Failure policy: a listing failing is infrastructure trouble, so Run stops
// and returns the error with whatever earlier pages already did (an empty
// result when the first page fails). A cancelled ctx stops the run before
// the next listing or delete, with the same partial result. A
// per-candidate delete that reports db.ErrNotFound is the benign, by-design
// outcome the delete-time re-check exists to produce (the account vanished,
// or a reactivation raced the sweep and made it ineligible again) — not a failure —
// so it is skipped and the batch continues. A per-candidate delete that
// fails for any other reason is collected via errors.Join and the batch
// continues past it, mirroring PartnerGuestGCService.Run in ovumcy-managed:
// one uncooperative row must never block cleanup of the rest of the batch,
// and nothing about a failed delete changes the candidate's eligibility for
// the next scheduled run — until maxConsecutiveLapsedDeleteFailures of them
// fail in a row, which ends the run with ErrLapsedSweepAborted joined into the
// error (the failures point at the store, not at one row). The abort adds no
// account id or other field to any message.
//
// With a per-run cap (WithMaxDeletesPerRun) the run stops before the next
// delete once the cap is reached, with Capped set; the remaining candidates
// stay eligible for the next run.
func (s *LapsedAccountSweepService) Run(ctx context.Context, limit int, dryRun bool) (LapsedAccountSweepResult, error) {
	if limit <= 0 {
		limit = db.DefaultLapsedAccountSweepLimit
	}
	cutoff := s.now().UTC().Add(-s.gracePeriod)

	var result LapsedAccountSweepResult
	var deleteErrs []error
	var after db.LapsedCandidate
	consecutiveFailures := 0

	for {
		if err := ctx.Err(); err != nil {
			return result, errors.Join(append(deleteErrs, err)...)
		}
		page, err := s.store.ListLapsedManagedAccountIDs(ctx, cutoff, after, limit)
		if err != nil {
			return result, errors.Join(append(deleteErrs, fmt.Errorf("list lapsed account candidates: %w", err))...)
		}

		for _, candidate := range page {
			if err := ctx.Err(); err != nil {
				return result, errors.Join(append(deleteErrs, err)...)
			}
			if !dryRun && s.maxDeletes > 0 && result.Deleted >= s.maxDeletes {
				result.Capped = true
				return result, errors.Join(deleteErrs...)
			}
			result.Examined++

			if dryRun {
				continue
			}

			if err := s.store.DeleteLapsedManagedAccount(ctx, candidate.ID, cutoff); err != nil {
				if errors.Is(err, db.ErrNotFound) {
					consecutiveFailures = 0
					continue
				}
				deleteErrs = append(deleteErrs, fmt.Errorf("delete lapsed account: %w", err))
				consecutiveFailures++
				if consecutiveFailures >= maxConsecutiveLapsedDeleteFailures {
					return result, errors.Join(append(deleteErrs, ErrLapsedSweepAborted)...)
				}
				continue
			}
			consecutiveFailures = 0
			result.Deleted++
			result.DeletedAccountIDs = append(result.DeletedAccountIDs, candidate.ID)
		}

		if len(page) < limit {
			return result, errors.Join(deleteErrs...)
		}
		after = page[len(page)-1]
	}
}
