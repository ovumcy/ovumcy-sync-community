package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/ovumcy/ovumcy-sync-community/internal/config"
	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/services"
)

// runPurgeLapsedAccounts backs the `purge-lapsed-accounts` operator
// subcommand: it deletes managed accounts whose entitlement-lapse marker
// (accounts.lapsed_at, set by the managed bridge's lapse signal —
// POST /managed/accounts/{account_id}/premium with {"active": false}, see
// services.ManagedBridgeService.SetAccountLapseSignal) is older than
// cfg.LapsedAccountGracePeriod, via the same whole-account transactional
// purge every account erase uses. See services.LapsedAccountSweepService and
// db.Store.DeleteLapsedManagedAccount for the delete-time re-check that
// makes this safe against a resubscribe (a reactivation signal) racing the sweep.
//
// It is the on-demand half of the purge. `serve` runs the same sweep on
// LAPSED_ACCOUNT_SWEEP_INTERVAL (see runLapsedAccountSweepLoop), because
// retention that waits on an operator remembering to schedule a cron is
// retention that silently does not happen. This subcommand remains for a
// one-off run, a -dry-run audit, and as the sole trigger on a deployment
// that sets the interval to 0. Both drive the identical eligibility path and
// are idempotent, so running a cron alongside the in-process sweep is
// harmless.
//
// args is the subcommand's own argv (excluding the "purge-lapsed-accounts"
// word itself):
//
//	-dry-run     report what would be deleted without deleting anything
//	-limit N     page size the run lists candidates in; the run still drains
//	             every eligible account (0 or omitted =
//	             db.DefaultLapsedAccountSweepLimit; below
//	             services.MinLapsedAccountSweepPage it is raised to that)
//	-max-deletes N  stop after erasing N accounts (0 = unbounded; omitted =
//	             LAPSED_ACCOUNT_SWEEP_MAX_DELETES); a capped run also prints
//	             lapsed_account_sweep_capped=true
//
// On a setup failure (bad flags, cannot open the database, schema not at this
// build's version) nothing
// is written to w and the error is returned immediately. Once the sweep
// itself has run, its report (examined/deleted counts, and the id of each
// account actually deleted — account ids only, never any other field) is
// written to w as stable key=value lines BEFORE any run error is returned,
// mirroring gc-guest-accounts's "report the counts before the error"
// convention.
var errSchemaNotCurrent = errors.New(
	"database schema is not at this build's version; run `migrate` with this build first, then rerun",
)

func runPurgeLapsedAccounts(cfg config.Config, args []string, w io.Writer) error {
	flagSet := flag.NewFlagSet("purge-lapsed-accounts", flag.ContinueOnError)
	flagSet.SetOutput(io.Discard)
	dryRun := flagSet.Bool("dry-run", false, "report eligible lapsed accounts without deleting them")
	limit := flagSet.Int("limit", 0, "candidate lapsed accounts listed per page; every run drains all eligible (0 = default)")
	maxDeletes := flagSet.Int("max-deletes", cfg.LapsedAccountSweepMaxDeletes, "stop after erasing this many accounts (0 = unbounded)")
	if err := flagSet.Parse(args); err != nil {
		return err
	}
	if *maxDeletes < 0 {
		return errors.New("-max-deletes must not be negative")
	}
	// Flag parsing stops at the first non-flag, so a typo like `dry-run` would
	// otherwise be ignored and the purge would run for real.
	if flagSet.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q; flags are -dry-run, -limit N and -max-deletes N", flagSet.Arg(0))
	}

	store, err := db.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() {
		_ = store.Close()
	}()

	// A maintenance command must not change the schema as a side effect: an
	// operator running it against a database the deployed server has not yet
	// migrated (or against a backup) would otherwise upgrade it unasked.
	ctx := context.Background()
	ready, err := store.SchemaReady(ctx)
	if err != nil {
		return fmt.Errorf("check schema: %w", err)
	}
	if !ready {
		return errSchemaNotCurrent
	}

	sweepService := services.NewLapsedAccountSweepService(store, cfg.LapsedAccountGracePeriod).
		WithMaxDeletesPerRun(*maxDeletes)
	result, runErr := sweepService.Run(ctx, services.LapsedAccountSweepPageSize(*limit), *dryRun)

	if _, err := fmt.Fprintf(
		w,
		"lapsed_account_sweep_dry_run=%t\nlapsed_account_sweep_examined=%d\nlapsed_account_sweep_deleted=%d\n",
		*dryRun, result.Examined, result.Deleted,
	); err != nil {
		return err
	}
	for _, accountID := range result.DeletedAccountIDs {
		if _, err := fmt.Fprintf(w, "lapsed_account_sweep_deleted_account_id=%s\n", accountID); err != nil {
			return err
		}
	}

	if result.Capped {
		if _, err := fmt.Fprint(w, "lapsed_account_sweep_capped=true\n"); err != nil {
			return err
		}
	}

	return runErr
}
