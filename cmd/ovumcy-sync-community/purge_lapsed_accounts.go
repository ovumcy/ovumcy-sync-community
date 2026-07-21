package main

import (
	"context"
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
// purge DeleteAccount uses. See services.LapsedAccountSweepService and
// db.Store.DeleteLapsedManagedAccount for the delete-time re-check that
// makes this safe against a resubscribe (a session mint) racing the sweep.
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
//	-limit N     cap how many candidate lapsed accounts this run examines
//	             (0 or omitted = db.DefaultLapsedAccountSweepLimit)
//
// On a setup failure (bad flags, cannot open/migrate the database) nothing
// is written to w and the error is returned immediately. Once the sweep
// itself has run, its report (examined/deleted counts, and the id of each
// account actually deleted — account ids only, never any other field) is
// written to w as stable key=value lines BEFORE any run error is returned,
// mirroring gc-guest-accounts's "report the counts before the error"
// convention.
func runPurgeLapsedAccounts(cfg config.Config, args []string, w io.Writer) error {
	flagSet := flag.NewFlagSet("purge-lapsed-accounts", flag.ContinueOnError)
	flagSet.SetOutput(io.Discard)
	dryRun := flagSet.Bool("dry-run", false, "report eligible lapsed accounts without deleting them")
	limit := flagSet.Int("limit", 0, "maximum number of candidate lapsed accounts to examine (0 = default)")
	if err := flagSet.Parse(args); err != nil {
		return err
	}

	store, err := db.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() {
		_ = store.Close()
	}()

	ctx := context.Background()
	if err := store.ApplyMigrations(ctx); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}

	sweepService := services.NewLapsedAccountSweepService(store, cfg.LapsedAccountGracePeriod)
	result, runErr := sweepService.Run(ctx, *limit, *dryRun)

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

	return runErr
}
