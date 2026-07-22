package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/api"
	"github.com/ovumcy/ovumcy-sync-community/internal/config"
	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/services"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatalf("%v", err)
	}
}

func shutdownSignal() <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	return ch
}

func run(args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	command := "serve"
	if len(args) > 0 {
		command = args[0]
	}

	switch command {
	case "serve":
		return runServe(cfg)
	case "migrate":
		return runMigrate(cfg)
	case "healthcheck":
		return runHealthcheck(cfg.BindAddr, 0)
	case "purge-lapsed-accounts":
		return runPurgeLapsedAccounts(cfg, args[1:], os.Stdout)
	default:
		return fmt.Errorf("unknown command %q; use `serve`, `migrate`, `healthcheck`, or `purge-lapsed-accounts`", command)
	}
}

func runMigrate(cfg config.Config) error {
	store, err := db.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			log.Printf("close database: %v", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := store.ApplyMigrations(ctx); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}

	log.Printf("applied database migrations for %s", cfg.DBPath)
	return nil
}

func runServe(cfg config.Config) error {
	store, err := db.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			log.Printf("close database: %v", closeErr)
		}
	}()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer readyCancel()
	ready, err := store.SchemaReady(readyCtx)
	if err != nil {
		return fmt.Errorf("check schema readiness: %w", err)
	}
	if !ready {
		return fmt.Errorf("database schema is not initialized; run `ovumcy-sync-community migrate` first")
	}

	authService := services.NewAuthService(store, cfg.SessionTTL)
	syncService := services.NewSyncService(store, services.SyncOptions{
		MaxDevices:   cfg.MaxDevices,
		MaxBlobBytes: cfg.MaxBlobBytes,
	})
	managedBridgeService := services.NewManagedBridgeService(store, authService)

	var totpService *services.TOTPService
	if len(cfg.FieldEncryptionKey) > 0 {
		totpService = services.NewTOTPService(
			store,
			authService,
			cfg.FieldEncryptionKey,
			cfg.TOTPIssuer,
		)
		authService.AttachTOTPChallengeIssuer(totpService)
	}

	server := &http.Server{
		Addr: cfg.BindAddr,
		Handler: api.NewServer(
			authService,
			syncService,
			managedBridgeService,
			totpService,
			api.ServerOptions{
				ManagedBridgeToken:  cfg.ManagedBridgeToken,
				MetricsEnabled:      cfg.MetricsEnabled,
				MetricsBearerToken:  cfg.MetricsBearerToken,
				AllowedOrigins:      cfg.AllowedOrigins,
				AuthRateLimitCount:  cfg.AuthRateLimitCount,
				AuthRateLimitWindow: cfg.AuthRateLimitWindow,
				MaxBlobBytes:        cfg.MaxBlobBytes,
				ReadinessCheck:      store.Ping,
				TrustedProxyCIDRs:   cfg.TrustedProxyCIDRs,
			},
		),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       cfg.HTTPReadTimeout,  // codecov:ignore -- process wiring reached only once ListenAndServe is about to run, same as the annotated block below; the value itself is covered by TestLoadHTTPTimeouts.
		WriteTimeout:      cfg.HTTPWriteTimeout, // codecov:ignore -- same seam as ReadTimeout above.
		IdleTimeout:       60 * time.Second,
	}

	// codecov:ignore:start -- process wiring reached only once ListenAndServe is
	// about to run. runServe's tested error paths (run_test.go) all return
	// before this point, and driving past it needs a real listener plus a
	// process signal to unwind it, which is not a black-box test. The behaviour
	// these lines wire up is covered directly instead:
	// lapsed_account_sweep_loop_test.go exercises the loop against every run
	// outcome, including the context-cancellation this shutdown path triggers.

	// backgroundCtx bounds the in-process sweep to the server's own lifetime:
	// the same signal that stops accepting requests stops the purge loop, so a
	// terminating container never leaves a delete transaction half-running.
	backgroundCtx, stopBackground := context.WithCancel(context.Background())
	defer stopBackground()

	go func() {
		<-shutdownSignal()
		stopBackground()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	go runLapsedAccountSweepLoop(
		backgroundCtx,
		services.NewLapsedAccountSweepService(store, cfg.LapsedAccountGracePeriod),
		cfg.LapsedAccountSweepInterval,
		cfg.LapsedAccountSweepLimit,
	)
	go runExpiredRowsSweepLoop(
		backgroundCtx,
		services.NewExpiredRowsSweepService(store),
		cfg.ExpiredRowsSweepInterval,
		cfg.ExpiredRowsSweepLimit,
	)
	// codecov:ignore:end

	log.Printf("ovumcy-sync-community listening on %s", cfg.BindAddr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("serve: %w", err)
	}

	return nil
}

// lapsedAccountSweeper is the narrow surface runLapsedAccountSweepLoop needs,
// satisfied by *services.LapsedAccountSweepService. Consumer-side so the loop
// can be tested against every run outcome without a database.
type lapsedAccountSweeper interface {
	Run(ctx context.Context, limit int, dryRun bool) (services.LapsedAccountSweepResult, error)
}

// runLapsedAccountSweepLoop erases accounts whose entitlement-lapse grace
// period has elapsed, on an interval, inside the server process.
//
// It exists because the retention promise had no enforcer. The managed side
// signals a lapse, this server records it and starts the clock — and then
// nothing happens unless an operator remembered to schedule the
// purge-lapsed-accounts subcommand. A stated retention window that nobody
// executes is worse than none: the data is kept indefinitely while the docs
// say otherwise.
//
// The loop decides only WHEN to purge, never WHOM: eligibility stays entirely
// inside services.LapsedAccountSweepService.Run and the in-transaction
// re-check beneath it, which is the same path the subcommand drives. Both
// triggers are therefore idempotent and safe to run together — an operator
// with an existing cron loses nothing.
//
// The first run happens one interval after boot, not at startup. A crash-loop
// must not turn into a purge-loop, and there is nothing so urgent about a
// 60-day grace period that it cannot wait one more tick.
//
// A non-positive interval disables the loop entirely, leaving the subcommand
// as the only trigger. That is the rollback lever: it takes effect on restart,
// without shipping a new image.
//
// Unlike the managed peer's lapse-signal sweep, there is no alerting monitor
// here and deliberately so. That sweep depends on reaching another server, so
// silence is ambiguous and needs escalation; this one deletes local rows, so a
// failure is a plain storage error that belongs in the log and nowhere else.
func runLapsedAccountSweepLoop(
	ctx context.Context,
	sweeper lapsedAccountSweeper,
	interval time.Duration,
	limit int,
) {
	if sweeper == nil || interval <= 0 {
		log.Print("lapsed-account sweep: in-process sweep disabled; schedule the purge-lapsed-accounts command instead")
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			result, err := sweeper.Run(ctx, limit, false)
			// A run can both delete and fail partway, so report the counts
			// before the error rather than instead of it. Account ids only —
			// never any other field (see SECURITY.md).
			if result.Deleted > 0 {
				log.Printf(
					"lapsed-account sweep examined %d accounts, deleted %d",
					result.Examined, result.Deleted,
				)
				for _, accountID := range result.DeletedAccountIDs {
					log.Printf("lapsed-account sweep deleted account_id=%s", accountID)
				}
			}
			if err != nil {
				log.Printf("lapsed-account sweep: %v", err)
			}
		}
	}
}

// expiredRowsSweeper is the narrow surface runExpiredRowsSweepLoop needs,
// satisfied by *services.ExpiredRowsSweepService. Consumer-side so the loop
// can be tested against every run outcome without a database.
type expiredRowsSweeper interface {
	Run(ctx context.Context, limit int) (services.ExpiredRowsSweepResult, error)
}

// runExpiredRowsSweepLoop deletes expired sessions, password-reset tokens,
// and TOTP challenges on an interval, inside the server process.
//
// Every read path already enforces expiry at use time, so these rows are
// unreadable the moment they expire — but nothing deleted them, and they
// were the only tables left growing without bound (sessions physically go
// away only on posture changes and logout). The loop decides only WHEN to
// sweep; WHAT qualifies is the expiry predicate inside the delete statements
// themselves, and since expiry is monotonic there is no race with valid use
// by construction.
//
// The first run happens one interval after boot, not at startup — same
// crash-loop reasoning as the lapsed-account sweep. A non-positive interval
// disables the loop entirely; that is the rollback lever, effective on
// restart with no new image.
func runExpiredRowsSweepLoop(
	ctx context.Context,
	sweeper expiredRowsSweeper,
	interval time.Duration,
	limit int,
) {
	if sweeper == nil || interval <= 0 {
		log.Print("expired-rows sweep: in-process sweep disabled")
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			result, err := sweeper.Run(ctx, limit)
			// A run can both delete and fail partway, so report the counts
			// before the error rather than instead of it. Counts only —
			// never row contents (see SECURITY.md).
			if result.Total() > 0 {
				log.Printf(
					"expired-rows sweep deleted %d sessions, %d password reset tokens, %d totp challenges",
					result.Sessions, result.PasswordResetTokens, result.TOTPChallenges,
				)
			}
			if err != nil {
				log.Printf("expired-rows sweep: %v", err)
			}
		}
	}
}
