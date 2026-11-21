package db

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

func createWindowTestAccount(t *testing.T, store *Store, accountID string) {
	t.Helper()
	if _, err := store.CreateAccount(context.Background(), models.Account{
		ID:               accountID,
		Login:            accountID + "@example.com",
		PasswordHash:     "hash",
		RecoveryCodeHash: "recovery-hash",
		Mode:             "self_hosted",
		CreatedAt:        time.Now().UTC(),
	}); err != nil {
		t.Fatalf("create account: %v", err)
	}
}

func TestReserveTOTPAttemptCapsAndRestartsTheWindow(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	createWindowTestAccount(t, store, "window-account")

	const window = 15 * time.Minute
	start := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	for i := range 3 {
		reserved, _, err := store.ReserveTOTPAttempt(ctx, "window-account", start.Add(time.Duration(i)*time.Second), window, 3)
		if err != nil || !reserved {
			t.Fatalf("attempt %d: reserved=%v err=%v", i+1, reserved, err)
		}
	}

	reserved, endsAt, err := store.ReserveTOTPAttempt(ctx, "window-account", start.Add(time.Minute), window, 3)
	if err != nil || reserved {
		t.Fatalf("over the cap: reserved=%v err=%v", reserved, err)
	}
	if !endsAt.Equal(start.Add(window)) {
		t.Fatalf("window ends at %v, want %v", endsAt, start.Add(window))
	}

	// At the window's end the next attempt restarts the count at 1.
	restart := start.Add(window)
	for i := range 3 {
		reserved, _, err := store.ReserveTOTPAttempt(ctx, "window-account", restart, window, 3)
		if err != nil || !reserved {
			t.Fatalf("restarted window attempt %d: reserved=%v err=%v", i+1, reserved, err)
		}
	}
	if reserved, _, _ := store.ReserveTOTPAttempt(ctx, "window-account", restart, window, 3); reserved {
		t.Fatal("restarted window must cap again at 3")
	}

	if err := store.ResetTOTPFailures(ctx, "window-account"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if reserved, _, err := store.ReserveTOTPAttempt(ctx, "window-account", restart, window, 3); err != nil || !reserved {
		t.Fatalf("after reset: reserved=%v err=%v", reserved, err)
	}

	// A clock stepped back behind the window's start restarts the window
	// rather than stretching the lock past its length.
	for range 3 {
		_, _, _ = store.ReserveTOTPAttempt(ctx, "window-account", restart, window, 3)
	}
	stepBack := restart.Add(-time.Hour)
	if reserved, _, err := store.ReserveTOTPAttempt(ctx, "window-account", stepBack, window, 3); err != nil || !reserved {
		t.Fatalf("after a clock step back: reserved=%v err=%v", reserved, err)
	}
}

func TestPendingEnrollmentTOTPAttemptKeepsItsCountAcrossAClockStepBack(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	createWindowTestAccount(t, store, "lifetime-account")

	start := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	for i := range 2 {
		reserved, err := store.ReservePendingEnrollmentTOTPAttempt(ctx, "lifetime-account", start.Add(time.Duration(i)*time.Hour), 3)
		if err != nil || !reserved {
			t.Fatalf("attempt %d: reserved=%v err=%v", i+1, reserved, err)
		}
	}
	stepBack := start.Add(-24 * time.Hour)
	if reserved, err := store.ReservePendingEnrollmentTOTPAttempt(ctx, "lifetime-account", stepBack, 3); err != nil || !reserved {
		t.Fatalf("third attempt after a clock step back: reserved=%v err=%v", reserved, err)
	}
	if reserved, err := store.ReservePendingEnrollmentTOTPAttempt(ctx, "lifetime-account", stepBack, 3); err != nil || reserved {
		t.Fatalf("a clock step back must not restart the lifetime count: reserved=%v err=%v", reserved, err)
	}

	var startedUnix int64
	var attempts int
	if err := store.db.QueryRowContext(ctx,
		`SELECT window_started_unix, failed_attempts FROM totp_failure_windows WHERE account_id = ?`,
		"lifetime-account",
	).Scan(&startedUnix, &attempts); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if startedUnix != stepBack.Unix() || attempts != 4 {
		t.Fatalf("row = (start %d, attempts %d), want (start %d, attempts 4)", startedUnix, attempts, stepBack.Unix())
	}
	if reserved, err := store.ReservePendingEnrollmentTOTPAttempt(ctx, "lifetime-account", start.Add(100*365*24*time.Hour), 3); err != nil || reserved {
		t.Fatalf("the lifetime count has no window to outlast: reserved=%v err=%v", reserved, err)
	}

	if err := store.ResetTOTPFailures(ctx, "lifetime-account"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if reserved, err := store.ReservePendingEnrollmentTOTPAttempt(ctx, "lifetime-account", start, 3); err != nil || !reserved {
		t.Fatalf("after reset: reserved=%v err=%v", reserved, err)
	}
}

func TestConcurrentReserveTOTPAttemptNeverExceedsTheCap(t *testing.T) {
	store, _ := newFileBackedTestStore(t)
	ctx := context.Background()
	createWindowTestAccount(t, store, "race-account")

	const attempts, limit = 50, 10
	now := time.Now().UTC()
	var wg sync.WaitGroup
	var mu sync.Mutex
	reservedCount := 0
	for range attempts {
		wg.Go(func() {
			reserved, _, err := store.ReserveTOTPAttempt(ctx, "race-account", now, 15*time.Minute, limit)
			if err != nil {
				t.Errorf("reserve: %v", err)
				return
			}
			if reserved {
				mu.Lock()
				reservedCount++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if reservedCount != limit {
		t.Fatalf("reserved %d attempts, want exactly %d", reservedCount, limit)
	}
}

func TestConcurrentPendingEnrollmentTOTPAttemptNeverExceedsTheCap(t *testing.T) {
	store, _ := newFileBackedTestStore(t)
	ctx := context.Background()
	createWindowTestAccount(t, store, "lifetime-race-account")

	const attempts, limit = 50, 10
	now := time.Now().UTC()
	var wg sync.WaitGroup
	var mu sync.Mutex
	reservedCount := 0
	for range attempts {
		wg.Go(func() {
			reserved, err := store.ReservePendingEnrollmentTOTPAttempt(ctx, "lifetime-race-account", now, limit)
			if err != nil {
				t.Errorf("reserve: %v", err)
				return
			}
			if reserved {
				mu.Lock()
				reservedCount++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if reservedCount != limit {
		t.Fatalf("reserved %d attempts, want exactly %d", reservedCount, limit)
	}
}

func TestTOTPFailureWindowSurfacesStoreErrors(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	ctx := context.Background()
	createWindowTestAccount(t, store, "broken-account")
	dropTable(t, dbPath, "totp_failure_windows")

	if _, _, err := store.ReserveTOTPAttempt(ctx, "broken-account", time.Now().UTC(), 15*time.Minute, 10); err == nil {
		t.Fatal("expected a reserve error once totp_failure_windows is dropped")
	}
	if _, err := store.ReservePendingEnrollmentTOTPAttempt(ctx, "broken-account", time.Now().UTC(), 10); err == nil {
		t.Fatal("expected a pending enrollment reserve error once totp_failure_windows is dropped")
	}
	if err := store.ResetTOTPFailures(ctx, "broken-account"); err == nil {
		t.Fatal("expected a reset error once totp_failure_windows is dropped")
	}
}
