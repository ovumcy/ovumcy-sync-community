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

func TestDeleteAccountErasesTheTOTPFailureWindow(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	createWindowTestAccount(t, store, "erased-account")
	if _, _, err := store.ReserveTOTPAttempt(ctx, "erased-account", time.Now().UTC(), 15*time.Minute, 10); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	if err := store.DeleteAccount(ctx, "erased-account"); err != nil {
		t.Fatalf("delete account: %v", err)
	}
	var rows int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM totp_failure_windows`).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 0 {
		t.Fatalf("expected the failure window erased with the account, found %d rows", rows)
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
	if err := store.ResetTOTPFailures(ctx, "broken-account"); err == nil {
		t.Fatal("expected a reset error once totp_failure_windows is dropped")
	}
}
