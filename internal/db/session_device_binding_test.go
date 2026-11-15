package db

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

func seedBindingSession(t *testing.T, store *Store, accountID, tokenHash string) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := store.CreateSession(context.Background(), models.Session{
		ID:         tokenHash + "-id",
		AccountID:  accountID,
		TokenHash:  tokenHash,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}
}

func bindingDevice(accountID, deviceID string) models.Device {
	now := time.Now().UTC()
	return models.Device{
		DeviceID:    deviceID,
		AccountID:   accountID,
		DeviceLabel: "Phone",
		CreatedAt:   now,
		LastSeenAt:  now,
	}
}

func seedBindingDevice(t *testing.T, store *Store, accountID, deviceID string) {
	t.Helper()
	if _, err := store.UpsertDevice(context.Background(), bindingDevice(accountID, deviceID), 10); err != nil {
		t.Fatalf("upsert device: %v", err)
	}
}

func attachForSession(store *Store, accountID, tokenHash, deviceID string, maxDevices int) error {
	_, err := store.AttachDeviceForSession(context.Background(), bindingDevice(accountID, deviceID), maxDevices, tokenHash)
	return err
}

func sessionExists(t *testing.T, store *Store, tokenHash string) bool {
	t.Helper()
	_, err := store.FindSessionByTokenHash(context.Background(), tokenHash)
	if err != nil && !errors.Is(err, ErrNotFound) {
		t.Fatalf("find session: %v", err)
	}
	return err == nil
}

func deviceCount(t *testing.T, store *Store, accountID string) int {
	t.Helper()
	count, err := store.CountDevicesForAccount(context.Background(), accountID)
	if err != nil {
		t.Fatalf("count devices: %v", err)
	}
	return count
}

// TestDeleteDeviceRevokesOnlySessionsBoundToIt: the bound session goes; an
// unbound session, a session bound to another device, and another account's
// session bound to the same device id all stay.
func TestDeleteDeviceRevokesOnlySessionsBoundToIt(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	createWindowTestAccount(t, store, "acct-a")
	createWindowTestAccount(t, store, "acct-b")

	seedBindingSession(t, store, "acct-a", "a-bound")
	seedBindingSession(t, store, "acct-a", "a-unbound")
	seedBindingSession(t, store, "acct-a", "a-other")
	seedBindingSession(t, store, "acct-b", "b-bound")
	for _, bind := range []struct{ account, token, device string }{
		{"acct-a", "a-bound", "device-shared1"},
		{"acct-a", "a-other", "device-other22"},
		{"acct-b", "b-bound", "device-shared1"},
	} {
		if err := attachForSession(store, bind.account, bind.token, bind.device, 10); err != nil {
			t.Fatalf("attach %s: %v", bind.token, err)
		}
	}

	if err := store.DeleteDevice(ctx, "acct-a", "a-unbound", "device-shared1"); err != nil {
		t.Fatalf("delete device: %v", err)
	}

	want := map[string]bool{"a-bound": false, "a-unbound": true, "a-other": true, "b-bound": true}
	for token, alive := range want {
		if got := sessionExists(t, store, token); got != alive {
			t.Fatalf("session %s alive=%v, want %v", token, got, alive)
		}
	}
}

// TestAttachDeviceForSessionIsOneDevicePerSession: a bound session re-attaches
// its own device, is refused a different one without that device being
// created, and a token hash named under another account binds nothing.
func TestAttachDeviceForSessionIsOneDevicePerSession(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	createWindowTestAccount(t, store, "acct-a")
	createWindowTestAccount(t, store, "acct-b")
	seedBindingSession(t, store, "acct-a", "a-session")
	seedBindingSession(t, store, "acct-a", "a-caller")
	seedBindingSession(t, store, "acct-b", "b-caller")

	if err := attachForSession(store, "acct-b", "a-session", "device-cross11", 10); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("expected a cross-account attach refused, got %v", err)
	}
	if got := deviceCount(t, store, "acct-b"); got != 0 {
		t.Fatalf("a cross-account attach must create no device, count=%d", got)
	}
	if err := attachForSession(store, "acct-a", "a-session", "device-first11", 10); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if err := attachForSession(store, "acct-a", "a-session", "device-first11", 10); err != nil {
		t.Fatalf("re-attach of the bound device: %v", err)
	}
	if err := attachForSession(store, "acct-a", "a-session", "device-second2", 10); !errors.Is(err, ErrSessionDeviceBound) {
		t.Fatalf("expected ErrSessionDeviceBound, got %v", err)
	}
	if got := deviceCount(t, store, "acct-a"); got != 1 {
		t.Fatalf("a refused attach must not create its device, count=%d", got)
	}

	if !sessionExists(t, store, "a-session") {
		t.Fatal("a cross-account attach must not bind the session")
	}
	if err := store.DeleteDevice(ctx, "acct-a", "a-caller", "device-first11"); err != nil {
		t.Fatalf("delete first device: %v", err)
	}
	if sessionExists(t, store, "a-session") {
		t.Fatal("removing the bound device must revoke the session")
	}
}

// TestAttachDeviceForSessionCeilingRollsBackTheBind: an attach refused by the
// device ceiling leaves the session unbound, free to bind an owned device.
func TestAttachDeviceForSessionCeilingRollsBackTheBind(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	createWindowTestAccount(t, store, "acct-a")
	seedBindingDevice(t, store, "acct-a", "device-owned11")
	seedBindingSession(t, store, "acct-a", "a-session")
	seedBindingSession(t, store, "acct-a", "a-caller")

	if err := attachForSession(store, "acct-a", "a-session", "device-new2222", 1); !errors.Is(err, ErrDeviceLimitReached) {
		t.Fatalf("expected ErrDeviceLimitReached, got %v", err)
	}
	if err := attachForSession(store, "acct-a", "a-session", "device-owned11", 1); err != nil {
		t.Fatalf("attach of an owned device at the ceiling: %v", err)
	}
	if err := store.DeleteDevice(ctx, "acct-a", "a-caller", "device-owned11"); err != nil {
		t.Fatalf("delete owned device: %v", err)
	}
	if sessionExists(t, store, "a-session") {
		t.Fatal("the session must have bound the owned device, not the refused one")
	}
}

// TestAttachDeviceForSessionWithoutASessionAttachesNothing: a session revoked
// before the attach lands (its body arrived late) attaches nothing.
func TestAttachDeviceForSessionWithoutASessionAttachesNothing(t *testing.T) {
	store := openTestStore(t)
	createWindowTestAccount(t, store, "acct-a")

	if err := attachForSession(store, "acct-a", "gone", "device-abcd1234", 10); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("expected ErrSessionRevoked, got %v", err)
	}
	if got := deviceCount(t, store, "acct-a"); got != 0 {
		t.Fatalf("device count=%d, want 0", got)
	}
}

// TestConcurrentAttachDeviceForSessionBindsExactlyOneDevice: one unbound
// session racing attaches of distinct devices ends bound to exactly one, and
// every loser is refused without creating its device.
func TestConcurrentAttachDeviceForSessionBindsExactlyOneDevice(t *testing.T) {
	store := openTestStore(t)
	createWindowTestAccount(t, store, "acct-a")
	seedBindingSession(t, store, "acct-a", "a-session")

	devices := []string{"device-race001", "device-race002", "device-race003", "device-race004", "device-race005", "device-race006"}
	errs := make([]error, len(devices))
	var wg sync.WaitGroup
	for i, deviceID := range devices {
		wg.Add(1)
		go func(i int, deviceID string) {
			defer wg.Done()
			errs[i] = attachForSession(store, "acct-a", "a-session", deviceID, 10)
		}(i, deviceID)
	}
	wg.Wait()

	winners := 0
	for i, err := range errs {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, ErrSessionDeviceBound):
		default:
			t.Fatalf("attach %s: %v", devices[i], err)
		}
	}
	if winners != 1 {
		t.Fatalf("winners=%d, want exactly 1", winners)
	}
	if got := deviceCount(t, store, "acct-a"); got != 1 {
		t.Fatalf("device count=%d, want 1", got)
	}
}

// TestDeleteDeviceRollsBackWhenSessionRevocationFails: the device row and its
// sessions go together or not at all.
func TestDeleteDeviceRollsBackWhenSessionRevocationFails(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	ctx := context.Background()
	createWindowTestAccount(t, store, "acct-a")
	seedBindingDevice(t, store, "acct-a", "device-kept111")
	seedBindingSession(t, store, "acct-a", "a-caller")
	seedBindingSession(t, store, "acct-a", "a-bound")
	if err := attachForSession(store, "acct-a", "a-bound", "device-kept111", 10); err != nil {
		t.Fatalf("bind the session to the device: %v", err)
	}
	failDeletesOn(t, dbPath, "sessions")

	if err := store.DeleteDevice(ctx, "acct-a", "a-caller", "device-kept111"); err == nil {
		t.Fatal("expected an error once session deletes fail")
	}
	if got := deviceCount(t, store, "acct-a"); got != 1 {
		t.Fatalf("device must survive the rolled-back delete, count=%d", got)
	}
	dropTable(t, dbPath, "sessions")
	if err := attachForSession(store, "acct-a", "any", "device-new1111", 10); err == nil {
		t.Fatal("expected a bind error once the sessions table is gone")
	}
	if got := deviceCount(t, store, "acct-a"); got != 1 {
		t.Fatalf("a failed bind must not attach its device, count=%d", got)
	}
}

func TestAttachDeviceForSessionSurfacesUpsertErrors(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	createWindowTestAccount(t, store, "acct-a")
	seedBindingSession(t, store, "acct-a", "a-session")
	dropTable(t, dbPath, "devices")

	if err := attachForSession(store, "acct-a", "a-session", "device-abcd1234", 10); err == nil {
		t.Fatal("expected an upsert error once the devices table is gone")
	}
}

func TestDeleteDeviceFailsOnAClosedStore(t *testing.T) {
	store := openTestStore(t)
	_ = store.Close()
	if err := store.DeleteDevice(context.Background(), "acct-a", "any-session", "device-abcd1234"); err == nil {
		t.Fatal("expected an error from a closed store")
	}
	if err := attachForSession(store, "acct-a", "any", "device-abcd1234", 10); err == nil {
		t.Fatal("expected an attach error from a closed store")
	}
}
