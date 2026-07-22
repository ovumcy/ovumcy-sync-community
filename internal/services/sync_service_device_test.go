package services

import (
	"context"
	"errors"
	"fmt"
	gosync "sync"
	"testing"
	"time"
)

func newDeviceTestServices(t *testing.T, maxDevices int) (*AuthService, *SyncService) {
	t.Helper()
	store := openTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	sync := NewSyncService(store, SyncOptions{MaxDevices: maxDevices, MaxBlobBytes: 16 << 20})
	return auth, sync
}

func registerDeviceTestAccount(t *testing.T, auth *AuthService, login string) string {
	t.Helper()
	result, err := auth.Register(context.Background(), login, "correct horse battery staple")
	if err != nil {
		t.Fatalf("register %s: %v", login, err)
	}
	return result.AccountID
}

func TestListDevicesReturnsAttachedDevices(t *testing.T) {
	auth, sync := newDeviceTestServices(t, 5)
	accountID := registerDeviceTestAccount(t, auth, "owner@example.com")

	for _, id := range []string{"device-aaaa1111", "device-bbbb2222"} {
		if _, err := sync.AttachDevice(context.Background(), accountID, id, "Label"); err != nil {
			t.Fatalf("attach %s: %v", id, err)
		}
	}

	devices, err := sync.ListDevices(context.Background(), accountID)
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(devices))
	}
	seen := map[string]bool{}
	for _, d := range devices {
		seen[d.DeviceID] = true
	}
	if !seen["device-aaaa1111"] || !seen["device-bbbb2222"] {
		t.Fatalf("unexpected device set: %#v", devices)
	}
}

func TestListDevicesIsAccountScoped(t *testing.T) {
	auth, sync := newDeviceTestServices(t, 5)
	accountA := registerDeviceTestAccount(t, auth, "a@example.com")
	accountB := registerDeviceTestAccount(t, auth, "b@example.com")

	if _, err := sync.AttachDevice(context.Background(), accountA, "device-aaaa1111", "Alpha"); err != nil {
		t.Fatalf("attach A: %v", err)
	}

	devices, err := sync.ListDevices(context.Background(), accountB)
	if err != nil {
		t.Fatalf("list B: %v", err)
	}
	if len(devices) != 0 {
		t.Fatalf("account B must not see account A's devices, got %#v", devices)
	}
}

func TestRemoveDeviceFreesSlotForReuse(t *testing.T) {
	auth, sync := newDeviceTestServices(t, 1)
	accountID := registerDeviceTestAccount(t, auth, "owner@example.com")

	if _, err := sync.AttachDevice(context.Background(), accountID, "device-first111", "First"); err != nil {
		t.Fatalf("attach first: %v", err)
	}
	// Second attach must hit the ceiling.
	if _, err := sync.AttachDevice(context.Background(), accountID, "device-second22", "Second"); !errors.Is(err, ErrTooManyDevices) {
		t.Fatalf("expected ErrTooManyDevices, got %v", err)
	}

	// Removing the first device frees the slot.
	if err := sync.RemoveDevice(context.Background(), accountID, "device-first111"); err != nil {
		t.Fatalf("remove first: %v", err)
	}
	if _, err := sync.AttachDevice(context.Background(), accountID, "device-second22", "Second"); err != nil {
		t.Fatalf("attach after freeing slot: %v", err)
	}
}

func TestRemoveDeviceRejectsUnknownDevice(t *testing.T) {
	auth, sync := newDeviceTestServices(t, 5)
	accountID := registerDeviceTestAccount(t, auth, "owner@example.com")

	if err := sync.RemoveDevice(context.Background(), accountID, "device-missing1"); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("expected ErrDeviceNotFound, got %v", err)
	}
}

func TestRemoveDeviceRejectsEmptyID(t *testing.T) {
	auth, sync := newDeviceTestServices(t, 5)
	accountID := registerDeviceTestAccount(t, auth, "owner@example.com")

	if err := sync.RemoveDevice(context.Background(), accountID, "   "); !errors.Is(err, ErrInvalidDevice) {
		t.Fatalf("expected ErrInvalidDevice, got %v", err)
	}
}

// Concurrent attaches must not each pass the same ceiling check and land a row.
// The limit is enforced by a predicate inside the insert statement; counting in
// service code first would reopen the TOCTOU window this closes.
func TestConcurrentAttachDeviceNeverExceedsMaxDevices(t *testing.T) {
	const maxDevices = 3
	auth, sync := newDeviceTestServices(t, maxDevices)
	accountID := registerDeviceTestAccount(t, auth, "owner@example.com")

	const fanout = 8
	results := make([]error, fanout)
	start := make(chan struct{})
	var wg gosync.WaitGroup
	for i := range fanout {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := sync.AttachDevice(
				context.Background(),
				accountID,
				fmt.Sprintf("device-racer-%02d", i),
				fmt.Sprintf("Racer %d", i),
			)
			results[i] = err
		}(i)
	}
	close(start)
	wg.Wait()

	attached := 0
	for _, err := range results {
		switch {
		case err == nil:
			attached++
		case errors.Is(err, ErrTooManyDevices):
		default:
			t.Errorf("unexpected error from concurrent AttachDevice: %v", err)
		}
	}
	if attached != maxDevices {
		t.Fatalf("expected exactly %d successful attaches across %d concurrent attempts, got %d", maxDevices, fanout, attached)
	}

	devices, err := sync.ListDevices(context.Background(), accountID)
	if err != nil {
		t.Fatalf("list devices after race: %v", err)
	}
	if len(devices) != maxDevices {
		t.Fatalf("expected %d stored devices after race, got %d", maxDevices, len(devices))
	}
}

// Re-attaching a device the account already owns refreshes its row instead of
// consuming a slot, so it stays allowed once the account sits at the ceiling.
func TestAttachDeviceAtCeilingStillRefreshesAnOwnedDevice(t *testing.T) {
	auth, sync := newDeviceTestServices(t, 2)
	accountID := registerDeviceTestAccount(t, auth, "owner@example.com")

	for _, id := range []string{"device-first111", "device-second22"} {
		if _, err := sync.AttachDevice(context.Background(), accountID, id, "Original"); err != nil {
			t.Fatalf("attach %s: %v", id, err)
		}
	}
	// A third distinct device is refused: the account is full.
	if _, err := sync.AttachDevice(context.Background(), accountID, "device-third333", "Third"); !errors.Is(err, ErrTooManyDevices) {
		t.Fatalf("expected ErrTooManyDevices at the ceiling, got %v", err)
	}
	// Re-attaching an owned device is not a new slot, so it must succeed.
	if _, err := sync.AttachDevice(context.Background(), accountID, "device-first111", "Renamed"); err != nil {
		t.Fatalf("re-attach of an owned device at the ceiling: %v", err)
	}

	devices, err := sync.ListDevices(context.Background(), accountID)
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("re-attach must not add a row, expected 2 devices, got %d", len(devices))
	}
	relabeled := false
	for _, d := range devices {
		if d.DeviceID == "device-first111" && d.DeviceLabel == "Renamed" {
			relabeled = true
		}
	}
	if !relabeled {
		t.Fatalf("re-attach must update the label, got %#v", devices)
	}
}

func TestRemoveDeviceIsAccountScopedNoIDOR(t *testing.T) {
	auth, sync := newDeviceTestServices(t, 5)
	accountA := registerDeviceTestAccount(t, auth, "a@example.com")
	accountB := registerDeviceTestAccount(t, auth, "b@example.com")

	if _, err := sync.AttachDevice(context.Background(), accountA, "device-aaaa1111", "Alpha"); err != nil {
		t.Fatalf("attach A: %v", err)
	}

	// Account B tries to remove account A's device id — must not succeed and
	// must not delete A's row.
	if err := sync.RemoveDevice(context.Background(), accountB, "device-aaaa1111"); !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("cross-account removal must be ErrDeviceNotFound, got %v", err)
	}

	devices, err := sync.ListDevices(context.Background(), accountA)
	if err != nil {
		t.Fatalf("list A: %v", err)
	}
	if len(devices) != 1 || devices[0].DeviceID != "device-aaaa1111" {
		t.Fatalf("account A's device must survive B's removal attempt, got %#v", devices)
	}
}
