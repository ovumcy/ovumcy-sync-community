package services

import (
	"context"
	"errors"
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
