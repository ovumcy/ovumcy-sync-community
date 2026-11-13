package db

import (
	"context"
	"errors"
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

func seedBindingDevice(t *testing.T, store *Store, accountID, deviceID string) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := store.UpsertDevice(context.Background(), models.Device{
		DeviceID:    deviceID,
		AccountID:   accountID,
		DeviceLabel: "Phone",
		CreatedAt:   now,
		LastSeenAt:  now,
	}, 10); err != nil {
		t.Fatalf("upsert device: %v", err)
	}
}

func sessionExists(t *testing.T, store *Store, tokenHash string) bool {
	t.Helper()
	_, err := store.FindSessionByTokenHash(context.Background(), tokenHash)
	if err != nil && !errors.Is(err, ErrNotFound) {
		t.Fatalf("find session: %v", err)
	}
	return err == nil
}

// TestDeleteDeviceRevokesOnlySessionsBoundToIt: the bound session goes; an
// unbound session, a session bound to another device, and another account's
// session bound to the same device id all stay.
func TestDeleteDeviceRevokesOnlySessionsBoundToIt(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	for _, accountID := range []string{"acct-a", "acct-b"} {
		createWindowTestAccount(t, store, accountID)
		seedBindingDevice(t, store, accountID, "device-shared1")
	}
	seedBindingDevice(t, store, "acct-a", "device-other22")

	seedBindingSession(t, store, "acct-a", "a-bound")
	seedBindingSession(t, store, "acct-a", "a-unbound")
	seedBindingSession(t, store, "acct-a", "a-other")
	seedBindingSession(t, store, "acct-b", "b-bound")
	for _, bind := range []struct{ account, token, device string }{
		{"acct-a", "a-bound", "device-shared1"},
		{"acct-a", "a-other", "device-other22"},
		{"acct-b", "b-bound", "device-shared1"},
	} {
		if err := store.BindSessionToDevice(ctx, bind.account, bind.token, bind.device); err != nil {
			t.Fatalf("bind %s: %v", bind.token, err)
		}
	}

	if err := store.DeleteDevice(ctx, "acct-a", "device-shared1"); err != nil {
		t.Fatalf("delete device: %v", err)
	}

	want := map[string]bool{"a-bound": false, "a-unbound": true, "a-other": true, "b-bound": true}
	for token, alive := range want {
		if got := sessionExists(t, store, token); got != alive {
			t.Fatalf("session %s alive=%v, want %v", token, got, alive)
		}
	}
}

// TestBindSessionToDeviceIsOnceAndAccountScoped: a bound session keeps its
// first device, and a bind naming another account changes nothing.
func TestBindSessionToDeviceIsOnceAndAccountScoped(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	createWindowTestAccount(t, store, "acct-a")
	createWindowTestAccount(t, store, "acct-b")
	seedBindingDevice(t, store, "acct-a", "device-first11")
	seedBindingDevice(t, store, "acct-a", "device-second2")
	seedBindingSession(t, store, "acct-a", "a-session")

	if err := store.BindSessionToDevice(ctx, "acct-b", "a-session", "device-first11"); err != nil {
		t.Fatalf("cross-account bind: %v", err)
	}
	// A device removed before the bind lands must not capture the session.
	if err := store.BindSessionToDevice(ctx, "acct-a", "a-session", "device-removed"); err != nil {
		t.Fatalf("bind to a missing device: %v", err)
	}
	if err := store.BindSessionToDevice(ctx, "acct-a", "a-session", "device-first11"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err := store.BindSessionToDevice(ctx, "acct-a", "a-session", "device-second2"); err != nil {
		t.Fatalf("rebind: %v", err)
	}

	if err := store.DeleteDevice(ctx, "acct-a", "device-second2"); err != nil {
		t.Fatalf("delete second device: %v", err)
	}
	if !sessionExists(t, store, "a-session") {
		t.Fatal("a rebind must not move the session to the second device")
	}
	if err := store.DeleteDevice(ctx, "acct-a", "device-first11"); err != nil {
		t.Fatalf("delete first device: %v", err)
	}
	if sessionExists(t, store, "a-session") {
		t.Fatal("removing the first device must revoke the session bound to it")
	}
}

// TestDeleteDeviceRollsBackWhenSessionRevocationFails: the device row and its
// sessions go together or not at all.
func TestDeleteDeviceRollsBackWhenSessionRevocationFails(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	ctx := context.Background()
	createWindowTestAccount(t, store, "acct-a")
	seedBindingDevice(t, store, "acct-a", "device-kept111")
	dropTable(t, dbPath, "sessions")

	if err := store.DeleteDevice(ctx, "acct-a", "device-kept111"); err == nil {
		t.Fatal("expected an error once the sessions table is gone")
	}
	if count, err := store.CountDevicesForAccount(ctx, "acct-a"); err != nil || count != 1 {
		t.Fatalf("device must survive the rolled-back delete, count=%d err=%v", count, err)
	}
	if err := store.BindSessionToDevice(ctx, "acct-a", "any", "device-kept111"); err == nil {
		t.Fatal("expected a bind error once the sessions table is gone")
	}
}

func TestDeleteDeviceFailsOnAClosedStore(t *testing.T) {
	store := openTestStore(t)
	_ = store.Close()
	if err := store.DeleteDevice(context.Background(), "acct-a", "device-abcd1234"); err == nil {
		t.Fatal("expected an error from a closed store")
	}
}
