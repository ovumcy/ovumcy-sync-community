package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

// A re-attach renames and refreshes the stored row but keeps its created_at,
// so the returned device must carry the stored created_at, not the caller's.
func TestUpsertDeviceReattachReturnsTheStoredCreatedAt(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	seedGuardAccount(t, store, "reattach-account")

	first := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	later := first.Add(24 * time.Hour)

	if _, err := store.UpsertDevice(ctx, models.Device{
		DeviceID: "d1", AccountID: "reattach-account", DeviceLabel: "old",
		CreatedAt: first, LastSeenAt: first,
	}, 1); err != nil {
		t.Fatalf("first attach: %v", err)
	}

	// At the ceiling (1 of 1): a re-attach is still allowed.
	got, err := store.UpsertDevice(ctx, models.Device{
		DeviceID: "d1", AccountID: "reattach-account", DeviceLabel: "new",
		CreatedAt: later, LastSeenAt: later,
	}, 1)
	if err != nil {
		t.Fatalf("re-attach: %v", err)
	}
	if !got.CreatedAt.Equal(first) {
		t.Fatalf("expected the original created_at %v, got %v", first, got.CreatedAt)
	}
	if got.DeviceLabel != "new" || !got.LastSeenAt.Equal(later) {
		t.Fatalf("expected the refreshed label and last_seen_at, got %q %v", got.DeviceLabel, got.LastSeenAt)
	}

	stored, err := store.FindDevice(ctx, "reattach-account", "d1")
	if err != nil {
		t.Fatalf("find device: %v", err)
	}
	if !stored.CreatedAt.Equal(got.CreatedAt) {
		t.Fatalf("returned created_at %v differs from stored %v", got.CreatedAt, stored.CreatedAt)
	}

	if _, err := store.UpsertDevice(ctx, models.Device{
		DeviceID: "d2", AccountID: "reattach-account", DeviceLabel: "x",
		CreatedAt: later, LastSeenAt: later,
	}, 1); !errors.Is(err, ErrDeviceLimitReached) {
		t.Fatalf("expected ErrDeviceLimitReached for a new device at the ceiling, got %v", err)
	}
}
