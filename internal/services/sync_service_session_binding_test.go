package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

func TestRemoveDeviceRevokesTheSessionThatAttachedIt(t *testing.T) {
	auth, sync := newDeviceTestServices(t, 5)
	ctx := context.Background()
	registered, err := auth.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if _, err := sync.AttachDeviceForSession(ctx, registered.AccountID, security.HashToken(registered.SessionToken), "device-abcd1234", "Pixel 7"); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if err := sync.RemoveDevice(ctx, registered.AccountID, "device-abcd1234"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := auth.Authenticate(ctx, registered.SessionToken); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected the bound session revoked, got %v", err)
	}
}

func TestAttachDeviceForSessionSurfacesBindErrors(t *testing.T) {
	store, dbPath := openFileBackedTestStore(t)
	auth := NewAuthService(store, 24*time.Hour)
	sync := NewSyncService(store, SyncOptions{MaxDevices: 5, MaxBlobBytes: 16 << 20})
	ctx := context.Background()
	registered, err := auth.Register(ctx, "owner@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	dropTable(t, dbPath, "sessions")

	if _, err := sync.AttachDeviceForSession(ctx, registered.AccountID, "hash", "device-abcd1234", "Pixel 7"); err == nil {
		t.Fatal("expected a bind error once the sessions table is gone")
	}
	if _, err := sync.AttachDeviceForSession(ctx, registered.AccountID, "hash", "x", "Pixel 7"); !errors.Is(err, ErrInvalidDevice) {
		t.Fatalf("expected ErrInvalidDevice, got %v", err)
	}
}
