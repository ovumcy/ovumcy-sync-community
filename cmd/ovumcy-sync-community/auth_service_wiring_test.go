package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/config"
	"github.com/ovumcy/ovumcy-sync-community/internal/db"
)

// The serve path's AuthService must carry MAX_SESSIONS_PER_ACCOUNT, not the
// service default: with a cap of 2 the third sign-in revokes the first.
func TestNewAuthServiceAppliesTheConfiguredSessionCap(t *testing.T) {
	ctx := context.Background()
	store, err := db.Open(filepath.Join(t.TempDir(), "wiring.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	if err := store.ApplyMigrations(ctx); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	auth := newAuthService(store, config.Config{SessionTTL: time.Hour, MaxSessionsPerAccount: 2})
	const login, password = "owner@example.com", "correct horse battery staple"
	first, err := auth.Register(ctx, login, password)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	for i := range 2 {
		if _, err := auth.Login(ctx, login, password); err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
	}

	if _, err := auth.Authenticate(ctx, first.SessionToken); err == nil {
		t.Fatal("expected the first session revoked past a cap of 2")
	}
}
