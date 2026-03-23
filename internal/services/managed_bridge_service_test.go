package services

import (
	"context"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

func TestManagedBridgeRejectsInvalidAccountID(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)

	if _, err := bridgeService.CreateManagedSession(context.Background(), "bad"); err != ErrInvalidManagedAccount {
		t.Fatalf("expected ErrInvalidManagedAccount for short id, got %v", err)
	}
}

func TestManagedBridgeRejectsExistingSelfHostedAccount(t *testing.T) {
	store := openTestStore(t)
	authService := NewAuthService(store, 24*time.Hour)
	bridgeService := NewManagedBridgeService(store, authService)

	result, err := authService.Register(
		context.Background(),
		"owner@example.com",
		"correct horse battery staple",
	)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if _, err := bridgeService.CreateManagedSession(context.Background(), result.AccountID); err != ErrInvalidManagedAccount {
		t.Fatalf("expected ErrInvalidManagedAccount for self-hosted account reuse, got %v", err)
	}
}

func TestExistingOrCreatedAtPrefersExistingTimestamp(t *testing.T) {
	now := time.Now().UTC()
	existing := now.Add(-time.Hour)

	if got := existingOrCreatedAt(models.Account{}, now); !got.Equal(now) {
		t.Fatalf("expected fallback timestamp, got %s", got)
	}
	if got := existingOrCreatedAt(models.Account{CreatedAt: existing}, now); !got.Equal(existing) {
		t.Fatalf("expected existing timestamp, got %s", got)
	}
}
