package services

import (
	"context"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
)

func TestAuthServiceRegisterAndLogin(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	result, err := service.Register(
		context.Background(),
		"Owner@Example.com",
		"correct horse battery staple",
	)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if result.AccountID == "" || result.SessionToken == "" {
		t.Fatalf("register result missing fields: %#v", result)
	}

	loginResult, err := service.Login(
		context.Background(),
		"owner@example.com",
		"correct horse battery staple",
	)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if loginResult.SessionToken == "" {
		t.Fatal("expected login session token")
	}
}

func TestAuthServiceDuplicateRegistrationIsGeneric(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	if _, err := service.Register(
		context.Background(),
		"owner@example.com",
		"correct horse battery staple",
	); err != nil {
		t.Fatalf("seed register: %v", err)
	}

	_, err := service.Register(
		context.Background(),
		"owner@example.com",
		"correct horse battery staple",
	)
	if err != ErrRegistrationFailed {
		t.Fatalf("expected ErrRegistrationFailed, got %v", err)
	}
}

func TestAuthServiceInvalidCredentialsStayGeneric(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	if _, err := service.Register(
		context.Background(),
		"owner@example.com",
		"correct horse battery staple",
	); err != nil {
		t.Fatalf("seed register: %v", err)
	}

	_, err := service.Login(context.Background(), "owner@example.com", "wrong password")
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestAuthServiceRevokesSession(t *testing.T) {
	store := openTestStore(t)
	service := NewAuthService(store, 24*time.Hour)

	result, err := service.Register(
		context.Background(),
		"owner@example.com",
		"correct horse battery staple",
	)
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	if err := service.RevokeSession(context.Background(), result.SessionToken); err != nil {
		t.Fatalf("revoke session: %v", err)
	}

	if _, err := service.Authenticate(context.Background(), result.SessionToken); err != ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized after revoke, got %v", err)
	}
}

func openTestStore(t *testing.T) *db.Store {
	t.Helper()

	store, err := db.Open(t.TempDir() + "/test.sqlite")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	if err := store.ApplyMigrations(context.Background()); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	return store
}
