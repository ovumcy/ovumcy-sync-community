package security

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNormalizeLoginAndValidateLogin(t *testing.T) {
	if got := NormalizeLogin("  Owner@Example.com "); got != "owner@example.com" {
		t.Fatalf("unexpected normalized login %q", got)
	}
	if ValidateLogin("ab") {
		t.Fatal("expected short login to be invalid")
	}
	if !ValidateLogin("abc") {
		t.Fatal("expected three-character login to be valid")
	}
}

func TestHashPasswordRejectsWeakPassword(t *testing.T) {
	if _, err := HashPassword("too short"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("expected ErrWeakPassword, got %v", err)
	}
}

func TestHashPasswordAndCompare(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if hash == "" || hash == "correct horse battery staple" {
		t.Fatalf("unexpected password hash %q", hash)
	}
	if err := ComparePasswordHash(hash, "correct horse battery staple"); err != nil {
		t.Fatalf("compare password hash: %v", err)
	}
	if err := ComparePasswordHash(hash, "wrong password"); err == nil {
		t.Fatal("expected wrong password comparison to fail")
	}
}

func TestTokenHelpersReturnOpaqueValues(t *testing.T) {
	plain, hash, err := NewOpaqueToken()
	if err != nil {
		t.Fatalf("new opaque token: %v", err)
	}
	if plain == "" || hash == "" || plain == hash {
		t.Fatalf("unexpected opaque token values plain=%q hash=%q", plain, hash)
	}
	if len(hash) != 64 {
		t.Fatalf("expected sha256 hex hash length, got %d", len(hash))
	}
	if HashToken(plain) != hash {
		t.Fatalf("expected HashToken to match generated hash")
	}

	identifierOne, err := NewIdentifier()
	if err != nil {
		t.Fatalf("new identifier one: %v", err)
	}
	identifierTwo, err := NewIdentifier()
	if err != nil {
		t.Fatalf("new identifier two: %v", err)
	}
	if len(identifierOne) != 32 || len(identifierTwo) != 32 {
		t.Fatalf("expected 16-byte hex identifiers, got %q and %q", identifierOne, identifierTwo)
	}
	if identifierOne == identifierTwo {
		t.Fatalf("expected unique identifiers, got %q twice", identifierOne)
	}
}

func TestRateLimiterResetsAfterWindow(t *testing.T) {
	limiter := NewRateLimiter(2, time.Minute)
	base := time.Date(2026, 3, 23, 9, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return base }

	if !limiter.Allow("ip:1") {
		t.Fatal("expected first request to pass")
	}
	if !limiter.Allow("ip:1") {
		t.Fatal("expected second request within limit to pass")
	}
	if limiter.Allow("ip:1") {
		t.Fatal("expected third request in same window to be rejected")
	}

	base = base.Add(2 * time.Minute)
	if !limiter.Allow("ip:1") {
		t.Fatal("expected limiter to reset after window")
	}
	if !limiter.Allow("ip:2") {
		t.Fatal("expected independent key to pass")
	}
	if len(limiter.entries) != 2 {
		t.Fatalf("expected entries for two keys, got %d", len(limiter.entries))
	}
}

func TestHashTokenIsStableLowerLevelHelper(t *testing.T) {
	first := HashToken("same-token")
	second := HashToken("same-token")
	if first != second {
		t.Fatal("expected HashToken to be deterministic")
	}
	if len(strings.TrimSpace(first)) != 64 {
		t.Fatalf("unexpected hash length %d", len(first))
	}
}
