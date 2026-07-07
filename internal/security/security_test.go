package security

import (
	"errors"
	"fmt"
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
	// The "managed:" namespace is reserved for bridge-provisioned accounts;
	// public registration must not be able to claim it (in any case).
	if ValidateLogin("managed:abc123") {
		t.Fatal("expected reserved managed: login prefix to be invalid")
	}
	if ValidateLogin("MANAGED:abc123") {
		t.Fatal("expected reserved managed: login prefix to be invalid regardless of case")
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

// TestRateLimiterSweepsExpiredEntries proves the amortized sweep actually
// removes entries whose window has fully elapsed, rather than leaking them for
// the process lifetime. It also confirms the sweep is behavior-preserving: an
// expired key that gets swept is indistinguishable from one that was never
// seen — its counter starts fresh on the next touch.
func TestRateLimiterSweepsExpiredEntries(t *testing.T) {
	limiter := NewRateLimiter(2, time.Minute)
	base := time.Date(2026, 3, 23, 9, 0, 0, 0, time.UTC)
	current := base
	limiter.now = func() time.Time { return current }

	// Seed one distinct key per Allow call, stopping one call short of the
	// sweep interval so no sweep has fired yet.
	seedKeys := rateLimiterSweepInterval - 1
	for i := range seedKeys {
		if !limiter.Allow(fmt.Sprintf("seed:%d", i)) {
			t.Fatalf("expected first touch of unique key seed:%d to pass", i)
		}
	}
	if got := len(limiter.entries); got != seedKeys {
		t.Fatalf("expected %d seeded entries before any sweep, got %d", seedKeys, got)
	}

	// Advance two full windows so every seeded entry is expired, then make
	// the interval-completing call: its sweep must delete all expired seeds,
	// leaving only the entry created by the sweeping call itself.
	current = base.Add(2 * time.Minute)
	if !limiter.Allow("trigger") {
		t.Fatal("expected trigger key to pass")
	}
	if got := len(limiter.entries); got != 1 {
		t.Fatalf("expected sweep to drop all expired seed entries (1 remaining), got %d", got)
	}

	// The swept keys must behave as brand-new: full budget available again.
	if !limiter.Allow("seed:0") {
		t.Fatal("expected swept key to have a fresh window")
	}
	if !limiter.Allow("seed:0") {
		t.Fatal("expected swept key to still be within its fresh budget")
	}
	if limiter.Allow("seed:0") {
		t.Fatal("expected swept key to throttle after its fresh budget is spent")
	}
}

// TestRateLimiterBoundsMapAcrossManyWindows drives far more unique keys than
// the sweep interval across several advancing windows and asserts the map
// never exceeds the documented bound — the current window's distinct keys
// plus at most one sweep interval of growth — and never approaches the total
// number of keys ever seen. Sweeps are driven purely by Allow-call count
// under the injected clock.
func TestRateLimiterBoundsMapAcrossManyWindows(t *testing.T) {
	limiter := NewRateLimiter(5, time.Minute)
	base := time.Date(2026, 3, 23, 9, 0, 0, 0, time.UTC)
	current := base
	limiter.now = func() time.Time { return current }

	const windows = 8
	// 1.5x the interval so interval-triggered sweeps land mid-window at
	// shifting offsets instead of aligning with window boundaries.
	const keysPerWindow = rateLimiterSweepInterval + rateLimiterSweepInterval/2
	maxSeen := 0
	for w := range windows {
		current = base.Add(time.Duration(w) * time.Minute)
		for i := range keysPerWindow {
			// Keys unique per window so every prior window's keys are expired
			// by the time the current window's sweeps run.
			limiter.Allow(fmt.Sprintf("w%d:k%d", w, i))
			if n := len(limiter.entries); n > maxSeen {
				maxSeen = n
			}
		}
	}

	totalKeysSeen := windows * keysPerWindow
	// The documented bound: distinct in-window keys plus at most one sweep
	// interval of growth between sweeps (each Allow inserts at most one key).
	ceiling := keysPerWindow + rateLimiterSweepInterval
	if maxSeen > ceiling {
		t.Fatalf("map grew to %d entries (bound %d); expected bounded growth, %d keys seen total",
			maxSeen, ceiling, totalKeysSeen)
	}
	// Sanity: the map never accumulates history — after eight windows it holds
	// nowhere near every key ever seen.
	if len(limiter.entries) >= totalKeysSeen {
		t.Fatalf("final map holds %d entries out of %d total keys seen; entries were never swept",
			len(limiter.entries), totalKeysSeen)
	}
}

// TestRateLimiterSweepPreservesInWindowEntries guards the security-critical
// half of the sweep contract: entries whose window is still open are NEVER
// evicted, so an attacker who floods unique keys cannot push their own
// throttled key out of the map to reset its counter.
func TestRateLimiterSweepPreservesInWindowEntries(t *testing.T) {
	limiter := NewRateLimiter(3, time.Minute)
	base := time.Date(2026, 3, 23, 9, 0, 0, 0, time.UTC)
	current := base
	limiter.now = func() time.Time { return current }

	// Drive the attacker key to its limit so it is throttled.
	for i := range 3 {
		if !limiter.Allow("attacker") {
			t.Fatalf("expected attacker touch %d to pass", i)
		}
	}
	if limiter.Allow("attacker") {
		t.Fatal("expected attacker key to be throttled after reaching the limit")
	}

	// Flood unique keys within the SAME window for more than two full sweep
	// intervals, guaranteeing at least two interval-triggered sweeps run while
	// the attacker's window is still open. The sweeps must not evict it.
	for i := range 2*rateLimiterSweepInterval + 10 {
		limiter.Allow(fmt.Sprintf("flood:%d", i))
	}

	if _, ok := limiter.entries["attacker"]; !ok {
		t.Fatal("in-window attacker entry was evicted by the sweep — counter could be reset")
	}
	if limiter.Allow("attacker") {
		t.Fatal("attacker key must remain throttled; the flood must not reset its counter")
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
