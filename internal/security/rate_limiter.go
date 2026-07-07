package security

import (
	"sync"
	"time"
)

// rateLimiterSweepInterval bounds the growth of the in-memory entries map.
// Without a sweep, keys (attacker-influenced login / client-IP strings)
// accumulate forever, so a sustained distributed attack spraying unique keys
// would grow the map without limit even though each individual key is
// throttled. Once every rateLimiterSweepInterval Allow calls, an amortized
// sweep deletes only EXPIRED entries — those whose window has fully elapsed —
// which is behavior-preserving: Allow already treats an expired entry
// identically to a missing one (it overwrites it with a fresh count-1 window
// on the next touch), so removing an expired key and letting the next touch
// recreate it yields the exact same throttling.
//
// In-window entries are never evicted, by design: an attacker who can flood
// unique keys must not be able to push their own throttled key out of the map
// and reset its counter (that would defeat the limiter).
//
// Each Allow call inserts at most one new key, so the map grows by at most
// rateLimiterSweepInterval keys between sweeps. Its size is therefore bounded
// by the distinct in-window keys plus rateLimiterSweepInterval — never by the
// total keys ever seen. After a burst goes idle, already-expired keys linger
// until rateLimiterSweepInterval further Allow calls accumulate; that linger
// is capped by the same bound and the map never grows while idle. Under
// normal single-instance self-hosted load the map holds a handful of client
// IPs and the amortized O(n) pass is negligible.
const rateLimiterSweepInterval = 1024

type RateLimiter struct {
	mu            sync.Mutex
	entries       map[string]rateLimitEntry
	limit         int
	window        time.Duration
	now           func() time.Time
	opsSinceSweep int
}

type rateLimitEntry struct {
	count       int
	windowStart time.Time
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		entries: make(map[string]rateLimitEntry),
		limit:   limit,
		window:  window,
		now:     time.Now,
	}
}

func (l *RateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now().UTC()
	allowed := l.allowLocked(key, now)
	l.maybeSweepLocked(now)
	return allowed
}

func (l *RateLimiter) allowLocked(key string, now time.Time) bool {
	entry, exists := l.entries[key]
	if !exists || now.Sub(entry.windowStart) >= l.window {
		l.entries[key] = rateLimitEntry{
			count:       1,
			windowStart: now,
		}
		return true
	}

	if entry.count >= l.limit {
		return false
	}

	entry.count++
	l.entries[key] = entry
	return true
}

// maybeSweepLocked runs an amortized, opportunistic sweep of expired entries.
// It is called from Allow with l.mu already held and fires once every
// rateLimiterSweepInterval Allow calls. The trigger is deliberately
// interval-only: a size-based trigger would degrade into a full-map scan on
// every single Allow call once the map held more than the threshold of
// in-window entries (each such sweep deletes nothing, resets the counter,
// and immediately re-arms), concentrating O(n) mutex work on exactly the
// flood the limiter exists to absorb.
func (l *RateLimiter) maybeSweepLocked(now time.Time) {
	l.opsSinceSweep++
	if l.opsSinceSweep < rateLimiterSweepInterval {
		return
	}
	l.opsSinceSweep = 0

	// Deleting only expired entries is behavior-preserving: allowLocked already
	// resets an expired entry to a fresh count-1 window on the next touch, so a
	// deleted-then-recreated expired key throttles identically to one that was
	// reset in place. In-window entries are retained so a throttled attacker
	// cannot evict and reset their own counter.
	for k, entry := range l.entries {
		if now.Sub(entry.windowStart) >= l.window {
			delete(l.entries, k)
		}
	}
}
