package security

import (
	"sync"
	"time"
)

// rateLimiterSweepInterval and rateLimiterSweepThreshold bound the growth of
// the in-memory entries map. Without a sweep, keys (attacker-influenced login
// / client-IP strings) accumulate forever, so a sustained distributed attack
// spraying unique keys would grow the map without limit even though each
// individual key is throttled. The sweep deletes only EXPIRED entries — those
// whose window has fully elapsed — which is behavior-preserving: Allow already
// treats an expired entry identically to a missing one (it overwrites it with
// a fresh count-1 window on the next touch), so removing an expired key and
// letting the next touch recreate it yields the exact same throttling.
//
// In-window entries are never evicted, by design: an attacker who can flood
// unique keys must not be able to push their own throttled key out of the map
// and reset its counter (that would defeat the limiter). Growth is therefore
// bounded by the number of distinct keys seen within the current window (plus
// up to one sweep interval of lag), not by the total number of keys ever seen.
//
// The constants are deliberately conservative. Under normal single-instance
// self-hosted load the map holds only a handful of client IPs, sweeps almost
// never fire, and the amortized O(n) pass is negligible. Under attack the
// interval caps how many Allow calls pass between sweeps, and the size
// threshold forces a sweep once the map has grown past the threshold even if
// the interval has not yet elapsed, so a burst cannot outrun the interval
// counter.
const (
	rateLimiterSweepInterval  = 1024
	rateLimiterSweepThreshold = 1024
)

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
// It is called from Allow with l.mu already held. A sweep fires when at least
// rateLimiterSweepInterval Allow calls have happened since the last sweep, or
// when the map has grown past rateLimiterSweepThreshold live-or-stale keys.
func (l *RateLimiter) maybeSweepLocked(now time.Time) {
	l.opsSinceSweep++
	if l.opsSinceSweep < rateLimiterSweepInterval && len(l.entries) <= rateLimiterSweepThreshold {
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
