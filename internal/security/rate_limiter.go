package security

import (
	"sync"
	"time"
)

type RateLimiter struct {
	mu      sync.Mutex
	entries map[string]rateLimitEntry
	limit   int
	window  time.Duration
	now     func() time.Time
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
