package api

import (
	"net/http"
	"strconv"
	"testing"
	"time"
)

// TestSyncRoutesUseTheirOwnLimiter pins the split: a sync route spends
// SYNC_RATE_LIMIT_* (here 3 per minute, so its 429 says at most 60 seconds),
// and spending it leaves the credential routes' AUTH_RATE_LIMIT_* budget
// (here 1 per 15 minutes) untouched.
func TestSyncRoutesUseTheirOwnLimiter(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		authRateLimitCount:  1,
		authRateLimitWindow: 15 * time.Minute,
		syncRateLimitCount:  3,
		syncRateLimitWindow: time.Minute,
	})
	token := registerStepUpOwner(t, handler)

	for range 3 {
		performJSONRequest(t, handler, http.MethodGet, "/sync/blob", nil, token, http.StatusNotFound)
	}
	throttled := performJSONRequest(t, handler, http.MethodGet, "/sync/blob", nil, token, http.StatusTooManyRequests)
	if seconds := retryAfterSeconds(t, throttled); seconds > 60 {
		t.Fatalf("sync Retry-After = %d, want at most the 60s sync window", seconds)
	}

	change := stepUpCalls("wrong password entirely")["change"]
	performJSONRequest(t, handler, change.method, change.path, change.body, token, http.StatusUnauthorized)
	throttled = performJSONRequest(t, handler, change.method, change.path, change.body, token, http.StatusTooManyRequests)
	if seconds := retryAfterSeconds(t, throttled); seconds <= 60 {
		t.Fatalf("auth Retry-After = %d, want the 15m auth window", seconds)
	}
}

// TestSessionReadBudgetFollowsTheSyncCount pins that the read-state budget is
// 30 x SYNC_RATE_LIMIT_COUNT, not 30 x the auth count.
func TestSessionReadBudgetFollowsTheSyncCount(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		authRateLimitCount:  1,
		authRateLimitWindow: 15 * time.Minute,
		syncRateLimitCount:  2,
		syncRateLimitWindow: time.Minute,
	})
	token := registerStepUpOwner(t, handler)

	for range 2 * sessionReadRateLimitMultiplier {
		performJSONRequest(t, handler, http.MethodGet, "/auth/session", nil, token, http.StatusOK)
	}
	performJSONRequest(t, handler, http.MethodGet, "/auth/session", nil, token, http.StatusTooManyRequests)
}

func retryAfterSeconds(t *testing.T, response interface{ Header() http.Header }) int {
	t.Helper()
	seconds, err := strconv.Atoi(response.Header().Get("Retry-After"))
	if err != nil {
		t.Fatalf("Retry-After is not an integer: %q", response.Header().Get("Retry-After"))
	}
	return seconds
}
