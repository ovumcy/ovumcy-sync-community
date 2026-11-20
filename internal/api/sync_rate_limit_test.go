package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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

// TestEveryRouteIsOnItsIntendedLimiter pins the split route by route. With an
// auth budget of 1 and a sync budget of 100, a credential route answers its
// second request 429 and a sync route does not. The body is not a JSON object,
// so each request stops at decoding, after the route limiter and before any
// step-up bucket or login-identifier bucket is charged.
func TestEveryRouteIsOnItsIntendedLimiter(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		authRateLimitCount:  1,
		authRateLimitWindow: 15 * time.Minute,
		syncRateLimitCount:  100,
		syncRateLimitWindow: time.Minute,
		enableTOTP:          true,
	})
	token := registerStepUpOwner(t, handler)

	send := func(method, path string) int {
		request := httptest.NewRequest(method, path, strings.NewReader(`"x"`))
		request.RemoteAddr = "203.0.113.70:4000"
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+token)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder.Code
	}

	credential := [][2]string{
		{http.MethodPost, "/auth/login"},
		{http.MethodPost, "/auth/forgot-password"},
		{http.MethodPost, "/auth/reset-password"},
		{http.MethodPost, "/auth/totp/challenge"},
		{http.MethodPost, "/auth/change-password"},
		{http.MethodPost, "/auth/recovery-code/regenerate"},
		{http.MethodPost, "/auth/totp/enroll"},
		{http.MethodPost, "/auth/totp/verify"},
		{http.MethodPost, "/auth/totp/disable"},
		{http.MethodDelete, "/account"},
	}
	for _, route := range credential {
		first := send(route[0], route[1])
		if second := send(route[0], route[1]); first == http.StatusTooManyRequests || second != http.StatusTooManyRequests {
			t.Errorf("%s %s: statuses %d, %d; want the auth budget of 1 to refuse the second", route[0], route[1], first, second)
		}
	}

	sync := [][2]string{
		{http.MethodPost, "/sync/devices"},
		{http.MethodDelete, "/sync/devices/device-0001"},
		{http.MethodGet, "/sync/recovery-key"},
		{http.MethodPut, "/sync/recovery-key"},
		{http.MethodGet, "/sync/blob"},
		{http.MethodPut, "/sync/blob"},
	}
	for _, route := range sync {
		for range 3 {
			if got := send(route[0], route[1]); got == http.StatusTooManyRequests {
				t.Errorf("%s %s: 429 inside the sync budget of 100", route[0], route[1])
				break
			}
		}
	}
}

// TestSuccessfulLogoutsDoNotSpendTheCredentialBudget: a revoke that finds its
// session refunds the per-IP slot, so users sharing an address can all sign
// out; a token with no session stays charged.
func TestSuccessfulLogoutsDoNotSpendTheCredentialBudget(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		authRateLimitCount:  1,
		authRateLimitWindow: 15 * time.Minute,
	})
	for i := range 3 {
		token := registerAccountFrom(t, handler, fmt.Sprintf("logout-%d@example.com", i), fmt.Sprintf("198.51.100.%d:4000", i+1))
		performJSONRequest(t, handler, http.MethodDelete, "/auth/session", nil, token, http.StatusOK)
	}
	performJSONRequest(t, handler, http.MethodDelete, "/auth/session", nil, "no-such-token", http.StatusUnauthorized)
	performJSONRequest(t, handler, http.MethodDelete, "/auth/session", nil, "no-such-token", http.StatusTooManyRequests)
}

// TestSuccessfulLoginsDoNotSpendThePerIPBudget: a login that issues a session
// refunds its per-IP slot, so sign-ins behind one address do not lock each
// other out; a wrong password stays charged.
func TestSuccessfulLoginsDoNotSpendThePerIPBudget(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		authRateLimitCount:  1,
		authRateLimitWindow: 15 * time.Minute,
	})
	registerOwner(t, handler)
	good := map[string]string{"login": "owner@example.com", "password": "correct horse battery staple"}
	for range 3 {
		performJSONRequest(t, handler, http.MethodPost, "/auth/login", good, "", http.StatusOK)
	}
	bad := map[string]string{"login": "someone@example.com", "password": "wrong-password-1"}
	performJSONRequest(t, handler, http.MethodPost, "/auth/login", bad, "", http.StatusUnauthorized)
	performJSONRequest(t, handler, http.MethodPost, "/auth/login", good, "", http.StatusTooManyRequests)
}

func retryAfterSeconds(t *testing.T, response interface{ Header() http.Header }) int {
	t.Helper()
	seconds, err := strconv.Atoi(response.Header().Get("Retry-After"))
	if err != nil {
		t.Fatalf("Retry-After is not an integer: %q", response.Header().Get("Retry-After"))
	}
	return seconds
}
