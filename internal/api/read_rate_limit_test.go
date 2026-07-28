package api

import (
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSyncReadEndpointsAreRateLimitedPerAccount pins that GET /sync/blob and
// GET /sync/recovery-key pass the same per-account limiter as their PUT
// counterparts: with a one-request budget the second read answers 429 with a
// Retry-After header, instead of letting a valid session drive unmetered
// MAX_BLOB_BYTES-sized reads past the per-IP auth gate.
func TestSyncReadEndpointsAreRateLimitedPerAccount(t *testing.T) {
	for _, path := range []string{"/sync/blob", "/sync/recovery-key"} {
		t.Run(path, func(t *testing.T) {
			handler := newTestServerWithOptions(t, serverTestOptions{authRateLimitCount: 1})
			registered := registerOwner(t, handler)

			// The budget's single slot. A 404 is expected — nothing is
			// stored yet — the point is that the read consumed the limiter.
			performJSONRequest(
				t,
				handler,
				http.MethodGet,
				path,
				nil,
				registered.SessionToken,
				http.StatusNotFound,
			)

			response := performJSONRequest(
				t,
				handler,
				http.MethodGet,
				path,
				nil,
				registered.SessionToken,
				http.StatusTooManyRequests,
			)

			var payload map[string]string
			decodeResponse(t, response.Body.Bytes(), &payload)
			if payload["error"] != "rate_limited" {
				t.Fatalf("unexpected rate limit payload: %#v", payload)
			}
			if response.Header().Get("Retry-After") == "" {
				t.Fatal("expected a Retry-After header on the throttled read")
			}
		})
	}
}

// sessionStateReadPaths are the authenticated read-only account-state routes:
// they answer from state the caller's session already entitles it to, and each
// costs one indexed query, so they share the higher per-account read budget
// rather than the auth budget.
var sessionStateReadPaths = []string{"/auth/session", "/sync/capabilities", "/sync/devices"}

// registerAccountFrom registers one account from an explicit client address, so
// a test that needs two accounts is not stopped by the per-IP register budget.
func registerAccountFrom(t *testing.T, handler http.Handler, login string, remoteAddr string) string {
	t.Helper()

	response := performJSONRequestWithOptions(t, requestOptions{
		handler:        handler,
		method:         http.MethodPost,
		path:           "/auth/register",
		body:           map[string]string{"login": login, "password": "correct horse battery staple"},
		remoteAddr:     remoteAddr,
		expectedStatus: http.StatusCreated,
	})

	var payload registerPayload
	decodeResponse(t, response.Body.Bytes(), &payload)
	return payload.SessionToken
}

// spendSessionReadBudget consumes the whole per-account read budget for path,
// asserting every request inside the budget still succeeds.
func spendSessionReadBudget(t *testing.T, handler http.Handler, path string, sessionToken string, remoteAddr string) {
	t.Helper()

	for range sessionReadRateLimitCount(1) {
		performJSONRequestWithOptions(t, requestOptions{
			handler:        handler,
			method:         http.MethodGet,
			path:           path,
			sessionToken:   sessionToken,
			remoteAddr:     remoteAddr,
			expectedStatus: http.StatusOK,
		})
	}
}

// assertRateLimited pins the repo's throttled-response shape: 429, the stable
// `rate_limited` error key, and a Retry-After header.
func assertRateLimited(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "rate_limited" {
		t.Fatalf("unexpected rate limit payload: %#v", payload)
	}
	if response.Header().Get("Retry-After") == "" {
		t.Fatal("expected a Retry-After header on the throttled response")
	}
}

// TestSessionStateReadsAreRateLimitedPerAccount pins that the authenticated
// read-only account-state routes carry a ceiling at all: every request inside
// the budget succeeds and the first one past it answers 429. Before this
// limiter these three routes were the only authenticated surface a valid
// session could drive without any bound.
func TestSessionStateReadsAreRateLimitedPerAccount(t *testing.T) {
	for _, path := range sessionStateReadPaths {
		t.Run(path, func(t *testing.T) {
			handler := newTestServerWithOptions(t, serverTestOptions{authRateLimitCount: 1})
			registered := registerOwner(t, handler)

			spendSessionReadBudget(t, handler, path, registered.SessionToken, "")

			response := performJSONRequest(
				t,
				handler,
				http.MethodGet,
				path,
				nil,
				registered.SessionToken,
				http.StatusTooManyRequests,
			)
			assertRateLimited(t, response)
		})
	}
}

// TestSessionStateReadsKeyOnAccountNotClientIP pins the keying: the budget
// belongs to the authenticated account, so moving to another source address
// does not mint a fresh one (a roaming or proxied client cannot multiply its
// quota), while a second account keeps a budget of its own from the very same
// address (the bucket is not global).
func TestSessionStateReadsKeyOnAccountNotClientIP(t *testing.T) {
	const (
		firstClient  = "203.0.113.10:4001"
		secondClient = "203.0.113.11:4002"
	)

	for _, path := range sessionStateReadPaths {
		t.Run(path, func(t *testing.T) {
			handler := newTestServerWithOptions(t, serverTestOptions{authRateLimitCount: 1})
			ownerToken := registerAccountFrom(t, handler, "owner@example.com", firstClient)
			otherToken := registerAccountFrom(t, handler, "other@example.com", secondClient)

			spendSessionReadBudget(t, handler, path, ownerToken, firstClient)

			// Same account, different client address: still throttled.
			response := performJSONRequestWithOptions(t, requestOptions{
				handler:        handler,
				method:         http.MethodGet,
				path:           path,
				sessionToken:   ownerToken,
				remoteAddr:     secondClient,
				expectedStatus: http.StatusTooManyRequests,
			})
			assertRateLimited(t, response)

			// Different account, the address that exhausted the first budget:
			// unaffected.
			performJSONRequestWithOptions(t, requestOptions{
				handler:        handler,
				method:         http.MethodGet,
				path:           path,
				sessionToken:   otherToken,
				remoteAddr:     firstClient,
				expectedStatus: http.StatusOK,
			})
		})
	}
}

// TestLogoutIsRateLimitedPerClientIP pins DELETE /auth/session on the per-IP
// auth budget. The route consumes the bearer token instead of authenticating
// through it, so there is no account to key on before the revoke; the client
// address is the only identity available, and it is the one that matters for an
// anonymous caller replaying invented tokens. The throttle runs ahead of the
// store, so the second attempt is refused whatever token it carries.
func TestLogoutIsRateLimitedPerClientIP(t *testing.T) {
	const (
		firstClient  = "203.0.113.20:5001"
		secondClient = "203.0.113.21:5002"
	)

	handler := newTestServerWithOptions(t, serverTestOptions{authRateLimitCount: 1})
	registered := registerOwner(t, handler)

	performJSONRequestWithOptions(t, requestOptions{
		handler:        handler,
		method:         http.MethodDelete,
		path:           "/auth/session",
		sessionToken:   registered.SessionToken,
		remoteAddr:     firstClient,
		expectedStatus: http.StatusOK,
	})

	response := performJSONRequestWithOptions(t, requestOptions{
		handler:        handler,
		method:         http.MethodDelete,
		path:           "/auth/session",
		sessionToken:   "bogus-session-token",
		remoteAddr:     firstClient,
		expectedStatus: http.StatusTooManyRequests,
	})
	assertRateLimited(t, response)

	// Another client address carries its own budget, so one caller exhausting
	// its quota cannot deny logout to everyone else behind the same server.
	performJSONRequestWithOptions(t, requestOptions{
		handler:        handler,
		method:         http.MethodDelete,
		path:           "/auth/session",
		sessionToken:   "bogus-session-token",
		remoteAddr:     secondClient,
		expectedStatus: http.StatusUnauthorized,
	})
}

// TestSessionReadRateLimitCountDerivesFromAuthBudget pins the arithmetic that
// sizes the read budget: it is a fixed multiple of AUTH_RATE_LIMIT_COUNT, so
// the default 10-per-minute auth budget yields 300 per minute per account per
// route. The guard cases matter because a silently negative product would
// invert the intent and make the most generous bucket the strictest one.
func TestSessionReadRateLimitCountDerivesFromAuthBudget(t *testing.T) {
	for _, testCase := range []struct {
		name string
		in   int
		want int
	}{
		{name: "default auth budget", in: 10, want: 300},
		{name: "single-request auth budget", in: 1, want: 30},
		{name: "zero is left alone", in: 0, want: 0},
		{name: "negative is left alone", in: -5, want: -5},
		{name: "overflow is left alone", in: math.MaxInt, want: math.MaxInt},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := sessionReadRateLimitCount(testCase.in); got != testCase.want {
				t.Fatalf("sessionReadRateLimitCount(%d) = %d, want %d", testCase.in, got, testCase.want)
			}
		})
	}
}

// TestHealthAndReadinessProbesAreNotRateLimited pins the deliberate exemption.
// The container HEALTHCHECK polls readiness on a fixed interval and an uptime
// monitor polls liveness on its own, so a limiter on either would convert
// routine monitoring into a reported outage: the probe would answer 429, the
// runtime would mark the container unhealthy, and an orchestrator acting on
// health would restart or depool a server that was serving correctly. Both
// probes therefore stay open however often they are called — asserted here well
// past the tightest budget the server can be configured with.
func TestHealthAndReadinessProbesAreNotRateLimited(t *testing.T) {
	for _, path := range []string{"/healthz", "/readyz"} {
		t.Run(path, func(t *testing.T) {
			handler := newTestServerWithOptions(t, serverTestOptions{authRateLimitCount: 1})

			for range 3 * sessionReadRateLimitCount(1) {
				performJSONRequest(t, handler, http.MethodGet, path, nil, "", http.StatusOK)
			}
		})
	}
}
