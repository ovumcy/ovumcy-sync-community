package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func sendRaw(handler http.Handler, method string, path string, body string, bearer string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = "203.0.113.50:4000"
	request.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestWithAuthRateLimitsFailedLookupsPerClientIP(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{authRateLimitCount: 1})
	budget := sessionReadRateLimitCount(1)
	session := registerAccountFrom(t, handler, "owner@example.com", "198.51.100.9:1000")

	for i := range budget - 1 {
		if got := sendRaw(handler, http.MethodGet, "/auth/session", "", "not-a-session").Code; got != http.StatusUnauthorized {
			t.Fatalf("failed lookup %d: status %d, want 401", i+1, got)
		}
	}
	// Valid sessions from the same address refund their slot.
	for i := range 3 {
		if got := sendRaw(handler, http.MethodGet, "/auth/session", "", session).Code; got != http.StatusOK {
			t.Fatalf("valid session %d: status %d, want 200", i+1, got)
		}
	}
	if got := sendRaw(handler, http.MethodGet, "/auth/session", "", "not-a-session").Code; got != http.StatusUnauthorized {
		t.Fatalf("last in-budget failure: status %d, want 401", got)
	}

	// Over budget the limiter answers before the store is consulted, for a
	// valid session too.
	for _, bearer := range []string{"not-a-session", "", session} {
		response := sendRaw(handler, http.MethodGet, "/auth/session", "", bearer)
		if response.Code != http.StatusTooManyRequests || !strings.Contains(response.Body.String(), "rate_limited") {
			t.Fatalf("bearer %q over budget: status %d body %s, want 429 rate_limited", bearer, response.Code, response.Body.String())
		}
	}
}

func TestWithAuthStoreFailureIsInternalErrorAndRefunded(t *testing.T) {
	store := newTestStore(t, ":memory:")
	handler := newTestServerWithOptions(t, serverTestOptions{authRateLimitCount: 1, store: store})
	session := registerAccountFrom(t, handler, "owner@example.com", "198.51.100.9:1000")
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	// More store failures than the pre-auth budget: each is a 500, never a
	// 429, because a store failure is not charged to the caller.
	for i := 0; i <= sessionReadRateLimitCount(1); i++ {
		response := sendRaw(handler, http.MethodGet, "/auth/session", "", session)
		if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "internal_error") {
			t.Fatalf("request %d: status %d body %s, want 500 internal_error", i+1, response.Code, response.Body.String())
		}
	}
}

// A stolen session hammering a per-account-limited route must not get its
// session lookups for free once the handler answers 429.
func TestWithAuthKeepsTheIPSlotChargedOnAHandler429(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{authRateLimitCount: 1})
	budget := sessionReadRateLimitCount(1)
	session := registerAccountFrom(t, handler, "owner@example.com", "198.51.100.9:1000")

	throttled := 0
	for range budget + 1 {
		if sendRaw(handler, http.MethodPost, "/auth/change-password", `{}`, session).Code == http.StatusTooManyRequests {
			throttled++
		}
	}
	if throttled != budget {
		t.Fatalf("handler 429s = %d, want %d", throttled, budget)
	}

	if got := sendRaw(handler, http.MethodGet, "/auth/session", "", session).Code; got != http.StatusTooManyRequests {
		t.Fatalf("read from the throttled address: status %d, want 429 before the session lookup", got)
	}
	request := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	request.RemoteAddr = "198.51.100.77:4000"
	request.Header.Set("Authorization", "Bearer "+session)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("read from another address: status %d, want 200", recorder.Code)
	}
}

func TestLogoutStoreFailureIsInternalError(t *testing.T) {
	store := newTestStore(t, ":memory:")
	handler := newTestServerWithOptions(t, serverTestOptions{store: store})
	session := registerAccountFrom(t, handler, "owner@example.com", "198.51.100.9:1000")
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	response := sendRaw(handler, http.MethodDelete, "/auth/session", "", session)
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "internal_error") {
		t.Fatalf("status %d body %s, want 500 internal_error", response.Code, response.Body.String())
	}
}

func TestLoginIdentifierKeyIsFixedSize(t *testing.T) {
	short, ok := loginIdentifierKey("Owner@Example.com ")
	if !ok {
		t.Fatal("expected a key for a non-empty login")
	}
	long, _ := loginIdentifierKey(strings.Repeat("a", 4000))
	if len(short) != len(long) {
		t.Fatalf("key lengths differ: %d vs %d", len(short), len(long))
	}
	if strings.Contains(short, "owner") {
		t.Fatalf("key %q holds the login in the clear", short)
	}
	if same, _ := loginIdentifierKey("owner@example.com"); same != short {
		t.Fatal("normalized logins must share one bucket")
	}
}

func TestDecodeJSONRejectsTrailingValues(t *testing.T) {
	handler := newTestServer(t)

	for _, trailer := range []string{"{}", "null", "1", `"x"`, "{"} {
		body := `{"login":"owner@example.com","password":"wrong password"}` + trailer
		response := sendRaw(handler, http.MethodPost, "/auth/login", body, "")
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_json") {
			t.Fatalf("trailer %q: status %d body %s, want 400 invalid_json", trailer, response.Code, response.Body.String())
		}
	}

	response := sendRaw(handler, http.MethodPost, "/auth/login", `{"login":"owner@example.com","password":"wrong password"}`+" \n\t", "")
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("trailing whitespace: status %d, want 401", response.Code)
	}
}

func TestTOTPChallengeIsRateLimitedBeforeConfigurationCheck(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{authRateLimitCount: 1})
	body := `{"challenge_id":"x","code":"000000"}`

	if got := sendRaw(handler, http.MethodPost, "/auth/totp/challenge", body, "").Code; got != http.StatusServiceUnavailable {
		t.Fatalf("first challenge without TOTP: status %d, want 503", got)
	}
	if got := sendRaw(handler, http.MethodPost, "/auth/totp/challenge", body, "").Code; got != http.StatusTooManyRequests {
		t.Fatalf("second challenge without TOTP: status %d, want 429", got)
	}
}
