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

	for i := 0; i < budget-1; i++ {
		if got := sendRaw(handler, http.MethodGet, "/auth/session", "", "not-a-session").Code; got != http.StatusUnauthorized {
			t.Fatalf("failed lookup %d: status %d, want 401", i+1, got)
		}
	}
	// Valid sessions from the same address refund their slot.
	for i := 0; i < 3; i++ {
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
