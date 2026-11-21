package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestServerRegisterRefusedWhenRegistrationDisabled pins the
// REGISTRATION_ENABLED=false contract: register answers
// 403 registration_disabled, the refusal comes before the body is read and
// before the rate limiter (so no bcrypt and no slot is spent), and an account
// created while registration was open still signs in.
func TestServerRegisterRefusedWhenRegistrationDisabled(t *testing.T) {
	store := newTestStore(t, ":memory:")
	open := newTestServerWithOptions(t, serverTestOptions{store: store})
	closed := newTestServerWithOptions(t, serverTestOptions{
		store:               store,
		disableRegistration: true,
		authRateLimitCount:  1,
	})

	credentials := map[string]string{
		"login":    "owner@example.com",
		"password": "correct horse battery staple",
	}
	performJSONRequest(t, open, http.MethodPost, "/auth/register", credentials, "", http.StatusCreated)

	// Past the one-request auth budget: a charged limiter would answer 429.
	for i := 0; i < 3; i++ {
		response := performJSONRequest(t, closed, http.MethodPost, "/auth/register", map[string]string{
			"login":    "intruder@example.com",
			"password": "another secure password!",
		}, "", http.StatusForbidden)

		var payload map[string]string
		decodeResponse(t, response.Body.Bytes(), &payload)
		if payload["error"] != "registration_disabled" {
			t.Fatalf("attempt %d: unexpected payload %#v", i+1, payload)
		}
	}

	// A body that would fail decoding still gets the refusal, not invalid_json.
	request := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewBufferString("{not json"))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	closed.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("malformed body: status = %d, want 403", recorder.Code)
	}

	// Nothing was created: the refused login is still free once registration
	// reopens.
	performJSONRequest(t, open, http.MethodPost, "/auth/register", map[string]string{
		"login":    "intruder@example.com",
		"password": "another secure password!",
	}, "", http.StatusCreated)

	performJSONRequest(t, closed, http.MethodPost, "/auth/login", credentials, "", http.StatusOK)
}
