package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func serveJSON(t *testing.T, handler http.Handler, method, path string, body any, sessionToken string) *httptest.ResponseRecorder {
	t.Helper()

	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			t.Fatalf("marshal body: %v", err)
		}
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+sessionToken)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// TestTOTPAccountRoutesMeterBeforeTheNotConfiguredAnswer: a server without a
// field-encryption key still charges the per-account credential budget before
// answering 503, so the 503 is not an unmetered loop.
func TestTOTPAccountRoutesMeterBeforeTheNotConfiguredAnswer(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		authRateLimitCount:  1,
		authRateLimitWindow: time.Hour,
	})
	token := registerOwnerWithTOTP(t, handler)

	for _, path := range []string{"/auth/totp/enroll", "/auth/totp/verify", "/auth/totp/disable"} {
		body := map[string]string{"current_password": totpTestPassword, "code": "123456"}
		first := serveJSON(t, handler, http.MethodPost, path, body, token)
		if first.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s first: status %d, body=%s", path, first.Code, first.Body.String())
		}
		second := serveJSON(t, handler, http.MethodPost, path, body, token)
		if second.Code != http.StatusTooManyRequests || second.Header().Get("Retry-After") == "" {
			t.Fatalf("%s second: status %d, body=%s", path, second.Code, second.Body.String())
		}
	}
}

// TestSyncDisabledAnswerIsMetered: an account refused with 403 sync_disabled
// still spends its route's per-account budget, and runs into 429 once it is
// spent.
func TestSyncDisabledAnswerIsMetered(t *testing.T) {
	store, _ := newFileBackedTestStore(t)
	handler := newTestServerWithOptions(t, serverTestOptions{
		store:               store,
		syncRateLimitCount:  2,
		syncRateLimitWindow: time.Hour,
	})

	const accountID = "managedacct5678"
	sessionToken := provisionManagedAccountWithData(t, handler, accountID)
	if err := store.SetAccountLapsed(context.Background(), accountID, time.Now().UTC()); err != nil {
		t.Fatalf("set account lapsed: %v", err)
	}

	// refusals is the route's budget left after provisioning, which spent one
	// slot each on POST /sync/devices, PUT /sync/recovery-key and PUT /sync/blob.
	routes := []struct {
		method   string
		path     string
		refusals int
	}{
		{http.MethodPost, "/sync/devices", 1},
		{http.MethodGet, "/sync/devices", 2 * sessionReadRateLimitMultiplier},
		{http.MethodDelete, "/sync/devices/device-1aaaa", 2},
		{http.MethodGet, "/sync/recovery-key", 2},
		{http.MethodPut, "/sync/recovery-key", 1},
		{http.MethodGet, "/sync/blob", 2},
		{http.MethodPut, "/sync/blob", 1},
	}
	for _, route := range routes {
		for attempt := 0; attempt < route.refusals; attempt++ {
			response := serveJSON(t, handler, route.method, route.path, nil, sessionToken)
			var payload map[string]string
			decodeResponse(t, response.Body.Bytes(), &payload)
			if response.Code != http.StatusForbidden || payload["error"] != "sync_disabled" {
				t.Fatalf("%s %s attempt %d: status %d, payload %#v", route.method, route.path, attempt+1, response.Code, payload)
			}
		}
		response := serveJSON(t, handler, route.method, route.path, nil, sessionToken)
		if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" {
			t.Fatalf("%s %s past its budget: status %d, body=%s", route.method, route.path, response.Code, response.Body.String())
		}
	}
}
