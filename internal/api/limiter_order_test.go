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

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/sync/devices"},
		{http.MethodGet, "/sync/devices"},
		{http.MethodDelete, "/sync/devices/device-1aaaa"},
		{http.MethodGet, "/sync/recovery-key"},
		{http.MethodPut, "/sync/recovery-key"},
		{http.MethodGet, "/sync/blob"},
		{http.MethodPut, "/sync/blob"},
	}
	// The largest budget is the read routes': SYNC count × the read multiplier.
	maxAttempts := 2*sessionReadRateLimitMultiplier + 1
	for _, route := range routes {
		throttled := false
		for attempt := 0; attempt < maxAttempts && !throttled; attempt++ {
			response := serveJSON(t, handler, route.method, route.path, nil, sessionToken)
			switch response.Code {
			case http.StatusTooManyRequests:
				throttled = true
			case http.StatusForbidden:
				var payload map[string]string
				decodeResponse(t, response.Body.Bytes(), &payload)
				if payload["error"] != "sync_disabled" {
					t.Fatalf("%s %s: unexpected payload %#v", route.method, route.path, payload)
				}
			default:
				t.Fatalf("%s %s: status %d, body=%s", route.method, route.path, response.Code, response.Body.String())
			}
		}
		if !throttled {
			t.Fatalf("%s %s: no 429 within %d sync_disabled answers", route.method, route.path, maxAttempts)
		}
	}
}
