package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const originGateTestPassword = "correct horse battery staple"

// A cross-site page can send a body-less POST in no-cors mode without a
// preflight. Refused on its Origin ahead of every limiter, it cannot spend the
// victim's per-IP login or session-lookup buckets.
func TestForeignOriginIsRefusedBeforeTheLimiters(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		allowedOrigins:     []string{"https://app.example"},
		authRateLimitCount: 10,
	})
	performJSONRequest(t, handler, http.MethodPost, "/auth/register",
		map[string]string{"login": "owner@example.com", "password": originGateTestPassword}, "", http.StatusCreated)

	for range 11 {
		for _, route := range []struct{ method, path string }{
			{http.MethodPost, "/auth/login"},
			{http.MethodGet, "/auth/session"},
		} {
			request := httptest.NewRequest(route.method, route.path, nil)
			request.Header.Set("Origin", "https://evil.example")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("%s %s from a foreign origin: status %d, body=%s", route.method, route.path, recorder.Code, recorder.Body.String())
			}
			var payload map[string]string
			decodeResponse(t, recorder.Body.Bytes(), &payload)
			if payload["error"] != "origin_not_allowed" {
				t.Fatalf("unexpected refusal payload: %#v", payload)
			}
			if recorder.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("a refused origin must get no CORS headers")
			}
		}
	}

	credentials := map[string]string{"login": "owner@example.com", "password": originGateTestPassword}
	performJSONRequest(t, handler, http.MethodPost, "/auth/login", credentials, "", http.StatusOK)
	performJSONRequest(t, handler, http.MethodGet, "/auth/session", nil, "", http.StatusUnauthorized)

	allowed := performJSONRequestWithOptions(t, requestOptions{
		handler:        handler,
		method:         http.MethodPost,
		path:           "/auth/login",
		body:           credentials,
		expectedStatus: http.StatusOK,
		headers:        map[string]string{"Origin": "https://app.example"},
	})
	if allowed.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatalf("expected the allowed origin echoed, got %q", allowed.Header().Get("Access-Control-Allow-Origin"))
	}

	preflight := httptest.NewRequest(http.MethodOptions, "/auth/login", nil)
	preflight.Header.Set("Origin", "https://app.example")
	preflight.Header.Set("Access-Control-Request-Method", http.MethodPost)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, preflight)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("allowed preflight: status %d", recorder.Code)
	}
}
