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
		authRateLimitCount: 1,
	})
	performJSONRequest(t, handler, http.MethodPost, "/auth/register",
		map[string]string{"login": "owner@example.com", "password": originGateTestPassword}, "", http.StatusCreated)

	// One more than each bucket holds: 1 login, 30 session lookups.
	for _, route := range []struct {
		method, path string
		times        int
	}{
		{http.MethodPost, "/auth/login", 2},
		{http.MethodGet, "/auth/session", 31},
	} {
		for range route.times {
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
			if recorder.Header().Get("Access-Control-Allow-Origin") != "" || recorder.Header().Get("Vary") != "Origin" {
				t.Fatalf("a refused origin must get Vary: Origin and no CORS headers, got %v", recorder.Header())
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
		remoteAddr:     "198.51.100.7:4000",
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

// A cross-site no-cors GET carries no Origin. Its fetch metadata is refused
// ahead of every limiter, so it cannot spend the victim's per-IP
// session-lookup bucket; the monitoring routes stay reachable.
func TestCrossSiteFetchWithoutOriginIsRefusedBeforeTheLimiters(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		allowedOrigins:     []string{"https://app.example"},
		authRateLimitCount: 1,
	})

	serveFrom := func(path, fetchSite, origin string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		if fetchSite != "" {
			request.Header.Set("Sec-Fetch-Site", fetchSite)
		}
		if origin != "" {
			request.Header.Set("Origin", origin)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	serve := func(path, fetchSite string) *httptest.ResponseRecorder {
		return serveFrom(path, fetchSite, "")
	}

	// One more than the session-lookup bucket holds, from both refused sites.
	for _, fetchSite := range []string{"cross-site", "Same-Site"} {
		for range 31 {
			recorder := serve("/auth/session", fetchSite)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("Sec-Fetch-Site %s: status %d, body=%s", fetchSite, recorder.Code, recorder.Body.String())
			}
			var payload map[string]string
			decodeResponse(t, recorder.Body.Bytes(), &payload)
			if payload["error"] != "origin_not_allowed" || recorder.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatalf("unexpected refusal: %#v %v", payload, recorder.Header())
			}
		}
	}

	for _, fetchSite := range []string{"", "same-origin", "none"} {
		if recorder := serve("/auth/session", fetchSite); recorder.Code != http.StatusUnauthorized {
			t.Fatalf("Sec-Fetch-Site %q: expected the session lookup to answer 401, got %d", fetchSite, recorder.Code)
		}
	}
	// An allowed web client is cross-site by definition; its Origin decides.
	if recorder := serveFrom("/auth/session", "cross-site", "https://app.example"); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("allowed origin with Sec-Fetch-Site cross-site: expected 401, got %d", recorder.Code)
	}
	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		if recorder := serve(path, "cross-site"); recorder.Code == http.StatusForbidden {
			t.Fatalf("%s from another site: refused, body=%s", path, recorder.Body.String())
		}
	}
}
