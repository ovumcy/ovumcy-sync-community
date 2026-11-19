package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func serveWithHost(handler http.Handler, method, path, host string, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, nil)
	request.Host = host
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// A page on a domain rebound to the server's address sends same-origin
// fetches with no Origin. Refused on its Host ahead of every limiter, it can
// neither read a response nor spend the victim's per-IP buckets.
func TestReboundHostIsRefusedBeforeTheLimiters(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		allowedHosts:       []string{"example.com"}, // httptest.NewRequest's Host
		authRateLimitCount: 1,
	})
	performJSONRequest(t, handler, http.MethodPost, "/auth/register",
		map[string]string{"login": "owner@example.com", "password": originGateTestPassword}, "", http.StatusCreated)

	rebound := map[string]string{"Sec-Fetch-Site": "same-origin"}
	for _, route := range []struct {
		method, path string
		times        int
	}{
		{http.MethodPost, "/auth/login", 2},
		{http.MethodGet, "/auth/session", 31},
		{http.MethodGet, "/healthz", 1},
	} {
		for range route.times {
			recorder := serveWithHost(handler, route.method, route.path, "rebound.evil.example", rebound)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("%s %s on a rebound host: status %d, body=%s", route.method, route.path, recorder.Code, recorder.Body.String())
			}
			var payload map[string]string
			decodeResponse(t, recorder.Body.Bytes(), &payload)
			if payload["error"] != "host_not_allowed" {
				t.Fatalf("unexpected refusal payload: %#v", payload)
			}
		}
	}

	credentials := map[string]string{"login": "owner@example.com", "password": originGateTestPassword}
	performJSONRequest(t, handler, http.MethodPost, "/auth/login", credentials, "", http.StatusOK)
	if code := serveWithHost(handler, http.MethodGet, "/auth/session", "example.com", nil).Code; code != http.StatusUnauthorized {
		t.Fatalf("the session-lookup bucket was spent by refused requests: status %d", code)
	}
}

func TestAllowedHostsMatching(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		allowedHosts: []string{"sync.example.com", "k.example"},
	})

	for _, host := range []string{
		"sync.example.com",
		"SYNC.Example.COM:8443",
		"sync.example.com.",
		"127.0.0.1:8080",
		"[::1]:8080",
		"[::1]",
		"localhost:8080",
		"localhost.",
	} {
		if code := serveWithHost(handler, http.MethodGet, "/healthz", host, nil).Code; code != http.StatusOK {
			t.Fatalf("Host %q: status %d, want 200", host, code)
		}
	}

	for _, host := range []string{
		"",
		"evil.example",
		"sync.example.com.evil.example",
		"evil-sync.example.com",
		"sync.example.com:80:80",
		"K.example", // KELVIN SIGN must not fold onto k.example
		"app.localhost",
		"127.0.0.1.",
		"127.0.0.1.nip.io",
	} {
		if code := serveWithHost(handler, http.MethodGet, "/healthz", host, nil).Code; code != http.StatusForbidden {
			t.Fatalf("Host %q: status %d, want 403", host, code)
		}
	}

	if code := serveWithHost(handler, http.MethodGet, "/healthz", "[fe80::1%25eth0]:8080", nil).Code; code != http.StatusOK {
		t.Fatalf("zoned IPv6 Host: status %d, want 200", code)
	}

	// The Host check runs ahead of the Origin check.
	recorder := serveWithHost(handler, http.MethodGet, "/healthz", "evil.example", map[string]string{"Origin": "https://evil.example"})
	var payload map[string]string
	decodeResponse(t, recorder.Body.Bytes(), &payload)
	if recorder.Code != http.StatusForbidden || payload["error"] != "host_not_allowed" {
		t.Fatalf("rebound Host with a foreign Origin: status %d, payload %#v", recorder.Code, payload)
	}
}

func TestEmptyAllowedHostsAcceptsAnyHost(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{})
	if code := serveWithHost(handler, http.MethodGet, "/healthz", "anything.example", nil).Code; code != http.StatusOK {
		t.Fatalf("with no ALLOWED_HOSTS: status %d, want 200", code)
	}
}
