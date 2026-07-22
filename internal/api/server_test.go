package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/services"
)

func TestCurrentSessionReportsTOTPState(t *testing.T) {
	handler := newTestServer(t)

	registerResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/register",
		map[string]string{
			"login":    "owner@example.com",
			"password": "correct horse battery staple",
		},
		"",
		http.StatusCreated,
	)
	var registerPayload struct {
		AccountID    string `json:"account_id"`
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, registerResponse.Body.Bytes(), &registerPayload)

	sessionResponse := performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/auth/session",
		nil,
		registerPayload.SessionToken,
		http.StatusOK,
	)
	var sessionPayload struct {
		AccountID   string `json:"account_id"`
		Login       string `json:"login"`
		TOTPEnabled bool   `json:"totp_enabled"`
	}
	decodeResponse(t, sessionResponse.Body.Bytes(), &sessionPayload)

	if sessionPayload.AccountID != registerPayload.AccountID {
		t.Fatalf("expected account id %q, got %q", registerPayload.AccountID, sessionPayload.AccountID)
	}
	if sessionPayload.Login == "" {
		t.Fatal("expected a login in the session view")
	}
	if sessionPayload.TOTPEnabled {
		t.Fatal("expected TOTP disabled for a fresh account")
	}
}

func TestServerRegisterLoginAndSyncFlow(t *testing.T) {
	handler := newTestServer(t)

	registerResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/register",
		map[string]string{
			"login":    "owner@example.com",
			"password": "correct horse battery staple",
		},
		"",
		http.StatusCreated,
	)

	var registerPayload struct {
		AccountID    string `json:"account_id"`
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, registerResponse.Body.Bytes(), &registerPayload)

	performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/sync/capabilities",
		nil,
		registerPayload.SessionToken,
		http.StatusOK,
	)

	deviceResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/sync/devices",
		map[string]string{
			"device_id":    "device-1aaaa",
			"device_label": "Pixel 7",
		},
		registerPayload.SessionToken,
		http.StatusOK,
	)

	var devicePayload map[string]any
	decodeResponse(t, deviceResponse.Body.Bytes(), &devicePayload)
	if devicePayload["device_id"] != "device-1aaaa" {
		t.Fatalf("unexpected device payload: %#v", devicePayload)
	}

	recoveryResponse := performJSONRequest(
		t,
		handler,
		http.MethodPut,
		"/sync/recovery-key",
		map[string]any{
			"algorithm":              "xchacha20poly1305",
			"kdf":                    "bip39_seed_hkdf_sha256",
			"mnemonic_word_count":    12,
			"wrap_nonce_hex":         strings.Repeat("a", 48),
			"wrapped_master_key_hex": strings.Repeat("b", 96),
			"phrase_fingerprint_hex": strings.Repeat("c", 16),
		},
		registerPayload.SessionToken,
		http.StatusOK,
	)

	var recoveryPayload map[string]any
	decodeResponse(t, recoveryResponse.Body.Bytes(), &recoveryPayload)
	if recoveryPayload["algorithm"] != "xchacha20poly1305" {
		t.Fatalf("unexpected recovery payload: %#v", recoveryPayload)
	}

	performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/sync/recovery-key",
		nil,
		registerPayload.SessionToken,
		http.StatusOK,
	)

	ciphertext := base64.StdEncoding.EncodeToString([]byte("ciphertext"))
	checksumBytes := sha256.Sum256([]byte("ciphertext"))
	putResponse := performJSONRequest(
		t,
		handler,
		http.MethodPut,
		"/sync/blob",
		map[string]any{
			"schema_version":    1,
			"generation":        1,
			"checksum_sha256":   hex.EncodeToString(checksumBytes[:]),
			"ciphertext_base64": ciphertext,
		},
		registerPayload.SessionToken,
		http.StatusOK,
	)

	var blobPayload map[string]any
	decodeResponse(t, putResponse.Body.Bytes(), &blobPayload)
	if blobPayload["ciphertext_base64"] != ciphertext {
		t.Fatalf("unexpected blob payload: %#v", blobPayload)
	}

	getBlobResponse := performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/sync/blob",
		nil,
		registerPayload.SessionToken,
		http.StatusOK,
	)

	// Close the zero-knowledge round-trip at the transport edge: the blob comes
	// back byte-for-byte as it was uploaded (the service layer proves the same
	// in TestSyncServiceAttachDeviceAndBlobRoundTrip).
	var getBlobPayload map[string]any
	decodeResponse(t, getBlobResponse.Body.Bytes(), &getBlobPayload)
	if getBlobPayload["ciphertext_base64"] != ciphertext {
		t.Fatalf("expected the stored blob returned byte-for-byte, got %#v", getBlobPayload)
	}
}

func TestServerUnauthorizedSyncAccess(t *testing.T) {
	handler := newTestServer(t)

	response := performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/sync/capabilities",
		nil,
		"",
		http.StatusUnauthorized,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "unauthorized" {
		t.Fatalf("unexpected unauthorized payload: %#v", payload)
	}
	if response.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("expected content security policy header")
	}
	if response.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("expected DENY frame options, got %q", response.Header().Get("X-Frame-Options"))
	}
	if response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("expected nosniff header, got %q", response.Header().Get("X-Content-Type-Options"))
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected Cache-Control no-store, got %q", got)
	}
}

func TestServerRateLimitsAuthEndpoints(t *testing.T) {
	handler := newTestServer(t)

	for range 10 {
		performJSONRequest(
			t,
			handler,
			http.MethodPost,
			"/auth/login",
			map[string]string{
				"login":    "owner@example.com",
				"password": "wrong password",
			},
			"",
			http.StatusUnauthorized,
		)
	}

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/login",
		map[string]string{
			"login":    "owner@example.com",
			"password": "wrong password",
		},
		"",
		http.StatusTooManyRequests,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "rate_limited" {
		t.Fatalf("unexpected rate limit payload: %#v", payload)
	}
}

func TestServerAuthRateLimitUsesForwardedClientFromTrustedProxy(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		authRateLimitCount: 1,
		trustedProxyCIDRs:  []string{"10.0.0.0/24"},
	})

	// Two requests share a trusted proxy peer (10.0.0.2) but carry
	// different forwarded client IPs. With per-IP keying on the
	// forwarded value, both should pass. Use distinct login strings so
	// the per-login-identifier limiter (a second gate added to defeat
	// distributed-bot brute) is not the side that fires first; the test
	// is asserting the IP-keying path specifically.
	performJSONRequestWithOptions(t, requestOptions{
		handler:        handler,
		method:         http.MethodPost,
		path:           "/auth/login",
		body:           map[string]string{"login": "owner-a@example.com", "password": "wrong password"},
		expectedStatus: http.StatusUnauthorized,
		remoteAddr:     "10.0.0.2:1234",
		headers:        map[string]string{"X-Forwarded-For": "203.0.113.10"},
	})

	performJSONRequestWithOptions(t, requestOptions{
		handler:        handler,
		method:         http.MethodPost,
		path:           "/auth/login",
		body:           map[string]string{"login": "owner-b@example.com", "password": "wrong password"},
		expectedStatus: http.StatusUnauthorized,
		remoteAddr:     "10.0.0.2:5678",
		headers:        map[string]string{"X-Forwarded-For": "203.0.113.11"},
	})
}

func TestServerAuthRateLimitResistsForwardedSpoofingBehindTrustedProxy(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		authRateLimitCount: 1,
		trustedProxyCIDRs:  []string{"10.0.0.0/24"},
	})

	// A conforming reverse proxy appends the real client (203.0.113.10) to the
	// RIGHT of any client-supplied X-Forwarded-For. An attacker who rotates the
	// spoofed leftmost value must not mint a fresh per-IP bucket each request:
	// both requests resolve to the same rightmost-untrusted address, so the
	// second is rate-limited. Distinct logins keep the per-login-identifier
	// limiter from being the gate that fires first — this asserts the IP path.
	performJSONRequestWithOptions(t, requestOptions{
		handler:        handler,
		method:         http.MethodPost,
		path:           "/auth/login",
		body:           map[string]string{"login": "owner-a@example.com", "password": "wrong password"},
		expectedStatus: http.StatusUnauthorized,
		remoteAddr:     "10.0.0.2:1234",
		headers:        map[string]string{"X-Forwarded-For": "1.1.1.1, 203.0.113.10"},
	})

	performJSONRequestWithOptions(t, requestOptions{
		handler:        handler,
		method:         http.MethodPost,
		path:           "/auth/login",
		body:           map[string]string{"login": "owner-b@example.com", "password": "wrong password"},
		expectedStatus: http.StatusTooManyRequests,
		remoteAddr:     "10.0.0.2:5678",
		headers:        map[string]string{"X-Forwarded-For": "2.2.2.2, 203.0.113.10"},
	})
}

func TestForwardedClientIPSkipsTrustedProxyHops(t *testing.T) {
	server := &Server{trustedProxyCIDRs: parseTrustedProxyCIDRs([]string{"10.0.0.0/24"})}

	// The real client 203.0.113.10 sits left of a trusted proxy hop (10.0.0.2)
	// and right of a spoofed prefix: walking right skips the trusted hop and
	// returns the rightmost non-trusted address, never the client-controlled left.
	addr, ok := forwardedClientIP("1.1.1.1, 203.0.113.10, 10.0.0.2", server.isTrustedProxy)
	if !ok || addr.String() != "203.0.113.10" {
		t.Fatalf("expected rightmost non-trusted 203.0.113.10, got %v ok=%v", addr, ok)
	}

	// When every forwarded entry is a trusted proxy, no client is resolvable
	// from the header and the caller falls back to the direct peer.
	if _, ok := forwardedClientIP("10.0.0.2, 10.0.0.3", server.isTrustedProxy); ok {
		t.Fatal("expected no address when every forwarded entry is a trusted proxy")
	}
}

func TestServerIgnoresForwardedClientFromUntrustedRemoteAddr(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		authRateLimitCount: 1,
	})

	performJSONRequestWithOptions(t, requestOptions{
		handler:        handler,
		method:         http.MethodPost,
		path:           "/auth/login",
		body:           map[string]string{"login": "owner@example.com", "password": "wrong password"},
		expectedStatus: http.StatusUnauthorized,
		remoteAddr:     "10.0.0.2:1234",
		headers:        map[string]string{"X-Forwarded-For": "203.0.113.10"},
	})

	response := performJSONRequestWithOptions(t, requestOptions{
		handler:        handler,
		method:         http.MethodPost,
		path:           "/auth/login",
		body:           map[string]string{"login": "owner@example.com", "password": "wrong password"},
		expectedStatus: http.StatusTooManyRequests,
		remoteAddr:     "10.0.0.2:5678",
		headers:        map[string]string{"X-Forwarded-For": "203.0.113.11"},
	})

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "rate_limited" {
		t.Fatalf("unexpected untrusted-forwarded rate limit payload: %#v", payload)
	}
}

func TestServerRejectsStaleBlobGeneration(t *testing.T) {
	handler := newTestServer(t)

	registerResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/register",
		map[string]string{
			"login":    "owner@example.com",
			"password": "correct horse battery staple",
		},
		"",
		http.StatusCreated,
	)

	var registerPayload struct {
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, registerResponse.Body.Bytes(), &registerPayload)

	checksumBytes := sha256.Sum256([]byte("ciphertext"))
	body := map[string]any{
		"schema_version":    1,
		"generation":        1,
		"checksum_sha256":   hex.EncodeToString(checksumBytes[:]),
		"ciphertext_base64": base64.StdEncoding.EncodeToString([]byte("ciphertext")),
	}

	performJSONRequest(
		t,
		handler,
		http.MethodPut,
		"/sync/blob",
		body,
		registerPayload.SessionToken,
		http.StatusOK,
	)

	response := performJSONRequest(
		t,
		handler,
		http.MethodPut,
		"/sync/blob",
		body,
		registerPayload.SessionToken,
		http.StatusConflict,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "stale_generation" {
		t.Fatalf("unexpected stale payload: %#v", payload)
	}
}

func TestServerReturnsNotFoundForMissingRecoveryKeyPackage(t *testing.T) {
	handler := newTestServer(t)

	registerResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/register",
		map[string]string{
			"login":    "owner@example.com",
			"password": "correct horse battery staple",
		},
		"",
		http.StatusCreated,
	)

	var registerPayload struct {
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, registerResponse.Body.Bytes(), &registerPayload)

	response := performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/sync/recovery-key",
		nil,
		registerPayload.SessionToken,
		http.StatusNotFound,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "recovery_package_not_found" {
		t.Fatalf("unexpected recovery not-found payload: %#v", payload)
	}
}

func TestServerRevokesSession(t *testing.T) {
	handler := newTestServer(t)

	registerResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/register",
		map[string]string{
			"login":    "owner@example.com",
			"password": "correct horse battery staple",
		},
		"",
		http.StatusCreated,
	)

	var registerPayload struct {
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, registerResponse.Body.Bytes(), &registerPayload)

	performJSONRequest(
		t,
		handler,
		http.MethodDelete,
		"/auth/session",
		nil,
		registerPayload.SessionToken,
		http.StatusOK,
	)

	performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/sync/capabilities",
		nil,
		registerPayload.SessionToken,
		http.StatusUnauthorized,
	)
}

func TestServerIssuesManagedBridgeSession(t *testing.T) {
	handler := newTestServer(t)

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/session",
		map[string]string{
			"account_id": "managedacct1234",
		},
		"test-managed-bridge-token",
		http.StatusOK,
	)

	var payload struct {
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload.SessionToken == "" {
		t.Fatal("expected managed bridge session token")
	}

	capabilitiesResponse := performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/sync/capabilities",
		nil,
		payload.SessionToken,
		http.StatusOK,
	)

	var capabilitiesPayload map[string]any
	decodeResponse(t, capabilitiesResponse.Body.Bytes(), &capabilitiesPayload)
	if capabilitiesPayload["mode"] != "managed" {
		t.Fatalf("expected managed capabilities, got %#v", capabilitiesPayload)
	}
	if capabilitiesPayload["premium_active"] != true {
		t.Fatalf("expected premium_active for managed bridge session, got %#v", capabilitiesPayload)
	}
}

func TestServerRejectsManagedBridgeWhenDisabled(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		disableManaged: true,
	})

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/session",
		map[string]string{
			"account_id": "managedacct1234",
		},
		"test-managed-bridge-token",
		http.StatusServiceUnavailable,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "managed_bridge_disabled" {
		t.Fatalf("unexpected managed bridge disabled payload: %#v", payload)
	}
}

func TestServerRejectsOversizedAuthJSON(t *testing.T) {
	handler := newTestServer(t)

	response := performRawRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/register",
		[]byte(`{"login":"owner@example.com","password":"`+strings.Repeat("a", 5000)+`"}`),
		"",
		http.StatusBadRequest,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "invalid_json" {
		t.Fatalf("unexpected oversized auth payload response: %#v", payload)
	}
}

func TestServerRejectsTrailingJSONGarbage(t *testing.T) {
	handler := newTestServer(t)

	response := performRawRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/register",
		[]byte(`{"login":"owner@example.com","password":"correct horse battery staple"}{"extra":true}`),
		"",
		http.StatusBadRequest,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "invalid_json" {
		t.Fatalf("unexpected trailing-json response: %#v", payload)
	}
}

func TestServerAllowsConfiguredOriginPreflight(t *testing.T) {
	handler := newTestServer(t, "http://127.0.0.1:4173")

	request := httptest.NewRequest(http.MethodOptions, "/sync/capabilities", nil)
	request.Header.Set("Origin", "http://127.0.0.1:4173")
	request.Header.Set("Access-Control-Request-Method", http.MethodGet)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("unexpected preflight status %d, body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Access-Control-Allow-Origin") != "http://127.0.0.1:4173" {
		t.Fatalf("expected allowed origin header, got %q", recorder.Header().Get("Access-Control-Allow-Origin"))
	}
	if recorder.Header().Get("Access-Control-Allow-Headers") == "" {
		t.Fatal("expected allow headers on preflight response")
	}
}

func TestServerRejectsUnknownOriginPreflight(t *testing.T) {
	handler := newTestServer(t, "http://127.0.0.1:4173")

	request := httptest.NewRequest(http.MethodOptions, "/sync/capabilities", nil)
	request.Header.Set("Origin", "http://malicious.invalid")
	request.Header.Set("Access-Control-Request-Method", http.MethodGet)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("unexpected preflight status %d, body=%s", recorder.Code, recorder.Body.String())
	}

	var payload map[string]string
	decodeResponse(t, recorder.Body.Bytes(), &payload)
	if payload["error"] != "origin_not_allowed" {
		t.Fatalf("unexpected preflight payload: %#v", payload)
	}
}

func TestServerReadinessEndpoint(t *testing.T) {
	handler := newTestServer(t)

	performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/readyz",
		nil,
		"",
		http.StatusOK,
	)
}

func TestServerHealthEndpoint(t *testing.T) {
	handler := newTestServer(t)

	response := performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/healthz",
		nil,
		"",
		http.StatusOK,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["status"] != "ok" {
		t.Fatalf("unexpected health payload: %#v", payload)
	}
}

func TestServerMetricsEndpointReturnsNotFoundWhenDisabled(t *testing.T) {
	handler := newTestServer(t)

	response := performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/metrics",
		nil,
		"",
		http.StatusNotFound,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "not_found" {
		t.Fatalf("unexpected disabled metrics payload: %#v", payload)
	}
}

func TestServerMetricsEndpointRequiresBearerTokenWhenConfigured(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		enableMetrics:      true,
		metricsBearerToken: "metrics-secret",
	})

	response := performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/metrics",
		nil,
		"",
		http.StatusUnauthorized,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "unauthorized" {
		t.Fatalf("unexpected metrics auth payload: %#v", payload)
	}
}

func TestServerMetricsEndpointReturnsPrometheusPayload(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		enableMetrics:      true,
		metricsBearerToken: "metrics-secret",
	})

	performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/healthz",
		nil,
		"",
		http.StatusOK,
	)

	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.Header.Set("Authorization", "Bearer metrics-secret")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected metrics status %d, body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("unexpected metrics content type %q", recorder.Header().Get("Content-Type"))
	}
	if !strings.Contains(recorder.Body.String(), "ovumcy_sync_community_http_requests_total") {
		t.Fatal("expected sync community metrics payload")
	}
}

func TestServerReadinessEndpointReturnsServiceUnavailableWhenProbeFails(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		readinessCheck: func(context.Context) error {
			return errors.New("db not ready")
		},
	})

	response := performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/readyz",
		nil,
		"",
		http.StatusServiceUnavailable,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "not_ready" {
		t.Fatalf("unexpected readiness payload: %#v", payload)
	}
}

func TestServerRejectsOversizedBlobByConfiguredLimit(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{maxBlobBytes: 4})

	registerResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/register",
		map[string]string{
			"login":    "owner@example.com",
			"password": "correct horse battery staple",
		},
		"",
		http.StatusCreated,
	)

	var registerPayload struct {
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, registerResponse.Body.Bytes(), &registerPayload)

	ciphertext := []byte("oversized")
	checksumBytes := sha256.Sum256(ciphertext)
	response := performJSONRequest(
		t,
		handler,
		http.MethodPut,
		"/sync/blob",
		map[string]any{
			"schema_version":    1,
			"generation":        1,
			"checksum_sha256":   hex.EncodeToString(checksumBytes[:]),
			"ciphertext_base64": base64.StdEncoding.EncodeToString(ciphertext),
		},
		registerPayload.SessionToken,
		http.StatusBadRequest,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "invalid_blob" {
		t.Fatalf("unexpected oversized blob payload: %#v", payload)
	}
}

func TestServerRegisterRejectsInvalidRegistrationInput(t *testing.T) {
	handler := newTestServer(t)

	for _, testCase := range []struct {
		name     string
		login    string
		password string
	}{
		{name: "weak password", login: "owner@example.com", password: "short"},
		{name: "login too short", login: "ab", password: "correct horse battery staple"},
		{name: "reserved managed namespace", login: "managed:squatter1234", password: "correct horse battery staple"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			response := performJSONRequest(
				t,
				handler,
				http.MethodPost,
				"/auth/register",
				map[string]string{
					"login":    testCase.login,
					"password": testCase.password,
				},
				"",
				http.StatusBadRequest,
			)

			var payload map[string]string
			decodeResponse(t, response.Body.Bytes(), &payload)
			if payload["error"] != "invalid_registration_input" {
				t.Fatalf("unexpected register validation payload: %#v", payload)
			}
		})
	}
}

func TestServerLoginRefusesManagedPrefixIdentity(t *testing.T) {
	handler := newTestServer(t)

	// A direct client must never authenticate as a reserved managed-bridge
	// identity, and the refusal must be indistinguishable from any other bad
	// login so it leaks nothing about which managed accounts exist. Registration
	// already refuses the prefix (TestServerRegisterRejectsInvalidRegistrationInput);
	// this locks the same boundary at the login edge.
	for _, login := range []string{"managed:managedacct1234", "managed:neverprovisioned9"} {
		response := performJSONRequest(
			t,
			handler,
			http.MethodPost,
			"/auth/login",
			map[string]string{
				"login":    login,
				"password": "correct horse battery staple",
			},
			"",
			http.StatusUnauthorized,
		)

		var payload map[string]string
		decodeResponse(t, response.Body.Bytes(), &payload)
		if payload["error"] != "invalid_credentials" {
			t.Fatalf("expected generic invalid_credentials for %q, got %#v", login, payload)
		}
	}
}

func TestServerRegisterRejectsDuplicateLogin(t *testing.T) {
	handler := newTestServer(t)

	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/register",
		map[string]string{
			"login":    "owner@example.com",
			"password": "correct horse battery staple",
		},
		"",
		http.StatusCreated,
	)

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/register",
		map[string]string{
			"login":    "owner@example.com",
			"password": "another secure password!",
		},
		"",
		http.StatusBadRequest,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "registration_failed" {
		t.Fatalf("unexpected duplicate register payload: %#v", payload)
	}
}

func TestServerRegisterRateLimitedPerClientIP(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		authRateLimitCount: 1,
	})

	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/register",
		map[string]string{
			"login":    "owner-a@example.com",
			"password": "correct horse battery staple",
		},
		"",
		http.StatusCreated,
	)

	// A different login from the same client IP: the per-IP gate fires before
	// the handler ever reaches registration.
	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/register",
		map[string]string{
			"login":    "owner-b@example.com",
			"password": "correct horse battery staple",
		},
		"",
		http.StatusTooManyRequests,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "rate_limited" {
		t.Fatalf("unexpected register rate limit payload: %#v", payload)
	}
}

func TestServerLoginRateLimitsPerIdentifierAcrossClientIPs(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		authRateLimitCount: 1,
	})

	// Same login identifier from two different source IPs: the per-IP gate
	// passes both, but the per-identifier ceiling caps the combined attempts,
	// which is what defeats a distributed brute force against one account.
	performJSONRequestWithOptions(t, requestOptions{
		handler:        handler,
		method:         http.MethodPost,
		path:           "/auth/login",
		body:           map[string]string{"login": "victim@example.com", "password": "wrong password"},
		expectedStatus: http.StatusUnauthorized,
		remoteAddr:     "203.0.113.10:1111",
	})

	response := performJSONRequestWithOptions(t, requestOptions{
		handler:        handler,
		method:         http.MethodPost,
		path:           "/auth/login",
		body:           map[string]string{"login": "victim@example.com", "password": "wrong password"},
		expectedStatus: http.StatusTooManyRequests,
		remoteAddr:     "203.0.113.11:2222",
	})

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "rate_limited" {
		t.Fatalf("unexpected per-identifier rate limit payload: %#v", payload)
	}
}

func TestServerLoginWithBlankLoginReturnsGenericInvalidCredentials(t *testing.T) {
	handler := newTestServer(t)

	// A whitespace-only login normalizes to empty: it must skip the
	// per-identifier limiter and still fail with the generic credentials
	// error, never a limiter response or a more specific hint.
	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/login",
		map[string]string{
			"login":    "   ",
			"password": "whatever password",
		},
		"",
		http.StatusUnauthorized,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "invalid_credentials" {
		t.Fatalf("unexpected blank-login payload: %#v", payload)
	}
}

func TestServerLogoutRejectsUnknownSessionToken(t *testing.T) {
	handler := newTestServer(t)

	for _, testCase := range []struct {
		name         string
		sessionToken string
	}{
		{name: "missing token", sessionToken: ""},
		{name: "unknown token", sessionToken: "bogus-session-token"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			response := performJSONRequest(
				t,
				handler,
				http.MethodDelete,
				"/auth/session",
				nil,
				testCase.sessionToken,
				http.StatusUnauthorized,
			)

			var payload map[string]string
			decodeResponse(t, response.Body.Bytes(), &payload)
			if payload["error"] != "unauthorized" {
				t.Fatalf("unexpected logout payload: %#v", payload)
			}
		})
	}
}

func TestServerManagedSessionRejectsMalformedJSON(t *testing.T) {
	handler := newTestServer(t)

	response := performRawRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/session",
		[]byte(`{"account_id":`),
		"test-managed-bridge-token",
		http.StatusBadRequest,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "invalid_json" {
		t.Fatalf("unexpected managed session malformed payload: %#v", payload)
	}
}

func TestServerManagedSessionRejectsInvalidAccountID(t *testing.T) {
	handler := newTestServer(t)

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/session",
		map[string]string{
			"account_id": "bad",
		},
		"test-managed-bridge-token",
		http.StatusBadRequest,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "invalid_managed_account" {
		t.Fatalf("unexpected managed session payload: %#v", payload)
	}
}

func TestServerManagedSessionRejectsWrongBridgeToken(t *testing.T) {
	handler := newTestServer(t)

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/session",
		map[string]string{
			"account_id": "managedacct1234",
		},
		"wrong-bridge-token",
		http.StatusUnauthorized,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "unauthorized" {
		t.Fatalf("unexpected managed bridge auth payload: %#v", payload)
	}
}

func TestServerSyncEndpointValidationErrors(t *testing.T) {
	handler := newTestServer(t)
	registered := registerOwner(t, handler)

	// Device id shorter than the 8-character minimum.
	deviceResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/sync/devices",
		map[string]string{
			"device_id":    "short",
			"device_label": "Pixel 7",
		},
		registered.SessionToken,
		http.StatusBadRequest,
	)
	var devicePayload map[string]string
	decodeResponse(t, deviceResponse.Body.Bytes(), &devicePayload)
	if devicePayload["error"] != "invalid_device" {
		t.Fatalf("unexpected invalid device payload: %#v", devicePayload)
	}

	// Malformed JSON on the device route.
	deviceJSONResponse := performRawRequest(
		t,
		handler,
		http.MethodPost,
		"/sync/devices",
		[]byte(`{"device_id":`),
		registered.SessionToken,
		http.StatusBadRequest,
	)
	var deviceJSONPayload map[string]string
	decodeResponse(t, deviceJSONResponse.Body.Bytes(), &deviceJSONPayload)
	if deviceJSONPayload["error"] != "invalid_json" {
		t.Fatalf("unexpected device malformed-json payload: %#v", deviceJSONPayload)
	}

	// Recovery-key package with an unsupported algorithm.
	recoveryResponse := performJSONRequest(
		t,
		handler,
		http.MethodPut,
		"/sync/recovery-key",
		map[string]any{
			"algorithm":              "rot13",
			"kdf":                    "bip39_seed_hkdf_sha256",
			"mnemonic_word_count":    12,
			"wrap_nonce_hex":         strings.Repeat("a", 48),
			"wrapped_master_key_hex": strings.Repeat("b", 96),
			"phrase_fingerprint_hex": strings.Repeat("c", 16),
		},
		registered.SessionToken,
		http.StatusBadRequest,
	)
	var recoveryPayload map[string]string
	decodeResponse(t, recoveryResponse.Body.Bytes(), &recoveryPayload)
	if recoveryPayload["error"] != "invalid_recovery_package" {
		t.Fatalf("unexpected invalid recovery package payload: %#v", recoveryPayload)
	}

	// Malformed JSON on the recovery-key route.
	recoveryJSONResponse := performRawRequest(
		t,
		handler,
		http.MethodPut,
		"/sync/recovery-key",
		[]byte(`{"algorithm":`),
		registered.SessionToken,
		http.StatusBadRequest,
	)
	var recoveryJSONPayload map[string]string
	decodeResponse(t, recoveryJSONResponse.Body.Bytes(), &recoveryJSONPayload)
	if recoveryJSONPayload["error"] != "invalid_json" {
		t.Fatalf("unexpected recovery malformed-json payload: %#v", recoveryJSONPayload)
	}

	// Ciphertext that is not valid base64 fails before any store access.
	blobResponse := performJSONRequest(
		t,
		handler,
		http.MethodPut,
		"/sync/blob",
		map[string]any{
			"schema_version":    1,
			"generation":        1,
			"checksum_sha256":   strings.Repeat("d", 64),
			"ciphertext_base64": "!!!not-base64!!!",
		},
		registered.SessionToken,
		http.StatusBadRequest,
	)
	var blobPayload map[string]string
	decodeResponse(t, blobResponse.Body.Bytes(), &blobPayload)
	if blobPayload["error"] != "invalid_ciphertext" {
		t.Fatalf("unexpected invalid ciphertext payload: %#v", blobPayload)
	}

	// Reading a blob that was never uploaded is a stable not-found key.
	missingBlobResponse := performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/sync/blob",
		nil,
		registered.SessionToken,
		http.StatusNotFound,
	)
	var missingBlobPayload map[string]string
	decodeResponse(t, missingBlobResponse.Body.Bytes(), &missingBlobPayload)
	if missingBlobPayload["error"] != "blob_not_found" {
		t.Fatalf("unexpected missing blob payload: %#v", missingBlobPayload)
	}
}

func TestServerAttachDeviceRejectsTooManyDevices(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{maxDevices: 1})
	registered := registerOwner(t, handler)

	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/sync/devices",
		map[string]string{
			"device_id":    "device-1aaaa",
			"device_label": "Pixel 7",
		},
		registered.SessionToken,
		http.StatusOK,
	)

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/sync/devices",
		map[string]string{
			"device_id":    "device-2bbbb",
			"device_label": "Tablet",
		},
		registered.SessionToken,
		http.StatusConflict,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "too_many_devices" {
		t.Fatalf("unexpected device limit payload: %#v", payload)
	}
}

func TestServerAttachDeviceRateLimitedPerAccount(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		authRateLimitCount: 1,
	})
	registered := registerOwner(t, handler)

	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/sync/devices",
		map[string]string{
			"device_id":    "device-1aaaa",
			"device_label": "Pixel 7",
		},
		registered.SessionToken,
		http.StatusOK,
	)

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/sync/devices",
		map[string]string{
			"device_id":    "device-1aaaa",
			"device_label": "Pixel 7",
		},
		registered.SessionToken,
		http.StatusTooManyRequests,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "rate_limited" {
		t.Fatalf("unexpected device rate limit payload: %#v", payload)
	}
}

func TestServerPutRecoveryKeyRateLimitedPerAccount(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		authRateLimitCount: 1,
	})
	registered := registerOwner(t, handler)

	body := map[string]any{
		"algorithm":              "xchacha20poly1305",
		"kdf":                    "bip39_seed_hkdf_sha256",
		"mnemonic_word_count":    12,
		"wrap_nonce_hex":         strings.Repeat("a", 48),
		"wrapped_master_key_hex": strings.Repeat("b", 96),
		"phrase_fingerprint_hex": strings.Repeat("c", 16),
	}

	performJSONRequest(
		t,
		handler,
		http.MethodPut,
		"/sync/recovery-key",
		body,
		registered.SessionToken,
		http.StatusOK,
	)

	response := performJSONRequest(
		t,
		handler,
		http.MethodPut,
		"/sync/recovery-key",
		body,
		registered.SessionToken,
		http.StatusTooManyRequests,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "rate_limited" {
		t.Fatalf("unexpected recovery key rate limit payload: %#v", payload)
	}
}

func TestServerSyncRoutesReturnInternalErrorWhenStoreFails(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	handler := newTestServerWithOptions(t, serverTestOptions{store: store})
	registered := registerOwner(t, handler)

	checksumBytes := sha256.Sum256([]byte("ciphertext"))

	dropTable(t, dbPath, "devices")
	deviceResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/sync/devices",
		map[string]string{
			"device_id":    "device-1aaaa",
			"device_label": "Pixel 7",
		},
		registered.SessionToken,
		http.StatusInternalServerError,
	)
	var devicePayload map[string]string
	decodeResponse(t, deviceResponse.Body.Bytes(), &devicePayload)
	if devicePayload["error"] != "internal_error" {
		t.Fatalf("unexpected device store failure payload: %#v", devicePayload)
	}

	dropTable(t, dbPath, "encrypted_blobs")
	getBlobResponse := performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/sync/blob",
		nil,
		registered.SessionToken,
		http.StatusInternalServerError,
	)
	var getBlobPayload map[string]string
	decodeResponse(t, getBlobResponse.Body.Bytes(), &getBlobPayload)
	if getBlobPayload["error"] != "internal_error" {
		t.Fatalf("unexpected blob read store failure payload: %#v", getBlobPayload)
	}

	putBlobResponse := performJSONRequest(
		t,
		handler,
		http.MethodPut,
		"/sync/blob",
		map[string]any{
			"schema_version":    1,
			"generation":        1,
			"checksum_sha256":   hex.EncodeToString(checksumBytes[:]),
			"ciphertext_base64": base64.StdEncoding.EncodeToString([]byte("ciphertext")),
		},
		registered.SessionToken,
		http.StatusInternalServerError,
	)
	var putBlobPayload map[string]string
	decodeResponse(t, putBlobResponse.Body.Bytes(), &putBlobPayload)
	if putBlobPayload["error"] != "internal_error" {
		t.Fatalf("unexpected blob write store failure payload: %#v", putBlobPayload)
	}

	dropTable(t, dbPath, "recovery_key_packages")
	recoveryResponse := performJSONRequest(
		t,
		handler,
		http.MethodPut,
		"/sync/recovery-key",
		map[string]any{
			"algorithm":              "xchacha20poly1305",
			"kdf":                    "bip39_seed_hkdf_sha256",
			"mnemonic_word_count":    12,
			"wrap_nonce_hex":         strings.Repeat("a", 48),
			"wrapped_master_key_hex": strings.Repeat("b", 96),
			"phrase_fingerprint_hex": strings.Repeat("c", 16),
		},
		registered.SessionToken,
		http.StatusInternalServerError,
	)
	var recoveryPayload map[string]string
	decodeResponse(t, recoveryResponse.Body.Bytes(), &recoveryPayload)
	if recoveryPayload["error"] != "internal_error" {
		t.Fatalf("unexpected recovery key store failure payload: %#v", recoveryPayload)
	}
}

func TestServerDeleteAccountReturnsInternalErrorAndRateLimitsRetry(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	handler := newTestServerWithOptions(t, serverTestOptions{
		store:              store,
		authRateLimitCount: 1,
	})
	registered := registerOwner(t, handler)

	// The account-erasure transaction deletes from every child table; with
	// one of them gone it must fail and roll back, so the caller's session
	// survives to retry.
	dropTable(t, dbPath, "devices")

	firstResponse := performJSONRequest(
		t,
		handler,
		http.MethodDelete,
		"/account",
		nil,
		registered.SessionToken,
		http.StatusInternalServerError,
	)
	var firstPayload map[string]string
	decodeResponse(t, firstResponse.Body.Bytes(), &firstPayload)
	if firstPayload["error"] != "internal_error" {
		t.Fatalf("unexpected delete-account store failure payload: %#v", firstPayload)
	}

	// The rolled-back session still authenticates, so the retry reaches the
	// per-account gate and is throttled rather than hammering the store.
	secondResponse := performJSONRequest(
		t,
		handler,
		http.MethodDelete,
		"/account",
		nil,
		registered.SessionToken,
		http.StatusTooManyRequests,
	)
	var secondPayload map[string]string
	decodeResponse(t, secondResponse.Body.Bytes(), &secondPayload)
	if secondPayload["error"] != "rate_limited" {
		t.Fatalf("unexpected delete-account rate limit payload: %#v", secondPayload)
	}
}

func TestServerAuthRoutesReturnInternalErrorWhenStoreFails(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	handler := newTestServerWithOptions(t, serverTestOptions{store: store})

	dropTable(t, dbPath, "accounts")

	registerResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/register",
		map[string]string{
			"login":    "owner@example.com",
			"password": "correct horse battery staple",
		},
		"",
		http.StatusInternalServerError,
	)
	var registerPayload map[string]string
	decodeResponse(t, registerResponse.Body.Bytes(), &registerPayload)
	if registerPayload["error"] != "internal_error" {
		t.Fatalf("unexpected register store failure payload: %#v", registerPayload)
	}

	loginResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/login",
		map[string]string{
			"login":    "owner@example.com",
			"password": "correct horse battery staple",
		},
		"",
		http.StatusInternalServerError,
	)
	var loginPayload map[string]string
	decodeResponse(t, loginResponse.Body.Bytes(), &loginPayload)
	if loginPayload["error"] != "internal_error" {
		t.Fatalf("unexpected login store failure payload: %#v", loginPayload)
	}

	managedResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/session",
		map[string]string{
			"account_id": "managedacct1234",
		},
		"test-managed-bridge-token",
		http.StatusInternalServerError,
	)
	var managedPayload map[string]string
	decodeResponse(t, managedResponse.Body.Bytes(), &managedPayload)
	if managedPayload["error"] != "internal_error" {
		t.Fatalf("unexpected managed session store failure payload: %#v", managedPayload)
	}
}

func newTestServer(t *testing.T, allowedOrigins ...string) http.Handler {
	return newTestServerWithOptions(t, serverTestOptions{
		allowedOrigins: allowedOrigins,
	})
}

type serverTestOptions struct {
	allowedOrigins     []string
	maxDevices         int
	maxBlobBytes       int
	readinessCheck     func(context.Context) error
	authRateLimitCount int
	trustedProxyCIDRs  []string
	enableMetrics      bool
	metricsBearerToken string
	disableManaged     bool
	enableTOTP         bool
	// store, when non-nil, is used instead of opening a private in-memory
	// database. The caller owns its lifecycle (open, migrations, close). This
	// lets a test share one database between two server instances or keep the
	// file path around for failure injection (see dropTable).
	store *db.Store
	// totpKey overrides the default TOTP field-encryption key when enableTOTP
	// is set, so two servers over a shared store can disagree on the key.
	totpKey []byte
}

// newTestStore opens a migrated store and registers its cleanup. Tests pass
// ":memory:" for a private throwaway database, or a file path when a second
// raw connection must reach the same database (see newFileBackedTestStore).
func newTestStore(t *testing.T, path string) *db.Store {
	t.Helper()

	store, err := db.Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	if err := store.ApplyMigrations(context.Background()); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	return store
}

// newFileBackedTestStore opens a migrated store on a temp file and returns it
// together with the database path, so a test can open an independent raw
// connection to the same database for failure injection.
func newFileBackedTestStore(t *testing.T) (*db.Store, string) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "sync-community-test.db")
	return newTestStore(t, dbPath), dbPath
}

// dropTable removes one table out from under a live server through a second
// connection to the same database file, simulating a persistent-store failure
// for exactly the routes that touch that table. Every other table — notably
// sessions and accounts, which bearer-token authentication reads — keeps
// working, so the test reaches the handler's internal-error branch instead of
// failing earlier in the auth middleware.
func dropTable(t *testing.T, dbPath string, table string) {
	t.Helper()

	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	defer func() {
		_ = raw.Close()
	}()

	if _, err := raw.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		t.Fatalf("configure raw sqlite: %v", err)
	}
	if _, err := raw.Exec("DROP TABLE " + table); err != nil { // #nosec G202 -- table is a test-fixture constant chosen by the test, never user input
		t.Fatalf("drop table %s: %v", table, err)
	}
}

func newTestServerWithOptions(t *testing.T, options serverTestOptions) http.Handler {
	t.Helper()

	store := options.store
	if store == nil {
		store = newTestStore(t, ":memory:")
	}

	maxDevices := options.maxDevices
	if maxDevices == 0 {
		maxDevices = 5
	}
	maxBlobBytes := options.maxBlobBytes
	if maxBlobBytes == 0 {
		maxBlobBytes = 16 << 20
	}
	authRateLimitCount := options.authRateLimitCount
	if authRateLimitCount == 0 {
		authRateLimitCount = 10
	}
	managedBridgeToken := "test-managed-bridge-token"
	if options.disableManaged {
		managedBridgeToken = ""
	}

	authService := services.NewAuthService(store, 24*time.Hour)
	syncService := services.NewSyncService(store, services.SyncOptions{
		MaxDevices:   maxDevices,
		MaxBlobBytes: maxBlobBytes,
	})
	managedBridgeService := services.NewManagedBridgeService(store, authService)

	var totpService *services.TOTPService
	if options.enableTOTP {
		key := options.totpKey
		if key == nil {
			key = make([]byte, 32)
			for i := range key {
				key[i] = byte(i + 1)
			}
		}
		totpService = services.NewTOTPService(
			store,
			authService,
			key,
			"ovumcy-sync-community-test",
		)
		authService.AttachTOTPChallengeIssuer(totpService)
	}

	return NewServer(
		authService,
		syncService,
		managedBridgeService,
		totpService,
		ServerOptions{
			ManagedBridgeToken:  managedBridgeToken,
			MetricsEnabled:      options.enableMetrics,
			MetricsBearerToken:  options.metricsBearerToken,
			AllowedOrigins:      options.allowedOrigins,
			AuthRateLimitCount:  authRateLimitCount,
			AuthRateLimitWindow: time.Minute,
			MaxBlobBytes:        maxBlobBytes,
			ReadinessCheck:      options.readinessCheck,
			TrustedProxyCIDRs:   options.trustedProxyCIDRs,
		},
	)
}

func performJSONRequest(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	body any,
	sessionToken string,
	expectedStatus int,
) *httptest.ResponseRecorder {
	t.Helper()

	return performJSONRequestWithOptions(t, requestOptions{
		handler:        handler,
		method:         method,
		path:           path,
		body:           body,
		sessionToken:   sessionToken,
		expectedStatus: expectedStatus,
	})
}

type requestOptions struct {
	handler        http.Handler
	method         string
	path           string
	body           any
	sessionToken   string
	expectedStatus int
	remoteAddr     string
	headers        map[string]string
}

func performJSONRequestWithOptions(t *testing.T, options requestOptions) *httptest.ResponseRecorder {
	t.Helper()

	var payload []byte
	if options.body != nil {
		var err error
		payload, err = json.Marshal(options.body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
	}

	request := httptest.NewRequest(options.method, options.path, bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	if options.sessionToken != "" {
		request.Header.Set("Authorization", "Bearer "+options.sessionToken)
	}
	for key, value := range options.headers {
		request.Header.Set(key, value)
	}
	if options.remoteAddr != "" {
		request.RemoteAddr = options.remoteAddr
	}

	recorder := httptest.NewRecorder()
	options.handler.ServeHTTP(recorder, request)

	if recorder.Code != options.expectedStatus {
		t.Fatalf("unexpected status %d, body=%s", recorder.Code, recorder.Body.String())
	}

	return recorder
}

func performRawRequest(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	body []byte,
	sessionToken string,
	expectedStatus int,
) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if sessionToken != "" {
		request.Header.Set("Authorization", "Bearer "+sessionToken)
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != expectedStatus {
		t.Fatalf("unexpected status %d, body=%s", recorder.Code, recorder.Body.String())
	}

	return recorder
}

func decodeResponse(t *testing.T, body []byte, target any) {
	t.Helper()

	if err := json.Unmarshal(body, target); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}
