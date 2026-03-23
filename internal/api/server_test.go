package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/db"
	"github.com/ovumcy/ovumcy-sync-community/internal/services"
)

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

	performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/sync/blob",
		nil,
		registerPayload.SessionToken,
		http.StatusOK,
	)
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

func newTestServer(t *testing.T, allowedOrigins ...string) http.Handler {
	return newTestServerWithOptions(t, serverTestOptions{
		allowedOrigins: allowedOrigins,
	})
}

type serverTestOptions struct {
	allowedOrigins []string
	maxDevices     int
	maxBlobBytes   int
	readinessCheck func(context.Context) error
}

func newTestServerWithOptions(t *testing.T, options serverTestOptions) http.Handler {
	t.Helper()

	store, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	if err := store.ApplyMigrations(context.Background()); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	maxDevices := options.maxDevices
	if maxDevices == 0 {
		maxDevices = 5
	}
	maxBlobBytes := options.maxBlobBytes
	if maxBlobBytes == 0 {
		maxBlobBytes = 16 << 20
	}

	return NewServer(
		services.NewAuthService(store, 24*time.Hour),
		services.NewSyncService(store, services.SyncOptions{
			MaxDevices:   maxDevices,
			MaxBlobBytes: maxBlobBytes,
		}),
		services.NewManagedBridgeService(store, services.NewAuthService(store, 24*time.Hour)),
		ServerOptions{
			ManagedBridgeToken:  "test-managed-bridge-token",
			AllowedOrigins:      options.allowedOrigins,
			AuthRateLimitCount:  10,
			AuthRateLimitWindow: time.Minute,
			MaxBlobBytes:        maxBlobBytes,
			ReadinessCheck:      options.readinessCheck,
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

	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
	}

	request := httptest.NewRequest(method, path, bytes.NewReader(payload))
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
