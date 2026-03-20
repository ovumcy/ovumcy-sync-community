package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

func newTestServer(t *testing.T) http.Handler {
	t.Helper()

	store, err := db.Open(t.TempDir() + "/test.sqlite")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	if err := store.ApplyMigrations(context.Background()); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	return NewServer(
		services.NewAuthService(store, 24*time.Hour),
		services.NewSyncService(store, 5),
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
