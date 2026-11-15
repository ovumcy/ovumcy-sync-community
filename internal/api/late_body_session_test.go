package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// revokingBody logs the caller out the moment the handler starts reading the
// body: the session was live when withAuth ran and is gone by the write.
type revokingBody struct {
	once   sync.Once
	revoke func()
	body   *bytes.Reader
}

func (b *revokingBody) Read(p []byte) (int, error) {
	b.once.Do(b.revoke)
	return b.body.Read(p)
}

func TestAttachDeviceWhoseSessionIsRevokedMidBodyAttachesNothing(t *testing.T) {
	handler := newTestServer(t)
	credentials := map[string]string{"login": "owner@example.com", "password": "correct horse battery staple"}
	var registered struct {
		SessionToken string `json:"session_token"`
	}
	registerResponse := performJSONRequest(t, handler, http.MethodPost, "/auth/register", credentials, "", http.StatusCreated)
	decodeResponse(t, registerResponse.Body.Bytes(), &registered)

	payload, err := json.Marshal(map[string]string{"device_id": "device-late0001", "device_label": "phone"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := &revokingBody{
		body: bytes.NewReader(payload),
		revoke: func() {
			logout := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
			logout.Header.Set("Authorization", "Bearer "+registered.SessionToken)
			handler.ServeHTTP(httptest.NewRecorder(), logout)
		},
	}
	request := httptest.NewRequest(http.MethodPost, "/sync/devices", body)
	request.Header.Set("Authorization", "Bearer "+registered.SessionToken)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a session revoked mid-body, got %d: %s", response.Code, response.Body.String())
	}

	var relogged struct {
		SessionToken string `json:"session_token"`
	}
	loginResponse := performJSONRequest(t, handler, http.MethodPost, "/auth/login", credentials, "", http.StatusOK)
	decodeResponse(t, loginResponse.Body.Bytes(), &relogged)
	listResponse := performJSONRequest(t, handler, http.MethodGet, "/sync/devices", nil, relogged.SessionToken, http.StatusOK)
	if bytes.Contains(listResponse.Body.Bytes(), []byte("device-late0001")) {
		t.Fatalf("expected no device attached, got %s", listResponse.Body.String())
	}
}

func TestPutBlobWhoseSessionIsRevokedMidBodyWritesNothing(t *testing.T) {
	handler := newTestServer(t)
	const login, password = "owner@example.com", "correct horse battery staple"
	credentials := map[string]string{"login": login, "password": password}

	var registered struct {
		SessionToken string `json:"session_token"`
	}
	registerResponse := performJSONRequest(t, handler, http.MethodPost, "/auth/register", credentials, "", http.StatusCreated)
	decodeResponse(t, registerResponse.Body.Bytes(), &registered)

	checksum := sha256.Sum256([]byte("ciphertext"))
	payload, err := json.Marshal(map[string]any{
		"schema_version":    1,
		"generation":        1,
		"checksum_sha256":   hex.EncodeToString(checksum[:]),
		"ciphertext_base64": base64.StdEncoding.EncodeToString([]byte("ciphertext")),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := &revokingBody{
		body: bytes.NewReader(payload),
		revoke: func() {
			logout := httptest.NewRequest(http.MethodDelete, "/auth/session", nil)
			logout.Header.Set("Authorization", "Bearer "+registered.SessionToken)
			handler.ServeHTTP(httptest.NewRecorder(), logout)
		},
	}
	request := httptest.NewRequest(http.MethodPut, "/sync/blob", body)
	request.Header.Set("Authorization", "Bearer "+registered.SessionToken)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a session revoked mid-body, got %d: %s", response.Code, response.Body.String())
	}
	var refusal map[string]string
	decodeResponse(t, response.Body.Bytes(), &refusal)
	if refusal["error"] != "unauthorized" {
		t.Fatalf("unexpected refusal: %#v", refusal)
	}

	var relogged struct {
		SessionToken string `json:"session_token"`
	}
	loginResponse := performJSONRequest(t, handler, http.MethodPost, "/auth/login", credentials, "", http.StatusOK)
	decodeResponse(t, loginResponse.Body.Bytes(), &relogged)
	performJSONRequest(t, handler, http.MethodGet, "/sync/blob", nil, relogged.SessionToken, http.StatusNotFound)
}
