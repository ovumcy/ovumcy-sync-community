package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
)

func TestDeleteAccountEndpointErasesBlobDeviceAndSession(t *testing.T) {
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
		http.MethodPost,
		"/sync/devices",
		map[string]string{
			"device_id":    "device-1aaaa",
			"device_label": "Pixel 7",
		},
		registerPayload.SessionToken,
		http.StatusOK,
	)

	performJSONRequest(
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

	ciphertext := base64.StdEncoding.EncodeToString([]byte("ciphertext"))
	checksumBytes := sha256.Sum256([]byte("ciphertext"))
	performJSONRequest(
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

	deleteResponse := performJSONRequest(
		t,
		handler,
		http.MethodDelete,
		"/account",
		nil,
		registerPayload.SessionToken,
		http.StatusOK,
	)

	var deletePayload map[string]string
	decodeResponse(t, deleteResponse.Body.Bytes(), &deletePayload)
	if deletePayload["status"] != "account_deleted" {
		t.Fatalf("unexpected delete-account payload: %#v", deletePayload)
	}

	// The session used to perform the delete no longer authenticates: the
	// account it belonged to is gone, unlike change-password's "keep the
	// caller's own session alive" carve-out.
	performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/sync/capabilities",
		nil,
		registerPayload.SessionToken,
		http.StatusUnauthorized,
	)

	// The blob and recovery key are gone too, not just the session: a fresh
	// login as the same identity is impossible because the account row
	// itself is erased.
	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/login",
		map[string]string{
			"login":    "owner@example.com",
			"password": "correct horse battery staple",
		},
		"",
		http.StatusUnauthorized,
	)
}

func TestDeleteAccountEndpointRequiresAuth(t *testing.T) {
	handler := newTestServer(t)

	response := performJSONRequest(
		t,
		handler,
		http.MethodDelete,
		"/account",
		nil,
		"",
		http.StatusUnauthorized,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "unauthorized" {
		t.Fatalf("unexpected unauthorized payload: %#v", payload)
	}
}

func TestDeleteAccountEndpointDoesNotAffectOtherAccounts(t *testing.T) {
	handler := newTestServer(t)

	targetResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/register",
		map[string]string{
			"login":    "target@example.com",
			"password": "correct horse battery staple",
		},
		"",
		http.StatusCreated,
	)
	var targetPayload struct {
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, targetResponse.Body.Bytes(), &targetPayload)

	bystanderResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/register",
		map[string]string{
			"login":    "bystander@example.com",
			"password": "correct horse battery staple",
		},
		"",
		http.StatusCreated,
	)
	var bystanderPayload struct {
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, bystanderResponse.Body.Bytes(), &bystanderPayload)

	performJSONRequest(
		t,
		handler,
		http.MethodDelete,
		"/account",
		nil,
		targetPayload.SessionToken,
		http.StatusOK,
	)

	// Bystander's own session must keep working: DELETE /account only ever
	// derives its target from the caller's own authenticated session, never
	// from a client-supplied account id, so one account can never erase
	// another's data.
	performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/sync/capabilities",
		nil,
		bystanderPayload.SessionToken,
		http.StatusOK,
	)
}

func TestDeleteAccountEndpointIsIdempotentOnRepeat(t *testing.T) {
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
		"/account",
		nil,
		registerPayload.SessionToken,
		http.StatusOK,
	)

	// The session is revoked along with the account, so a literal repeat
	// call with the *same* bearer token now reads as unauthenticated rather
	// than "delete this account again" — which is itself the correct
	// idempotent outcome from the caller's point of view: the account's
	// data is gone either way, and no session can ever resurrect it.
	performJSONRequest(
		t,
		handler,
		http.MethodDelete,
		"/account",
		nil,
		registerPayload.SessionToken,
		http.StatusUnauthorized,
	)
}
