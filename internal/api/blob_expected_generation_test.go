package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"testing"
)

func TestServerPutBlobExpectedGeneration(t *testing.T) {
	handler := newTestServer(t)

	registerResponse := performJSONRequest(t, handler, http.MethodPost, "/auth/register", map[string]string{
		"login":    "owner@example.com",
		"password": "correct horse battery staple",
	}, "", http.StatusCreated)
	var registered struct {
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, registerResponse.Body.Bytes(), &registered)
	token := registered.SessionToken

	blobBody := func(generation int64, ciphertext string, expected any) map[string]any {
		sum := sha256.Sum256([]byte(ciphertext))
		body := map[string]any{
			"schema_version":    1,
			"generation":        generation,
			"checksum_sha256":   hex.EncodeToString(sum[:]),
			"ciphertext_base64": base64.StdEncoding.EncodeToString([]byte(ciphertext)),
		}
		if expected != nil {
			body["expected_generation"] = expected
		}
		return body
	}
	errorKey := func(t *testing.T, body []byte) string {
		t.Helper()
		var payload map[string]string
		decodeResponse(t, body, &payload)
		return payload["error"]
	}
	storedGeneration := func(t *testing.T) (int64, string) {
		t.Helper()
		response := performJSONRequest(t, handler, http.MethodGet, "/sync/blob", nil, token, http.StatusOK)
		var payload struct {
			Generation       int64  `json:"generation"`
			CiphertextBase64 string `json:"ciphertext_base64"`
		}
		decodeResponse(t, response.Body.Bytes(), &payload)
		return payload.Generation, payload.CiphertextBase64
	}

	// Absent field: today's behaviour, a first write at any positive generation.
	performJSONRequest(t, handler, http.MethodPut, "/sync/blob", blobBody(1, "first", nil), token, http.StatusOK)

	response := performJSONRequest(t, handler, http.MethodPut, "/sync/blob", blobBody(3, "lost-update", 0), token, http.StatusBadRequest)
	if key := errorKey(t, response.Body.Bytes()); key != "invalid_blob" {
		t.Fatalf("non-positive expected_generation: error = %q, want invalid_blob", key)
	}

	response = performJSONRequest(t, handler, http.MethodPut, "/sync/blob", blobBody(3, "lost-update", 2), token, http.StatusConflict)
	if key := errorKey(t, response.Body.Bytes()); key != "stale_generation" {
		t.Fatalf("mismatched expected_generation: error = %q, want stale_generation", key)
	}
	if generation, ciphertext := storedGeneration(t); generation != 1 || ciphertext != base64.StdEncoding.EncodeToString([]byte("first")) {
		t.Fatalf("refused write changed the blob: generation %d ciphertext %q", generation, ciphertext)
	}

	performJSONRequest(t, handler, http.MethodPut, "/sync/blob", blobBody(2, "second", 1), token, http.StatusOK)
	if generation, _ := storedGeneration(t); generation != 2 {
		t.Fatalf("matching expected_generation did not commit: generation %d", generation)
	}
}
