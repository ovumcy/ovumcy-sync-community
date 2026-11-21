package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
)

func rekeyBody(fingerprint string, generation int64, ciphertext string, expected any, stepUp map[string]string) map[string]any {
	sum := sha256.Sum256([]byte(ciphertext))
	body := map[string]any{
		"recovery_key": recoveryKeyBody(fingerprint, nil),
		"blob": map[string]any{
			"schema_version":    1,
			"generation":        generation,
			"checksum_sha256":   hex.EncodeToString(sum[:]),
			"ciphertext_base64": base64.StdEncoding.EncodeToString([]byte(ciphertext)),
		},
	}
	if expected != nil {
		body["expected_generation"] = expected
	}
	for key, value := range stepUp {
		body[key] = value
	}
	return body
}

func TestServerPutRekey(t *testing.T) {
	handler := newTestServer(t)
	registered := registerOwner(t, handler)
	token := registered.SessionToken
	password := map[string]string{"current_password": "correct horse battery staple"}
	k1, k2 := strings.Repeat("c", 16), strings.Repeat("d", 16)
	stored := func(t *testing.T) (string, string) {
		t.Helper()
		pkg := performJSONRequest(t, handler, http.MethodGet, "/sync/recovery-key", nil, token, http.StatusOK)
		var key struct {
			PhraseFingerprintHex string `json:"phrase_fingerprint_hex"`
		}
		decodeResponse(t, pkg.Body.Bytes(), &key)
		blob := performJSONRequest(t, handler, http.MethodGet, "/sync/blob", nil, token, http.StatusOK)
		var payload struct {
			CiphertextBase64 string `json:"ciphertext_base64"`
		}
		decodeResponse(t, blob.Body.Bytes(), &payload)
		raw, _ := base64.StdEncoding.DecodeString(payload.CiphertextBase64)
		return key.PhraseFingerprintHex, string(raw)
	}

	response := performJSONRequest(t, handler, http.MethodPut, "/sync/rekey", rekeyBody(k1, 1, "k1", nil, password), token, http.StatusBadRequest)
	expectErrorKey(t, response.Body.Bytes(), "invalid_blob")

	response = performJSONRequest(t, handler, http.MethodPut, "/sync/rekey", rekeyBody(k1, 1, "k1", 0, nil), token, http.StatusUnauthorized)
	expectErrorKey(t, response.Body.Bytes(), "invalid_current_password")

	response = performJSONRequest(t, handler, http.MethodPut, "/sync/rekey", rekeyBody(k1, 1, "k1", 0, password), token, http.StatusOK)
	var result struct {
		RecoveryKey struct {
			PhraseFingerprintHex string `json:"phrase_fingerprint_hex"`
		} `json:"recovery_key"`
		Blob struct {
			Generation int64 `json:"generation"`
		} `json:"blob"`
	}
	decodeResponse(t, response.Body.Bytes(), &result)
	if result.RecoveryKey.PhraseFingerprintHex != k1 || result.Blob.Generation != 1 {
		t.Fatalf("unexpected rekey response %s", response.Body.String())
	}

	response = performJSONRequest(t, handler, http.MethodPut, "/sync/rekey", rekeyBody(k2, 2, "k2", 0, password), token, http.StatusConflict)
	expectErrorKey(t, response.Body.Bytes(), "stale_generation")
	if fingerprint, ciphertext := stored(t); fingerprint != k1 || ciphertext != "k1" {
		t.Fatalf("a refused rekey changed state: %q %q", fingerprint, ciphertext)
	}

	// The stored package back needs no password.
	performJSONRequest(t, handler, http.MethodPut, "/sync/rekey", rekeyBody(k1, 2, "k1b", 1, nil), token, http.StatusOK)
	performJSONRequest(t, handler, http.MethodPut, "/sync/rekey", rekeyBody(k2, 3, "k2", 2, password), token, http.StatusOK)
	if fingerprint, ciphertext := stored(t); fingerprint != k2 || ciphertext != "k2" {
		t.Fatalf("rekey did not land both: %q %q", fingerprint, ciphertext)
	}

	unknown := rekeyBody(k2, 4, "k2", 3, password)
	unknown["recovery_key"].(map[string]any)["current_password"] = "correct horse battery staple"
	performJSONRequest(t, handler, http.MethodPut, "/sync/rekey", unknown, token, http.StatusBadRequest)

	capabilities := performJSONRequest(t, handler, http.MethodGet, "/sync/capabilities", nil, token, http.StatusOK)
	var document struct {
		AtomicRekey bool `json:"atomic_rekey"`
	}
	decodeResponse(t, capabilities.Body.Bytes(), &document)
	if !document.AtomicRekey {
		t.Fatalf("capabilities must report atomic_rekey: %s", capabilities.Body.String())
	}
}

// A wrong password on a differing package spends the step-up bucket; the
// stored package back never waits on it.
func TestServerPutRekeyStepUpBucket(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{authRateLimitCount: 4})
	token := registerStepUpOwner(t, handler)
	k1 := strings.Repeat("c", 16)
	performJSONRequest(t, handler, http.MethodPut, "/sync/rekey",
		rekeyBody(k1, 1, "k1", 0, map[string]string{"current_password": stepUpOwnerPassword}), token, http.StatusOK)

	// Budget 4 against 3 rekey PUTs: the last 429 can only come from the
	// step-up bucket, not the route's own one.
	performJSONRequest(t, handler, http.MethodPut, "/sync/rekey",
		rekeyBody(strings.Repeat("d", 16), 2, "k2", 1, map[string]string{"current_password": "wrong password entirely"}),
		token, http.StatusUnauthorized)
	wrongDelete := stepUpCalls("wrong password entirely")["delete"]
	for range 3 {
		performJSONRequest(t, handler, wrongDelete.method, wrongDelete.path, wrongDelete.body, token, http.StatusUnauthorized)
	}
	performJSONRequest(t, handler, http.MethodPut, "/sync/rekey", rekeyBody(k1, 2, "k1b", 1, nil), token, http.StatusOK)
	performJSONRequest(t, handler, http.MethodPut, "/sync/rekey",
		rekeyBody(strings.Repeat("d", 16), 3, "k2", 2, map[string]string{"current_password": stepUpOwnerPassword}),
		token, http.StatusTooManyRequests)
}
