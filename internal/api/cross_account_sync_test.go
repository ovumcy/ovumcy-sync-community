package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
)

// TestSyncBlobAndRecoveryKeyAreScopedToTheCallersAccount proves account B's
// session can neither read nor overwrite account A's blob or recovery key:
// every read answers from B's own (empty) scope, and a write by B lands in
// B's scope, leaving A's data byte-for-byte unchanged.
func TestSyncBlobAndRecoveryKeyAreScopedToTheCallersAccount(t *testing.T) {
	handler := newTestServer(t)
	const password = "correct horse battery staple"

	register := func(login string) string {
		response := performJSONRequest(t, handler, http.MethodPost, "/auth/register",
			map[string]string{"login": login, "password": password}, "", http.StatusCreated)
		var payload registerPayload
		decodeResponse(t, response.Body.Bytes(), &payload)
		return payload.SessionToken
	}
	tokenA := register("account-a@example.com")
	tokenB := register("account-b@example.com")

	blobBody := func(plain string) map[string]any {
		sum := sha256.Sum256([]byte(plain))
		return map[string]any{
			"schema_version":    1,
			"generation":        1,
			"checksum_sha256":   hex.EncodeToString(sum[:]),
			"ciphertext_base64": base64.StdEncoding.EncodeToString([]byte(plain)),
		}
	}
	recoveryBody := func(fill string) map[string]any {
		return map[string]any{
			"algorithm":              "xchacha20poly1305",
			"kdf":                    "bip39_seed_hkdf_sha256",
			"mnemonic_word_count":    12,
			"wrap_nonce_hex":         strings.Repeat(fill, 48),
			"wrapped_master_key_hex": strings.Repeat(fill, 96),
			"phrase_fingerprint_hex": strings.Repeat(fill, 16),
			"current_password":       password,
		}
	}

	performJSONRequest(t, handler, http.MethodPut, "/sync/blob", blobBody("account-a-secret"), tokenA, http.StatusOK)
	performJSONRequest(t, handler, http.MethodPut, "/sync/recovery-key", recoveryBody("a"), tokenA, http.StatusOK)

	// B reads: nothing of A's is visible.
	performJSONRequest(t, handler, http.MethodGet, "/sync/blob", nil, tokenB, http.StatusNotFound)
	performJSONRequest(t, handler, http.MethodGet, "/sync/recovery-key", nil, tokenB, http.StatusNotFound)

	// B writes at the same generation as A's: it is B's first blob (200), not
	// a stale-generation conflict against A's, and it is stored under B.
	performJSONRequest(t, handler, http.MethodPut, "/sync/blob", blobBody("account-b-secret"), tokenB, http.StatusOK)
	performJSONRequest(t, handler, http.MethodPut, "/sync/recovery-key", recoveryBody("b"), tokenB, http.StatusOK)

	// A's data is untouched by B's writes.
	var blobA struct {
		CiphertextBase64 string `json:"ciphertext_base64"`
	}
	decodeResponse(t, performJSONRequest(t, handler, http.MethodGet, "/sync/blob", nil, tokenA, http.StatusOK).Body.Bytes(), &blobA)
	if got, _ := base64.StdEncoding.DecodeString(blobA.CiphertextBase64); string(got) != "account-a-secret" {
		t.Fatalf("account A's blob changed after B wrote: %q", got)
	}
	var keyA struct {
		WrapNonceHex string `json:"wrap_nonce_hex"`
	}
	decodeResponse(t, performJSONRequest(t, handler, http.MethodGet, "/sync/recovery-key", nil, tokenA, http.StatusOK).Body.Bytes(), &keyA)
	if keyA.WrapNonceHex != strings.Repeat("a", 48) {
		t.Fatalf("account A's recovery key changed after B wrote: %q", keyA.WrapNonceHex)
	}

	// And B reads back its own.
	var blobB struct {
		CiphertextBase64 string `json:"ciphertext_base64"`
	}
	decodeResponse(t, performJSONRequest(t, handler, http.MethodGet, "/sync/blob", nil, tokenB, http.StatusOK).Body.Bytes(), &blobB)
	if got, _ := base64.StdEncoding.DecodeString(blobB.CiphertextBase64); string(got) != "account-b-secret" {
		t.Fatalf("account B reads %q, want its own blob", got)
	}
}
