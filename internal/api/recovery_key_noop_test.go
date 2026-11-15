package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

func recoveryKeyBody(fingerprint string, stepUp map[string]string) map[string]any {
	body := map[string]any{
		"algorithm":              "xchacha20poly1305",
		"kdf":                    "bip39_seed_hkdf_sha256",
		"mnemonic_word_count":    12,
		"wrap_nonce_hex":         strings.Repeat("a", 48),
		"wrapped_master_key_hex": strings.Repeat("b", 96),
		"phrase_fingerprint_hex": fingerprint,
	}
	for key, value := range stepUp {
		body[key] = value
	}
	return body
}

// Clients re-put the wrapped recovery key on every upload without a password:
// the stored package back is a 200 that writes nothing, while a different one
// is still an overwrite behind the step-up.
func TestPutRecoveryKeyIdenticalRePutNeedsNoPassword(t *testing.T) {
	handler := newTestServer(t)
	registered := registerOwner(t, handler)
	fingerprint := strings.Repeat("c", 16)

	performJSONRequest(t, handler, http.MethodPut, "/sync/recovery-key",
		recoveryKeyBody(fingerprint, map[string]string{"current_password": "correct horse battery staple"}),
		registered.SessionToken, http.StatusOK)
	before := performJSONRequest(t, handler, http.MethodGet, "/sync/recovery-key", nil, registered.SessionToken, http.StatusOK)

	rePut := recoveryKeyBody(strings.ToUpper(fingerprint), nil)
	noop := performJSONRequest(t, handler, http.MethodPut, "/sync/recovery-key", rePut, registered.SessionToken, http.StatusOK)
	if noop.Body.String() != before.Body.String() {
		t.Fatalf("expected the stored package back unchanged, got %s want %s", noop.Body.String(), before.Body.String())
	}

	refused := performJSONRequest(t, handler, http.MethodPut, "/sync/recovery-key",
		recoveryKeyBody(strings.Repeat("d", 16), nil), registered.SessionToken, http.StatusUnauthorized)
	expectErrorKey(t, refused.Body.Bytes(), "invalid_current_password")

	after := performJSONRequest(t, handler, http.MethodGet, "/sync/recovery-key", nil, registered.SessionToken, http.StatusOK)
	if after.Body.String() != before.Body.String() {
		t.Fatalf("neither re-put may write, got %s want %s", after.Body.String(), before.Body.String())
	}
}

func TestPutRecoveryKeyIdenticalRePutOnTOTPAccountNeedsNoCode(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{enableTOTP: true})
	token, secret, nextStep := enrollOwnerOverHTTP(t, handler)
	fingerprint := strings.Repeat("c", 16)

	performJSONRequest(t, handler, http.MethodPut, "/sync/recovery-key",
		recoveryKeyBody(fingerprint, map[string]string{
			"current_password": totpTestPassword,
			"code":             security.GenerateTOTPCode(secret, nextStep),
		}), token, http.StatusOK)

	performJSONRequest(t, handler, http.MethodPut, "/sync/recovery-key", recoveryKeyBody(fingerprint, nil), token, http.StatusOK)

	missing := performJSONRequest(t, handler, http.MethodPut, "/sync/recovery-key",
		recoveryKeyBody(strings.Repeat("d", 16), map[string]string{"current_password": totpTestPassword}),
		token, http.StatusUnauthorized)
	expectErrorKey(t, missing.Body.Bytes(), "totp_invalid_code")
}
