package api

import (
	"net/http"
	"testing"
)

const stepUpOwnerPassword = "correct horse battery staple"

type stepUpCall struct {
	method string
	path   string
	body   map[string]any
}

func stepUpCalls(password string) map[string]stepUpCall {
	return map[string]stepUpCall{
		"change": {http.MethodPost, "/auth/change-password", map[string]any{
			"current_password": password, "new_password": "new staple battery horse correct",
		}},
		"regen":  {http.MethodPost, "/auth/recovery-code/regenerate", map[string]any{"current_password": password}},
		"enroll": {http.MethodPost, "/auth/totp/enroll", map[string]any{"current_password": password}},
		"disable": {http.MethodPost, "/auth/totp/disable", map[string]any{
			"current_password": password, "code": "000000",
		}},
		"delete": {http.MethodDelete, "/account", map[string]any{"current_password": password}},
		"recovery_key": {http.MethodPut, "/sync/recovery-key", map[string]any{
			"algorithm": "xchacha20poly1305", "kdf": "bip39_seed_hkdf_sha256", "mnemonic_word_count": 12,
			"wrap_nonce_hex": "", "wrapped_master_key_hex": "", "phrase_fingerprint_hex": "",
			"current_password": password,
		}},
	}
}

func registerStepUpOwner(t *testing.T, handler http.Handler) string {
	t.Helper()
	response := performJSONRequest(t, handler, http.MethodPost, "/auth/register",
		map[string]string{"login": "owner@example.com", "password": stepUpOwnerPassword}, "", http.StatusCreated)
	var body struct {
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, response.Body.Bytes(), &body)
	return body.SessionToken
}

func TestStepUpRoutesShareOneWrongPasswordBucket(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{authRateLimitCount: 5, enableTOTP: true})
	token := registerStepUpOwner(t, handler)
	wrong := stepUpCalls("wrong password entirely")

	for _, route := range []string{"change", "regen", "enroll", "delete", "recovery_key"} {
		call := wrong[route]
		performJSONRequest(t, handler, call.method, call.path, call.body, token, http.StatusUnauthorized)
	}

	// Each route's own bucket still has room; the shared one is spent.
	right := stepUpCalls(stepUpOwnerPassword)
	for _, route := range []string{"disable", "change"} {
		call := right[route]
		response := performJSONRequest(t, handler, call.method, call.path, call.body, token, http.StatusTooManyRequests)
		if response.Header().Get("Retry-After") == "" {
			t.Fatalf("%s: 429 without Retry-After", route)
		}
	}
}

func TestStepUpBucketKeepsOnlyWrongPasswords(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{authRateLimitCount: 2, enableTOTP: true})
	token := registerStepUpOwner(t, handler)
	right := stepUpCalls(stepUpOwnerPassword)
	wrong := stepUpCalls("wrong password entirely")

	// A refusal that is not a wrong password, and a correct password, leave
	// the bucket as they found it.
	performJSONRequest(t, handler, right["disable"].method, right["disable"].path, right["disable"].body,
		token, http.StatusServiceUnavailable)
	performJSONRequest(t, handler, right["regen"].method, right["regen"].path, right["regen"].body,
		token, http.StatusOK)

	performJSONRequest(t, handler, wrong["change"].method, wrong["change"].path, wrong["change"].body,
		token, http.StatusUnauthorized)
	performJSONRequest(t, handler, wrong["delete"].method, wrong["delete"].path, wrong["delete"].body,
		token, http.StatusUnauthorized)
	performJSONRequest(t, handler, wrong["recovery_key"].method, wrong["recovery_key"].path,
		wrong["recovery_key"].body, token, http.StatusTooManyRequests)
}
