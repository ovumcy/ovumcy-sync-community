package api

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

// enrollOwnerOverHTTP registers and enrolls an owner, returning the session,
// the secret and the next unspent step (the enrollment code spent the current
// one).
func enrollOwnerOverHTTP(t *testing.T, handler http.Handler) (token string, secret []byte, nextStep int64) {
	t.Helper()
	token = registerOwnerWithTOTP(t, handler)
	enrollResp := performJSONRequest(t, handler, http.MethodPost, "/auth/totp/enroll",
		map[string]string{"current_password": totpTestPassword}, token, http.StatusOK)
	var enrollBody struct {
		SecretBase32 string `json:"secret_base32"`
	}
	decodeResponse(t, enrollResp.Body.Bytes(), &enrollBody)
	secret, err := security.DecodeTOTPSecretBase32(enrollBody.SecretBase32)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	step := time.Now().Unix() / security.TOTPStepSeconds
	performJSONRequest(t, handler, http.MethodPost, "/auth/totp/verify",
		map[string]string{"code": security.GenerateTOTPCode(secret, step)}, token, http.StatusOK)
	return token, secret, step + 1
}

func expectErrorKey(t *testing.T, body []byte, want string) {
	t.Helper()
	var decoded map[string]string
	decodeResponse(t, body, &decoded)
	if decoded["error"] != want {
		t.Fatalf("expected %s, got %#v", want, decoded)
	}
}

func TestStepUpRoutesRequireTOTPCodeWhenEnrolled(t *testing.T) {
	recoveryKey := func(code string) map[string]any {
		body := map[string]any{
			"algorithm":              "xchacha20poly1305",
			"kdf":                    "bip39_seed_hkdf_sha256",
			"mnemonic_word_count":    12,
			"wrap_nonce_hex":         strings.Repeat("a", 48),
			"wrapped_master_key_hex": strings.Repeat("b", 96),
			"phrase_fingerprint_hex": strings.Repeat("c", 16),
			"current_password":       totpTestPassword,
		}
		if code != "" {
			body["code"] = code
		}
		return body
	}
	passwordAndCode := func(code string) map[string]any {
		body := map[string]any{"current_password": totpTestPassword}
		if code != "" {
			body["code"] = code
		}
		return body
	}

	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   func(code string) map[string]any
	}{
		{"recovery key", http.MethodPut, "/sync/recovery-key", recoveryKey},
		{"account delete", http.MethodDelete, "/account", passwordAndCode},
		{"device remove", http.MethodDelete, "/sync/devices/device-totp1111", passwordAndCode},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := newTestServerWithOptions(t, serverTestOptions{enableTOTP: true})
			token, secret, nextStep := enrollOwnerOverHTTP(t, handler)
			performJSONRequest(t, handler, http.MethodPost, "/sync/devices",
				map[string]string{"device_id": "device-totp1111", "device_label": "phone"}, token, http.StatusOK)

			missing := performJSONRequest(t, handler, tc.method, tc.path, tc.body(""), token, http.StatusUnauthorized)
			expectErrorKey(t, missing.Body.Bytes(), "totp_invalid_code")

			performJSONRequest(t, handler, tc.method, tc.path,
				tc.body(security.GenerateTOTPCode(secret, nextStep)), token, http.StatusOK)
		})
	}
}

// An enrolled account's device removal is a step-up: no body (no password)
// is refused and the device stays.
func TestRemoveDeviceOnTOTPAccountRequiresPassword(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{enableTOTP: true})
	token, secret, nextStep := enrollOwnerOverHTTP(t, handler)
	performJSONRequest(t, handler, http.MethodPost, "/sync/devices",
		map[string]string{"device_id": "device-totp1111", "device_label": "phone"}, token, http.StatusOK)

	resp := performJSONRequest(t, handler, http.MethodDelete, "/sync/devices/device-totp1111", nil, token, http.StatusUnauthorized)
	expectErrorKey(t, resp.Body.Bytes(), "invalid_current_password")
	wrong := performJSONRequest(t, handler, http.MethodDelete, "/sync/devices/device-totp1111",
		map[string]string{"current_password": "not the password at all", "code": security.GenerateTOTPCode(secret, nextStep)},
		token, http.StatusUnauthorized)
	expectErrorKey(t, wrong.Body.Bytes(), "invalid_current_password")

	list := performJSONRequest(t, handler, http.MethodGet, "/sync/devices", nil, token, http.StatusOK)
	if !strings.Contains(list.Body.String(), "device-totp1111") {
		t.Fatalf("a refused removal must keep the device, got %s", list.Body.String())
	}
}

// An account without TOTP removes a device with no body at all, as before.
func TestRemoveDeviceWithoutTOTPNeedsNoBody(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{enableTOTP: true})
	token := registerOwnerWithTOTP(t, handler)
	performJSONRequest(t, handler, http.MethodPost, "/sync/devices",
		map[string]string{"device_id": "device-plain111", "device_label": "phone"}, token, http.StatusOK)

	performJSONRequest(t, handler, http.MethodDelete, "/sync/devices/device-plain111", nil, token, http.StatusOK)
}

func TestRemoveDeviceRejectsAMalformedBody(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{enableTOTP: true})
	token := registerOwnerWithTOTP(t, handler)

	for _, body := range []any{
		map[string]string{"unknown": "x"},
		"not an object",
		map[string]string{"code": strings.Repeat("1", 5<<10)},
	} {
		resp := performJSONRequest(t, handler, http.MethodDelete, "/sync/devices/device-plain111", body, token, http.StatusBadRequest)
		expectErrorKey(t, resp.Body.Bytes(), "invalid_json")
	}
}
