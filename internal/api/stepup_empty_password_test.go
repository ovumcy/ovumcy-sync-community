package api

import (
	"net/http"
	"testing"
)

// An empty current_password answers 401 invalid_current_password on every
// step-up route but gives the shared step-up slot back; a wrong non-empty one
// still keeps it.
func TestStepUpEmptyPasswordSpendsNoSlot(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{authRateLimitCount: 2, enableTOTP: true})
	token := registerStepUpOwner(t, handler)
	empty := stepUpCalls("")
	wrong := stepUpCalls("wrong password entirely")

	// Five empty passwords against a bucket of two: none was charged.
	for _, route := range []string{"change", "regen", "enroll", "delete", "recovery_key"} {
		call := empty[route]
		response := performJSONRequest(t, handler, call.method, call.path, call.body, token, http.StatusUnauthorized)
		expectErrorKey(t, response.Body.Bytes(), "invalid_current_password")
	}

	performJSONRequest(t, handler, wrong["change"].method, wrong["change"].path, wrong["change"].body,
		token, http.StatusUnauthorized)
	performJSONRequest(t, handler, wrong["delete"].method, wrong["delete"].path, wrong["delete"].body,
		token, http.StatusUnauthorized)
	performJSONRequest(t, handler, wrong["regen"].method, wrong["regen"].path, wrong["regen"].body,
		token, http.StatusTooManyRequests)
}

// A bodiless removal on an enrolled account answers 401 and spends no
// step-up slot.
func TestRemoveDeviceOnTOTPAccountWithoutBodySpendsNoSlot(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{enableTOTP: true, authRateLimitCount: 2})
	token, _, _ := enrollOwnerOverHTTP(t, handler)

	for range 2 {
		response := performJSONRequest(t, handler, http.MethodDelete, "/sync/devices/device-totp1111", nil,
			token, http.StatusUnauthorized)
		expectErrorKey(t, response.Body.Bytes(), "invalid_current_password")
	}
	for range 2 {
		performJSONRequest(t, handler, http.MethodDelete, "/account",
			map[string]string{"current_password": "not the password at all"}, token, http.StatusUnauthorized)
	}
	performJSONRequest(t, handler, http.MethodPost, "/auth/recovery-code/regenerate",
		map[string]string{"current_password": "not the password at all"}, token, http.StatusTooManyRequests)
}
