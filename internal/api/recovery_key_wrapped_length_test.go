package api

import (
	"net/http"
	"strings"
	"testing"
)

// PUT /sync/recovery-key takes a wrapped master key of exactly 96 lowercase
// hex characters (a 32-byte key plus the 16-byte tag) and refuses any other
// length or a non-hex value with invalid_recovery_package.
func TestPutRecoveryKeyRequiresA96HexWrappedKey(t *testing.T) {
	handler := newTestServer(t)
	registered := registerOwner(t, handler)
	stepUp := map[string]string{"current_password": "correct horse battery staple"}

	for _, wrapped := range []string{
		strings.Repeat("b", 95),
		strings.Repeat("b", 97),
		strings.Repeat("b", 98),
		strings.Repeat("b", 64),
		strings.Repeat("g", 96),
	} {
		body := recoveryKeyBody(strings.Repeat("c", 16), stepUp)
		body["wrapped_master_key_hex"] = wrapped
		response := performJSONRequest(t, handler, http.MethodPut, "/sync/recovery-key",
			body, registered.SessionToken, http.StatusBadRequest)
		var payload map[string]string
		decodeResponse(t, response.Body.Bytes(), &payload)
		if payload["error"] != "invalid_recovery_package" {
			t.Fatalf("expected invalid_recovery_package for a %d-char wrapped key, got %#v", len(wrapped), payload)
		}
	}

	body := recoveryKeyBody(strings.Repeat("c", 16), stepUp)
	body["wrapped_master_key_hex"] = strings.Repeat("e", 96)
	performJSONRequest(t, handler, http.MethodPut, "/sync/recovery-key",
		body, registered.SessionToken, http.StatusOK)
}
