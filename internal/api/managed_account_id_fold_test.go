package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// strings.ToLower folds U+212A KELVIN SIGN to "k" and U+0130 to "i", and
// strings.TrimSpace strips Unicode spaces, so a check after either let a
// non-ASCII spelling through as "kelvin-acct". Every bridge route refuses
// each spelling and leaves the ASCII account untouched; an ASCII id in upper
// case, padded with ASCII spaces, still names it.
func TestBridgeRoutesRefuseAnIDThatOnlyLowercasingMakesASCII(t *testing.T) {
	handler := newTestServer(t)
	sessionToken := provisionManagedAccountWithData(t, handler, "kelvin-acct")

	asOf := time.Now().UTC().Format(time.RFC3339)
	for _, spelling := range []string{"Kelvin-acct", "kelvİn-acct", " kelvin-acct", "kelvin-acct　"} {
		escaped := url.PathEscape(spelling)
		for _, route := range []struct {
			method, path string
			body         any
		}{
			{http.MethodPost, "/managed/session", map[string]string{"account_id": spelling}},
			{http.MethodDelete, "/managed/accounts/" + escaped, nil},
			{http.MethodPost, "/managed/accounts/" + escaped + "/premium", map[string]any{"active": false, "as_of": asOf}},
			{http.MethodPost, "/managed/accounts/" + escaped + "/sessions/revoke", nil},
			{http.MethodPut, managedRecoveryKeyPath(escaped), recoveryKeyBody(strings.Repeat("d", 16), nil)},
		} {
			response := performJSONRequest(t, handler, route.method, route.path, route.body,
				"test-managed-bridge-token", http.StatusBadRequest)
			var payload map[string]string
			decodeResponse(t, response.Body.Bytes(), &payload)
			if payload["error"] != "invalid_managed_account" {
				t.Fatalf("%q: %s %s: unexpected payload %#v", spelling, route.method, route.path, payload)
			}
		}
	}

	performJSONRequest(t, handler, http.MethodGet, "/auth/session", nil, sessionToken, http.StatusOK)
	performJSONRequest(t, handler, http.MethodGet, "/sync/blob", nil, sessionToken, http.StatusOK)
	if got := storedRecoveryFingerprint(t, handler, sessionToken); got != strings.Repeat("c", 16) {
		t.Fatalf("expected the refused re-key to leave the package, got fingerprint %q", got)
	}

	performJSONRequest(t, handler, http.MethodPost, "/managed/session",
		map[string]string{"account_id": " KELVIN-ACCT "}, "test-managed-bridge-token", http.StatusOK)
	performJSONRequest(t, handler, http.MethodPost, "/managed/accounts/KELVIN-ACCT/sessions/revoke",
		nil, "test-managed-bridge-token", http.StatusOK)
	performJSONRequest(t, handler, http.MethodGet, "/auth/session", nil, sessionToken, http.StatusUnauthorized)
}
