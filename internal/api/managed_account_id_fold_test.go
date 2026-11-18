package api

import (
	"net/http"
	"testing"
	"time"
)

// strings.ToLower folds U+212A KELVIN SIGN to "k", so a check after lowering
// let "Kelvin-acct" through as "kelvin-acct". Every bridge route refuses
// the non-ASCII id and leaves the ASCII account untouched; an ASCII id in
// upper case still names it.
func TestBridgeRoutesRefuseAnIDThatOnlyLowercasingMakesASCII(t *testing.T) {
	handler := newTestServer(t)
	sessionToken := provisionManagedAccountWithData(t, handler, "kelvin-acct")

	const folded = "%E2%84%AAelvin-acct"
	asOf := time.Now().UTC().Format(time.RFC3339)
	for _, route := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/managed/session", map[string]string{"account_id": "Kelvin-acct"}},
		{http.MethodDelete, "/managed/accounts/" + folded, nil},
		{http.MethodPost, "/managed/accounts/" + folded + "/premium", map[string]any{"active": false, "as_of": asOf}},
		{http.MethodPost, "/managed/accounts/" + folded + "/sessions/revoke", nil},
	} {
		response := performJSONRequest(t, handler, route.method, route.path, route.body,
			"test-managed-bridge-token", http.StatusBadRequest)
		var payload map[string]string
		decodeResponse(t, response.Body.Bytes(), &payload)
		if payload["error"] != "invalid_managed_account" {
			t.Fatalf("%s %s: unexpected payload %#v", route.method, route.path, payload)
		}
	}

	performJSONRequest(t, handler, http.MethodGet, "/auth/session", nil, sessionToken, http.StatusOK)
	performJSONRequest(t, handler, http.MethodGet, "/sync/blob", nil, sessionToken, http.StatusOK)

	performJSONRequest(t, handler, http.MethodPost, "/managed/session",
		map[string]string{"account_id": " KELVIN-ACCT "}, "test-managed-bridge-token", http.StatusOK)
	performJSONRequest(t, handler, http.MethodPost, "/managed/accounts/KELVIN-ACCT/sessions/revoke",
		nil, "test-managed-bridge-token", http.StatusOK)
	performJSONRequest(t, handler, http.MethodGet, "/auth/session", nil, sessionToken, http.StatusUnauthorized)
}
