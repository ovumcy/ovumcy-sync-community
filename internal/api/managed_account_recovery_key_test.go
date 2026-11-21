package api

import (
	"net/http"
	"strings"
	"testing"
)

func managedRecoveryKeyPath(accountID string) string {
	return "/managed/accounts/" + accountID + "/recovery-key"
}

func storedRecoveryFingerprint(t *testing.T, handler http.Handler, sessionToken string) string {
	t.Helper()
	response := performJSONRequest(t, handler, http.MethodGet, "/sync/recovery-key", nil, sessionToken, http.StatusOK)
	var payload struct {
		PhraseFingerprintHex string `json:"phrase_fingerprint_hex"`
	}
	decodeResponse(t, response.Body.Bytes(), &payload)
	return payload.PhraseFingerprintHex
}

func TestServerRejectsManagedRecoveryKeyWhenDisabled(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{disableManaged: true})

	response := performJSONRequest(t, handler, http.MethodPut, managedRecoveryKeyPath("managedacct1234"),
		recoveryKeyBody(strings.Repeat("d", 16), nil), "test-managed-bridge-token", http.StatusServiceUnavailable)
	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "managed_bridge_disabled" {
		t.Fatalf("unexpected managed bridge disabled payload: %#v", payload)
	}
}

// TestServerManagedRecoveryKeyRejectsMissingOrWrongBridgeToken: the managed
// account's own session is not a bridge credential, so it cannot re-key here.
func TestServerManagedRecoveryKeyRejectsMissingOrWrongBridgeToken(t *testing.T) {
	handler := newTestServer(t)
	sessionToken := provisionManagedAccountWithData(t, handler, "managedacct1234")

	for _, bearer := range []string{"wrong-bridge-token", "", sessionToken} {
		response := performJSONRequest(t, handler, http.MethodPut, managedRecoveryKeyPath("managedacct1234"),
			recoveryKeyBody(strings.Repeat("d", 16), nil), bearer, http.StatusUnauthorized)
		var payload map[string]string
		decodeResponse(t, response.Body.Bytes(), &payload)
		if payload["error"] != "unauthorized" {
			t.Fatalf("unexpected bridge auth payload: %#v", payload)
		}
	}

	if got := storedRecoveryFingerprint(t, handler, sessionToken); got != strings.Repeat("c", 16) {
		t.Fatalf("expected the refused calls to leave the package, got fingerprint %q", got)
	}
}

// TestServerManagedRecoveryKeyReplacesThePackage: the bridge replaces a
// managed account's stored package — the overwrite its session is refused —
// and leaves the session, devices and blob in place; a repeat is safe. The
// session route then treats the new package as the stored one: re-putting it
// is the no-op 200, and the old package is an overwrite again.
func TestServerManagedRecoveryKeyReplacesThePackage(t *testing.T) {
	handler := newTestServer(t)
	sessionToken := provisionManagedAccountWithData(t, handler, "managedacct1234")
	devicesBefore := performJSONRequest(t, handler, http.MethodGet, "/sync/devices", nil, sessionToken, http.StatusOK).Body.String()
	blobBefore := performJSONRequest(t, handler, http.MethodGet, "/sync/blob", nil, sessionToken, http.StatusOK).Body.String()
	rekey := recoveryKeyBody(strings.Repeat("d", 16), nil)

	performJSONRequest(t, handler, http.MethodPut, "/sync/recovery-key", rekey, sessionToken, http.StatusForbidden)

	for attempt := range 2 {
		response := performJSONRequest(t, handler, http.MethodPut, managedRecoveryKeyPath("ManagedAcct1234"),
			rekey, "test-managed-bridge-token", http.StatusOK)
		if body := strings.TrimSpace(response.Body.String()); body != `{"status":"recovery_key_replaced"}` {
			t.Fatalf("unexpected re-key body on call %d: %s", attempt+1, body)
		}
	}

	if got := storedRecoveryFingerprint(t, handler, sessionToken); got != strings.Repeat("d", 16) {
		t.Fatalf("expected the re-keyed fingerprint, got %q", got)
	}
	if got := performJSONRequest(t, handler, http.MethodGet, "/sync/devices", nil, sessionToken, http.StatusOK).Body.String(); got != devicesBefore {
		t.Fatalf("expected devices untouched by the re-key, before %s after %s", devicesBefore, got)
	}
	if got := performJSONRequest(t, handler, http.MethodGet, "/sync/blob", nil, sessionToken, http.StatusOK).Body.String(); got != blobBefore {
		t.Fatal("expected the blob untouched by the re-key")
	}

	performJSONRequest(t, handler, http.MethodPut, "/sync/recovery-key", rekey, sessionToken, http.StatusOK)
	performJSONRequest(t, handler, http.MethodPut, "/sync/recovery-key",
		recoveryKeyBody(strings.Repeat("c", 16), nil), sessionToken, http.StatusForbidden)
}

// TestServerManagedRecoveryKeyValidatesLikeTheSessionRoute: a package the
// session route refuses is refused here too, an id outside the managed
// pattern is refused before it, and the step-up fields of the session body are
// unknown fields here. None of them writes.
func TestServerManagedRecoveryKeyValidatesLikeTheSessionRoute(t *testing.T) {
	handler := newTestServer(t)
	sessionToken := provisionManagedAccountWithData(t, handler, "managedacct1234")

	invalid := []map[string]any{
		recoveryKeyBody(strings.Repeat("d", 15), nil),
		recoveryKeyBody("not-hex-not-hex!", nil),
	}
	for _, mutate := range []func(map[string]any){
		func(body map[string]any) { body["algorithm"] = "aes256gcm" },
		func(body map[string]any) { body["kdf"] = "pbkdf2" },
		func(body map[string]any) { body["mnemonic_word_count"] = 24 },
		func(body map[string]any) { body["wrap_nonce_hex"] = strings.Repeat("a", 46) },
		func(body map[string]any) { body["wrapped_master_key_hex"] = strings.Repeat("b", 62) },
		func(body map[string]any) { body["wrapped_master_key_hex"] = strings.Repeat("b", 97) },
		func(body map[string]any) { body["wrapped_master_key_hex"] = strings.Repeat("b", 95) },
		func(body map[string]any) { body["wrapped_master_key_hex"] = strings.Repeat("b", 98) },
		func(body map[string]any) { body["wrapped_master_key_hex"] = strings.Repeat("b", 64) },
		func(body map[string]any) { body["wrapped_master_key_hex"] = strings.Repeat("g", 96) },
	} {
		body := recoveryKeyBody(strings.Repeat("d", 16), nil)
		mutate(body)
		invalid = append(invalid, body)
	}
	for _, body := range invalid {
		response := performJSONRequest(t, handler, http.MethodPut, managedRecoveryKeyPath("managedacct1234"),
			body, "test-managed-bridge-token", http.StatusBadRequest)
		var payload map[string]string
		decodeResponse(t, response.Body.Bytes(), &payload)
		if payload["error"] != "invalid_recovery_package" {
			t.Fatalf("expected invalid_recovery_package for %#v, got %#v", body, payload)
		}
	}

	response := performJSONRequest(t, handler, http.MethodPut, managedRecoveryKeyPath("bad"),
		recoveryKeyBody(strings.Repeat("d", 16), nil), "test-managed-bridge-token", http.StatusBadRequest)
	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "invalid_managed_account" {
		t.Fatalf("unexpected bad-id payload: %#v", payload)
	}

	performJSONRequest(t, handler, http.MethodPut, managedRecoveryKeyPath("managedacct1234"),
		recoveryKeyBody(strings.Repeat("d", 16), map[string]string{"current_password": "x"}),
		"test-managed-bridge-token", http.StatusBadRequest)

	if got := storedRecoveryFingerprint(t, handler, sessionToken); got != strings.Repeat("c", 16) {
		t.Fatalf("expected refused re-keys to leave the package, got fingerprint %q", got)
	}
}

// TestServerManagedRecoveryKeyAnswersASelfHostedIDLikeAnAbsentOne: the bridge
// never writes a self-hosted account's package, and a self-hosted account's
// real id gets the exact answer an id nobody holds gets.
func TestServerManagedRecoveryKeyAnswersASelfHostedIDLikeAnAbsentOne(t *testing.T) {
	handler := newTestServer(t)
	registered := registerOwner(t, handler)
	performJSONRequest(t, handler, http.MethodPut, "/sync/recovery-key",
		recoveryKeyBody(strings.Repeat("c", 16), map[string]string{"current_password": "correct horse battery staple"}),
		registered.SessionToken, http.StatusOK)

	rekey := recoveryKeyBody(strings.Repeat("d", 16), nil)
	absent := performJSONRequest(t, handler, http.MethodPut, managedRecoveryKeyPath("neverexisted1234"),
		rekey, "test-managed-bridge-token", http.StatusNotFound)
	selfHosted := performJSONRequest(t, handler, http.MethodPut, managedRecoveryKeyPath(registered.AccountID),
		rekey, "test-managed-bridge-token", http.StatusNotFound)
	if absent.Body.String() != selfHosted.Body.String() || !strings.Contains(absent.Body.String(), "managed_account_not_found") {
		t.Fatalf("self-hosted answer %q differs from the absent answer %q", selfHosted.Body.String(), absent.Body.String())
	}

	if got := storedRecoveryFingerprint(t, handler, registered.SessionToken); got != strings.Repeat("c", 16) {
		t.Fatalf("expected the self-hosted package untouched, got fingerprint %q", got)
	}
}

func TestServerManagedRecoveryKeyReturnsInternalErrorOnStoreFailure(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	handler := newTestServerWithOptions(t, serverTestOptions{store: store})
	provisionManagedAccountWithData(t, handler, "managedacct1234")
	dropTable(t, dbPath, "recovery_key_packages")

	response := performJSONRequest(t, handler, http.MethodPut, managedRecoveryKeyPath("managedacct1234"),
		recoveryKeyBody(strings.Repeat("d", 16), nil), "test-managed-bridge-token", http.StatusInternalServerError)
	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "internal_error" {
		t.Fatalf("unexpected internal error payload: %#v", payload)
	}
}
