package api

import (
	"net/http"
	"strings"
	"testing"
)

func expectingRecoveryKeyBody(fingerprint, expected string) map[string]any {
	return recoveryKeyBody(fingerprint, map[string]string{"expected_phrase_fingerprint_hex": expected})
}

func assertRecoveryKeyError(t *testing.T, response interface{ Bytes() []byte }, want string) {
	t.Helper()
	var payload map[string]string
	decodeResponse(t, response.Bytes(), &payload)
	if payload["error"] != want {
		t.Fatalf("expected error %q, got %#v", want, payload)
	}
}

// TestServerManagedRecoveryKeyExpectedFingerprintGuardsTheReplace: with
// expected_phrase_fingerprint_hex the re-key replaces the package only while
// the stored one carries that fingerprint; a mismatch answers
// 409 recovery_key_conflict and leaves the stored package, so a re-sent older
// rotation cannot bring a retired phrase back. A committed re-key's retry is
// still the idempotent 200.
func TestServerManagedRecoveryKeyExpectedFingerprintGuardsTheReplace(t *testing.T) {
	handler := newTestServer(t)
	sessionToken := provisionManagedAccountWithData(t, handler, "managedacct1234")
	path := managedRecoveryKeyPath("managedacct1234")
	stored := strings.Repeat("c", 16)

	response := performJSONRequest(t, handler, http.MethodPut, path,
		expectingRecoveryKeyBody(strings.Repeat("d", 16), strings.Repeat("e", 16)), "test-managed-bridge-token", http.StatusConflict)
	assertRecoveryKeyError(t, response.Body, "recovery_key_conflict")
	if got := storedRecoveryFingerprint(t, handler, sessionToken); got != stored {
		t.Fatalf("expected the conflict to leave fingerprint %q, got %q", stored, got)
	}

	rotation := expectingRecoveryKeyBody(strings.Repeat("d", 16), strings.ToUpper(stored))
	for attempt := range 2 {
		response := performJSONRequest(t, handler, http.MethodPut, path, rotation, "test-managed-bridge-token", http.StatusOK)
		if body := strings.TrimSpace(response.Body.String()); body != `{"status":"recovery_key_replaced"}` {
			t.Fatalf("unexpected re-key body on call %d: %s", attempt+1, body)
		}
	}
	if got := storedRecoveryFingerprint(t, handler, sessionToken); got != strings.Repeat("d", 16) {
		t.Fatalf("expected the matched re-key to commit, got fingerprint %q", got)
	}

	performJSONRequest(t, handler, http.MethodPut, path,
		expectingRecoveryKeyBody(strings.Repeat("e", 16), stored), "test-managed-bridge-token", http.StatusConflict)
	if got := storedRecoveryFingerprint(t, handler, sessionToken); got != strings.Repeat("d", 16) {
		t.Fatalf("expected the stale rotation to leave fingerprint %q, got %q", strings.Repeat("d", 16), got)
	}
}

// TestServerManagedRecoveryKeyWithoutExpectedFingerprintStaysUnconditional:
// the field is optional, so a caller that omits it (or sends null) replaces
// the package as before; a malformed one is refused like a malformed package.
func TestServerManagedRecoveryKeyWithoutExpectedFingerprintStaysUnconditional(t *testing.T) {
	handler := newTestServer(t)
	sessionToken := provisionManagedAccountWithData(t, handler, "managedacct1234")
	path := managedRecoveryKeyPath("managedacct1234")

	performJSONRequest(t, handler, http.MethodPut, path,
		recoveryKeyBody(strings.Repeat("d", 16), nil), "test-managed-bridge-token", http.StatusOK)
	if got := storedRecoveryFingerprint(t, handler, sessionToken); got != strings.Repeat("d", 16) {
		t.Fatalf("expected the omitted field to replace unconditionally, got %q", got)
	}

	withNull := recoveryKeyBody(strings.Repeat("e", 16), nil)
	withNull["expected_phrase_fingerprint_hex"] = nil
	performJSONRequest(t, handler, http.MethodPut, path, withNull, "test-managed-bridge-token", http.StatusOK)
	if got := storedRecoveryFingerprint(t, handler, sessionToken); got != strings.Repeat("e", 16) {
		t.Fatalf("expected a null field to replace unconditionally, got %q", got)
	}

	for _, expected := range []string{"", "zz", strings.Repeat("e", 15), strings.Repeat("g", 16)} {
		response := performJSONRequest(t, handler, http.MethodPut, path,
			expectingRecoveryKeyBody(strings.Repeat("f", 16), expected), "test-managed-bridge-token", http.StatusBadRequest)
		assertRecoveryKeyError(t, response.Body, "invalid_recovery_package")
	}
	if got := storedRecoveryFingerprint(t, handler, sessionToken); got != strings.Repeat("e", 16) {
		t.Fatalf("expected refused calls to leave the package, got %q", got)
	}
}
