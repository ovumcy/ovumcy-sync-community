package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// A managed account has no password to step up with, so its session may store
// a first recovery key and re-put it unchanged, but never replace it: a
// stolen managed session alone must not swap out the owner's recovery path.
func TestPutRecoveryKeyManagedSessionCannotOverwrite(t *testing.T) {
	store := newTestStore(t, ":memory:")
	handler := newTestServerWithOptions(t, serverTestOptions{store: store})

	const accountID = "managedacct9012"
	sessionResponse := performJSONRequest(t, handler, http.MethodPost, "/managed/session",
		map[string]string{"account_id": accountID}, "test-managed-bridge-token", http.StatusOK)
	var session struct {
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, sessionResponse.Body.Bytes(), &session)
	if session.SessionToken == "" {
		t.Fatal("expected managed bridge session token")
	}

	packageA := strings.Repeat("c", 16)
	packageB := strings.Repeat("d", 16)
	performJSONRequest(t, handler, http.MethodPut, "/sync/recovery-key",
		recoveryKeyBody(packageA, nil), session.SessionToken, http.StatusOK)

	for _, stepUp := range []map[string]string{nil, {"current_password": "anything at all"}} {
		response := performJSONRequest(t, handler, http.MethodPut, "/sync/recovery-key",
			recoveryKeyBody(packageB, stepUp), session.SessionToken, http.StatusForbidden)
		var payload map[string]string
		decodeResponse(t, response.Body.Bytes(), &payload)
		if payload["error"] != "managed_recovery_key_overwrite" {
			t.Fatalf("unexpected refusal payload for %#v: %#v", stepUp, payload)
		}
	}

	stored, err := store.GetRecoveryKeyPackage(context.Background(), accountID)
	if err != nil {
		t.Fatalf("expected the first package to stay stored, got %v", err)
	}
	if stored.PhraseFingerprintHex != packageA {
		t.Fatalf("expected the refused overwrite to leave package A, got %q", stored.PhraseFingerprintHex)
	}

	performJSONRequest(t, handler, http.MethodPut, "/sync/recovery-key",
		recoveryKeyBody(strings.ToUpper(packageA), nil), session.SessionToken, http.StatusOK)
}
