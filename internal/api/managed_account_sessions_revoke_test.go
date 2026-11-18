package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func sessionsRevokePath(accountID string) string {
	return "/managed/accounts/" + accountID + "/sessions/revoke"
}

func TestServerRejectsManagedSessionsRevokeWhenDisabled(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{disableManaged: true})

	response := performJSONRequest(t, handler, http.MethodPost, sessionsRevokePath("managedacct1234"),
		nil, "test-managed-bridge-token", http.StatusServiceUnavailable)
	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "managed_bridge_disabled" {
		t.Fatalf("unexpected managed bridge disabled payload: %#v", payload)
	}
}

func TestServerManagedSessionsRevokeRejectsMissingOrWrongBridgeToken(t *testing.T) {
	handler := newTestServer(t)
	sessionToken := provisionManagedAccountWithData(t, handler, "managedacct1234")

	for _, bearer := range []string{"wrong-bridge-token", "", sessionToken} {
		response := performJSONRequest(t, handler, http.MethodPost, sessionsRevokePath("managedacct1234"),
			nil, bearer, http.StatusUnauthorized)
		var payload map[string]string
		decodeResponse(t, response.Body.Bytes(), &payload)
		if payload["error"] != "unauthorized" {
			t.Fatalf("unexpected bridge auth payload: %#v", payload)
		}
	}

	// Nothing was revoked by a refused call.
	performJSONRequest(t, handler, http.MethodGet, "/auth/session", nil, sessionToken, http.StatusOK)
}

// TestServerManagedSessionsRevokeContentTypeGate: a body must be JSON like on
// every bridge route; the route reads none, so a bodiless call needs no type.
func TestServerManagedSessionsRevokeContentTypeGate(t *testing.T) {
	handler := newTestServer(t)
	send := func(body string, contentType string) int {
		request := httptest.NewRequest(http.MethodPost, sessionsRevokePath("managedacct1234"), strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer test-managed-bridge-token")
		if contentType != "" {
			request.Header.Set("Content-Type", contentType)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder.Code
	}

	for _, contentType := range []string{"text/plain", ""} {
		if got := send(`{}`, contentType); got != http.StatusUnsupportedMediaType {
			t.Fatalf("body with Content-Type %q: status %d, want 415", contentType, got)
		}
	}
	if got := send("", ""); got != http.StatusOK {
		t.Fatalf("bodiless revoke: status %d, want 200", got)
	}
}

func TestServerManagedSessionsRevokeRejectsInvalidAccountID(t *testing.T) {
	handler := newTestServer(t)

	response := performJSONRequest(t, handler, http.MethodPost, sessionsRevokePath("bad"),
		nil, "test-managed-bridge-token", http.StatusBadRequest)
	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "invalid_managed_account" {
		t.Fatalf("unexpected invalid id payload: %#v", payload)
	}
}

func TestServerManagedSessionsRevokeRevokesSessionsOnlyAndIsSafeToRepeat(t *testing.T) {
	store := newTestStore(t, ":memory:")
	handler := newTestServerWithOptions(t, serverTestOptions{store: store})

	const accountID = "managedacct1234"
	sessionToken := provisionManagedAccountWithData(t, handler, accountID)
	bystanderToken := provisionManagedAccountWithData(t, handler, "managedbystander")
	performJSONRequest(t, handler, http.MethodGet, "/auth/session", nil, sessionToken, http.StatusOK)

	for attempt := range 2 {
		response := performJSONRequest(t, handler, http.MethodPost, sessionsRevokePath(accountID),
			nil, "test-managed-bridge-token", http.StatusOK)
		if body := strings.TrimSpace(response.Body.String()); body != `{"status":"sessions_revoked"}` {
			t.Fatalf("call %d: unexpected revoke body %s", attempt+1, body)
		}
	}

	// The revoked session no longer authenticates; the other managed
	// account's session does.
	performJSONRequest(t, handler, http.MethodGet, "/auth/session", nil, sessionToken, http.StatusUnauthorized)
	performJSONRequest(t, handler, http.MethodGet, "/auth/session", nil, bystanderToken, http.StatusOK)

	// Sessions only: the account, its blob, device and recovery-key package
	// stay, and a fresh mint serves the same blob.
	ctx := context.Background()
	account, err := store.FindAccountByID(ctx, accountID)
	if err != nil || account.Mode != "managed" || !account.PremiumActive {
		t.Fatalf("expected the managed account row intact, got %+v err=%v", account, err)
	}
	if count, err := store.CountDevicesForAccount(ctx, accountID); err != nil || count != 1 {
		t.Fatalf("expected the device kept, got count=%d err=%v", count, err)
	}
	if _, err := store.GetRecoveryKeyPackage(ctx, accountID); err != nil {
		t.Fatalf("expected the recovery-key package kept, got %v", err)
	}
	if _, err := store.GetEncryptedBlob(ctx, accountID); err != nil {
		t.Fatalf("expected the encrypted blob kept, got %v", err)
	}
	reminted := performJSONRequest(t, handler, http.MethodPost, "/managed/session",
		map[string]string{"account_id": accountID}, "test-managed-bridge-token", http.StatusOK)
	var mintPayload struct {
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, reminted.Body.Bytes(), &mintPayload)
	performJSONRequest(t, handler, http.MethodGet, "/sync/blob", nil, mintPayload.SessionToken, http.StatusOK)
}

// TestServerManagedSessionsRevokeAnswersASelfHostedIDLikeAnAbsentOne: a
// self-hosted account's real id gets the exact answer an id nobody holds
// gets, and its session keeps working.
func TestServerManagedSessionsRevokeAnswersASelfHostedIDLikeAnAbsentOne(t *testing.T) {
	handler := newTestServer(t)
	registered := registerOwner(t, handler)

	absent := performJSONRequest(t, handler, http.MethodPost, sessionsRevokePath("neverexisted1234"),
		nil, "test-managed-bridge-token", http.StatusOK)
	selfHosted := performJSONRequest(t, handler, http.MethodPost, sessionsRevokePath(registered.AccountID),
		nil, "test-managed-bridge-token", http.StatusOK)
	if absent.Body.String() != selfHosted.Body.String() || absent.Body.String() == "" {
		t.Fatalf("self-hosted answer %q differs from the absent answer %q", selfHosted.Body.String(), absent.Body.String())
	}

	performJSONRequest(t, handler, http.MethodGet, "/auth/session", nil, registered.SessionToken, http.StatusOK)
}

func TestServerManagedSessionsRevokeReturnsInternalErrorOnStoreFailure(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	handler := newTestServerWithOptions(t, serverTestOptions{store: store})
	dropTable(t, dbPath, "sessions")

	response := performJSONRequest(t, handler, http.MethodPost, sessionsRevokePath("managedacct1234"),
		nil, "test-managed-bridge-token", http.StatusInternalServerError)
	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "internal_error" {
		t.Fatalf("unexpected internal error payload: %#v", payload)
	}
}
