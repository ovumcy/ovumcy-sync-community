package api

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestServerRejectsManagedAccountPremiumWhenDisabled(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{
		disableManaged: true,
	})

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/accounts/managedacct1234/premium",
		map[string]any{"active": false},
		"test-managed-bridge-token",
		http.StatusServiceUnavailable,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "managed_bridge_disabled" {
		t.Fatalf("unexpected managed bridge disabled payload: %#v", payload)
	}
}

func TestServerManagedAccountPremiumRejectsWrongBridgeToken(t *testing.T) {
	handler := newTestServer(t)

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/accounts/managedacct1234/premium",
		map[string]any{"active": false},
		"wrong-bridge-token",
		http.StatusUnauthorized,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "unauthorized" {
		t.Fatalf("unexpected managed bridge auth payload: %#v", payload)
	}

	// A request with no bearer at all is refused the same way.
	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/accounts/managedacct1234/premium",
		map[string]any{"active": false},
		"",
		http.StatusUnauthorized,
	)
}

func TestServerManagedAccountPremiumRejectsInvalidAccountIDShape(t *testing.T) {
	handler := newTestServer(t)

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/accounts/bad/premium",
		map[string]any{"active": false},
		"test-managed-bridge-token",
		http.StatusBadRequest,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "invalid_managed_account" {
		t.Fatalf("unexpected invalid-shape payload: %#v", payload)
	}
}

// TestServerManagedAccountPremiumRejectsMalformedJSON pins the decodeJSON
// early-return: a syntactically broken body is refused with the transport's
// canonical invalid_json before the bridge service is ever consulted, so a
// garbled lapse signal can never be misread as either direction of the flag.
func TestServerManagedAccountPremiumRejectsMalformedJSON(t *testing.T) {
	handler := newTestServer(t)

	response := performRawRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/accounts/managedacct1234/premium",
		[]byte(`{"active":`),
		"test-managed-bridge-token",
		http.StatusBadRequest,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "invalid_json" {
		t.Fatalf("unexpected malformed-json payload: %#v", payload)
	}
}

// TestServerManagedAccountPremiumRecordsLapseRevokesSessionAndReplayIsIdempotent
// exercises the full HTTP contract for active=false: the response status
// string, the immediate session revocation, and idempotent replay.
func TestServerManagedAccountPremiumRecordsLapseRevokesSessionAndReplayIsIdempotent(t *testing.T) {
	handler := newTestServer(t)

	const accountID = "managedacct1234"
	sessionToken := provisionManagedAccountWithData(t, handler, accountID)

	for attempt := range 2 {
		response := performJSONRequest(
			t,
			handler,
			http.MethodPost,
			"/managed/accounts/"+accountID+"/premium",
			map[string]any{"active": false},
			"test-managed-bridge-token",
			http.StatusOK,
		)
		var payload map[string]string
		decodeResponse(t, response.Body.Bytes(), &payload)
		if payload["status"] != "lapse_recorded" {
			t.Fatalf("unexpected lapse payload on call %d: %#v", attempt+1, payload)
		}
	}

	// The pre-lapse session no longer authenticates.
	performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/sync/capabilities",
		nil,
		sessionToken,
		http.StatusUnauthorized,
	)
}

func TestServerManagedAccountPremiumClearsMarker(t *testing.T) {
	handler := newTestServer(t)

	const accountID = "managedacct1234"
	provisionManagedAccountWithData(t, handler, accountID)

	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/accounts/"+accountID+"/premium",
		map[string]any{"active": false},
		"test-managed-bridge-token",
		http.StatusOK,
	)

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/accounts/"+accountID+"/premium",
		map[string]any{"active": true, "as_of": asOfAfterNow()},
		"test-managed-bridge-token",
		http.StatusOK,
	)
	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["status"] != "lapse_cleared" {
		t.Fatalf("unexpected retraction payload: %#v", payload)
	}
}

func TestServerManagedAccountPremiumUnknownAccountIsIdempotentSuccess(t *testing.T) {
	handler := newTestServer(t)

	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/accounts/neverexisted1234/premium",
		map[string]any{"active": false},
		"test-managed-bridge-token",
		http.StatusOK,
	)
	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/accounts/neverexisted1234/premium",
		map[string]any{"active": true, "as_of": asOfAfterNow()},
		"test-managed-bridge-token",
		http.StatusOK,
	)
}

// asOfAfterNow is a reactivation as-of strictly newer than a lapse the
// server just stamped with its own clock, and inside the skew bound.
func asOfAfterNow() string {
	return time.Now().UTC().Add(time.Second).Format(time.RFC3339Nano)
}

func TestServerManagedAccountPremiumRejectsInvalidSignal(t *testing.T) {
	handler := newTestServer(t)

	const accountID = "managedacct1234"
	provisionManagedAccountWithData(t, handler, accountID)

	for _, body := range []map[string]any{
		{"active": true},
		{"active": false, "as_of": time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)},
	} {
		response := performJSONRequest(
			t,
			handler,
			http.MethodPost,
			"/managed/accounts/"+accountID+"/premium",
			body,
			"test-managed-bridge-token",
			http.StatusBadRequest,
		)
		var payload map[string]string
		decodeResponse(t, response.Body.Bytes(), &payload)
		if payload["error"] != "invalid_entitlement_signal" {
			t.Fatalf("unexpected payload for %#v: %#v", body, payload)
		}
	}
}

// TestServerManagedAccountPremiumRejectsStaleReactivation: a reactivation
// observed before the applied lapse is refused with 409 and the account
// stays unable to mint.
func TestServerManagedAccountPremiumRejectsStaleReactivation(t *testing.T) {
	handler := newTestServer(t)

	const accountID = "managedacct1234"
	provisionManagedAccountWithData(t, handler, accountID)

	lapseAsOf := time.Now().UTC().Add(-time.Minute)
	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/accounts/"+accountID+"/premium",
		map[string]any{"active": false, "as_of": lapseAsOf.Format(time.RFC3339Nano)},
		"test-managed-bridge-token",
		http.StatusOK,
	)

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/accounts/"+accountID+"/premium",
		map[string]any{"active": true, "as_of": lapseAsOf.Add(-time.Second).Format(time.RFC3339Nano)},
		"test-managed-bridge-token",
		http.StatusConflict,
	)
	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "stale_entitlement_signal" {
		t.Fatalf("unexpected stale payload: %#v", payload)
	}

	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/session",
		map[string]string{"account_id": accountID},
		"test-managed-bridge-token",
		http.StatusConflict,
	)
}

// TestServerSyncRoutesEnforceSyncDisabled: a session that outlived its
// account's premium (a mint racing a lapse) is refused on every data route
// with 403 sync_disabled, while capabilities still report why.
func TestServerSyncRoutesEnforceSyncDisabled(t *testing.T) {
	store, _ := newFileBackedTestStore(t)
	handler := newTestServerWithOptions(t, serverTestOptions{store: store})

	const accountID = "managedacct1234"
	sessionToken := provisionManagedAccountWithData(t, handler, accountID)

	// The unordered store primitive clears premium without revoking
	// sessions — the state a mint racing a lapse leaves behind.
	if err := store.SetAccountLapsed(context.Background(), accountID, time.Now().UTC()); err != nil {
		t.Fatalf("set account lapsed: %v", err)
	}

	routes := []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodPost, "/sync/devices", map[string]string{"device_id": "device-2bbbb", "device_label": "Pixel 8"}},
		{http.MethodGet, "/sync/devices", nil},
		{http.MethodDelete, "/sync/devices/device-1aaaa", nil},
		{http.MethodGet, "/sync/recovery-key", nil},
		{http.MethodPut, "/sync/recovery-key", map[string]any{}},
		{http.MethodGet, "/sync/blob", nil},
		{http.MethodPut, "/sync/blob", map[string]any{}},
	}
	for _, route := range routes {
		response := performJSONRequest(t, handler, route.method, route.path, route.body, sessionToken, http.StatusForbidden)
		var payload map[string]string
		decodeResponse(t, response.Body.Bytes(), &payload)
		if payload["error"] != "sync_disabled" {
			t.Fatalf("%s %s: unexpected payload %#v", route.method, route.path, payload)
		}
	}

	capabilitiesResponse := performJSONRequest(t, handler, http.MethodGet, "/sync/capabilities", nil, sessionToken, http.StatusOK)
	var capabilities struct {
		SyncEnabled bool `json:"sync_enabled"`
	}
	decodeResponse(t, capabilitiesResponse.Body.Bytes(), &capabilities)
	if capabilities.SyncEnabled {
		t.Fatal("expected capabilities to report sync_enabled=false")
	}
}

func TestServerManagedAccountPremiumRefusesSelfHostedAccount(t *testing.T) {
	handler := newTestServer(t)

	registered := registerOwner(t, handler)

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/accounts/"+registered.AccountID+"/premium",
		map[string]any{"active": false},
		"test-managed-bridge-token",
		http.StatusBadRequest,
	)
	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "invalid_managed_account" {
		t.Fatalf("unexpected refusal payload: %#v", payload)
	}

	// The self-hosted account is untouched: its session still authenticates.
	performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/sync/capabilities",
		nil,
		registered.SessionToken,
		http.StatusOK,
	)
}

func TestServerManagedAccountPremiumReturnsInternalErrorOnStoreFailure(t *testing.T) {
	store, dbPath := newFileBackedTestStore(t)
	handler := newTestServerWithOptions(t, serverTestOptions{store: store})

	const accountID = "managedacct1234"
	provisionManagedAccountWithData(t, handler, accountID)

	// Drop the sessions table out from under the live server: the account
	// lookup and the lapsed_at write both succeed, but revoking sessions
	// fails, so the handler must map that generic store error to a 500
	// rather than reporting success while sessions may still be live.
	dropTable(t, dbPath, "sessions")

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/accounts/"+accountID+"/premium",
		map[string]any{"active": false},
		"test-managed-bridge-token",
		http.StatusInternalServerError,
	)
	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "internal_error" {
		t.Fatalf("unexpected internal error payload: %#v", payload)
	}
}

// TestServerManagedAccountPremiumReactivationThenMintReenablesSync is the
// resubscribe path end to end over HTTP: after a lapse, a mint alone is
// refused (409 managed_account_lapsed — a delayed mint must never reverse
// a lapse); an ordered reactivation followed by a mint restores sync.
func TestServerManagedAccountPremiumReactivationThenMintReenablesSync(t *testing.T) {
	handler := newTestServer(t)

	const accountID = "managedacct1234"
	provisionManagedAccountWithData(t, handler, accountID)

	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/accounts/"+accountID+"/premium",
		map[string]any{"active": false},
		"test-managed-bridge-token",
		http.StatusOK,
	)

	refused := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/session",
		map[string]string{"account_id": accountID},
		"test-managed-bridge-token",
		http.StatusConflict,
	)
	var refusedPayload map[string]string
	decodeResponse(t, refused.Body.Bytes(), &refusedPayload)
	if refusedPayload["error"] != "managed_account_lapsed" {
		t.Fatalf("unexpected refused-mint payload: %#v", refusedPayload)
	}

	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/accounts/"+accountID+"/premium",
		map[string]any{"active": true, "as_of": asOfAfterNow()},
		"test-managed-bridge-token",
		http.StatusOK,
	)

	sessionResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/managed/session",
		map[string]string{"account_id": accountID},
		"test-managed-bridge-token",
		http.StatusOK,
	)
	var sessionPayload struct {
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, sessionResponse.Body.Bytes(), &sessionPayload)

	capabilitiesResponse := performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/sync/capabilities",
		nil,
		sessionPayload.SessionToken,
		http.StatusOK,
	)
	var capabilities struct {
		PremiumActive bool `json:"premium_active"`
		SyncEnabled   bool `json:"sync_enabled"`
	}
	decodeResponse(t, capabilitiesResponse.Body.Bytes(), &capabilities)
	if !capabilities.PremiumActive || !capabilities.SyncEnabled {
		t.Fatalf("expected premium and sync re-enabled after resubscribe mint, got %#v", capabilities)
	}
}
