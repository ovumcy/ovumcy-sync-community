package api

import (
	"net/http"
	"testing"
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
		map[string]any{"active": true},
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
		map[string]any{"active": true},
		"test-managed-bridge-token",
		http.StatusOK,
	)
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

// TestServerManagedAccountPremiumMintAfterLapseReenablesSync is the
// resubscribe path exercised end to end over HTTP: after a lapse signal
// revokes sync, a fresh POST /managed/session mint clears the marker and
// restores capabilities without any separate call.
func TestServerManagedAccountPremiumMintAfterLapseReenablesSync(t *testing.T) {
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
