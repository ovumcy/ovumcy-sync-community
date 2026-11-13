package api

import (
	"net/http"
	"testing"
)

func attachTestDevice(t *testing.T, handler http.Handler, sessionToken, deviceID, label string) {
	t.Helper()
	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/sync/devices",
		map[string]string{"device_id": deviceID, "device_label": label},
		sessionToken,
		http.StatusOK,
	)
}

// loginOwnerSession opens a second session for the account registerOwner
// created.
func loginOwnerSession(t *testing.T, handler http.Handler) string {
	t.Helper()
	response := performJSONRequest(t, handler, http.MethodPost, "/auth/login",
		map[string]string{"login": "owner@example.com", "password": "correct horse battery staple"}, "", http.StatusOK)
	var body struct {
		SessionToken string `json:"session_token"`
	}
	decodeResponse(t, response.Body.Bytes(), &body)
	if body.SessionToken == "" {
		t.Fatal("expected a session token from login")
	}
	return body.SessionToken
}

type deviceListBody struct {
	Devices []struct {
		DeviceID    string `json:"device_id"`
		DeviceLabel string `json:"device_label"`
	} `json:"devices"`
}

func TestListDevicesRequiresAuth(t *testing.T) {
	handler := newTestServer(t)
	performJSONRequest(t, handler, http.MethodGet, "/sync/devices", nil, "", http.StatusUnauthorized)
}

func TestRemoveDeviceRequiresAuth(t *testing.T) {
	handler := newTestServer(t)
	performJSONRequest(t, handler, http.MethodDelete, "/sync/devices/device-abcd1234", nil, "", http.StatusUnauthorized)
}

// TestListAndRemoveDeviceRoundTrip removes a device from another session:
// the device leaves the list and the session bound to it is revoked, while
// the remover's own session stays valid.
func TestListAndRemoveDeviceRoundTrip(t *testing.T) {
	handler := newTestServer(t)
	registered := registerOwner(t, handler)
	other := loginOwnerSession(t, handler)

	attachTestDevice(t, handler, registered.SessionToken, "device-abcd1234", "Pixel 7")

	listResponse := performJSONRequest(t, handler, http.MethodGet, "/sync/devices", nil, other, http.StatusOK)
	var listed deviceListBody
	decodeResponse(t, listResponse.Body.Bytes(), &listed)
	if len(listed.Devices) != 1 || listed.Devices[0].DeviceID != "device-abcd1234" {
		t.Fatalf("unexpected device list: %#v", listed.Devices)
	}

	removeResponse := performJSONRequest(t, handler, http.MethodDelete, "/sync/devices/device-abcd1234", nil, other, http.StatusOK)
	var removePayload map[string]string
	decodeResponse(t, removeResponse.Body.Bytes(), &removePayload)
	if removePayload["status"] != "removed" {
		t.Fatalf("unexpected remove payload: %#v", removePayload)
	}

	afterResponse := performJSONRequest(t, handler, http.MethodGet, "/sync/devices", nil, other, http.StatusOK)
	var after deviceListBody
	decodeResponse(t, afterResponse.Body.Bytes(), &after)
	if len(after.Devices) != 0 {
		t.Fatalf("device should be gone after removal, got %#v", after.Devices)
	}

	performJSONRequest(t, handler, http.MethodGet, "/auth/session", nil, registered.SessionToken, http.StatusUnauthorized)
}

// TestRemovingOwnDeviceEndsTheCallingSession: the remover's session is bound
// to the device it removes, so the 200 is its last authenticated answer.
func TestRemovingOwnDeviceEndsTheCallingSession(t *testing.T) {
	handler := newTestServer(t)
	registered := registerOwner(t, handler)
	unbound := loginOwnerSession(t, handler)

	attachTestDevice(t, handler, registered.SessionToken, "device-abcd1234", "Pixel 7")
	performJSONRequest(t, handler, http.MethodDelete, "/sync/devices/device-abcd1234", nil, registered.SessionToken, http.StatusOK)

	performJSONRequest(t, handler, http.MethodGet, "/auth/session", nil, registered.SessionToken, http.StatusUnauthorized)
	performJSONRequest(t, handler, http.MethodGet, "/auth/session", nil, unbound, http.StatusOK)
}

func TestRemoveDeviceUnknownReturns404(t *testing.T) {
	handler := newTestServer(t)
	registered := registerOwner(t, handler)

	response := performJSONRequest(t, handler, http.MethodDelete, "/sync/devices/device-missing1", nil, registered.SessionToken, http.StatusNotFound)
	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "device_not_found" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestRemoveDeviceRateLimitedPerAccount(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{authRateLimitCount: 1})
	registered := registerOwner(t, handler)
	other := loginOwnerSession(t, handler)

	attachTestDevice(t, handler, registered.SessionToken, "device-abcd1234", "Pixel 7")

	// First removal consumes the single per-account slot and succeeds.
	performJSONRequest(t, handler, http.MethodDelete, "/sync/devices/device-abcd1234", nil, other, http.StatusOK)

	// The rate-limit guard runs before the store, keyed on a stable string, so
	// a second removal — even of a different id — is rejected, proving the path
	// parameter cannot be used to sidestep the per-account ceiling.
	response := performJSONRequest(t, handler, http.MethodDelete, "/sync/devices/device-other999", nil, other, http.StatusTooManyRequests)
	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "rate_limited" {
		t.Fatalf("unexpected rate limit payload: %#v", payload)
	}
}
