package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
	"github.com/ovumcy/ovumcy-sync-community/internal/services"
)

func sendWithContentType(handler http.Handler, method string, path string, body string, contentType string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = "203.0.113.60:4000"
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// TestBodyWithoutJSONContentTypeIs415BeforeTheLimiter: a body that is not
// declared application/json is refused before any limiter is charged, so a
// cross-site text/plain POST cannot spend the caller's per-IP auth bucket.
func TestBodyWithoutJSONContentTypeIs415BeforeTheLimiter(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{authRateLimitCount: 1})
	body := `{"login":"nobody@example.com","password":"correct horse battery staple"}`

	for _, contentType := range []string{"text/plain", "", "application/x-www-form-urlencoded", "application/jsonp", "not a media type"} {
		recorder := sendWithContentType(handler, http.MethodPost, "/auth/login", body, contentType)
		if recorder.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("Content-Type %q: status %d, want 415", contentType, recorder.Code)
		}
		var payload struct {
			Error string `json:"error"`
		}
		decodeResponse(t, recorder.Body.Bytes(), &payload)
		if payload.Error != "unsupported_media_type" {
			t.Fatalf("Content-Type %q: error %q, want unsupported_media_type", contentType, payload.Error)
		}
	}

	if got := sendWithContentType(handler, http.MethodPost, "/auth/login", body, "application/json; charset=utf-8").Code; got != http.StatusUnauthorized {
		t.Fatalf("JSON login after the refused bodies: status %d, want 401 (the bucket must be unspent)", got)
	}
}

// TestEmptyBodyNeedsNoContentType: a request without a body (logout, a
// session-only device removal) is not asked for a content type.
func TestEmptyBodyNeedsNoContentType(t *testing.T) {
	handler := newTestServer(t)
	if got := sendWithContentType(handler, http.MethodDelete, "/auth/session", "", "").Code; got != http.StatusUnauthorized {
		t.Fatalf("bodiless logout: status %d, want 401", got)
	}
}

// TestManagedBridgeBodiesNeedJSONContentType: the bridge routes sit behind the
// same gate, so a non-JSON body never reaches the bridge-token check; a
// bodiless purge is not asked for a content type.
func TestManagedBridgeBodiesNeedJSONContentType(t *testing.T) {
	handler := newTestServer(t)
	send := func(method string, path string, body string, contentType string) int {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.RemoteAddr = "203.0.113.61:4000"
		request.Header.Set("Authorization", "Bearer test-managed-bridge-token")
		if contentType != "" {
			request.Header.Set("Content-Type", contentType)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder.Code
	}

	for _, path := range []string{"/managed/session", "/managed/accounts/managedacct1234/premium"} {
		for _, contentType := range []string{"text/plain", ""} {
			if got := send(http.MethodPost, path, `{"active":false}`, contentType); got != http.StatusUnsupportedMediaType {
				t.Fatalf("POST %s with Content-Type %q: status %d, want 415", path, contentType, got)
			}
		}
	}
	if got := send(http.MethodDelete, "/managed/accounts/managedacct1234", "", ""); got == http.StatusUnsupportedMediaType {
		t.Fatalf("bodiless purge: status 415, want the route's own answer")
	}
}

func TestRegisterCapsTheLoginLength(t *testing.T) {
	handler := newTestServer(t)
	domain := "@example.com"
	atCap := strings.Repeat("a", security.MaxLoginBytes-len(domain)) + domain

	registerAccountFrom(t, handler, atCap, "198.51.100.9:1000")
	performJSONRequest(t, handler, http.MethodPost, "/auth/register",
		map[string]string{"login": "b" + atCap, "password": "correct horse battery staple"}, "", http.StatusBadRequest)
}

func TestAttachDeviceCapsIDAndLabelLength(t *testing.T) {
	handler := newTestServer(t)
	token := registerAccountFrom(t, handler, "owner@example.com", "198.51.100.9:1000")
	longID := strings.Repeat("d", services.MaxDeviceIDBytes)
	longLabel := strings.Repeat("L", services.MaxDeviceLabelBytes)

	for _, device := range []map[string]string{
		{"device_id": longID + "d", "device_label": "Pixel 7"},
		{"device_id": "device-1aaaa", "device_label": longLabel + "L"},
	} {
		response := performJSONRequest(t, handler, http.MethodPost, "/sync/devices", device, token, http.StatusBadRequest)
		var payload struct {
			Error string `json:"error"`
		}
		decodeResponse(t, response.Body.Bytes(), &payload)
		if payload.Error != "invalid_device" {
			t.Fatalf("error %q, want invalid_device", payload.Error)
		}
	}
	performJSONRequest(t, handler, http.MethodPost, "/sync/devices",
		map[string]string{"device_id": longID, "device_label": longLabel}, token, http.StatusOK)
}
