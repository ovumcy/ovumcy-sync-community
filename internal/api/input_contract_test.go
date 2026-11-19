package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
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

// TestChunkedBodyIsJudgedByItsBytes: an unknown length (chunked) with zero
// bytes is no body and needs no content type; one with bytes still does, and a
// chunked JSON body reaches the handler whole.
func TestChunkedBodyIsJudgedByItsBytes(t *testing.T) {
	handler := newTestServer(t)
	send := func(body string, contentType string) int {
		request := httptest.NewRequest(http.MethodDelete, "/auth/session", strings.NewReader(body))
		request.ContentLength = -1
		request.RemoteAddr = "203.0.113.62:4000"
		if contentType != "" {
			request.Header.Set("Content-Type", contentType)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder.Code
	}

	if got := send("", ""); got != http.StatusUnauthorized {
		t.Fatalf("empty chunked logout: status %d, want 401", got)
	}
	if got := send("{}", ""); got != http.StatusUnsupportedMediaType {
		t.Fatalf("chunked body without Content-Type: status %d, want 415", got)
	}

	login := httptest.NewRequest(http.MethodPost, "/auth/login",
		strings.NewReader(`{"login":"nobody@example.com","password":"correct horse battery staple"}`))
	login.ContentLength = -1
	login.RemoteAddr = "203.0.113.62:4000"
	login.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, login)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("chunked JSON login: status %d, want 401 (the whole body must decode)", recorder.Code)
	}
}

// TestManagedBridgeBodiesNeedJSONContentType:the bridge routes sit behind the
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

// TestEveryRegisteredRouteGatesANonJSONBody pins the 415 content-type gate for
// every route the server registers. The route set is read from the
// registrations in server.go, so a route added later is covered without
// touching this test. The gate is universal (it runs ahead of the mux), so a
// body on a route that never reads one is refused too, and the same body
// declared as JSON is not.
func TestEveryRegisteredRouteGatesANonJSONBody(t *testing.T) {
	source, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	routes := regexp.MustCompile(`handleRoute\("([A-Z]+) (/[^"]*)"`).FindAllSubmatch(source, -1)
	if len(routes) == 0 {
		t.Fatal("found no handleRoute registrations in server.go")
	}
	handler := newTestServer(t)
	wildcard := regexp.MustCompile(`\{[a-z_]+\}`)

	send := func(method string, path string, contentType string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(`{"active":false}`))
		request.RemoteAddr = "203.0.113.63:4000"
		request.Header.Set("Authorization", "Bearer test-managed-bridge-token")
		if contentType != "" {
			request.Header.Set("Content-Type", contentType)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}

	for _, route := range routes {
		method, pattern := string(route[1]), string(route[2])
		path := wildcard.ReplaceAllString(pattern, "managedacct1234")
		for _, contentType := range []string{"text/plain", ""} {
			recorder := send(method, path, contentType)
			if recorder.Code != http.StatusUnsupportedMediaType {
				t.Fatalf("%s %s with Content-Type %q: status %d, want 415", method, pattern, contentType, recorder.Code)
			}
			var payload struct {
				Error string `json:"error"`
			}
			decodeResponse(t, recorder.Body.Bytes(), &payload)
			if payload.Error != "unsupported_media_type" {
				t.Fatalf("%s %s with Content-Type %q: error %q, want unsupported_media_type", method, pattern, contentType, payload.Error)
			}
		}
		if got := send(method, path, "application/json").Code; got == http.StatusUnsupportedMediaType {
			t.Fatalf("%s %s with a JSON body: status 415, want the route's own answer", method, pattern)
		}
	}
}

// TestUnknownPathAndWrongMethodAreNotJSON pins the transport-level answers the
// API description states: an unknown path or a method the path does not take
// gets the standard library's plain-text 404/405 (405 with Allow), and OPTIONS
// answers a bare 204, none of them the JSON error envelope.
func TestUnknownPathAndWrongMethodAreNotJSON(t *testing.T) {
	handler := newTestServer(t)
	send := func(method string, path string) *httptest.ResponseRecorder {
		return sendWithContentType(handler, method, path, "", "")
	}

	notFound := send(http.MethodGet, "/no/such/path")
	if notFound.Code != http.StatusNotFound {
		t.Fatalf("unknown path: status %d, want 404", notFound.Code)
	}
	wrongMethod := send(http.MethodGet, "/auth/login")
	if wrongMethod.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /auth/login: status %d, want 405", wrongMethod.Code)
	}
	if allow := wrongMethod.Header().Get("Allow"); !strings.Contains(allow, http.MethodPost) {
		t.Fatalf("405 Allow = %q, want it to name POST", allow)
	}
	for name, recorder := range map[string]*httptest.ResponseRecorder{"404": notFound, "405": wrongMethod} {
		if contentType := recorder.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/plain") {
			t.Fatalf("%s Content-Type = %q, want text/plain", name, contentType)
		}
		if json.Valid(recorder.Body.Bytes()) {
			t.Fatalf("%s body %q is JSON, want the plain-text stdlib answer", name, recorder.Body.String())
		}
	}

	options := send(http.MethodOptions, "/auth/login")
	if options.Code != http.StatusNoContent || options.Body.Len() != 0 {
		t.Fatalf("OPTIONS: status %d, body %q, want a bare 204", options.Code, options.Body.String())
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
