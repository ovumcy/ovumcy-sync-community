package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServeWithPanicRecoveryReturns500(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/boom", nil)

	// A panicking handler must not propagate — it becomes a clean 500.
	serveWithPanicRecovery(recorder, request, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}
	var payload map[string]string
	decodeResponse(t, recorder.Body.Bytes(), &payload)
	if payload["error"] != "internal_error" {
		t.Fatalf("expected internal_error, got %#v", payload)
	}
}

func TestSanitizeLogValueStripsLineBreaks(t *testing.T) {
	got := sanitizeLogValue("GET /x\r\nInjected: forged-log-line")
	for _, r := range got {
		if r == '\n' || r == '\r' {
			t.Fatalf("sanitized value still contains a line break: %q", got)
		}
	}
	if got != "GET /xInjected: forged-log-line" {
		t.Fatalf("unexpected sanitized value: %q", got)
	}
}

func TestServeWithPanicRecoveryPassesThroughNormalResponse(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/ok", nil)

	serveWithPanicRecovery(recorder, request, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	var payload map[string]string
	decodeResponse(t, recorder.Body.Bytes(), &payload)
	if payload["status"] != "ok" {
		t.Fatalf("expected status ok, got %#v", payload)
	}
}
