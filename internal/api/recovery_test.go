package api

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// captureStandardLog redirects the standard logger for the duration of run and
// returns everything written to it. Flags are zeroed so an assertion sees the
// message alone, without a timestamp prefix in front of it.
func captureStandardLog(t *testing.T, run func()) string {
	t.Helper()

	previousWriter := log.Writer()
	previousFlags := log.Flags()
	t.Cleanup(func() {
		log.SetOutput(previousWriter)
		log.SetFlags(previousFlags)
	})

	var captured bytes.Buffer
	log.SetOutput(&captured)
	log.SetFlags(0)

	run()

	return captured.String()
}

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

// TestServeWithPanicRecoveryDoesNotLogThePanicValue pins the logging half of
// the recovery contract. A panic value is request-reachable text, so the
// recovery entry may carry only its shape — type and length — plus the stack
// trace, and the request still has to end as a clean 500.
//
// Before the redaction the panic value was interpolated with %v and the
// secret below appeared verbatim in the log.
func TestServeWithPanicRecoveryDoesNotLogThePanicValue(t *testing.T) {
	const secret = "ovumcy-recovery-code-7QF4-2XKD-9RMB-JT6P"
	panicMessage := "sync blob decode failed for " + secret

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/sync/blob", nil)

	logged := captureStandardLog(t, func() {
		serveWithPanicRecovery(recorder, request, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic(errors.New(panicMessage))
		}))
	})

	if strings.Contains(logged, secret) {
		t.Fatalf("recovery log leaked the panic value: %q", logged)
	}
	if strings.Contains(logged, panicMessage) {
		t.Fatalf("recovery log leaked the panic message: %q", logged)
	}

	// What must survive: the request line, the panic's shape, and the stack.
	if !strings.Contains(logged, "recovered panic serving POST /sync/blob") {
		t.Fatalf("expected a recovery log line, got %q", logged)
	}
	if !strings.Contains(logged, "panic_type=*errors.errorString") {
		t.Fatalf("expected the panic value's type in the log, got %q", logged)
	}
	if wantLen := fmt.Sprintf("panic_len=%d", len(panicMessage)); !strings.Contains(logged, wantLen) {
		t.Fatalf("expected %q in the log, got %q", wantLen, logged)
	}
	if !strings.Contains(logged, "api.serveWithPanicRecovery") {
		t.Fatalf("expected a stack trace in the log, got %q", logged)
	}

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}
	var payload map[string]string
	decodeResponse(t, recorder.Body.Bytes(), &payload)
	if payload["error"] != "internal_error" {
		t.Fatalf("expected internal_error, got %#v", payload)
	}
}

// TestPanicValueSummaryDescribesShapeOnly covers the value kinds a handler
// panic actually arrives as — a bare string, a wrapped error, a runtime error
// raised by the runtime itself — and asserts none of them renders its
// content.
func TestPanicValueSummaryDescribesShapeOnly(t *testing.T) {
	var nilMap map[string]string
	runtimeErr := func() (rec any) {
		defer func() { rec = recover() }()
		nilMap["k"] = "v"
		return nil
	}()

	for _, testCase := range []struct {
		name     string
		value    any
		contains string
	}{
		{name: "string", value: "login=owner@example.test", contains: "panic_type=string panic_len=24"},
		{name: "error", value: errors.New("boom"), contains: "panic_type=*errors.errorString panic_len=4"},
		{name: "runtime error", value: runtimeErr, contains: "panic_type=runtime.plainError"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got := panicValueSummary(testCase.value)
			if !strings.Contains(got, testCase.contains) {
				t.Fatalf("expected %q to contain %q", got, testCase.contains)
			}
			if strings.Contains(got, "owner@example.test") || strings.Contains(got, "boom") {
				t.Fatalf("summary rendered the panic value: %q", got)
			}
		})
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
