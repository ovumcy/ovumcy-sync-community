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
	"unicode"
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

// TestSanitizeLogValueStripsControlCharacters covers what a steering character
// in a method or path can do: a line break forges or splits an entry in the log
// file, an ESC byte rewrites the line in the terminal the operator reads that
// file with, U+009B does the same as a single character, and a bidirectional
// override reorders how the entry is displayed. None is legitimate input here,
// so the C0 range, DEL, the C1 range and the Unicode format category are all
// asserted gone, while ordinary non-ASCII text is asserted intact.
//
// The characters under test are written as escape sequences on purpose: a
// literal one in this file would be invisible in review and in a diff, which
// is the property that makes them worth stripping in the first place.
func TestSanitizeLogValueStripsControlCharacters(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "line breaks",
			value: "GET /x\r\nInjected: forged-log-line",
			want:  "GET /xInjected: forged-log-line",
		},
		{
			// Stripped of the ESC bytes, the terminal prints what is left as
			// ordinary text instead of acting on it.
			name:  "ansi escape",
			value: "/sync/blob\x1b[31mnot-a-real-error\x1b[0m",
			want:  "/sync/blob[31mnot-a-real-error[0m",
		},
		{
			// A line-clearing sequence hides whatever the entry said before it.
			name:  "ansi erase",
			value: "/sync/blob\x1b[2K\x1b[1G200 OK",
			want:  "/sync/blob[2K[1G200 OK",
		},
		{
			name:  "nul",
			value: "/sync/blob\x00truncated",
			want:  "/sync/blobtruncated",
		},
		{
			name:  "del",
			value: "/sync/blob\x7fgone",
			want:  "/sync/blobgone",
		},
		{
			// A method is a token and a path is percent-encoded: neither has a
			// legitimate tab, and a tab still shifts the columns of the entry.
			name:  "tab",
			value: "GET\t/sync/blob",
			want:  "GET/sync/blob",
		},
		{
			// U+009B is the single-character CSI: a terminal decoding the log
			// as UTF-8 acts on it exactly as it would on \x1b[, so stripping
			// only the C0 range left the escape route open. The path arrives
			// percent-decoded, so %C2%9B is all a caller needs to reach here.
			name:  "c1 control sequence introducer",
			value: "/sync/blob\u009b2K\u009b1G200 OK",
			want:  "/sync/blob2K1G200 OK",
		},
		{
			// The bidirectional override executes nothing; it reorders how the
			// rest of the entry is displayed, so the reader sees a different
			// request than the one that was served.
			name:  "bidi override",
			value: "/sync/blob\u202ekcatta\u202c",
			want:  "/sync/blobkcatta",
		},
		{
			// A zero-width joiner is invisible: it splits a word for a log
			// parser while looking untouched to the operator reading it.
			name:  "zero-width format character",
			value: "/sync/\u200dblob",
			want:  "/sync/blob",
		},
		{
			// Legitimate non-ASCII text is not a control character and stays:
			// a path is text, and mangling it would lose what was requested.
			name:  "non-ascii text survives",
			value: "/sync/blob/тест",
			want:  "/sync/blob/тест",
		},
		{
			name:  "no control characters",
			value: "POST /sync/blob",
			want:  "POST /sync/blob",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got := sanitizeLogValue(testCase.value)
			if got != testCase.want {
				t.Fatalf("sanitizeLogValue(%q) = %q, want %q", testCase.value, got, testCase.want)
			}
			for _, r := range got {
				if r < 0x20 || r == 0x7F || (r >= 0x80 && r <= 0x9F) || unicode.Is(unicode.Cf, r) {
					t.Fatalf("sanitized value still holds control character %#U: %q", r, got)
				}
			}
		})
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
