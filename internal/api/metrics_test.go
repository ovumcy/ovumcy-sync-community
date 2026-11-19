package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStatusCapturingResponseWriterDefaultsImplicitWriteToOK(t *testing.T) {
	recorder := httptest.NewRecorder()
	writer := &statusCapturingResponseWriter{
		ResponseWriter: recorder,
		status:         http.StatusOK,
	}

	// A handler that writes a body without an explicit WriteHeader commits an
	// implicit 200; the recorded status must reflect that.
	if _, err := writer.Write([]byte("payload")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if writer.status != http.StatusOK {
		t.Fatalf("expected implicit 200 status, got %d", writer.status)
	}

	// A late WriteHeader after the first write must not rewrite the recorded
	// status: the first committed status is what the metrics label reports.
	writer.WriteHeader(http.StatusInternalServerError)
	if writer.status != http.StatusOK {
		t.Fatalf("expected status to stay 200 after late WriteHeader, got %d", writer.status)
	}
}

func TestStatusCapturingResponseWriterKeepsFirstExplicitStatus(t *testing.T) {
	recorder := httptest.NewRecorder()
	writer := &statusCapturingResponseWriter{
		ResponseWriter: recorder,
		status:         http.StatusOK,
	}

	writer.WriteHeader(http.StatusNotFound)
	writer.WriteHeader(http.StatusInternalServerError)

	if writer.status != http.StatusNotFound {
		t.Fatalf("expected first explicit status 404 to win, got %d", writer.status)
	}
}

func TestTOTPMetricsObserversTolerateNilMetrics(t *testing.T) {
	// Both observer methods document that they are safe no-ops on a nil
	// receiver, so a metrics-disabled wiring mistake can never panic a
	// running server. Pin that contract.
	var metrics *Metrics
	metrics.ObserveTOTPEnrollmentCompletion("ok")
	metrics.ObserveTOTPChallengeCompletion("ok")
}

// A panicking handler is counted: the recovery wrapper sits outside the
// instrumented mux, so the request is recorded as the 500 it becomes.
func TestInstrumentCountsAPanickingHandlerAs500(t *testing.T) {
	metrics := NewMetrics()
	mux := http.NewServeMux()
	mux.Handle("GET /boom", metrics.Instrument("boom_route", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})))

	recorder := httptest.NewRecorder()
	serveWithPanicRecovery(recorder, httptest.NewRequest(http.MethodGet, "/boom", nil), mux)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected the recovery 500, got %d", recorder.Code)
	}

	scrape := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(scrape, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := scrape.Body.String()
	for _, name := range []string{"http_requests_total", "http_request_duration_seconds_count"} {
		found := false
		for _, line := range strings.Split(body, "\n") {
			if strings.Contains(line, name) && strings.Contains(line, `route="boom_route"`) &&
				strings.Contains(line, `code="500"`) && strings.HasSuffix(line, " 1") {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected a boom_route 500 sample for %s with value 1, got:\n%s", name, body)
		}
	}
}
