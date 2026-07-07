package api

import (
	"net/http"
	"net/http/httptest"
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
