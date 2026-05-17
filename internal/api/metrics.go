package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	registry              *prometheus.Registry
	inFlight              prometheus.Gauge
	requestTotal          *prometheus.CounterVec
	requestDuration       *prometheus.HistogramVec
	totpEnrollmentTotal   *prometheus.CounterVec
	totpChallengeTotal    *prometheus.CounterVec
}

func NewMetrics() *Metrics {
	registry := prometheus.NewRegistry()
	inFlight := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "ovumcy",
		Subsystem: "sync_community",
		Name:      "http_in_flight_requests",
		Help:      "Current in-flight HTTP requests.",
	})
	requestTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ovumcy",
			Subsystem: "sync_community",
			Name:      "http_requests_total",
			Help:      "Total HTTP requests handled by the sync community server.",
		},
		[]string{"route", "method", "code"},
	)
	requestDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "ovumcy",
			Subsystem: "sync_community",
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request duration by route, method, and status code.",
			Buckets:   prometheus.DefBuckets,
		},
		[]string{"route", "method", "code"},
	)
	// Domain-level counters complement the HTTP histograms by distinguishing
	// TOTP outcomes that all share the same 401 status code (`invalid_code`
	// vs `replayed` vs `challenge_invalid` vs `burnt`). Operators use the
	// `burnt` rate as an early signal that an attacker is brute-forcing a
	// stolen challenge id.
	totpEnrollmentTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ovumcy",
			Subsystem: "sync_community",
			Name:      "totp_enrollment_completion_total",
			Help:      "TOTP enrollment verify outcomes (`ok`, `invalid_code`, `replayed`, `secret_failed`).",
		},
		[]string{"result"},
	)
	totpChallengeTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ovumcy",
			Subsystem: "sync_community",
			Name:      "totp_challenge_completion_total",
			Help:      "TOTP login challenge outcomes (`ok`, `invalid_code`, `replayed`, `challenge_invalid`, `burnt`, `secret_failed`).",
		},
		[]string{"result"},
	)

	registry.MustRegister(
		collectors.NewGoCollector(),
		inFlight,
		requestTotal,
		requestDuration,
		totpEnrollmentTotal,
		totpChallengeTotal,
	)

	return &Metrics{
		registry:            registry,
		inFlight:            inFlight,
		requestTotal:        requestTotal,
		requestDuration:     requestDuration,
		totpEnrollmentTotal: totpEnrollmentTotal,
		totpChallengeTotal:  totpChallengeTotal,
	}
}

// ObserveTOTPEnrollmentCompletion records the outcome of a single
// `POST /auth/totp/verify` call. `result` must be one of: `ok`,
// `invalid_code`, `replayed`, `secret_failed`. Any other value is
// recorded under the literal label, which surfaces label leakage as a
// visible metrics anomaly rather than silently dropping the sample.
func (m *Metrics) ObserveTOTPEnrollmentCompletion(result string) {
	if m == nil {
		return
	}
	m.totpEnrollmentTotal.WithLabelValues(result).Inc()
}

// ObserveTOTPChallengeCompletion records the outcome of a single
// `POST /auth/totp/challenge` call. `result` must be one of: `ok`,
// `invalid_code`, `replayed`, `challenge_invalid`, `burnt`,
// `secret_failed`. The `burnt` label fires when the per-challenge
// attempt counter crossed `maxTOTPChallengeFailedAttempts` and the
// challenge id was destroyed — this is the alerting signal for an
// online brute-force attempt.
func (m *Metrics) ObserveTOTPChallengeCompletion(result string) {
	if m == nil {
		return
	}
	m.totpChallengeTotal.WithLabelValues(result).Inc()
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

func (m *Metrics) Instrument(route string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		m.inFlight.Inc()
		defer m.inFlight.Dec()

		start := time.Now()
		recorder := &statusCapturingResponseWriter{
			ResponseWriter: writer,
			status:         http.StatusOK,
		}

		next.ServeHTTP(recorder, request)

		code := strconv.Itoa(recorder.status)
		m.requestTotal.WithLabelValues(route, request.Method, code).Inc()
		m.requestDuration.WithLabelValues(route, request.Method, code).Observe(time.Since(start).Seconds())
	})
}

type statusCapturingResponseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusCapturingResponseWriter) WriteHeader(status int) {
	if !w.wroteHeader {
		w.status = status
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusCapturingResponseWriter) Write(payload []byte) (int, error) {
	if !w.wroteHeader {
		w.status = http.StatusOK
		w.wroteHeader = true
	}

	return w.ResponseWriter.Write(payload)
}
