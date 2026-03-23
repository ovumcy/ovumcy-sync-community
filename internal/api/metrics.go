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
	registry        *prometheus.Registry
	inFlight        prometheus.Gauge
	requestTotal    *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
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

	registry.MustRegister(
		collectors.NewGoCollector(),
		inFlight,
		requestTotal,
		requestDuration,
	)

	return &Metrics{
		registry:        registry,
		inFlight:        inFlight,
		requestTotal:    requestTotal,
		requestDuration: requestDuration,
	}
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
