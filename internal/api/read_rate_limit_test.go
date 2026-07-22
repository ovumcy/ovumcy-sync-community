package api

import (
	"net/http"
	"testing"
)

// TestSyncReadEndpointsAreRateLimitedPerAccount pins that GET /sync/blob and
// GET /sync/recovery-key pass the same per-account limiter as their PUT
// counterparts: with a one-request budget the second read answers 429 with a
// Retry-After header, instead of letting a valid session drive unmetered
// MAX_BLOB_BYTES-sized reads past the per-IP auth gate.
func TestSyncReadEndpointsAreRateLimitedPerAccount(t *testing.T) {
	for _, path := range []string{"/sync/blob", "/sync/recovery-key"} {
		t.Run(path, func(t *testing.T) {
			handler := newTestServerWithOptions(t, serverTestOptions{authRateLimitCount: 1})
			registered := registerOwner(t, handler)

			// The budget's single slot. A 404 is expected — nothing is
			// stored yet — the point is that the read consumed the limiter.
			performJSONRequest(
				t,
				handler,
				http.MethodGet,
				path,
				nil,
				registered.SessionToken,
				http.StatusNotFound,
			)

			response := performJSONRequest(
				t,
				handler,
				http.MethodGet,
				path,
				nil,
				registered.SessionToken,
				http.StatusTooManyRequests,
			)

			var payload map[string]string
			decodeResponse(t, response.Body.Bytes(), &payload)
			if payload["error"] != "rate_limited" {
				t.Fatalf("unexpected rate limit payload: %#v", payload)
			}
			if response.Header().Get("Retry-After") == "" {
				t.Fatal("expected a Retry-After header on the throttled read")
			}
		})
	}
}
