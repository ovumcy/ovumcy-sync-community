package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/services"
)

// The step-up writes answer through mapTOTPError; its unauthorized branch
// covers a session revoked between withAuth and the store write, a race HTTP
// tests cannot schedule.
func TestMapTOTPErrorStepUpRefusals(t *testing.T) {
	for _, tc := range []struct {
		err        error
		wantStatus int
		wantKey    string
	}{
		{services.ErrInvalidCurrentPassword, http.StatusUnauthorized, "invalid_current_password"},
		{services.ErrUnauthorized, http.StatusUnauthorized, "unauthorized"},
		{services.ErrTOTPInvalidCode, http.StatusUnauthorized, "totp_invalid_code"},
		{services.ErrTOTPReplayed, http.StatusUnauthorized, "totp_replayed"},
		{services.ErrTOTPNotConfigured, http.StatusServiceUnavailable, "totp_not_configured"},
		{services.ErrTOTPNotEnabled, http.StatusConflict, "totp_not_enabled"},
		{services.ErrTOTPEnrollmentNotStarted, http.StatusConflict, "totp_enrollment_not_started"},
		{services.ErrTOTPEnrollmentDiscarded, http.StatusConflict, "totp_enrollment_discarded"},
		{errors.New("boom"), http.StatusInternalServerError, "internal_error"},
	} {
		recorder := httptest.NewRecorder()
		mapTOTPError(recorder, tc.err)

		var body map[string]string
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if recorder.Code != tc.wantStatus || body["error"] != tc.wantKey {
			t.Fatalf("%v: got %d %q, want %d %q", tc.err, recorder.Code, body["error"], tc.wantStatus, tc.wantKey)
		}
	}
}

// Only a spent rolling budget answers 429 with Retry-After; a pending secret
// discarded at its lifetime cap is an account state no wait changes.
func TestMapTOTPErrorSeparatesDiscardedEnrollmentFromRateLimit(t *testing.T) {
	discarded := httptest.NewRecorder()
	mapTOTPError(discarded, services.ErrTOTPEnrollmentDiscarded)
	if discarded.Code != http.StatusConflict || discarded.Header().Get("Retry-After") != "" {
		t.Fatalf("discarded enrollment: got %d with Retry-After %q", discarded.Code, discarded.Header().Get("Retry-After"))
	}

	locked := httptest.NewRecorder()
	mapTOTPError(locked, &services.TOTPLockedError{RetryAfter: 90 * time.Second})
	var body map[string]string
	if err := json.Unmarshal(locked.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if locked.Code != http.StatusTooManyRequests || body["error"] != "rate_limited" || locked.Header().Get("Retry-After") != "90" {
		t.Fatalf("spent budget: got %d %q with Retry-After %q", locked.Code, body["error"], locked.Header().Get("Retry-After"))
	}
}
