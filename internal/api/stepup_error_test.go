package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ovumcy/ovumcy-sync-community/internal/services"
)

// writeStepUpError's unauthorized branch answers a session revoked between
// withAuth and the store write, a race HTTP tests cannot schedule.
func TestWriteStepUpError(t *testing.T) {
	for _, tc := range []struct {
		err        error
		wantStatus int
		wantKey    string
	}{
		{services.ErrInvalidCurrentPassword, http.StatusUnauthorized, "invalid_current_password"},
		{services.ErrUnauthorized, http.StatusUnauthorized, "unauthorized"},
		{errors.New("boom"), http.StatusInternalServerError, "internal_error"},
	} {
		recorder := httptest.NewRecorder()
		writeStepUpError(recorder, tc.err)

		var body map[string]string
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if recorder.Code != tc.wantStatus || body["error"] != tc.wantKey {
			t.Fatalf("%v: got %d %q, want %d %q", tc.err, recorder.Code, body["error"], tc.wantStatus, tc.wantKey)
		}
	}
}
