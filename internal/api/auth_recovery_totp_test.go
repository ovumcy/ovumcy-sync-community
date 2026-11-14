package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

func TestRegenerateRecoveryCodeEndpointRequiresTOTPCodeWhenEnrolled(t *testing.T) {
	handler := newTestServerWithOptions(t, serverTestOptions{enableTOTP: true})
	token := registerOwnerWithTOTP(t, handler)

	enrollResp := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/enroll",
		map[string]string{"current_password": totpTestPassword},
		token,
		http.StatusOK,
	)
	var enrollBody struct {
		SecretBase32 string `json:"secret_base32"`
	}
	decodeResponse(t, enrollResp.Body.Bytes(), &enrollBody)
	secret, err := security.DecodeTOTPSecretBase32(enrollBody.SecretBase32)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	enrollStep := time.Now().Unix() / security.TOTPStepSeconds
	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/totp/verify",
		map[string]string{"code": security.GenerateTOTPCode(secret, enrollStep)},
		token,
		http.StatusOK,
	)

	missing := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/recovery-code/regenerate",
		map[string]string{"current_password": totpTestPassword},
		token,
		http.StatusUnauthorized,
	)
	var body map[string]string
	decodeResponse(t, missing.Body.Bytes(), &body)
	if body["error"] != "totp_invalid_code" {
		t.Fatalf("expected totp_invalid_code, got %#v", body)
	}

	ok := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/recovery-code/regenerate",
		map[string]string{
			"current_password": totpTestPassword,
			"code":             security.GenerateTOTPCode(secret, enrollStep+1),
		},
		token,
		http.StatusOK,
	)
	var regenerate struct {
		RecoveryCode string `json:"recovery_code"`
	}
	decodeResponse(t, ok.Body.Bytes(), &regenerate)
	if regenerate.RecoveryCode == "" {
		t.Fatal("expected a new recovery code")
	}
}
