package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/security"
)

func TestChangePasswordEndpointRequiresTOTPCodeWhenEnrolled(t *testing.T) {
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

	const newPassword = "new staple battery horse correct"
	missing := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/change-password",
		map[string]string{"current_password": totpTestPassword, "new_password": newPassword},
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
		"/auth/change-password",
		map[string]string{
			"current_password": totpTestPassword,
			"new_password":     newPassword,
			"code":             security.GenerateTOTPCode(secret, enrollStep+1),
		},
		token,
		http.StatusOK,
	)
	var changed map[string]string
	decodeResponse(t, ok.Body.Bytes(), &changed)
	if changed["status"] != "password_changed" || changed["recovery_code"] == "" {
		t.Fatalf("expected password_changed with a new recovery code, got %#v", changed)
	}
}
