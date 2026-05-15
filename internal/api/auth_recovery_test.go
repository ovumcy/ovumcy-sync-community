package api

import (
	"net/http"
	"testing"
)

type registerPayload struct {
	AccountID    string `json:"account_id"`
	SessionToken string `json:"session_token"`
	RecoveryCode string `json:"recovery_code"`
}

type forgotPayload struct {
	ResetToken          string `json:"reset_token"`
	ResetTokenExpiresAt string `json:"reset_token_expires_at"`
}

type resetPayload struct {
	RecoveryCode string `json:"recovery_code"`
}

func registerOwner(t *testing.T, handler http.Handler) registerPayload {
	t.Helper()

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/register",
		map[string]string{
			"login":    "owner@example.com",
			"password": "correct horse battery staple",
		},
		"",
		http.StatusCreated,
	)

	var payload registerPayload
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload.RecoveryCode == "" {
		t.Fatal("expected register response to include recovery_code")
	}
	return payload
}

func TestRegisterEndpointReturnsRecoveryCode(t *testing.T) {
	handler := newTestServer(t)
	_ = registerOwner(t, handler)
}

func TestForgotPasswordResetEndToEnd(t *testing.T) {
	handler := newTestServer(t)
	registered := registerOwner(t, handler)

	forgotResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/forgot-password",
		map[string]string{
			"login":         "owner@example.com",
			"recovery_code": registered.RecoveryCode,
		},
		"",
		http.StatusOK,
	)
	var forgot forgotPayload
	decodeResponse(t, forgotResponse.Body.Bytes(), &forgot)
	if forgot.ResetToken == "" {
		t.Fatal("expected reset token")
	}

	resetResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/reset-password",
		map[string]string{
			"reset_token":  forgot.ResetToken,
			"new_password": "another secure password!",
		},
		"",
		http.StatusOK,
	)
	var reset resetPayload
	decodeResponse(t, resetResponse.Body.Bytes(), &reset)
	if reset.RecoveryCode == "" || reset.RecoveryCode == registered.RecoveryCode {
		t.Fatalf("expected new recovery code, got %q (was %q)", reset.RecoveryCode, registered.RecoveryCode)
	}

	performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/sync/capabilities",
		nil,
		registered.SessionToken,
		http.StatusUnauthorized,
	)

	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/login",
		map[string]string{
			"login":    "owner@example.com",
			"password": "correct horse battery staple",
		},
		"",
		http.StatusUnauthorized,
	)

	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/login",
		map[string]string{
			"login":    "owner@example.com",
			"password": "another secure password!",
		},
		"",
		http.StatusOK,
	)
}

func TestForgotPasswordEndpointGenericErrorForUnknownLogin(t *testing.T) {
	handler := newTestServer(t)

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/forgot-password",
		map[string]string{
			"login":         "ghost@example.com",
			"recovery_code": "deadbeefdeadbeefdeadbeefdeadbeef",
		},
		"",
		http.StatusUnauthorized,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "invalid_recovery_credentials" {
		t.Fatalf("unexpected error key: %#v", payload)
	}
}

func TestForgotPasswordEndpointGenericErrorForWrongCode(t *testing.T) {
	handler := newTestServer(t)
	registerOwner(t, handler)

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/forgot-password",
		map[string]string{
			"login":         "owner@example.com",
			"recovery_code": "00000000000000000000000000000000",
		},
		"",
		http.StatusUnauthorized,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "invalid_recovery_credentials" {
		t.Fatalf("unexpected error key: %#v", payload)
	}
}

func TestResetPasswordEndpointRejectsInvalidToken(t *testing.T) {
	handler := newTestServer(t)

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/reset-password",
		map[string]string{
			"reset_token":  "bogus-token",
			"new_password": "another secure password!",
		},
		"",
		http.StatusUnauthorized,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "invalid_reset_token" {
		t.Fatalf("unexpected error key: %#v", payload)
	}
}

func TestResetPasswordEndpointRejectsWeakNew(t *testing.T) {
	handler := newTestServer(t)
	registered := registerOwner(t, handler)

	forgotResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/forgot-password",
		map[string]string{
			"login":         "owner@example.com",
			"recovery_code": registered.RecoveryCode,
		},
		"",
		http.StatusOK,
	)
	var forgot forgotPayload
	decodeResponse(t, forgotResponse.Body.Bytes(), &forgot)

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/reset-password",
		map[string]string{
			"reset_token":  forgot.ResetToken,
			"new_password": "short",
		},
		"",
		http.StatusBadRequest,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "weak_new_password" {
		t.Fatalf("unexpected error key: %#v", payload)
	}
}

func TestRegenerateRecoveryCodeEndpointSucceeds(t *testing.T) {
	handler := newTestServer(t)
	registered := registerOwner(t, handler)

	regenerateResponse := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/recovery-code/regenerate",
		map[string]string{
			"current_password": "correct horse battery staple",
		},
		registered.SessionToken,
		http.StatusOK,
	)

	var regenerate resetPayload
	decodeResponse(t, regenerateResponse.Body.Bytes(), &regenerate)
	if regenerate.RecoveryCode == "" || regenerate.RecoveryCode == registered.RecoveryCode {
		t.Fatalf("expected new recovery code, got %q (was %q)", regenerate.RecoveryCode, registered.RecoveryCode)
	}

	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/forgot-password",
		map[string]string{
			"login":         "owner@example.com",
			"recovery_code": registered.RecoveryCode,
		},
		"",
		http.StatusUnauthorized,
	)
	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/forgot-password",
		map[string]string{
			"login":         "owner@example.com",
			"recovery_code": regenerate.RecoveryCode,
		},
		"",
		http.StatusOK,
	)
}

func TestRegenerateRecoveryCodeEndpointRejectsWrongPassword(t *testing.T) {
	handler := newTestServer(t)
	registered := registerOwner(t, handler)

	response := performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/recovery-code/regenerate",
		map[string]string{
			"current_password": "wrong password",
		},
		registered.SessionToken,
		http.StatusUnauthorized,
	)

	var payload map[string]string
	decodeResponse(t, response.Body.Bytes(), &payload)
	if payload["error"] != "invalid_current_password" {
		t.Fatalf("unexpected error key: %#v", payload)
	}
}

func TestRegenerateRecoveryCodeEndpointRequiresAuth(t *testing.T) {
	handler := newTestServer(t)

	performJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/auth/recovery-code/regenerate",
		map[string]string{
			"current_password": "correct horse battery staple",
		},
		"",
		http.StatusUnauthorized,
	)
}
