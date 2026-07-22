package api

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/config"
	"github.com/ovumcy/ovumcy-sync-community/internal/models"
	"github.com/ovumcy/ovumcy-sync-community/internal/security"
	"github.com/ovumcy/ovumcy-sync-community/internal/services"
)

type Server struct {
	auth                *services.AuthService
	sync                *services.SyncService
	managedBridge       *services.ManagedBridgeService
	totp                *services.TOTPService
	managedBridgeToken  string
	metrics             *Metrics
	metricsBearerToken  string
	authLimiter         *security.RateLimiter
	allowedOrigins      map[string]struct{}
	trustedProxyCIDRs   []netip.Prefix
	maxBlobRequestBytes int64
	readinessCheck      func(context.Context) error
	mux                 *http.ServeMux
}

type ServerOptions struct {
	ManagedBridgeToken  string
	MetricsEnabled      bool
	MetricsBearerToken  string
	AllowedOrigins      []string
	AuthRateLimitCount  int
	AuthRateLimitWindow time.Duration
	MaxBlobBytes        int
	ReadinessCheck      func(context.Context) error
	TrustedProxyCIDRs   []string
}

func NewServer(
	auth *services.AuthService,
	sync *services.SyncService,
	managedBridge *services.ManagedBridgeService,
	totp *services.TOTPService,
	options ServerOptions,
) http.Handler {
	originSet := make(map[string]struct{}, len(options.AllowedOrigins))
	for _, origin := range options.AllowedOrigins {
		trimmed := strings.TrimSpace(origin)
		if trimmed == "" {
			continue
		}
		originSet[trimmed] = struct{}{}
	}

	var metrics *Metrics
	if options.MetricsEnabled {
		metrics = NewMetrics()
	}

	server := &Server{
		auth:                auth,
		sync:                sync,
		managedBridge:       managedBridge,
		totp:                totp,
		managedBridgeToken:  strings.TrimSpace(options.ManagedBridgeToken),
		metrics:             metrics,
		metricsBearerToken:  strings.TrimSpace(options.MetricsBearerToken),
		authLimiter:         security.NewRateLimiter(options.AuthRateLimitCount, options.AuthRateLimitWindow),
		allowedOrigins:      originSet,
		trustedProxyCIDRs:   parseTrustedProxyCIDRs(options.TrustedProxyCIDRs),
		maxBlobRequestBytes: encodedBlobRequestLimit(options.MaxBlobBytes),
		readinessCheck:      options.ReadinessCheck,
		mux:                 http.NewServeMux(),
	}
	// Wire the domain-level TOTP metrics observer onto the service. The
	// service ignores nil observers, so disabling metrics simply skips the
	// extra counters.
	if totp != nil && metrics != nil {
		totp.AttachMetricsObserver(metrics)
	}
	server.routes()
	return server
}

func (s *Server) routes() {
	s.handleRoute("GET /healthz", "healthz", http.HandlerFunc(s.handleHealth))
	s.handleRoute("GET /readyz", "readyz", http.HandlerFunc(s.handleReady))
	s.handleRoute("GET /metrics", "", http.HandlerFunc(s.handleMetrics))
	s.handleRoute("POST /auth/register", "auth_register", http.HandlerFunc(s.handleRegister))
	s.handleRoute("POST /auth/login", "auth_login", http.HandlerFunc(s.handleLogin))
	s.handleRoute("POST /auth/change-password", "auth_change_password", s.withAuth(s.handleChangePassword))
	s.handleRoute("POST /auth/forgot-password", "auth_forgot_password", http.HandlerFunc(s.handleForgotPassword))
	s.handleRoute("POST /auth/reset-password", "auth_reset_password", http.HandlerFunc(s.handleResetPassword))
	s.handleRoute("POST /auth/recovery-code/regenerate", "auth_recovery_code_regenerate", s.withAuth(s.handleRegenerateRecoveryCode))
	s.handleRoute("POST /auth/totp/enroll", "auth_totp_enroll", s.withAuth(s.handleTOTPEnroll))
	s.handleRoute("POST /auth/totp/verify", "auth_totp_verify", s.withAuth(s.handleTOTPVerifyEnrollment))
	s.handleRoute("POST /auth/totp/disable", "auth_totp_disable", s.withAuth(s.handleTOTPDisable))
	s.handleRoute("POST /auth/totp/challenge", "auth_totp_challenge", http.HandlerFunc(s.handleTOTPChallenge))
	s.handleRoute("GET /auth/session", "auth_session", s.withAuth(s.handleCurrentSession))
	s.handleRoute("DELETE /auth/session", "auth_logout", http.HandlerFunc(s.handleLogout))
	s.handleRoute("DELETE /account", "account_delete", s.withAuth(s.handleDeleteAccount))
	s.handleRoute("POST /managed/session", "managed_session", s.withManagedBridge(s.handleManagedSession))
	s.handleRoute("DELETE /managed/accounts/{account_id}", "managed_account_purge", s.withManagedBridge(s.handleManagedAccountPurge))
	s.handleRoute("POST /managed/accounts/{account_id}/premium", "managed_account_premium", s.withManagedBridge(s.handleManagedAccountPremium))
	s.handleRoute("GET /sync/capabilities", "sync_capabilities", s.withAuth(s.handleCapabilities))
	s.handleRoute("POST /sync/devices", "sync_devices", s.withAuth(s.handleAttachDevice))
	s.handleRoute("GET /sync/devices", "sync_devices_list", s.withAuth(s.handleListDevices))
	s.handleRoute("DELETE /sync/devices/{device_id}", "sync_devices_remove", s.withAuth(s.handleRemoveDevice))
	s.handleRoute("GET /sync/recovery-key", "sync_recovery_key_get", s.withAuth(s.handleGetRecoveryKey))
	s.handleRoute("PUT /sync/recovery-key", "sync_recovery_key_put", s.withAuth(s.handlePutRecoveryKey))
	s.handleRoute("GET /sync/blob", "sync_blob_get", s.withAuth(s.handleGetBlob))
	s.handleRoute("PUT /sync/blob", "sync_blob_put", s.withAuth(s.handlePutBlob))
}

func (s *Server) handleRoute(pattern string, metricsRoute string, handler http.Handler) {
	if s.metrics != nil && metricsRoute != "" {
		handler = s.metrics.Instrument(metricsRoute, handler)
	}

	s.mux.Handle(pattern, handler)
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	writer.Header().Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=(), usb=()")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	writer.Header().Set("X-Frame-Options", "DENY")
	writer.Header().Set("X-Content-Type-Options", "nosniff")

	if origin := request.Header.Get("Origin"); origin != "" {
		writer.Header().Add("Vary", "Origin")
		if _, ok := s.allowedOrigins[origin]; ok {
			writer.Header().Set("Access-Control-Allow-Origin", origin)
			writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		} else if request.Method == http.MethodOptions {
			writeError(writer, http.StatusForbidden, "origin_not_allowed")
			return
		}
	}

	if request.Method == http.MethodOptions {
		writer.WriteHeader(http.StatusNoContent)
		return
	}
	serveWithPanicRecovery(writer, request, s.mux)
}

// recoveryWriter tracks whether a response has begun so the panic recovery only
// writes a 500 when the handler has not already started writing.
type recoveryWriter struct {
	http.ResponseWriter
	wrote bool
}

func (w *recoveryWriter) WriteHeader(code int) {
	w.wrote = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *recoveryWriter) Write(b []byte) (int, error) {
	w.wrote = true
	return w.ResponseWriter.Write(b)
}

// serveWithPanicRecovery runs next and converts a handler panic into a clean
// 500 instead of net/http's default (which drops the connection and logs an
// unbounded stack trace to stderr). The recovery log line is deliberately
// secret-free — method and path only, never the body, headers, or query — so
// it stays inside the zero-knowledge no-secret-in-logs contract.
func serveWithPanicRecovery(writer http.ResponseWriter, request *http.Request, next http.Handler) {
	rw := &recoveryWriter{ResponseWriter: writer}
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("recovered panic serving %s %s: %v", sanitizeLogValue(request.Method), sanitizeLogValue(request.URL.Path), rec)
			if !rw.wrote {
				writeError(rw, http.StatusInternalServerError, "internal_error")
			}
		}
	}()

	next.ServeHTTP(rw, request)
}

// sanitizeLogValue strips CR and LF from a request-derived value (method,
// path) before it reaches a log call, so a caller cannot inject line breaks to
// forge or split log entries (CWE-117 log injection).
func sanitizeLogValue(value string) string {
	value = strings.ReplaceAll(value, "\n", "")
	value = strings.ReplaceAll(value, "\r", "")
	return value
}

func (s *Server) handleHealth(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReady(writer http.ResponseWriter, request *http.Request) {
	if s.readinessCheck != nil {
		if err := s.readinessCheck(request.Context()); err != nil {
			writeError(writer, http.StatusServiceUnavailable, "not_ready")
			return
		}
	}

	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleMetrics(writer http.ResponseWriter, request *http.Request) {
	if s.metrics == nil {
		writeError(writer, http.StatusNotFound, "not_found")
		return
	}

	if s.metricsBearerToken != "" {
		token := bearerTokenFromRequest(request)
		if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.metricsBearerToken)) != 1 {
			writeError(writer, http.StatusUnauthorized, "unauthorized")
			return
		}
	}

	s.metrics.Handler().ServeHTTP(writer, request)
}

func (s *Server) handleRegister(writer http.ResponseWriter, request *http.Request) {
	if !s.allowAuthRequest(writer, request) {
		return
	}

	var payload credentialsRequest
	if !decodeJSON(writer, request, &payload, 4<<10) {
		return
	}

	result, err := s.auth.Register(request.Context(), payload.Login, payload.Password)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidRegistrationInput):
			writeError(writer, http.StatusBadRequest, "invalid_registration_input")
		case errors.Is(err, services.ErrRegistrationFailed):
			writeError(writer, http.StatusBadRequest, "registration_failed")
		default:
			writeError(writer, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	writeJSON(writer, http.StatusCreated, result)
}

func (s *Server) handleLogin(writer http.ResponseWriter, request *http.Request) {
	if !s.allowAuthRequest(writer, request) {
		return
	}

	var payload credentialsRequest
	if !decodeJSON(writer, request, &payload, 4<<10) {
		return
	}

	// Per-identifier ceiling layered on top of per-IP. The per-IP limit
	// alone is bypassable by a distributed attacker (bot-net) brute-forcing
	// one victim's password / 2FA across many source IPs. Keying the
	// secondary bucket on the normalized login string forces all those IPs
	// to share one quota for that identifier, capping practical brute
	// throughput against a single account. Trade-off: an attacker can lock
	// out a known victim's login by spamming bad credentials; rate-limit
	// burns out on its own window, and recovery-code is the unblock path.
	if !s.allowLoginRequestForIdentifier(writer, request, payload.Login) {
		return
	}

	result, err := s.auth.Login(request.Context(), payload.Login, payload.Password)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidCredentials):
			writeError(writer, http.StatusUnauthorized, "invalid_credentials")
		case errors.Is(err, services.ErrTOTPNotConfigured):
			// An enrolled 2FA account on a server whose field encryption key is
			// no longer configured: fail closed instead of issuing a
			// password-only session. Mirrors the 503 the TOTP endpoints return.
			writeError(writer, http.StatusServiceUnavailable, "totp_not_configured")
		default:
			writeError(writer, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) handleChangePassword(
	writer http.ResponseWriter,
	request *http.Request,
	account models.Account,
) {
	if !s.allowAuthRequestForAccount(writer, request, account.ID) {
		return
	}

	var payload changePasswordRequest
	if !decodeJSON(writer, request, &payload, 4<<10) {
		return
	}

	currentSessionTokenHash := security.HashToken(bearerTokenFromRequest(request))

	err := s.auth.ChangePassword(
		request.Context(),
		account.ID,
		currentSessionTokenHash,
		payload.CurrentPassword,
		payload.NewPassword,
	)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidCurrentPassword):
			writeError(writer, http.StatusUnauthorized, "invalid_current_password")
		case errors.Is(err, services.ErrNewPasswordMustDiffer):
			writeError(writer, http.StatusBadRequest, "new_password_must_differ")
		case errors.Is(err, services.ErrWeakNewPassword):
			writeError(writer, http.StatusBadRequest, "weak_new_password")
		case errors.Is(err, services.ErrUnauthorized):
			writeError(writer, http.StatusUnauthorized, "unauthorized")
		default:
			writeError(writer, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	writeJSON(writer, http.StatusOK, map[string]string{"status": "password_changed"})
}

func (s *Server) handleForgotPassword(writer http.ResponseWriter, request *http.Request) {
	if !s.allowAuthRequest(writer, request) {
		return
	}

	var payload forgotPasswordRequest
	if !decodeJSON(writer, request, &payload, 4<<10) {
		return
	}

	result, err := s.auth.ForgotPassword(request.Context(), payload.Login, payload.RecoveryCode)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidRecoveryCredentials):
			writeError(writer, http.StatusUnauthorized, "invalid_recovery_credentials")
		default:
			writeError(writer, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) handleResetPassword(writer http.ResponseWriter, request *http.Request) {
	if !s.allowAuthRequest(writer, request) {
		return
	}

	var payload resetPasswordRequest
	if !decodeJSON(writer, request, &payload, 4<<10) {
		return
	}

	result, err := s.auth.ResetPassword(request.Context(), payload.ResetToken, payload.NewPassword)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidResetToken):
			writeError(writer, http.StatusUnauthorized, "invalid_reset_token")
		case errors.Is(err, services.ErrWeakNewPassword):
			writeError(writer, http.StatusBadRequest, "weak_new_password")
		default:
			writeError(writer, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) handleRegenerateRecoveryCode(
	writer http.ResponseWriter,
	request *http.Request,
	account models.Account,
) {
	if !s.allowAuthRequestForAccount(writer, request, account.ID) {
		return
	}

	var payload regenerateRecoveryCodeRequest
	if !decodeJSON(writer, request, &payload, 4<<10) {
		return
	}

	recoveryCode, err := s.auth.RegenerateRecoveryCode(request.Context(), account.ID, payload.CurrentPassword)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidCurrentPassword):
			writeError(writer, http.StatusUnauthorized, "invalid_current_password")
		case errors.Is(err, services.ErrUnauthorized):
			writeError(writer, http.StatusUnauthorized, "unauthorized")
		default:
			writeError(writer, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	writeJSON(writer, http.StatusOK, map[string]string{"recovery_code": recoveryCode})
}

func (s *Server) handleTOTPEnroll(
	writer http.ResponseWriter,
	request *http.Request,
	account models.Account,
) {
	if s.totp == nil {
		writeError(writer, http.StatusServiceUnavailable, "totp_not_configured")
		return
	}
	if !s.allowAuthRequestForAccount(writer, request, account.ID) {
		return
	}

	var payload totpEnrollRequest
	if !decodeJSON(writer, request, &payload, 4<<10) {
		return
	}

	result, err := s.totp.StartEnrollment(request.Context(), account.ID, payload.CurrentPassword)
	if err != nil {
		mapTOTPError(writer, err)
		return
	}

	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) handleTOTPVerifyEnrollment(
	writer http.ResponseWriter,
	request *http.Request,
	account models.Account,
) {
	if s.totp == nil {
		writeError(writer, http.StatusServiceUnavailable, "totp_not_configured")
		return
	}
	if !s.allowAuthRequestForAccount(writer, request, account.ID) {
		return
	}

	var payload totpVerifyRequest
	if !decodeJSON(writer, request, &payload, 4<<10) {
		return
	}

	currentSessionTokenHash := security.HashToken(bearerTokenFromRequest(request))

	if err := s.totp.CompleteEnrollment(
		request.Context(),
		account.ID,
		currentSessionTokenHash,
		payload.Code,
	); err != nil {
		mapTOTPError(writer, err)
		return
	}

	writeJSON(writer, http.StatusOK, map[string]string{"status": "totp_enabled"})
}

func (s *Server) handleTOTPDisable(
	writer http.ResponseWriter,
	request *http.Request,
	account models.Account,
) {
	if s.totp == nil {
		writeError(writer, http.StatusServiceUnavailable, "totp_not_configured")
		return
	}
	if !s.allowAuthRequestForAccount(writer, request, account.ID) {
		return
	}

	var payload totpDisableRequest
	if !decodeJSON(writer, request, &payload, 4<<10) {
		return
	}

	if err := s.totp.Disable(
		request.Context(),
		account.ID,
		payload.CurrentPassword,
		payload.Code,
	); err != nil {
		mapTOTPError(writer, err)
		return
	}

	writeJSON(writer, http.StatusOK, map[string]string{"status": "totp_disabled"})
}

func (s *Server) handleTOTPChallenge(writer http.ResponseWriter, request *http.Request) {
	if s.totp == nil {
		writeError(writer, http.StatusServiceUnavailable, "totp_not_configured")
		return
	}
	if !s.allowAuthRequest(writer, request) {
		return
	}

	var payload totpChallengeRequest
	if !decodeJSON(writer, request, &payload, 4<<10) {
		return
	}

	result, err := s.totp.VerifyChallenge(request.Context(), payload.ChallengeID, payload.Code)
	if err != nil {
		mapTOTPError(writer, err)
		return
	}

	writeJSON(writer, http.StatusOK, result)
}

func mapTOTPError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, services.ErrTOTPNotConfigured):
		writeError(writer, http.StatusServiceUnavailable, "totp_not_configured")
	case errors.Is(err, services.ErrTOTPAlreadyEnabled):
		writeError(writer, http.StatusConflict, "totp_already_enabled")
	case errors.Is(err, services.ErrInvalidCurrentPassword):
		writeError(writer, http.StatusUnauthorized, "invalid_current_password")
	case errors.Is(err, services.ErrTOTPInvalidCode):
		writeError(writer, http.StatusUnauthorized, "totp_invalid_code")
	case errors.Is(err, services.ErrTOTPReplayed):
		writeError(writer, http.StatusUnauthorized, "totp_replayed")
	case errors.Is(err, services.ErrTOTPChallengeInvalid):
		writeError(writer, http.StatusUnauthorized, "totp_challenge_invalid")
	case errors.Is(err, services.ErrTOTPSecretEncrypt),
		errors.Is(err, services.ErrTOTPSecretDecrypt):
		writeError(writer, http.StatusInternalServerError, "totp_secret_failed")
	case errors.Is(err, services.ErrUnauthorized):
		writeError(writer, http.StatusUnauthorized, "unauthorized")
	default:
		writeError(writer, http.StatusInternalServerError, "internal_error")
	}
}

func (s *Server) handleLogout(writer http.ResponseWriter, request *http.Request) {
	if err := s.auth.RevokeSession(request.Context(), bearerTokenFromRequest(request)); err != nil {
		writeError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}

	writeJSON(writer, http.StatusOK, map[string]string{"status": "revoked"})
}

// handleDeleteAccount implements DELETE /account: permanent, authenticated
// self-service account erasure (Google Play data-deletion compliance and
// general privacy hygiene).
//
// account is derived exclusively from the authenticated session via
// s.withAuth — there is no request field the caller can use to name a
// different account, so one session can never erase another account's data.
// The service call is idempotent, so a retried request (e.g. a client that
// did not see the first 200 due to a dropped connection) still reports
// success instead of surfacing an error for an account that is already gone.
func (s *Server) handleDeleteAccount(
	writer http.ResponseWriter,
	request *http.Request,
	account models.Account,
) {
	if !s.allowAuthRequestForAccount(writer, request, account.ID) {
		return
	}

	if err := s.auth.DeleteAccount(request.Context(), account.ID); err != nil {
		writeError(writer, http.StatusInternalServerError, "internal_error")
		return
	}

	writeJSON(writer, http.StatusOK, map[string]string{"status": "account_deleted"})
}

func (s *Server) handleManagedSession(writer http.ResponseWriter, request *http.Request) {
	var payload managedSessionRequest
	if !decodeJSON(writer, request, &payload, 4<<10) {
		return
	}

	result, err := s.managedBridge.CreateManagedSession(request.Context(), payload.AccountID)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidManagedAccount):
			writeError(writer, http.StatusBadRequest, "invalid_managed_account")
		default:
			writeError(writer, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	writeJSON(writer, http.StatusOK, result)
}

// handleManagedAccountPurge implements DELETE /managed/accounts/{account_id}:
// the machine-to-machine purge half of managed-cloud account deletion. It is
// gated by withManagedBridge (the same MANAGED_BRIDGE_TOKEN bearer as
// POST /managed/session) and relays the path id to the service, which owns
// normalization, the managed-mode guard, and idempotency — a repeat purge of
// an already-erased account reports success, so the managed caller can retry
// after a dropped response.
func (s *Server) handleManagedAccountPurge(writer http.ResponseWriter, request *http.Request) {
	err := s.managedBridge.PurgeManagedAccount(request.Context(), request.PathValue("account_id"))
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidManagedAccount):
			writeError(writer, http.StatusBadRequest, "invalid_managed_account")
		default:
			writeError(writer, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	writeJSON(writer, http.StatusOK, map[string]string{"status": "account_purged"})
}

// handleManagedAccountPremium implements POST /managed/accounts/{account_id}
// /premium: the entitlement-lapse signal half of the sync-side lapse-cleanup
// design documented in docs/self-hosting.md ("Entitlement-Lapse Cleanup")
// and SECURITY.md. It is gated by withManagedBridge — the same
// MANAGED_BRIDGE_TOKEN bearer as
// POST /managed/session and the account-purge endpoint — and relays the
// path id and the request body's active flag to
// ManagedBridgeService.SetAccountLapseSignal, which owns normalization, the
// managed-mode guard, idempotency, and (for active=false) the immediate
// session revocation. This is a lifecycle signal only: the request and
// response never carry anything beyond the account id and the boolean flag,
// so no health-adjacent content ever crosses the bridge.
func (s *Server) handleManagedAccountPremium(writer http.ResponseWriter, request *http.Request) {
	var payload managedAccountPremiumRequest
	if !decodeJSON(writer, request, &payload, 4<<10) {
		return
	}

	err := s.managedBridge.SetAccountLapseSignal(request.Context(), request.PathValue("account_id"), payload.Active)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidManagedAccount):
			writeError(writer, http.StatusBadRequest, "invalid_managed_account")
		default:
			writeError(writer, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	if payload.Active {
		writeJSON(writer, http.StatusOK, map[string]string{"status": "lapse_cleared"})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "lapse_recorded"})
}

func (s *Server) handleCapabilities(writer http.ResponseWriter, _ *http.Request, account models.Account) {
	writeJSON(writer, http.StatusOK, s.sync.CapabilitiesForAccount(account))
}

// accountSessionView is the GET /auth/session response: the minimal
// account-scoped state a client needs to show live status — notably whether
// TOTP two-factor is currently enabled — without inferring it from a login
// challenge.
type accountSessionView struct {
	AccountID   string `json:"account_id"`
	Login       string `json:"login"`
	TOTPEnabled bool   `json:"totp_enabled"`
}

func (s *Server) handleCurrentSession(writer http.ResponseWriter, _ *http.Request, account models.Account) {
	writeJSON(writer, http.StatusOK, accountSessionView{
		AccountID:   account.ID,
		Login:       account.Login,
		TOTPEnabled: account.TOTPEnabled,
	})
}

func (s *Server) handleAttachDevice(
	writer http.ResponseWriter,
	request *http.Request,
	account models.Account,
) {
	// Per-account ceiling: even though MaxDevices caps the row count inside
	// the UpsertDevice statement, unbounded attach attempts thrash that
	// insert and its count sub-select under contention.
	if !s.allowAuthRequestForAccount(writer, request, account.ID) {
		return
	}

	var payload deviceRequest
	if !decodeJSON(writer, request, &payload, 4<<10) {
		return
	}

	device, err := s.sync.AttachDevice(
		request.Context(),
		account.ID,
		payload.DeviceID,
		payload.DeviceLabel,
	)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidDevice):
			writeError(writer, http.StatusBadRequest, "invalid_device")
		case errors.Is(err, services.ErrTooManyDevices):
			writeError(writer, http.StatusConflict, "too_many_devices")
		default:
			writeError(writer, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	writeJSON(writer, http.StatusOK, device)
}

func (s *Server) handleListDevices(
	writer http.ResponseWriter,
	request *http.Request,
	account models.Account,
) {
	devices, err := s.sync.ListDevices(request.Context(), account.ID)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "internal_error")
		return
	}

	writeJSON(writer, http.StatusOK, deviceListResponse{Devices: devices})
}

func (s *Server) handleRemoveDevice(
	writer http.ResponseWriter,
	request *http.Request,
	account models.Account,
) {
	// Mutating account op — rate-limit like attach, keyed on a stable
	// route-scoped string (not the path, whose device_id segment varies).
	if !s.allowAuthRequestWithKey(writer, "sync_devices_remove:"+account.ID) {
		return
	}

	// device_id comes from the path; the delete is scoped to the authenticated
	// account in the query, so a caller can only remove its own devices.
	err := s.sync.RemoveDevice(request.Context(), account.ID, request.PathValue("device_id"))
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidDevice):
			writeError(writer, http.StatusBadRequest, "invalid_device")
		case errors.Is(err, services.ErrDeviceNotFound):
			writeError(writer, http.StatusNotFound, "device_not_found")
		default:
			writeError(writer, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	writeJSON(writer, http.StatusOK, map[string]string{"status": "removed"})
}

func (s *Server) handlePutBlob(
	writer http.ResponseWriter,
	request *http.Request,
	account models.Account,
) {
	// Per-account ceiling: each upload runs a base64 decode and SHA-256
	// over up to MaxBlobBytes (16 MB default) plus two DB queries. Without
	// a per-account limit, a captured session can flood CPU/IO regardless
	// of the per-IP gate.
	if !s.allowAuthRequestForAccount(writer, request, account.ID) {
		return
	}

	var payload blobPutRequest
	if !decodeJSON(writer, request, &payload, s.maxBlobRequestBytes) {
		return
	}

	ciphertext, err := base64.StdEncoding.DecodeString(payload.CiphertextBase64)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_ciphertext")
		return
	}

	blob, err := s.sync.PutBlob(request.Context(), account.ID, services.PutBlobInput{
		SchemaVersion:  payload.SchemaVersion,
		Generation:     payload.Generation,
		ChecksumSHA256: payload.ChecksumSHA256,
		Ciphertext:     ciphertext,
	})
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidBlob):
			writeError(writer, http.StatusBadRequest, "invalid_blob")
		case errors.Is(err, services.ErrStaleGeneration):
			writeError(writer, http.StatusConflict, "stale_generation")
		default:
			writeError(writer, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	writeJSON(writer, http.StatusOK, blobResponseFromModel(blob))
}

func (s *Server) handlePutRecoveryKey(
	writer http.ResponseWriter,
	request *http.Request,
	account models.Account,
) {
	// Per-account ceiling: single-row UPSERT per account, but unbounded
	// calls thrash DB writers under contention.
	if !s.allowAuthRequestForAccount(writer, request, account.ID) {
		return
	}

	var payload recoveryKeyPackageRequest
	if !decodeJSON(writer, request, &payload, 8<<10) {
		return
	}

	recoveryKeyPackage, err := s.sync.PutRecoveryKeyPackage(
		request.Context(),
		account.ID,
		services.PutRecoveryKeyPackageInput{
			Algorithm:            payload.Algorithm,
			KDF:                  payload.KDF,
			MnemonicWordCount:    payload.MnemonicWordCount,
			WrapNonceHex:         payload.WrapNonceHex,
			WrappedMasterKeyHex:  payload.WrappedMasterKeyHex,
			PhraseFingerprintHex: payload.PhraseFingerprintHex,
		},
	)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidRecoveryPackage):
			writeError(writer, http.StatusBadRequest, "invalid_recovery_package")
		default:
			writeError(writer, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	writeJSON(writer, http.StatusOK, recoveryKeyPackageResponseFromModel(recoveryKeyPackage))
}

func (s *Server) handleGetBlob(
	writer http.ResponseWriter,
	request *http.Request,
	account models.Account,
) {
	blob, err := s.sync.GetBlob(request.Context(), account.ID)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrBlobNotFound):
			writeError(writer, http.StatusNotFound, "blob_not_found")
		default:
			writeError(writer, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	writeJSON(writer, http.StatusOK, blobResponseFromModel(blob))
}

func (s *Server) handleGetRecoveryKey(
	writer http.ResponseWriter,
	request *http.Request,
	account models.Account,
) {
	recoveryKeyPackage, err := s.sync.GetRecoveryKeyPackage(request.Context(), account.ID)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrRecoveryPackageNotFound):
			writeError(writer, http.StatusNotFound, "recovery_package_not_found")
		default:
			writeError(writer, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	writeJSON(writer, http.StatusOK, recoveryKeyPackageResponseFromModel(recoveryKeyPackage))
}

func (s *Server) withAuth(next func(http.ResponseWriter, *http.Request, models.Account)) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		account, err := s.auth.Authenticate(request.Context(), bearerTokenFromRequest(request))
		if err != nil {
			writeError(writer, http.StatusUnauthorized, "unauthorized")
			return
		}

		next(writer, request, account)
	}
}

func (s *Server) withManagedBridge(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if s.managedBridgeToken == "" {
			writeError(writer, http.StatusServiceUnavailable, "managed_bridge_disabled")
			return
		}

		token := bearerTokenFromRequest(request)
		if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.managedBridgeToken)) != 1 {
			writeError(writer, http.StatusUnauthorized, "unauthorized")
			return
		}

		next(writer, request)
	}
}

func bearerTokenFromRequest(request *http.Request) string {
	authorization := request.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
}

func decodeJSON(writer http.ResponseWriter, request *http.Request, target any, maxBytes int64) bool {
	defer func() { _ = request.Body.Close() }()
	request.Body = http.MaxBytesReader(writer, request.Body, maxBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_json")
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != nil && !errors.Is(err, io.EOF) {
		writeError(writer, http.StatusBadRequest, "invalid_json")
		return false
	}
	return true
}

func (s *Server) allowAuthRequest(writer http.ResponseWriter, request *http.Request) bool {
	key := request.URL.Path + ":" + s.clientIPForRateLimit(request)
	if s.authLimiter.Allow(key) {
		return true
	}

	writer.Header().Set("Retry-After", "60")
	writeError(writer, http.StatusTooManyRequests, "rate_limited")
	return false
}

func (s *Server) allowAuthRequestForAccount(
	writer http.ResponseWriter,
	request *http.Request,
	accountID string,
) bool {
	return s.allowAuthRequestWithKey(writer, request.URL.Path+":"+accountID)
}

// allowAuthRequestWithKey applies the per-account auth limiter under an explicit
// key. Routes with a path parameter (e.g. DELETE /sync/devices/{device_id})
// must not key on request.URL.Path — the varying segment would give each id its
// own bucket and let a caller sidestep the per-account ceiling — so they pass a
// stable route-scoped key instead.
func (s *Server) allowAuthRequestWithKey(writer http.ResponseWriter, key string) bool {
	if s.authLimiter.Allow(key) {
		return true
	}

	writer.Header().Set("Retry-After", "60")
	writeError(writer, http.StatusTooManyRequests, "rate_limited")
	return false
}

// allowLoginRequestForIdentifier enforces a per-login-identifier ceiling on
// top of the per-IP allowAuthRequest gate. Without this layer, a distributed
// attacker with a stolen password can brute-force the TOTP second factor
// across many source IPs (per-IP limiter stops one source; identifier-keyed
// limiter caps total per-account throughput, which is what matters for
// account brute-force).
//
// Empty/whitespace identifiers are accepted without consuming a slot so the
// downstream credential-validation path can return its canonical
// invalid-credentials response instead of an unrelated 429.
func (s *Server) allowLoginRequestForIdentifier(
	writer http.ResponseWriter,
	_ *http.Request,
	login string,
) bool {
	normalized := security.NormalizeLogin(login)
	if normalized == "" {
		return true
	}
	key := "login_identifier:" + normalized
	if s.authLimiter.Allow(key) {
		return true
	}

	writer.Header().Set("Retry-After", "60")
	writeError(writer, http.StatusTooManyRequests, "rate_limited")
	return false
}

func (s *Server) clientIPForRateLimit(request *http.Request) string {
	remoteAddr, ok := parseClientIP(strings.TrimSpace(request.RemoteAddr))
	if !ok {
		return strings.TrimSpace(request.RemoteAddr)
	}

	if !s.isTrustedProxy(remoteAddr) {
		return remoteAddr.String()
	}

	if forwarded, ok := forwardedClientIP(request.Header.Get("X-Forwarded-For")); ok {
		return forwarded.String()
	}

	if realIP, ok := parseClientIP(request.Header.Get("X-Real-IP")); ok {
		return realIP.String()
	}

	return remoteAddr.String()
}

func (s *Server) isTrustedProxy(addr netip.Addr) bool {
	for _, prefix := range s.trustedProxyCIDRs {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func parseTrustedProxyCIDRs(values []string) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		// Values are validated by config.Validate at startup; a parse
		// failure here can only mean the entry never passed validation.
		prefix, err := config.ParseTrustedProxyCIDR(value)
		if err != nil {
			continue
		}
		result = append(result, prefix)
	}
	return result
}

func forwardedClientIP(value string) (netip.Addr, bool) {
	for _, part := range strings.Split(value, ",") {
		if addr, ok := parseClientIP(part); ok {
			return addr, true
		}
	}
	return netip.Addr{}, false
}

func parseClientIP(value string) (netip.Addr, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return netip.Addr{}, false
	}

	if host, _, err := net.SplitHostPort(trimmed); err == nil {
		trimmed = host
	}
	trimmed = strings.Trim(trimmed, "[]")

	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		return netip.Addr{}, false
	}

	// Canonicalize the rate-limit key: Unmap folds ::ffff:1.2.3.4 onto
	// 1.2.3.4, and WithZone("") strips any IPv6 zone. A remote client's IP
	// never legitimately carries a zone, and leaving it would let an IPv6
	// caller behind a trusted proxy mint distinct buckets for one address by
	// varying %zone in a forwarded header.
	return addr.Unmap().WithZone(""), true
}

func writeError(writer http.ResponseWriter, status int, key string) {
	writeJSON(writer, status, map[string]string{"error": key})
}

func writeJSON(writer http.ResponseWriter, status int, payload any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(payload)
}

func encodedBlobRequestLimit(maxBlobBytes int) int64 {
	if maxBlobBytes <= 0 {
		return 24 << 20
	}

	base64Bytes := ((int64(maxBlobBytes) + 2) / 3) * 4
	return base64Bytes + 8<<10
}

type credentialsRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type forgotPasswordRequest struct {
	Login        string `json:"login"`
	RecoveryCode string `json:"recovery_code"`
}

type resetPasswordRequest struct {
	ResetToken  string `json:"reset_token"`
	NewPassword string `json:"new_password"`
}

type regenerateRecoveryCodeRequest struct {
	CurrentPassword string `json:"current_password"`
}

type totpEnrollRequest struct {
	CurrentPassword string `json:"current_password"`
}

type totpVerifyRequest struct {
	Code string `json:"code"`
}

type totpDisableRequest struct {
	CurrentPassword string `json:"current_password"`
	Code            string `json:"code"`
}

type totpChallengeRequest struct {
	ChallengeID string `json:"challenge_id"`
	Code        string `json:"code"`
}

type managedSessionRequest struct {
	AccountID string `json:"account_id"`
}

// managedAccountPremiumRequest is the POST /managed/accounts/{account_id}
// /premium body. Active false records an entitlement lapse; true retracts a
// previously recorded one. An omitted field decodes to false, the sketch's
// primary case (see handleManagedAccountPremium).
type managedAccountPremiumRequest struct {
	Active bool `json:"active"`
}

type deviceRequest struct {
	DeviceID    string `json:"device_id"`
	DeviceLabel string `json:"device_label"`
}

type deviceListResponse struct {
	Devices []models.Device `json:"devices"`
}

type blobPutRequest struct {
	SchemaVersion    int    `json:"schema_version"`
	Generation       int64  `json:"generation"`
	ChecksumSHA256   string `json:"checksum_sha256"`
	CiphertextBase64 string `json:"ciphertext_base64"`
}

type blobResponse struct {
	SchemaVersion    int    `json:"schema_version"`
	Generation       int64  `json:"generation"`
	ChecksumSHA256   string `json:"checksum_sha256"`
	CiphertextBase64 string `json:"ciphertext_base64"`
	CiphertextSize   int    `json:"ciphertext_size"`
	UpdatedAt        string `json:"updated_at"`
}

type recoveryKeyPackageRequest struct {
	Algorithm            string `json:"algorithm"`
	KDF                  string `json:"kdf"`
	MnemonicWordCount    int    `json:"mnemonic_word_count"`
	WrapNonceHex         string `json:"wrap_nonce_hex"`
	WrappedMasterKeyHex  string `json:"wrapped_master_key_hex"`
	PhraseFingerprintHex string `json:"phrase_fingerprint_hex"`
}

type recoveryKeyPackageResponse struct {
	Algorithm            string `json:"algorithm"`
	KDF                  string `json:"kdf"`
	MnemonicWordCount    int    `json:"mnemonic_word_count"`
	WrapNonceHex         string `json:"wrap_nonce_hex"`
	WrappedMasterKeyHex  string `json:"wrapped_master_key_hex"`
	PhraseFingerprintHex string `json:"phrase_fingerprint_hex"`
	UpdatedAt            string `json:"updated_at"`
}

func blobResponseFromModel(blob models.EncryptedBlob) blobResponse {
	return blobResponse{
		SchemaVersion:    blob.SchemaVersion,
		Generation:       blob.Generation,
		ChecksumSHA256:   blob.ChecksumSHA256,
		CiphertextBase64: base64.StdEncoding.EncodeToString(blob.Ciphertext),
		CiphertextSize:   blob.CiphertextSize,
		UpdatedAt:        blob.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}

func recoveryKeyPackageResponseFromModel(
	recoveryKeyPackage models.RecoveryKeyPackage,
) recoveryKeyPackageResponse {
	return recoveryKeyPackageResponse{
		Algorithm:            recoveryKeyPackage.Algorithm,
		KDF:                  recoveryKeyPackage.KDF,
		MnemonicWordCount:    recoveryKeyPackage.MnemonicWordCount,
		WrapNonceHex:         recoveryKeyPackage.WrapNonceHex,
		WrappedMasterKeyHex:  recoveryKeyPackage.WrappedMasterKeyHex,
		PhraseFingerprintHex: recoveryKeyPackage.PhraseFingerprintHex,
		UpdatedAt:            recoveryKeyPackage.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}
}
