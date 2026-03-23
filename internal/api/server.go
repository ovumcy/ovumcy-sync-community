package api

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
	"github.com/ovumcy/ovumcy-sync-community/internal/security"
	"github.com/ovumcy/ovumcy-sync-community/internal/services"
)

type Server struct {
	auth                *services.AuthService
	sync                *services.SyncService
	managedBridge       *services.ManagedBridgeService
	managedBridgeToken  string
	authLimiter         *security.RateLimiter
	allowedOrigins      map[string]struct{}
	maxBlobRequestBytes int64
	readinessCheck      func(context.Context) error
	mux                 *http.ServeMux
}

type ServerOptions struct {
	ManagedBridgeToken  string
	AllowedOrigins      []string
	AuthRateLimitCount  int
	AuthRateLimitWindow time.Duration
	MaxBlobBytes        int
	ReadinessCheck      func(context.Context) error
}

func NewServer(
	auth *services.AuthService,
	sync *services.SyncService,
	managedBridge *services.ManagedBridgeService,
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

	server := &Server{
		auth:                auth,
		sync:                sync,
		managedBridge:       managedBridge,
		managedBridgeToken:  strings.TrimSpace(options.ManagedBridgeToken),
		authLimiter:         security.NewRateLimiter(options.AuthRateLimitCount, options.AuthRateLimitWindow),
		allowedOrigins:      originSet,
		maxBlobRequestBytes: encodedBlobRequestLimit(options.MaxBlobBytes),
		readinessCheck:      options.ReadinessCheck,
		mux:                 http.NewServeMux(),
	}
	server.routes()
	return server
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /readyz", s.handleReady)
	s.mux.HandleFunc("POST /auth/register", s.handleRegister)
	s.mux.HandleFunc("POST /auth/login", s.handleLogin)
	s.mux.HandleFunc("DELETE /auth/session", s.handleLogout)
	s.mux.HandleFunc("POST /managed/session", s.withManagedBridge(s.handleManagedSession))
	s.mux.HandleFunc("GET /sync/capabilities", s.withAuth(s.handleCapabilities))
	s.mux.HandleFunc("POST /sync/devices", s.withAuth(s.handleAttachDevice))
	s.mux.HandleFunc("GET /sync/recovery-key", s.withAuth(s.handleGetRecoveryKey))
	s.mux.HandleFunc("PUT /sync/recovery-key", s.withAuth(s.handlePutRecoveryKey))
	s.mux.HandleFunc("GET /sync/blob", s.withAuth(s.handleGetBlob))
	s.mux.HandleFunc("PUT /sync/blob", s.withAuth(s.handlePutBlob))
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
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
	s.mux.ServeHTTP(writer, request)
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

	result, err := s.auth.Login(request.Context(), payload.Login, payload.Password)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidCredentials):
			writeError(writer, http.StatusUnauthorized, "invalid_credentials")
		default:
			writeError(writer, http.StatusInternalServerError, "internal_error")
		}
		return
	}

	writeJSON(writer, http.StatusOK, result)
}

func (s *Server) handleLogout(writer http.ResponseWriter, request *http.Request) {
	if err := s.auth.RevokeSession(request.Context(), bearerTokenFromRequest(request)); err != nil {
		writeError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}

	writeJSON(writer, http.StatusOK, map[string]string{"status": "revoked"})
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

func (s *Server) handleCapabilities(writer http.ResponseWriter, _ *http.Request, account models.Account) {
	writeJSON(writer, http.StatusOK, s.sync.CapabilitiesForAccount(account))
}

func (s *Server) handleAttachDevice(
	writer http.ResponseWriter,
	request *http.Request,
	account models.Account,
) {
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

func (s *Server) handlePutBlob(
	writer http.ResponseWriter,
	request *http.Request,
	account models.Account,
) {
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
	defer request.Body.Close()
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
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		host = request.RemoteAddr
	}

	key := request.URL.Path + ":" + host
	if s.authLimiter.Allow(key) {
		return true
	}

	writer.Header().Set("Retry-After", "60")
	writeError(writer, http.StatusTooManyRequests, "rate_limited")
	return false
}

func writeError(writer http.ResponseWriter, status int, key string) {
	writeJSON(writer, status, map[string]string{"error": key})
}

func writeJSON(writer http.ResponseWriter, status int, payload any) {
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

type managedSessionRequest struct {
	AccountID string `json:"account_id"`
}

type deviceRequest struct {
	DeviceID    string `json:"device_id"`
	DeviceLabel string `json:"device_label"`
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
