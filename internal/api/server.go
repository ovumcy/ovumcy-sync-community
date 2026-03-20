package api

import (
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
	auth           *services.AuthService
	sync           *services.SyncService
	authLimiter    *security.RateLimiter
	allowedOrigins map[string]struct{}
	mux            *http.ServeMux
}

func NewServer(
	auth *services.AuthService,
	sync *services.SyncService,
	allowedOrigins []string,
) http.Handler {
	originSet := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		trimmed := strings.TrimSpace(origin)
		if trimmed == "" {
			continue
		}
		originSet[trimmed] = struct{}{}
	}

	server := &Server{
		auth:           auth,
		sync:           sync,
		authLimiter:    security.NewRateLimiter(10, time.Minute),
		allowedOrigins: originSet,
		mux:            http.NewServeMux(),
	}
	server.routes()
	return server
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("POST /auth/register", s.handleRegister)
	s.mux.HandleFunc("POST /auth/login", s.handleLogin)
	s.mux.HandleFunc("DELETE /auth/session", s.handleLogout)
	s.mux.HandleFunc("GET /sync/capabilities", s.withAuth(s.handleCapabilities))
	s.mux.HandleFunc("POST /sync/devices", s.withAuth(s.handleAttachDevice))
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

func (s *Server) handleCapabilities(writer http.ResponseWriter, _ *http.Request, _ models.Account) {
	writeJSON(writer, http.StatusOK, s.sync.Capabilities())
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
	if !decodeJSON(writer, request, &payload, 24<<20) {
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

type credentialsRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
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
