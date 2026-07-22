package api

import (
	"net/http/httptest"
	"testing"
)

// TestBearerTokenFromRequestAcceptsAnySchemeCase pins RFC 7235 §2.1: the
// auth-scheme is case-insensitive, so "bearer" and "BEARER" must
// authenticate exactly like "Bearer". The token itself is untouched.
func TestBearerTokenFromRequestAcceptsAnySchemeCase(t *testing.T) {
	for _, header := range []string{
		"Bearer tok-123",
		"bearer tok-123",
		"BEARER tok-123",
		"bEaReR tok-123",
	} {
		request := httptest.NewRequest("GET", "/auth/session", nil)
		request.Header.Set("Authorization", header)
		if got := bearerTokenFromRequest(request); got != "tok-123" {
			t.Fatalf("header %q: expected the token to parse, got %q", header, got)
		}
	}
}

// TestBearerTokenFromRequestRejectsNonBearer pins the negative space: other
// schemes, a bare scheme with no token, and a scheme not followed by a
// space all resolve to "no token" — never a partial parse.
func TestBearerTokenFromRequestRejectsNonBearer(t *testing.T) {
	for _, header := range []string{
		"",
		"Basic dXNlcjpwdw==",
		"Bearer",
		"Bearertok-123",
		"token tok-123",
	} {
		request := httptest.NewRequest("GET", "/auth/session", nil)
		request.Header.Set("Authorization", header)
		if got := bearerTokenFromRequest(request); got != "" {
			t.Fatalf("header %q: expected an empty token, got %q", header, got)
		}
	}
}
