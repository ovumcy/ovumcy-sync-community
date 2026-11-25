package services

import (
	"context"
	"time"
)

// createSession inserts a session with none of the mint guards (lapse,
// verified password, session cap). Test-only, so no production path can mint
// past MAX_SESSIONS_PER_ACCOUNT.
func (s *AuthService) createSession(
	ctx context.Context,
	accountID string,
	now time.Time,
) (AuthResult, error) {
	session, result, err := s.newSession(accountID, now)
	if err != nil {
		return AuthResult{}, err
	}
	if _, err := s.store.CreateSession(ctx, session); err != nil {
		return AuthResult{}, err
	}
	return result, nil
}
