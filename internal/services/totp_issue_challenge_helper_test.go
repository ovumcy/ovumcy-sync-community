package services

import (
	"context"
	"time"
)

// IssueChallenge issues a login challenge against the account's current
// password hash, for tests that need a challenge without driving Login.
func (s *TOTPService) IssueChallenge(
	ctx context.Context,
	accountID string,
) (string, time.Time, error) {
	account, err := s.store.FindAccountByID(ctx, accountID)
	if err != nil {
		return "", time.Time{}, err
	}
	return s.IssueChallengeForVerifiedPassword(ctx, accountID, account.PasswordHash)
}
