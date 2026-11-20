package db

import (
	"context"
	"fmt"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/models"
)

// UpsertTOTPChallenge is a test-only fixture insert: it writes a challenge row
// with no account, password-hash or TOTP-enabled precondition, so repository
// tests can seed rows the guarded production path
// (CreateTOTPChallengeForVerifiedPassword) would refuse. Living in a _test.go
// file keeps it out of the production binary.
func (s *Store) UpsertTOTPChallenge(
	ctx context.Context,
	challenge models.TOTPChallenge,
) error {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO totp_challenges (challenge_id_hash, account_id, created_at, expires_at)
		 VALUES (?, ?, ?, ?)`,
		challenge.ChallengeIDHash,
		challenge.AccountID,
		challenge.CreatedAt.UTC().Format(time.RFC3339Nano),
		challenge.ExpiresAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("insert totp challenge: %w", err)
	}
	return nil
}
