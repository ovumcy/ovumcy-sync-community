-- Lets the expired-rows sweep (DeleteExpiredSessions and its password-reset
-- and TOTP-challenge siblings) find its batch through an index instead of a
-- full scan per batch. Each index is on the exact expression the sweep's
-- predicate uses, julianday(expires_at), so the planner can match it; an
-- unreadable expiry indexes as NULL and is found by the same index.
CREATE INDEX IF NOT EXISTS idx_sessions_expires_julianday ON sessions (julianday(expires_at));
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires_julianday ON password_reset_tokens (julianday(expires_at));
CREATE INDEX IF NOT EXISTS idx_totp_challenges_expires_julianday ON totp_challenges (julianday(expires_at));
