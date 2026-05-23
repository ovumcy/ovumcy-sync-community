-- Adds a consumed_at marker so password reset tokens can be claimed atomically.
-- Without this column, ResetPassword had to read-then-delete the token, leaving
-- a race window where two concurrent POST /auth/reset-password calls with the
-- same plaintext token could both succeed, rotating the password and recovery
-- code twice and returning two divergent plaintext recovery codes to the caller.
-- The single-use semantics now live in the UPDATE ... WHERE consumed_at IS NULL
-- CAS in ConsumePasswordResetToken.
ALTER TABLE password_reset_tokens ADD COLUMN consumed_at TEXT;
