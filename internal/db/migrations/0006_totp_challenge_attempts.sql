ALTER TABLE totp_challenges ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0;
