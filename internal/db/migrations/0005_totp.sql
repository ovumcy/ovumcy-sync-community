ALTER TABLE accounts ADD COLUMN totp_secret_encrypted TEXT NOT NULL DEFAULT '';
ALTER TABLE accounts ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN totp_last_used_step INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS totp_challenges (
  challenge_id_hash TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_totp_challenges_account_id ON totp_challenges(account_id);
