ALTER TABLE accounts ADD COLUMN recovery_code_hash TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  account_id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token_hash ON password_reset_tokens(token_hash);
