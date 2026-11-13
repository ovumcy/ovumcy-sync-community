-- Per-account failed-TOTP counter in a fixed window. Unlike
-- totp_challenges.failed_attempts it survives a fresh login challenge, so
-- logging in again cannot reset the guess budget. window_started_unix is
-- integer seconds so the expiry test inside the reserving upsert is numeric.
CREATE TABLE IF NOT EXISTS totp_failure_windows (
  account_id TEXT PRIMARY KEY,
  window_started_unix INTEGER NOT NULL,
  failed_attempts INTEGER NOT NULL,
  FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
