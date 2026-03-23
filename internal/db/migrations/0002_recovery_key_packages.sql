CREATE TABLE IF NOT EXISTS recovery_key_packages (
  account_id TEXT PRIMARY KEY,
  algorithm TEXT NOT NULL,
  kdf TEXT NOT NULL,
  mnemonic_word_count INTEGER NOT NULL,
  wrap_nonce_hex TEXT NOT NULL,
  wrapped_master_key_hex TEXT NOT NULL,
  phrase_fingerprint_hex TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE
);
