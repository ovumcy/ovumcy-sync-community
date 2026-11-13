# Data Handling

This page lists what the SQLite database holds, how sensitive each table is, and how rows leave it.
The schema is defined by the forward-only migrations in `internal/db/migrations/`. Related:
[threat-model.md](threat-model.md), [logging.md](logging.md),
[backup-restore.md](../backup-restore.md).

Sensitivity classes used below:

- **Identity**: names or links a person to an account.
- **Credential**: material that authenticates or recovers an account.
- **Metadata**: usage facts about an account.
- **Ciphertext**: opaque client-encrypted content.

The server never stores cycle dates, symptoms, notes, recovery phrases, client master keys or
decrypted payloads.

## Tables

| Table | Columns | Class | Notes |
| --- | --- | --- | --- |
| `accounts` | `id`, `login`, `created_at`, `mode`, `premium_active`, `lapsed_at`, `entitlement_signal_as_of` | Identity, metadata | `login` is the only user-chosen identifier; `mode` is `self_hosted` or `managed`; `lapsed_at` and `entitlement_signal_as_of` (the ordering point of the newest bridge lapse/reactivation signal) are set only for managed accounts |
| `accounts` | `password_hash`, `recovery_code_hash` | Credential | bcrypt, cost 12; an empty recovery hash means no recovery code |
| `accounts` | `totp_secret_encrypted`, `totp_enabled`, `totp_last_used_step` | Credential | Secret is AES-256-GCM under `FIELD_ENCRYPTION_KEY`, AAD bound to the account; the last used step blocks replay |
| `sessions` | `id`, `account_id`, `token_hash`, `created_at`, `last_seen_at`, `expires_at`, `device_id` | Credential (hash), metadata | Token stored as SHA-256 only; `device_id` is the device the session first attached (NULL until then) |
| `devices` | `account_id`, `device_id`, `device_label`, `created_at`, `last_seen_at` | Metadata | The label is client-supplied text; clients should not put personal data in it |
| `encrypted_blobs` | `account_id`, `schema_version`, `generation`, `checksum_sha256`, `ciphertext`, `ciphertext_size`, `created_at`, `updated_at` | Ciphertext, metadata | One row per account; the checksum and size are visible to the operator |
| `recovery_key_packages` | `account_id`, `algorithm`, `kdf`, `mnemonic_word_count`, `wrap_nonce_hex`, `wrapped_master_key_hex`, `phrase_fingerprint_hex`, `updated_at` | Ciphertext, credential | Wrapped master key; the phrase is not stored |
| `password_reset_tokens` | `account_id`, `token_hash`, `created_at`, `expires_at`, `consumed_at` | Credential (hash) | One row per account; token valid for 30 minutes and single-use |
| `totp_challenges` | `challenge_id_hash`, `account_id`, `created_at`, `expires_at`, `failed_attempts` | Credential (hash) | Valid for 5 minutes, locked after 5 failed attempts |
| `totp_failure_windows` | `account_id`, `window_started_unix`, `failed_attempts` | Metadata | One row per account; cleared by a successful TOTP verify |

## Retention and deletion

| Data | Leaves the database when |
| --- | --- |
| Everything for an account | The account is deleted: one transaction removes rows from `sessions`, `devices`, `encrypted_blobs`, `recovery_key_packages`, `password_reset_tokens`, `totp_challenges` and `totp_failure_windows`, then the `accounts` row (`Store.DeleteAccount`, `internal/db/repositories.go`) |
| A managed account on bridge request | `DELETE /managed/accounts/{account_id}` behind the managed-bridge token purges the account |
| A single session | Logout, a password change (every other session), or a recovery-based reset |
| Expired sessions, reset tokens, TOTP challenges | The expired-rows sweep removes rows past `expires_at`. Interval `EXPIRED_ROWS_SWEEP_INTERVAL` (default 24 h; the in-process sweep can be disabled), batch size `EXPIRED_ROWS_SWEEP_LIMIT` (0 uses the built-in default). Expiry is already enforced at use time, so an expired row is unusable before it is erased |
| A managed account whose entitlement lapsed | The lapse sweep deletes it once `lapsed_at` is older than `LAPSED_ACCOUNT_GRACE_PERIOD` (default 60 days). Interval `LAPSED_ACCOUNT_SWEEP_INTERVAL` (default 24 h), batch size `LAPSED_ACCOUNT_SWEEP_LIMIT`. Sync access is revoked immediately at lapse; only the data is kept for the grace period. Only a reactivation signal newer than the lapse clears `lapsed_at`; a session mint never does. The same purge can be run by hand with the `purge-lapsed-accounts` command. Self-hosted accounts are never swept |
| A device record | The user removes the device, or the account is deleted |

The sweeps are enabled by default in the server process. Rows with no expiry (`devices`,
`encrypted_blobs`, `recovery_key_packages`) stay until the account is deleted, and self-hosted
accounts have no automatic retention limit.

## Backups outlive erasure

Account deletion and the sweeps act on the live database only. Any earlier copy, whether a file
backup, a `VACUUM INTO` snapshot, a volume snapshot or a copy held by a hosting provider, still
contains the deleted rows until that copy is destroyed. The same applies to the write-ahead log
files next to the database until they are checkpointed.

For operators:

- Give backups a fixed retention and rotate them on schedule, so a deleted account leaves every copy
  within a known time. Choose the window with the grace period in mind.
- Encrypt backups and restrict access; they hold the same hashes and metadata as the live database.
  `FIELD_ENCRYPTION_KEY` is not in the database, so keep it out of the same backup.
- After a restore, expect previously deleted accounts to reappear. Re-apply deletions that happened
  after the backup was taken.

The backup and restore steps are in [backup-restore.md](../backup-restore.md).
