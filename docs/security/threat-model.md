# Threat Model

This document describes what `ovumcy-sync-community` protects, from whom, and where each
protection lives in the code. The test-backed claim matrix is in [SECURITY.md](../../SECURITY.md);
this page does not repeat it. Related: [logging.md](logging.md), [data-handling.md](data-handling.md),
[backup-restore.md](../backup-restore.md).

## Zero-knowledge boundary

The server stores ciphertext it cannot open. Clients encrypt the sync payload with a master key that
never leaves the device; the server keeps the blob byte-for-byte (`encrypted_blobs.ciphertext`) and
a wrapped copy of the master key (`recovery_key_packages`), wrapped under a key derived from the
recovery phrase on the client.

An operator with full database access and the server's environment (including `FIELD_ENCRYPTION_KEY`)
**can** learn:

- that an account exists, its login, creation time, mode (`self_hosted` or `managed`), premium flag
  and lapse time;
- device ids and labels, and session creation, last-seen and expiry times;
- blob size, schema version, generation, SHA-256 checksum and update times, which reveal how often
  and how much a user syncs;
- whether TOTP is enabled, and the TOTP secret itself (the key is held by the operator, see below);
- the recovery package's algorithm, KDF name, word count and `phrase_fingerprint_hex`.

The same operator **cannot** learn, from the server side alone:

- cycle dates, symptoms, notes or any decrypted payload: no plaintext or payload key exists on the
  server;
- the master key or the recovery phrase: only the wrapped key is stored;
- plaintext passwords or recovery codes: only bcrypt hashes are stored (cost 12,
  `internal/security/password.go`);
- bearer tokens, reset tokens or TOTP challenge ids: only their SHA-256 hashes are stored
  (`internal/security/token.go`).

An operator can, however, modify or delete ciphertext, withhold it, replay an older blob, or mint
sessions by writing rows, which is a weaker guarantee than confidentiality. Integrity of the payload
rests on client-side authenticated encryption, not on the server. The recovery package carries a
fingerprint of the phrase, not the phrase; offline guessing against a stolen package is bounded by
the strength of the phrase and the client KDF, which are client concerns and outside this repository.

## Assets

| Asset | Where it lives | Notes |
| --- | --- | --- |
| Ciphertext blobs | `encrypted_blobs` | Opaque; size capped by `MAX_BLOB_BYTES` (default 16 MiB) |
| Recovery-key packages | `recovery_key_packages` | Wrapped master key, nonce, fingerprint |
| Account, session, device metadata | `accounts`, `sessions`, `devices` | Linkable usage metadata |
| Password and recovery-code hashes | `accounts.password_hash`, `accounts.recovery_code_hash` | bcrypt cost 12 |
| Session, reset and challenge token hashes | `sessions.token_hash`, `password_reset_tokens.token_hash`, `totp_challenges.challenge_id_hash` | 32-byte random tokens, SHA-256 at rest |
| TOTP secrets | `accounts.totp_secret_encrypted` | AES-256-GCM, key from `FIELD_ENCRYPTION_KEY` via HKDF-SHA256, AAD bound to the account id (`internal/security/field_crypto.go`, `internal/services/totp_service.go`) |
| `FIELD_ENCRYPTION_KEY` | Process environment | Without it, TOTP enrollment is unavailable and an already-enrolled account fails closed at login (503 `totp_not_configured`), never falling back to password-only; loss makes stored TOTP secrets unreadable |
| `MANAGED_BRIDGE_TOKEN` | Process environment | Authorizes the managed bridge routes; unset means the bridge answers 503 |
| `METRICS_BEARER_TOKEN` | Process environment | Optional guard on the metrics endpoint |

## Adversaries

### Network attacker

- Mitigation: the service speaks plain HTTP and expects TLS termination in front of it
  (`docs/self-hosting.md`, `deploy/`). Responses carry `Cache-Control: no-store` and
  `X-Content-Type-Options: nosniff` (`internal/api/server.go`). CORS reflects only origins listed in
  `ALLOWED_ORIGINS`. Server read and write timeouts and a 5 s header timeout are set in
  `cmd/ovumcy-sync-community/main.go`; request bodies are bounded with `http.MaxBytesReader`.
- Residual: without TLS at the proxy, bearer tokens and passwords cross the network in clear. Blob
  contents remain ciphertext either way, but metadata and credentials do not.

### Credential stuffer or brute-force client

- Mitigation: a per-IP and per-account fixed-window limiter on auth routes
  (`AUTH_RATE_LIMIT_COUNT`, default 10 per `AUTH_RATE_LIMIT_WINDOW`, default 1 minute;
  `allowAuthRequest*` in `internal/api/server.go`, `internal/security/rate_limiter.go`). Passwords
  need at least 12 runes. bcrypt cost 12 slows offline guessing. Login timing is equalized between
  known and unknown accounts (`internal/services/auth_service_timing.go`). A TOTP challenge is
  single-use, lives 5 minutes and dies after 5 failed attempts; a used TOTP step cannot be replayed
  (`internal/services/totp_service.go`). Recovery codes carry 128 bits of entropy.
- Residual: the limiter is in-process memory, so it resets on restart and is not shared across
  replicas. Behind a proxy that is not listed in `TRUSTED_PROXY_CIDRS`, every client shares the
  proxy's address and limiter bucket.

### Stolen bearer token

- Mitigation: tokens are random, stored only as hashes, expire after `SESSION_TTL` (default 720 h),
  and are revoked on logout. A password change revokes every session except the current one
  (`DeleteSessionsForAccountExcept`). A recovery-based reset revokes sessions. Devices can be listed
  and removed. Expired rows are erased by the sweep.
- Residual: a stolen token is valid until expiry or revocation; there is no device binding.
  A holder can read and overwrite that account's blob.

### Other account holder (IDOR)

- Mitigation: every data route resolves the account from the session and passes that account id to
  the store; blob, device and recovery-package rows are keyed by it and no route takes a foreign
  account id from the caller. Managed routes take an account id only behind the bridge token. TOTP
  ciphertext is bound to its account id through AAD, so a secret copied between rows does not decrypt.
- Residual: correctness depends on each handler using the session's account id; this is covered by
  tests rather than by a structural barrier.

### Malicious operator or database theft

- Mitigation: see the zero-knowledge boundary above. A stolen database alone yields metadata,
  hashes and ciphertext. TOTP secrets additionally need `FIELD_ENCRYPTION_KEY`, which is not stored
  in the database.
- Residual: an attacker with the database and the key reads TOTP secrets. An operator can deny
  service, delete or roll back blobs, and observe sync timing and size. Backups outlive account
  deletion (see [data-handling.md](data-handling.md)).

### Compromised or misconfigured reverse proxy

- Mitigation: `X-Forwarded-For` and `X-Real-IP` are honoured only when the direct peer is inside
  `TRUSTED_PROXY_CIDRS`; the forwarded chain is walked right to left past trusted hops
  (`forwardedClientIP`, `internal/api/server.go`). Default is no trusted proxy.
- Residual: a proxy in the trusted set can claim any client address, which defeats per-IP limiting;
  nothing else depends on the address, since the application does not log it. A compromised
  proxy sees all traffic, including credentials and bearer tokens, in the clear.

### Managed-bridge impersonation

- Mitigation: bridge routes require `Authorization: Bearer <MANAGED_BRIDGE_TOKEN>`, compared in
  constant time; with no token configured they return 503 `managed_bridge_disabled`
  (`withManagedBridge`, `internal/api/server.go`). The service never issues or verifies entitlement
  tokens; it records the flag the bridge sends. Lapse timestamps are preserved on replay so repeated
  signals cannot extend the grace period (`internal/services/managed_bridge_service.go`).
- Residual: whoever holds the bridge token can set the premium flag, trigger lapse and purge managed
  accounts. Treat it as a high-value secret, restrict the bridge network path, and rotate by
  restarting with a new value.

### Metrics endpoint exposure

- Mitigation: the endpoint is off unless `METRICS_ENABLED=true`; with `METRICS_BEARER_TOKEN` set it
  requires that token, compared in constant time (`handleMetrics`).
- Residual: with metrics enabled and no token, the endpoint is unauthenticated; restrict it at the
  proxy or network layer.
