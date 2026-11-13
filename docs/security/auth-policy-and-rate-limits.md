# Auth policy and rate limits

This is the route-by-route policy as implemented in `internal/api/server.go` (`routes()`), with the
numbers at their defaults from `internal/config/config.go`. The claims are pinned by tests listed in
[SECURITY.md](../../SECURITY.md); this page does not duplicate that matrix. See
[architecture](../architecture.md) for where the limiter sits in the request lifecycle.

## Defaults used below

| Setting | Default |
| --- | --- |
| `AUTH_RATE_LIMIT_COUNT` / `AUTH_RATE_LIMIT_WINDOW` | 10 per 1m (fixed window per key) |
| Read-state budget | 30 x `AUTH_RATE_LIMIT_COUNT` = 300 per 1m (`sessionReadRateLimitMultiplier`) |
| `MAX_BLOB_BYTES` | 16 MiB (16777216) |
| `SESSION_TTL` | 720h |

A throttled request gets `429` with `{"error": "rate_limited"}` and `Retry-After: 60`
(`allowUnderLimiter`). Each limiter key is prefixed with the request path (or an explicit route key), so
every route has its own bucket. Limiter state is in memory, per process. The one exception is the
per-account TOTP code window below: it lives in the database (`totp_failure_windows`), so it survives a
restart, and its `429` carries a `Retry-After` of the seconds left in the window (1–900).

Limiter keys: **IP** is the client IP resolved by `clientIPForRateLimit` (the socket peer, or the
rightmost non-trusted forwarded address when the peer is in `TRUSTED_PROXY_CIDRS`), an IPv6 client
keyed by its /64; **account** is the
authenticated account id; **login** is the lowercased, trimmed login from the request body.

## Routes

| Route | Auth | Limiter and key | Budget (default) | Body cap |
| --- | --- | --- | --- | --- |
| `GET /healthz` | none | none (deliberate) | unlimited | none |
| `GET /readyz` | none | none (deliberate) | unlimited | none |
| `GET /metrics` | optional bearer `METRICS_BEARER_TOKEN`; 404 unless `METRICS_ENABLED` | none (deliberate) | unlimited | none |
| `POST /auth/register` | none | auth, IP | 10/min | 4 KiB |
| `POST /auth/login` | none | auth, IP, and a second auth bucket on login | 10/min each; both must pass | 4 KiB |
| `POST /auth/forgot-password` | none | auth, IP | 10/min | 4 KiB |
| `POST /auth/reset-password` | reset token in body | auth, IP | 10/min | 4 KiB |
| `POST /auth/totp/challenge` | challenge id in body; 503 if no `FIELD_ENCRYPTION_KEY` | auth, IP | 10/min | 4 KiB |
| `DELETE /auth/session` | the bearer token it revokes | auth, IP | 10/min | none read |
| `POST /auth/change-password` | session | auth, account | 10/min | 4 KiB |
| `POST /auth/recovery-code/regenerate` | session | auth, account | 10/min | 4 KiB |
| `POST /auth/totp/enroll` | session | auth, account | 10/min | 4 KiB |
| `POST /auth/totp/verify` | session | auth, account | 10/min | 4 KiB |
| `POST /auth/totp/disable` | session | auth, account | 10/min | 4 KiB |
| `GET /auth/session` | session | read, account | 300/min | none |
| `DELETE /account` | session | auth, account | 10/min | none |
| `GET /sync/capabilities` | session | read, account | 300/min | none |
| `GET /sync/devices` | session | read, account | 300/min | none |
| `POST /sync/devices` | session | auth, account | 10/min | 4 KiB |
| `DELETE /sync/devices/{device_id}` | session | auth, account (stable key `sync_devices_remove:<account>`, not the path) | 10/min | none |
| `GET /sync/recovery-key` | session | auth, account | 10/min | none |
| `PUT /sync/recovery-key` | session | auth, account | 10/min | 8 KiB |
| `GET /sync/blob` | session | auth, account | 10/min | none |
| `PUT /sync/blob` | session | auth, account | 10/min | base64 of `MAX_BLOB_BYTES` plus 8 KiB: 22377816 bytes at the default (`encodedBlobRequestLimit`) |
| `POST /managed/session` | `MANAGED_BRIDGE_TOKEN` bearer; 503 if unset | none (deliberate) | unlimited | 4 KiB |
| `DELETE /managed/accounts/{account_id}` | `MANAGED_BRIDGE_TOKEN` bearer | none (deliberate) | unlimited | none |
| `POST /managed/accounts/{account_id}/premium` | `MANAGED_BRIDGE_TOKEN` bearer | none (deliberate) | unlimited | 4 KiB |

Notes on the table:

- Session routes authenticate first (`withAuth`), so an invalid bearer token answers 401 without touching
  a limiter; per-account limiting only ever applies to a caller with a valid session.
- The 30x read budget covers exactly three routes: `GET /auth/session`, `GET /sync/capabilities`,
  `GET /sync/devices`. `GET /sync/blob` and `GET /sync/recovery-key` are not in that set and use the
  10/min per-account budget.
- Login carries a second ceiling keyed on the normalized login (`login_identifier:<login>` in the same
  limiter), so a distributed attacker cannot multiply the budget across source IPs. The cost is that
  someone can exhaust a known login's budget for the rest of the window. An empty login consumes no slot.
- `POST /auth/totp/challenge` answers 503 before limiting when TOTP is not configured.
- The body is decoded strictly: unknown fields and trailing data are `400 invalid_json`, as is any body over
  the cap.
- Raising `AUTH_RATE_LIMIT_COUNT` or `AUTH_RATE_LIMIT_WINDOW` moves every bucket; the read budget has no
  separate setting.

### Deliberately unlimited

- `GET /healthz`, `GET /readyz`: polled on a fixed interval by the container `HEALTHCHECK` and by uptime
  monitors. A 429 would be reported as an outage and could get a healthy server restarted. Both are
  cheap.
- `GET /metrics`: a scrape endpoint, off unless `METRICS_ENABLED`, gated by `METRICS_BEARER_TOKEN` when set.
- `/managed/*`: unreachable without the operator-held `MANAGED_BRIDGE_TOKEN` (at least 32 bytes,
  enforced at startup), refused at the public edge by the bundled proxy examples, and its one caller is a
  first-party service that may reconcile in bursts. A per-IP ceiling would throttle the operator's own
  control plane without stopping anyone who lacks the token.

## Credential and token policy

| Item | Value | Source |
| --- | --- | --- |
| Password length | at least 12 Unicode runes after trimming whitespace; at most 72 UTF-8 bytes (bcrypt's input ceiling), rejected as weak before a reset token is consumed | `ValidatePassword`, `internal/security/password.go` |
| Login | lowercased and trimmed, at least 3 characters, the `managed:` prefix is reserved and rejected | `NormalizeLogin`, `ValidateLogin` |
| Password and recovery-code hashing | bcrypt, cost 12 (`PasswordHashCost`); older lower-cost hashes are re-hashed on the next successful login | `internal/security/password.go`, `AuthService.Login` |
| Session lifetime | `SESSION_TTL`, default 720h; stored as a hash, never in plaintext | `internal/config/config.go`, `AuthService.createSession` |
| Password-reset token lifetime | 30 minutes, single use (`PasswordResetTokenTTL`) | `internal/services/auth_service.go` |
| TOTP login challenge lifetime | 5 minutes, single use (`TOTPChallengeTTL`) | `internal/services/totp_service.go` |
| TOTP failed attempts per challenge | 5, after which the challenge is burnt (`maxTOTPChallengeFailedAttempts`) | `internal/services/totp_service.go` |
| TOTP code attempts per account | 10 per fixed 15-minute window across all challenges and disable (`maxTOTPAccountFailedAttempts`, `TOTPFailureWindow`); past it 429 `rate_limited` until the window ends; a new login does not reset it, a successful verify or completed enrollment does. Trade-off: only someone who already holds the password can spend the window (a challenge is issued only after it), and while it is spent the owner's own correct code also gets 429; the way out is the window ending or a recovery-code reset | `internal/services/totp_service.go`, `Store.ReserveTOTPAttempt` |
| TOTP code | 6 digits, 30 s step; a used step cannot be replayed | `internal/security/totp.go`, `totp_replayed` |
| TOTP secret at rest | AES-256-GCM under `FIELD_ENCRYPTION_KEY` | `internal/security/field_crypto.go` |

## Session revocation on posture changes

| Event | Sessions revoked | Code |
| --- | --- | --- |
| Change password | all except the caller's current session | `AuthService.ChangePassword` |
| Reset password (recovery code flow) | all; pending TOTP challenges and reset tokens are deleted too, and the password and recovery code rotate | `AuthService.ResetPassword` |
| TOTP enrollment verified | all except the caller's current session | `TOTPService.CompleteEnrollment` |
| TOTP disabled (needs password and current code) | all | `TOTPService.Disable` |
| Entitlement lapse signal (`active=false`) | all | `ManagedBridgeService.SetAccountLapseSignal` |
| Logout | the presented session | `AuthService.RevokeSession` |
| Account delete | everything for the account (cascade) | `AuthService.DeleteAccount` |

Recovery-code regeneration and TOTP enroll-start leave sessions untouched; the revocation for enrollment
happens at verify. Regeneration does delete pending reset tokens, so a token issued against the old code
cannot outlive the rotation.

## Enumeration and timing safety

- Login returns the same `invalid_credentials` for an unknown login, a wrong password and a managed
  account; each of those paths burns a bcrypt compare at the current cost
  (`equalizePasswordTiming`, `internal/services/auth_service_timing.go`) so latency does not distinguish them.
- Forgot-password does the same for an unknown login, an account with no recovery code, and a wrong
  recovery code, all answering `invalid_recovery_credentials`.
- Reset tokens, session tokens and TOTP challenge ids are looked up by hash; the metrics and bridge bearer
  checks use constant-time comparison.
- Login never returns a session token and a TOTP challenge in the same response, and an enrolled account
  fails closed (503 `totp_not_configured`) when the server has no field encryption key.
- Registration is the one place existence shows: a taken login answers `400 registration_failed`, distinct
  from `invalid_registration_input`. Registration is limited per IP as the mitigation.

Tests backing each claim are indexed in the Test Enforcement Matrix of [SECURITY.md](../../SECURITY.md)
(Passwords, Password Change, Recovery Codes and Password Reset, Timing Parity, Sessions, Two-Factor
Authentication, Rate Limiting, Managed Bridge).
