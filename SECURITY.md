# Security Policy

## Supported Versions

Security fixes are provided for the `main` branch only.

| Version | Supported |
| --- | --- |
| `main` | :white_check_mark: |
| older commits/tags | :x: |

## Reporting a Vulnerability

Please report security issues privately.

- Email: `contact@ovumcy.com`
- Subject: `SECURITY: <short summary>`
- Include: impact, reproduction steps, affected endpoints/files, and suggested fix if available

We will acknowledge receipt within 72 hours and provide a remediation plan after triage.

Do not open public GitHub issues for unpatched security vulnerabilities.

## Scope and Data Boundary

`ovumcy-sync-community` is a self-hosted, zero-knowledge sync backend for the
Ovumcy app. The server stores account identity, session/device metadata,
capability limits, wrapped recovery-key packages, and opaque ciphertext blobs.
It never receives or stores cycle dates, symptoms, notes, recovery phrases,
client master keys, or decrypted sync payloads. Uploaded blobs are persisted
and returned byte-for-byte without interpretation.

The service does not issue or verify premium entitlements. The
`premium_active` capability flag is written only by `ovumcy-managed` through
the bearer-gated managed bridge and is reflected to the client unchanged;
self-hosted accounts always register with `premium_active=false`.

## Accepted Residual Risks

- **In-memory rate limiting.** Rate-limit state is per-process and resets on
  restart. Accepted for the single-instance self-hosted baseline. The limiter
  map is bounded by an amortized sweep that removes only entries whose window
  has fully elapsed (in-window entries are never evicted, so a throttled key
  can never be flushed to reset its counter). Memory is therefore bounded by
  the distinct client keys seen within the current window plus up to one sweep
  interval (1024 calls) of lag, not by the total number of keys ever seen;
  expired keys from a burst linger within that same cap until enough further
  calls accumulate, and the map never grows while idle. Under a sustained
  distributed attack that upper bound is still attack-rate × window, which is
  accepted for the single-instance self-hosted baseline.
- **Field-encryption key rotation.** Rotating `FIELD_ENCRYPTION_KEY`
  invalidates every stored TOTP ciphertext; affected accounts fail closed on
  the next login until they reset via their recovery code. Operator
  responsibility, documented rather than defended at runtime.
- **Timing-equalization tests assert call counts, not wall-clock latency.**
  The guarded property is "equalizing bcrypt work runs on every early-return
  path"; wall-clock assertions would be flaky on shared CI.
- **`managed:` login namespace.** Public registration cannot claim the
  `managed:` prefix, while bridge-provisioned logins use it by design behind
  the `MANAGED_BRIDGE_TOKEN` gate.

## Test Enforcement Matrix

This section maps each test-enforceable claim above — and the core security
invariants of the auth, sync-blob, TOTP, and transport layers — to the Go test
that guards it. When a claim changes, the corresponding test must change in
the same commit; when a test is removed, the claim is no longer enforced and
must be retracted from this document.

Policy-level claims (zero-knowledge design rationale, "never log secrets"
discipline, key-rotation contracts) are intentionally excluded — they are
reviewed by humans, not by `go test` — and are listed at the end together
with known coverage gaps. `scripts/runtime-smoke.sh` additionally exercises
the register/sync/recovery/TOTP flows against a real container image; it is
live-server evidence, not a substitute for the rows below.

### Passwords

| Claim | Enforced by |
| --- | --- |
| Passwords shorter than the minimum length are rejected | `TestHashPasswordRejectsWeakPassword` in [internal/security/security_test.go](internal/security/security_test.go) |
| Hash/compare round-trip succeeds and a wrong password is rejected | `TestHashPasswordAndCompare` in [internal/security/security_test.go](internal/security/security_test.go) |

### Login Normalization and Validation

| Claim | Enforced by |
| --- | --- |
| Login is lowercased and trimmed; inputs shorter than 3 chars are invalid; the reserved `managed:` prefix is rejected in any case | `TestNormalizeLoginAndValidateLogin` in [internal/security/security_test.go](internal/security/security_test.go) |
| Normalization is lowercase, trimmed, and idempotent over arbitrary inputs | `FuzzNormalizeLogin` in [internal/security/security_fuzz_test.go](internal/security/security_fuzz_test.go) |
| Any accepted login is ≥3 chars after normalization and never sits in the reserved `managed:` namespace | `FuzzValidateLogin` in [internal/security/security_fuzz_test.go](internal/security/security_fuzz_test.go) |

### Password Change

| Claim | Enforced by |
| --- | --- |
| Requires an authenticated session | `TestChangePasswordEndpointRequiresAuth` in [internal/api/auth_change_password_test.go](internal/api/auth_change_password_test.go) |
| Verifies the current password | `TestChangePasswordRejectsWrongCurrent` in [internal/services/auth_service_change_password_test.go](internal/services/auth_service_change_password_test.go); `TestChangePasswordEndpointRejectsWrongCurrent` in [internal/api/auth_change_password_test.go](internal/api/auth_change_password_test.go) |
| Rejects an unchanged new password | `TestChangePasswordRejectsSamePassword` in [internal/services/auth_service_change_password_test.go](internal/services/auth_service_change_password_test.go); `TestChangePasswordEndpointRejectsSamePassword` in [internal/api/auth_change_password_test.go](internal/api/auth_change_password_test.go) |
| Rejects a weak new password | `TestChangePasswordRejectsWeakNew` in [internal/services/auth_service_change_password_test.go](internal/services/auth_service_change_password_test.go); `TestChangePasswordEndpointRejectsWeakNew` in [internal/api/auth_change_password_test.go](internal/api/auth_change_password_test.go) |
| On success, revokes every session except the caller's | `TestChangePasswordSuccessRevokesOtherSessions` in [internal/services/auth_service_change_password_test.go](internal/services/auth_service_change_password_test.go); `TestChangePasswordEndpointSucceedsAndRevokesOtherSessions` in [internal/api/auth_change_password_test.go](internal/api/auth_change_password_test.go) |
| Deletes pending reset tokens so a previously issued reset token cannot be reused | `TestChangePasswordInvalidatesPendingResetToken` in [internal/services/auth_service_recovery_test.go](internal/services/auth_service_recovery_test.go) |

### Recovery Codes and Password Reset

| Claim | Enforced by |
| --- | --- |
| Registration issues the plaintext recovery code exactly once | `TestRegisterIssuesRecoveryCode` in [internal/services/auth_service_recovery_test.go](internal/services/auth_service_recovery_test.go); `TestRegisterEndpointReturnsRecoveryCode` in [internal/api/auth_recovery_test.go](internal/api/auth_recovery_test.go) |
| Forgot-password (`{login, recovery_code}`) issues a short-lived reset token (30-minute TTL) | `TestForgotPasswordIssuesResetToken` in [internal/services/auth_service_recovery_test.go](internal/services/auth_service_recovery_test.go) |
| Unknown login and wrong recovery code fail identically (enumeration-safe) | `TestForgotPasswordRejectsUnknownLogin`, `TestForgotPasswordRejectsWrongRecoveryCode` in [internal/services/auth_service_recovery_test.go](internal/services/auth_service_recovery_test.go) |
| The HTTP surface returns the generic `invalid_recovery_credentials` key for both failure shapes | `TestForgotPasswordEndpointGenericErrorForUnknownLogin`, `TestForgotPasswordEndpointGenericErrorForWrongCode` in [internal/api/auth_recovery_test.go](internal/api/auth_recovery_test.go) |
| Issuing a new reset token invalidates the previous one | `TestForgotPasswordReplacesExistingResetToken` in [internal/services/auth_service_recovery_test.go](internal/services/auth_service_recovery_test.go) |
| Reset rotates the password AND the recovery code and revokes every session | `TestResetPasswordRotatesPasswordRecoveryAndSessions` in [internal/services/auth_service_recovery_test.go](internal/services/auth_service_recovery_test.go) |
| Reset tokens are single-use | `TestResetPasswordRejectsReuse` in [internal/services/auth_service_recovery_test.go](internal/services/auth_service_recovery_test.go) |
| Concurrent reuse of one reset token succeeds at most once (atomic `consumed_at` CAS) | `TestResetPasswordConcurrentReuseRejectsAllButOne` in [internal/services/auth_service_recovery_test.go](internal/services/auth_service_recovery_test.go) |
| Expired reset tokens are rejected | `TestResetPasswordRejectsExpiredToken` in [internal/services/auth_service_recovery_test.go](internal/services/auth_service_recovery_test.go) |
| Reset enforces password-strength rules | `TestResetPasswordRejectsWeakNew` in [internal/services/auth_service_recovery_test.go](internal/services/auth_service_recovery_test.go); `TestResetPasswordEndpointRejectsWeakNew` in [internal/api/auth_recovery_test.go](internal/api/auth_recovery_test.go) |
| Reset clears the TOTP secret and pending challenges; the next login issues a regular session | `TestResetPasswordClearsTOTPAndPendingChallenges` in [internal/services/auth_service_recovery_test.go](internal/services/auth_service_recovery_test.go) |
| Recovery-code regeneration requires auth plus the current password | `TestRegenerateRecoveryCodeEndpointRequiresAuth`, `TestRegenerateRecoveryCodeEndpointRejectsWrongPassword` in [internal/api/auth_recovery_test.go](internal/api/auth_recovery_test.go); `TestRegenerateRecoveryCodeRejectsWrongPassword` in [internal/services/auth_service_recovery_test.go](internal/services/auth_service_recovery_test.go) |
| Recovery-code regeneration rotates the code; the old code stops working | `TestRegenerateRecoveryCodeRotatesCode` in [internal/services/auth_service_recovery_test.go](internal/services/auth_service_recovery_test.go); `TestRegenerateRecoveryCodeEndpointSucceeds` in [internal/api/auth_recovery_test.go](internal/api/auth_recovery_test.go) |
| Recovery-code normalization is idempotent over arbitrary inputs | `FuzzNormalizeRecoveryCode` in [internal/security/security_fuzz_test.go](internal/security/security_fuzz_test.go) |

### Timing Parity (CWE-208)

| Claim | Enforced by |
| --- | --- |
| Login on an unknown login performs equalizing bcrypt work | `TestLoginEqualizesTimingForUnknownLogin` in [internal/services/auth_service_timing_test.go](internal/services/auth_service_timing_test.go) |
| Forgot-password on an unknown login performs equalizing bcrypt work | `TestForgotPasswordEqualizesTimingForUnknownLogin` in [internal/services/auth_service_timing_test.go](internal/services/auth_service_timing_test.go) |
| Forgot-password with no stored recovery hash performs equalizing bcrypt work | `TestForgotPasswordEqualizesTimingWhenRecoveryCodeUnset` in [internal/services/auth_service_timing_test.go](internal/services/auth_service_timing_test.go) |
| The equalization placeholder hash stays bcrypt-compatible | `TestPasswordTimingEqualizationHashIsBcryptCompatible` in [internal/services/auth_service_timing_test.go](internal/services/auth_service_timing_test.go) |

### Sessions

| Claim | Enforced by |
| --- | --- |
| Session tokens are opaque; plaintext differs from the stored hash, and `HashToken` is stable SHA-256 hex | `TestTokenHelpersReturnOpaqueValues`, `TestHashTokenIsStableLowerLevelHelper` in [internal/security/security_test.go](internal/security/security_test.go) |
| Revoked sessions are rejected | `TestAuthServiceRevokesSession` in [internal/services/auth_service_test.go](internal/services/auth_service_test.go); `TestServerRevokesSession` in [internal/api/server_test.go](internal/api/server_test.go) |
| Empty and expired sessions are rejected | `TestAuthServiceRejectsEmptyAndExpiredSession` in [internal/services/auth_service_test.go](internal/services/auth_service_test.go) |
| Self-hosted registration creates `mode=self_hosted`, `premium_active=false` accounts | `TestAuthServiceRegisterAndLogin` in [internal/services/auth_service_test.go](internal/services/auth_service_test.go) |
| Login on a TOTP-enabled account fails closed when the field key is absent — no password-only session | `TestAuthServiceLoginFailsClosedWhenTOTPEnabledButNoIssuer` in [internal/services/auth_service_test.go](internal/services/auth_service_test.go); `TestTOTPNotConfiguredWhenServerHasNoFieldKey` in [internal/api/auth_totp_test.go](internal/api/auth_totp_test.go) |

### Two-Factor Authentication (TOTP)

| Claim | Enforced by |
| --- | --- |
| TOTP secrets are sealed with AES-256-GCM; round-trip works, wrong AAD and wrong key fail to open | `TestEncryptFieldRoundtrip`, `TestDecryptFieldRejectsWrongAAD`, `TestDecryptFieldRejectsWrongKey` in [internal/security/field_crypto_test.go](internal/security/field_crypto_test.go) |
| Encryption requires key and AAD; ciphertexts are non-deterministic | `TestEncryptFieldRequiresKeyAndAAD`, `TestEncryptFieldProducesDifferentCiphertextEachCall` in [internal/security/field_crypto_test.go](internal/security/field_crypto_test.go) |
| Round-trip and AAD binding hold over generated and fuzzed inputs | `TestFieldCryptoRoundTripProperty`, `TestFieldCryptoAADBindingProperty` in [internal/security/security_property_test.go](internal/security/security_property_test.go); `FuzzFieldCryptoRoundTrip` in [internal/security/security_fuzz_test.go](internal/security/security_fuzz_test.go) |
| 2FA endpoints are disabled (503) when `FIELD_ENCRYPTION_KEY` is absent | `TestTOTPNotConfiguredWhenServerHasNoFieldKey` in [internal/api/auth_totp_test.go](internal/api/auth_totp_test.go) |
| Enrollment requires the current password; completion rejects a wrong code; login with 2FA returns a challenge and no session token; the challenge is single-use; disable requires password and a correct code | `TestTOTPEnrollVerifyDisableEndToEnd` in [internal/api/auth_totp_test.go](internal/api/auth_totp_test.go) |
| A challenge burns after five wrong codes; a correct code does not reopen it | `TestTOTPChallengeBurnsAfterFiveWrongCodes` in [internal/api/auth_totp_test.go](internal/api/auth_totp_test.go) |
| An invalid challenge id returns a generic error | `TestTOTPChallengeWithInvalidIDReturnsGenericError` in [internal/api/auth_totp_test.go](internal/api/auth_totp_test.go) |
| Re-enrollment while TOTP is enabled returns a conflict | `TestTOTPEnrollRejectsWhenAlreadyEnabled` in [internal/api/auth_totp_test.go](internal/api/auth_totp_test.go) |
| Secrets are 160-bit; base32 round-trips; code generation matches RFC 6238 vectors; only current and adjacent steps verify; empty codes are rejected; the provisioning URI carries secret and issuer | `TestNewTOTPSecretIs160Bits`, `TestEncodeDecodeBase32Roundtrip`, `TestGenerateTOTPCodeIsRFC6238TestVector`, `TestVerifyTOTPCodeAcceptsCurrentAndAdjacentSteps`, `TestVerifyTOTPCodeRejectsFarFutureAndPastSteps`, `TestVerifyTOTPCodeRejectsEmpty`, `TestBuildTOTPProvisioningURIIncludesSecretAndIssuer` in [internal/security/totp_test.go](internal/security/totp_test.go) |
| Generate/verify, skew window, and base32 round-trip hold over generated inputs | `TestTOTPGenerateVerifyProperty`, `TestTOTPSkewWindowProperty`, `TestTOTPBase32RoundTripProperty` in [internal/security/security_property_test.go](internal/security/security_property_test.go) |
| Secret decoding never panics; accepted secrets survive canonical re-encoding | `FuzzDecodeTOTPSecretBase32` in [internal/security/security_fuzz_test.go](internal/security/security_fuzz_test.go) |

### Rate Limiting

| Claim | Enforced by |
| --- | --- |
| The limiter allows up to the configured count, then resets after the window | `TestRateLimiterResetsAfterWindow` in [internal/security/security_test.go](internal/security/security_test.go) |
| Expired entries are swept, so the limiter map does not leak keys for the process lifetime | `TestRateLimiterSweepsExpiredEntries` in [internal/security/security_test.go](internal/security/security_test.go) |
| Map size stays bounded by the current window's keys plus one sweep interval across many unique keys over multiple windows | `TestRateLimiterBoundsMapAcrossManyWindows` in [internal/security/security_test.go](internal/security/security_test.go) |
| The sweep never evicts an in-window entry, so a throttled key cannot be flushed to reset its counter | `TestRateLimiterSweepPreservesInWindowEntries` in [internal/security/security_test.go](internal/security/security_test.go) |
| Auth endpoints are rate-limited per client; excess requests receive `rate_limited` | `TestServerRateLimitsAuthEndpoints` in [internal/api/server_test.go](internal/api/server_test.go) |
| `X-Forwarded-For` is honored only from a trusted-proxy CIDR | `TestServerAuthRateLimitUsesForwardedClientFromTrustedProxy` in [internal/api/server_test.go](internal/api/server_test.go) |
| `X-Forwarded-For` from an untrusted peer is ignored; the raw peer address is the key | `TestServerIgnoresForwardedClientFromUntrustedRemoteAddr` in [internal/api/server_test.go](internal/api/server_test.go) |

### Zero-Knowledge Blob Handling

| Claim | Enforced by |
| --- | --- |
| Uploaded blob ciphertext is returned byte-for-byte without server interpretation | `TestSyncServiceAttachDeviceAndBlobRoundTrip` in [internal/services/sync_service_test.go](internal/services/sync_service_test.go); `TestServerRegisterLoginAndSyncFlow` in [internal/api/server_test.go](internal/api/server_test.go) |
| Checksum mismatch is rejected | `TestSyncServiceRejectsChecksumMismatchAndStaleGeneration` in [internal/services/sync_service_test.go](internal/services/sync_service_test.go) |
| Stale or regressing blob generations are rejected | `TestSyncServiceRejectsChecksumMismatchAndStaleGeneration` in [internal/services/sync_service_test.go](internal/services/sync_service_test.go); `TestServerRejectsStaleBlobGeneration` in [internal/api/server_test.go](internal/api/server_test.go) |
| Concurrent equal-generation writes collapse to exactly one winner (CAS) | `TestSyncServicePutBlobConcurrentEqualGenerationCollapsesToOneWinner` in [internal/services/sync_service_test.go](internal/services/sync_service_test.go) |
| The first write succeeds at generation 1 (the CAS predicate does not block the initial insert) | `TestSyncServicePutBlobFirstWriteSucceeds` in [internal/services/sync_service_test.go](internal/services/sync_service_test.go) |
| Oversized blobs are rejected by the configured limit | `TestSyncServiceRejectsOversizedBlob` in [internal/services/sync_service_test.go](internal/services/sync_service_test.go); `TestServerRejectsOversizedBlobByConfiguredLimit` in [internal/api/server_test.go](internal/api/server_test.go) |
| Invalid recovery-key packages (unsupported algorithm, malformed fields, wrong word count) are rejected | `TestSyncServiceRejectsInvalidRecoveryKeyPackage` in [internal/services/sync_service_test.go](internal/services/sync_service_test.go) |
| The device limit is enforced | `TestSyncServiceEnforcesDeviceLimit` in [internal/services/sync_service_test.go](internal/services/sync_service_test.go) |

### Managed Bridge

| Claim | Enforced by |
| --- | --- |
| `POST /managed/session` is disabled unless `MANAGED_BRIDGE_TOKEN` is configured; requests without the bearer are refused | `TestServerRejectsManagedBridgeWhenDisabled` in [internal/api/server_test.go](internal/api/server_test.go) |
| A valid bridge token issues a managed session that authenticates against `/sync/capabilities` | `TestServerIssuesManagedBridgeSession` in [internal/api/server_test.go](internal/api/server_test.go) |
| The bridge rejects too-short account IDs | `TestManagedBridgeRejectsInvalidAccountID` in [internal/services/managed_bridge_service_test.go](internal/services/managed_bridge_service_test.go) |
| The bridge rejects reuse of an existing self-hosted account ID | `TestManagedBridgeRejectsExistingSelfHostedAccount` in [internal/services/managed_bridge_service_test.go](internal/services/managed_bridge_service_test.go) |
| Bridge-provisioned sessions carry `mode=managed` with `premium_active` from the account row | `TestAuthServiceCreatesManagedSessionForExistingAccount` in [internal/services/auth_service_test.go](internal/services/auth_service_test.go) |

### No Premium Entitlement Logic (Community Mode)

| Claim | Enforced by |
| --- | --- |
| Self-hosted capabilities always report `mode=self_hosted`, `premium_active=false` | `TestSyncServiceCapabilitiesStaySelfHosted` in [internal/services/sync_service_test.go](internal/services/sync_service_test.go) |
| Managed accounts with an inactive subscription report `sync_enabled=false`, `premium_active=false` | `TestSyncServiceManagedInactiveAccountDisablesSync` in [internal/services/sync_service_test.go](internal/services/sync_service_test.go) |
| Managed accounts with `premium_active=true` report `sync_enabled=true` | `TestSyncServiceCapabilitiesForManagedAccount` in [internal/services/sync_service_test.go](internal/services/sync_service_test.go); `TestServerIssuesManagedBridgeSession` in [internal/api/server_test.go](internal/api/server_test.go) |

### Metrics and Transport

| Claim | Enforced by |
| --- | --- |
| `/metrics` is absent when disabled and requires the bearer token when configured | `TestServerMetricsEndpointReturnsNotFoundWhenDisabled`, `TestServerMetricsEndpointRequiresBearerTokenWhenConfigured`, `TestServerMetricsEndpointReturnsPrometheusPayload` in [internal/api/server_test.go](internal/api/server_test.go) |
| Baseline hardening headers (`Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`) are asserted on unauthenticated responses | `TestServerUnauthorizedSyncAccess` in [internal/api/server_test.go](internal/api/server_test.go) |
| CORS allows a configured origin on preflight and rejects unknown origins | `TestServerAllowsConfiguredOriginPreflight`, `TestServerRejectsUnknownOriginPreflight` in [internal/api/server_test.go](internal/api/server_test.go) |

### Policy-Level Claims (Human-Reviewed, Exempt from the Matrix)

- Secrets, tokens, recovery codes, login identifiers, and blob contents are
  never written to logs. Enforced by code review, not by a single unit test.
- The HKDF labels and the TOTP AAD prefix are pinned by the implementation;
  changing them invalidates stored secrets and is treated as a breaking change.
- The `FIELD_ENCRYPTION_KEY` rotation contract (see Accepted Residual Risks)
  is an operator-facing policy, not a runtime behavior.

### Planned Regressions (Known Coverage Gaps)

Test-enforceable claims that currently rely on implementation review; each is
a planned dedicated regression:

- A consumed TOTP time step is rejected on replay (atomic `totp_last_used_step`
  CAS) — the end-to-end flow waits for a fresh step instead of asserting the
  rejection directly.
- The exact production TOTP AAD string binds ciphertexts to the account row.
- Raw session tokens never reach the `sessions` table (hash-only persistence).
- Recovery codes are persisted only as bcrypt hashes.
- `POST /auth/login` never returns a session token and a TOTP challenge in the
  same response (both directions).
- The auth-endpoint JSON body-size ceiling is enforced at the documented limit.
- TOTP challenges expire after their TTL (clock-advancing unit test).
- `premium_active` cannot be set on a self-hosted account through any public
  endpoint (bridge-only write path).
