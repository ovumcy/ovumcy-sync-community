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
self-hosted accounts always register with `premium_active=false`. When a
managed account's entitlement lapses, the bridge's lifecycle signal
(`POST /managed/accounts/{account_id}/premium`) records the lapse and
revokes sync access immediately, but the account's own encrypted data is
retained for a grace period (data minimization, not a security boundary —
see *Managed Bridge* below and the entitlement-lapse grace-period bullet
under *Accepted Residual Risks*) rather than erased on the spot, so a
resubscribe within the grace period never loses the device's encrypted
snapshot.

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
  the next login until they sign in with a recovery code and re-enroll. Operator
  responsibility, documented rather than defended at runtime.
- **Timing-equalization tests assert call counts, not wall-clock latency.**
  The guarded property is "equalizing bcrypt work runs on every early-return
  path"; wall-clock assertions would be flaky on shared CI.
- **Transitional bcrypt-cost skew for pre-upgrade accounts.** Hashes created
  before the cost-12 bump verify at their embedded cost 10, so until such an
  account's next successful login (which transparently re-hashes it at cost
  12), a wrong-password attempt against it burns less bcrypt work than the
  cost-12 equalization placeholder — a bounded window in which pre-upgrade
  accounts are timing-distinguishable from unknown logins. Legacy
  recovery-code hashes converge on the next rotation (password reset or
  explicit regeneration) instead. Accepted as bounded and converging.
- **Registration reveals whether a login is taken.** A taken login answers
  `400 registration_failed`, distinct from success. Logins are self-chosen and
  registration has no channel to confirm one before answering, so it must
  refuse a taken login and say so; a fake success would hand out a session for
  an account that was never created. `Register` hashes the password before the
  insert, so a taken and a free login cost the same bcrypt work. The route is
  rate-limited per client IP only (there is no per-login bucket), and probing a
  free login creates that account. Login and forgot-password stay
  enumeration-safe.
- **`managed:` login namespace.** Public registration cannot claim the
  `managed:` prefix, while bridge-provisioned logins use it by design behind
  the `MANAGED_BRIDGE_TOKEN` gate.
- **Entitlement-lapse grace-period retention window.** After the managed
  bridge signals a lapse, this server keeps the account's `encrypted_blobs`,
  `recovery_key_packages`, `devices`, and shadow `accounts` row for
  `LAPSED_ACCOUNT_GRACE_PERIOD` (default 60 days, operator-tunable) before
  the in-process sweep (`LAPSED_ACCOUNT_SWEEP_INTERVAL`, default daily) or a
  manual `purge-lapsed-accounts` run erases them. This is a deliberate data-minimization
  trade-off, not a plaintext-exposure risk — the retained blobs are the same
  end-to-end-encrypted ciphertext an active account holds, this server never
  gains any additional ability to read them, and sync access itself is cut
  immediately at lapse (session revocation), not deferred to the grace
  period. The window exists solely so a resubscribe does not cost the device
  its encrypted snapshot. Community-mode (self-hosted, non-bridge) accounts
  are entirely unaffected: the lapse marker can only ever be set by the
  bridge, on a `mode=managed` account.

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

Account passwords and recovery codes are hashed with bcrypt at cost 12
(`PasswordHashCost` in `internal/security`). The login timing-equalization
placeholder is pinned to the same cost (see Timing Parity below), and a hash
stored at a lower legacy cost is transparently re-hashed at the current cost
on the account's next successful login.

| Claim | Enforced by |
| --- | --- |
| Passwords shorter than the minimum length are rejected | `TestHashPasswordRejectsWeakPassword` in [internal/security/security_test.go](internal/security/security_test.go) |
| Passwords over bcrypt's 72-byte input ceiling are rejected as weak (400, never a 500) on register, change, and reset | `TestHashPasswordRejectsPasswordOverBcryptByteLimit` in [internal/security/security_test.go](internal/security/security_test.go); `TestRegisterRejectsPasswordOverByteLimit`, `TestChangePasswordRejectsNewPasswordOverByteLimit` in [internal/services/auth_service_password_length_test.go](internal/services/auth_service_password_length_test.go); `TestServerRegisterRejectsInvalidRegistrationInput` in [internal/api/server_test.go](internal/api/server_test.go) |
| Minimum length counts Unicode runes, not UTF-8 bytes — matches `ovumcy-managed`'s `HashPassword` so the same password can't pass one backend and fail the other | `TestHashPasswordCountsRunesNotBytes` in [internal/security/security_test.go](internal/security/security_test.go) |
| Hash/compare round-trip succeeds and a wrong password is rejected | `TestHashPasswordAndCompare` in [internal/security/security_test.go](internal/security/security_test.go) |
| Freshly generated password and recovery-code hashes carry bcrypt cost 12 (`PasswordHashCost`) | `TestHashPasswordUsesConfiguredCost`, `TestNewRecoveryCodeUsesConfiguredCost` in [internal/security/security_test.go](internal/security/security_test.go) |
| Only parseable lower-cost hashes are flagged for rehash; current-cost and unparseable hashes are not | `TestPasswordHashNeedsRehash` in [internal/security/security_test.go](internal/security/security_test.go) |
| A successful login transparently upgrades a legacy lower-cost password hash to the current cost, on the session path and the TOTP-challenge path alike | `TestLoginRehashesLegacyLowerCostHash`, `TestLoginRehashesLegacyHashOnTOTPChallengePath` in [internal/services/auth_service_rehash_test.go](internal/services/auth_service_rehash_test.go) |
| Login succeeds even when the transparent rehash cannot produce a new hash | `TestLoginSucceedsWhenRehashCannotProduceNewHash` in [internal/services/auth_service_rehash_test.go](internal/services/auth_service_rehash_test.go) |
| The login rehash writes only while the stored hash still equals the one it verified, so a concurrent password change is never rolled back | `TestLoginRehashDoesNotRollBackAConcurrentPasswordChange` in [internal/services/auth_service_rehash_test.go](internal/services/auth_service_rehash_test.go), `TestUpgradeAccountPasswordHashRefusesAStaleVerifiedHash` in [internal/db/account_password_upgrade_test.go](internal/db/account_password_upgrade_test.go) |

### Login Normalization and Validation

| Claim | Enforced by |
| --- | --- |
| Login is lowercased and trimmed; inputs shorter than 3 chars are invalid; the reserved `managed:` prefix is rejected in any case | `TestNormalizeLoginAndValidateLogin` in [internal/security/security_test.go](internal/security/security_test.go) |
| Normalization is lowercase, trimmed, and idempotent over arbitrary inputs | `FuzzNormalizeLogin` in [internal/security/security_fuzz_test.go](internal/security/security_fuzz_test.go) |
| Any accepted login is ≥3 chars after normalization and never sits in the reserved `managed:` namespace | `FuzzValidateLogin` in [internal/security/security_fuzz_test.go](internal/security/security_fuzz_test.go) |
| A direct client cannot log in as a `managed:` identity — the login edge returns the generic invalid-credentials response, leaking nothing about which managed accounts exist | `TestServerLoginRefusesManagedPrefixIdentity` in [internal/api/server_test.go](internal/api/server_test.go) |

### Password Change

| Claim | Enforced by |
| --- | --- |
| Requires an authenticated session | `TestChangePasswordEndpointRequiresAuth` in [internal/api/auth_change_password_test.go](internal/api/auth_change_password_test.go) |
| Verifies the current password | `TestChangePasswordRejectsWrongCurrent` in [internal/services/auth_service_change_password_test.go](internal/services/auth_service_change_password_test.go); `TestChangePasswordEndpointRejectsWrongCurrent` in [internal/api/auth_change_password_test.go](internal/api/auth_change_password_test.go) |
| Rejects an unchanged new password | `TestChangePasswordRejectsSamePassword` in [internal/services/auth_service_change_password_test.go](internal/services/auth_service_change_password_test.go); `TestChangePasswordEndpointRejectsSamePassword` in [internal/api/auth_change_password_test.go](internal/api/auth_change_password_test.go) |
| Rejects a weak new password | `TestChangePasswordRejectsWeakNew` in [internal/services/auth_service_change_password_test.go](internal/services/auth_service_change_password_test.go); `TestChangePasswordEndpointRejectsWeakNew` in [internal/api/auth_change_password_test.go](internal/api/auth_change_password_test.go) |
| On success, revokes every session except the caller's | `TestChangePasswordSuccessRevokesOtherSessions` in [internal/services/auth_service_change_password_test.go](internal/services/auth_service_change_password_test.go); `TestChangePasswordEndpointSucceedsAndRevokesOtherSessions` in [internal/api/auth_change_password_test.go](internal/api/auth_change_password_test.go) |
| Deletes pending reset tokens so a previously issued reset token cannot be reused | `TestChangePasswordInvalidatesPendingResetToken` in [internal/services/auth_service_recovery_test.go](internal/services/auth_service_recovery_test.go) |
| Deletes pending TOTP login challenges, so one minted under the old password cannot complete into a session | `TestChangePasswordInvalidatesPendingTOTPChallenge` in [internal/services/auth_service_recovery_test.go](internal/services/auth_service_recovery_test.go) |

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
| A rejected new password leaves the reset token unconsumed for a corrected retry | `TestResetPasswordRejectedPasswordKeepsToken` in [internal/services/auth_service_password_length_test.go](internal/services/auth_service_password_length_test.go) |
| Reset clears the TOTP secret and pending challenges; the next login issues a regular session | `TestResetPasswordClearsTOTPAndPendingChallenges` in [internal/services/auth_service_recovery_test.go](internal/services/auth_service_recovery_test.go) |
| Recovery-code regeneration requires auth plus the current password | `TestRegenerateRecoveryCodeEndpointRequiresAuth`, `TestRegenerateRecoveryCodeEndpointRejectsWrongPassword` in [internal/api/auth_recovery_test.go](internal/api/auth_recovery_test.go); `TestRegenerateRecoveryCodeRejectsWrongPassword` in [internal/services/auth_service_recovery_test.go](internal/services/auth_service_recovery_test.go) |
| Recovery-code regeneration deletes pending reset tokens in the rotation's own transaction (one issued against the old code dies with it; a failed delete rolls the rotation back) and leaves sessions untouched | `TestRegenerateRecoveryCodeInvalidatesPendingResetToken` in [internal/services/auth_service_recovery_test.go](internal/services/auth_service_recovery_test.go); `TestRegenerateRecoveryCodeStoreErrors` in [internal/services/auth_service_fault_injection_test.go](internal/services/auth_service_fault_injection_test.go) |
| A reset token is written only while the account's recovery-code hash still equals the one the code was verified against, so a rotation racing forgot-password leaves no token behind | `TestUpsertPasswordResetTokenRequiresVerifiedRecoveryHash` in [internal/db/fault_injection_test.go](internal/db/fault_injection_test.go) |
| Recovery-code regeneration rotates the code; the old code stops working | `TestRegenerateRecoveryCodeRotatesCode` in [internal/services/auth_service_recovery_test.go](internal/services/auth_service_recovery_test.go); `TestRegenerateRecoveryCodeEndpointSucceeds` in [internal/api/auth_recovery_test.go](internal/api/auth_recovery_test.go) |
| Recovery-code normalization is idempotent over arbitrary inputs | `FuzzNormalizeRecoveryCode` in [internal/security/security_fuzz_test.go](internal/security/security_fuzz_test.go) |
| Recovery codes are persisted only as verifying bcrypt hashes — never the plaintext (proven against the database file through an independent raw connection) | `TestSessionTokensAndRecoveryCodesPersistOnlyAsHashes` in [internal/api/planned_regressions_test.go](internal/api/planned_regressions_test.go) |

### Timing Parity (CWE-208)

| Claim | Enforced by |
| --- | --- |
| Login on an unknown login performs equalizing bcrypt work | `TestLoginEqualizesTimingForUnknownLogin` in [internal/services/auth_service_timing_test.go](internal/services/auth_service_timing_test.go) |
| Forgot-password on an unknown login performs equalizing bcrypt work | `TestForgotPasswordEqualizesTimingForUnknownLogin` in [internal/services/auth_service_timing_test.go](internal/services/auth_service_timing_test.go) |
| Forgot-password with no stored recovery hash performs equalizing bcrypt work | `TestForgotPasswordEqualizesTimingWhenRecoveryCodeUnset` in [internal/services/auth_service_timing_test.go](internal/services/auth_service_timing_test.go) |
| The equalization placeholder hash stays bcrypt-compatible | `TestPasswordTimingEqualizationHashIsBcryptCompatible` in [internal/services/auth_service_timing_test.go](internal/services/auth_service_timing_test.go) |
| The equalization placeholder's bcrypt cost equals the real hashing cost (`PasswordHashCost`) | `TestPasswordTimingEqualizationHashCostMatchesPasswordHashCost` in [internal/services/auth_service_timing_test.go](internal/services/auth_service_timing_test.go) |

### Sessions

| Claim | Enforced by |
| --- | --- |
| Session tokens are opaque; plaintext differs from the stored hash, and `HashToken` is stable SHA-256 hex | `TestTokenHelpersReturnOpaqueValues`, `TestHashTokenIsStableLowerLevelHelper` in [internal/security/security_test.go](internal/security/security_test.go) |
| Revoked sessions are rejected | `TestAuthServiceRevokesSession` in [internal/services/auth_service_test.go](internal/services/auth_service_test.go); `TestServerRevokesSession` in [internal/api/server_test.go](internal/api/server_test.go) |
| Empty and expired sessions are rejected | `TestAuthServiceRejectsEmptyAndExpiredSession` in [internal/services/auth_service_test.go](internal/services/auth_service_test.go) |
| Self-hosted registration creates `mode=self_hosted`, `premium_active=false` accounts | `TestAuthServiceRegisterAndLogin` in [internal/services/auth_service_test.go](internal/services/auth_service_test.go) |
| Login on a TOTP-enabled account fails closed when the field key is absent — no password-only session | `TestAuthServiceLoginFailsClosedWhenTOTPEnabledButNoIssuer` in [internal/services/auth_service_test.go](internal/services/auth_service_test.go); `TestTOTPNotConfiguredWhenServerHasNoFieldKey` in [internal/api/auth_totp_test.go](internal/api/auth_totp_test.go) |
| Raw session tokens never reach the `sessions` table — no column carries the issued token, and `token_hash` is exactly `security.HashToken` of it (proven against the database file through an independent raw connection) | `TestSessionTokensAndRecoveryCodesPersistOnlyAsHashes` in [internal/api/planned_regressions_test.go](internal/api/planned_regressions_test.go) |
| A session alone cannot delete the account: `DELETE /account` re-checks the current password (wrong or absent `current_password` → 401 `invalid_current_password`; no JSON body → 400 `invalid_json`) and a refused attempt leaves the account, session, and login intact; managed accounts, which have no password, are exempt — a stolen managed session can still delete its account, since a bridge re-mint does not revoke earlier sessions | `TestConfirmCurrentPassword`, `TestConfirmCurrentPasswordPassesManagedAccount` in [internal/services/auth_service_confirm_password_test.go](internal/services/auth_service_confirm_password_test.go); `TestDeleteAccountEndpointRequiresCurrentPassword` in [internal/api/account_delete_test.go](internal/api/account_delete_test.go) |
| A session alone cannot overwrite the wrapped recovery key: `PUT /sync/recovery-key` re-checks the current password and a refused write stores nothing | `TestPutRecoveryKeyRequiresCurrentPassword` in [internal/api/server_test.go](internal/api/server_test.go) |

### Two-Factor Authentication (TOTP)

| Claim | Enforced by |
| --- | --- |
| TOTP secrets are sealed with AES-256-GCM; round-trip works, wrong AAD and wrong key fail to open | `TestEncryptFieldRoundtrip`, `TestDecryptFieldRejectsWrongAAD`, `TestDecryptFieldRejectsWrongKey` in [internal/security/field_crypto_test.go](internal/security/field_crypto_test.go) |
| Encryption requires key and AAD; ciphertexts are non-deterministic | `TestEncryptFieldRequiresKeyAndAAD`, `TestEncryptFieldProducesDifferentCiphertextEachCall` in [internal/security/field_crypto_test.go](internal/security/field_crypto_test.go) |
| Round-trip and AAD binding hold over generated and fuzzed inputs | `TestFieldCryptoRoundTripProperty`, `TestFieldCryptoAADBindingProperty` in [internal/security/security_property_test.go](internal/security/security_property_test.go); `FuzzFieldCryptoRoundTrip` in [internal/security/security_fuzz_test.go](internal/security/security_fuzz_test.go) |
| 2FA endpoints are disabled (503) when `FIELD_ENCRYPTION_KEY` is absent | `TestTOTPNotConfiguredWhenServerHasNoFieldKey` in [internal/api/auth_totp_test.go](internal/api/auth_totp_test.go) |
| Enrollment requires the current password; completion rejects a wrong code; login with 2FA returns a challenge and no session token; the challenge is single-use; disable requires password and a correct code | `TestTOTPEnrollVerifyDisableEndToEnd` in [internal/api/auth_totp_test.go](internal/api/auth_totp_test.go) |
| A challenge burns after five wrong codes; a correct code does not reopen it | `TestTOTPChallengeBurnsAfterFiveWrongCodes` in [internal/api/auth_totp_test.go](internal/api/auth_totp_test.go) |
| Code attempts are capped per account at 10 per 15-minute window across every challenge and disable: logging in again does not reset the count, the eleventh attempt (a correct code included) answers 429 `rate_limited` with `Retry-After` at the window's end, and only a successful verify, a completed (re-)enrollment, or the window ending clears it. The attempt is reserved in one upsert before the code is checked, so concurrent guesses cannot exceed the cap | `TestReLoginCannotResetTheAccountTOTPBudget`, `TestAccountTOTPWindowEndsAndSuccessClearsIt`, `TestCompletedEnrollmentClearsASpentWindow`, `TestConcurrentDisableGuessesSpendExactlyTheAccountCap`, `TestDisableSharesTheAccountTOTPWindow` in [internal/services/totp_failure_window_test.go](internal/services/totp_failure_window_test.go); `TestConcurrentReserveTOTPAttemptNeverExceedsTheCap` in [internal/db/totp_failure_window_test.go](internal/db/totp_failure_window_test.go); `TestTOTPChallengeLocksTheAccountAcrossLogins` in [internal/api/auth_totp_lockout_test.go](internal/api/auth_totp_lockout_test.go) |
| An invalid challenge id returns a generic error | `TestTOTPChallengeWithInvalidIDReturnsGenericError` in [internal/api/auth_totp_test.go](internal/api/auth_totp_test.go) |
| Re-enrollment while TOTP is enabled returns a conflict | `TestTOTPEnrollRejectsWhenAlreadyEnabled` in [internal/api/auth_totp_test.go](internal/api/auth_totp_test.go) |
| A consumed TOTP step is rejected on replay (atomic `totp_last_used_step` CAS): the step claimed at enrollment survives the enable flip, so the same enrollment code cannot re-verify on the login challenge or disable; a fresh enrollment resets the step so a new secret's first code still verifies | `TestCompleteEnrollmentStepSurvivesEnableSoLoginChallengeCannotReplay`, `TestCompleteEnrollmentStepSurvivesEnableSoDisableCannotReplay`, `TestFreshStartEnrollmentResetsStaleStepClaim`, `TestLoginChallengeSucceedsOnAFreshStep` in [internal/services/totp_service_test.go](internal/services/totp_service_test.go) |
| Secrets are 160-bit; base32 round-trips; code generation matches RFC 6238 vectors; only current and adjacent steps verify; empty codes are rejected; the provisioning URI carries secret and issuer | `TestNewTOTPSecretIs160Bits`, `TestEncodeDecodeBase32Roundtrip`, `TestGenerateTOTPCodeIsRFC6238TestVector`, `TestVerifyTOTPCodeAcceptsCurrentAndAdjacentSteps`, `TestVerifyTOTPCodeRejectsFarFutureAndPastSteps`, `TestVerifyTOTPCodeRejectsEmpty`, `TestBuildTOTPProvisioningURIIncludesSecretAndIssuer` in [internal/security/totp_test.go](internal/security/totp_test.go) |
| Generate/verify, skew window, and base32 round-trip hold over generated inputs | `TestTOTPGenerateVerifyProperty`, `TestTOTPSkewWindowProperty`, `TestTOTPBase32RoundTripProperty` in [internal/security/security_property_test.go](internal/security/security_property_test.go) |
| Secret decoding never panics; accepted secrets survive canonical re-encoding | `FuzzDecodeTOTPSecretBase32` in [internal/security/security_fuzz_test.go](internal/security/security_fuzz_test.go) |
| The exact production TOTP AAD string (`ovumcy.sync-community.field.totp_secret:<account_id>`) is pinned literally — a drive-by constant edit fails the tripwire instead of silently invalidating every stored secret | `TestAADForTOTPSecretPinsTheExactProductionString` in [internal/services/totp_planned_regressions_test.go](internal/services/totp_planned_regressions_test.go) |
| A challenge one second past `TOTPChallengeTTL` is rejected even with a code valid for the later instant — expiry alone is terminal | `TestVerifyChallengeRejectsAnExpiredChallenge` in [internal/services/totp_planned_regressions_test.go](internal/services/totp_planned_regressions_test.go) |
| `POST /auth/login` never returns a session token and a TOTP challenge in one response, pinned in both directions (plain account: session and no challenge; TOTP account: challenge and empty session field) | `TestLoginNeverReturnsSessionTokenAlongsideTOTPChallenge` in [internal/api/planned_regressions_test.go](internal/api/planned_regressions_test.go) |

### Rate Limiting

| Claim | Enforced by |
| --- | --- |
| The limiter allows up to the configured count, then resets after the window | `TestRateLimiterResetsAfterWindow` in [internal/security/security_test.go](internal/security/security_test.go) |
| Expired entries are swept, so the limiter map does not leak keys for the process lifetime | `TestRateLimiterSweepsExpiredEntries` in [internal/security/security_test.go](internal/security/security_test.go) |
| Map size stays bounded by the current window's keys plus one sweep interval across many unique keys over multiple windows | `TestRateLimiterBoundsMapAcrossManyWindows` in [internal/security/security_test.go](internal/security/security_test.go) |
| The sweep never evicts an in-window entry, so a throttled key cannot be flushed to reset its counter | `TestRateLimiterSweepPreservesInWindowEntries` in [internal/security/security_test.go](internal/security/security_test.go) |
| Anonymous auth endpoints are rate-limited per route and client IP; excess requests receive `rate_limited` | `TestServerRateLimitsAuthEndpoints`, `TestServerRegisterRateLimitedPerClientIP` in [internal/api/server_test.go](internal/api/server_test.go) |
| Authenticated mutating routes and the ciphertext reads (`GET /sync/blob`, `GET /sync/recovery-key`) are rate-limited per account at the `AUTH_RATE_LIMIT_COUNT` budget, not the 30× read-state budget; device removal uses a stable route key, so the path id cannot open fresh buckets | `TestServerAttachDeviceRateLimitedPerAccount`, `TestServerPutRecoveryKeyRateLimitedPerAccount` in [internal/api/server_test.go](internal/api/server_test.go), `TestSyncReadEndpointsAreRateLimitedPerAccount` in [internal/api/read_rate_limit_test.go](internal/api/read_rate_limit_test.go), `TestRemoveDeviceRateLimitedPerAccount` in [internal/api/device_management_test.go](internal/api/device_management_test.go) |
| `X-Forwarded-For` is honored only from a trusted-proxy CIDR | `TestServerAuthRateLimitUsesForwardedClientFromTrustedProxy` in [internal/api/server_test.go](internal/api/server_test.go) |
| The forwarded client IP is the rightmost address not in `TRUSTED_PROXY_CIDRS`, so a client cannot spoof its rate-limit bucket by prepending `X-Forwarded-For` entries | `TestServerAuthRateLimitResistsForwardedSpoofingBehindTrustedProxy` in [internal/api/server_test.go](internal/api/server_test.go) |
| `X-Real-IP` is never read, even from a trusted proxy whose forwarded chain is all trusted hops; every `X-Forwarded-For` header line is considered | `TestClientIPIgnoresXRealIPFromTrustedProxy`, `TestClientIPConsidersEveryForwardedForHeaderLine` in [internal/api/client_ip_test.go](internal/api/client_ip_test.go) |
| An IPv6 client is keyed by its /64, so one subscriber's prefix cannot mint a bucket per address | `TestClientIPKeysIPv6ByNetwork64` in [internal/api/client_ip_test.go](internal/api/client_ip_test.go) |
| `TRUSTED_PROXY_CIDRS` refuses an over-broad prefix at startup — IPv4 wider than /8, IPv6 wider than /32 (unique-local wider than /8), so `0.0.0.0/0` and `::/0` fail — and unmaps IPv4-mapped entries so they match unmapped peers | `TestParseTrustedProxyCIDRRejectsOverBroadPrefixes`, `TestParseTrustedProxyCIDRUnmapsIPv4MappedEntries`, `TestLoadRejectsOverBroadTrustedProxyCIDR` in [internal/config/config_test.go](internal/config/config_test.go) |
| An unparseable `X-Forwarded-For` hop (a proxy's `unknown`) ends the walk, so the client's own entries left of it never become the key | `TestClientIPStopsAtUnparseableForwardedHop` in [internal/api/client_ip_test.go](internal/api/client_ip_test.go) |
| `X-Forwarded-For` from an untrusted peer is ignored; the raw peer address is the key | `TestServerIgnoresForwardedClientFromUntrustedRemoteAddr` in [internal/api/server_test.go](internal/api/server_test.go) |
| The resolved client IP is canonical — IPv4-unmapped and zone-stripped — so one address cannot occupy several rate-limit buckets | `FuzzParseClientIP`, `FuzzForwardedClientIP` in [internal/api/client_ip_fuzz_test.go](internal/api/client_ip_fuzz_test.go) |
| Login attempts share one quota per normalized login identifier across all source IPs, so a distributed brute force cannot multiply per-account attempts by rotating addresses | `TestServerLoginRateLimitsPerIdentifierAcrossClientIPs` in [internal/api/server_test.go](internal/api/server_test.go) |
| The login-identifier quota charges only failed logins (a login that issues a session refunds its slot), and proving the recovery code via forgot-password clears it, so a victim locked out by someone else's failures has an unblock path; a failed forgot-password clears nothing | `TestLoginIdentifierBucketChargesOnlyFailures`, `TestForgotPasswordClearsLoginIdentifierLockout`, `TestFailedForgotPasswordKeepsLoginIdentifierLockout` in [internal/api/login_identifier_limit_test.go](internal/api/login_identifier_limit_test.go); `TestRateLimiterRefundAndReset` in [internal/security/security_test.go](internal/security/security_test.go) |
| A blank login skips the identifier bucket without consuming a slot and still returns the generic invalid-credentials error, so the limiter cannot turn an empty submission into a distinguishable response | `TestServerLoginWithBlankLoginReturnsGenericInvalidCredentials` in [internal/api/server_test.go](internal/api/server_test.go) |
| The authenticated read-only account-state routes (`GET /auth/session`, `GET /sync/capabilities`, `GET /sync/devices`) carry a per-account ceiling, so a valid session cannot drive session lookups and device queries without bound | `TestSessionStateReadsAreRateLimitedPerAccount` in [internal/api/read_rate_limit_test.go](internal/api/read_rate_limit_test.go) |
| That ceiling is keyed on the authenticated account, not the client address: the same account throttled at one address stays throttled at another, while a second account keeps its own budget from the address that exhausted the first | `TestSessionStateReadsKeyOnAccountNotClientIP` in [internal/api/read_rate_limit_test.go](internal/api/read_rate_limit_test.go) |
| The read-state budget is a fixed multiple of `AUTH_RATE_LIMIT_COUNT` — 300 per minute per account per route at the default — so one dial moves every bucket and no arithmetic edge case can invert it into a stricter one | `TestSessionReadRateLimitCountDerivesFromAuthBudget` in [internal/api/read_rate_limit_test.go](internal/api/read_rate_limit_test.go) |
| `DELETE /auth/session` is rate-limited per client IP ahead of the store — it consumes the bearer token rather than authenticating through it, so no account identity exists to key on — and another client address keeps a budget of its own | `TestLogoutIsRateLimitedPerClientIP` in [internal/api/read_rate_limit_test.go](internal/api/read_rate_limit_test.go) |
| `GET /healthz` and `GET /readyz` are deliberately never rate-limited, so a container healthcheck or uptime monitor polling on a fixed interval cannot be throttled into reporting an outage | `TestHealthAndReadinessProbesAreNotRateLimited` in [internal/api/read_rate_limit_test.go](internal/api/read_rate_limit_test.go) |

### Zero-Knowledge Blob Handling

| Claim | Enforced by |
| --- | --- |
| Uploaded blob ciphertext is returned byte-for-byte without server interpretation | `TestSyncServiceAttachDeviceAndBlobRoundTrip` in [internal/services/sync_service_test.go](internal/services/sync_service_test.go); `TestServerRegisterLoginAndSyncFlow` in [internal/api/server_test.go](internal/api/server_test.go) |
| Checksum mismatch is rejected | `TestSyncServiceRejectsChecksumMismatchAndStaleGeneration` in [internal/services/sync_service_test.go](internal/services/sync_service_test.go) |
| Stale or regressing blob generations are rejected | `TestSyncServiceRejectsChecksumMismatchAndStaleGeneration` in [internal/services/sync_service_test.go](internal/services/sync_service_test.go); `TestServerRejectsStaleBlobGeneration` in [internal/api/server_test.go](internal/api/server_test.go) |
| A blob generation more than 15 minutes ahead of server time is rejected, and the bound moves with the clock, so no accepted generation can ever strand an owner's blob at an unbeatable value, and one parked at the ceiling by a since-revoked session blocks the owner's writes for at most 15 minutes (a generation stored under the earlier 24-hour cap still blocks until the clock passes it) | `TestPutBlobGenerationCeilingIsFifteenMinutes`, `TestPutBlobRejectsGenerationFarAheadOfServerTime`, `TestPutBlobHasNoTerminalGeneration`, `TestPutBlobParkedGenerationLockOutIsBounded`, `TestPutBlobStillRejectsStaleGenerationWithinTheBound` in [internal/services/sync_service_blob_generation_test.go](internal/services/sync_service_blob_generation_test.go) |
| Concurrent equal-generation writes collapse to exactly one winner (CAS) | `TestSyncServicePutBlobConcurrentEqualGenerationCollapsesToOneWinner` in [internal/services/sync_service_test.go](internal/services/sync_service_test.go) |
| The first write succeeds at generation 1 (the CAS predicate does not block the initial insert) | `TestSyncServicePutBlobFirstWriteSucceeds` in [internal/services/sync_service_test.go](internal/services/sync_service_test.go) |
| Oversized blobs are rejected by the configured limit | `TestSyncServiceRejectsOversizedBlob` in [internal/services/sync_service_test.go](internal/services/sync_service_test.go); `TestServerRejectsOversizedBlobByConfiguredLimit` in [internal/api/server_test.go](internal/api/server_test.go) |
| Invalid recovery-key packages (unsupported algorithm, malformed fields, wrong word count) are rejected | `TestSyncServiceRejectsInvalidRecoveryKeyPackage` in [internal/services/sync_service_test.go](internal/services/sync_service_test.go) |
| The device limit is enforced | `TestSyncServiceEnforcesDeviceLimit` in [internal/services/sync_service_test.go](internal/services/sync_service_test.go) |
| Concurrent attaches cannot push an account past the device limit — the ceiling is a predicate inside the insert statement, not a separate count | `TestConcurrentAttachDeviceNeverExceedsMaxDevices` in [internal/services/sync_service_device_test.go](internal/services/sync_service_device_test.go) |
| Re-attaching a device the account already owns refreshes its row instead of consuming a slot, so it stays allowed at the ceiling | `TestAttachDeviceAtCeilingStillRefreshesAnOwnedDevice` in [internal/services/sync_service_device_test.go](internal/services/sync_service_device_test.go) |
| Device list and removal are account-scoped — one account can neither see nor remove another account's devices | `TestListDevicesIsAccountScoped`, `TestRemoveDeviceIsAccountScopedNoIDOR` in [internal/services/sync_service_device_test.go](internal/services/sync_service_device_test.go) |
| Sessions are device-scoped: `POST /sync/devices` binds the calling session to the device once (a later attach never moves it), and removing a device revokes every session of that account bound to it in the same transaction — the remover's own included; unbound sessions and other accounts' sessions on the same device id are untouched | `TestDeleteDeviceRevokesOnlySessionsBoundToIt`, `TestBindSessionToDeviceIsOnceAndAccountScoped`, `TestDeleteDeviceRollsBackWhenSessionRevocationFails` in [internal/db/session_device_binding_test.go](internal/db/session_device_binding_test.go); `TestRemoveDeviceRevokesTheSessionThatAttachedIt` in [internal/services/sync_service_session_binding_test.go](internal/services/sync_service_session_binding_test.go); `TestListAndRemoveDeviceRoundTrip`, `TestRemovingOwnDeviceEndsTheCallingSession` in [internal/api/device_management_test.go](internal/api/device_management_test.go) |

### Managed Bridge

| Claim | Enforced by |
| --- | --- |
| `POST /managed/session` is disabled unless `MANAGED_BRIDGE_TOKEN` is configured; requests without the bearer are refused | `TestServerRejectsManagedBridgeWhenDisabled` in [internal/api/server_test.go](internal/api/server_test.go) |
| A set `MANAGED_BRIDGE_TOKEN` shorter than 32 bytes (after trimming) is a startup error | `TestLoadSurfacesEveryValidationAndParseError` in [internal/config/load_test.go](internal/config/load_test.go) |
| A valid bridge token issues a managed session that authenticates against `/sync/capabilities` | `TestServerIssuesManagedBridgeSession` in [internal/api/server_test.go](internal/api/server_test.go) |
| The bridge rejects too-short account IDs | `TestManagedBridgeRejectsInvalidAccountID` in [internal/services/managed_bridge_service_test.go](internal/services/managed_bridge_service_test.go) |
| The bridge rejects reuse of an existing self-hosted account ID | `TestManagedBridgeRejectsExistingSelfHostedAccount` in [internal/services/managed_bridge_service_test.go](internal/services/managed_bridge_service_test.go) |
| Bridge-provisioned sessions carry `mode=managed` with `premium_active` from the account row | `TestAuthServiceCreatesManagedSessionForExistingAccount` in [internal/services/auth_service_test.go](internal/services/auth_service_test.go) |
| `DELETE /managed/accounts/{account_id}` is disabled unless `MANAGED_BRIDGE_TOKEN` is configured and refuses a missing or wrong bearer | `TestServerRejectsManagedAccountPurgeWhenDisabled`, `TestServerManagedAccountPurgeRejectsWrongBridgeToken` in [internal/api/managed_account_purge_test.go](internal/api/managed_account_purge_test.go) |
| The bridge purge erases every row held for a managed account — including `encrypted_blobs` — in one transaction | `TestServerManagedAccountPurgeCascades` in [internal/api/managed_account_purge_test.go](internal/api/managed_account_purge_test.go); `TestManagedBridgePurgeErasesBlobDeviceAndSessionThenIsIdempotent` in [internal/services/managed_bridge_service_test.go](internal/services/managed_bridge_service_test.go) |
| The bridge purge is idempotent: a repeat purge and a never-existed account id both report success | `TestServerManagedAccountPurgeIsIdempotent` in [internal/api/managed_account_purge_test.go](internal/api/managed_account_purge_test.go); `TestManagedBridgePurgeUnknownAccountIsIdempotentNoOp` in [internal/services/managed_bridge_service_test.go](internal/services/managed_bridge_service_test.go) |
| The bridge purge refuses to erase a self-hosted account and leaves its rows untouched | `TestManagedBridgePurgeRefusesSelfHostedAccount` in [internal/services/managed_bridge_service_test.go](internal/services/managed_bridge_service_test.go); `TestServerManagedAccountPurgeRefusesSelfHostedAccount` in [internal/api/managed_account_purge_test.go](internal/api/managed_account_purge_test.go) |
| `POST /managed/accounts/{account_id}/premium` is disabled unless `MANAGED_BRIDGE_TOKEN` is configured and refuses a missing or wrong bearer | `TestServerRejectsManagedAccountPremiumWhenDisabled`, `TestServerManagedAccountPremiumRejectsWrongBridgeToken` in [internal/api/managed_account_premium_test.go](internal/api/managed_account_premium_test.go) |
| `active=false` records `lapsed_at`, clears `premium_active`, and immediately revokes every still-valid session on the account (no entitlement, no sync); replaying the same signal is idempotent and never pushes `lapsed_at` forward | `TestSetAccountLapsedRecordsMarkerPreservesOnReplayAndScopesToManaged` in [internal/db/repositories_test.go](internal/db/repositories_test.go); `TestSetAccountLapseSignalRecordsLapseRevokesSessionsAndReplayIsIdempotent` in [internal/services/managed_bridge_service_test.go](internal/services/managed_bridge_service_test.go); `TestServerManagedAccountPremiumRecordsLapseRevokesSessionAndReplayIsIdempotent` in [internal/api/managed_account_premium_test.go](internal/api/managed_account_premium_test.go) |
| `active=true` (with a required `as_of`) is the only way back from a lapse: it clears the marker without touching `premium_active` or any session — restoring premium and issuing a session stay the mint path's job | `TestClearAccountLapseRetractsMarkerWithoutTouchingPremiumActive` in [internal/db/repositories_test.go](internal/db/repositories_test.go); `TestSetAccountLapseSignalActiveTrueRetractsWithoutTouchingSessionsOrPremium` in [internal/services/managed_bridge_service_test.go](internal/services/managed_bridge_service_test.go); `TestServerManagedAccountPremiumClearsMarker` in [internal/api/managed_account_premium_test.go](internal/api/managed_account_premium_test.go) |
| A session mint (`POST /managed/session`) never reverses a lapse: on a lapsed account it answers `409 managed_account_lapsed`, leaves `lapsed_at` and `premium_active=false` in place and issues no session; after a reactivation the next mint restores `premium_active` | `TestUpsertManagedAccountRefusesLapsedAccount` in [internal/db/repositories_test.go](internal/db/repositories_test.go); `TestCreateManagedSessionAfterLapseIsRefusedUntilReactivation` in [internal/services/managed_bridge_service_test.go](internal/services/managed_bridge_service_test.go); `TestServerManagedAccountPremiumReactivationThenMintReenablesSync` in [internal/api/managed_account_premium_test.go](internal/api/managed_account_premium_test.go) |
| Lapse and reactivation signals are ordered by the managed service's `as_of`: a reactivation must be strictly newer than the applied lapse, a lapse older than an applied reactivation changes nothing (`409 stale_entitlement_signal`), ties go to the lapse, a lapse without `as_of` is never stale, and an `as_of` more than 5 minutes ahead of this server's clock is refused (`400 invalid_entitlement_signal`); the lapse write and its session revocation share one transaction | `TestApplyEntitlementSignalOrdersAndRevokesInOneTransaction` in [internal/db/repositories_test.go](internal/db/repositories_test.go); `TestSetAccountLapseSignalOrdersSignalsByAsOf`, `TestSetAccountLapseSignalRejectsInvalidSignal` in [internal/services/managed_bridge_service_test.go](internal/services/managed_bridge_service_test.go); `TestServerManagedAccountPremiumRejectsStaleReactivation`, `TestServerManagedAccountPremiumRejectsInvalidSignal` in [internal/api/managed_account_premium_test.go](internal/api/managed_account_premium_test.go) |
| `sync_enabled=false` is enforced, not only reported: every device, recovery-key and blob route answers `403 sync_disabled` for a session whose account reports it, while `GET /sync/capabilities` still answers | `TestServerSyncRoutesEnforceSyncDisabled` in [internal/api/managed_account_premium_test.go](internal/api/managed_account_premium_test.go) |
| The lapse signal refuses a self-hosted account and leaves it completely untouched; an unknown account id (either direction) is an idempotent no-op | `TestSetAccountLapseSignalRefusesSelfHostedAccount`, `TestSetAccountLapseSignalUnknownAccountIsIdempotentNoOp` in [internal/services/managed_bridge_service_test.go](internal/services/managed_bridge_service_test.go); `TestServerManagedAccountPremiumRefusesSelfHostedAccount`, `TestServerManagedAccountPremiumUnknownAccountIsIdempotentSuccess` in [internal/api/managed_account_premium_test.go](internal/api/managed_account_premium_test.go) |
| The `purge-lapsed-accounts` sweep deletes a managed account — every row it owns, including `encrypted_blobs` — only once `lapsed_at` is older than the configured grace period; an account still inside the grace window is left untouched | `TestLapsedAccountSweepServiceDeletesPastGraceSurvivesWithinGraceAndSkipsCommunityAccounts`, `TestLapsedAccountSweepServiceCutoffIsFixedForTheWholeRun` in [internal/services/lapsed_account_sweep_service_test.go](internal/services/lapsed_account_sweep_service_test.go); `TestListAndDeleteLapsedManagedAccountRespectCutoffAndManagedScope` in [internal/db/repositories_test.go](internal/db/repositories_test.go) |
| The sweep re-checks the lapse marker and grace cutoff INSIDE the same delete transaction as the erasure itself, so a reactivation racing the sweep always preserves the account and every row it owns — and the sweep reports the raced candidate as a benign skip, not an error | `TestDeleteLapsedManagedAccountRecheckInsideTransactionPreservesRacingMint` in [internal/db/repositories_test.go](internal/db/repositories_test.go); `TestLapsedAccountSweepServiceTreatsMintRacedCandidateAsBenignSkip` in [internal/services/lapsed_account_sweep_service_test.go](internal/services/lapsed_account_sweep_service_test.go) |
| A self-hosted (community-mode) account can never carry a lapse marker and can never be selected by the sweep, even by id — `SetAccountLapsed` itself refuses any non-managed account | `TestSetAccountLapsedRecordsMarkerPreservesOnReplayAndScopesToManaged`, `TestListAndDeleteLapsedManagedAccountRespectCutoffAndManagedScope` in [internal/db/repositories_test.go](internal/db/repositories_test.go); `TestLapsedAccountSweepServiceDeletesPastGraceSurvivesWithinGraceAndSkipsCommunityAccounts` in [internal/services/lapsed_account_sweep_service_test.go](internal/services/lapsed_account_sweep_service_test.go) |

### No Premium Entitlement Logic (Community Mode)

| Claim | Enforced by |
| --- | --- |
| Self-hosted capabilities always report `mode=self_hosted`, `premium_active=false` | `TestSyncServiceCapabilitiesStaySelfHosted` in [internal/services/sync_service_test.go](internal/services/sync_service_test.go) |
| Managed accounts with an inactive subscription report `sync_enabled=false`, `premium_active=false` | `TestSyncServiceManagedInactiveAccountDisablesSync` in [internal/services/sync_service_test.go](internal/services/sync_service_test.go) |
| Managed accounts with `premium_active=true` report `sync_enabled=true` | `TestSyncServiceCapabilitiesForManagedAccount` in [internal/services/sync_service_test.go](internal/services/sync_service_test.go); `TestServerIssuesManagedBridgeSession` in [internal/api/server_test.go](internal/api/server_test.go) |
| `premium_active` cannot be set through any public endpoint — the bridge premium route refuses a session bearer, and the flag stays `0` on disk after the ordinary public flows (bridge-only write path) | `TestPremiumActiveIsUntouchableThroughPublicEndpoints` in [internal/api/planned_regressions_test.go](internal/api/planned_regressions_test.go) |

### Metrics and Transport

| Claim | Enforced by |
| --- | --- |
| `/metrics` is absent when disabled and requires the bearer token when configured | `TestServerMetricsEndpointReturnsNotFoundWhenDisabled`, `TestServerMetricsEndpointRequiresBearerTokenWhenConfigured`, `TestServerMetricsEndpointReturnsPrometheusPayload` in [internal/api/server_test.go](internal/api/server_test.go) |
| Startup refuses `METRICS_ENABLED=true` without `METRICS_BEARER_TOKEN`, so `/metrics` is never served unauthenticated | `TestLoadRejectsMetricsWithoutBearerToken` in [internal/config/load_test.go](internal/config/load_test.go) |
| An invalid `FIELD_ENCRYPTION_KEY` is reported without quoting any character of it | `TestFieldEncryptionKeyFromEnvRejectsInvalidHexCharacters` in [internal/config/load_test.go](internal/config/load_test.go) |
| Every session-authenticated route passes a per-client-IP bucket before the session lookup; a valid session refunds its slot, so only failed lookups stay charged | `TestWithAuthRateLimitsFailedLookupsPerClientIP` in [internal/api/pre_auth_hardening_test.go](internal/api/pre_auth_hardening_test.go) |
| `POST /auth/totp/challenge` is rate-limited before it reports `totp_not_configured`, so configuration cannot be probed unmetered | `TestTOTPChallengeIsRateLimitedBeforeConfigurationCheck` in [internal/api/pre_auth_hardening_test.go](internal/api/pre_auth_hardening_test.go) |
| A JSON body followed by anything but whitespace (`{}`, `null`, a second value) is `invalid_json` | `TestDecodeJSONRejectsTrailingValues` in [internal/api/pre_auth_hardening_test.go](internal/api/pre_auth_hardening_test.go) |
| `purge-lapsed-accounts` refuses a database with pending migrations and changes nothing, rather than migrating it as a side effect | `TestRunPurgeLapsedAccountsRefusesUnmigratedDatabase`, `TestRunPurgeLapsedAccountsRefusesPendingMigrations` in [cmd/ovumcy-sync-community/purge_lapsed_accounts_test.go](cmd/ovumcy-sync-community/purge_lapsed_accounts_test.go) |
| Baseline hardening headers (`Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cache-Control: no-store`) are asserted on unauthenticated responses | `TestServerUnauthorizedSyncAccess` in [internal/api/server_test.go](internal/api/server_test.go) |
| CORS allows a configured origin on preflight and rejects unknown origins | `TestServerAllowsConfiguredOriginPreflight`, `TestServerRejectsUnknownOriginPreflight` in [internal/api/server_test.go](internal/api/server_test.go) |
| A handler panic is recovered into a clean `500 internal_error` instead of a dropped connection, and the recovery log entry carries only the panic value's type and length beside the stack trace — never the value itself, which can hold request-derived text | `TestServeWithPanicRecoveryReturns500`, `TestServeWithPanicRecoveryPassesThroughNormalResponse`, `TestServeWithPanicRecoveryDoesNotLogThePanicValue`, `TestPanicValueSummaryDescribesShapeOnly` in [internal/api/recovery_test.go](internal/api/recovery_test.go) |
| Request-derived values reaching a log line (method, path) carry nothing that steers a reader — the C0 range, DEL, the C1 range (whose U+009B is a bare CSI), and the Unicode format category (bidirectional overrides, zero-width joiners) are all stripped, so a caller can neither forge a log entry (CWE-117), nor drive the terminal an operator reads the log with, nor reorder how the entry is displayed | `TestSanitizeLogValueStripsControlCharacters` in [internal/api/recovery_test.go](internal/api/recovery_test.go) |
| The auth-endpoint JSON body ceiling sits at the documented 4 KiB — an oversized body is rejected as `invalid_json`, while a body under the cap reaches the credential check | `TestAuthEndpointJSONBodyCeilingIsEnforced` in [internal/api/planned_regressions_test.go](internal/api/planned_regressions_test.go) |

### Container Readiness (Fail-Closed)

The container `HEALTHCHECK` probes `GET /readyz`, not `GET /healthz`. Liveness
answers from a constant and consults nothing, so it cannot go red for the most
likely failure a self-hosted deployment has — a database that has become
unreadable. Readiness touches the store, and it applies the same
migration-name-set comparison that gates startup, so it also refuses a
database a newer image migrated out from under a still-running process.
`GET /healthz` is unchanged and remains the pure liveness answer for a proxy
or uptime check.

| Claim | Enforced by |
| --- | --- |
| The container healthcheck fails while readiness is unavailable, even though liveness answers `200` — the probe is bound to `/readyz` | `TestRunHealthcheckProbesReadinessNotLiveness` in [cmd/ovumcy-sync-community/healthcheck_test.go](cmd/ovumcy-sync-community/healthcheck_test.go) |
| Readiness turns `503 not_ready` once the database stops answering, while `/healthz` keeps returning `200` | `TestServerReadinessFailsWhenTheDatabaseIsUnusableWhileLivenessStaysOK` in [internal/api/server_test.go](internal/api/server_test.go) |
| The readiness check refuses a database ahead of this build, an uninitialized schema, and a store that no longer answers — it is the startup gate's set comparison, re-run per probe | `TestCheckReadyRefusesADatabaseAheadOfThisBuild`, `TestCheckReadyRefusesAnUninitializedSchema`, `TestCheckReadyFailsOnAClosedStore`, `TestCheckReadyPassesOnAMigratedDatabase` in [internal/db/migrations_schema_ahead_test.go](internal/db/migrations_schema_ahead_test.go) |

### Policy-Level Claims (Human-Reviewed, Exempt from the Matrix)

- Secrets, tokens, recovery codes, login identifiers, and blob contents are
  never written to logs. Enforced by code review, not by a single unit test.
- The HKDF labels are pinned by the implementation; changing them invalidates
  stored secrets and is treated as a breaking change. (The TOTP AAD string
  itself is now matrix-enforced — see the TOTP section.)
- The `FIELD_ENCRYPTION_KEY` rotation contract (see Accepted Residual Risks)
  is an operator-facing policy, not a runtime behavior.

### Planned Regressions (Known Coverage Gaps)

None currently — every previously listed gap has a dedicated regression in
the matrix above (sessions/recovery hash-only persistence, the literal TOTP
AAD pin, challenge TTL expiry, the login session/challenge mutual exclusion,
the auth body ceiling, and the bridge-only `premium_active` write path). New
test-enforceable claims that temporarily rely on implementation review get
listed here again.
