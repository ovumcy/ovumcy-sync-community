# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Extensive auth and security work has landed on `main` since `v0.2.0` and is not yet tagged.

### Added

- **TOTP two-factor authentication.** Optional owner 2FA — enrollment, a login second-factor challenge, and disable — gated on `FIELD_ENCRYPTION_KEY`, with challenge metrics exposed for operators.
- **Account recovery and password management.** Password change, recovery codes, and recovery-code-based password reset across the auth surface.
- **Authenticated account deletion.** `DELETE /account` erases every row the server holds for an account in a single transaction.
- **`GET /auth/session`** exposing the current `totp_enabled` state.

### Changed

- **Relicensed** from AGPL-3.0 to the PolyForm Noncommercial License 1.0.0.
- **Runtime image switched to distroless** to drop the vulnerable gnutls chain.
- Tightened auth rate-limit ceilings.

### Security

- Reject the reserved `managed:` login prefix on public registration.
- Fail closed on login when a TOTP-enrolled account has no encryption key — no silent single-factor downgrade.
- Equalize bcrypt timing on `Login` and `ForgotPassword` early-return paths (CWE-208).
- Bound the in-memory auth rate-limiter map with an amortized sweep of expired entries, so a sustained distributed attempt can no longer grow it without limit; in-window entries are never evicted, preserving throttling.
- Move blob generation-freshness into an atomic SQL compare-and-swap; make password-reset-token consumption atomic.
- Harden the TOTP login flow; annotate reviewed gosec findings (G202 in `DeleteAccount`, G505/G115 in TOTP).

### Internal

- Healthcheck self-probe plus container `HEALTHCHECK`; `govulncheck`, native fuzz, and advisory mutation (gremlins) CI lanes; fuzz and property tests for crypto, TOTP, and login/recovery helpers.
- Pinned the Go toolchain to 1.25.11 and bumped `golang.org/x/crypto` to v0.53.0 for advisories; made the Codecov upload non-blocking on pull requests.
- Added the `SECURITY.md` Test Enforcement Matrix; documented the optional TOTP second factor and the mutation/fuzz/property test stack.

## [0.2.0] - 2026-03-23

### Added

- Operator Prometheus metrics and post-release self-hosting documentation.

### Changed

- Hardened the self-hosted runtime and reverse-proxy handling.

## [0.1.0] - 2026-03-23

### Added

- Initial public release of `ovumcy-sync-community` — the encrypted sync community server: account registration and sign-in, hashed bearer sessions, device registration, a community capability document, wrapped recovery-key package storage, and encrypted blob upload/download.
- Public repository community metadata, split CI checks for branch protection, and an explicit browser-sync CORS origin allowlist.

[Unreleased]: https://github.com/ovumcy/ovumcy-sync-community/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ovumcy/ovumcy-sync-community/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ovumcy/ovumcy-sync-community/releases/tag/v0.1.0
