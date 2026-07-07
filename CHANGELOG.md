# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-07-07

A major auth, security-hardening, and supply-chain release since `v0.2.0`: optional TOTP 2FA, account recovery and password management, authenticated account deletion, signed release artifacts, and a substantially hardened CI and quality bar.

### Added

- **TOTP two-factor authentication.** Optional owner 2FA — enrollment, a login second-factor challenge, and disable — gated on `FIELD_ENCRYPTION_KEY`, with challenge metrics exposed for operators.
- **Account recovery and password management.** Password change, recovery codes, and recovery-code-based password reset across the auth surface.
- **Authenticated account deletion.** `DELETE /account` erases every row the server holds for an account in a single transaction.
- **`GET /auth/session`** exposing the current `totp_enabled` state.
- **Device management.** `GET /sync/devices` lists an account's attached devices and `DELETE /sync/devices/{device_id}` removes one (account-scoped, no IDOR), so reaching the device limit no longer forces deleting the whole account to free a slot.
- **Machine-readable OpenAPI 3.1 spec** (`openapi.yaml`) covering the full HTTP surface, plus a zero-knowledge boundary diagram in the README.

### Changed

- **Relicensed** from AGPL-3.0 to the PolyForm Noncommercial License 1.0.0.
- **Runtime image switched to distroless** to drop the vulnerable gnutls chain.
- Tightened auth rate-limit ceilings.
- **Compose baseline now binds to loopback by default.** `docker-compose.yml` publishes the service on `127.0.0.1:8080` instead of all host interfaces; use a `docker-compose.override.yml` to publish on `0.0.0.0` for remote/LAN access.

### Security

- Reject the reserved `managed:` login prefix on public registration.
- Fail closed on login when a TOTP-enrolled account has no encryption key — no silent single-factor downgrade.
- Equalize bcrypt timing on `Login` and `ForgotPassword` early-return paths (CWE-208).
- Bound the in-memory auth rate-limiter map with an amortized sweep of expired entries, so a sustained distributed attempt can no longer grow it without limit; in-window entries are never evicted, preserving throttling.
- Raise the bcrypt cost for password and recovery-code hashes from 10 to 12, regenerate the timing-equalization placeholder at the same cost so CWE-208 login-enumeration parity holds, and transparently re-hash legacy cost-10 password hashes on the next successful login (best-effort; a failed re-hash never fails the login).
- Preserve the claimed TOTP step when enabling 2FA so an enrollment code can no longer be replayed within its skew window. The enable transition previously reset `totp_last_used_step` to 0, letting the just-verified enrollment code re-authenticate on the login-challenge and disable paths; the enable flip now touches only the enabled flag while a fresh enrollment still resets the step (RFC 6238 §5.2).
- Move blob generation-freshness into an atomic SQL compare-and-swap; make password-reset-token consumption atomic.
- Harden the TOTP login flow; annotate reviewed gosec findings (G202 in `DeleteAccount`, G505/G115 in TOTP).
- Pin both Dockerfile base images (`golang`, `distroless/static-debian12`) by digest instead of tag alone, kept current by Dependabot's weekly `docker` update.
- Sign published release binaries. A `Release` workflow builds the `linux/amd64` and `linux/arm64` server binaries with the Dockerfile's flags, signs the `SHA256SUMS` manifest with keyless cosign, and attaches the binaries, manifest, signature, certificate, and SLSA build provenance to each GitHub Release. Verification steps for both release binaries and the container image are documented in [docs/self-hosting.md](docs/self-hosting.md).
- Recover from handler panics at the transport layer: a panic now returns a clean `500 internal_error` instead of a dropped connection, and is logged as a controlled, secret-free line (method + path only) rather than `net/http`'s default unbounded stack trace — keeping the no-secret-in-logs contract even on the failure path.

### Internal

- Added a `gitleaks` secret-scanning CI lane (full-history, on every PR, push to `main`, and weekly) with a `.gitleaks.toml` allowlist scaffold.
- Healthcheck self-probe plus container `HEALTHCHECK`; `govulncheck`, native fuzz, and advisory mutation (gremlins) CI lanes; fuzz and property tests for crypto, TOTP, and login/recovery helpers.
- Set the Go directive to 1.26.4 (parity with `ovumcy-web`) and bumped `golang.org/x/crypto` to v0.53.0 for advisories; made the Codecov upload non-blocking on pull requests.
- Added the `SECURITY.md` Test Enforcement Matrix; documented the optional TOTP second factor and the mutation/fuzz/property test stack.
- Run the CI `test` job with `go test -race` to catch data races in the concurrency-sensitive auth/session/CAS logic; `-covermode=atomic` retained as required alongside `-race`.
- Added a `golangci-lint` v2.12.2 CI gate (`.golangci.yml`, parallel `golangci-lint` job) alongside the existing `staticcheck` and `go vet` jobs; fixed the mechanical findings it surfaced (unchecked deferred `Close` errors, redundant `http.HandlerFunc` conversions, three-clause counting loops rewritten to `range`).
- Added a daily `fuzz-continuous` job to the `Fuzz` workflow that runs each native Go fuzz target for 10m with its generated corpus cached and restored between runs (`actions/cache`, keyed per target), so coverage accumulates instead of restarting from the seed corpus every time; the existing weekly 3m short pass is unchanged.
- Added an `oss-fuzz/` scaffold (`project.yaml`, `Dockerfile`, `build.sh`) following the `google/oss-fuzz` Go project layout. This is preparation only — see [`oss-fuzz/ONBOARDING.md`](oss-fuzz/ONBOARDING.md); OSS-Fuzz does not run against this repository until a maintainer opens a separate PR against `google/oss-fuzz` and Google accepts it.
- Moved workflow write permissions to the job level (OpenSSF Scorecard least-privilege), added `THIRD_PARTY_LICENSES.md`, and raised test coverage from ~63% to ~83% — `internal/db` error branches via fault injection (to 93%) and `internal/api` handler error paths (to 90%).
- Credited cross-package coverage in CI with `-coverpkg`, matching ovumcy-web's coverage measurement, so code exercised by integration tests (e.g. `internal/db` methods driven through the service and API layers) is no longer scored 0% and the Codecov patch report reflects real coverage.
- **Restructured CI coverage and enforcement**, mirroring `ovumcy-web`: split the `test` job (which had carried `-race`, `-covermode=atomic`, and, as of the `-coverpkg` change above, `-coverpkg` all together) into a coverage-only `test` job (`go test ./cmd/... ./internal/... -coverpkg=./cmd/...,./internal/...`, no `-race`) and a separate `race` job (`go test -race ./...`, no coverage), so a coverage regression and a data race fail independently; added an in-CI `scripts/patchcov` patch-coverage gate (`patch-coverage` job, test-tested by `scripts/patchcov/main_test.go`) that fails a PR when a modified, coverable Go line is left untested, replacing reliance on the external Codecov patch status; set `codecov.yml`'s `patch.target` to `100%`; and added `scripts/patch-coverage-local.sh` plus an opt-in `scripts/hooks/pre-push` (wired via `scripts/setup-hooks.sh`) so the same gate can be checked, and enforced, before a push leaves a contributor's machine. Scoped the `gosec` CI job to `./cmd/... ./internal/...` (was `./...`), matching `ovumcy-web`: `scripts/` is CI tooling, not the server's attack surface, and gosec's subprocess/file-read findings on a coverage-diff CLI tool are expected, not actionable.

## [0.2.0] - 2026-03-23

### Added

- Operator Prometheus metrics and post-release self-hosting documentation.

### Changed

- Hardened the self-hosted runtime and reverse-proxy handling.

## [0.1.0] - 2026-03-23

### Added

- Initial public release of `ovumcy-sync-community` — the encrypted sync community server: account registration and sign-in, hashed bearer sessions, device registration, a community capability document, wrapped recovery-key package storage, and encrypted blob upload/download.
- Public repository community metadata, split CI checks for branch protection, and an explicit browser-sync CORS origin allowlist.

[Unreleased]: https://github.com/ovumcy/ovumcy-sync-community/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/ovumcy/ovumcy-sync-community/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ovumcy/ovumcy-sync-community/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ovumcy/ovumcy-sync-community/releases/tag/v0.1.0
