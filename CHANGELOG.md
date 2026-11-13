# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Foreign keys and the busy timeout lapsed after 30 minutes.** `foreign_keys`, `busy_timeout` and `journal_mode` were set by one `Exec` on the first pooled connection, but the pool retires a connection after 30 minutes and the replacement opened with SQLite's defaults: foreign keys off and no busy wait. From then on a write racing an account deletion or a lapsed-account purge could leave orphaned device, blob or recovery rows, and a write contending with the purge failed at once with `SQLITE_BUSY`. The pragmas now travel in the connection string, so the driver applies them to every connection it opens.

- **A client could choose its own rate-limit bucket behind a trusted proxy.** When every `X-Forwarded-For` hop was trusted — a NAT gateway inside the trusted range — the server fell back to `X-Real-IP`, which some proxies pass through from the client verbatim. `X-Real-IP` is no longer read; every `X-Forwarded-For` header line is considered, not just the first. An IPv6 client is now keyed by its /64 rather than its full address, since one subscriber routinely holds the whole /64. An unparseable hop such as a proxy's `unknown` now ends the walk instead of letting the client's own entries to its left become the key. `TRUSTED_PROXY_CIDRS` refuses an over-broad prefix at startup (IPv4 wider than /8, IPv6 wider than /32, unique-local IPv6 wider than /8, so `0.0.0.0/0` and `::/0` fail) and unmaps IPv4-mapped entries, which previously never matched.

- **Rotating the recovery code left issued reset tokens valid.** Whoever held the old code could start a reset, wait for the owner to rotate, and still complete the reset — taking the account and clearing its 2FA — for the rest of the token's 30 minutes. Regeneration now deletes pending reset tokens; sessions are still left alone. Forgot-password writes its token only while the recovery-code hash it verified against is still current, so a request racing the rotation cannot slip a token in after the delete.

- **Changing the password left a pending TOTP login challenge valid.** A challenge minted by a login under the old password could still be completed with a code after the change, yielding a fresh session. Change-password now deletes pending challenges along with reset tokens.

- **A password over 72 bytes returned 500 and burned the reset token.** bcrypt refuses input past 72 bytes, and that error surfaced raw; 37 Cyrillic characters were enough. Register, change-password, and reset now reject such a password with their usual weak-password key, and reset checks it before consuming the token, so a rejected password leaves the token usable for a retry.

- **Removing a device left its sessions alive.** Sessions were scoped to the account only, so removing a lost or stolen device from the device list freed its slot but its session kept syncing for up to the full `SESSION_TTL`. A session is now bound to the device it attaches through `POST /sync/devices` (the first attach; a later one never moves it), and `DELETE /sync/devices/{device_id}` revokes every session bound to that device in the same transaction — removing your own device signs that client out. Sessions that existed before this release are bound on their client's next attach; until then a password change remains the way to cut them off. Requires running `migrate` (adds `sessions.device_id`).

- **Logging in again reset the TOTP guess budget.** Each login challenge allowed five wrong codes, and a new login replaced the challenge with a fresh one, so an attacker holding the password could cycle logins and keep guessing — roughly a one-in-five chance a day of landing a valid code. Code attempts are now also capped per account: 10 per fixed 15-minute window across every challenge and `POST /auth/totp/disable`, after which those routes answer 429 `rate_limited` with `Retry-After` at the window's end. A new login does not reset the count; a successful verify does. The attempt is reserved in one statement before the code is checked, so concurrent guesses cannot slip past the cap. Requires running `migrate` (adds `totp_failure_windows`).

- **Pre-authentication hardening.** Every session-authenticated route now passes a per-client-IP bucket before the session lookup, with a valid session refunding its slot, so a caller without a session can no longer drive store lookups unmetered. `POST /auth/totp/challenge` is rate-limited before it reports `503 totp_not_configured`. A JSON body followed by anything but whitespace — even `{}` or `null` — is now `400 invalid_json`. An invalid `FIELD_ENCRYPTION_KEY` no longer quotes the offending character of the key in the startup error. `purge-lapsed-accounts` no longer applies pending migrations as a side effect; it refuses and points at `migrate`.

- **`METRICS_ENABLED=true` now requires `METRICS_BEARER_TOKEN`.** An unauthenticated `/metrics` was one proxy rule away from public; the server now refuses to start with metrics on and no token.

- **Anyone could lock a known login out with no way back in.** The per-login ceiling counted every attempt, successful or not, and nothing cleared it, though the code claimed the recovery code was the unblock path: a reset did not touch the bucket, and the owner's next login was still `429`. A login that issues a session now refunds its slot, so only failures stay charged, and a successful `POST /auth/forgot-password` clears the login's bucket. A sustained flood of failures still blocks the login while it lasts.

- **A delayed managed-session mint could reverse an entitlement lapse.** `POST /managed/session` set `premium_active` and cleared `lapsed_at` on every call, so a mint that was retried or delivered late, after the lapse signal had already been applied, restored premium and returned a live session. A mint now never clears a lapse: on a lapsed account it answers `409 managed_account_lapsed` and issues nothing. The way back is the reactivation signal (`POST /managed/accounts/{account_id}/premium` with `active: true`), which now requires an `as_of` timestamp and is applied only when it is newer than the lapse. Lapse and reactivation signals are ordered by `as_of` (new column `entitlement_signal_as_of`, migration `0011`), so a stale signal answers `409 stale_entitlement_signal` and changes nothing. A lapse without `as_of` is still accepted and never stale. The lapse write and its session revocation now share one transaction.

  `sync_enabled=false` is now enforced as well as reported: device, recovery-key and blob routes answer `403 sync_disabled` for a session whose account reports it, which covers a session minted in a race with a lapse. The managed service has to send the reactivation signal before minting for a resubscribed account; until it does, a lapsed account cannot sync again.

- **The log sanitizer missed two families of steering characters.** It stripped the C0 range and DEL, which closed line-break forgery and the `\x1b[` escape route, but left the C1 range and the Unicode format category untouched. A path arrives percent-decoded, so `%C2%9B` reached the log as U+009B — the single-character CSI a terminal acts on exactly like `\x1b[` — and `%E2%80%AE` reached it as a bidirectional override, which reorders how the rest of the entry is displayed without executing anything. Both are now stripped alongside the C0 range; printable text, including non-ASCII paths, is untouched.

- **Four routes reached the store with no rate limit at all.** `GET /auth/session`, `GET /sync/capabilities`, `GET /sync/devices`, and `DELETE /auth/session` were the only routes that could spend server work on a caller's behalf without passing a limiter, so a looping client or a captured session could drive session lookups and device queries at whatever rate the connection allowed. The three authenticated read-only routes now carry a per-account ceiling and `DELETE /auth/session` a per-client-IP one — the latter because it consumes the bearer token instead of authenticating through it, leaving no account identity to key on before the revoke. `openapi.yaml` records the added `429` on all four.

  The read ceiling is a fixed multiple of the existing `AUTH_RATE_LIMIT_COUNT` (300 per minute per account per route at the default) rather than a new knob, so there is still one rate-limit dial. It is deliberately far above any real client cadence: these routes are called on screen focus or an explicit tap, never on a timer, so the bound is reachable by a runaway loop and not by a person navigating an app.

  Decision (2026-07-28): `GET /healthz` and `GET /readyz` stay unlimited, now pinned by a regression test. A container healthcheck polls readiness on a fixed interval and an uptime monitor polls liveness on its own; throttling either would turn routine monitoring into a reported outage, with an orchestrator restarting or depooling a server that was answering correctly. `GET /metrics` (off by default, scraped on the collector's interval) and the `MANAGED_BRIDGE_TOKEN` machine-to-machine bridge routes (disabled by default, one first-party caller that may reconcile in bursts) stay unlimited for the same operator-facing reasons.

- **The container healthcheck now reports database health.** `HEALTHCHECK` probed `GET /healthz`, which answers from a constant and consults nothing, so a container whose database had become unreadable — deleted, corrupt, permission-locked — reported `healthy` to the runtime and to any orchestrator for as long as the HTTP loop kept accepting connections. It probes `GET /readyz` instead, which touches the store. `GET /healthz` is unchanged and stays the pure liveness answer for a proxy or uptime check.

- **The bundled Caddy edge collapsed every client into one rate-limit bucket.** `docker-compose.caddy.yml` set no `TRUSTED_PROXY_CIDRS`, so every request reached the server from Caddy's address and a few failed logins from anyone throttled auth for all users for the window. Caddy now sits at a fixed address on its own network (`SYNC_PROXY_IP` in `SYNC_EDGE_SUBNET`) and only that address is trusted.

- **Compose could not configure 2FA, sweeps, or timeouts.** `docker-compose.yml` hard-coded its environment and omitted `FIELD_ENCRYPTION_KEY`, `TOTP_ISSUER`, the sweep variables, and both HTTP timeouts, so the documented way to enable TOTP did not reach the container. Every configuration variable is now passed through from the shell or a `.env` file, with the server default when unset.

- **Docs drift.** The plain `docker run` quick start now prepares `./data` for the non-root image and binds loopback like Compose; the lint pin in `CONTRIBUTING.md` matches CI; `SECURITY.md` names the in-process lapse sweep, the recovery-then-re-enroll path after a key rotation, and all six asserted hardening headers; the proxy docs name the forwarded-IP headers.

### Changed

- **Hardened reference edge and bridge token.** `docker-compose.caddy.yml` no longer defaults `SYNC_SITE_ADDRESS` to `:80`, which served plain HTTP; the stack now refuses to start until it names the public hostname, so Caddy serves HTTPS. The Caddy, nginx and Traefik examples answer `/managed/*` with `403` at the public edge, as they already did for `/metrics` — the managed bridge's one caller reaches the service over the private network. A set `MANAGED_BRIDGE_TOKEN` shorter than 32 bytes is now a startup error: the bridge routes are not rate-limited, so the token alone must resist guessing. **Upgrade:** set `SYNC_SITE_ADDRESS` before `docker compose up` with the Caddy example, and regenerate a short bridge token with `openssl rand -hex 32`.

- **Breaking: `DELETE /account` and `PUT /sync/recovery-key` require the current password.** A session token lives for 30 days by default, and with it alone anyone could erase the account or overwrite the wrapped recovery key that is the owner's only way back to their data. Both requests now carry `current_password` in the JSON body and get `401 invalid_current_password` when it is wrong; `DELETE /account` therefore needs a body. Managed accounts have no password and are exempt — their sessions come only from the managed bridge.

- **A blob generation may run at most 15 minutes ahead of server time, down from 24 hours.** A write parked at the ceiling keeps every later write stale until the clock passes it, so a session that wrote one before being revoked could freeze the owner's sync for a day. Fifteen minutes still covers real device clock drift; a device whose clock is further ahead gets `invalid_blob` until it is corrected. A generation already stored under the old 24-hour cap is not rewritten: such an account stays write-stale until the clock passes it, at most a day after upgrading.

- **Go 1.27.** The Go directive moves to 1.27.4 and the build image to `golang:1.27-bookworm`; CI's golangci-lint pin moves to v2.15.0 to analyse the 1.27 toolchain. A source build now needs Go 1.27.4 or later.

- **`GET /readyz` is schema-aware.** Readiness now applies the same applied-migration name-set comparison that gates startup, so a still-running `serve` whose volume a newer image has migrated turns not-ready instead of continuing to look serviceable — the running-process half of the refusal that already stopped a downgraded binary from booting (see [docs/self-hosting.md](docs/self-hosting.md#upgrading-and-rolling-back)). Operator-visible consequence: a container can now go `unhealthy` for a reason other than the process being gone, and an orchestrator configured to act on health will act on it. The probe stays two small statements — a `sqlite_master` lookup and the `schema_migrations` name set — so polling it on the healthcheck interval costs nothing measurable.

## [0.3.0] - 2026-07-24

A major auth, security-hardening, and supply-chain release since `v0.2.0`: optional TOTP 2FA, account recovery and password management, authenticated account deletion, managed entitlement-lapse cleanup, in-process retention sweeps, signed release artifacts, and a substantially hardened CI and quality bar.

### Added

- **TOTP two-factor authentication.** Optional owner 2FA — enrollment, a login second-factor challenge, and disable — gated on `FIELD_ENCRYPTION_KEY`, with challenge metrics exposed for operators.
- **Account recovery and password management.** Password change, recovery codes, and recovery-code-based password reset across the auth surface.
- **Authenticated account deletion.** `DELETE /account` erases every row the server holds for an account in a single transaction.
- **`GET /auth/session`** exposing the current `totp_enabled` state.
- **Device management.** `GET /sync/devices` lists an account's attached devices and `DELETE /sync/devices/{device_id}` removes one (account-scoped, no IDOR), so reaching the device limit no longer forces deleting the whole account to free a slot.
- **Machine-readable OpenAPI 3.1 spec** (`openapi.yaml`) covering the full HTTP surface, plus a zero-knowledge boundary diagram in the README.
- **Entitlement-lapse cleanup for managed accounts.** New bridge endpoint `POST /managed/accounts/{account_id}/premium` lets the managed-auth service signal an entitlement lapse (`active: false`) or retract one (`active: true`); a new `purge-lapsed-accounts` CLI subcommand (`-dry-run`, `-limit`) erases a managed account's data once its lapse has exceeded the configurable `LAPSED_ACCOUNT_GRACE_PERIOD` (default 60 days). Self-hosted/community accounts are entirely unaffected — the lapse marker can only ever be set on a `mode=managed` account. See [docs/self-hosting.md](docs/self-hosting.md#entitlement-lapse-cleanup).
- **In-process lapsed-account sweep.** `serve` itself now erases lapsed managed accounts past the grace period, every `LAPSED_ACCOUNT_SWEEP_INTERVAL` (default `24h`, first run one interval after boot; `0` disables the in-process sweep and leaves `purge-lapsed-accounts` as the only trigger — the rollback lever), with `LAPSED_ACCOUNT_SWEEP_LIMIT` capping candidates per run (unset = the store's default page size). Both triggers are idempotent and safe to run together, so the documented retention window holds without an operator scheduling anything.
- **In-process expired-rows sweep.** `serve` now deletes expired sessions, password-reset tokens, and TOTP challenges every `EXPIRED_ROWS_SWEEP_INTERVAL` (default `24h`, first run one interval after boot; a non-positive value disables the sweep — the rollback lever), bounded by `EXPIRED_ROWS_SWEEP_LIMIT` rows per table per run (`0` = the store's own default page size). Expiry was already enforced at use time on every read path; these tables were simply never physically emptied and were the only ones still growing without bound.
- **Operator-tunable HTTP timeouts.** `HTTP_READ_TIMEOUT` (default `10s`) and `HTTP_WRITE_TIMEOUT` (default `15s`) expose the previously hardcoded per-request windows. Together with `MAX_BLOB_BYTES` they bound how slow a client may be while still moving a full-size blob — at the defaults a 16 MiB transfer needs roughly 1.7 MB/s — so deployments syncing large blobs over slow links can widen the windows without a fork. Zero and negative values are rejected: a zero `net/http` timeout means no timeout at all.

### Changed

- **Relicensed** from AGPL-3.0 to the PolyForm Noncommercial License 1.0.0.
- **Runtime image switched to distroless** to drop the vulnerable gnutls chain.
- Tightened auth rate-limit ceilings.
- **Compose baseline now binds to loopback by default.** `docker-compose.yml` publishes the service on `127.0.0.1:8080` instead of all host interfaces; use a `docker-compose.override.yml` to publish on `0.0.0.0` for remote/LAN access.

### Fixed

- **Device limit could be exceeded under concurrency.** Attaching a device counted the account's devices and then inserted in two separate steps, so simultaneous attaches all passed the same check and overran `MAX_DEVICES`. The ceiling is now a predicate inside the insert statement (matching the blob-generation CAS), so concurrent attaches collapse to the limit. Re-attaching an already-owned device still refreshes its row without consuming a slot.
- **Explicit `LAPSED_ACCOUNT_SWEEP_LIMIT=0` no longer fails startup.** The documented "0 = the store's own default page size" held only for the unset case; an explicitly set `0` was rejected as non-positive. Only negative values are rejected now.
- **The `Authorization` scheme is case-insensitive.** `bearer <token>` and `BEARER <token>` now authenticate exactly like `Bearer <token>` (RFC 7235 §2.1); previously they were rejected with `401`.

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
- Sign the published container image. The `Docker Image` workflow signs the runtime image with keyless cosign and attaches SLSA build provenance. Verification steps are documented in [docs/self-hosting.md](docs/self-hosting.md).
- Recover from handler panics at the transport layer: a panic now returns a clean `500 internal_error` instead of a dropped connection, and is logged as a controlled, secret-free line (method + path only) rather than `net/http`'s default unbounded stack trace — keeping the no-secret-in-logs contract even on the failure path.
- Cap the accepted blob generation below the int64 ceiling. Without it, a client holding its own valid session could write `generation = math.MaxInt64` and permanently lock itself out of its own blob (the monotonic-generation CAS could never find a strictly-greater value). Owner-only self-lockout hardening surfaced by an adversarial audit; the client's millisecond-timestamp generation is astronomically far below the cap, so legitimate writes are unaffected.
- The entitlement-lapse signal immediately revokes every still-valid session on a lapsed managed account (no entitlement, no sync), independent of the data-retention grace period.
- The purge sweep re-checks the lapse marker and grace cutoff inside the same transaction as the deletion itself, so a session mint that races a scheduled sweep run always preserves the account intact.
- The rate-limit client IP is now canonicalized (IPv4-unmapped and IPv6 zone-stripped), so an IPv6 caller behind a trusted proxy can no longer mint distinct rate-limit buckets for one address by varying the zone in a forwarded header. Added native fuzz coverage for the client-IP parsers.
- **Per-account rate limit on sync reads.** `GET /sync/blob` and `GET /sync/recovery-key` now pass the same per-account limiter as their PUT counterparts: a valid session could previously drive unmetered reads of up to `MAX_BLOB_BYTES` ciphertext (plus the base64 encoding cost) past the per-IP auth gate. The budget is unchanged — `AUTH_RATE_LIMIT_COUNT` per `AUTH_RATE_LIMIT_WINDOW` per account, per endpoint.

### Internal

- Added a `gitleaks` secret-scanning CI lane (full-history, on every PR, push to `main`, and weekly) with a `.gitleaks.toml` allowlist scaffold.
- Healthcheck self-probe plus container `HEALTHCHECK`; `govulncheck`, native fuzz, and advisory mutation (gremlins) CI lanes; fuzz and property tests for crypto, TOTP, and login/recovery helpers.
- Set the Go directive to 1.26.4 (parity with `ovumcy-web`) and bumped `golang.org/x/crypto` to v0.53.0 for advisories; made the Codecov upload non-blocking on pull requests.
- Added the `SECURITY.md` Test Enforcement Matrix; documented the optional TOTP second factor and the mutation/fuzz/property test stack.
- Run the CI `test` job with `go test -race` to catch data races in the concurrency-sensitive auth/session/CAS logic; `-covermode=atomic` retained as required alongside `-race`.
- Added a `golangci-lint` v2.12.2 CI gate (`.golangci.yml`, parallel `golangci-lint` job) alongside the existing `staticcheck` and `go vet` jobs; fixed the mechanical findings it surfaced (unchecked deferred `Close` errors, redundant `http.HandlerFunc` conversions, three-clause counting loops rewritten to `range`).
- Added a daily `fuzz-continuous` job to the `Fuzz` workflow that runs each native Go fuzz target for 10m with its generated corpus cached and restored between runs (`actions/cache`, keyed per target), so coverage accumulates instead of restarting from the seed corpus every time; the existing weekly 3m short pass is unchanged.
- Moved workflow write permissions to the job level (OpenSSF Scorecard least-privilege), added `THIRD_PARTY_LICENSES.md`, and raised test coverage from ~63% to ~83% — `internal/db` error branches via fault injection (to 93%) and `internal/api` handler error paths (to 90%).
- Credited cross-package coverage in CI with `-coverpkg`, matching ovumcy-web's coverage measurement, so code exercised by integration tests (e.g. `internal/db` methods driven through the service and API layers) is no longer scored 0% and the Codecov patch report reflects real coverage.
- **Restructured CI coverage and enforcement**, mirroring `ovumcy-web`: split the `test` job (which had carried `-race`, `-covermode=atomic`, and, as of the `-coverpkg` change above, `-coverpkg` all together) into a coverage-only `test` job (`go test ./cmd/... ./internal/... -coverpkg=./cmd/...,./internal/...`, no `-race`) and a separate `race` job (`go test -race ./...`, no coverage), so a coverage regression and a data race fail independently; added an in-CI `scripts/patchcov` patch-coverage gate (`patch-coverage` job, test-tested by `scripts/patchcov/main_test.go`) that fails a PR when a modified, coverable Go line is left untested, replacing reliance on the external Codecov patch status; set `codecov.yml`'s `patch.target` to `100%`; and added `scripts/patch-coverage-local.sh` plus an opt-in `scripts/hooks/pre-push` (wired via `scripts/setup-hooks.sh`) so the same gate can be checked, and enforced, before a push leaves a contributor's machine. Scoped the `gosec` CI job to `./cmd/... ./internal/...` (was `./...`), matching `ovumcy-web`: `scripts/` is CI tooling, not the server's attack surface, and gosec's subprocess/file-read findings on a coverage-diff CLI tool are expected, not actionable.
- A corrupt stored timestamp now surfaces as a scan error naming its table and column instead of a recovered panic naming only the method and path; unique-constraint detection matches the driver's typed error code first, with the previous message-substring check kept as a fallback.
- Seven formerly planned security regressions are now dedicated tests: hash-only persistence of session tokens and recovery codes (proven against the database file through an independent raw connection), the literal TOTP AAD pin, TOTP-challenge TTL expiry, the login session/challenge mutual exclusion in both directions, the 4 KiB auth body ceiling from both sides, and the bridge-only `premium_active` write path. SECURITY.md's "Planned Regressions" list is now empty.

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
