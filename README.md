[![CI](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/ci.yml/badge.svg)](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/ci.yml)
[![Security](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/security.yml/badge.svg)](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/security.yml)
[![CodeQL](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/codeql.yml/badge.svg)](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/ovumcy/ovumcy-sync-community/badge)](https://securityscorecards.dev/viewer/?uri=github.com/ovumcy/ovumcy-sync-community)
[![Coverage](https://codecov.io/gh/ovumcy/ovumcy-sync-community/graph/badge.svg)](https://app.codecov.io/gh/ovumcy/ovumcy-sync-community)
[![Tested](https://img.shields.io/badge/tested-mutation%20%C2%B7%20fuzz%20%C2%B7%20property-2ea44f)](https://github.com/ovumcy/ovumcy-sync-community/blob/main/TESTING.md)
[![License: PolyForm Noncommercial 1.0.0](https://img.shields.io/badge/License-PolyForm%20NC%201.0.0-blue.svg)](https://polyformproject.org/licenses/noncommercial/1.0.0/)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)](https://go.dev/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker)](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/docker-image.yml)
[![Release](https://img.shields.io/github/v/release/ovumcy/ovumcy-sync-community?display_name=tag&sort=semver)](https://github.com/ovumcy/ovumcy-sync-community/releases)
[![Self-hosted](https://img.shields.io/badge/Self--hosted-yes-2ea44f)](https://github.com/ovumcy/ovumcy-sync-community/blob/main/docs/self-hosting.md)
[![Zero-knowledge](https://img.shields.io/badge/Zero--knowledge-transport-2ea44f)](#what-the-server-can-see)
[![No telemetry](https://img.shields.io/badge/Telemetry-none-2ea44f)](#what-the-server-can-see)

# ovumcy-sync-community

**Self-hosted, zero-knowledge encrypted-sync backend for the [Ovumcy](https://github.com/ovumcy/ovumcy-app) period & cycle tracker.**

Run your own Ovumcy sync server so your devices can back up and stay in sync — without handing a cloud vendor your readable health data. The server only ever holds **ciphertext it cannot decrypt**: your cycle dates, symptoms, and notes are encrypted on your phone, with a key the server never receives.

> The Ovumcy app is local-first. This server is the **optional** transport for encrypted backup, restore, and multi-device sync. You only need it if you want those.

## Why run your own sync server

- **You keep the keys.** Health data is encrypted on the client; the server stores opaque blobs. Even a fully compromised server (or its operator) cannot read your cycle data.
- **No lock-in, no tracking.** No accounts with a third party, no analytics, no ad trackers, no outbound telemetry.
- **Small and auditable.** One Go binary, one SQLite file, a narrow HTTP surface you can read end to end — and a [machine-readable API spec](openapi.yaml).
- **Multi-device.** Back up on one device, restore on another, all end-to-end encrypted.

## What the server can see

![Zero-knowledge boundary: the Ovumcy app on the owner's device encrypts all health data with a master key the server never receives; only ciphertext and metadata cross the boundary. The sync server stores account, session, and device metadata plus opaque ciphertext, and never sees cycle dates, symptoms, notes, the recovery phrase, the client master key, or any decrypted payload.](docs/assets/zero-knowledge.svg)

The boundary is deliberate and narrow. The server **may** hold:

- the account login you chose on your own server, and bearer-session metadata;
- attached device IDs and labels;
- capability metadata (device limits, blob-size limits);
- encrypted-blob metadata (generation, checksum, ciphertext size, timestamps);
- the wrapped recovery-key package (opaque ciphertext).

The server **never** holds:

- cycle dates, symptoms, notes, or any plaintext health content;
- your recovery phrase or client master key;
- any decrypted sync payload.

## FAQ

**Can the server read my cycle data?** No. The app encrypts everything with a master key derived on your device from your recovery phrase. The server receives only ciphertext and cannot decrypt it.

**Where is my data stored?** In a single SQLite file on the machine you run this on (persisted under `/data`). You own the disk and the backups.

**Does it phone home or use analytics?** No. There are no ad trackers and no outbound telemetry. Operator metrics exist only behind an optional, pull-based `/metrics` endpoint that is off by default.

**Is there an API specification?** Yes — a machine-readable OpenAPI 3.1 spec in [`openapi.yaml`](openapi.yaml).

**Do I have to trust the operator?** For confidentiality of your health data, no — that is the point of the zero-knowledge design. The operator does control availability and sees account/device *metadata* (see the boundary above).

**Can I verify a release?** Yes. Release binaries and the container image are signed with keyless [cosign](https://www.sigstore.dev/) and carry SLSA build provenance. See [Verifying release integrity](docs/self-hosting.md#verifying-release-integrity).

## Features

- Account registration and login, with bearer session tokens stored only as hashes.
- Encrypted blob upload/download for one account-scoped sync state, with generation-based conflict rejection.
- Device registration, listing, and removal, bounded by a configurable device limit.
- Account recovery: recovery codes and recovery-code-based password reset.
- Optional TOTP two-factor authentication (off until you set an encryption key).
- Wrapped recovery-key package storage for zero-knowledge key recovery.
- Authenticated, permanent account deletion that erases every row the server holds in one transaction.

## Quick start

**Docker Compose (recommended).** Migrate the database once, then start the server:

```bash
docker compose run --rm ovumcy-sync-community migrate
docker compose up --build
```

The baseline publishes on `127.0.0.1:8080` (loopback only) and persists SQLite under `./data`. For remote or LAN access, put a reverse proxy in front of the loopback port — see [Self-hosting in production](#self-hosting-in-production).

**Docker (without Compose):**

```bash
docker build -t ovumcy-sync-community .
docker run --rm -v "$(pwd)/data:/data" ovumcy-sync-community migrate
docker run --rm -p 8080:8080 -v "$(pwd)/data:/data" ovumcy-sync-community serve
```

**Local (Go toolchain).** The schema must exist first, so `migrate` before `serve`:

```bash
go run ./cmd/ovumcy-sync-community migrate
go run ./cmd/ovumcy-sync-community serve
```

**Connect the Ovumcy app:** open `Backup & sync` → choose `Self-hosted` → enter your HTTPS sync endpoint → prepare the device, save the recovery phrase, then register or sign in on your own server.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `BIND_ADDR` | `:8080` | Address the server listens on |
| `DB_PATH` | `./data/ovumcy-sync-community.sqlite` | SQLite database file |
| `SESSION_TTL` | `720h` | Session token lifetime |
| `MAX_DEVICES` | `5` | Devices attachable per account |
| `MAX_BLOB_BYTES` | `16777216` | Ciphertext size cap (16 MiB) |
| `AUTH_RATE_LIMIT_COUNT` | `10` | Auth requests allowed per window |
| `AUTH_RATE_LIMIT_WINDOW` | `1m` | Auth rate-limit window |
| `METRICS_ENABLED` | `false` | Enables `GET /metrics` |
| `METRICS_BEARER_TOKEN` | _(unset)_ | Bearer token for `/metrics` (requires `METRICS_ENABLED=true`) |
| `MANAGED_BRIDGE_TOKEN` | _(unset)_ | Enables the managed-bridge endpoint (leave unset for community use) |
| `ALLOWED_ORIGINS` | _(empty)_ | Explicit CORS allowlist for browser clients |
| `TRUSTED_PROXY_CIDRS` | _(unset)_ | Reverse-proxy CIDRs whose forwarded client IP is trusted for rate limiting |
| `FIELD_ENCRYPTION_KEY` | _(unset)_ | Hex key (≥32 bytes / 64 hex chars) that enables the optional TOTP surface |
| `TOTP_ISSUER` | `ovumcy-sync-community` | Issuer label embedded in `otpauth://` provisioning URIs |

TOTP endpoints stay inactive (`503 totp_not_configured`) until `FIELD_ENCRYPTION_KEY` is set; see [docs/self-hosting.md](docs/self-hosting.md#optional-two-factor-authentication) for the 2FA and account-recovery flows.

<details>
<summary><strong>Runtime endpoints</strong> (full list — machine-readable spec in <a href="openapi.yaml"><code>openapi.yaml</code></a>)</summary>

- `GET /healthz` liveness · `GET /readyz` readiness · `GET /metrics` optional Prometheus endpoint
- `POST /auth/register` · `POST /auth/login`
- `POST /auth/change-password` (auth) · `POST /auth/forgot-password` · `POST /auth/reset-password` · `POST /auth/recovery-code/regenerate` (auth)
- `POST /auth/totp/enroll` (auth) · `POST /auth/totp/verify` (auth) · `POST /auth/totp/disable` (auth) · `POST /auth/totp/challenge`
- `GET /auth/session` (auth) returns `account_id` / `login` / `totp_enabled` · `DELETE /auth/session`
- `DELETE /account` (auth) permanently erases the account and every row it owns
- `GET /sync/capabilities`
- `POST /sync/devices` (auth) attach · `GET /sync/devices` (auth) list · `DELETE /sync/devices/{device_id}` (auth) remove
- `GET /sync/recovery-key` · `PUT /sync/recovery-key`
- `GET /sync/blob` · `PUT /sync/blob`

</details>

## Self-hosting in production

- Put the service behind HTTPS (terminate TLS at a reverse proxy such as Caddy, Nginx, or Traefik).
- Persist the `/data` volume so SQLite survives restarts.
- Set `TRUSTED_PROXY_CIDRS` to your reverse-proxy addresses so auth rate limiting sees real client IPs.
- Enable `METRICS_ENABLED` only when needed, and keep `/metrics` internal or protect it with `METRICS_BEARER_TOKEN`.
- Leave `MANAGED_BRIDGE_TOKEN` unset unless you operate a separate trusted managed-auth service.
- Set `ALLOWED_ORIGINS` only when browser clients need direct CORS access.

A ready-to-adapt Caddy edge (which blocks `/metrics` publicly by default):

```bash
docker compose -f docker-compose.yml -f docker-compose.caddy.yml run --rm ovumcy-sync-community migrate
docker compose -f docker-compose.yml -f docker-compose.caddy.yml up --build
```

See [docs/self-hosting.md](docs/self-hosting.md) for the reverse-proxy, TLS, 2FA, and release-verification details, and [docs/backup-restore.md](docs/backup-restore.md) for an operator restore drill.

> **Publishing on all interfaces.** The baseline binds loopback only. To expose the port directly (a reverse proxy is preferred), add a `docker-compose.override.yml` (auto-loaded) with `ports: !override` — the `!override` tag *replaces* the loopback mapping; a plain `ports:` list would append and double-bind port 8080, failing to start.

## Security

Confidentiality of health data is a property of the client encryption — the server is deliberately blind to payload contents. On top of that, the server is built to be correct about authentication and storage and paranoid about the primitives it owns: bcrypt password/recovery-code hashing, hashed session tokens, AES-256-GCM field encryption for TOTP secrets, enumeration- and timing-safe auth, and per-account rate limiting.

- Design, threat model, and the test-backed invariants: **[SECURITY.md](SECURITY.md)**.
- How it is tested (mutation, fuzz, property, race, and supply-chain scanning): **[TESTING.md](TESTING.md)**.
- Report a vulnerability privately: see [SECURITY.md](SECURITY.md).

## Architecture & tech stack

A single Go binary with a strict layering — transport never touches the database, services never touch HTTP:

```
internal/api  →  internal/services  →  internal/db     (+ internal/security, internal/models)
 (transport)      (AuthService,          (repositories,
                   SyncService)           forward-only migrations)
```

- **Language:** Go 1.26, `net/http`, CGO-free build.
- **Storage:** SQLite in WAL mode; forward-only SQL migrations (explicit `migrate` before `serve`).
- **Runtime image:** multi-stage, distroless, non-root, digest-pinned base images.
- **Supply chain:** cosign-signed image and release binaries, SLSA provenance, CycloneDX SBOM, digest-pinned GitHub Actions.

## Advanced: managed bridge

When `MANAGED_BRIDGE_TOKEN` is set, one extra endpoint is enabled — `POST /managed/session` — intended only for a separate trusted managed-auth service to provision a managed-mode session for an opaque managed `account_id`. Most self-hosted operators do not need this; leave the token unset and ignore the endpoint.

## Development

```bash
go test ./...
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.6.1 ./...
```

Project layout:

- `cmd/ovumcy-sync-community` — entrypoint (`migrate`, `serve`, `healthcheck`)
- `internal/api` — HTTP transport, handlers, response mapping
- `internal/services` — domain logic (`AuthService`, `SyncService`)
- `internal/db` — persistence, repositories, forward-only migrations
- `internal/models` — transport-free domain types
- `internal/security` — password hashing, tokens, field encryption
- `internal/config` — runtime configuration from the environment

CI runs staticcheck, `go vet`, golangci-lint, race-enabled tests with coverage, and a Docker runtime smoke on every push and pull request; a dedicated security workflow runs `gosec`, `govulncheck`, gitleaks, and Trivy scans, with CodeQL, native fuzzing, and mutation testing in their own lanes. See [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

## Releases & license

This README tracks the `main` branch. Tagged versions, release notes, and signed artifacts are on the [Releases](https://github.com/ovumcy/ovumcy-sync-community/releases) page; notable changes are in [CHANGELOG.md](CHANGELOG.md).

Source-available under the **PolyForm Noncommercial License 1.0.0** — view, self-host, use, and modify for any noncommercial purpose, and share noncommercially. Commercial use is not granted; contact Ovumcy for a commercial license. See [LICENSE](LICENSE). Third-party dependency licenses are listed in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
