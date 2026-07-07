[![CI](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/ci.yml/badge.svg)](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/ci.yml)
[![Security](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/security.yml/badge.svg)](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/security.yml)
[![CodeQL](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/codeql.yml/badge.svg)](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/ovumcy/ovumcy-sync-community/badge)](https://securityscorecards.dev/viewer/?uri=github.com/ovumcy/ovumcy-sync-community)
[![Coverage](https://codecov.io/gh/ovumcy/ovumcy-sync-community/graph/badge.svg)](https://app.codecov.io/gh/ovumcy/ovumcy-sync-community)
[![Tested](https://img.shields.io/badge/tested-mutation%20%C2%B7%20fuzz%20%C2%B7%20property-2ea44f)](https://github.com/ovumcy/ovumcy-sync-community/blob/main/TESTING.md)
[![License: PolyForm Noncommercial 1.0.0](https://img.shields.io/badge/License-PolyForm%20NC%201.0.0-blue.svg)](https://polyformproject.org/licenses/noncommercial/1.0.0/)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)](https://go.dev/)
[![Go Reference](https://pkg.go.dev/badge/github.com/ovumcy/ovumcy-sync-community.svg)](https://pkg.go.dev/github.com/ovumcy/ovumcy-sync-community)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker)](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/docker-image.yml)
[![Release](https://img.shields.io/github/v/release/ovumcy/ovumcy-sync-community?display_name=tag&sort=semver)](https://github.com/ovumcy/ovumcy-sync-community/releases)
[![Last Commit](https://img.shields.io/github/last-commit/ovumcy/ovumcy-sync-community)](https://github.com/ovumcy/ovumcy-sync-community/commits/main)
[![Self-hosted](https://img.shields.io/badge/Self--hosted-yes-2ea44f)](https://github.com/ovumcy/ovumcy-sync-community/blob/main/docs/self-hosting.md)
[![Zero-knowledge](https://img.shields.io/badge/Zero--knowledge-transport-2ea44f)](https://github.com/ovumcy/ovumcy-sync-community#what-the-server-can-see)
[![No telemetry](https://img.shields.io/badge/Telemetry-none-2ea44f)](https://github.com/ovumcy/ovumcy-sync-community#what-the-server-can-see)

# ovumcy-sync-community

`ovumcy-sync-community` is the self-hosted encrypted sync backend for the [Ovumcy app](https://github.com/ovumcy/ovumcy-app).

It is built for people who want to run their own Ovumcy sync server for backup, restore, and multi-device encrypted sync without turning the server into a plaintext health-data processor.

It is designed around a zero-knowledge contract:

- the server knows account identity, device registry, capability metadata, and encrypted blob metadata;
- the server stores only ciphertext for synced health data;
- the server never receives recovery phrases or plaintext health records.

With the Ovumcy app, this repository provides the self-hosted server side of:

- account registration and sign-in on your own server;
- encrypted backup and restore across devices;
- device registration and recovery-key package storage;
- a simple, auditable community deployment baseline.

## What The Server Can See

![Zero-knowledge boundary. The Ovumcy app on the owner's device encrypts all health data with a master key the server never receives; only ciphertext and metadata cross the boundary. The sync server stores account, session, and device metadata plus opaque ciphertext, and never sees cycle dates, symptoms, notes, the recovery phrase, the client master key, or any decrypted payload.](docs/assets/zero-knowledge.svg)

`ovumcy-sync-community` is intentionally narrow. In community mode it may know:

- the account login that the owner chose on their own server;
- bearer-session lifecycle metadata;
- attached device IDs and device labels;
- capability metadata such as device limits and blob-size limits;
- encrypted blob metadata such as generation, checksum, ciphertext size, and timestamps;
- wrapped recovery-key package metadata.

It must not know:

- cycle dates, symptoms, notes, or other plaintext health content;
- recovery phrases;
- client master keys;
- decrypted sync payloads.

The server ships no analytics, ad trackers, or outbound telemetry. Operator metrics are exposed only through the optional, pull-based `/metrics` endpoint and are never reported anywhere outbound.

## What You Get With Ovumcy App

This README describes the current `main` branch. The latest tagged release is `v0.3.0`.

This repository currently provides:

- account registration and login;
- bearer session tokens with hashed storage;
- device registration;
- a capability document for the community/self-hosted mode;
- account-scoped wrapped recovery-key package storage for zero-knowledge recovery setup;
- encrypted blob upload and download for one account-scoped sync state;
- authenticated, permanent account deletion that erases every row the server holds for that account in one transaction.

In the Ovumcy app, this is the backend used for the `Self-hosted` backup and sync mode.

The core Ovumcy product remains local-first. This server exists only for optional encrypted sync and recovery transport.

## Current v1 Baseline

The supported deployment baseline is:

- one self-hosted instance;
- SQLite persisted on a local disk or volume;
- HTTPS terminated at a reverse proxy or load balancer in front of this service.

This repository is not intended to become a general product backend, analytics service, or plaintext health-data processor.

## Why This Repository Exists

Ovumcy app users may want multi-device backup and restore without giving a cloud vendor access to readable health data.

`ovumcy-sync-community` exists to provide that self-hosted transport layer:

- self-hosted by the user or operator;
- narrow and auditable;
- compatible with zero-knowledge encrypted client payloads;
- honest about the metadata a sync server can still see.

## Configuration

Environment variables:

- `BIND_ADDR` default `:8080`
- `DB_PATH` default `./data/ovumcy-sync-community.sqlite`
- `SESSION_TTL` default `720h`
- `MAX_DEVICES` default `5`
- `MAX_BLOB_BYTES` default `16777216` (16 MiB ciphertext cap)
- `AUTH_RATE_LIMIT_COUNT` default `10`
- `AUTH_RATE_LIMIT_WINDOW` default `1m`
- `METRICS_ENABLED` default `false`; enables `GET /metrics`
- `METRICS_BEARER_TOKEN` optional bearer token for `GET /metrics`; requires `METRICS_ENABLED=true`
- `MANAGED_BRIDGE_TOKEN` optional bearer token that enables the machine-to-machine managed bridge endpoint
- `ALLOWED_ORIGINS` comma-separated allowlist for browser clients; empty by default
- `TRUSTED_PROXY_CIDRS` optional comma-separated list of trusted reverse-proxy IPs or CIDRs whose forwarded client IP headers may be used for auth rate limiting
- `FIELD_ENCRYPTION_KEY` optional hex-encoded master key (>=32 bytes / 64 hex chars) that enables the optional TOTP second-factor surface; leave unset to disable 2FA entirely
- `TOTP_ISSUER` default `ovumcy-sync-community`; issuer label embedded in `otpauth://` provisioning URIs so authenticator apps show which instance a secret belongs to

Runtime endpoints (machine-readable spec: [openapi.yaml](openapi.yaml)):

- `GET /healthz` liveness
- `GET /readyz` readiness
- `GET /metrics` optional Prometheus endpoint for operators
- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/change-password` (authenticated) change the account password
- `POST /auth/forgot-password` start a recovery-code-based password reset
- `POST /auth/reset-password` complete a password reset and rotate the recovery code
- `POST /auth/recovery-code/regenerate` (authenticated) rotate the account recovery code
- `POST /auth/totp/enroll` (authenticated) begin optional TOTP 2FA enrollment
- `POST /auth/totp/verify` (authenticated) confirm TOTP enrollment
- `POST /auth/totp/disable` (authenticated) turn off TOTP 2FA
- `POST /auth/totp/challenge` complete the TOTP second factor after login
- `GET /auth/session` (authenticated) return the current session's `account_id`, `login`, and `totp_enabled`
- `DELETE /auth/session`
- `DELETE /account` (authenticated) permanently erase the account and every row it owns: sessions, devices, the encrypted sync blob, the wrapped recovery-key package, pending password reset tokens, and pending TOTP challenges
- `GET /sync/capabilities`
- `POST /sync/devices` (authenticated) attach a device to the account
- `GET /sync/devices` (authenticated) list the account's attached devices
- `DELETE /sync/devices/{device_id}` (authenticated) remove one attached device, freeing a slot
- `GET /sync/recovery-key`
- `PUT /sync/recovery-key`
- `GET /sync/blob`
- `PUT /sync/blob`

The TOTP endpoints stay inactive (`503 totp_not_configured`) until `FIELD_ENCRYPTION_KEY` is set; see [docs/self-hosting.md](docs/self-hosting.md#optional-two-factor-authentication) for the 2FA and account-recovery flows.

## Run locally

```bash
go run ./cmd/ovumcy-sync-community migrate
go run ./cmd/ovumcy-sync-community serve
```

## Docker

```bash
docker build -t ovumcy-sync-community .
docker run --rm -v $(pwd)/data:/data ovumcy-sync-community migrate
docker run --rm -p 8080:8080 -v $(pwd)/data:/data ovumcy-sync-community serve
```

## Docker Compose

```bash
docker compose run --rm ovumcy-sync-community migrate
docker compose up --build
```

The compose baseline publishes the service on `127.0.0.1:8080` only (loopback, via `ports: ["127.0.0.1:8080:8080"]`) and persists SQLite data under `./data`. For remote or LAN access, put a reverse proxy in front of the loopback port (recommended) rather than exposing the app port directly. If you must publish on all host interfaces anyway, add a `docker-compose.override.yml` (auto-loaded by `docker compose`) with:

```yaml
services:
  ovumcy-sync-community:
    ports: !override
      - "8080:8080"
```

The `!override` tag replaces the baseline loopback mapping. A plain `ports:` list in an override file would be merged by appending, leaving two bindings of host port 8080 (loopback plus all interfaces) and the container would fail to start with a port-allocation conflict.

For local browser-preview work with `ovumcy-app`, use the dedicated override:

```bash
docker compose -f docker-compose.yml -f docker-compose.browser.yml run --rm ovumcy-sync-community migrate
docker compose -f docker-compose.yml -f docker-compose.browser.yml up --build
```

That override allows only:

- `http://127.0.0.1:4173`
- `http://localhost:4173`

Keep the base compose file unchanged for the default self-hosted security posture.

For an optional reverse-proxy example with Caddy:

```bash
docker compose -f docker-compose.yml -f docker-compose.caddy.yml run --rm ovumcy-sync-community migrate
docker compose -f docker-compose.yml -f docker-compose.caddy.yml up --build
```

The bundled Caddy example blocks `/metrics` at the public edge by default. If you enable metrics, prefer scraping the backend container directly from a private network or protect the endpoint with `METRICS_BEARER_TOKEN`.

To use it with the Ovumcy app:

1. start the server with Docker Compose or your own deployment stack;
2. open `Backup & sync` in the Ovumcy app;
3. choose `Self-hosted`;
4. enter your HTTPS sync endpoint;
5. prepare the device, save the recovery phrase, then register or sign in on your own server.

For a production-style self-hosted setup:

- put this service behind HTTPS;
- persist `/data`;
- set `TRUSTED_PROXY_CIDRS` to your trusted reverse-proxy addresses if you want auth rate limiting to distinguish real client IPs behind the proxy;
- enable `METRICS_ENABLED` only when you really need operator metrics, and keep `/metrics` internal or protect it with `METRICS_BEARER_TOKEN`;
- keep `MANAGED_BRIDGE_TOKEN` unset unless you really run a separate trusted managed-auth service;
- set `ALLOWED_ORIGINS` only when browser clients need direct CORS access.

See [docs/self-hosting.md](docs/self-hosting.md) for a minimal reverse-proxy, TLS, and backup checklist, and [docs/backup-restore.md](docs/backup-restore.md) for an operator restore drill.

## Advanced: Managed Bridge

If `MANAGED_BRIDGE_TOKEN` is configured, the service also enables:

- `POST /managed/session`

This endpoint is intended only for a separate trusted managed-auth service. It provisions a managed-mode sync session for an opaque managed `account_id` without sending email or password through the sync endpoint.

Most self-hosted operators do not need this. For normal community usage, leave `MANAGED_BRIDGE_TOKEN` unset and ignore this endpoint.

## Development

Common commands from the repository root:

```bash
go test ./...
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.6.1 ./...
```

Project structure:

- `cmd/ovumcy-sync-community` — application entrypoint (`migrate`, `serve`, `healthcheck`)
- `internal/api` — HTTP transport, handlers, and response mapping
- `internal/services` — domain logic (`AuthService`, `SyncService`)
- `internal/db` — persistence, repositories, and forward-only migrations under `internal/db/migrations/`
- `internal/models` — transport-free domain types
- `internal/security` — password hashing, tokens, and field encryption
- `internal/config` — runtime configuration from environment

CI runs staticcheck, `go vet`, tests with coverage, and a Docker runtime smoke on pushes and pull requests. A dedicated security workflow runs `gosec`, `govulncheck`, and Trivy filesystem/image scans and publishes a CycloneDX image SBOM; CodeQL, native fuzzing, and mutation testing run in their own workflows. See **[TESTING.md](TESTING.md)** for the full quality and security approach.

## Releases

- Latest tagged release: `v0.2.0`.
- Notable changes are tracked in [CHANGELOG.md](CHANGELOG.md); release notes are published via GitHub Releases.

## License

Ovumcy Sync Community is source-available under the **PolyForm Noncommercial
License 1.0.0**. You may view, self-host, use, and modify it for any
noncommercial purpose, and share it noncommercially. Commercial use is not
granted; contact Ovumcy for a commercial license.
See [LICENSE](LICENSE).

Third-party Go module dependencies compiled into the binary and container image are listed
with their licenses in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

If you found a security issue, see [SECURITY.md](SECURITY.md).
