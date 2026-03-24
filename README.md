[![CI](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/ci.yml/badge.svg)](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/ci.yml)
[![Security](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/security.yml/badge.svg)](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/security.yml)
[![CodeQL](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/codeql.yml/badge.svg)](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/codeql.yml)
[![Coverage](https://codecov.io/gh/ovumcy/ovumcy-sync-community/graph/badge.svg)](https://app.codecov.io/gh/ovumcy/ovumcy-sync-community)
[![Go Report Card](https://goreportcard.com/badge/github.com/ovumcy/ovumcy-sync-community)](https://goreportcard.com/report/github.com/ovumcy/ovumcy-sync-community)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://go.dev/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker)](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/docker-image.yml)
[![Release](https://img.shields.io/github/v/release/ovumcy/ovumcy-sync-community?display_name=tag&sort=semver)](https://github.com/ovumcy/ovumcy-sync-community/releases)
[![Self-hosted](https://img.shields.io/badge/Self--hosted-yes-2ea44f)](https://github.com/ovumcy/ovumcy-sync-community/blob/main/docs/self-hosting.md)
[![Zero-knowledge](https://img.shields.io/badge/Zero--knowledge-transport-2ea44f)](https://github.com/ovumcy/ovumcy-sync-community#what-the-server-can-see)

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

## What You Get With Ovumcy App

This README describes the current `main` branch.

This repository currently provides:

- account registration and login;
- bearer session tokens with hashed storage;
- device registration;
- a capability document for the community/self-hosted mode;
- account-scoped wrapped recovery-key package storage for zero-knowledge recovery setup;
- encrypted blob upload and download for one account-scoped sync state.

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

Runtime endpoints:

- `GET /healthz` liveness
- `GET /readyz` readiness
- `GET /metrics` optional Prometheus endpoint for operators
- `POST /auth/register`
- `POST /auth/login`
- `DELETE /auth/session`
- `GET /sync/capabilities`
- `POST /sync/devices`
- `GET /sync/recovery-key`
- `PUT /sync/recovery-key`
- `GET /sync/blob`
- `PUT /sync/blob`

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

The compose baseline binds the service to `http://127.0.0.1:8080` and persists SQLite data under `./data`.

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

## License

Ovumcy Sync Community is licensed under AGPL v3.
See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

If you found a security issue, see [SECURITY.md](SECURITY.md).
