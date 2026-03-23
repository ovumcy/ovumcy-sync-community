[![CI](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/ci.yml/badge.svg)](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/ci.yml)
[![Security](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/security.yml/badge.svg)](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/security.yml)
[![CodeQL](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/codeql.yml/badge.svg)](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/codeql.yml)
[![Coverage](https://codecov.io/gh/ovumcy/ovumcy-sync-community/graph/badge.svg)](https://app.codecov.io/gh/ovumcy/ovumcy-sync-community)
[![Go Report Card](https://goreportcard.com/badge/github.com/ovumcy/ovumcy-sync-community)](https://goreportcard.com/report/github.com/ovumcy/ovumcy-sync-community)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://go.dev/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker)](https://github.com/ovumcy/ovumcy-sync-community/actions/workflows/docker-image.yml)
[![Self-hosted](https://img.shields.io/badge/Self--hosted-yes-2ea44f)](https://github.com/ovumcy/ovumcy-sync-community/blob/main/docs/self-hosting.md)
[![Zero-knowledge](https://img.shields.io/badge/Zero--knowledge-transport-2ea44f)](https://github.com/ovumcy/ovumcy-sync-community#what-the-server-can-see)

# ovumcy-sync-community

`ovumcy-sync-community` is the self-hosted encrypted sync backend for Ovumcy.

It is built for people who want self-hosted multi-device encrypted sync without turning the sync server into a plaintext health-data processor.

It is designed around a zero-knowledge contract:

- the server knows account identity, device registry, capability metadata, and encrypted blob metadata;
- the server stores only ciphertext for synced health data;
- the server never receives recovery phrases or plaintext health records.

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

## Current v1 Baseline

This README describes the current `main` branch.

This repository currently provides:

- account registration and login;
- bearer session tokens with hashed storage;
- device registration;
- a capability document for the community/self-hosted mode;
- account-scoped wrapped recovery-key package storage for zero-knowledge recovery setup;
- encrypted blob upload and download for one account-scoped sync state.

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
- `MANAGED_BRIDGE_TOKEN` optional bearer token that enables the machine-to-machine managed bridge endpoint
- `ALLOWED_ORIGINS` comma-separated allowlist for browser clients; empty by default

Runtime endpoints:

- `GET /healthz` liveness
- `GET /readyz` readiness
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
go run ./cmd/ovumcy-sync-community
```

## Docker

```bash
docker build -t ovumcy-sync-community .
docker run --rm -p 8080:8080 -v $(pwd)/data:/data ovumcy-sync-community
```

## Docker Compose

```bash
docker compose up --build
```

The compose baseline binds the service to `http://127.0.0.1:8080` and persists SQLite data under `./data`.

For a production-style self-hosted setup:

- put this service behind HTTPS;
- persist `/data`;
- keep `MANAGED_BRIDGE_TOKEN` unset unless you really run a separate trusted managed-auth service;
- set `ALLOWED_ORIGINS` only when browser clients need direct CORS access.

See [docs/self-hosting.md](docs/self-hosting.md) for a minimal reverse-proxy, TLS, and backup checklist.

## Optional Managed Bridge

If `MANAGED_BRIDGE_TOKEN` is configured, the service also enables:

- `POST /managed/session`

This endpoint is intended for a separate trusted managed-auth service. It provisions a managed-mode sync session for an opaque managed `account_id` without sending email/password through the sync endpoint.

The managed bridge is not a public sign-in surface. End users should not send their email or password to `/managed/session`.

## License

Ovumcy Sync Community is licensed under AGPL v3.
See [LICENSE](LICENSE).
