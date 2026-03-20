# Ovumcy Sync Community AI Context

Read this file together with:

- `.agents/context/architecture.md`
- `.agents/context/security.md`
- `.agents/context/testing.md`
- `.agents/context/deployment.md`

## Core Principles

- Project: `ovumcy-sync-community` — privacy-sensitive community sync backend for Ovumcy.
- Goal: provide a self-hosted zero-knowledge sync server that stores only auth/account metadata, device metadata, and ciphertext blobs.
- This repository must stay production-grade and must not grow into a generic product backend that knows plaintext health data.

## Architecture Boundaries

- Entrypoint lives in `cmd/`.
- HTTP transport lives in `internal/api`.
- Business rules live in `internal/services`.
- Persistence lives in `internal/db`.
- Domain models live in `internal/models`.
- Cross-cutting security helpers live in `internal/security`.

## Security Invariants

- The server must not store or log plaintext health data, recovery phrases, client master keys, or decrypted sync payloads.
- Auth/session endpoints and sync blob endpoints are security-sensitive by default.
- Default HTTP responses should include baseline browser hardening headers and `Cache-Control: no-store`.
- Community mode capabilities must remain honest: do not claim managed-cloud premium or recovery features that do not exist in this server.

## Deployment Invariants

- The supported baseline is a single-instance self-hosted deployment with persistent SQLite storage and HTTPS at the edge.
- Runtime images must stay runtime-only; CI/test tooling must not leak into pushed runtime layers.
- All schema changes must go through forward-only SQL migrations.
