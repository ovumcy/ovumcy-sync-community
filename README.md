# ovumcy-sync-community

`ovumcy-sync-community` is the self-hosted encrypted sync backend for Ovumcy.

It is designed around a zero-knowledge contract:

- the server knows account identity, device registry, capability metadata, and encrypted blob metadata;
- the server stores only ciphertext for synced health data;
- the server never receives recovery phrases or plaintext health records.

## Current foundation

This repository currently provides:

- account registration and login;
- bearer session tokens with hashed storage;
- device registration;
- a capability document for the community/self-hosted mode;
- encrypted blob upload and download for one account-scoped sync state.

## Configuration

Environment variables:

- `BIND_ADDR` default `:8080`
- `DB_PATH` default `./data/ovumcy-sync-community.sqlite`
- `SESSION_TTL` default `720h`
- `MAX_DEVICES` default `5`
- `ALLOWED_ORIGINS` comma-separated allowlist for browser clients; empty by default

## Run locally

```bash
go run ./cmd/ovumcy-sync-community
```

## Docker

```bash
docker build -t ovumcy-sync-community .
docker run --rm -p 8080:8080 -v $(pwd)/data:/data ovumcy-sync-community
```
