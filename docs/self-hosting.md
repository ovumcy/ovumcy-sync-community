# Self-Hosting Guide

This repository is designed for a simple self-hosted baseline:

- one instance;
- one SQLite database;
- one persistent data volume;
- HTTPS terminated at the edge.

## Minimum Deployment Shape

1. Run `ovumcy-sync-community` behind a reverse proxy such as Caddy, Nginx, or Traefik.
2. Persist `/data` so SQLite survives container restarts.
3. Expose the service only through HTTPS on the public internet.
4. Keep `MANAGED_BRIDGE_TOKEN` empty unless you operate a separate trusted managed-auth service.

## Example Reverse Proxy Pattern

- public TLS endpoint: `https://sync.example.com`
- reverse proxy forwards to `http://127.0.0.1:8080`
- the reverse proxy is responsible for certificates, TLS policy, and internet exposure

This service itself does not terminate TLS. Production deployments should not expose raw `http://` directly to the public internet.

## Recommended Environment Baseline

- `DB_PATH=/data/ovumcy-sync-community.sqlite`
- `SESSION_TTL=720h`
- `MAX_DEVICES=5`
- `MAX_BLOB_BYTES=16777216`
- `AUTH_RATE_LIMIT_COUNT=10`
- `AUTH_RATE_LIMIT_WINDOW=1m`

Adjust limits only when you understand the tradeoff between usability and abuse resistance.

## What The Operator Can See

The server operator can see:

- the account login chosen on that self-hosted server;
- the existence of accounts and sessions;
- device labels and device count;
- blob generation, size, checksum, and timestamps;
- wrapped recovery-key package metadata.

The operator cannot read from this server alone:

- plaintext cycle or symptom data;
- notes or health history content;
- recovery phrases;
- client master keys.

## Backup Guidance

Back up the SQLite file and its volume as sensitive metadata-bearing infrastructure.

- The database does not contain plaintext health payloads.
- It does contain account identifiers, device metadata, wrapped recovery-key packages, and ciphertext blobs.

At minimum:

1. stop writes or use a consistent volume snapshot;
2. back up the `/data` volume;
3. protect backups as sensitive operational artifacts.

## Managed Bridge Note

`POST /managed/session` exists only for a separate trusted managed-auth service.

- It is not needed for normal self-hosted community usage.
- It should not be exposed as an end-user login flow.
- If you do not run a managed-auth service, leave `MANAGED_BRIDGE_TOKEN` unset.
