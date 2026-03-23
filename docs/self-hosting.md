# Self-Hosting Guide

This repository is designed for a simple self-hosted baseline:

- one instance;
- one SQLite database;
- one persistent data volume;
- HTTPS terminated at the edge.

It is intended to be used with the [Ovumcy app](https://github.com/ovumcy/ovumcy-app) in `Self-hosted` sync mode.

## What Self-Hosting Means For Ovumcy App

When you self-host `ovumcy-sync-community`, you are operating the optional encrypted sync server for the Ovumcy app.

In the app, users can:

- prepare a device for encrypted sync;
- save a recovery phrase locally;
- register or sign in against their own server;
- upload encrypted sync state;
- restore encrypted sync state on another device.

Core tracking in the Ovumcy app still remains local-first. This server is for optional sync and recovery transport, not for normal day-to-day product use.

## Minimum Deployment Shape

1. Run `ovumcy-sync-community` behind a reverse proxy such as Caddy, Nginx, or Traefik.
2. Persist `/data` so SQLite survives container restarts.
3. Expose the service only through HTTPS on the public internet.
4. Keep `MANAGED_BRIDGE_TOKEN` empty unless you operate a separate trusted managed-auth service.
5. Set `TRUSTED_PROXY_CIDRS` if you want auth rate limiting to use real client IPs from a trusted reverse proxy.
6. Keep `/metrics` internal or protect it with `METRICS_BEARER_TOKEN` if you enable metrics.

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
- `METRICS_ENABLED=false`
- `METRICS_BEARER_TOKEN=` optional bearer token for `GET /metrics`
- `TRUSTED_PROXY_CIDRS=` set this to your reverse-proxy IP or CIDR when you want forwarded client IPs to participate in auth rate limiting

Adjust limits only when you understand the tradeoff between usability and abuse resistance.

## Basic Setup Flow In Ovumcy App

1. Deploy this service and put it behind HTTPS.
2. Run `ovumcy-sync-community migrate` once for the target database or volume.
3. Start `ovumcy-sync-community serve`.
4. Open the Ovumcy app and go to `Backup & sync`.
5. Choose `Self-hosted`.
6. Enter your sync endpoint, for example `https://sync.example.com`.
7. Prepare the device and save the recovery phrase somewhere safe.
8. Create an account on your own server or sign in to an existing one.
9. Run encrypted sync from the app.

## Optional Caddy Compose Example

The repository also includes `docker-compose.caddy.yml` and `deploy/caddy/Caddyfile` as a reference edge setup.

Use it like this:

```bash
docker compose -f docker-compose.yml -f docker-compose.caddy.yml run --rm ovumcy-sync-community migrate
docker compose -f docker-compose.yml -f docker-compose.caddy.yml up --build
```

The example is intentionally conservative:

- it reverse-proxies the sync service;
- it blocks `/metrics` at the public edge by default;
- it is still only a baseline and must be adapted to your real public hostname and TLS policy.

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

See [backup-restore.md](backup-restore.md) for a simple restore drill and operator checklist.

## Managed Bridge Note

`POST /managed/session` exists only for a separate trusted managed-auth service.

- It is not needed for normal self-hosted community usage.
- It should not be exposed as an end-user login flow.
- If you do not run a managed-auth service, leave `MANAGED_BRIDGE_TOKEN` unset.
