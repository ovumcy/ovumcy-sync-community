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
- `FIELD_ENCRYPTION_KEY=` optional hex-encoded master key (>=32 bytes / 64 hex chars) that enables the TOTP second-factor surface; leave unset to disable 2FA entirely (see *Optional Two-Factor Authentication* below)
- `TOTP_ISSUER=ovumcy-sync-community` optional label embedded in `otpauth://` provisioning URIs so authenticator apps know which instance the secret belongs to
- `LAPSED_ACCOUNT_GRACE_PERIOD=1440h` (60 days) how long a managed account's data is kept after the managed bridge signals an entitlement lapse, before it is erased; irrelevant unless you run the managed bridge (see *Entitlement-Lapse Cleanup* below)
- `LAPSED_ACCOUNT_SWEEP_INTERVAL=24h` how often `serve` purges accounts past that window on its own; `0` disables the in-process sweep and leaves `purge-lapsed-accounts` as the only trigger. `LAPSED_ACCOUNT_SWEEP_LIMIT` caps candidates per run (`0` or unset = store default)
- `EXPIRED_ROWS_SWEEP_INTERVAL=24h` how often `serve` deletes expired sessions, password-reset tokens, and TOTP challenges. Expiry is already enforced at use time on every read path, so this is data minimization, not a security switch; `0` disables the sweep. `EXPIRED_ROWS_SWEEP_LIMIT` caps rows per table per run (`0` or unset = store default)
- `HTTP_READ_TIMEOUT=10s` / `HTTP_WRITE_TIMEOUT=15s` per-request read/write windows. A full `MAX_BLOB_BYTES` transfer must fit inside them — at the defaults a 16 MiB blob needs roughly 1.7 MB/s of client bandwidth — so widen both on deployments syncing large blobs over slow links; zero is rejected (a zero `net/http` timeout means no timeout at all)

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

## Optional Two-Factor Authentication

`ovumcy-sync-community` supports optional TOTP (RFC 6238) as a second factor on top of the account password. 2FA is **off by default**: the relevant endpoints all return `503 totp_not_configured` until you set a server-wide master key.

### Enabling

1. Generate a 32-byte master key and place it in the environment as 64 hex characters:

   ```bash
   openssl rand -hex 32
   ```

2. Set `FIELD_ENCRYPTION_KEY` to that hex string. Optionally override `TOTP_ISSUER` (default `ovumcy-sync-community`); the issuer label is what authenticator apps display next to the account.

3. Restart the server. The TOTP endpoints (`/auth/totp/{enroll,verify,disable,challenge}`) become live; password-only login still works for accounts that have not opted in.

After that, any owner who opens *Account Security* in the Ovumcy app can enroll an authenticator app. Login on a 2FA-enabled account returns a short-lived challenge handoff instead of a session; the app drives the 6-digit prompt and completes the challenge to receive a real session.

### What The Server Stores

- TOTP secrets are AES-256-GCM encrypted with an HKDF-SHA256-derived key. The ciphertext lives in `accounts.totp_secret_encrypted` and is AEAD-bound to the account id, so a database-level row swap cannot decrypt one account's secret into another.
- Each successful verification advances `accounts.totp_last_used_step` atomically; the same step cannot be replayed inside its 30-second window.
- Login second-factor challenges are persisted only as SHA-256 hashes in `totp_challenges`, expire after 5 minutes, and are single-use.

### Operational Notes

- **Treat `FIELD_ENCRYPTION_KEY` as a long-lived secret.** Back it up alongside your database. Rotation is *not* transparent: changing the key invalidates every stored TOTP secret and forces every 2FA-enabled owner to re-enroll. There is no in-place key rotation.
- **Never log the key, the otpauth provisioning URIs, raw codes, or raw challenge ids.** The server already redacts these; if you add custom logging, keep them out.
- **2FA is per account, not server-wide.** Even after you set the env var, individual owners must explicitly enroll. Existing accounts continue to log in with password only until they opt in.
- **Disabling the server-wide key after some accounts enrolled is destructive.** The TOTP endpoints will start returning `503 totp_not_configured` and those owners cannot complete login. Either keep the key set or have owners disable 2FA on their accounts first.

## What The Operator Can See

The server operator can see:

- the account login chosen on that self-hosted server;
- the existence of accounts and sessions;
- device labels and device count;
- blob generation, size, checksum, and timestamps;
- wrapped recovery-key package metadata;
- whether an account has 2FA enabled, the encrypted TOTP secret blob, and hashes of any in-flight TOTP login challenges (never the secret in plaintext, never raw codes).

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

## Verifying Release Integrity

The container image is signed with [Sigstore](https://www.sigstore.dev/) keyless signing (no
long-lived keys to manage) and carries SLSA build provenance. Verifying the image before you run it
confirms it was built by this repository's CI from this source and was not tampered with in
transit. (Images published before this was in place may not yet carry these assets.)

The published image is cosign-signed and carries build provenance:

```bash
cosign verify ghcr.io/ovumcy/ovumcy-sync-community:<tag> \
  --certificate-identity-regexp '^https://github.com/ovumcy/ovumcy-sync-community/\.github/workflows/docker-image\.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Account Deletion

`DELETE /account` lets an authenticated owner permanently erase their own account and every row this server holds for it: sessions, devices, the encrypted sync blob, the wrapped recovery-key package, any pending password reset token, and any pending TOTP login challenge. This exists for Google Play data-deletion compliance and general privacy hygiene.

Operational notes:

- The delete is irreversible. There is no soft-delete, undo window, or server-side recovery once the transaction commits — the only way back is restoring the whole `/data` volume from a backup taken before the delete, which would also roll back every other account's state in the same restore.
- The request is authenticated the same way as every other account-scoped endpoint (`Authorization: Bearer <session token>`). The server only ever erases the account behind that session; there is no request field that can name a different account, so a stolen or forged request cannot be used to erase someone else's data.
- The endpoint is idempotent at the account-data level: once an account is gone, a request that could somehow still prove ownership of it would be a no-op rather than an error. In practice a repeat call with the same bearer token gets `401 unauthorized` instead, because the session itself was deleted along with the account — the same outcome ("this account's data does not exist") either way.
- This is a one-account operation. It does not touch, rate-limit, or otherwise affect other accounts on the same server.

## Managed Bridge Note

`POST /managed/session` exists only for a separate trusted managed-auth service.

- It is not needed for normal self-hosted community usage.
- It should not be exposed as an end-user login flow.
- If you do not run a managed-auth service, leave `MANAGED_BRIDGE_TOKEN` unset.

## Entitlement-Lapse Cleanup

This section only applies if you run the managed bridge (`MANAGED_BRIDGE_TOKEN` set). Plain self-hosted/community accounts are entirely unaffected — they can never carry the lapse marker described below.

When a managed account's subscription lapses, the separate managed-auth service calls `POST /managed/accounts/{account_id}/premium` with `{"active": false}`. This server responds by:

1. Clearing `premium_active` and recording the lapse timestamp.
2. Immediately revoking every still-valid session the account holds — no entitlement, no sync, from that moment on.
3. Leaving the account's encrypted data (`encrypted_blobs`, the wrapped recovery-key package, devices) exactly where it is.

The retained data is erased only after `LAPSED_ACCOUNT_GRACE_PERIOD` (default 60 days) has elapsed.

`serve` does this itself, every `LAPSED_ACCOUNT_SWEEP_INTERVAL` (default `24h`), starting one interval after boot. Nothing to schedule: the retention window the paragraph above promises is enforced by the running server, not by an operator remembering to wire a timer. `LAPSED_ACCOUNT_SWEEP_LIMIT` caps how many candidates one run examines (unset uses the store's default page size), and `LAPSED_ACCOUNT_SWEEP_INTERVAL=0` turns the in-process sweep off entirely — which is also the rollback lever, effective on restart with no new image.

The same work is available on demand as a subcommand, for a one-off run, a dry-run audit, or as the sole trigger on a deployment that keeps the interval at `0`:

```bash
ovumcy-sync-community purge-lapsed-accounts            # deletes eligible accounts
ovumcy-sync-community purge-lapsed-accounts -dry-run    # report only, deletes nothing
ovumcy-sync-community purge-lapsed-accounts -limit 200  # cap how many candidates one run examines
```

Both triggers drive the identical eligibility path and are idempotent, so an existing cron or systemd timer alongside the in-process sweep is harmless — neither can delete anything the other would have spared. Each subcommand run prints a stable, greppable summary to stdout and never logs anything beyond account ids:

```
lapsed_account_sweep_dry_run=false
lapsed_account_sweep_examined=3
lapsed_account_sweep_deleted=1
lapsed_account_sweep_deleted_account_id=<account id>
```

Operational notes:

- **A resubscribe within the grace period is always safe.** The very next `POST /managed/session` mint for the account clears the lapse marker and restores `premium_active` on its own — no separate "un-lapse" call is required, and the device's encrypted snapshot is never touched.
- **The signal is idempotent.** Replaying `{"active": false}` for an already-lapsed account never pushes the recorded lapse timestamp forward, so a retried or duplicated signal can never extend the retention window past the configured grace period.
- **The sweep re-checks eligibility at the moment of deletion, not at the moment of listing.** If a resubscribe races a scheduled sweep run, the account and every row it owns survive intact — the delete is scoped inside one transaction that re-verifies the account is still lapsed and still past grace before anything is removed.
- **This erases the whole account**, the same as `DELETE /account` or the managed-bridge purge: sessions, devices, the encrypted blob, the recovery-key package, and the account row itself, in one transaction. The device re-uploads its snapshot on the next sync after resubscribing past the grace period.
- Deploy `ovumcy-sync-community` before the managed service starts calling this endpoint — it is purely additive and safe to have present-but-unused on an older managed deployment.
