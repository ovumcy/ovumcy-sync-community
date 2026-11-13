# Troubleshooting

Symptom, cause, fix. Every error key below is the literal `error` value the server returns. For
setup see [self-hosting.md](self-hosting.md); for upgrades see [upgrading.md](upgrading.md).

First checks, in order:

1. `docker compose ps` — is the container `healthy`?
2. `docker compose logs --tail=100 ovumcy-sync-community` — startup refusals (bad config, schema
   ahead of the binary, unwritable `/data`) are logged there, and `serve` exits before listening.
3. `GET /healthz` answers `200` whenever the HTTP loop is alive. `GET /readyz` also touches the
   database and answers `503 not_ready` when the store is unusable or its schema is not the one
   this binary expects.

## Everyone gets `429 rate_limited` behind a reverse proxy

**Cause.** `TRUSTED_PROXY_CIDRS` is unset (or does not contain the proxy's address), so the server
keys the auth rate limiter on the TCP peer, which is the proxy. All users then share one bucket
(`AUTH_RATE_LIMIT_COUNT` per `AUTH_RATE_LIMIT_WINDOW`, default 10 per minute).

**Fix.**

1. Set `TRUSTED_PROXY_CIDRS` to the proxy's address or network as the app container sees it
   (comma-separated, e.g. the Docker network subnet).
2. Make the proxy send `X-Forwarded-For` carrying the real client address. The server walks that
   header from the right and uses the first address that is not itself a trusted proxy.
   `X-Real-IP` is never read. If the connecting peer is not trusted, the header is ignored.
3. Have the proxy overwrite client-supplied values rather than append to them. Working examples:
   [nginx](examples/reverse-proxy/nginx/setup.md), [Traefik](examples/reverse-proxy/traefik/setup.md).

Do not trust a whole public range just to silence the 429: any client could then pick its own
rate-limit key.

## Container is `unhealthy`

**Cause.** The image `HEALTHCHECK` runs `ovumcy-sync-community healthcheck`, which requests
`http://127.0.0.1:<port>/readyz` (port taken from `BIND_ADDR`, default `8080`) with a 5 s timeout.
`/readyz` is schema-aware, so unhealthy means the process cannot serve the database it holds:
the file is unreadable or unwritable, the schema is ahead of this binary, or migrations are
pending.

**Fix.** Read the logs. Then, as applicable: fix `/data` permissions (next section), run
`migrate` for pending migrations, or deploy the build that applied the schema (see
"schema is ahead" below). If you changed `BIND_ADDR` to another port, the check follows it.

## `permission denied` on `/data`

**Cause.** The image runs as uid/gid `65532` (distroless nonroot) and `/data` is the volume
holding the SQLite file. A bind mount or a volume created by another user is not writable by it.

**Fix.** Make the directory owned by `65532:65532` (`chown -R 65532:65532 <host-path>`), or use a
named Docker volume, which is seeded from the image with that owner. Do not run the container as
root to work around it.

## `503 totp_not_configured`

**Cause.** `FIELD_ENCRYPTION_KEY` is unset (or empty). Two-factor is off by default and the
`/auth/totp/*` endpoints all return this.

**Fix.** To use 2FA, set `FIELD_ENCRYPTION_KEY` to a hex-encoded key of at least 32 bytes (64 hex
characters) and restart; see "Optional Two-Factor Authentication" in
[self-hosting.md](self-hosting.md). If nobody uses 2FA, the response is expected.

## An account with 2FA fails to log in after a key change

**Cause.** Login for an account that has enrolled in 2FA returns `503 totp_not_configured`
instead of a password-only session when the server has no key (fail closed). With a different
key set, the stored TOTP secret cannot be decrypted, so that account's second factor cannot be
verified.

**Fix.** Restore the original `FIELD_ENCRYPTION_KEY` (keep it backed up with the database). The
key is not rotatable in place: changing it invalidates every stored TOTP secret and forces every
2FA-enabled owner to re-enroll. See the key-handling notes in [self-hosting.md](self-hosting.md).

## Uploads time out or fail on slow links

**Cause.** `PUT /sync/blob` carries the ciphertext base64-encoded in JSON. With the default
`MAX_BLOB_BYTES` of 16 MiB the server accepts a request body of about 21.3 MiB (4/3 of the blob
size plus 8 KiB). The server enforces `HTTP_READ_TIMEOUT` (default `10s`) and
`HTTP_WRITE_TIMEOUT` (default `15s`); a slow link may not finish the body in time. A proxy in
front has its own limits too.

**Fix.**

- Raise `HTTP_READ_TIMEOUT` and `HTTP_WRITE_TIMEOUT` (Go durations, must be positive).
- Make the proxy body-size limit larger than the encoded request (the examples use 32 MiB) and
  its read/send timeouts at least as long as the app's, or the proxy cuts the request first
  (nginx `413`, `408`, `504`).
- A body over the app's limit is rejected as `400 invalid_json`, not as a size error.

## `schema is ahead of this binary`

**Cause.** An older image was started against a database a newer build already migrated.
Migrations only move forward; `serve` and `migrate` both refuse, naming the migration, and a
running older process turns `503 not_ready` on `/readyz`.

**Fix.** Deploy the build that applied the migration, or restore the database backup taken
before the upgrade together with the older image. See "Upgrading And Rolling Back" in
[self-hosting.md](self-hosting.md) and [upgrading.md](upgrading.md).

## Browser or web client preflight rejected: `403 origin_not_allowed`

**Cause.** A request with an `Origin` header that is not in `ALLOWED_ORIGINS` and uses the
`OPTIONS` method is refused. Without `ALLOWED_ORIGINS` no origin is allowed. Native apps do not
send `Origin` and are not affected.

**Fix.** Add the exact origin (scheme, host, port, no trailing slash) to the comma-separated
`ALLOWED_ORIGINS` and restart. Allowed origins get `Access-Control-Allow-Headers:
Authorization, Content-Type` and methods `GET, POST, PUT, DELETE, OPTIONS`. If the proxy
answers `OPTIONS` itself, make sure it does not strip these headers.

## `/metrics` returns `404 not_found`, `401 unauthorized` or `403`

- `404 not_found` — `METRICS_ENABLED` is not `true`; the endpoint is off by default.
- `401 unauthorized` — the scraper did not send `METRICS_BEARER_TOKEN` as a matching
  `Authorization: Bearer <token>`.
- `403` with body `metrics_not_exposed` — the reference proxy configs block `/metrics` at the
  public edge on purpose. Scrape it from inside the Docker network instead of through the proxy.
