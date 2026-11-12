# Traefik reverse proxy

A reference compose override: Traefik terminates TLS (Let's Encrypt, TLS-ALPN challenge), sends the
real client address upstream, limits request bodies, and answers `/metrics` with `403`.
[docker-compose.traefik.yml](docker-compose.traefik.yml) is meant to be layered on the base
`docker-compose.yml`; the app container listens on plain HTTP `:8080`.

## Use

```bash
export SYNC_HOST=sync.example.com
export ACME_EMAIL=ops@example.com
export TRUSTED_PROXY_CIDRS=<Docker network subnet>
docker compose -f docker-compose.yml -f docs/examples/reverse-proxy/traefik/docker-compose.traefik.yml config --quiet
docker compose -f docker-compose.yml -f docs/examples/reverse-proxy/traefik/docker-compose.traefik.yml up -d
```

If the base file publishes the app's port to the host, remove that mapping so the proxy is the only
entry point.

## What it does and why

- **Client address.** The entrypoint does not trust inbound `X-Forwarded-*` headers
  (`forwardedheaders.insecure=false`), so Traefik replaces them with the connecting client's
  address. The server honours them only from `TRUSTED_PROXY_CIDRS`.
- **`TRUSTED_PROXY_CIDRS`** must contain Traefik's address as the app sees it. Use the shared
  network subnet (`docker network inspect <network>`), not a public range. Without it all users
  share one rate-limit bucket and get `429 rate_limited`; see
  [troubleshooting.md](../../../troubleshooting.md).
- **Body size.** The buffering middleware caps bodies at 32 MiB. With the default `MAX_BLOB_BYTES`
  (16 MiB) an upload is a base64 JSON body of about 21.3 MiB; raise the cap with `MAX_BLOB_BYTES`.
- **Timeouts.** Responding read/write timeouts are 30 s, above the app defaults
  (`HTTP_READ_TIMEOUT=10s`, `HTTP_WRITE_TIMEOUT=15s`). Keep them at or above the app values.
- **`/metrics`.** A higher-priority router for `Path(/metrics)` applies an IP allowlist containing
  only a documentation address (`192.0.2.1/32`), so every real caller gets `403`. Scrape from
  inside the Docker network.
- The Docker socket is mounted read-only for provider discovery; that is still sensitive access.
  Use a socket proxy if that matters in your environment.
