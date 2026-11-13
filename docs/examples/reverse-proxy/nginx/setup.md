# nginx reverse proxy

A reference edge for `ovumcy-sync-community`: TLS termination, the real client address forwarded
for rate limiting, a request size and timeout budget that fits blob uploads, and `/metrics` and
`/managed/*` blocked publicly. [nginx.conf](nginx.conf) is a `conf.d` file; adapt `server_name` and
the certificate paths.

## What it does and why

- **TLS** terminates at nginx; the app container speaks plain HTTP on `:8080`.
- **Client address.** `X-Forwarded-For` and `X-Real-IP` are set to `$remote_addr`, replacing
  anything the client sent. The server only honours these headers from addresses in
  `TRUSTED_PROXY_CIDRS`; see [troubleshooting.md](../../../troubleshooting.md).
- **Body size.** `client_max_body_size 32m`. With the default `MAX_BLOB_BYTES` (16 MiB) a blob upload
  is a base64 JSON body of about 21.3 MiB. Raise the limit together with `MAX_BLOB_BYTES`.
- **Timeouts.** 30 s, above the app defaults `HTTP_READ_TIMEOUT=10s` and `HTTP_WRITE_TIMEOUT=15s`.
  If you raise the app values, raise these too.
- **`/metrics`** returns `403` at the edge. Scrape it from inside the Docker network.
- **`/managed/*`** returns `403` at the edge. The managed bridge's one caller reaches the app over
  the private network, never through the public edge.

## App settings that must match

```
TRUSTED_PROXY_CIDRS=<nginx address or the Docker network subnet>
```

Find the subnet with `docker network inspect <network>`. Trust only the proxy, not a public range.
Without it every user shares one rate-limit bucket and gets `429 rate_limited`.

## Run

Put nginx and the app on one Docker network and mount the config and certificates, for example:

```yaml
services:
  nginx:
    image: nginx:stable
    ports: ["80:80", "443:443"]
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on: [ovumcy-sync-community]
```

Validate before reloading:

```bash
docker run --rm \
  -v "$PWD/nginx.conf:/etc/nginx/conf.d/default.conf:ro" \
  --add-host ovumcy-sync-community:127.0.0.1 \
  nginx:stable nginx -t
```

(That check also needs the certificate files at the configured paths.)
