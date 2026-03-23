# Backup And Restore Runbook

This runbook is for the self-hosted `ovumcy-sync-community` baseline:

- one service instance;
- one SQLite database under `/data`;
- HTTPS terminated at the edge.

## What Needs Backup

Back up the SQLite database or the entire `/data` volume as sensitive operational state.

The backup contains:

- account and session metadata;
- device metadata;
- encrypted blob metadata;
- ciphertext blobs;
- wrapped recovery-key package metadata.

It does not contain plaintext health data, recovery phrases, or client master keys.

## Before You Start

1. Make sure the service is healthy before the backup window.
2. Prefer a consistent filesystem or volume snapshot.
3. If you do not have snapshot support, stop writes during the copy.

## Simple Backup Flow

For the repository's default Docker Compose layout, the SQLite file lives under `./data/ovumcy-sync-community.sqlite` on the host.

Recommended baseline:

1. Stop the service or otherwise freeze writes.
2. Copy `./data/ovumcy-sync-community.sqlite` to your backup target.
3. Store the backup with the same care you would use for other sensitive application metadata.

## Simple Restore Flow

1. Stop the running service.
2. Restore the SQLite file into `./data/ovumcy-sync-community.sqlite` or your chosen `/data` location.
3. Run the explicit migration step for the restored database:

```bash
docker compose run --rm ovumcy-sync-community migrate
```

4. Start the service again:

```bash
docker compose up --build
```

5. Verify:
   - `GET /readyz` returns `200`
   - account login still works
   - `GET /sync/blob` and `GET /sync/recovery-key` still work for a known test account

## Restore Drill Recommendation

Do at least one restore drill before you rely on this server operationally:

1. copy a real backup to a disposable environment;
2. run `migrate`;
3. start `serve`;
4. verify `readyz`;
5. log in with a non-production test account or a staged copy of a real account;
6. confirm blob and recovery-key round trips.

## Metrics Note

If you enable `/metrics`, treat it as an operator endpoint:

- keep it internal when possible;
- or protect it with `METRICS_BEARER_TOKEN`;
- or block it at the reverse proxy and scrape the backend container directly from your private network.
