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
3. If you do not have snapshot support, either stop the service or take a
   WAL-consistent copy (see below) — merely pausing new requests is not enough.

> **The database runs in WAL mode.** Recent writes live in the `-wal` sidecar
> until they are checkpointed into the main `.sqlite` file. Copying only
> `./data/ovumcy-sync-community.sqlite` while the service is running — even with
> writes paused — silently drops everything still in the `-wal` file. Use one of
> the WAL-safe methods below, not a bare copy of the main file.

## Simple Backup Flow

For the repository's default Docker Compose layout, the SQLite file lives under `./data/ovumcy-sync-community.sqlite` on the host.

Pick one WAL-safe method:

- **Service stopped.** Stop the container first (a clean shutdown checkpoints
  the WAL), then copy `./data/ovumcy-sync-community.sqlite`. The shutdown logs
  `close database: wal checkpoint blocked by a concurrent reader/writer ...`
  if some other connection to the database file — a second `sqlite3` shell, a
  monitoring or replication tool, another process pointed at the same file —
  held the checkpoint back. Check the shutdown logs for that line before
  trusting the copy: if it's there, the file is not self-contained — close
  the other connection and stop the service again, or fall back to one of the
  service-running methods below.
- **Service running.** Take a consistent snapshot without a bare copy — either
  copy `.sqlite`, `.sqlite-wal`, and `.sqlite-shm` together, or produce a
  single self-contained file with SQLite's online backup:

  ```bash
  sqlite3 ./data/ovumcy-sync-community.sqlite "VACUUM INTO './backup/ovumcy-sync-community.sqlite'"
  ```

Store the backup with the same care you would use for other sensitive application metadata.

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
2. run an integrity check on the restored file **before** trusting it:

   ```bash
   sqlite3 ./data/ovumcy-sync-community.sqlite "PRAGMA integrity_check"
   ```

   It must print `ok`. `migrate` does not scan table data — it can succeed on a
   file whose data pages are corrupt — so a green `migrate` is not proof the
   restore is intact. It is also not proof the backup itself was WAL-complete:
   a bare copy taken while data was still sitting in an uncheckpointed `-wal`
   is a structurally valid, merely stale file, and `integrity_check` reports
   `ok` on it the same as it would on a complete one — this step catches
   page-level corruption, not a missed checkpoint (see the shutdown-log note
   above);
3. run `migrate`;
4. start `serve`;
5. verify `readyz`;
6. log in with a non-production test account or a staged copy of a real account;
7. confirm blob and recovery-key round trips.

## Metrics Note

If you enable `/metrics`, treat it as an operator endpoint:

- keep it internal when possible;
- or protect it with `METRICS_BEARER_TOKEN`;
- or block it at the reverse proxy and scrape the backend container directly from your private network.
