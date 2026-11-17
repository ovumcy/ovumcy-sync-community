# Upgrading

The ordinary path is: pull the new image, run `migrate`, start `serve`. Rolling back is not
symmetric — read "Rollback limits" before you start. Background:
[self-hosting.md](self-hosting.md) ("Upgrading And Rolling Back").

## Pre-upgrade checklist

1. **Back up the database.** Stop writes or snapshot the volume, then copy the `/data` volume
   (the SQLite file). Do this before `migrate`, not after: it is the only thing that makes a
   rollback possible. Procedure and restore drill: [backup-restore.md](backup-restore.md).
2. **Back up `FIELD_ENCRYPTION_KEY`** (if set) alongside the database, in your secret store. It
   cannot be recovered from the database, and a different key leaves 2FA-enrolled accounts unable
   to log in ([troubleshooting.md](troubleshooting.md)).
3. **Read the release notes** for the target version for new or changed environment variables.
4. **Pin the image by digest.** Resolve the tag you intend to run to its `sha256:` digest and
   reference `ghcr.io/ovumcy/ovumcy-sync-community@sha256:<digest>` in your compose file, so what
   you verified is what runs. Release tags are `X.Y.Z`, `vX.Y.Z`, `X.Y` and `latest`; `latest`
   and `X.Y` move only when a release is tagged. `main` is the unreleased tip of the main branch
   and may carry migrations no release has announced: do not run it in production.
5. **Verify the signature and provenance** of that image as described in "Verifying Release
   Integrity" in [self-hosting.md](self-hosting.md) (cosign v3 or newer; `gh attestation verify`
   for provenance and SBOMs). Do not copy the commands here; that section is the reference.
6. Note the currently running image digest so you can name it in a rollback.

## Procedure

1. Pull the new image (by digest).
2. Stop the running `serve` container, so an old process does not hold the volume while the new
   one migrates.
3. Run migrations once against the volume:

   ```bash
   docker compose run --rm ovumcy-sync-community migrate
   ```

   Use the same `-f` files you normally run with. `migrate` logs `applied database migrations`
   on success. If it refuses with `database schema is ahead of this binary`, you are starting an
   older image than the one that last touched the database. `migrate` has no time limit, since
   building an index over a large table can take minutes; stop it with Ctrl-C or SIGTERM, which
   rolls back only the migration in progress. Run one `migrate` at a time. A second run that
   waits more than 5 s for the first one's lock exits with `database is locked`, leaving no
   migration half-applied; run it again once the first has finished.
4. Start `serve`: `docker compose up -d`.
5. Check readiness. `GET /readyz` must answer `200` (it also compares the applied migrations with
   what the binary embeds), and `docker compose ps` should show `healthy` once the 20 s start
   period passes:

   ```bash
   curl -fsS https://<your-host>/readyz
   ```

   `GET /healthz` is a constant liveness answer and does not prove the database is usable.
6. Smoke-test from the Ovumcy app: sign in and run one sync.

## Rollback limits

- Migrations are forward-only; there are no down-migrations. After a newer build migrates the
  database, an older build refuses to start against it.
- A rollback is a pair: the older image **and** the database backup taken before the upgrade.
  Writes made after the upgrade are not in that backup and are lost on restore.
- If losing those writes is unacceptable, fix forward on the newer build instead of rolling back.
- A rolled-back image started against an unrestored database does not serve traffic; it exits at
  startup, and a running older process turns `503 not_ready` once a newer image migrates the
  volume.
- Restore `FIELD_ENCRYPTION_KEY` to the value that matches the restored data.

Symptoms during an upgrade are covered in [troubleshooting.md](troubleshooting.md).
