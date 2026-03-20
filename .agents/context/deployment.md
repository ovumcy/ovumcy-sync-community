# Ovumcy Sync Community AI Context: Deployment

## Deployment Baseline

- The supported baseline is a single-instance self-hosted community sync server with persistent SQLite storage and HTTPS at the edge.
- Docker/runtime images must remain runtime-only.

## Storage and Migrations

- SQLite is the baseline storage engine for the community server today.
- All schema changes must go through forward-only SQL migrations.
- Do not add runtime auto-migration or schema drift behavior at application boot.

## Operator Contract

- Community mode must stay honest in docs and capability responses:
  - self-hosted,
  - encrypted blob sync,
  - no managed premium claims.
- Deployment docs must not imply that this server can decrypt owner data or recover data without the client recovery phrase.
