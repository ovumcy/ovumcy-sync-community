# Ovumcy Sync Community Agent Instructions

## Relationship to AI context

- Before making non-trivial changes in this repository, read:
  - `AI_CONTEXT.md`
  - `.agents/context/architecture.md`
  - `.agents/context/security.md`
  - `.agents/context/testing.md`
  - `.agents/context/deployment.md`
- Treat that local AI context set as the source of truth for sync-server flows and invariants.

## Core Rules

- Keep the repository layered: `api -> services -> db -> models`.
- `internal/api` owns only transport concerns: request parsing, auth/session checks, response mapping, and headers.
- `internal/services` owns domain rules such as auth, session lifecycle, capability policy, device attachment, blob generation rules, and checksum validation.
- `internal/db` owns persistence only and must not grow HTTP or business logic.

## Zero-Knowledge Contract

- Do not add plaintext health-data fields, decrypted snapshot handling, or recovery-phrase transport to this server unless the product contract changes explicitly.
- The server may know:
  - account identity,
  - entitlement/capability state,
  - device metadata,
  - blob metadata,
  - ciphertext.
- The server must not know:
  - cycle dates,
  - symptoms,
  - notes,
  - recovery phrases,
  - client master keys,
  - decrypted payload content.

## Security-Sensitive Changes

- Treat all changes in `internal/security`, auth/session flows, capability policy, rate limiting, and blob upload/download flows as security-sensitive.
- For such changes:
  - call out the security sensitivity explicitly,
  - add or update focused tests,
  - avoid logging secrets, tokens, login identifiers, or blob contents.

## Testing Expectations

- After backend changes, run `go test ./...` and `staticcheck ./...`.
- Migration changes must update or stay compatible with `internal/db/migrations_bootstrap_test.go`.
- API tests should assert stable error keys and status codes instead of relying on incidental response wording.

## Deployment Rules

- Do not add runtime schema changes or auto-migration behavior at boot.
- Do not modify Docker/runtime defaults without checking that the repository still describes a supported self-hosted contract.
- Keep the baseline deployment path self-hosted and honest about its capabilities.
