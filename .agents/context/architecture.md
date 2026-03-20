# Ovumcy Sync Community AI Context: Architecture

## Backend Layers

- Backend: Go.
- Entrypoint in `cmd/`.
- Transport in `internal/api`.
- Business logic in `internal/services`.
- Persistence in `internal/db`.
- Domain models in `internal/models`.
- Security helpers in `internal/security`.

## Service Domains

- `AuthService` owns registration, login, session issuance, session authentication, and session revoke behavior.
- `SyncService` owns capability policy, device attachment, blob validation, blob generation monotonicity, and ciphertext size/checksum validation.

## Package Boundaries

- `internal/api` must not access the database directly.
- `internal/services` must not depend on `http.Request`, `http.ResponseWriter`, or transport-layer error formatting.
- `internal/db` methods should stay narrow and explicit so API handlers never build SQL or persistence policy ad hoc.
