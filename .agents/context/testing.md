# Ovumcy Sync Community AI Context: Testing

## Backend Test Rules

- Run `go test ./...` and `staticcheck ./...` after backend changes.
- Keep service tests focused on behavior:
  - registration/login/session lifecycle,
  - capability policy,
  - device limits,
  - checksum and generation validation.
- Keep API tests focused on stable contracts:
  - HTTP status,
  - error key,
  - auth requirements,
  - JSON payload shape.

## Migration and Persistence Coverage

- Migration changes must stay covered by `internal/db/migrations_bootstrap_test.go`.
- Repository tests should verify multi-account isolation for device and blob ownership whenever schema or repository logic changes.

## CI Expectations

- CI must run the same core backend checks that developers rely on locally:
  - `go test ./...`
  - `staticcheck ./...`
- Prefer direct tool installation in CI over fragile third-party wrappers when the wrapper does not add product-specific value.
