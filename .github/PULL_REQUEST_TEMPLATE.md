<!-- Keep changes scoped and atomic. See CONTRIBUTING.md. -->

## Summary

<!-- What does this change do, and why? -->

## Layer(s) touched

<!-- api (transport) / services (rules) / db (persistence) / models / security / docs / ci -->

## Checklist

- [ ] Tests added or adjusted for behavioral changes (`go test ./...` passes).
- [ ] `go vet ./...`, `staticcheck`, and `golangci-lint` are clean.
- [ ] Zero-knowledge contract held: no plaintext health data, recovery phrases, client master keys, or decrypted payloads are stored, logged, or inspected.
- [ ] No secret (password, session/reset token, recovery code, login identifier, TOTP secret/code, `FIELD_ENCRYPTION_KEY`, blob contents) is logged.
- [ ] Any security-relevant change updates `SECURITY.md` (and its Test Enforcement Matrix) in the same PR.
- [ ] Schema changes go through a forward-only migration under `internal/db/migrations/`.
- [ ] Public HTTP surface changes are reflected in `openapi.yaml` and the README endpoint list.

## Risk & rollback

<!-- What could this break, and how is it reverted? -->
