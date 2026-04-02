---
name: backend-testing
description: Plan and run focused Go verification for ovumcy-sync-community.
---

## Workflow

1. Prefer:
   - `go test ./...`
   - `go vet ./...`
   - `go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...`
2. If migrations or bootstrap changed, include migration-specific regression checks.
3. If auth or blob flows changed, call out the security sensitivity explicitly.
4. End with a short readiness summary for commit.

