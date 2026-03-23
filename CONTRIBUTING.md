# Contributing to Ovumcy Sync Community

Thanks for contributing.

## Development Setup

1. Install Go and Docker.
2. Run checks locally:

```bash
go test ./...
go vet ./...
staticcheck ./...
docker compose config
docker build -t ovumcy-sync-community-local .
```

3. Run the server locally:

```bash
go run ./cmd/ovumcy-sync-community
```

## Reporting Bugs

Before opening a bug, check existing issues:
- https://github.com/ovumcy/ovumcy-sync-community/issues

When opening a bug report, include:
- environment (OS, Go version, Docker version, deployment shape),
- exact steps to reproduce,
- expected vs actual behavior,
- relevant logs,
- commit hash or branch if testing unreleased code.

Use the bug report template in `.github/ISSUE_TEMPLATE/bug_report.yml`.

Security issues should not be reported publicly. Use [SECURITY.md](SECURITY.md).

## Pull Request Rules

- Keep changes scoped and atomic.
- Add or adjust tests for behavioral changes.
- Keep the zero-knowledge server contract honest: do not add plaintext health-data handling, recovery-phrase transport, or decrypted payload processing without an explicit product change.
- Do not add runtime schema shortcuts or backward-incompatible migration behavior outside forward-only SQL migrations.

## Commit Style

Use imperative commit messages, e.g.:

- `Add readiness endpoint for sync-community`
- `Split CI checks for branch protection`
