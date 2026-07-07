# Contributing to Ovumcy Sync Community

Thanks for contributing.

## Development Setup

1. Install Go and Docker.
2. Run checks locally:

```bash
go test ./...
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.6.1 ./...
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run ./...
docker compose config
docker build -t ovumcy-sync-community-local .
```

If your change touches Go code, also gate it on patch coverage before opening a
PR: `scripts/patch-coverage-local.sh` (see "Checking patch coverage locally" in
[TESTING.md](TESTING.md) — a stale `coverage.out` gives a false pass, so don't
run `scripts/patchcov` by hand without a fresh profile).

**Recommended: enable the pre-push patch-coverage hook** so this runs
automatically instead of relying on remembering to run it by hand:

```bash
bash scripts/setup-hooks.sh
# equivalent one-liner, if you'd rather not run the script:
#   git config core.hooksPath scripts/hooks
```

This wires `scripts/hooks/pre-push` in via git's `core.hooksPath` (git does not
run a hook committed under a repo path unless something points it there first
— this is a one-time, per-clone setup step). Once enabled, `git push` first
checks whether the push includes any `*.go` changes:

- **No Go files changed** (e.g. a docs-only push): the hook exits immediately,
  no coverage run.
- **Go files changed**: the hook runs the same fresh patch-coverage gate as
  `scripts/patch-coverage-local.sh` (a few minutes — it reruns the real test
  suite on purpose, to avoid the stale-`coverage.out` false pass described
  above) and blocks the push if any modified line isn't covered, printing
  which lines and how to fix it.

Emergency bypass: `git push --no-verify` skips the hook entirely.

3. Run the server locally. The schema must exist first, so run `migrate` once before `serve`:

```bash
go run ./cmd/ovumcy-sync-community migrate
go run ./cmd/ovumcy-sync-community serve
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

## Contribution Licensing

By submitting a contribution to this repository (for example, a pull request),
you agree that:

- your contribution is licensed to the project and its users under the
  repository's license, the PolyForm Noncommercial License 1.0.0; and
- you additionally grant Ovumcy a perpetual, worldwide, non-exclusive,
  royalty-free, irrevocable license to use, reproduce, modify, distribute, and
  relicense your contribution under any terms, including commercial terms and
  inclusion in Ovumcy's proprietary products (such as Ovumcy Managed).

You confirm that you are legally entitled to grant these rights and that, to
your knowledge, the contribution is your original work.
