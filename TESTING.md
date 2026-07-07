# Testing & Quality

`ovumcy-sync-community` is the self-hosted Ovumcy sync server. It stores and
serves **encrypted** backup blobs and account metadata; it never sees plaintext
health data, decrypted payloads, recovery phrases, or client master keys. Its job
is to be correct about authentication and storage and paranoid about the security
primitives it owns. This document describes how that is tested, and how we verify
the tests themselves are worth anything. Every claim here is backed by code in
the repository and by CI.

## Layers

| Layer | What it checks | Where |
|-------|----------------|-------|
| **Unit** | Account, session, entitlement, and sync-blob business logic | `internal/services/*_test.go` |
| **Integration** | HTTP handlers against a real SQLite database — register/login, TOTP, device + blob upload/restore | `internal/api/*_test.go` |
| **Persistence** | Repository queries, constraints, and cascade behavior | `internal/db/*_test.go` |
| **Security primitives** | Password hashing, opaque tokens, field encryption, TOTP, login normalization | `internal/security/*_test.go` |
| **Property-based** | Invariants of the security primitives over thousands of generated inputs | `internal/security/security_property_test.go` (`pgregory.net/rapid`) |
| **Fuzz** | Robustness of parsers/validators against arbitrary/invalid input | `internal/security/security_fuzz_test.go` (native Go fuzzing) |
| **Runtime smoke** | A live server is registered against, signs in, exercises TOTP, and uploads/restores a blob | `scripts/runtime-smoke.sh` |

Currently **120+ Go test and fuzz functions** across `internal/`. Tests favor
behavior and persisted state over implementation details.

CI runs the full suite twice in parallel: a `test` job that generates the
coverage profile (`-coverpkg=./cmd/...,./internal/...`, no `-race`, so a
coverage regression fails independently and legibly) and a separate `race`
job that runs the same packages under the Go race detector (`go test -race
./...`, no coverage) so concurrency bugs in authentication, session, and CAS
logic surface as CI failures rather than intermittent production incidents.

### Fuzz targets

Five native Go fuzz targets guard the inputs that sit on the trust boundary:

- `FuzzNormalizeLogin`, `FuzzValidateLogin` — login canonicalization/validation (including the reserved `managed:` prefix guard)
- `FuzzNormalizeRecoveryCode` — recovery-code parsing
- `FuzzDecodeTOTPSecretBase32` — TOTP secret decoding
- `FuzzFieldCryptoRoundTrip` — field-encryption encrypt→decrypt round-trip

CI runs the seed corpus on every push. The `Fuzz` workflow additionally runs
active fuzzing on GitHub Actions: a short (3m/target) weekly pass over every
target, and a longer (10m/target) daily pass whose generated corpus is cached
and restored between runs so coverage accumulates — both also runnable on
demand via `workflow_dispatch`. An `oss-fuzz/` scaffold prepares this project
for Google's OSS-Fuzz infrastructure but is not itself active; see
[`oss-fuzz/ONBOARDING.md`](oss-fuzz/ONBOARDING.md).

## We test our tests

High coverage proves code *ran*, not that a test would *fail if the code broke*.
We close that gap with **mutation testing**
([gremlins](https://github.com/go-gremlins/gremlins)): it injects faults into the
production code and checks that at least one test fails ("kills" the mutant).
Surviving mutants reveal weak assertions.

- Run it locally: `scripts/mutation.sh baseline` (full) or `scripts/mutation.sh diff <ref>` (changed code only).
- Scope: `internal/services` + `internal/security` — the packages that carry the
  behavioral and security signal worth mutating. `internal/api` is
  transport-heavy and far slower to mutate, so it is covered by integration
  tests and the runtime smoke instead.
- A weekly CI job (`.github/workflows/mutation.yml`) tracks the trend; it is
  **advisory and never blocks a merge**.

Surviving mutants are triaged honestly: a *real* gap gets a new behavior test; an
*equivalent* mutant (one that cannot change any observable outcome — a log line,
an error string, an unreachable guard) is documented rather than papered over
with a brittle test. We do not chase a fake 100%.

## Security & supply chain

| Tool | Purpose |
|------|---------|
| `staticcheck` + `go vet` | Static analysis |
| [`golangci-lint`](https://golangci-lint.run) | Aggregated Go linting (`errcheck`, `govet`, `ineffassign`, `staticcheck`, `unused`, plus `copyloopvar`/`intrange`/`misspell`/`unconvert`); config in `.golangci.yml` |
| [`gosec`](https://github.com/securego/gosec) | Go security (SAST), results in the GitHub Security tab |
| [CodeQL](https://codeql.github.com) | Semantic code scanning |
| [Trivy](https://trivy.dev) | Dependency and container image scanning |
| [`gitleaks`](https://github.com/gitleaks/gitleaks) | Secret scanning of the full git history on every PR, push to `main`, and weekly |
| CycloneDX SBOM | Software bill of materials generated for the runtime image |
| [`cosign`](https://docs.sigstore.dev/cosign/overview/) | Keyless Sigstore signatures for the runtime image and for release-binary checksums, plus SLSA build provenance |

The runtime image is a multi-stage build running as a non-root user. Both base
images are pinned by digest (`FROM image:tag@sha256:...`, kept current by
Dependabot's weekly `docker` update) and Go module dependencies are pinned via
`go.sum`. Test code never ships in the image.

## What the server can see

The server stores ciphertext. Confidentiality of a backup does not depend on the
server being trusted — it cannot decrypt blobs without keys it never receives.
The integration tests assert that uploaded payloads are persisted and returned
byte-for-byte without the server ever interpreting their contents.

## Running the suite

```bash
# Unit + integration + persistence + property + fuzz seeds
go test ./...

# Active fuzzing of a single target (example)
go test ./internal/security/ -run '^$' -fuzz FuzzFieldCryptoRoundTrip -fuzztime 30s

# Runtime smoke against a locally built server
bash scripts/runtime-smoke.sh

# Mutation testing (slow; local or nightly)
bash scripts/mutation.sh baseline
```

## Checking patch coverage locally

`scripts/patchcov` is the same gate CI's `patch-coverage` job runs: every modified,
coverable Go line in your diff against `origin/main` must be exercised by a test
(a genuinely unreachable line is excluded with a trailing `// codecov:ignore`, see
the comment at the top of `scripts/patchcov/main.go`).

**Warning: running `patchcov` against a stale `coverage.out` gives a false pass.**
`go test -coverprofile` is subject to Go's test result cache — if you edit a file
and re-run the coverage command without also touching its test, `go test` can
silently reuse a cached run from *before* your latest edit. `coverage.out` then
reflects the old code, `patchcov` reports your newest lines as covered, and CI
(which always starts from a clean checkout with an empty test cache) fails on the
same diff. This has bitten contributors more than once — always regenerate the
profile fresh before trusting a local "gate OK".

The one-liner that reproduces CI's coverage condition end to end:

```bash
bash scripts/patch-coverage-local.sh
```

It removes any existing `coverage.out`, runs `go clean -testcache`, regenerates
the profile with the exact package set and flags CI uses
(`-covermode=atomic -count=1`), then runs `scripts/patchcov` against it. It takes
a few minutes — that's the point, it is the real test suite run for real.

If you'd rather run it by hand, the two steps that matter are `go clean
-testcache` and `-count=1`; either alone defeats the cache, but the script uses
both for good measure:

```bash
rm -f coverage.out
go clean -testcache
go test ./cmd/... ./internal/... \
  -coverprofile=coverage.out -covermode=atomic \
  -coverpkg=./cmd/...,./internal/... \
  -count=1
COVERAGE_FILE=coverage.out BASE_REF=origin/main go run ./scripts/patchcov
```

## Enforcing patch coverage before you push (pre-push hook)

Running `patch-coverage-local.sh` by hand only helps if you remember to do it —
and the stale-`coverage.out` false-pass trap above has bitten contributors more
than once even when they *did* remember. `scripts/hooks/pre-push` closes that
gap by running the check automatically as part of `git push`.

**Enable it once per clone:**

```bash
bash scripts/setup-hooks.sh
```

This points git's `core.hooksPath` at `scripts/hooks` (committing a file under
that path does not make git run it — `core.hooksPath` is what wires a
version-controlled hook directory up to git's actual hook dispatch) and marks
`scripts/hooks/pre-push` executable. Equivalent one-liner, if you'd rather
configure it yourself: `git config core.hooksPath scripts/hooks` (then `chmod
+x scripts/hooks/pre-push` — this repo pins `core.fileMode=false`, so a fresh
checkout may not carry the executable bit git needs to run the hook directly).

**What it does on every `git push`:**

1. Reads the ref range being pushed (git feeds this to the hook on stdin: `<local
   ref> <local sha1> <remote ref> <remote sha1>` per updated ref) and diffs it
   for `*.go` changes.
2. **No Go files changed** (e.g. a docs-only push): skips immediately, no
   coverage run.
3. **Go files changed**: runs `scripts/patch-coverage-local.sh` — the exact
   same fresh, cache-defeated gate described above — and blocks the push
   (non-zero exit) if it fails, printing the uncovered `file:line` entries
   `scripts/patchcov` reports and how to fix them (add a test, or annotate a
   genuinely unreachable line with `// codecov:ignore`).

It is bounded but not instant: expect it to take as long as the full test
suite (a few minutes), since that is the only way to get a trustworthy
answer. The hook prints a notice before it starts so it doesn't look hung.

**Emergency bypass:** `git push --no-verify` skips the hook entirely (git's
own built-in escape hatch). Use it sparingly — CI's `patch-coverage` job will
still enforce the same gate on the PR, so a bypassed push only defers the
failure, it doesn't avoid it.

## Honest limits

- Mutation efficacy will never be 100%: equivalent mutants are unkillable by
  construction, and we refuse to add brittle log-string/error-string tests just
  to move a number.
- The server is deliberately blind to payload contents. End-to-end confidentiality
  of health data is a property of the client encryption, verified in `ovumcy-app`.
