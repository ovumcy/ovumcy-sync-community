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

CI runs the unit, integration, persistence, security, and property-based layers
under the Go race detector (`go test -race`) so concurrency bugs in
authentication, session, and CAS logic surface as CI failures rather than
intermittent production incidents.

### Fuzz targets

Five native Go fuzz targets guard the inputs that sit on the trust boundary:

- `FuzzNormalizeLogin`, `FuzzValidateLogin` — login canonicalization/validation (including the reserved `managed:` prefix guard)
- `FuzzNormalizeRecoveryCode` — recovery-code parsing
- `FuzzDecodeTOTPSecretBase32` — TOTP secret decoding
- `FuzzFieldCryptoRoundTrip` — field-encryption encrypt→decrypt round-trip

CI runs the seed corpus on every push; longer active fuzzing is run on demand
(see below).

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
| [`gosec`](https://github.com/securego/gosec) | Go security (SAST), results in the GitHub Security tab |
| [CodeQL](https://codeql.github.com) | Semantic code scanning |
| [Trivy](https://trivy.dev) | Dependency and container image scanning |
| [`gitleaks`](https://github.com/gitleaks/gitleaks) | Secret scanning of the full git history on every PR, push to `main`, and weekly |
| CycloneDX SBOM | Software bill of materials generated for the runtime image |

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

## Honest limits

- Mutation efficacy will never be 100%: equivalent mutants are unkillable by
  construction, and we refuse to add brittle log-string/error-string tests just
  to move a number.
- The server is deliberately blind to payload contents. End-to-end confidentiality
  of health data is a property of the client encryption, verified in `ovumcy-app`.
