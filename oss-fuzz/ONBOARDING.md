# OSS-Fuzz scaffold

This directory prepares `ovumcy-sync-community` for [OSS-Fuzz](https://github.com/google/oss-fuzz)
integration. **OSS-Fuzz is not running against this repository.** Nothing here is executed by this
repo's own CI (see [`.github/workflows/fuzz.yml`](../.github/workflows/fuzz.yml) for the fuzzing that
actually runs today, on GitHub Actions, against `internal/security`'s native Go fuzz targets).

## What is here

- `project.yaml` — the `google/oss-fuzz` project descriptor: language, contact, and repo URL.
- `Dockerfile` — builds from `gcr.io/oss-fuzz-base/base-builder-go`, per the
  [Go project guide](https://google.github.io/oss-fuzz/getting-started/new-project-guide/go-lang/).
- `build.sh` — compiles this repo's existing `func FuzzXxx(f *testing.F)` targets in
  `internal/security` via `compile_native_go_fuzzer`, the documented entry point for native Go 1.18+
  fuzz functions (as opposed to the older `compile_go_fuzzer`, which expects a `Fuzz(data []byte)`
  signature this repo does not use).

These files follow the layout OSS-Fuzz expects from a project's own PR into
[`google/oss-fuzz`](https://github.com/google/oss-fuzz/tree/master/projects) — they do not, by
themselves, put the project on Google's infrastructure.

## What still has to happen for OSS-Fuzz to actually run

Getting continuous fuzzing on Google's infrastructure requires steps outside this repository, done by
a project maintainer:

1. Open a pull request against `google/oss-fuzz` that adds a `projects/ovumcy-sync-community/`
   directory containing (copies of, or references to) the three files above.
2. Google's OSS-Fuzz maintainers review and merge that PR.
3. Only after that merge does Google's infrastructure start building this project's fuzz targets and
   running them continuously, with results (including any crashes) reported to the addresses in
   `project.yaml`.

None of that is initiated by anything in this repository or its CI. Until step 2 happens, this
directory is scaffolding only.

## Before submitting

A maintainer should, before opening the `google/oss-fuzz` PR:

- Confirm `primary_contact` in `project.yaml` is an address that should receive OSS-Fuzz crash
  reports (it currently reuses the [`SECURITY.md`](../SECURITY.md) contact, `contact@ovumcy.com`).
- Confirm the fuzz target list in `build.sh` is current — it mirrors the targets in
  [`.github/workflows/fuzz.yml`](../.github/workflows/fuzz.yml) as of this writing; keep the two in
  sync as targets are added or renamed.
- Optionally test the build locally per OSS-Fuzz's own tooling
  (`infra/helper.py build_image` / `build_fuzzers` from a `google/oss-fuzz` checkout), since this
  repo's own CI does not exercise `build.sh` or the `base-builder-go` image.
