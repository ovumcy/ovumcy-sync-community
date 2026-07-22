# Third-Party Licenses

`ovumcy-sync-community` is licensed under the PolyForm Noncommercial License 1.0.0 (see
[LICENSE](LICENSE)). This file covers **third-party code only**: the Go module dependencies
compiled into the `ovumcy-sync-community` binary and container image, plus the modules used
only by this repository's own test suite (never linked into a shipped artifact, called out
below).

Unlike [ovumcy-web](https://github.com/ovumcy/ovumcy-web), this repository is a pure Go
backend with no bundled frontend assets (no `node_modules`, no `go:embed` of third-party
JS/CSS) — the only `go:embed` in this repo covers this project's own SQL migrations. So the
third-party surface here is exactly this repo's Go dependency graph.

## How this list was generated

1. Resolve the exact set of non-standard-library packages reachable from this repo's own
   code, including test files (`go list -deps -test ./...`), then map each package to its
   owning module:

   ```bash
   go list -f '{{if not .Standard}}{{.ImportPath}}{{"\t"}}{{.Module}}{{end}}' \
     $(go list -deps -test ./... | grep -v '^github.com/ovumcy/ovumcy-sync-community') \
     | awk -F'\t' '{print $2}' | awk '{print $1, $2}' | sort -u -k1,1
   ```

   This is the module list below. It is a subset of `go list -m all` (which also reports
   transitive dependencies of dev/CI tooling — linters, mutation testing, etc. — that are
   never imported by this repo's own `.go` files).
2. Cross-check with an automated report:

   ```bash
   go run github.com/google/go-licenses@latest report ./...
   ```

   `go-licenses` only walks the non-test build graph, so it does not see the test-only
   `pgregory.net/rapid` dependency, and it failed to auto-classify `modernc.org/mathutil`'s
   license text (see below) — both were confirmed manually.
3. For every module, open `LICENSE`/`LICENSE.txt`/`NOTICE` etc. directly in the local module
   cache (`go env GOMODCACHE`) and read the actual text rather than trusting a package's
   `go.mod` metadata or an SPDX guess. Regenerate by re-running step 1 against a current
   `go.sum` and re-reading any new or changed module's license file.

Regenerate this file whenever `go.mod`/`go.sum` changes in a way that adds, removes, or
upgrades a dependency across a license boundary.

As of this writing, `go list -deps -test ./...` resolves to **18 third-party modules**
(the table below), out of **62 modules** in the full `go list -m all` graph for this repo.

## Direct dependencies (`go.mod` `require`, non-indirect)

| Module | License |
| --- | --- |
| [github.com/prometheus/client_golang](https://github.com/prometheus/client_golang) | Apache-2.0 |
| [golang.org/x/crypto](https://cs.opensource.google/go/x/crypto) | BSD-3-Clause |
| [modernc.org/sqlite](https://gitlab.com/cznic/sqlite) | BSD-3-Clause |
| [pgregory.net/rapid](https://github.com/flyingmutant/rapid) | MPL-2.0 (test-only, see below) |

## All third-party modules (direct + transitive, build- and test-reachable)

| Module | Version | License |
| --- | --- | --- |
| github.com/beorn7/perks | v1.0.1 | MIT |
| github.com/cespare/xxhash/v2 | v2.3.0 | MIT |
| github.com/dustin/go-humanize | v1.0.1 | MIT |
| github.com/mattn/go-isatty | v0.0.20 | MIT |
| github.com/munnerz/goautoneg | v0.0.0-20191010083416-a7dc8b61c822 | BSD-3-Clause |
| github.com/ncruces/go-strftime | v1.0.0 | MIT |
| github.com/prometheus/client_golang | v1.24.0 | Apache-2.0 |
| github.com/prometheus/client_model | v0.6.2 | Apache-2.0 |
| github.com/prometheus/common | v0.70.0 | Apache-2.0 |
| github.com/remyoudompheng/bigfft | v0.0.0-20230129092748-24d4a6f8daec | BSD-3-Clause |
| golang.org/x/crypto | v0.54.0 | BSD-3-Clause |
| golang.org/x/sys | v0.47.0 | BSD-3-Clause |
| google.golang.org/protobuf | v1.36.11 | BSD-3-Clause |
| modernc.org/libc | v1.74.1 | BSD-3-Clause |
| modernc.org/mathutil | v1.7.1 | BSD-3-Clause |
| modernc.org/memory | v1.11.0 | BSD-3-Clause |
| modernc.org/sqlite | v1.54.0 | BSD-3-Clause |
| pgregory.net/rapid | v1.3.0 | MPL-2.0 |

Every entry was verified by reading the module's own `LICENSE`/`LICENSE.txt` (or equivalent)
file in the local module cache, not inferred from package metadata.

### Note on `pgregory.net/rapid` (MPL-2.0)

`rapid` (property-based testing) is imported only by
`internal/security/security_property_test.go` — a `_test.go` file. It is compiled only when
running `go test` and is never linked into the `ovumcy-sync-community` binary or container
image. It is listed here for transparency about the full dependency graph, not because it is
redistributed.

### Note on `modernc.org/mathutil` (BSD-3-Clause)

The automated `go-licenses` report above could not auto-classify this module's `LICENSE`
file (it uses a slightly nonstandard header). Manual inspection confirms it is the standard
3-clause BSD template also used by `golang.org/x/sys`, `golang.org/x/crypto`, and the other
`modernc.org/*` modules in this table.
