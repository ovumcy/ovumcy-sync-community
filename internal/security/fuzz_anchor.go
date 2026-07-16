//go:build tools

// This file anchors the native-fuzzer build dependency in the module graph.
//
// The package's FuzzXxx targets are compiled by ClusterFuzzLite / OSS-Fuzz via
// compile_native_go_fuzzer, which rewrites each target into a main package that
// imports go-118-fuzz-build's testing shim. No production or test Go file
// imports that module, so a routine `go mod tidy` — which Dependabot runs on
// every dependency bump — drops it and breaks the native-fuzzer build (see
// .clusterfuzzlite/build.sh). The blank import below keeps it, and its
// go-fuzz-headers helper, in go.mod. The `tools` build tag is set nowhere in a
// normal build, test, lint, or the fuzz compile itself, so this file never
// contributes code to any built binary; it exists only for dependency
// resolution.
package security

import (
	_ "github.com/AdamKorcz/go-118-fuzz-build/testing"
)
