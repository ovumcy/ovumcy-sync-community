#!/bin/bash -eu
#
# OSS-Fuzz build script for ovumcy-sync-community.
#
# Compiles the native Go fuzz targets (func FuzzXxx(f *testing.F), the
# standard library `go test -fuzz` style already used by this repo's own
# CI in .github/workflows/fuzz.yml) via compile_native_go_fuzzer, per
# https://google.github.io/oss-fuzz/getting-started/new-project-guide/go-lang/.
#
# This script is exercised by `docker run .../base-builder-go` on Google's
# OSS-Fuzz builders, not by this repo's own CI — see oss-fuzz/ONBOARDING.md.

compile_native_go_fuzzer github.com/ovumcy/ovumcy-sync-community/internal/security FuzzNormalizeLogin fuzz_normalize_login
compile_native_go_fuzzer github.com/ovumcy/ovumcy-sync-community/internal/security FuzzValidateLogin fuzz_validate_login
compile_native_go_fuzzer github.com/ovumcy/ovumcy-sync-community/internal/security FuzzNormalizeRecoveryCode fuzz_normalize_recovery_code
compile_native_go_fuzzer github.com/ovumcy/ovumcy-sync-community/internal/security FuzzDecodeTOTPSecretBase32 fuzz_decode_totp_secret_base32
compile_native_go_fuzzer github.com/ovumcy/ovumcy-sync-community/internal/security FuzzFieldCryptoRoundTrip fuzz_field_crypto_round_trip
