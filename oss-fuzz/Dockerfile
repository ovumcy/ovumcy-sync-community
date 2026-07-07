# OSS-Fuzz build image for ovumcy-sync-community.
#
# This file follows the standard google/oss-fuzz Go project layout
# (https://google.github.io/oss-fuzz/getting-started/new-project-guide/go-lang/).
# It is NOT active on Google's infrastructure from this repository alone —
# see oss-fuzz/ONBOARDING.md for what onboarding still requires.
#
# The base image is digest-pinned per this repo's supply-chain policy (every
# base image is pinned; Dependabot keeps the digest current). At actual
# OSS-Fuzz onboarding, Google's build environment governs the base image, so
# the pin here is for our own reproducibility, not a constraint on their infra.
FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:911e2949bd1487fe8d586bbc8c59cf9155aca1d4ff348dc3f83d98d5d7baac04

RUN git clone --depth 1 https://github.com/ovumcy/ovumcy-sync-community

COPY build.sh $SRC/

WORKDIR $SRC/ovumcy-sync-community
