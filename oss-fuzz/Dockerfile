# OSS-Fuzz build image for ovumcy-sync-community.
#
# This file follows the standard google/oss-fuzz Go project layout
# (https://google.github.io/oss-fuzz/getting-started/new-project-guide/go-lang/).
# It is NOT active on Google's infrastructure from this repository alone —
# see oss-fuzz/ONBOARDING.md for what onboarding still requires.

FROM gcr.io/oss-fuzz-base/base-builder-go

RUN git clone --depth 1 https://github.com/ovumcy/ovumcy-sync-community

COPY build.sh $SRC/

WORKDIR $SRC/ovumcy-sync-community
