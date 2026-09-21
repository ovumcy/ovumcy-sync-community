FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:c74d701a74af681e18bde2db89775711c074001b10f38460675a4bc0dc60d760
COPY . $SRC/ovumcy-sync-community
WORKDIR $SRC/ovumcy-sync-community
COPY .clusterfuzzlite/build.sh $SRC/
