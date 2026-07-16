FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:0d53f59908d49f9038f5256b12b831a6ce68efb109775cfe87d1ef0a118ff4d8
COPY . $SRC/ovumcy-sync-community
WORKDIR $SRC/ovumcy-sync-community
COPY .clusterfuzzlite/build.sh $SRC/
