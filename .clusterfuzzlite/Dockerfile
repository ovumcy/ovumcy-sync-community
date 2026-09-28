FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:6bd18ef3f943ae94dcb97c80b7e3ec0dbea398b40181732d2e27f4a2d2ef4135
COPY . $SRC/ovumcy-sync-community
WORKDIR $SRC/ovumcy-sync-community
COPY .clusterfuzzlite/build.sh $SRC/
