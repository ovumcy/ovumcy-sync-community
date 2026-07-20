FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:21c5b7d03174e2f400283de7139b2131a6c7efd28f8f156a4fa5e8175ff31308
COPY . $SRC/ovumcy-sync-community
WORKDIR $SRC/ovumcy-sync-community
COPY .clusterfuzzlite/build.sh $SRC/
