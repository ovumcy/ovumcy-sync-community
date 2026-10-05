FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:1fd52de184d67413e027f2534dc0dde8fec60f17c70dac7ce793a526a9e24275
COPY . $SRC/ovumcy-sync-community
WORKDIR $SRC/ovumcy-sync-community
COPY .clusterfuzzlite/build.sh $SRC/
