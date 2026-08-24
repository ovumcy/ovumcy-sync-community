FROM golang:1.27-bookworm@sha256:484ef6066fa69acb059fdfeda7ba2b8f7391f2ef6abc6f9b8411e669ebd56466 AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/ovumcy-sync-community ./cmd/ovumcy-sync-community

# Prepare a /data dir to copy into the distroless image (no shell there to mkdir at runtime).
RUN mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35

WORKDIR /app

COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build --chown=65532:65532 /out/ovumcy-sync-community /app/ovumcy-sync-community

ENV BIND_ADDR=:8080
ENV DB_PATH=/data/ovumcy-sync-community.sqlite
ENV SESSION_TTL=720h
ENV MAX_DEVICES=5

VOLUME ["/data"]
EXPOSE 8080

USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["/app/ovumcy-sync-community", "healthcheck"]
ENTRYPOINT ["/app/ovumcy-sync-community"]
