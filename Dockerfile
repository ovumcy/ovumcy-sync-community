FROM golang:1.26-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0 AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/ovumcy-sync-community ./cmd/ovumcy-sync-community

# Prepare a /data dir to copy into the distroless image (no shell there to mkdir at runtime).
RUN mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

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
