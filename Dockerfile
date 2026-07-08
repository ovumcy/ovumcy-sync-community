FROM golang:1.26-bookworm@sha256:fc4332778f8745404df530b4bdef3aed280b8c8da18847baffb4d4b9dd041046 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/ovumcy-sync-community ./cmd/ovumcy-sync-community

# Prepare a /data dir to copy into the distroless image (no shell there to mkdir at runtime).
RUN mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639

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
