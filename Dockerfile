FROM golang:1.25-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/ovumcy-sync-community ./cmd/ovumcy-sync-community

# Prepare a /data dir to copy into the distroless image (no shell there to mkdir at runtime).
RUN mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot

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
ENTRYPOINT ["/app/ovumcy-sync-community"]
