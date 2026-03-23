FROM golang:1.25-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/ovumcy-sync-community ./cmd/ovumcy-sync-community

FROM debian:bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd --system --gid 10001 ovumcy \
  && useradd --system --uid 10001 --gid 10001 --create-home --home-dir /app --shell /usr/sbin/nologin ovumcy \
  && mkdir -p /data /app \
  && chown -R 10001:10001 /data /app

WORKDIR /app

COPY --from=build /out/ovumcy-sync-community /app/ovumcy-sync-community

ENV BIND_ADDR=:8080
ENV DB_PATH=/data/ovumcy-sync-community.sqlite
ENV SESSION_TTL=720h
ENV MAX_DEVICES=5

VOLUME ["/data"]
EXPOSE 8080

USER 10001:10001
ENTRYPOINT ["/app/ovumcy-sync-community"]
