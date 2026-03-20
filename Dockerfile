FROM golang:1.25-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/ovumcy-sync-community ./cmd/ovumcy-sync-community

FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY --from=build /out/ovumcy-sync-community /app/ovumcy-sync-community

ENV BIND_ADDR=:8080
ENV DB_PATH=/data/ovumcy-sync-community.sqlite
ENV SESSION_TTL=720h
ENV MAX_DEVICES=5

VOLUME ["/data"]
EXPOSE 8080

ENTRYPOINT ["/app/ovumcy-sync-community"]

