# Build a static single-binary registry. modernc.org/sqlite is pure Go, so the
# image needs no libc and can run FROM scratch.
FROM golang:1.26-alpine AS build

WORKDIR /src

# Dependencies first so edits to source do not invalidate the module cache.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/registry ./cmd/registry

# ------------------------------------------------------------------ runtime

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata wget \
 && adduser -D -u 10001 -h /var/lib/registry registry \
 && mkdir -p /var/lib/registry \
 && chown -R registry:registry /var/lib/registry

COPY --from=build /out/registry /usr/local/bin/registry

USER registry
WORKDIR /var/lib/registry
VOLUME ["/var/lib/registry"]

ENV REGISTRY_ADDR=:5000 \
    REGISTRY_DATA_DIR=/var/lib/registry

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:5000/healthz >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/registry"]
