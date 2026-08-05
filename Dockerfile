# Build a static single-binary registry. modernc.org/sqlite is pure Go, so the
# image needs no libc and can run FROM scratch.
# Base images are pinned by digest as well as tag: a tag is a moving pointer,
# so without the digest the same commit can build against a different base
# tomorrow. Dependabot proposes the bump when one moves.
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build

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

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

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
