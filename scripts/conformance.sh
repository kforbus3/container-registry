#!/usr/bin/env bash
# Run the official OCI distribution-spec conformance suite against a throwaway
# instance of this registry.
#
#   ./scripts/conformance.sh [port]
#
# The suite is cloned and built on first run and cached under .conformance/.
set -euo pipefail

PORT="${1:-5444}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE="$ROOT/.conformance"
BIN="$CACHE/oci-conformance"
DATA="$(mktemp -d)"
PASSWORD="conformance-$RANDOM$RANDOM"

# macOS binds port 5000 to the AirPlay receiver, which will silently answer
# every request and produce a wall of misleading failures.
if command -v lsof >/dev/null && lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "port $PORT is already in use; pass a free port: $0 <port>" >&2
  exit 1
fi

if [ ! -x "$BIN" ]; then
  echo "==> building the conformance suite (first run only)"
  mkdir -p "$CACHE"
  if [ ! -d "$CACHE/distribution-spec" ]; then
    git clone --depth 1 https://github.com/opencontainers/distribution-spec.git \
      "$CACHE/distribution-spec"
  fi
  (cd "$CACHE/distribution-spec/conformance" && go test -c -o "$BIN" .)
fi

echo "==> starting registry on :$PORT"
REGISTRY_ADDR=":$PORT" \
REGISTRY_DATA_DIR="$DATA" \
REGISTRY_ADMIN_PASSWORD="$PASSWORD" \
REGISTRY_LOG_LEVEL=error \
  "$ROOT/bin/registry" >"$DATA/registry.log" 2>&1 &
REGISTRY_PID=$!
trap 'kill $REGISTRY_PID 2>/dev/null || true; rm -rf "$DATA"' EXIT

for _ in $(seq 1 40); do
  curl -sf "http://localhost:$PORT/healthz" >/dev/null && break
  sleep 0.25
done

echo "==> running conformance suite"
cd "$DATA"
OCI_REGISTRY="localhost:$PORT" \
OCI_TLS=disabled \
OCI_REPO1=conformance/repo1 \
OCI_REPO2=conformance/repo2 \
OCI_USERNAME=admin \
OCI_PASSWORD="$PASSWORD" \
OCI_API_BLOBS_UPLOAD_CANCEL=true \
OCI_API_MANIFESTS_TAG_PARAM=true \
  "$BIN"
