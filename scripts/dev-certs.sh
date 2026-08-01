#!/usr/bin/env bash
# Generate a development certificate for the registry.
#
#   ./scripts/dev-certs.sh [hostname ...]
#
# Creates a small local certificate authority and issues a server certificate
# signed by it, into ./certs:
#
#   certs/ca.crt    the authority — this is what clients must trust
#   certs/ca.key    the authority's private key — keep it, or lose the ability
#                   to issue more certificates for this CA
#   certs/tls.crt   the server certificate the registry serves
#   certs/tls.key   its private key
#
# A CA plus a leaf rather than one bare self-signed certificate, because a
# client then trusts the CA *once* and keeps working when the server
# certificate is reissued, renewed, or extended to another hostname.
#
# These are for development. Anything reachable by other people wants a
# certificate from a real authority.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/certs"

# Names the certificate will be valid for. Modern clients ignore the common
# name entirely and match only these, so anything you plan to type into a
# `docker push` has to be listed here.
HOSTS=("$@")
if [ ${#HOSTS[@]} -eq 0 ]; then
  HOSTS=(registry.local localhost)
fi

mkdir -p "$OUT"

# Build the subjectAltName list: names as DNS entries, literal addresses as IP.
SAN=""
for h in "${HOSTS[@]}"; do
  if [[ "$h" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    SAN="${SAN}IP:${h},"
  else
    SAN="${SAN}DNS:${h},"
  fi
done
# Loopback is always useful: it is what the container's own health probe and
# any local curl will use.
SAN="${SAN}IP:127.0.0.1,IP:::1"

echo "==> issuing a certificate for: ${HOSTS[*]}"

# The authority is reused if it already exists, so re-running this to add a
# hostname does not invalidate trust you have already set up.
if [ -f "$OUT/ca.key" ] && [ -f "$OUT/ca.crt" ]; then
  echo "    reusing the existing authority in $OUT/ca.crt"
else
  echo "    creating a new authority"
  openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout "$OUT/ca.key" -out "$OUT/ca.crt" \
    -days 3650 -sha256 \
    -subj "/CN=container-registry development CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
fi

openssl req -newkey rsa:2048 -nodes \
  -keyout "$OUT/tls.key" -out "$OUT/tls.csr" \
  -subj "/CN=${HOSTS[0]}" 2>/dev/null

# 397 days: Apple and Chrome reject server certificates with a longer lifetime,
# and they enforce that for locally-trusted authorities too.
cat > "$OUT/leaf.ext" <<EXT
subjectAltName = ${SAN}
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EXT

openssl x509 -req -in "$OUT/tls.csr" \
  -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
  -out "$OUT/tls.crt" -days 397 -sha256 \
  -extfile "$OUT/leaf.ext" 2>/dev/null

rm -f "$OUT/tls.csr" "$OUT/leaf.ext"

# The registry runs as uid 10001 inside the container and has to read the key.
chmod 644 "$OUT/tls.crt" "$OUT/ca.crt" "$OUT/tls.key"
chmod 600 "$OUT/ca.key"

echo
openssl x509 -in "$OUT/tls.crt" -noout -subject -issuer -dates | sed 's/^/    /'
# Printed from the full text rather than with `-ext`, which LibreSSL — the
# openssl that ships with macOS — does not have.
openssl x509 -in "$OUT/tls.crt" -noout -text \
  | grep -A1 "Subject Alternative Name" | tail -1 \
  | sed 's/^ */    SAN: /'
echo
cat <<INSTRUCTIONS
==> written to $OUT

Start the registry:

    REGISTRY_ADMIN_PASSWORD=choose-something-strong docker compose up -d --build

Check it, trusting the authority explicitly:

    curl --cacert certs/ca.crt https://${HOSTS[0]}/healthz

Nothing trusts this authority yet, so that is all that works so far. To let
other tools in:

  curl / scripts   pass --cacert certs/ca.crt, or export
                   SSL_CERT_FILE=\$PWD/certs/ca.crt

  Docker Engine    sudo mkdir -p /etc/docker/certs.d/${HOSTS[0]}
  (Linux)          sudo cp certs/ca.crt /etc/docker/certs.d/${HOSTS[0]}/ca.crt
                   Add the port if you use one: ${HOSTS[0]}:5001

  Docker Desktop   sudo security add-trusted-cert -d -r trustRoot \\
  (macOS)              -k /Library/Keychains/System.keychain certs/ca.crt
                   then restart Docker Desktop

  podman, skopeo   sudo mkdir -p /etc/containers/certs.d/${HOSTS[0]}
  buildah          sudo cp certs/ca.crt /etc/containers/certs.d/${HOSTS[0]}/ca.crt

If ${HOSTS[0]} is not a real name, point it at yourself:

    echo "127.0.0.1 ${HOSTS[0]}" | sudo tee -a /etc/hosts
INSTRUCTIONS
