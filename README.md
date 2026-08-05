# Container Registry

A self-hosted container registry implementing the [OCI Distribution
Specification](https://github.com/opencontainers/distribution-spec) v1.1. It
**passes the official OCI conformance suite — 986 assertions, zero failures** —
so it works with any OCI client, not just Docker. Every image pushed to it is
automatically described by a CycloneDX SBOM, published back as an OCI referrer.

Single Go binary, embedded web UI, SQLite metadata, and blobs on local disk or
any S3-compatible object store. No external services required.

```
$ make conformance
  Tag listing.......: Pass      Manifest put by digest..: Pass
  Blob push.........: Pass      Manifest put by tag.....: Pass
  Blob chunked......: Pass      Manifest put w/ subject.: Pass
  Blob mount........: Pass      Referrers...............: Pass
  Blobs sha256/512..: Pass      Digest Algorithm sha512.: Pass
  ...                           PASS
```

---

## Quick start

New to this? **[docs/USER-GUIDE.md](docs/USER-GUIDE.md)** walks from an empty
directory to a pushed image step by step.

### Locally, over plain HTTP

```bash
REGISTRY_ADMIN_PASSWORD=choose-something-strong docker compose \
  -f docker-compose.yml -f docker-compose.local.yml up -d
```

Open <http://localhost:5001>, sign in as `admin`, then:

```bash
docker login localhost:5001
docker tag alpine:latest localhost:5001/team-a/alpine:1.0
docker push localhost:5001/team-a/alpine:1.0
docker pull localhost:5001/team-a/alpine:1.0
```

Port 5001 rather than 5000 because macOS binds 5000 to the AirPlay Receiver,
which answers requests instead of the registry. Set `REGISTRY_PORT` to change it.

### Anywhere real: HTTPS on 443

`docker-compose.yml` on its own serves **HTTPS on port 443** and is the default.
Put a certificate and key in `./certs`, then:

```bash
REGISTRY_ADMIN_PASSWORD=choose-something-strong docker compose up -d --build
```

```
certs/
  tls.crt    full chain: leaf first, then any intermediates
  tls.key    readable by uid 10001, the user the registry runs as
```

For testing, generate one:

```bash
make certs                                  # registry.local + localhost
make certs HOSTS="registry.example.com"     # or name your own
```

That creates a small local authority in `certs/ca.crt` and a server certificate
signed by it, and prints how to make Docker, podman and curl trust the
authority. See [Development certificates](#development-certificates) below.

The registry listens on 5000 inside the container and is published on 443 on the
host, so it never needs `CAP_NET_BIND_SERVICE`. To serve on a different host
port, set `REGISTRY_PORT`; to have the process itself bind 443 (with host
networking, say), set `REGISTRY_ADDR=:443` and add
`cap_add: [NET_BIND_SERVICE]`.

TLS is all-or-nothing: with both variables set the registry serves HTTPS only,
and it refuses to start with just one. The certificate is loaded before the
listener opens, so a missing or mismatched key pair fails immediately with a
clear message rather than after announcing itself. Session cookies gain the
`Secure` flag automatically once TLS is on.

`certs/` and `*.key`/`*.crt`/`*.pem` are in `.gitignore`, so a private key
cannot be committed by accident.

To run without Docker:

```bash
make build
REGISTRY_ADMIN_PASSWORD=choose-something-strong ./bin/registry
```

> Docker refuses plain HTTP for any host other than `localhost`/`127.0.0.1`.
> For anything else, either serve TLS as above, put it behind a TLS-terminating
> proxy, or add the host to Docker's `insecure-registries`.

---

## Verified clients

Compliance is verified against the official suite and against four independent
client implementations — deliberately not just Docker:

| Client | Implementation | Verified |
| --- | --- | --- |
| **conformance suite** | opencontainers/distribution-spec | 986 assertions, 0 failures |
| **crane** | google/go-containerregistry | copy from Docker Hub, catalog, ls, digest, manifest |
| **skopeo** | containers/image (the Podman/Buildah/CRI-O stack) | multi-arch copy, list-tags, inspect |
| **ORAS** | oras-project | arbitrary artifacts, attach, discover, pull |
| **Podman** | containers/podman | login, pull, tag, push |
| **Helm** | helm, OCI charts | registry login, push, pull of `oci://` charts |
| **Docker / buildx** | moby | login, push, pull, multi-platform build --push |

Cross-client interoperability is exercised too: an image pushed by crane, with a
referrer attached by ORAS, discovered back through the referrers API.

The web UI reflects this rather than assuming Docker: the push, pull and token
cards each offer the same operation for every client above, including the flag
that client needs to accept a plain-HTTP registry — the usual reason a first
push fails, and different in every one of them. A repository holding Helm charts
offers chart commands instead of image ones. Every command shown was run against
this registry.

## What it does

**OCI Distribution v1.1**

- Blob upload: monolithic, chunked and resumable (`Content-Range`, offset tracking)
- Cross-repository blob mounting (`?mount=&from=`), authorised against the source repo
- Image manifests and multi-platform indexes, byte-for-byte round-tripped
- Referrers API (`/v2/<name>/referrers/<digest>`) for signatures, SBOMs and attestations
- Both mandated digest algorithms: `sha256` and `sha512`, across every upload style
- Tag creation via `tag` query parameters when pushing by digest (`end-7b`)
- Content-addressable storage: identical layers are stored once, however many
  repositories use them
- Range requests on blob pulls, `Docker-Content-Digest` on every relevant response
- Paginated catalog and tag listing, filtered by what the caller may see

**Automatic SBOM generation**

- Every pushed image is scanned and described in [CycloneDX](https://cyclonedx.org/) 1.5
- Published back as an OCI referrer (`artifactType: application/vnd.cyclonedx+json`),
  so `oras discover`, `cosign` and any OCI-aware scanner find it
- Detects OS packages (`apk`, `dpkg`, `rpm`), language packages (npm, PyPI,
  Maven/Java archives, RubyGems, NuGet, Composer), Go module versions embedded
  in binaries — which covers `FROM scratch` and distroless images with no
  package database — and interpreters compiled into an image rather than
  installed, such as the Python and Node builds in their official images
- Runs on background workers; a push is never delayed or failed by it

**Vulnerability scanning**

- Each SBOM is matched against [OSV.dev](https://osv.dev) — free, no credentials,
  and covering every ecosystem the SBOM scanner detects
- Severity from the CVSS v3 vector computed in-registry rather than taken from a
  vendor label, because the same CVE is rated differently by different databases
- Fixed-version reported per finding, which is the part anyone can act on
- Per-tag risk in the repository listing, findings and re-scan on the image page
- Advisories are cached and shared across images, with a freshness bound

**Storage routing**

- Blobs are routed to a backend by repository namespace, so one registry can
  hold content that must not share storage: `gov/*` in a GovCloud bucket,
  `partners/*` in a commercial one, everything else on local disk
- Ordered rules, first match wins; anything unmatched uses the default backend
- Cross-repository blob mounting is refused across backends, which is what stops
  a mount publishing content into a bucket that never received the bytes
- Changing a rule never moves or breaks anything: a repository keeps reading from
  where its blobs already are, and is listed as misplaced until an explicit
  migration copies and verifies them

**Access control**

- Users with `admin`/`user` roles; the last administrator cannot be removed
- API tokens with independent `pull`/`push`/`delete`/`admin` permissions
- Per-token repository scopes as comma-separated globs (`team-a/*, shared/base`)
- Tokens can never exceed the rights of the user that owns them
- Repositories can be marked public (readable by anyone) or immutable
  (existing tags cannot be moved to different content)
- Per-repository access grants with graded roles, opt-in per repository
- Every push, delete, tag and administrative change is written to an audit log
- Per-caller rate limiting, with pushes limited separately from reads
- Per-repository storage quotas, enforced on push

**Webhooks**

- Signed deliveries on push, delete and scan-complete, with per-hook event
  filters and registry-wide or per-repository scope
- HMAC-SHA256 over timestamp and body, so a receiver can verify the delivery
  came from the registry and a captured one cannot be replayed forever
- Retry with backoff on server errors, no retry on a 4xx that will not improve
- Delivery history per hook, so a webhook that is not arriving can be diagnosed
  from the registry rather than from the receiver's logs

**Pull-through cache**

- Mirror an upstream registry: an image pulled once is served locally forever
  after, so a build farm counts as one puller rather than hundreds
- Handles the Docker token-auth flow, with per-scope token caching
- Scoped to a prefix, so one registry can hold its own images and mirror an
  upstream at the same time

**Management**

- Web UI: repositories browsed as a folder tree by namespace — `demo/` opens to
  what is under it — with paged and searchable tags, layer inspection,
  image config and build history, token issue/revoke, user management, audit
  log, retention rules, webhooks and maintenance
- Prometheus metrics at `/metrics`, with bounded label cardinality
- Mark-and-sweep garbage collection with a dry-run mode and a configurable
  grace period that protects in-flight pushes
- Retention rules per repository — keep the newest N, delete older than a
  duration, protect tag patterns — applied on a schedule alongside collection,
  with a preview that shows every decision and its reason before anything runs

---

## Configuration

All configuration is by environment variable.

| Variable | Default | Purpose |
| --- | --- | --- |
| `REGISTRY_ADDR` | `:5000` | Listen address |
| `REGISTRY_DATA_DIR` | `./data` | Blob store and upload scratch space |
| `REGISTRY_DB_PATH` | `<data dir>/registry.db` | SQLite metadata database |
| `REGISTRY_ADMIN_USER` | `admin` | Bootstrap administrator name |
| `REGISTRY_ADMIN_PASSWORD` | *(generated)* | Bootstrap password; printed once if unset |
| `REGISTRY_REALM` | `container-registry` | Realm in the `WWW-Authenticate` challenge |
| `REGISTRY_TLS_CERT` / `REGISTRY_TLS_KEY` | — | Serve HTTPS directly; both or neither |
| `REGISTRY_ANONYMOUS_PULL` | `false` | Allow unauthenticated pulls of **public** repositories |
| `REGISTRY_MAX_UPLOAD_BYTES` | `0` | Per-blob upload cap; `0` is unlimited |
| `REGISTRY_SESSION_TTL` | `12h` | Web UI session lifetime |
| `REGISTRY_GC_GRACE` | `1h` | Blobs newer than this are never collected |
| `REGISTRY_GC_UPLOAD_TTL` | `24h` | How long an abandoned upload is retained |
| `REGISTRY_SBOM` | `true` | Generate an SBOM for each pushed image |
| `REGISTRY_SBOM_WORKERS` | `2` | Concurrent image scans |
| `REGISTRY_SBOM_QUEUE` | `256` | Backlog depth before jobs are dropped |
| `REGISTRY_VULN_SCAN` | `true` | Match each SBOM against an advisory database |
| `REGISTRY_VULN_ENDPOINT` | `https://api.osv.dev` | OSV-compatible API; point at a mirror to avoid egress |
| `REGISTRY_VULN_WORKERS` | `2` | Concurrent scans |
| `REGISTRY_VULN_QUEUE` | `256` | Backlog depth before scans are dropped |
| `REGISTRY_VULN_TIMEOUT` | `60s` | Per-request timeout to the advisory service |
| `REGISTRY_VULN_ADVISORY_TTL` | `24h` | How long a cached advisory is reused, and how long an unreferenced one is kept |
| `REGISTRY_MAINTENANCE_INTERVAL` | `6h` | How often retention and collection run; `0` disables |
| `REGISTRY_MAINTENANCE_DELAY` | `5m` | Delay before the first scheduled sweep |
| `REGISTRY_RATE_LIMIT` | `0` | Requests per minute per caller; `0` disables |
| `REGISTRY_RATE_LIMIT_WRITES` | *(uses `RATE_LIMIT`)* | Separate, usually lower, limit for pushes and deletes |
| `REGISTRY_RATE_BURST` | *(one second's worth)* | How many requests may arrive at once |
| `REGISTRY_AUTH_FAIL_THRESHOLD` | `5` | Failed authentications tolerated before waits begin; `0` disables |
| `REGISTRY_AUTH_FAIL_WINDOW` | `15m` | How long a quiet caller keeps its failure count |
| `REGISTRY_AUTH_LOCKOUT_MAX` | `15m` | Longest wait imposed on a persistent guesser |
| `REGISTRY_TRUSTED_PROXIES` | — | Addresses or CIDRs whose `X-Forwarded-*` headers are believed; `*` trusts any peer |
| `REGISTRY_TLS_MIN_VERSION` | `1.2` | Oldest TLS version accepted; `1.2` or `1.3` |
| `REGISTRY_HSTS_MAX_AGE` | `8760h` | `Strict-Transport-Security` max-age over HTTPS; `0` omits the header |
| `REGISTRY_HSTS_INCLUDE_SUBDOMAINS` | `false` | Add `includeSubDomains` |
| `REGISTRY_HSTS_PRELOAD` | `false` | Add `preload` |
| `REGISTRY_WEBHOOK_ALLOW_INTERNAL` | `false` | Deliver webhooks to loopback, link-local and private addresses |
| `REGISTRY_S3_BUCKET` | — | Setting this moves blobs to an object store |
| `REGISTRY_S3_ENDPOINT` | *(derived from region)* | `http://minio:9000`, or an AWS endpoint |
| `REGISTRY_S3_REGION` | `us-east-1` | Signing region |
| `REGISTRY_S3_ACCESS_KEY` / `REGISTRY_S3_SECRET_KEY` | — | Credentials |
| `REGISTRY_S3_SESSION_TOKEN` | — | For temporary credentials |
| `REGISTRY_S3_PREFIX` | — | Key prefix, so one bucket can hold several registries |
| `REGISTRY_S3_PATH_STYLE` | `true` | Path-style addressing; MinIO and most gateways need it |
| `REGISTRY_WEBHOOKS` | `true` | Deliver events to registered endpoints |
| `REGISTRY_WEBHOOK_WORKERS` | `2` | Concurrent deliveries |
| `REGISTRY_WEBHOOK_QUEUE` | `512` | Backlog before events are dropped |
| `REGISTRY_WEBHOOK_TIMEOUT` | `10s` | Per-attempt timeout |
| `REGISTRY_METRICS_TOKEN` | — | Require a bearer token on `/metrics` |
| `REGISTRY_PROXY_REMOTE` | — | Upstream registry to cache, e.g. `https://registry-1.docker.io` |
| `REGISTRY_PROXY_PREFIX` | `proxy` | Namespace the cache lives under; empty mirrors everything |
| `REGISTRY_PROXY_USERNAME` / `REGISTRY_PROXY_PASSWORD` | — | Upstream credentials; anonymous pulls have far lower limits |
| `REGISTRY_PROXY_TIMEOUT` | `120s` | Upstream request timeout |
| `REGISTRY_TOKEN_AUTH` | `false` | Offer the Docker bearer-token scheme alongside Basic |
| `REGISTRY_TOKEN_REALM` | *(derived from the request)* | Absolute URL clients fetch tokens from; set this when behind a proxy that does not send `X-Forwarded-*` |
| `REGISTRY_TOKEN_SECRET` | *(generated)* | Signs issued tokens; required if running more than one instance |
| `REGISTRY_TOKEN_TTL` | `5m` | How long an issued token stays valid |
| `REGISTRY_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |

The bootstrap administrator is created only when the user table is empty. If
`REGISTRY_ADMIN_PASSWORD` is unset, a random password is generated and printed
to stdout once — there is no built-in default password.

---

## Using tokens

Create a token in the UI under **API Tokens**, or over the API:

```bash
curl -u admin:PASSWORD -X POST http://localhost:5000/api/tokens \
  -H 'Content-Type: application/json' \
  -d '{
        "name": "ci-team-a",
        "can_pull": true,
        "can_push": true,
        "repo_pattern": "team-a/*",
        "expires_days": 90
      }'
```

The response contains `secret` — the only time the plaintext is available.

A token works in three places:

```bash
# 1. As the password for docker login
echo "$REGISTRY_TOKEN" | docker login localhost:5000 -u ci --password-stdin

# 2. As a bearer token on the management API
curl -H "Authorization: Bearer $REGISTRY_TOKEN" http://localhost:5000/api/repositories

# 3. As basic-auth credentials against the OCI API
curl -u "ci:$REGISTRY_TOKEN" http://localhost:5000/v2/_catalog
```

### Repository scopes

`repo_pattern` is a comma-separated list of globs, where `*` matches any run of
characters (including `/`) and `?` matches one:

| Pattern | Matches | Does not match |
| --- | --- | --- |
| `*` | everything | — |
| `team-a/*` | `team-a/app`, `team-a/nested/app` | `team-a`, `team-b/app` |
| `team-a/*, shared/base` | `team-a/app`, `shared/base` | `shared/other` |
| `*-prod` | `svc-prod` | `svc-dev` |

---

## Management API

Everything under `/api` accepts either a session cookie (web UI) or an
`Authorization` header (`Bearer <token>` or Basic). Admin-only routes are marked.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/auth/login` | Sign in, set a session cookie |
| `POST` | `/api/auth/logout` | End the session |
| `GET` | `/api/auth/me` | Current principal and its permissions |
| `POST` | `/api/auth/password` | Change your own password |
| `GET` | `/api/stats` | Counts and storage usage |
| `POST` | `/api/storage/check` | Write, read back and delete a probe object; confirms the blob store is reachable and writable (admin). `?backend=<name>` probes a named one |
| `PUT` | `/api/storage` | Set the default backend, after proving it works (admin) |
| `POST` | `/api/storage/migrate` | Move every blob to the saved default backend (admin) |
| `GET` | `/api/storage/migrate` | Migration progress |
| `GET` | `/api/storage/backends` | Named backends and their health (admin) |
| `POST` | `/api/storage/backends` | Add a named backend, after proving it works (admin) |
| `DELETE` | `/api/storage/backends/<name>` | Remove a backend; refused while a rule points at it (admin) |
| `GET` | `/api/storage/rules` | Routing rules in evaluation order (admin) |
| `POST` | `/api/storage/rules` | Add a rule (admin) |
| `PATCH` | `/api/storage/rules/<id>` | Reorder a rule (admin) |
| `DELETE` | `/api/storage/rules/<id>` | Delete a rule (admin) |
| `POST` | `/api/repositories/<name>/migrate` | Move one repository's blobs to the backend its rule names (admin) |
| `GET` | `/api/repositories` | Repositories visible to the caller |
| `GET` | `/api/repositories/<name>` | Tags, manifests and untagged manifests |
| `PATCH` | `/api/repositories/<name>` | Set public / immutable / description |
| `DELETE` | `/api/repositories/<name>` | Delete a repository |
| `GET` | `/api/repositories/<name>/tags` | Tags with size and media type |
| `POST` | `/api/repositories/<name>/tags` | **Create or move a tag** |
| `DELETE` | `/api/repositories/<name>/tags/<tag>` | Delete a tag |
| `GET` | `/api/repositories/<name>/manifests/<digest>` | Manifest, layers, image config, history |
| `DELETE` | `/api/repositories/<name>/manifests/<digest>` | Delete a manifest and its tags |
| `GET` | `/api/repositories/<name>/manifests/<digest>/sbom` | Download the generated CycloneDX SBOM (`?platform=os/arch` for a multi-platform index) |
| `GET` | `/api/repositories/<name>/manifests/<digest>/vulnerabilities` | Findings for an image, worst first |
| `POST` | `/api/repositories/<name>/manifests/<digest>/rescan` | Re-check against current advisories |
| `GET` `POST` | `/api/tokens` | List / create tokens |
| `POST` | `/api/tokens/<id>/revoke` | Revoke a token |
| `DELETE` | `/api/tokens/<id>` | Delete a token record |
| `GET` `POST` | `/api/users` | List / create users *(admin)* |
| `PATCH` `DELETE` | `/api/users/<id>` | Update / delete a user *(admin)* |
| `GET` | `/api/audit` | Audit log *(admin)* |
| `GET` `POST` | `/api/gc` | Status / run garbage collection *(admin)* |
| `GET` `POST` | `/api/repositories/<name>/retention` | List / create retention rules |
| `PATCH` `DELETE` | `/api/repositories/<name>/retention/<id>` | Enable / remove a rule |
| `POST` | `/api/retention/preview` | Show what a sweep would delete *(admin)* |
| `GET` `POST` | `/api/repositories/<name>/grants` | List / create access grants |
| `DELETE` | `/api/repositories/<name>/grants/<user>` | Revoke a grant |
| `GET` `POST` | `/api/webhooks` | List / create webhooks *(admin)* |
| `DELETE` | `/api/webhooks/<id>` | Remove a webhook *(admin)* |
| `GET` | `/api/webhooks/<id>/deliveries` | Delivery history *(admin)* |
| `POST` | `/api/webhooks/<id>/test` | Send a synthetic event *(admin)* |
| `GET` | `/api/maintenance` | Scheduled-run history *(admin)* |
| `POST` | `/api/maintenance/sweep` | Run retention and collection now *(admin)* |
| `GET` | `/api/settings` | Effective configuration *(admin)* |
| `GET` | `/healthz` | Liveness probe, no auth |

### Tagging without pushing

Point a new tag at content that is already in the repository — by an existing
tag or by digest. This is the cheap way to promote a build:

```bash
curl -H "Authorization: Bearer $REGISTRY_TOKEN" \
  -X POST http://localhost:5000/api/repositories/team-a/app/tags \
  -H 'Content-Type: application/json' \
  -d '{"tag": "production", "target": "build-1841"}'
```

No layers move; only the tag is written. It is immediately visible to
`docker pull` and to `/v2/<name>/tags/list`.

---

## Software Bill of Materials

Every image push schedules a background scan. The resulting CycloneDX 1.5
document is stored as a blob and attached to the image with an OCI artifact
manifest whose `subject` is the image, which makes it a standard referrer:

```bash
# Any OCI client can find it — nothing registry-specific involved
oras discover localhost:5001/team-a/alpine:1.0
# └── application/vnd.cyclonedx+json
#     └── sha256:6e61aa6f62d5...

# Or fetch it directly
curl -u admin:PASSWORD \
  http://localhost:5001/api/repositories/team-a/alpine/manifests/<digest>/sbom
```

An SBOM is attached to the image manifest it describes, but a tag usually points
at an *index* — that is what `docker push` produces even for a single platform.
The endpoint resolves through the index to the platform manifests beneath it, so
the digest you have in hand is the one to ask about. A genuinely multi-platform
index has one SBOM per platform and needs `?platform=linux/amd64` to
disambiguate; the error lists what is available. The platform actually returned
comes back in `X-Registry-Sbom-Platform`.

What it detects:

| Ecosystem | Source | Covers |
| --- | --- | --- |
| **apk** | `lib/apk/db/installed` | Alpine, with version, architecture and license |
| **dpkg** | `var/lib/dpkg/status` | Debian and Ubuntu (entries left behind by a removed package are excluded) |
| **rpm** | `rpmdb.sqlite`, `Packages` (Berkeley DB), `Packages.db` (ndb) | Fedora, RHEL, CentOS, Rocky, Alma, Amazon Linux, openSUSE — including epoch |
| **npm** | `**/node_modules/*/package.json` | Installed packages including scoped and nested ones |
| **PyPI** | `*.dist-info/METADATA`, `*.egg-info/PKG-INFO` | Installed distributions, names normalised per PEP 503 |
| **Go** | build info embedded in binaries | Module versions — the only source for `FROM scratch` and distroless images |

RPM's storage format has changed three times and an image may carry any of
them; all three containers are read, and the header format inside is shared.
The Berkeley DB backend follows overflow-page chains, so packages whose header
exceeds one page are not silently lost.

Layers are applied in order with whiteouts honoured, so a package database or a
dependency directory replaced or deleted by a later layer is read correctly.
Components are emitted with package URLs (`pkg:apk/…`, `pkg:deb/…`, `pkg:rpm/…`,
`pkg:npm/…`, `pkg:pypi/…`, `pkg:golang/…`) that vulnerability scanners match on,
sorted and de-duplicated so identical content yields an identical document.

Output was checked against the images themselves rather than assumed correct:

| Image | Ground truth | Scanner |
| --- | --- | --- |
| `redhat/ubi8` | `rpm -qa` → 184 | 184, no differences |
| `node:22-alpine` | every `node_modules/*/package.json` → 186 | 186, no differences |
| `python:3.12-slim` | `pip list` → `pip 25.0.1` | `pkg:pypi/pip@25.0.1` |

**Scope and limits.** Not covered: RubyGems, Maven, Cargo, Composer, NuGet, and
binaries other than Go. `gzip` and `zstd` layers are both decompressed, and a
layer that cannot be read is skipped without sinking the scan. Reaching the
language-package cap is recorded in the document as `registry:truncated` rather
than silently under-reporting. Scans are bounded (file size, database size,
total bytes, entry count, manifest count, binary count) so a hostile image
cannot exhaust the server. Indexes are not scanned directly — each platform
manifest they point at is described on its own. Set `REGISTRY_SBOM=false` to
turn the whole thing off.

---

## Development certificates

`make certs` (or `./scripts/dev-certs.sh [hostname ...]`) issues a certificate
for local testing:

```
certs/ca.crt    the authority — this is what clients trust
certs/ca.key    its key; keep it to issue more certificates later
certs/tls.crt   the server certificate the registry serves
certs/tls.key   its key
```

It creates a small authority and signs a leaf with it, rather than emitting one
bare self-signed certificate. That is deliberate: a client trusts the CA **once**
and keeps working when the server certificate is reissued, renewed, or extended
to another hostname. Re-running the script reuses an existing authority, so
adding a hostname does not invalidate trust you have already set up.

Every name you intend to use must be on the certificate. Modern clients ignore
the common name entirely and match only the subject alternative names, so
`./scripts/dev-certs.sh registry.local` will not work for `myhost.lan`.

Generating the certificate is the easy half; making clients trust it is where
this usually goes wrong. The script prints the exact commands, which differ by
tool:

| Tool | Where the CA goes |
| --- | --- |
| curl, scripts | `--cacert certs/ca.crt`, or `SSL_CERT_FILE=$PWD/certs/ca.crt` |
| Docker Engine (Linux) | `/etc/docker/certs.d/<host>[:<port>]/ca.crt` |
| Docker Desktop (macOS) | the system keychain, then restart Docker |
| podman, skopeo, buildah | `/etc/containers/certs.d/<host>/ca.crt` |

If the hostname is not real, point it at yourself:
`echo "127.0.0.1 registry.local" | sudo tee -a /etc/hosts`.

Prefer not to manage trust by hand? [mkcert](https://github.com/FiloSottile/mkcert)
installs its authority into the system store for you:

```bash
brew install mkcert && mkcert -install
mkcert -cert-file certs/tls.crt -key-file certs/tls.key registry.local localhost 127.0.0.1
```

Certificates are development-only either way, and `certs/` is gitignored so a
private key cannot be committed. Anything other people reach wants a
certificate from a real authority — [Let's Encrypt](https://letsencrypt.org) is
free.

---

## Vulnerability scanning

Publishing an SBOM schedules a scan. Package URLs are matched against
[OSV.dev](https://osv.dev), and the result is stored per image manifest:

```bash
curl -u admin:PASSWORD \
  http://localhost:5001/api/repositories/team-a/app/manifests/<digest>/vulnerabilities
```

Severity is computed from the advisory's CVSS v3 vector rather than taken from a
vendor's own label, because the same CVE is routinely rated differently by
different databases and only the vector is common to all of them. Where no
usable vector exists the database's qualitative rating is used, and where
neither exists the finding is reported as `UNKNOWN` rather than assumed benign.

**Accuracy.** Two things had to be handled to avoid reporting nonsense:

- OSV indexes operating-system packages by ecosystem name and language packages
  by package URL. A purl query for an Alpine or Debian package returns *nothing*
  — not an error — so getting this wrong reads as "no vulnerabilities". Each
  component is sent in whichever shape actually finds it.
- Red Hat's advisories are published under an ecosystem that is not split by
  release, so a query matches every RHEL major version at once. Left alone, a
  current UBI 8 image reported 463 high-severity findings, none with a fix.
  Red Hat findings are now verified against the advisory's own affected ranges
  using RPM version comparison — including the epoch, which lives in a purl
  qualifier and outranks everything else. The same image now reports 11.

**What it does not do.** It reports on what the SBOM found, so its coverage is
the SBOM's coverage. Distribution-backported fixes are a known source of
over-reporting for language packages bundled by a distribution: RHEL ships
`urllib3 1.24.2` with fixes backported, but the upstream PyPI feed only knows
the version number. Findings are advisory matches, not exploitability
judgements. A failed scan is recorded as failed and shown as such, because
"could not check" must never render as "clean".

**Turning it off.** Scanning is the only part of the registry that talks to
anything outside it, so it is the one thing an air-gapped or egress-restricted
deployment has to decide about:

```bash
REGISTRY_VULN_SCAN=false                        # keep SBOMs, do no matching
REGISTRY_VULN_ENDPOINT=https://osv.internal     # or match against a mirror
REGISTRY_SBOM=false                             # or generate no SBOMs at all
```

Each is independent: SBOM generation is local and works with scanning off.

---

## Token authentication

HTTP Basic is the default and works with every client tested here. Setting
`REGISTRY_TOKEN_AUTH=true` additionally offers the Docker bearer-token scheme,
which Harbor, ECR, GCR and Docker Hub use and which some tooling assumes a
registry speaks:

```bash
REGISTRY_TOKEN_AUTH=true
REGISTRY_TOKEN_SECRET=...    # required if you run more than one instance
REGISTRY_TOKEN_REALM=https://registry.example.com/token   # optional; see below
```

The realm must be an **absolute URL** — clients reject a bare path outright
rather than resolving it against the registry. Since the registry does not know
its own public address, an unset realm is derived per request from the `Host`
header, honouring `X-Forwarded-Proto` and `X-Forwarded-Host`. That is correct
for direct access and for a normal reverse proxy; set the variable explicitly
for anything else.

A client is challenged with the token service and the scope it is attempting,
fetches a token for that scope, and retries:

```
WWW-Authenticate: Bearer realm="https://registry.example.com/token",service="container-registry"
GET /token?service=...&scope=repository:team-a/app:pull
```

The token service is part of the registry, so enabling this costs nothing
operationally. Tokens are signed rather than stored: they are short-lived and
self-describing, so validating one does not need a database round trip on every
blob request. The requested scope is **narrowed** to what the caller actually
has rather than trusted — asking for `pull,push` with a pull-only credential
yields a token good for `pull` alone.

Basic auth keeps working with this enabled, so turning it on cannot break a
client that already works.

An issued bearer token is a credential for `/v2` and nothing else. It is
refused by the management API and cannot be exchanged for another token: it is
short-lived, scoped to one repository, and handed to whatever container tool
asked for it, so treating it as a login would let a pull token read the audit
log or mint an API token that outlives it. Sign in to the management API with a
password or an API token instead.

Because a bearer token is verified by its signature rather than looked up, a
disabled account or revoked token is re-checked against the database at most
every 30 seconds rather than on every request — revocation takes effect within
that window instead of at the end of the token's lifetime.

---

## Pull-through cache

Setting `REGISTRY_PROXY_REMOTE` makes the registry mirror an upstream. An image
under the proxy prefix that is missing locally is fetched, stored, and served
from here from then on:

```bash
REGISTRY_PROXY_REMOTE=https://registry-1.docker.io
REGISTRY_PROXY_USERNAME=...    # anonymous works, at a much lower rate limit
```

```bash
docker pull registry.example.com/proxy/library/alpine:3.20
```

The prefix scopes it, so `proxy/library/alpine` comes from upstream while
`team-a/app` stays purely local. Set an empty prefix to mirror everything.

Upstream blobs are streamed through the same upload path as a push, so their
digests are verified on the way in — an upstream is not more trusted than a
client. The Docker token-auth flow is handled, with tokens cached per scope
because upstreams issue one per repository and re-fetching for every blob would
triple the request count.

**Verified against Docker Hub**: pulling `proxy/library/alpine:3.20` fetched the
multi-platform index and its blobs, and a second pull made no upstream requests
at all.

---

## Repository access grants

By default any user who can reach a repository may use it. Adding the first
grant governs that repository, and from then on only the people named on it have
access:

```bash
curl -u admin:PASSWORD -X POST \
  http://localhost:5001/api/repositories/team-a/app/grants \
  -H 'Content-Type: application/json' -d '{"username":"dev","role":"write"}'
```

Roles are graded: `read` pulls, `write` also pushes, `admin` also deletes and
manages the repository's own grants. Two deliberate exceptions — a registry
administrator is never locked out, or a mistaken grant could make a repository
unadministrable; and a public repository stays readable, because that is what
public means.

Grants apply to the management API exactly as they do to `/v2`: an ungranted
user cannot read a governed repository's tags, manifests or SBOM through
`/api/repositories`, cannot delete anything in it, and cannot mark it public —
which would otherwise re-open it to everyone. A governed repository is also
hidden from `/v2/_catalog` and the repository listing, because a name is itself
information.

---

## Metrics

`/metrics` serves the Prometheus text format, written directly rather than by
depending on the client library: the registry publishes a few dozen series with
no histograms, and the format is a documented handful of lines.

Requests are labelled by *kind* — `blob`, `blob_upload`, `manifest`, `tags`,
`api` — rather than by path. A label per repository would give the scrape
unbounded cardinality, which is the usual way a metrics endpoint becomes the
most expensive thing in a system.

Gauges cover repositories, tags, manifests, blobs, storage bytes, images
scanned and open findings by severity, plus SBOM and webhook activity.

The endpoint is unauthenticated by default, because that is what every scraper
expects and the values are counts rather than content. Set
`REGISTRY_METRICS_TOKEN` to require `Authorization: Bearer` when it is
reachable from outside.

---

## Quotas

A repository with no quota is unlimited, so this changes nothing until set:

```bash
curl -u admin:PASSWORD -X PATCH \
  http://localhost:5001/api/repositories/team-a/app \
  -H 'Content-Type: application/json' -d '{"quota_bytes": 5368709120}'
```

The check runs after a blob's bytes have landed but before it is linked to the
repository, so an over-quota push is refused without the repository being
charged for it; the orphaned blob is reclaimed by the next collection. Setting a
quota is administrator-only.

---

## Webhooks

```bash
curl -u admin:PASSWORD -X POST http://localhost:5001/api/webhooks \
  -H 'Content-Type: application/json' \
  -d '{"name":"ci","url":"https://ci.example.com/hook",
       "secret":"a-shared-secret","events":"push.tag,delete.tag"}'
```

Events: `push.tag`, `push.manifest`, `delete.tag`, `delete.manifest`,
`scan.complete`, `retention.delete_tag`. Omit `events` or use `*` for all of
them. Adding `"repository"` scopes the hook to one repository instead of the
whole registry.

Each delivery carries `X-Registry-Signature-256`, an HMAC-SHA256 over
`"<timestamp>.<body>"` keyed with the secret. Verifying it:

```python
import hashlib, hmac
ts = request.headers["X-Registry-Timestamp"]
want = "sha256=" + hmac.new(SECRET, f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
hmac.compare_digest(want, request.headers["X-Registry-Signature-256"])
```

The timestamp is signed alongside the body so a captured delivery cannot be
replayed indefinitely — reject one whose timestamp is far from now.

Server errors are retried with exponential backoff; a 4xx other than 429 is not
retried, because it will not improve and hammering a receiver that has rejected
the request shape is pointless. Delivery never blocks the request that caused
it: events are queued, and a saturated queue drops them and counts the drops.

---

## How it compares to Harbor and Zot

[`docs/COMPARISON.md`](docs/COMPARISON.md) is a candid comparison against the two
open-source registries most often chosen for self-hosting — including where this
one loses, which is mostly high availability, replication and identity
integration.

---

## Storage routing

One registry can store blobs in several places, chosen by the repository they
belong to. The case this exists for is content that must not share storage: an
export-controlled namespace belongs in a GovCloud bucket, a partner namespace in
a commercial one, scratch work on local disk.

Configure it under **Maintenance**: add named backends, then ordered rules that
send repository namespaces to them.

```
 10  gov/*        -> govcloud       s3, us-gov-west-1
 20  partners/*   -> commercial     s3, us-east-1
 30  public/*     -> archive        s3
  —  *            -> default        local disk
```

Rules are checked in order and the first match wins, so specific patterns go
above general ones. `*` spans `/`, so `gov/*` also covers `gov/team/app`. A
repository matching no rule uses the default backend.

A rule can target **`default`** as well as a named backend, which is how a
namespace stays on — or returns to — local storage while a broader rule sends
its siblings elsewhere:

```
 10  demo/keep-*  -> default     local disk
100  demo/*       -> remote      s3
```

Without it the only way back was to delete or narrow the rule that sent the
content away, which is a blunt instrument when that rule is still right for
everything else.

**The routing key is the repository, not the user who pushed.** Following the
actor would let one repository accumulate layers in several buckets depending on
who happened to push them, and would make the residency boundary track people
rather than content. Who may push into a namespace is a separate question,
answered by the [per-repository grants](#repository-access-grants) that already
existed.

**Deduplication stops being global.** A layer in two repositories on two
backends is stored twice. For a boundary that is the point, not a regression:
deduplicating across it would put one copy of the bytes in whichever bucket saw
them first.

**Cross-repository blob mounting is refused across backends.** A mount links a
blob into another repository without moving bytes, so across a boundary the
target would advertise content whose bytes are in a bucket it never reads — a
broken pull, and where the boundary is a jurisdiction, content escaping the
region it was confined to. The registry declines and the client falls back to a
normal upload, which puts the bytes where they belong.

**Garbage collection is per backend**, with a reachable set per backend rather
than one global set. A digest alive in one bucket says nothing about an
identical orphan in another, and a single set would keep that orphan forever.

### Changing a rule does not move anything

Blobs do not move themselves, so a rule added after content exists leaves that
content where it is. The repository keeps reading from — and writing to — the
backend its blobs are already in, and is listed as **misplaced** until you move
it. Following the new rule for reads would 404 every image the repository
already held; following it for writes alone would split one repository across
two buckets.

Moving one is a migration, from the button beside it or:

```bash
curl -u admin:PASSWORD -X POST \
  https://registry.example.com/api/repositories/team-a/app/migrate
```

It copies only the digests that repository references, verifies each one by
reading it back from the target and comparing against the digest its key
encodes, and only then starts reading from the new backend. Writes are mirrored
to the target while the copy runs, so a push landing mid-move is not lost at the
switch. A failure changes nothing: the repository still reads from where it was,
and blobs already copied make a retry resume rather than start over. The old
backend keeps its copy until you remove it.

Only one migration runs at a time; a second is refused while one is in flight.

**Upgrading an existing registry** records a placement for every repository that
already has content, before any rule is consulted — before routing existed there
was one backend, so that is where their blobs are. Without that, a rule added
later would treat them as new and send their reads to an empty bucket.

---

## Putting storage on another disk

The compose file stores data in a named Docker volume, which lives under
`/var/lib/docker/volumes` — on the OS disk. That is the wrong place when the OS
disk is small, because everything that grows is in there.

Point it at another mount instead:

```bash
sudo mkdir -p /mnt/data/registry
sudo chown 10001:10001 /mnt/data/registry     # the uid the registry runs as

REGISTRY_STORAGE_PATH=/mnt/data/registry \
  docker compose -f docker-compose.yml -f docker-compose.hostpath.yml up -d
```

The `chown` is the step that catches people out. The registry does not run as
root, and a bind-mounted host directory keeps whatever ownership it has on the
host — unlike a named volume, which Docker initialises from the image, ownership
included. A directory created with `mkdir` belongs to root, and the registry
cannot write to it. Setting `REGISTRY_STORAGE_PATH` is mandatory in that
override rather than defaulting to something: a typo silently filling the OS
disk is exactly what it exists to prevent.

To keep using a named volume while its contents live elsewhere, bind it instead
of moving Docker's whole data root:

```yaml
volumes:
  registry-data:
    driver_opts:
      type: none
      o: bind
      device: /mnt/data/registry
```

**What ends up there.** Blobs, the upload scratch area, `registry.db` and its
write-ahead log, and `config.key`. Size the disk for the blobs; the database is
small by comparison.

Note that **object storage does not empty this directory**. With an S3 backend
configured, blobs go to the bucket but the metadata database, the encryption key
and the upload scratch area stay local, and an in-progress upload is buffered in
full before it is committed — so a registry taking multi-gigabyte layers still
needs room for them. Only completed blobs move off the disk.

---

## Object storage

Blobs live on local disk by default. Setting `REGISTRY_S3_BUCKET` moves them to
any S3-compatible store — AWS, MinIO, Ceph RADOS Gateway, Backblaze B2,
Cloudflare R2 — which is what lifts the single-host limit:

```bash
REGISTRY_S3_ENDPOINT=http://minio:9000
REGISTRY_S3_BUCKET=registry-blobs
REGISTRY_S3_ACCESS_KEY=...
REGISTRY_S3_SECRET_KEY=...
REGISTRY_S3_PREFIX=production      # optional; one bucket, several registries
```

Signing is AWS Signature Version 4, implemented directly rather than by
depending on an SDK: the registry needs six S3 operations, and the algorithm is
a page of well-specified hashing against a very large dependency. Upload bodies
are streamed with `UNSIGNED-PAYLOAD` — hashing a multi-gigabyte layer twice to
satisfy a signature would defeat the point of streaming, and the registry
verifies the digest itself regardless.

Upload scratch space stays on local disk even when blobs do not. An in-progress
upload is appended to and re-read constantly, and object stores charge per
request.

### Configuring it from the UI

The **Maintenance** page shows which backend is in effect — endpoint, bucket,
region, key prefix, addressing style and a masked access key — and can change
it. The settings are proved against the real backend before being saved (a
write, a read back and a delete), so a wrong bucket or an expired key fails at
the form rather than at the next push. The secret key is never returned by the
API.

Saving does not move anything, because blobs do not move themselves: until they
are copied, a new backend would answer 404 for every image the registry already
had. So the switch is an explicit **migration** that copies every blob, verifies
each one by reading it back and comparing against the digest its key encodes,
and only then starts serving from the new backend. Pushes keep working
throughout — writes go to both backends until the copy finishes, so nothing
pushed mid-migration is lost at the switch. A failed or interrupted migration
changes nothing: blobs are content-addressed, so a retry resumes rather than
starting over. The old backend keeps its copy until you remove it.

`REGISTRY_S3_*` in the environment still wins. A value set in a unit file is
what its author expects to be in force, so when those variables are present the
UI shows the configuration read-only and refuses to override it. Only when the
environment is silent does the saved configuration apply.

The secret key is encrypted with AES-GCM under a key in `config.key`, written
0600 beside the database rather than inside it — a stolen database file alone
does not yield the object-store credential.

**Verified against MinIO**: the full OCI conformance suite passes with blobs in
object storage — 986 assertions, zero failures — as do byte-range reads,
garbage collection walking and deleting bucket objects, and pulls through both
crane and skopeo.

The SQLite metadata database is still local, so this removes the storage
bottleneck but not the single-writer one. Two registry processes cannot yet
share a database.

---

## Rate limiting

Off by default. Setting `REGISTRY_RATE_LIMIT` bounds how fast one caller can
drive the registry, which authentication alone does nothing about — a single
valid token can otherwise saturate upload capacity and fill the disk.

```bash
REGISTRY_RATE_LIMIT=600          # 10 requests a second, sustained
REGISTRY_RATE_LIMIT_WRITES=60    # but only one push a second
REGISTRY_RATE_BURST=50           # tolerate a burst of 50
```

Writes are limited separately because a push costs far more than a manifest
read, so a single number for both cannot be right; leaving the write limit
unset applies the general limit to both.

A caller is identified by its principal — a token or a user — so a limit
follows the credential wherever it connects from, and an anonymous caller is
identified by address because that is all there is. Over-limit requests get
`429` with the OCI `TOOMANYREQUESTS` code and a `Retry-After` in whole seconds,
never zero.

Buckets are held in memory, so limits are **per process**: two instances behind
a load balancer each enforce their own. A shared counter would need a shared
store and turn every request into a network round trip.

### Failed authentication

Rate limits apply once a caller is known, which is exactly the point a rejected
credential never reaches. Failed authentications are therefore counted
separately, and this is **on by default** — password guessing is otherwise free,
and each guess costs the registry a bcrypt hash whether or not it was close.

```bash
REGISTRY_AUTH_FAIL_THRESHOLD=5   # failures tolerated before waiting begins
REGISTRY_AUTH_FAIL_WINDOW=15m    # how long a quiet caller keeps its count
REGISTRY_AUTH_LOCKOUT_MAX=15m    # longest wait imposed
```

Failures are counted against both the calling address and the account being
tried, so neither one host working through a list of accounts nor many hosts
working on one account goes unbounded. The wait doubles with each further
failure up to the maximum, and one success clears the record — a mistyped
password costs nothing.

While a wait stands the correct credential is refused too; otherwise the
throttle would report which guess was right. Callers presenting no credential
are unaffected, so anonymous pulls keep working during someone else's lockout.
Refusals are `429` with `Retry-After`, not `401`, so a client stops retrying and
a lockout is distinguishable from a wrong password in the log.

---

## Retention and garbage collection

Retention decides what is no longer wanted; collection frees the space. They run
together on `REGISTRY_MAINTENANCE_INTERVAL` (six hours by default), because
storage otherwise only grows — collection used to run when somebody remembered
to ask for it, which is not a maintenance strategy.

Rules are per repository and opt-in: **a repository with no rules keeps
everything**, so enabling the scheduler changes nothing on its own.

```bash
# keep only the ten newest nightly builds
curl -u admin:PASSWORD -X POST \
  http://localhost:5001/api/repositories/team-a/app/retention \
  -H 'Content-Type: application/json' \
  -d '{"kind":"keep_last","pattern":"nightly-*","keep_count":10}'

# never remove a production tag, whatever any other rule says
curl -u admin:PASSWORD -X POST \
  http://localhost:5001/api/repositories/team-a/app/retention \
  -H 'Content-Type: application/json' \
  -d '{"kind":"protect","pattern":"prod-*"}'

# what would a sweep do right now?
curl -u admin:PASSWORD -X POST http://localhost:5001/api/retention/preview
```

The preview names every tag it would remove and why, because retention deletes
permanently and that decision should be readable before it is trusted.
Protection is evaluated first and always wins. A malformed duration is ignored
rather than treated as "everything has expired", so a typo cannot empty a
repository.

Deleting a tag or a manifest removes the reference, not the bytes. Run a
collection to reclaim disk:

```bash
curl -u admin:PASSWORD -X POST 'http://localhost:5000/api/gc?dry_run=true'   # report only
curl -u admin:PASSWORD -X POST 'http://localhost:5000/api/gc'                # delete
```

It is a mark-and-sweep over the blob store:

1. Unlink blobs no manifest in their repository still references.
2. Snapshot everything reachable from a live manifest.
3. Delete unreachable blobs, skipping anything written within `REGISTRY_GC_GRACE`
   (default one hour) so a push in progress is never broken.

Collection is serialised — a second run is refused while one is active — and
abandoned upload sessions are purged in the same pass.

---

## Storage layout

```
<data dir>/
  registry.db                       SQLite metadata (WAL mode)
  blobs/sha256/<aa>/<full-hex>      blob content, named by its own digest
  uploads/<uuid>.data               in-progress upload body
  uploads/<uuid>.state              serialised SHA-256 state and offset
```

Blobs are shared globally and content-addressed, so pushing the same base image
to twenty repositories stores its layers once. The `blobs` table records which
repositories may serve which digest — a repository can never serve a blob it did
not upload or explicitly mount, even though the bytes are on disk.

Upload sessions persist their running SHA-256 state, so a chunked upload
survives a client reconnect and the digest is verified without re-reading the
blob.

---

## Development

```bash
make build       # build ./bin/registry
make run         # run locally on :5000
make test        # run the test suite
make test-race   # run under the race detector
make check       # fmt + vet + test
make audit       # vet + staticcheck + govulncheck
make docker      # build the container image
make conformance # run the official OCI distribution-spec conformance suite
```

The build stamps the version from `git describe`, which `registry --version`
reports and which is logged at start-up, so a running instance can be identified
from its logs. A binary built without that stamp says `dev`.

`make conformance` clones and builds the upstream suite on first run, starts a
throwaway registry on a scratch data directory, and runs the full set including
the optional upload-cancel and tag-parameter workflows.

Layout:

```
cmd/registry/      entrypoint, bootstrap, graceful shutdown
internal/config/   environment configuration
internal/db/       SQLite schema, migrations and queries
internal/store/    content-addressable blob store, upload sessions,
                   backend routing and migration between backends
internal/auth/     passwords, tokens, principals, scope matching
internal/api/      OCI /v2 API, management API, UI serving
internal/gc/       mark-and-sweep garbage collection
internal/sbom/     layer scanning, package parsers and CycloneDX publishing
web/               embedded management UI
```

The test suite covers the push/pull cycle, chunked and monolithic uploads,
digest verification under both sha256 and sha512, manifest validation,
multi-platform indexes, cross-repo mounts, blob isolation between repositories,
token scope enforcement, garbage collection, SBOM scanning and publishing, and
the management API. A dedicated group pins the spec behaviours the conformance
suite checks, so regressions surface in `go test` rather than only in the full
suite run.

---

## Security notes

To report a vulnerability, see [SECURITY.md](SECURITY.md), which also lists the
behaviour that is deliberate rather than a defect, and a hardening checklist for
a deployment that has to stand up to review.

- Passwords are bcrypt-hashed. Token secrets carry 256 bits of entropy and are
  stored as SHA-256, compared in constant time; the plaintext is shown once.
- Session cookies are `HttpOnly`, `SameSite=Strict`, and `Secure` when TLS is on.
- An administrative password reset invalidates that user's sessions, and
  changing your own password ends every session but the one you changed it in.
- Disabling a user immediately invalidates their tokens.
- Failed authentications are throttled by default, per address and per account,
  so password guessing is bounded rather than free. See [Failed
  authentication](#failed-authentication).
- Registry-issued bearer tokens are confined to `/v2`; the management API takes
  a password, a session or an API token.
- Per-repository grants are enforced identically on `/v2` and the management
  API, and govern listings as well as access.
- Uploaded content is verified against its claimed digest before it enters the
  blob store; a mismatch discards the upload.
- Anonymous pull, when enabled, applies only to repositories explicitly marked
  public — it is not a blanket read grant.
- Forwarding headers are believed only from a declared proxy, so the address in
  the audit log is not caller-controlled.
- Webhook deliveries refuse internal addresses, do not follow redirects, and
  re-check the destination as the connection is opened.
- The container runs as an unprivileged user with no capabilities and a
  read-only root filesystem; CI proves it starts and serves a push that way.
- CI runs `go vet`, `staticcheck`, `govulncheck` and Trivy against the source
  and the built image, weekly as well as on every change; CodeQL is configured
  and opt-in. See [SECURITY.md](SECURITY.md#what-ci-checks).

Run it behind TLS. The `WWW-Authenticate: Basic` challenge that makes
`docker login` work sends credentials base64-encoded, not encrypted.

### Behind a reverse proxy

`X-Forwarded-For`, `-Proto` and `-Host` are ignored unless the peer sending them
is named in `REGISTRY_TRUSTED_PROXIES`. Anyone can send those headers, and
believing them from an arbitrary caller lets it choose the address written to
the audit log, the bucket its failed logins are counted against, and the URL
clients are told to fetch credentials from.

```bash
REGISTRY_TRUSTED_PROXIES=10.0.0.0/8,192.168.1.5   # addresses or CIDR blocks
REGISTRY_TRUSTED_PROXIES='*'                      # any peer, if only the proxy can reach it
```

Unset — the default — the peer on the socket is the client, which is correct
for direct exposure and wrong behind a proxy: every request will appear to come
from the proxy. Set it to the proxy's address.

`Strict-Transport-Security` is sent only over a connection that is already
secure, directly or by a trusted proxy's `X-Forwarded-Proto`. Over plain HTTP it
would be ignored by browsers anyway, and would be a lie on a registry
deliberately run without TLS.

### Response headers

The web UI is served with a content security policy confining every fetch to
this origin, with framing, plugins, `<base>` rewriting and cross-origin form
posts refused outright. `script-src` still carries `'unsafe-inline'` because the
UI wires its buttons with inline `onclick` attributes, which no nonce or hash
covers — moving those to delegated listeners is what it would take to drop it.
The policy is not applied to `/v2`, which serves no HTML.

### Webhook destinations

A webhook URL is written by an administrator but fetched by the registry, so a
URL naming an address only the registry can reach — cloud metadata at
`169.254.169.254`, a database admin port, anything on loopback — turns the
registry into a way in. Delivery to loopback, link-local, private, shared and
unique-local addresses is refused unless `REGISTRY_WEBHOOK_ALLOW_INTERNAL=true`,
which is the setting for a receiver that genuinely lives on the private network.

The address is checked twice: when the webhook is created, so a mistake is
caught where it is made, and again as the connection is opened, which is the
check a DNS answer cannot be raced past. Redirects are not followed — a receiver
would otherwise be choosing the second destination itself.
