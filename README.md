# Container Registry

A self-hosted container registry implementing the [OCI Distribution
Specification](https://github.com/opencontainers/distribution-spec) v1.1. It
**passes the official OCI conformance suite — 986 assertions, zero failures** —
so it works with any OCI client, not just Docker. Every image pushed to it is
automatically described by a CycloneDX SBOM, published back as an OCI referrer.

Single Go binary, embedded web UI, SQLite metadata, filesystem blob storage.
No external services.

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
| **Docker / buildx** | moby | login, push, pull, multi-platform build --push |

Cross-client interoperability is exercised too: an image pushed by crane, with a
referrer attached by ORAS, discovered back through the referrers API.

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
- Detects OS packages (`apk`, `dpkg`, `rpm`), language packages (npm, PyPI) and
  Go module versions embedded in binaries — the last covers `FROM scratch` and
  distroless images that have no package database at all
- Runs on background workers; a push is never delayed or failed by it

**Vulnerability scanning**

- Each SBOM is matched against [OSV.dev](https://osv.dev) — free, no credentials,
  and covering every ecosystem the SBOM scanner detects
- Severity from the CVSS v3 vector computed in-registry rather than taken from a
  vendor label, because the same CVE is rated differently by different databases
- Fixed-version reported per finding, which is the part anyone can act on
- Per-tag risk in the repository listing, findings and re-scan on the image page
- Advisories are cached and shared across images, with a freshness bound

**Access control**

- Users with `admin`/`user` roles; the last administrator cannot be removed
- API tokens with independent `pull`/`push`/`delete`/`admin` permissions
- Per-token repository scopes as comma-separated globs (`team-a/*, shared/base`)
- Tokens can never exceed the rights of the user that owns them
- Repositories can be marked public (readable by anyone) or immutable
  (existing tags cannot be moved to different content)
- Every push, delete, tag and administrative change is written to an audit log

**Management**

- Web UI: repository browser, tag and layer inspection, image config and build
  history, token issue/revoke, user management, audit log, garbage collection
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
| `REGISTRY_VULN_ADVISORY_TTL` | `24h` | How long a cached advisory is reused |
| `REGISTRY_MAINTENANCE_INTERVAL` | `6h` | How often retention and collection run; `0` disables |
| `REGISTRY_MAINTENANCE_DELAY` | `5m` | Delay before the first scheduled sweep |
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
binaries other than Go. `zstd`-compressed layers are skipped, and when that
happens the document records it in a `registry:skippedLayers` property rather
than silently under-reporting; reaching the language-package cap is recorded the
same way as `registry:truncated`. Scans are bounded (file size, database size,
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
make docker      # build the container image
make conformance # run the official OCI distribution-spec conformance suite
```

`make conformance` clones and builds the upstream suite on first run, starts a
throwaway registry on a scratch data directory, and runs the full set including
the optional upload-cancel and tag-parameter workflows.

Layout:

```
cmd/registry/      entrypoint, bootstrap, graceful shutdown
internal/config/   environment configuration
internal/db/       SQLite schema, migrations and queries
internal/store/    content-addressable blob store and upload sessions
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

- Passwords are bcrypt-hashed. Token secrets carry 256 bits of entropy and are
  stored as SHA-256, compared in constant time; the plaintext is shown once.
- Session cookies are `HttpOnly`, `SameSite=Strict`, and `Secure` when TLS is on.
- An administrative password reset invalidates that user's sessions.
- Disabling a user immediately invalidates their tokens.
- Uploaded content is verified against its claimed digest before it enters the
  blob store; a mismatch discards the upload.
- Anonymous pull, when enabled, applies only to repositories explicitly marked
  public — it is not a blanket read grant.

Run it behind TLS. The `WWW-Authenticate: Basic` challenge that makes
`docker login` work sends credentials base64-encoded, not encrypted.
