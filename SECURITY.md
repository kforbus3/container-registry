# Security policy

## Reporting a vulnerability

Report privately through GitHub's [Report a
vulnerability](https://github.com/kforbus3/container-registry/security/advisories/new)
form, which opens a draft advisory only the maintainers can see. Please do not
open a public issue for something exploitable.

Useful things to include: what an attacker can do, the smallest sequence of
requests that shows it, and the version or commit you saw it on. A proof of
concept is welcome but not required — a clear description of the flaw is
usually enough to reproduce it.

You should get an acknowledgement within a week. Fixes go out as a release, and
you will be credited in it unless you would rather not be.

## What is in scope

The registry as it runs from this repository: the OCI `/v2` API, the management
API and the web UI, the authentication and permission model, the storage layer,
SBOM generation and vulnerability scanning, and the container image built from
the `Dockerfile` here.

Some things that are documented behaviour rather than defects:

- **Registry administrators are never governed by repository grants.** A
  mistaken grant would otherwise be able to make a repository unadministrable.
- **A public repository is readable by anyone who can reach the registry**, and
  by unauthenticated callers when `REGISTRY_ANONYMOUS_PULL=true`. That is what
  public means here.
- **Users hold full rights on repositories that no grant governs.** Per-repository
  grants are what narrow that; API tokens can be narrowed with a repository
  pattern.
- **Bearer tokens are valid for up to `REGISTRY_TOKEN_TTL` after the account
  behind one is disabled**, bounded by a 30-second re-check against the
  database. They are signed rather than stored so that pulling a large image
  does not become one database round trip per layer.
- **Rate limits and authentication throttling are per process.** Two instances
  behind a load balancer each count their own; a shared counter would need a
  shared store.
- **Running without TLS.** `docker login` sends credentials base64-encoded, not
  encrypted. Serve HTTPS, either directly or behind a proxy.

## Reporting something in a dependency

If the issue is in a dependency rather than in this code, an issue is fine —
there is nothing to keep quiet, and `govulncheck` runs in CI weekly and may
already have flagged it.

## Hardening checklist

For a deployment that has to stand up to review:

- Serve TLS, directly or behind a proxy. Set `REGISTRY_TRUSTED_PROXIES` to the
  proxy's address so forwarded headers are believed from it and nowhere else.
- Set `REGISTRY_ADMIN_PASSWORD` before the first start, or record the generated
  one that is printed once.
- Set `REGISTRY_TOKEN_SECRET` if you run more than one instance.
- Set `REGISTRY_RATE_LIMIT`; leave `REGISTRY_AUTH_FAIL_THRESHOLD` on.
- Set `REGISTRY_METRICS_TOKEN` if `/metrics` is reachable from anywhere but a
  scraper you control.
- Set `REGISTRY_MAX_UPLOAD_BYTES` to something larger than your biggest layer
  but smaller than your disk.
- Leave `REGISTRY_WEBHOOK_ALLOW_INTERNAL` off unless a receiver genuinely lives
  on the private network.
- Use the `security_opt`, `cap_drop` and `read_only` settings from
  `docker-compose.yml`; the registry is tested running with them.

## What CI checks

Every push and pull request, and weekly on a schedule:

| Check | What it covers |
| --- | --- |
| `go vet`, `gofmt` | Correctness and formatting |
| `staticcheck` | Dead code, misuse, suspect constructs |
| `govulncheck` | Known vulnerabilities in code paths this binary reaches |
| Trivy (image) | Packages the base image contributes |
| Trivy (config) | The Dockerfile and compose files |
| `go test -race` | The suite, with the race detector |
| Image smoke test | The registry starts with no capabilities and a read-only root, and round-trips a blob |

`make audit` runs the source-level ones locally.

CodeQL is configured but **off by default**: it reports through code scanning,
which needs GitHub Advanced Security on a private repository. Set the repository
variable `ENABLE_CODEQL` to `true` once code scanning is available under
Settings → Code security, or if the repository is made public, where it is
free. Trivy deliberately does not depend on it — findings fail the job and are
printed in the log instead.
