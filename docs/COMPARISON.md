# How this registry compares to Harbor and Zot

A candid comparison against the two open-source registries most often chosen for
self-hosting. It is written to be useful when deciding, which means it spends as
much time on where this registry loses as on where it wins.

**What was measured and what was not.** Zot was run locally and its numbers are
observed. Harbor was not: it is a nine-service deployment and standing one up
was out of proportion to the question, so its entries come from its
documentation and architecture rather than a local run — treated here as claims,
not measurements. Anything measured is marked *(measured)*.

---

## The short version

| | This registry | Harbor | Zot |
| --- | --- | --- | --- |
| Best at | Doing a lot in one binary | Being an enterprise platform | Being a minimal conformant registry |
| Worst at | Scale beyond one host | Operational weight | Everything past storing artifacts |
| Choose it when | One host, and you want SBOMs, scanning, quotas and RBAC without deploying a platform | You need replication, projects, robot accounts, SSO, and have people to run it | You want a small, fast, conformant registry and will bring your own tooling |

---

## Where this registry is genuinely better

**It does the whole job in one process.** A single ~40 MB image *(measured)*
with no database server, no queue, no object store required. Harbor needs
Postgres, Redis, and roughly nine containers; Zot is one binary but leaves
scanning, quotas and RBAC to you or to extensions. Here, SBOM generation,
vulnerability scanning, retention, quotas, RBAC, webhooks, metrics and the UI
are all in the same binary and on by default.

**Resource footprint** *(measured, steady state, one image pushed)*:

| | Image size | Idle RSS |
| --- | --- | --- |
| This registry | 39.4 MB | 14.2 MiB |
| Zot | 319 MB | 204.1 MiB |
| Harbor | not measured; multi-container | documented at ~4 GB RAM recommended |

**SBOMs are generated automatically, by the registry, on push.** Harbor and Zot
both scan by delegating to Trivy; neither publishes an SBOM as a first-class
artifact of the push itself. Here every image gets a CycloneDX 1.5 SBOM attached
as an OCI referrer, so `oras discover` and any OCI-aware tool find it without
knowing anything about this registry.

**Package detection is at parity with Syft** *(measured)*, which is what Harbor
and Zot's Trivy integration uses underneath:

| Image | This registry | Syft |
| --- | --- | --- |
| maven:3.9-eclipse-temurin-21 | 212 | 215 |
| ruby:3.3-slim | 168 | 169 |
| traefik:v3.1 | 334 | 335 |
| python:3.11-slim | 108 | 122 |

The python gap is not coverage: 14 of Syft's 15 extra entries are pip's vendored
Windows launcher stubs with no version. The fifteenth, the interpreter itself,
is detected.

**Per-namespace storage backends.** Repositories route to different backends by
name pattern, so `gov/*` can live in a GovCloud bucket while `partners/*` lives
in a commercial one, with cross-backend blob mounting refused and per-backend
garbage collection. Harbor supports one storage backend per instance; Zot the
same. For a data-residency boundary inside one registry, neither has an
equivalent — you would run separate instances.

**No third-party egress by default in the `no-vuln-scanning` build.** For an
air-gapped or export-controlled deployment, a registry that provably makes no
outbound connections is a shorter conversation than one that must be configured
not to.

---

## Where this registry falls short

**One host. No high availability.** The metadata lives in SQLite, so two
processes cannot share it. Blobs can be on S3, but the database cannot, which
means no active-active, no rolling restart without a blip, and a host failure is
an outage. Harbor runs multiple replicas against Postgres; Zot is stateless
enough to run several against shared storage. This is the single biggest reason
to choose something else, and it is architectural rather than a missing feature.

**No replication between registries.** Harbor's replication — pull-through and
push-based, on rules and schedules, to other Harbors, Docker Hub, ECR, GCR,
Quay — is a genuinely large feature with no counterpart here. There is a
pull-through cache, which covers "avoid Docker Hub rate limits" but not "keep
two sites in sync".

**No projects, robot accounts, or SSO.** Access control here is users, API
tokens with repository-pattern scopes, and per-repository grants. Harbor has
projects as a first-class tenancy boundary, robot accounts scoped to them, and
OIDC/LDAP integration. For an organisation with many teams and an existing
identity provider, that gap is decisive.

**No image signing or policy enforcement.** Harbor integrates Cosign/Notation
and can refuse to serve unsigned or vulnerable images. This registry stores
signatures if you push them as referrers, but enforces nothing: it will not
block a pull because an image failed a scan. If your requirement is "only signed
images may be deployed", this does not meet it on its own.

**Vulnerability data comes from OSV.dev, not a curated feed.** Harbor's Trivy
integration carries vendor-specific advisory sources and their severity
overrides. The scanning here computes severity from the CVSS vector and applies
Red Hat range filtering, but does not carry per-vendor curation, so results can
differ from what a Trivy-based scanner reports on the same image.

**No quota or GC maturity at scale.** Retention and collection work and are
tested, but they walk the whole backend. Harbor's have been exercised on
registries far larger than anything this has seen.

**Smaller everything else.** No Helm chart, no operator, no CVE allowlists, no
tag immutability rules beyond a per-repository flag, no audit log export, no
proxy cache quotas, and a far smaller community if something breaks at 2am.

---

## Where Zot is better than this registry

- **Simpler to reason about.** It stores artifacts and does that well. Fewer
  moving parts than either alternative.
- **Genuinely stateless.** Nothing but the storage layer holds state, so scaling
  horizontally is a matter of running more copies. This registry cannot.
- **Broader storage support**, including reading and writing OCI layouts
  directly, which makes it easy to bootstrap from a directory.
- **Actively developed under CNCF**, with a security posture and release cadence
  that a single-author project cannot match.

## Where this registry is better than Zot

- Batteries included: Zot's search, UI, scanning and sync are extensions that
  must be enabled and configured; here they are the default behaviour.
- SBOMs on push, which Zot does not do at all.
- Much smaller footprint *(measured: 39 MB vs 319 MB image, 14 MiB vs 204 MiB
  idle)* — surprising, given Zot's minimalism is its pitch, and worth verifying
  in your own environment before relying on it.
- Per-namespace storage routing, retention rules, and quotas out of the box.

---

## Honest recommendation

**Choose Harbor** if you are an organisation: multiple teams, SSO, replication
between sites, signing policy, and staff to operate a multi-service deployment.
Nothing here competes on that ground.

**Choose Zot** if you want a small conformant registry and intend to bring your
own scanning, UI and policy, or if you need horizontal scaling and are happy to
assemble the rest.

**Choose this** for a single host that should do a lot without becoming a
platform: a team or a lab registry where SBOMs, scanning, quotas, retention and
RBAC matter but a nine-container deployment does not make sense — or where the
per-namespace storage boundary or the no-egress build solves a specific problem
the other two do not address.

**Do not choose this** if you need high availability. That is not a gap that
configuration closes.

---

## Conformance

All three implement the OCI Distribution Specification v1.1. This registry
passes the official conformance suite at 986 assertions with zero failures
*(measured)*, and Zot's `/v2/` and referrers endpoints answered correctly in the
same local run *(measured)*; a full suite run against Zot and Harbor was not
performed, and both projects publish their own conformance results.
