# Building an image and pushing it to your registry

A walkthrough from an empty directory to an image stored in your own registry,
pulled back, and its bill of materials inspected. Every command here was run
against a real registry; the output shown is what you should see.

You need Docker installed. Nothing else.

---

## 1. Start the registry

For a first run on your own machine, use the local override. It serves plain
HTTP on `localhost:5001`, which needs no certificates:

```bash
cd container-registry
REGISTRY_ADMIN_PASSWORD=choose-a-password docker compose \
  -f docker-compose.yml -f docker-compose.local.yml up -d
```

> The base `docker-compose.yml` on its own serves **HTTPS on port 443** and
> expects certificates — that is the right setup for a real deployment, and is
> covered in the README. The override above is purely for trying things out.
>
> Port **5001**, not the conventional 5000, because macOS binds 5000 to the
> AirPlay Receiver. If 5000 is free on your machine you can set
> `REGISTRY_PORT=5000`.

Check it came up:

```bash
docker compose -f docker-compose.yml -f docker-compose.local.yml ps
```

```
NAME                 STATUS
container-registry   Up 6 seconds (healthy)   0.0.0.0:5001->5000/tcp
```

If you left `REGISTRY_ADMIN_PASSWORD` unset, a password was generated and
printed once — read it out of the log:

```bash
docker compose -f docker-compose.yml -f docker-compose.local.yml logs registry \
  | grep -A3 "generated password"
```

Open <http://localhost:5001> and sign in as `admin` to see the web UI.

---

## 2. Log in from Docker

```bash
docker login localhost:5001 -u admin
```

It prompts for the password. To avoid putting it in your shell history:

```bash
echo "choose-a-password" | docker login localhost:5001 -u admin --password-stdin
```

```
Login Succeeded
```

Docker allows plain HTTP for `localhost` and `127.0.0.1` only. Any other
hostname needs HTTPS — see [Troubleshooting](#troubleshooting).

---

## 3. Build an image

Make a directory with two files.

`app.sh`:

```sh
#!/bin/sh
echo "Hello from my first image!"
echo "built for: $(uname -m)"
```

`Dockerfile`:

```dockerfile
FROM alpine:3.20
COPY app.sh /usr/local/bin/app.sh
CMD ["/usr/local/bin/app.sh"]
```

Make the script executable, then build:

```bash
chmod +x app.sh
docker build -t hello-app:1.0 .
```

Check it works before pushing anything:

```bash
docker run --rm hello-app:1.0
```

```
Hello from my first image!
built for: aarch64
```

---

## 4. Tag it for your registry

Docker decides where to push from the image's **name**, so the registry address
has to be part of it. `hello-app:1.0` would go to Docker Hub; retag it:

```bash
docker tag hello-app:1.0 localhost:5001/demo/hello-app:1.0
```

The name breaks down as:

```
localhost:5001  /  demo        /  hello-app  :  1.0
─── registry ──    ─ project ─    ── name ──    tag
```

The `demo/` part is yours to choose — repositories are created on first push,
so nothing needs setting up in advance.

---

## 5. Push

```bash
docker push localhost:5001/demo/hello-app:1.0
```

```
3f26bc2dec0b: Pushed
708d939eae3b: Pushed
1.0: digest: sha256:985ecdad… size: 855
```

That is it. Refresh the web UI and the repository is listed.

Confirm from the command line too:

```bash
curl -s -u admin:choose-a-password http://localhost:5001/v2/_catalog
curl -s -u admin:choose-a-password http://localhost:5001/v2/demo/hello-app/tags/list
```

```json
{"repositories":["demo/hello-app"]}
{"name":"demo/hello-app","tags":["1.0"]}
```

---

## 6. Pull it back

To prove it really round-trips, delete your local copies and run it straight
from the registry:

```bash
docker rmi localhost:5001/demo/hello-app:1.0 hello-app:1.0
docker run --rm localhost:5001/demo/hello-app:1.0
```

```
Hello from my first image!
built for: aarch64
```

---

## 7. Look at the SBOM

A software bill of materials was generated automatically in the background —
you did not ask for it and the push did not wait for it. It lists everything
installed in the image.

The easiest way to see it is the web UI: open the repository, click **Inspect**
on the tag, and scroll to **Software Bill of Materials**. **View components**
lists them; **Download SBOM** saves the CycloneDX file.

From the command line, get the tag's digest and then its SBOM:

```bash
DIGEST=$(curl -s -u admin:choose-a-password \
  http://localhost:5001/api/repositories/demo/hello-app \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["tags"][0]["digest"])')

curl -s -u admin:choose-a-password \
  "http://localhost:5001/api/repositories/demo/hello-app/manifests/$DIGEST/sbom" \
  > sbom.json
```

Your `alpine` base contributes 14 packages:

```bash
python3 -c 'import json;d=json.load(open("sbom.json"));print(len(d["components"]),"components");[print(" -",c["name"],c.get("version","")) for c in d["components"][:5]]'
```

```
14 components
 - alpine-baselayout 3.6.5-r0
 - alpine-baselayout-data 3.6.5-r0
 - alpine-keys 2.4-r1
 - apk-tools 2.14.4-r1
 - busybox 1.36.1-r29
```

Because it is attached as a standard OCI referrer, other tools find it without
knowing anything about this registry:

```bash
oras discover localhost:5001/demo/hello-app:1.0
```

---

## 8. Use a token instead of your password

Putting your admin password into a script or CI job is a bad habit. Create a
token scoped to just what it needs — here, push access to `demo/*` only:

```bash
curl -s -u admin:choose-a-password -X POST http://localhost:5001/api/tokens \
  -H 'Content-Type: application/json' \
  -d '{"name":"my-laptop","can_pull":true,"can_push":true,"repo_pattern":"demo/*"}'
```

The response contains `secret`. **It is shown once and never again** — copy it
now. Then use it as the password:

```bash
echo "crt_xxxxxxxxxxxx_yyyy…" | docker login localhost:5001 -u my-laptop --password-stdin
```

```
Login Succeeded
```

The username is ignored when you present a token, so use anything memorable.
A token can never do more than its owner can, and this one cannot touch
anything outside `demo/`. Revoke it from the UI under **API Tokens** the moment
it is no longer needed.

You can also create tokens in the UI — **API Tokens → New token**.

---

## 9. Push a new version

The everyday loop, once everything is set up:

```bash
docker build -t localhost:5001/demo/hello-app:1.1 .
docker push localhost:5001/demo/hello-app:1.1
```

Building straight to the full name saves the separate `docker tag` step.

To promote an existing image to another tag **without** rebuilding or
re-uploading anything, point a new tag at content that is already there:

```bash
curl -s -u admin:choose-a-password -X POST \
  http://localhost:5001/api/repositories/demo/hello-app/tags \
  -H 'Content-Type: application/json' \
  -d '{"tag":"production","target":"1.1"}'
```

No layers move; only the tag is written. `docker pull` sees it immediately.

---

## Moving to HTTPS

Everything above used `localhost`, which Docker lets you talk to over plain
HTTP. The moment you use any other name — a hostname on your LAN, a server —
Docker demands HTTPS. Here is the shortest path to that working.

**1. Issue a certificate.** Name every host you will type into a `docker push`:

```bash
make certs HOSTS="registry.local"
```

This writes `certs/ca.crt` (the authority), `certs/tls.crt` and `certs/tls.key`.

**2. Make the name resolve**, if it is not already a real DNS name:

```bash
echo "127.0.0.1 registry.local" | sudo tee -a /etc/hosts
```

**3. Start the registry**, this time with the plain compose file — it serves
HTTPS on 443 and picks up `./certs` automatically:

```bash
REGISTRY_ADMIN_PASSWORD=choose-a-password docker compose up -d --build
```

Check it before involving Docker, trusting the authority explicitly:

```bash
curl --cacert certs/ca.crt https://registry.local/healthz
```

```json
{"status":"ok"}
```

**4. Teach Docker to trust the authority.** This is the step people skip, and
the reason for `x509: certificate signed by unknown authority`.

On Docker Desktop for macOS:

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain certs/ca.crt
```

Then restart Docker Desktop — it only reads the keychain at startup.

On Docker Engine on Linux, no restart needed:

```bash
sudo mkdir -p /etc/docker/certs.d/registry.local
sudo cp certs/ca.crt /etc/docker/certs.d/registry.local/ca.crt
```

**5. Push as usual**, with no port in the name — 443 is implied:

```bash
docker login registry.local -u admin
docker tag hello-app:1.0 registry.local/demo/hello-app:1.0
docker push registry.local/demo/hello-app:1.0
```

To check the TLS side without changing any system trust, use a tool that takes
the CA as an argument:

```bash
docker run --rm --add-host=registry.local:host-gateway \
  -v "$PWD/certs/ca.crt":/etc/containers/certs.d/registry.local/ca.crt:ro \
  quay.io/skopeo/stable:latest \
  copy --dest-creds admin:choose-a-password \
  docker://alpine:3.20 docker://registry.local/demo/alpine:3.20
```

These certificates are for development. For anything other people reach, get a
real one — [Let's Encrypt](https://letsencrypt.org) is free — and skip the
trust step entirely, because the whole world already trusts it.

---

## Troubleshooting

**`connection refused` on port 5000, or you get a strange 403.**
macOS binds port 5000 to the AirPlay Receiver, which answers requests instead of
your registry. Use another port, or turn it off in
*System Settings → General → AirDrop & Handoff → AirPlay Receiver*.

```bash
lsof -nP -iTCP:5000 -sTCP:LISTEN     # shows "ControlCe" if AirPlay has it
```

**`http: server gave HTTP response to HTTPS client`.**
Docker insists on HTTPS for every host except `localhost` and `127.0.0.1`. Use
`localhost`, serve real TLS, or add the host to Docker's `insecure-registries`
in *Docker Desktop → Settings → Docker Engine*.

**`x509: certificate signed by unknown authority`.**
You are on HTTPS with a certificate Docker does not trust. Install the CA:

```bash
sudo mkdir -p /etc/docker/certs.d/registry.example.com
sudo cp ca.crt /etc/docker/certs.d/registry.example.com/ca.crt
```

On Docker Desktop, add the CA to the macOS keychain and restart Docker.

**`denied: insufficient permission for push on repository`.**
The token's `repo_pattern` does not cover that repository. `demo/*` matches
`demo/hello-app` but not `other/app`. Check under **API Tokens**.

**`unauthorized` after it worked yesterday.**
The token expired or was revoked. Log in again with a fresh one.

**The push worked but the SBOM says "no SBOM yet".**
Generation is asynchronous — give it a few seconds and refresh. Artifacts and
manifests without a real filesystem (build attestations) are skipped by design.

**Where did my images go?**
They are in a Docker volume, not your project directory. `docker compose down`
keeps them; `docker compose down -v` **deletes them permanently**.

---

## Not using Docker?

Nothing here depends on Docker — the registry implements the OCI distribution
specification, and this guide simply picks one client to keep the walkthrough
concrete. The **web UI prints the equivalent commands for whichever client you
use**: open the overview, a repository, or the API Tokens page and choose from
the tabs above each command block.

The equivalent of "log in, tag, push" in each:

```bash
# Podman -- same verbs as Docker; add --tls-verify=false for plain HTTP
podman login localhost:5001
podman tag myapp:latest localhost:5001/demo/myapp:1.0
podman push localhost:5001/demo/myapp:1.0

# skopeo -- copies straight out of the local daemon, no tagging step
skopeo copy --dest-tls-verify=false \
  docker-daemon:myapp:latest docker://localhost:5001/demo/myapp:1.0

# crane -- also copies registry to registry without a local daemon
crane auth login localhost:5001 -u admin
crane copy --insecure alpine:3.20 localhost:5001/demo/alpine:3.20

# ORAS -- for artifacts that are not images at all
oras push --plain-http localhost:5001/demo/report:v1 ./report.json:application/json

# Helm -- OCI charts; --plain-http is needed on BOTH login and push
helm registry login localhost:5001 -u admin --plain-http
helm push mychart-0.1.0.tgz oci://localhost:5001/charts --plain-http
```

Each client has its own way of being told to accept a plain-HTTP registry, and
getting it wrong is the most common cause of a failed first push:

| Client | Plain HTTP |
| --- | --- |
| Docker | list the host under `insecure-registries` in `daemon.json`, then restart |
| Podman, skopeo, Buildah | `--tls-verify=false` |
| crane | `--insecure` |
| ORAS | `--plain-http` |
| Helm | `--plain-http` on **both** `registry login` and `push`/`pull` |

---

## Cheat sheet

```bash
# start (local, plain HTTP)
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d

# log in
echo "$PASSWORD" | docker login localhost:5001 -u admin --password-stdin

# build, tag, push
docker build -t localhost:5001/demo/myapp:1.0 .
docker push localhost:5001/demo/myapp:1.0

# what is in there
curl -s -u admin:$PASSWORD http://localhost:5001/v2/_catalog
curl -s -u admin:$PASSWORD http://localhost:5001/v2/demo/myapp/tags/list

# pull it back
docker pull localhost:5001/demo/myapp:1.0

# stop (keeps images) / stop and delete everything
docker compose -f docker-compose.yml -f docker-compose.local.yml down
docker compose -f docker-compose.yml -f docker-compose.local.yml down -v
```
