/* Container Registry management UI.
   Vanilla ES modules-free script: hash routing, fetch against /api, no build step. */

'use strict';

const state = { me: null, settings: null };

/* ----------------------------------------------------------------- helpers */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

/** Escape text for interpolation into HTML. Every dynamic value goes through this. */
function esc(v) {
  if (v === null || v === undefined) return '';
  return String(v).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

/** Escape a value for use inside a single-quoted JS string in an inline handler. */
function jsq(v) {
  return String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/</g, '\\u003c');
}

function bytes(n) {
  if (!n) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = Number(n);
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

function ago(ts) {
  if (!ts) return '—';
  const then = new Date(ts).getTime();
  if (Number.isNaN(then)) return '—';
  const diff = Math.max(0, Date.now() - then) / 1000;
  if (diff < 60) return 'just now';
  const steps = [[60, 'min'], [24, 'hr'], [30, 'day'], [12, 'mo'], [Infinity, 'yr']];
  let v = diff / 60;
  for (const [size, unit] of steps) {
    if (v < size) {
      const r = Math.floor(v);
      return `${r} ${unit}${r === 1 ? '' : 's'} ago`;
    }
    v /= size;
  }
  return '—';
}

function fullDate(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? '' : d.toLocaleString();
}

/** Render an OCI media type as a short human label. */
function mediaLabel(mt) {
  if (!mt) return '';
  if (mt.includes('image.index') || mt.includes('manifest.list')) return 'index';
  if (mt.includes('image.manifest') || mt.includes('distribution.manifest')) return 'manifest';
  if (mt.includes('image.config')) return 'config';
  const tail = mt.split('/').pop().replace(/^vnd\./, '').replace(/\+json$/, '');
  return tail.replace(/\.v\d+$/, '');
}

function shortDigest(d) {
  if (!d) return '';
  const hex = d.includes(':') ? d.split(':')[1] : d;
  return hex.slice(0, 12);
}

function toast(message, kind = 'info') {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = message;
  $('#toasts').append(el);
  setTimeout(() => {
    el.style.transition = 'opacity .25s';
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 250);
  }, kind === 'error' ? 6000 : 3200);
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast('Copied to clipboard', 'success');
  } catch {
    toast('Could not access the clipboard', 'error');
  }
}
window.copy = copy;

/* ----------------------------------------------------------------- api */

async function api(path, options = {}) {
  const res = await fetch(`/api${path}`, {
    credentials: 'same-origin',
    headers: options.body ? { 'Content-Type': 'application/json' } : {},
    ...options,
  });
  if (res.status === 401) {
    state.me = null;
    showLogin();
    throw new Error('Not signed in');
  }
  const text = await res.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch { data = { error: text }; }
  }
  if (!res.ok) throw new Error((data && data.error) || `Request failed (${res.status})`);
  return data;
}

/* ----------------------------------------------------------------- modal */

/**
 * Show a modal. `fields` renders the body; resolves with the collected values,
 * or null if dismissed.
 */
function modal({ title, bodyHTML, okLabel = 'Confirm', okClass = 'primary', onOpen, dismissOnly = false }) {
  return new Promise((resolve) => {
    const dlg = $('#modal');
    $('#modal-title').textContent = title;
    $('#modal-body').innerHTML = bodyHTML;
    const ok = $('#modal-ok');
    ok.textContent = okLabel;
    ok.className = `btn ${okClass}`;
    // An informational dialog has nothing to cancel — one dismiss button is enough.
    $('#modal-cancel').hidden = dismissOnly;
    if (onOpen) onOpen($('#modal-body'));

    const done = () => {
      dlg.removeEventListener('close', done);
      if (dlg.returnValue !== 'ok') { resolve(null); return; }
      const values = {};
      $$('[name]', $('#modal-body')).forEach((el) => {
        values[el.name] = el.type === 'checkbox' ? el.checked : el.value;
      });
      resolve(values);
    };
    dlg.addEventListener('close', done);
    dlg.showModal();
    const first = $('input, select, textarea', $('#modal-body'));
    if (first) first.focus();
  });
}

async function confirmDanger(title, message, okLabel = 'Delete') {
  const r = await modal({
    title,
    bodyHTML: `<p class="muted">${esc(message)}</p>`,
    okLabel,
    okClass: 'danger',
  });
  return r !== null;
}

/* ----------------------------------------------------------------- auth */

function showLogin() {
  $('#app').hidden = true;
  $('#login').hidden = false;
  $('#login-error').hidden = true;
  $('#login-user').focus();
}

function showApp() {
  $('#login').hidden = true;
  $('#app').hidden = false;
  $('#who-name').textContent = state.me.username;
  const role = $('#who-role');
  role.textContent = state.me.admin ? 'admin' : 'user';
  role.className = `badge ${state.me.admin ? 'accent' : ''}`;
  $$('[data-admin]').forEach((el) => { el.hidden = !state.me.admin; });
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('#login-error');
  err.hidden = true;
  try {
    state.me = await api('/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        username: $('#login-user').value.trim(),
        password: $('#login-pass').value,
      }),
    });
    $('#login-pass').value = '';
    showApp();
    route();
  } catch (ex) {
    err.textContent = ex.message;
    err.hidden = false;
  }
});

$('#btn-logout').addEventListener('click', async () => {
  try { await api('/auth/logout', { method: 'POST' }); } catch { /* already gone */ }
  state.me = null;
  showLogin();
});

$('#btn-password').addEventListener('click', async () => {
  const v = await modal({
    title: 'Change password',
    okLabel: 'Update',
    bodyHTML: `
      <div class="field"><label>Current password</label>
        <input type="password" name="current_password" autocomplete="current-password"></div>
      <div class="field"><label>New password</label>
        <input type="password" name="new_password" autocomplete="new-password">
        <span class="hint">At least 8 characters.</span></div>`,
  });
  if (!v) return;
  try {
    await api('/auth/password', { method: 'POST', body: JSON.stringify(v) });
    toast('Password updated', 'success');
  } catch (ex) { toast(ex.message, 'error'); }
});

/* ------------------------------------------------------------- client hints

Every command shown here has been run against this registry. The registry
implements the OCI distribution specification rather than anything Docker
specific, so the point of this section is that the choice of client is the
operator's -- Docker is one option among several, not the assumed one.

Each client differs in how it is told to accept a plain-HTTP registry, which is
the single most common reason a first push fails, so that note lives with the
commands rather than in a general remark. */

const CLIENTS = {
  docker: {
    name: 'Docker',
    login: (h, u) => `echo "$REGISTRY_TOKEN" | docker login ${h} -u ${u} --password-stdin`,
    push: (h, u) => `docker login ${h} -u ${u}
docker tag myapp:latest ${h}/myapp:latest
docker push ${h}/myapp:latest`,
    pull: (h, ref) => `docker pull ${h}/${ref}`,
    insecure: 'Docker refuses plain HTTP unless the registry is listed under '
      + '<code>insecure-registries</code> in <code>/etc/docker/daemon.json</code> '
      + '(Docker Desktop: Settings &rarr; Docker Engine), followed by a restart. '
      + '<code>localhost</code> is exempt.',
  },
  podman: {
    name: 'Podman',
    login: (h, u) => `echo "$REGISTRY_TOKEN" | podman login ${h} -u ${u} --password-stdin`,
    push: (h, u) => `podman login ${h} -u ${u}
podman tag myapp:latest ${h}/myapp:latest
podman push ${h}/myapp:latest`,
    pull: (h, ref) => `podman pull ${h}/${ref}`,
    insecure: 'Pass <code>--tls-verify=false</code> to every command, including '
      + '<code>login</code>. Buildah takes the same flag.',
  },
  skopeo: {
    name: 'skopeo',
    login: (h, u) => `echo "$REGISTRY_TOKEN" | skopeo login ${h} -u ${u} --password-stdin`,
    push: (h, u) => `skopeo login ${h} -u ${u}

# copy straight from the local daemon, no tag dance
skopeo copy docker-daemon:myapp:latest docker://${h}/myapp:latest`,
    pull: (h, ref) => `skopeo copy docker://${h}/${ref} docker-daemon:${ref}

# or inspect it without pulling
skopeo inspect docker://${h}/${ref}`,
    insecure: 'Pass <code>--tls-verify=false</code>. For <code>copy</code>, which '
      + 'touches two registries, the flags are <code>--src-tls-verify</code> and '
      + '<code>--dest-tls-verify</code> separately.',
  },
  crane: {
    name: 'crane',
    login: (h, u) => `crane auth login ${h} -u ${u} -p "$REGISTRY_TOKEN"`,
    push: (h, u) => `crane auth login ${h} -u ${u}

# push a tarball, or copy an image between registries
crane push myapp.tar ${h}/myapp:latest
crane copy alpine:3.20 ${h}/alpine:3.20`,
    pull: (h, ref) => `crane pull ${h}/${ref} myapp.tar

# digest and manifest without downloading layers
crane digest ${h}/${ref}`,
    insecure: 'Pass <code>--insecure</code>.',
  },
  oras: {
    name: 'ORAS',
    login: (h, u) => `echo "$REGISTRY_TOKEN" | oras login ${h} -u ${u} --password-stdin`,
    push: (h, u) => `oras login ${h} -u ${u}

# any file is a valid OCI artifact, not just images
oras push ${h}/myartifact:v1 ./report.json:application/json`,
    pull: (h, ref) => `oras pull ${h}/${ref}

# what is attached to it (SBOMs, signatures, attestations)
oras discover ${h}/${ref}`,
    insecure: 'Pass <code>--plain-http</code>.',
  },
  helm: {
    name: 'Helm',
    login: (h, u) => `echo "$REGISTRY_TOKEN" | helm registry login ${h} -u ${u} --password-stdin`,
    push: (h, u) => `helm registry login ${h} -u ${u}

helm package mychart
helm push mychart-0.1.0.tgz oci://${h}/charts`,
    pull: (h, ref, tag) => `helm pull oci://${h}/${ref.split(':')[0]} --version ${tag}`,
    insecure: 'Pass <code>--plain-http</code> to <strong>both</strong> '
      + '<code>helm registry login</code> and <code>helm push</code>/<code>pull</code>. '
      + 'Setting it on only one of them fails with '
      + '<code>basic credential not found</code>.',
  },
};

// The order clients are offered in. Image clients first; ORAS and Helm handle
// artifacts that are not images at all.
const IMAGE_CLIENTS = ['docker', 'podman', 'skopeo', 'crane', 'oras'];
const HELM_CLIENTS = ['helm', 'oras', 'skopeo', 'crane'];

// helmChartType is the config media type Helm gives its chart manifests.
const HELM_CHART_TYPE = 'application/vnd.cncf.helm.config.v1+json';

// Remember the operator's client across pages and sessions: someone using
// Podman is not going to want Docker instructions on the next page either.
function currentClient(ids) {
  const saved = localStorage.getItem('registry.client');
  return ids.includes(saved) ? saved : ids[0];
}

// blocks holds the render function for each tab strip on the page, so choosing
// a client can redraw just that block.
const clientBlocks = {};

/**
 * Render a client picker over a set of equivalent commands.
 *
 * @param {string} key    unique id for this block on the page
 * @param {string[]} ids  clients to offer, in order
 * @param {(c: object, id: string) => string} body  renders one client's commands
 */
function clientTabs(key, ids, body) {
  clientBlocks[key] = { ids, body };
  return `<div id="ct-${key}">${clientTabsInner(key)}</div>`;
}

function clientTabsInner(key) {
  const { ids, body } = clientBlocks[key];
  const active = currentClient(ids);
  const tabs = ids.map((id) => `<button class="${id === active ? 'active' : ''}"
      onclick="pickClient('${jsq(key)}','${jsq(id)}')">${esc(CLIENTS[id].name)}</button>`).join('');
  const client = CLIENTS[active];
  const insecure = location.protocol !== 'https:' && client.insecure
    ? `<p class="muted small" style="margin-top:.7rem"><strong>Plain HTTP:</strong> ${client.insecure}</p>`
    : '';
  return `<div class="tabs">${tabs}</div><pre>${esc(body(client, active))}</pre>${insecure}`;
}

window.pickClient = (key, id) => {
  localStorage.setItem('registry.client', id);
  // Every tab strip on the page follows the same choice, so the page does not
  // end up showing Podman in one card and Docker in another.
  Object.keys(clientBlocks).forEach((k) => {
    const el = document.getElementById(`ct-${k}`);
    if (el) el.innerHTML = clientTabsInner(k);
  });
};

/* ----------------------------------------------------------------- router */

const routes = {
  overview: renderOverview,
  repositories: renderRepositories,
  repo: renderRepo,
  manifest: renderManifest,
  tokens: renderTokens,
  users: renderUsers,
  audit: renderAudit,
  maintenance: renderMaintenance,
};

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '');
  if (!raw) return { name: 'overview', args: [] };
  const parts = raw.split('/').map(decodeURIComponent);
  return { name: parts[0], args: parts.slice(1) };
}

async function route() {
  if (!state.me) return;
  const { name, args } = parseHash();
  const fn = routes[name] || renderOverview;

  const navKey = { repo: 'repositories', manifest: 'repositories' }[name] || name;
  $$('#nav a').forEach((a) => a.classList.toggle('active', a.dataset.nav === navKey));

  const view = $('#view');
  view.innerHTML = '<div class="loading">Loading…</div>';
  try {
    await fn(view, args);
  } catch (ex) {
    view.innerHTML = `<div class="card"><h2>Something went wrong</h2>
      <p class="muted">${esc(ex.message)}</p></div>`;
  }
  window.scrollTo(0, 0);
}

window.addEventListener('hashchange', route);

/* ----------------------------------------------------------------- views */

function pageHead(title, subtitle, actions = '') {
  return `<div class="page-head">
    <div><h1>${esc(title)}</h1>${subtitle ? `<p class="muted">${subtitle}</p>` : ''}</div>
    <div class="row">${actions}</div>
  </div>`;
}

function tableOrEmpty(rows, headHTML, emptyMessage) {
  if (!rows || rows.length === 0) return `<div class="empty">${esc(emptyMessage)}</div>`;
  return `<div class="table-wrap"><table><thead>${headHTML}</thead>
    <tbody>${rows.join('')}</tbody></table></div>`;
}

// ---- overview

async function renderOverview(view) {
  const [stats, repoData] = await Promise.all([api('/stats'), api('/repositories')]);
  const repos = (repoData.repositories || []).slice().sort(
    (a, b) => new Date(b.updated_at) - new Date(a.updated_at)
  ).slice(0, 8);

  const host = location.host;
  const rows = repos.map((r) => `<tr>
    <td><a href="#/repo/${encodeURIComponent(r.name)}">${esc(r.name)}</a></td>
    <td class="num">${r.tag_count}</td>
    <td class="num">${esc(bytes(r.size_bytes))}</td>
    <td class="muted small" title="${esc(fullDate(r.updated_at))}">${esc(ago(r.updated_at))}</td>
  </tr>`);

  view.innerHTML = pageHead('Overview', `Registry at <code>${esc(host)}</code>`) + `
    <div class="stat-grid">
      ${stat('Repositories', stats.repositories)}
      ${stat('Tags', stats.tags)}
      ${stat('Manifests', stats.manifests)}
      ${stat('Unique blobs', stats.blobs)}
      ${stat('Storage on disk', bytes(stats.disk_bytes), `${stats.disk_blob_count} objects`)}
      ${stat('Active tokens', stats.active_tokens)}
    </div>

    <div class="card">
      <h2>Recently updated</h2>
      ${tableOrEmpty(rows,
        '<tr><th>Repository</th><th class="num">Tags</th><th class="num">Size</th><th>Updated</th></tr>',
        'No images have been pushed yet.')}
    </div>

    <div class="card">
      <h2>Push your first image</h2>
      ${clientTabs('push', IMAGE_CLIENTS, (c) => c.push(host, state.me.username))}
      <p class="muted small" style="margin-top:.7rem">
        Sign in with your username and either your password or an API token as the password.
        This registry implements the OCI distribution specification, so any conformant
        client works — these are the ones it is tested against.
      </p>
    </div>`;
}

function stat(label, value, sub = '') {
  return `<div class="stat">
    <div class="label">${esc(label)}</div>
    <div class="value">${esc(value)}</div>
    ${sub ? `<div class="sub">${esc(sub)}</div>` : ''}
  </div>`;
}

// ---- repositories

async function renderRepositories(view) {
  const data = await api('/repositories');
  const repos = data.repositories || [];

  const rows = repos.map((r) => `<tr>
    <td>
      <a href="#/repo/${encodeURIComponent(r.name)}">${esc(r.name)}</a>
      ${r.public ? '<span class="badge ok">public</span>' : ''}
      ${r.immutable ? '<span class="badge warn">immutable</span>' : ''}
      ${r.description ? `<div class="muted small">${esc(r.description)}</div>` : ''}
    </td>
    <td class="num">${r.tag_count}</td>
    <td class="num">${esc(bytes(r.size_bytes))}</td>
    <td class="muted small" title="${esc(fullDate(r.updated_at))}">${esc(ago(r.updated_at))}</td>
  </tr>`);

  view.innerHTML = pageHead('Repositories',
    `${repos.length} repositor${repos.length === 1 ? 'y' : 'ies'} visible to you`) +
    `<div class="card">
      <div class="field"><input id="repo-filter" placeholder="Filter repositories…"></div>
      ${tableOrEmpty(rows,
        '<tr><th>Name</th><th class="num">Tags</th><th class="num">Size</th><th>Updated</th></tr>',
        'No repositories yet. Push an image to create one.')}
    </div>`;

  const filter = $('#repo-filter');
  if (filter) {
    filter.addEventListener('input', () => {
      const q = filter.value.toLowerCase();
      $$('#view tbody tr').forEach((tr) => {
        tr.hidden = !tr.textContent.toLowerCase().includes(q);
      });
    });
  }
}

// ---- repository detail

const TAG_PAGE_SIZE = 25;

async function renderRepo(view, [name, offsetArg, searchArg]) {
  if (!name) { location.hash = '#/repositories'; return; }
  const offset = parseInt(offsetArg, 10) || 0;
  const search = searchArg ? decodeURIComponent(searchArg) : '';
  const data = await api(`/repositories/${encodeURI(name)}`);
  // Tags come from a paged endpoint rather than the repository payload, so a
  // repository with thousands of them does not render every row.
  const tagPage = await api(
    `/repositories/${encodeURI(name)}/tags?limit=${TAG_PAGE_SIZE}` +
    `&offset=${offset}&search=${encodeURIComponent(search)}`);
  const repo = data.repository;
  const tags = tagPage.tags || [];
  const totalTags = tagPage.total || 0;
  const untagged = data.untagged_manifests || [];
  const referrers = data.referrer_manifests || [];
  const host = location.host;
  const canWrite = state.me.admin || state.me.can_push;
  const canDelete = state.me.admin || state.me.can_delete;

  // Helm charts are pulled with helm, not docker, so offer the clients that
  // actually apply to what this repository holds.
  const isChart = (data.manifests || []).some((m) => m.artifact_type === HELM_CHART_TYPE);
  const pullTag = tags[0] ? tags[0].name : 'latest';
  const tagRows = tags.map((t) => `<tr>
    <td><strong>${esc(t.name)}</strong></td>
    <td><span class="digest" onclick="copy('${jsq(t.digest)}')"
        title="${esc(t.digest)} — click to copy">${esc(shortDigest(t.digest))}</span></td>
    <td class="num">${esc(bytes(t.size))}</td>
    <td class="muted small" title="${esc(fullDate(t.updated_at))}">${esc(ago(t.updated_at))}</td>
    <td class="actions">
      <a class="btn ghost small" href="#/manifest/${encodeURIComponent(repo.name)}/${encodeURIComponent(t.digest)}">Inspect</a>
      ${canDelete ? `<button class="btn ghost small danger"
        onclick="deleteTag('${jsq(repo.name)}','${jsq(t.name)}')">Delete</button>` : ''}
    </td>
  </tr>`);

  const untaggedRows = untagged.map((m) => `<tr>
    <td><span class="digest" onclick="copy('${jsq(m.digest)}')"
        title="${esc(m.digest)}">${esc(shortDigest(m.digest))}</span></td>
    <td class="muted small">${esc(mediaLabel(m.media_type))}</td>
    <td class="num">${esc(bytes(m.size))}</td>
    <td class="muted small" title="${esc(fullDate(m.created_at))}">${esc(ago(m.created_at))}</td>
    <td class="actions">
      <a class="btn ghost small" href="#/manifest/${encodeURIComponent(repo.name)}/${encodeURIComponent(m.digest)}">Inspect</a>
    </td>
  </tr>`);

  view.innerHTML = `
    <div class="crumbs"><a href="#/repositories">Repositories</a> / ${esc(repo.name)}</div>
    ${pageHead(repo.name, repo.description ? esc(repo.description) : 'No description',
      `${canWrite ? `<button class="btn" onclick="createTag('${jsq(repo.name)}')">New tag</button>` : ''}
       ${canWrite ? `<button class="btn ghost" onclick="editRepo('${jsq(repo.name)}')">Settings</button>` : ''}
       ${canDelete ? `<button class="btn danger" onclick="deleteRepo('${jsq(repo.name)}')">Delete</button>` : ''}`)}

    <div class="stat-grid">
      ${stat('Tags', tags.length)}
      ${stat('Manifests', (data.manifests || []).length)}
      ${stat('Untagged', untagged.length, 'reclaimable by GC')}
      ${stat('Attached artifacts', referrers.length, 'SBOMs, signatures')}
      ${stat('Visibility', repo.public ? 'Public' : 'Private')}
      ${stat('Storage', bytes(data.used_bytes || 0),
        repo.quota_bytes ? `of ${bytes(repo.quota_bytes)} quota` : 'no quota')}
    </div>

    <div class="card">
      <h2>Tags <span class="badge">${totalTags}</span></h2>
      <div class="field"><input id="tag-search" placeholder="Filter tags…" value="${esc(search)}"></div>
      ${tableOrEmpty(tagRows,
        `<tr><th>Tag</th><th>Digest</th><th class="num">Size</th><th>Updated</th><th></th></tr>`,
        search ? 'No tags match that filter.' : 'No tags in this repository.')}
      ${totalTags > TAG_PAGE_SIZE ? `<div class="row" style="margin-top:.8rem;justify-content:space-between">
        <span class="muted small">${offset + 1}–${Math.min(offset + TAG_PAGE_SIZE, totalTags)} of ${totalTags}</span>
        <span class="row">
          <button class="btn small" ${offset === 0 ? 'disabled' : ''}
            onclick="tagPage('${jsq(repo.name)}',${Math.max(0, offset - TAG_PAGE_SIZE)},'${jsq(search)}')">Previous</button>
          <button class="btn small" ${offset + TAG_PAGE_SIZE >= totalTags ? 'disabled' : ''}
            onclick="tagPage('${jsq(repo.name)}',${offset + TAG_PAGE_SIZE},'${jsq(search)}')">Next</button>
        </span>
      </div>` : ''}
    </div>

    ${referrers.length ? `<div class="card">
      <h2>Attached artifacts</h2>
      <p class="muted small" style="margin-top:-.4rem">
        Referrers attached to images in this repository. They carry no tag by design
        and are reachable through the manifest they describe, so garbage collection
        leaves them alone.</p>
      ${tableOrEmpty(referrers.map((m) => `<tr>
        <td><span class="digest" onclick="copy('${jsq(repo.name)}')"
            title="${esc(m.digest)}">${esc(shortDigest(m.digest))}</span></td>
        <td class="muted small">${esc(m.artifact_type || mediaLabel(m.media_type))}</td>
        <td class="muted small">describes ${esc(shortDigest(m.subject))}</td>
        <td class="num">${esc(bytes(m.size))}</td>
        <td class="actions">
          <a class="btn ghost small" href="#/manifest/${encodeURIComponent(repo.name)}/${encodeURIComponent(m.digest)}">Inspect</a>
        </td>
      </tr>`), '<tr><th>Digest</th><th>Artifact type</th><th>Subject</th><th class="num">Size</th><th></th></tr>', '')}
    </div>` : ''}

    ${untagged.length ? `<div class="card">
      <h2>Untagged manifests</h2>
      <p class="muted small" style="margin-top:-.4rem">
        Nothing points at these. Garbage collection will reclaim their layers.</p>
      ${tableOrEmpty(untaggedRows,
        '<tr><th>Digest</th><th>Type</th><th class="num">Size</th><th>Pushed</th><th></th></tr>', '')}
    </div>` : ''}

    <div class="card">
      <h2>Retention <span class="badge">${(data.retention || []).length} rules</span></h2>
      <p class="muted small" style="margin-top:-.4rem">
        With no rules, nothing is ever removed automatically.</p>
      ${tableOrEmpty((data.retention || []).map((rr) => `<tr>
        <td><span class="badge ${rr.kind === 'protect' ? 'ok' : 'warn'}">${esc(rr.kind)}</span></td>
        <td class="mono small">${esc(rr.pattern)}</td>
        <td class="small">${rr.kind === 'keep_last' ? `keep ${rr.keep_count}`
            : rr.kind === 'delete_older_than' ? `older than ${esc(rr.max_age)}` : '—'}</td>
        <td>${rr.enabled ? '<span class="badge ok">on</span>' : '<span class="badge">off</span>'}</td>
        <td class="actions">${canDelete ? `<button class="btn ghost small danger"
          onclick="deleteRule('${jsq(repo.name)}',${rr.id})">Remove</button>` : ''}</td>
      </tr>`), '<tr><th>Rule</th><th>Pattern</th><th>Setting</th><th></th><th></th></tr>',
        'No retention rules — this repository keeps everything.')}
      ${canDelete ? `<div class="row" style="margin-top:.8rem">
        <button class="btn" onclick="addRule('${jsq(repo.name)}')">Add rule</button>
      </div>` : ''}
    </div>

    <div class="card">
      <h2>Pull this ${isChart ? 'chart' : 'image'}</h2>
      ${clientTabs('pull', isChart ? HELM_CLIENTS : IMAGE_CLIENTS,
        (c) => c.pull(host, `${repo.name}:${pullTag}`, pullTag))}
      ${repo.public ? `<p class="muted small" style="margin-top:.7rem">This repository is
        public, so pulling needs no credentials.</p>`
      : `<p class="muted small" style="margin-top:.7rem">This repository is private:
        log in first with the same client — the
        <a href="#/tokens">API Tokens</a> page shows the command for each.</p>`}
    </div>`;

  bindTagSearch(repo.name);
}

window.addRule = async (repo) => {
  const v = await modal({
    title: `Retention rule for ${repo}`,
    okLabel: 'Add rule',
    bodyHTML: `
      <div class="field"><label>Rule</label>
        <select name="kind">
          <option value="keep_last">Keep only the newest N tags</option>
          <option value="delete_older_than">Delete tags older than…</option>
          <option value="protect">Never delete matching tags</option>
        </select></div>
      <div class="field"><label>Tag pattern</label>
        <input name="pattern" value="*" placeholder="*">
        <span class="hint">Globs, comma-separated: <code>nightly-*, dev-*</code></span></div>
      <div class="field"><label>Keep how many</label>
        <input name="keep_count" type="number" min="1" value="10">
        <span class="hint">Used by "keep the newest N".</span></div>
      <div class="field"><label>Maximum age</label>
        <input name="max_age" placeholder="720h">
        <span class="hint">Used by "older than": a duration such as <code>720h</code>.</span></div>`,
  });
  if (!v) return;
  try {
    await api(`/repositories/${encodeURI(repo)}/retention`, {
      method: 'POST',
      body: JSON.stringify({
        kind: v.kind, pattern: v.pattern,
        keep_count: parseInt(v.keep_count, 10) || 0,
        max_age: v.max_age,
      }),
    });
    toast('Rule added', 'success');
    route();
  } catch (ex) { toast(ex.message, 'error'); }
};

window.deleteRule = async (repo, id) => {
  if (!await confirmDanger('Remove rule', 'Remove this retention rule?', 'Remove')) return;
  try {
    await api(`/repositories/${encodeURI(repo)}/retention/${id}`, { method: 'DELETE' });
    toast('Rule removed', 'success');
    route();
  } catch (ex) { toast(ex.message, 'error'); }
};

window.tagPage = (repo, offset, search) => {
  location.hash = `#/repo/${encodeURIComponent(repo)}/${offset}/${encodeURIComponent(search || '')}`;
};

window.deleteTag = async (repo, tag) => {
  if (!await confirmDanger('Delete tag', `Delete tag "${tag}" from ${repo}? The manifest stays until garbage collection runs.`)) return;
  try {
    await api(`/repositories/${encodeURI(repo)}/tags/${encodeURIComponent(tag)}`, { method: 'DELETE' });
    toast(`Deleted tag ${tag}`, 'success');
    route();
  } catch (ex) { toast(ex.message, 'error'); }
};

// Bind the tag filter after each repository render.
function bindTagSearch(repoName) {
  const box = document.getElementById('tag-search');
  if (!box) return;
  box.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') window.tagPage(repoName, 0, box.value.trim());
  });
}

window.deleteRepo = async (repo) => {
  if (!await confirmDanger('Delete repository',
    `Delete "${repo}" and all of its tags and manifests? Layer data is freed on the next garbage collection.`)) return;
  try {
    await api(`/repositories/${encodeURI(repo)}`, { method: 'DELETE' });
    toast(`Deleted ${repo}`, 'success');
    location.hash = '#/repositories';
  } catch (ex) { toast(ex.message, 'error'); }
};

window.createTag = async (repo) => {
  const v = await modal({
    title: `New tag in ${repo}`,
    okLabel: 'Create tag',
    bodyHTML: `
      <div class="field"><label>New tag name</label>
        <input name="tag" placeholder="v1.2.3"></div>
      <div class="field"><label>Points at</label>
        <input name="target" placeholder="latest, or sha256:…">
        <span class="hint">An existing tag in this repository, or a manifest digest.</span></div>`,
  });
  if (!v) return;
  try {
    await api(`/repositories/${encodeURI(repo)}/tags`, { method: 'POST', body: JSON.stringify(v) });
    toast(`Created tag ${v.tag}`, 'success');
    route();
  } catch (ex) { toast(ex.message, 'error'); }
};

window.editRepo = async (repo) => {
  const data = await api(`/repositories/${encodeURI(repo)}`);
  const r = data.repository;
  const v = await modal({
    title: `${repo} settings`,
    okLabel: 'Save',
    bodyHTML: `
      <div class="field"><label>Description</label>
        <textarea name="description">${esc(r.description)}</textarea></div>
      <label class="check"><input type="checkbox" name="public" ${r.public ? 'checked' : ''}>
        Public — any authenticated user can pull</label>
      <label class="check" style="margin-top:.5rem">
        <input type="checkbox" name="immutable" ${r.immutable ? 'checked' : ''}>
        Immutable — existing tags cannot be moved to a different image</label>
      ${state.me.admin ? `<div class="field" style="margin-top:.8rem">
        <label>Storage quota (MB)</label>
        <input name="quota_mb" type="number" min="0"
          value="${r.quota_bytes ? Math.round(r.quota_bytes / 1048576) : 0}">
        <span class="hint">0 means unlimited. A push that would exceed it is refused.</span>
      </div>` : ''}`,
  });
  if (!v) return;
  try {
    await api(`/repositories/${encodeURI(repo)}`, {
      method: 'PATCH',
      body: JSON.stringify({
        description: v.description,
        public: !!v.public,
        immutable: !!v.immutable,
        ...(v.quota_mb !== undefined
          ? { quota_bytes: (parseInt(v.quota_mb, 10) || 0) * 1048576 }
          : {}),
      }),
    });
    toast('Repository updated', 'success');
    route();
  } catch (ex) { toast(ex.message, 'error'); }
};

// ---- manifest detail

async function renderManifest(view, [repo, digest]) {
  const data = await api(`/repositories/${encodeURI(repo)}/manifests/${encodeURIComponent(digest)}`);
  const m = data.manifest;
  const cfg = data.config;
  const refs = data.refs || [];
  const layers = refs.filter((r) => r.kind === 'layer' || r.kind === 'foreign');
  const children = refs.filter((r) => r.kind === 'manifest');
  const canDelete = state.me.admin || state.me.can_delete;

  const layerRows = layers.map((l, i) => `<tr>
    <td class="num muted">${i + 1}</td>
    <td><span class="digest" onclick="copy('${jsq(l.digest)}')"
        title="${esc(l.digest)}">${esc(shortDigest(l.digest))}</span></td>
    <td class="num">${esc(bytes(l.size))}</td>
    <td>${l.kind === 'foreign' ? '<span class="badge">foreign</span>' : ''}</td>
  </tr>`);

  const childRows = children.map((c) => `<tr>
    <td><a href="#/manifest/${encodeURIComponent(repo)}/${encodeURIComponent(c.digest)}">${esc(shortDigest(c.digest))}</a></td>
    <td class="num">${esc(bytes(c.size))}</td>
  </tr>`);

  const historyRows = (cfg && cfg.History ? cfg.History : (cfg && cfg.history) || [])
    .map((h) => `<tr>
      <td class="muted small">${esc(ago(h.created))}</td>
      <td><code>${esc((h.created_by || h.comment || '').slice(0, 200))}</code></td>
    </tr>`);

  view.innerHTML = `
    <div class="crumbs">
      <a href="#/repositories">Repositories</a> /
      <a href="#/repo/${encodeURIComponent(repo)}">${esc(repo)}</a> / ${esc(shortDigest(digest))}
    </div>
    ${pageHead(shortDigest(digest), esc(m.media_type),
      `<button class="btn ghost" onclick="copy('${jsq(digest)}')">Copy digest</button>
       ${canDelete ? `<button class="btn danger" onclick="deleteManifest('${jsq(repo)}','${jsq(digest)}')">Delete</button>` : ''}`)}

    <div class="card">
      <h2>Details</h2>
      <dl class="kv">
        <dt>Digest</dt><dd class="mono">${esc(m.digest)}</dd>
        <dt>Media type</dt><dd class="mono">${esc(m.media_type)}</dd>
        ${m.artifact_type ? `<dt>Artifact type</dt><dd class="mono">${esc(m.artifact_type)}</dd>` : ''}
        ${m.subject ? `<dt>Subject</dt><dd class="mono">${esc(m.subject)}</dd>` : ''}
        <dt>Tags</dt><dd>${(data.tags || []).map((t) => `<span class="badge accent">${esc(t)}</span>`).join(' ') || '<span class="muted">untagged</span>'}</dd>
        <dt>Total size</dt><dd>${esc(bytes(data.total_size))}</dd>
        <dt>Pushed</dt><dd>${esc(fullDate(m.created_at))}</dd>
        ${cfg ? `<dt>Platform</dt><dd>${esc(cfg.os || '?')}/${esc(cfg.architecture || '?')}${cfg.variant ? '/' + esc(cfg.variant) : ''}</dd>` : ''}
      </dl>
    </div>

    ${cfg ? `<div class="card">
      <h2>Image configuration</h2>
      <dl class="kv">
        ${cfg.config.Entrypoint ? `<dt>Entrypoint</dt><dd class="mono">${esc(JSON.stringify(cfg.config.Entrypoint))}</dd>` : ''}
        ${cfg.config.Cmd ? `<dt>Cmd</dt><dd class="mono">${esc(JSON.stringify(cfg.config.Cmd))}</dd>` : ''}
        ${cfg.config.WorkingDir ? `<dt>Workdir</dt><dd class="mono">${esc(cfg.config.WorkingDir)}</dd>` : ''}
        ${cfg.config.User ? `<dt>User</dt><dd class="mono">${esc(cfg.config.User)}</dd>` : ''}
        ${cfg.config.ExposedPorts ? `<dt>Ports</dt><dd class="mono">${esc(Object.keys(cfg.config.ExposedPorts).join(', '))}</dd>` : ''}
        ${cfg.config.Env ? `<dt>Env</dt><dd class="mono">${esc(cfg.config.Env.join('\n'))}</dd>` : ''}
      </dl>
      ${cfg.config.Labels && Object.keys(cfg.config.Labels).length ? `
        <h3 style="margin-top:1rem">Labels</h3>
        <dl class="kv">${Object.entries(cfg.config.Labels)
          .map(([k, val]) => `<dt class="mono">${esc(k)}</dt><dd class="mono">${esc(val)}</dd>`).join('')}</dl>` : ''}
    </div>` : ''}

    ${children.length ? `<div class="card">
      <h2>Platform manifests</h2>
      ${tableOrEmpty(childRows, '<tr><th>Digest</th><th class="num">Size</th></tr>', '')}
    </div>` : ''}

    ${layers.length ? `<div class="card">
      <h2>Layers</h2>
      ${tableOrEmpty(layerRows,
        '<tr><th class="num">#</th><th>Digest</th><th class="num">Size</th><th></th></tr>', '')}
    </div>` : ''}

    ${historyRows.length ? `<div class="card">
      <h2>Build history</h2>
      ${tableOrEmpty(historyRows, '<tr><th>When</th><th>Command</th></tr>', '')}
    </div>` : ''}

    ${sbomCard(repo, digest, data.sbom)}

    <div class="card">
      <h2>Raw manifest</h2>
      <pre>${esc(JSON.stringify(data.content, null, 2))}</pre>
    </div>`;
}

/** Render the SBOM panel for a manifest, generated automatically on push. */
function sbomCard(repo, digest, sbom) {
  const href = `/api/repositories/${encodeURI(repo)}/manifests/${encodeURIComponent(digest)}/sbom`;
  if (!sbom) {
    return `<div class="card">
      <h2>Software Bill of Materials</h2>
      <p class="muted small">No SBOM yet. One is generated automatically a moment after
      an image is pushed; artifacts and indexes are not scanned.</p>
    </div>`;
  }
  return `<div class="card">
    <h2>Software Bill of Materials
      <span class="badge ok">${esc(sbom.component_count || '?')} components</span></h2>
    <dl class="kv">
      <dt>Format</dt><dd>CycloneDX 1.5</dd>
      <dt>Artifact</dt><dd><span class="digest" onclick="copy('${jsq(sbom.digest)}')"
        title="${esc(sbom.digest)}">${esc(shortDigest(sbom.digest))}</span></dd>
      ${sbom.created ? `<dt>Generated</dt><dd>${esc(fullDate(sbom.created))}</dd>` : ''}
    </dl>
    <div class="row" style="margin-top:.8rem">
      <a class="btn" href="${href}" download="sbom.cdx.json">Download SBOM</a>
      <button class="btn ghost" onclick="viewSBOM('${jsq(repo)}','${jsq(digest)}')">View components</button>
    </div>
    <p class="muted small" style="margin-top:.7rem">
      Attached to this image as an OCI referrer, so
      <code>oras discover</code> and other OCI clients find it too.</p>
  </div>`;
}

window.viewSBOM = async (repo, digest) => {
  try {
    const res = await fetch(
      `/api/repositories/${encodeURI(repo)}/manifests/${encodeURIComponent(digest)}/sbom`,
      { credentials: 'same-origin' });
    if (!res.ok) throw new Error(`Request failed (${res.status})`);
    const doc = await res.json();
    const rows = (doc.components || []).map((c) => `<tr>
      <td>${esc(c.name)}</td>
      <td class="mono small">${esc(c.version || '—')}</td>
      <td class="muted small">${esc((c.licenses || []).map((l) => l.license.name || l.license.id).join(', '))}</td>
    </tr>`);
    await modal({
      title: `${doc.components.length} components`,
      okLabel: 'Close',
      dismissOnly: true,
      bodyHTML: `<div style="max-height:60vh;overflow:auto">
        ${tableOrEmpty(rows, '<tr><th>Component</th><th>Version</th><th>License</th></tr>',
          'This image contains no detectable packages.')}
      </div>`,
    });
  } catch (ex) { toast(ex.message, 'error'); }
};

window.deleteManifest = async (repo, digest) => {
  if (!await confirmDanger('Delete manifest',
    `Delete manifest ${shortDigest(digest)} and every tag pointing at it?`)) return;
  try {
    await api(`/repositories/${encodeURI(repo)}/manifests/${encodeURIComponent(digest)}`, { method: 'DELETE' });
    toast('Manifest deleted', 'success');
    location.hash = `#/repo/${encodeURIComponent(repo)}`;
  } catch (ex) { toast(ex.message, 'error'); }
};

// ---- tokens

async function renderTokens(view) {
  const data = await api(`/tokens${state.me.admin ? '?all=true' : ''}`);
  const tokens = data.tokens || [];

  const rows = tokens.map((t) => {
    const revoked = !!t.revoked_at;
    const expired = t.expires_at && new Date(t.expires_at) < new Date();
    const status = revoked
      ? '<span class="badge danger">revoked</span>'
      : expired ? '<span class="badge warn">expired</span>' : '<span class="badge ok">active</span>';
    const perms = [
      t.can_pull ? 'pull' : null,
      t.can_push ? 'push' : null,
      t.can_delete ? 'delete' : null,
      t.is_admin ? 'admin' : null,
    ].filter(Boolean).map((p) => `<span class="badge">${p}</span>`).join(' ');

    return `<tr>
      <td><strong>${esc(t.name)}</strong>
        <div class="muted small mono">crt_${esc(t.prefix)}_…</div></td>
      ${state.me.admin ? `<td class="muted small">${esc(t.username || '')}</td>` : ''}
      <td>${perms}</td>
      <td class="mono small">${esc(t.repo_pattern)}</td>
      <td>${status}</td>
      <td class="muted small" title="${esc(fullDate(t.last_used_at))}">${esc(t.last_used_at ? ago(t.last_used_at) : 'never')}</td>
      <td class="actions">
        ${revoked ? '' : `<button class="btn ghost small" onclick="revokeToken(${t.id})">Revoke</button>`}
        <button class="btn ghost small danger" onclick="deleteToken(${t.id})">Delete</button>
      </td>
    </tr>`;
  });

  view.innerHTML = pageHead('API Tokens',
    'Tokens authenticate any OCI client and the management API.',
    '<button class="btn primary" onclick="createToken()">New token</button>') +
    `<div class="card">
      ${tableOrEmpty(rows,
        `<tr><th>Name</th>${state.me.admin ? '<th>Owner</th>' : ''}<th>Permissions</th>
         <th>Scope</th><th>Status</th><th>Last used</th><th></th></tr>`,
        'No tokens yet. Create one to push images from CI.')}
    </div>

    <div class="card">
      <h2>Using a token</h2>
      ${clientTabs('token', IMAGE_CLIENTS.concat('helm'),
        (c) => c.login(location.host, state.me.username))}
      <p class="muted small" style="margin-top:.7rem">The same token authenticates the
        management API:</p>
      <pre>curl -H "Authorization: Bearer $REGISTRY_TOKEN" \\
  ${esc(location.protocol)}//${esc(location.host)}/api/repositories</pre>
    </div>`;
}

window.createToken = async () => {
  const v = await modal({
    title: 'New API token',
    okLabel: 'Create token',
    bodyHTML: `
      <div class="field"><label>Name</label>
        <input name="name" placeholder="ci-pipeline"></div>
      <div class="field"><label>Repository scope</label>
        <input name="repo_pattern" value="*" placeholder="*">
        <span class="hint">Comma-separated globs, e.g. <code>team-a/*, shared/base</code>.</span></div>
      <div class="field"><label>Expires in (days)</label>
        <input name="expires_days" type="number" min="0" value="0">
        <span class="hint">0 means the token never expires.</span></div>
      <label class="check"><input type="checkbox" name="can_pull" checked> Pull</label>
      <label class="check"><input type="checkbox" name="can_push"> Push</label>
      <label class="check"><input type="checkbox" name="can_delete"> Delete</label>
      ${state.me.admin ? '<label class="check"><input type="checkbox" name="is_admin"> Administrator</label>' : ''}`,
  });
  if (!v) return;
  try {
    const res = await api('/tokens', {
      method: 'POST',
      body: JSON.stringify({
        name: v.name,
        repo_pattern: v.repo_pattern,
        expires_days: parseInt(v.expires_days, 10) || 0,
        can_pull: !!v.can_pull,
        can_push: !!v.can_push,
        can_delete: !!v.can_delete,
        is_admin: !!v.is_admin,
      }),
    });
    await modal({
      title: 'Token created',
      okLabel: 'Done',
      dismissOnly: true,
      bodyHTML: `<p class="muted">Copy this now — it is never shown again.</p>
        <div class="copy-row">
          <input readonly id="new-token" value="${esc(res.secret)}">
          <button type="button" class="btn" onclick="copy('${jsq(res.secret)}')">Copy</button>
        </div>`,
      onOpen: () => { const el = $('#new-token'); if (el) el.select(); },
    });
    route();
  } catch (ex) { toast(ex.message, 'error'); }
};

window.revokeToken = async (id) => {
  if (!await confirmDanger('Revoke token', 'Revoke this token? Anything using it stops working immediately.', 'Revoke')) return;
  try {
    await api(`/tokens/${id}/revoke`, { method: 'POST' });
    toast('Token revoked', 'success');
    route();
  } catch (ex) { toast(ex.message, 'error'); }
};

window.deleteToken = async (id) => {
  if (!await confirmDanger('Delete token', 'Permanently delete this token record?')) return;
  try {
    await api(`/tokens/${id}`, { method: 'DELETE' });
    toast('Token deleted', 'success');
    route();
  } catch (ex) { toast(ex.message, 'error'); }
};

// ---- users

async function renderUsers(view) {
  const data = await api('/users');
  const users = data.users || [];

  const rows = users.map((u) => `<tr>
    <td><strong>${esc(u.username)}</strong></td>
    <td>${u.role === 'admin' ? '<span class="badge accent">admin</span>' : '<span class="badge">user</span>'}</td>
    <td>${u.disabled ? '<span class="badge danger">disabled</span>' : '<span class="badge ok">active</span>'}</td>
    <td class="muted small" title="${esc(fullDate(u.last_login_at))}">${esc(u.last_login_at ? ago(u.last_login_at) : 'never')}</td>
    <td class="muted small">${esc(ago(u.created_at))}</td>
    <td class="actions">
      <button class="btn ghost small" onclick="editUser(${u.id},'${jsq(u.username)}','${jsq(u.role)}',${u.disabled})">Edit</button>
      <button class="btn ghost small danger" onclick="deleteUser(${u.id},'${jsq(u.username)}')">Delete</button>
    </td>
  </tr>`);

  view.innerHTML = pageHead('Users', 'Accounts that can sign in and own API tokens.',
    '<button class="btn primary" onclick="createUser()">New user</button>') +
    `<div class="card">
      ${tableOrEmpty(rows,
        '<tr><th>Username</th><th>Role</th><th>Status</th><th>Last login</th><th>Created</th><th></th></tr>',
        'No users.')}
    </div>`;
}

window.createUser = async () => {
  const v = await modal({
    title: 'New user',
    okLabel: 'Create user',
    bodyHTML: `
      <div class="field"><label>Username</label>
        <input name="username" placeholder="jane">
        <span class="hint">Lowercase letters, digits, <code>.</code>, <code>_</code> and <code>-</code>.</span></div>
      <div class="field"><label>Password</label>
        <input name="password" type="password" autocomplete="new-password">
        <span class="hint">At least 8 characters.</span></div>
      <div class="field"><label>Role</label>
        <select name="role"><option value="user">User</option><option value="admin">Administrator</option></select></div>`,
  });
  if (!v) return;
  try {
    await api('/users', { method: 'POST', body: JSON.stringify(v) });
    toast(`Created ${v.username}`, 'success');
    route();
  } catch (ex) { toast(ex.message, 'error'); }
};

window.editUser = async (id, username, role, disabled) => {
  const v = await modal({
    title: `Edit ${username}`,
    okLabel: 'Save',
    bodyHTML: `
      <div class="field"><label>Role</label>
        <select name="role">
          <option value="user" ${role === 'user' ? 'selected' : ''}>User</option>
          <option value="admin" ${role === 'admin' ? 'selected' : ''}>Administrator</option>
        </select></div>
      <div class="field"><label>Reset password</label>
        <input name="password" type="password" autocomplete="new-password" placeholder="leave blank to keep">
        <span class="hint">Setting a password signs the user out everywhere.</span></div>
      <label class="check"><input type="checkbox" name="disabled" ${disabled ? 'checked' : ''}>
        Disabled — cannot sign in and all their tokens stop working</label>`,
  });
  if (!v) return;
  const body = { role: v.role, disabled: !!v.disabled };
  if (v.password) body.password = v.password;
  try {
    await api(`/users/${id}`, { method: 'PATCH', body: JSON.stringify(body) });
    toast('User updated', 'success');
    route();
  } catch (ex) { toast(ex.message, 'error'); }
};

window.deleteUser = async (id, username) => {
  if (!await confirmDanger('Delete user', `Delete "${username}" and all of their API tokens?`)) return;
  try {
    await api(`/users/${id}`, { method: 'DELETE' });
    toast(`Deleted ${username}`, 'success');
    route();
  } catch (ex) { toast(ex.message, 'error'); }
};

// ---- audit

async function renderAudit(view) {
  const data = await api('/audit?limit=300');
  const entries = data.entries || [];

  const rows = entries.map((e) => `<tr>
    <td class="muted small" title="${esc(fullDate(e.ts))}">${esc(ago(e.ts))}</td>
    <td><span class="badge">${esc(e.action)}</span></td>
    <td class="small">${esc(e.actor)}</td>
    <td class="small">${e.repo ? `<a href="#/repo/${encodeURIComponent(e.repo)}">${esc(e.repo)}</a>` : ''}
      ${e.reference ? `<span class="muted">${esc(e.reference.length > 24 ? shortDigest(e.reference) : e.reference)}</span>` : ''}</td>
    <td class="muted small">${esc(e.detail || '')}</td>
    <td class="muted small mono">${esc(e.remote_ip || '')}</td>
  </tr>`);

  view.innerHTML = pageHead('Audit Log', 'Most recent 300 events.') +
    `<div class="card">
      <div class="field"><input id="audit-filter" placeholder="Filter events…"></div>
      ${tableOrEmpty(rows,
        '<tr><th>When</th><th>Action</th><th>Actor</th><th>Target</th><th>Detail</th><th>IP</th></tr>',
        'Nothing has happened yet.')}
    </div>`;

  const f = $('#audit-filter');
  if (f) {
    f.addEventListener('input', () => {
      const q = f.value.toLowerCase();
      $$('#view tbody tr').forEach((tr) => { tr.hidden = !tr.textContent.toLowerCase().includes(q); });
    });
  }
}

// ---- maintenance

async function renderMaintenance(view) {
  const [gcState, settings, stats, maint] = await Promise.all([
    api('/gc'), api('/settings'), api('/stats'), api('/maintenance'),
  ]);
  const last = gcState.last;

  const st = settings.storage || {};
  view.innerHTML = pageHead('Maintenance', 'Reclaim storage and review the running configuration.') +
    `<div class="card">
      <h2>Garbage collection</h2>
      <p class="muted small" style="margin-top:-.4rem">
        Deletes blobs no live manifest references. Blobs written in the last hour are
        skipped so an in-flight push is never broken.</p>
      <div class="row" style="margin-top:.8rem">
        <button class="btn" onclick="runGC(true)">Dry run</button>
        <button class="btn primary" onclick="runGC(false)">Run collection</button>
        ${gcState.running ? '<span class="badge warn">running</span>' : ''}
      </div>
      ${last ? `<h3 style="margin-top:1.2rem">Last run — ${esc(fullDate(last.started_at))}
          ${last.dry_run ? '<span class="badge">dry run</span>' : ''}</h3>
        <dl class="kv">
          <dt>Duration</dt><dd>${esc(last.duration)}</dd>
          <dt>Blobs scanned</dt><dd>${last.blobs_scanned}</dd>
          <dt>Blobs deleted</dt><dd>${last.blobs_deleted}</dd>
          <dt>Reclaimed</dt><dd>${esc(bytes(last.bytes_reclaimed))}</dd>
          <dt>Skipped (grace)</dt><dd>${last.blobs_skipped_grace}</dd>
          <dt>Links pruned</dt><dd>${last.links_pruned}</dd>
          <dt>Uploads purged</dt><dd>${last.uploads_purged}</dd>
          ${last.errors && last.errors.length ? `<dt>Errors</dt><dd class="mono">${esc(last.errors.join('\n'))}</dd>` : ''}
        </dl>` : '<p class="muted small">Garbage collection has not run yet.</p>'}
    </div>

    <div class="card">
      <h2>Storage
        <span class="badge ${st.is_object_store ? 'accent' : ''}">${esc(st.kind || 'filesystem')}</span></h2>
      <div class="stat-grid" style="margin:0 0 1rem">
        ${stat('Stored', bytes(stats.disk_bytes), `${stats.disk_blob_count} objects`)}
        ${stat('Referenced', bytes(stats.logical_bytes))}
        ${stat('Unique blobs', stats.blobs)}
      </div>
      <dl class="kv">
        ${st.is_object_store ? `
          <dt>Endpoint</dt><dd class="mono">${esc(st.endpoint || '')}</dd>
          <dt>Bucket</dt><dd class="mono">${esc(st.bucket || '')}</dd>
          <dt>Region</dt><dd class="mono">${esc(st.region || '')}</dd>
          ${st.prefix ? `<dt>Key prefix</dt><dd class="mono">${esc(st.prefix)}</dd>` : ''}
          <dt>Addressing</dt><dd>${st.path_style ? 'path style' : 'virtual host style'}</dd>
          <dt>Access key</dt><dd class="mono">${esc(st.access_key || '(anonymous)')}</dd>
          <dt>Upload scratch</dt><dd class="mono">${esc(st.scratch_dir || '')}</dd>
        ` : `
          <dt>Blob directory</dt><dd class="mono">${esc(st.backend || '')}</dd>
          <dt>Upload scratch</dt><dd class="mono">${esc(st.scratch_dir || '')}</dd>
        `}
      </dl>
      <div class="row" style="margin-top:.8rem">
        <button class="btn" onclick="checkStorage()">Test connection</button>
      </div>
      <p class="muted small" style="margin-top:.7rem">
        Storage is chosen at start-up from the environment
        (<code>REGISTRY_S3_BUCKET</code> and friends) and cannot be switched
        while the registry is running — blobs already written would be stranded
        in the old backend. Change the environment and restart.
      </p>
    </div>

    <div class="card">
      <h2>Scheduled maintenance</h2>
      <p class="muted small" style="margin-top:-.4rem">
        Retention decides what is no longer wanted; collection frees the space.
        They run together on a schedule so storage does not grow without bound.</p>
      <dl class="kv">
        <dt>Interval</dt><dd>${esc(maint.interval || 'disabled')}</dd>
        <dt>Recent runs</dt><dd>${(maint.runs || []).length}</dd>
      </dl>
      <div class="row" style="margin-top:.8rem">
        <button class="btn" onclick="retentionPreview()">Preview retention</button>
        <button class="btn primary" onclick="sweepNow()">Run maintenance now</button>
      </div>
      ${(maint.runs || []).length ? `<div class="table-wrap" style="margin-top:1rem">
        <table><thead><tr><th>When</th><th>Kind</th><th>Trigger</th>
          <th class="num">Tags</th><th class="num">Blobs</th><th class="num">Freed</th></tr></thead>
        <tbody>${maint.runs.slice(0, 10).map((r) => `<tr>
          <td class="muted small" title="${esc(fullDate(r.started_at))}">${esc(ago(r.started_at))}</td>
          <td><span class="badge">${esc(r.kind)}</span></td>
          <td class="muted small">${esc(r.trigger)}</td>
          <td class="num">${r.tags_deleted || ''}</td>
          <td class="num">${r.blobs_deleted || ''}</td>
          <td class="num">${r.bytes_freed ? esc(bytes(r.bytes_freed)) : ''}</td>
        </tr>`).join('')}</tbody></table></div>` : ''}
    </div>

    <div class="card">
      <h2>Configuration</h2>
      <dl class="kv">
        <dt>Listen address</dt><dd class="mono">${esc(settings.addr)}</dd>
        <dt>Auth realm</dt><dd class="mono">${esc(settings.realm)}</dd>
        <dt>TLS</dt><dd>${settings.tls ? '<span class="badge ok">enabled</span>' : '<span class="badge warn">disabled</span>'}</dd>
        <dt>Token auth</dt><dd>${settings.token_auth
          ? `<span class="badge ok">enabled</span> <span class="muted small mono">${esc(settings.token_realm || '')}</span>`
          : '<span class="badge">Basic only</span>'}</dd>
        <dt>Anonymous pull</dt><dd>${settings.anonymous_pull ? '<span class="badge warn">enabled</span>' : '<span class="badge">disabled</span>'}</dd>
        <dt>Rate limit</dt><dd>${settings.rate_limit
          ? `${settings.rate_limit}/min reads, ${settings.rate_limit_writes}/min writes, burst ${settings.rate_burst || 'default'}`
          : '<span class="badge">off</span>'}</dd>
        <dt>Max upload</dt><dd>${settings.max_upload_bytes ? esc(bytes(settings.max_upload_bytes)) : 'unlimited'}</dd>
        <dt>Session lifetime</dt><dd>${esc(settings.session_ttl)}</dd>
        <dt>SBOM generation</dt><dd>${settings.sbom_enabled ? '<span class="badge ok">on</span>' : '<span class="badge">off</span>'}</dd>
        <dt>Webhooks</dt><dd>${settings.webhooks_enabled ? '<span class="badge ok">on</span>' : '<span class="badge">off</span>'}</dd>
        <dt>Pull-through cache</dt><dd>${settings.proxy_remote
          ? `<span class="badge ok">on</span> <span class="mono small">${esc(settings.proxy_remote)}</span> under <code>${esc(settings.proxy_prefix || '')}</code>`
          : '<span class="badge">off</span>'}</dd>
        <dt>Maintenance</dt><dd>${settings.maintenance_interval && settings.maintenance_interval !== '0s'
          ? `every ${esc(settings.maintenance_interval)}` : '<span class="badge">on demand only</span>'}</dd>
        <dt>GC grace period</dt><dd>${esc(settings.gc_grace)}</dd>
        <dt>Metrics</dt><dd><code>/metrics</code>${settings.metrics_protected
          ? ' <span class="badge ok">token required</span>' : ' <span class="badge warn">unauthenticated</span>'}</dd>
      </dl>
      <p class="muted small" style="margin-top:.8rem">
        These come from environment variables and are fixed for the life of the process.</p>
    </div>`;
}

window.retentionPreview = async () => {
  try {
    const res = await api('/retention/preview', { method: 'POST' });
    const rows = (res.decisions || []).map((d) => `<tr>
      <td>${esc(d.repository)}</td>
      <td><strong>${esc(d.tag)}</strong></td>
      <td>${d.delete ? '<span class="badge danger">delete</span>'
                     : '<span class="badge ok">protected</span>'}</td>
      <td class="muted small">${esc(d.reason)}</td>
    </tr>`);
    await modal({
      title: `Retention preview — ${res.tags_deleted} of ${res.tags_examined} tags`,
      okLabel: 'Close',
      dismissOnly: true,
      bodyHTML: `<p class="muted small">Nothing has been deleted. This is what a
        sweep would do right now.</p>
        <div style="max-height:55vh;overflow:auto">
        ${tableOrEmpty(rows, '<tr><th>Repository</th><th>Tag</th><th></th><th>Reason</th></tr>',
          'No rules match anything — nothing would be removed.')}
        </div>`,
    });
  } catch (ex) { toast(ex.message, 'error'); }
};

window.sweepNow = async () => {
  if (!await confirmDanger('Run maintenance',
    'Apply retention rules and then collect unreferenced blobs? Deletions are permanent.',
    'Run')) return;
  toast('Sweeping…');
  try {
    await api('/maintenance/sweep', { method: 'POST' });
    toast('Maintenance complete', 'success');
    route();
  } catch (ex) { toast(ex.message, 'error'); }
};

window.checkStorage = async () => {
  toast('Testing the blob store…');
  try {
    const res = await api('/storage/check', { method: 'POST' });
    if (res.ok) {
      toast(`Storage is reachable and writable (${res.latency_ms} ms)`, 'success');
    } else {
      toast(`Storage check failed at ${res.stage}: ${res.error}`, 'error');
    }
  } catch (ex) { toast(ex.message, 'error'); }
};

window.runGC = async (dryRun) => {
  if (!dryRun && !await confirmDanger('Run garbage collection',
    'Permanently delete unreferenced blobs from disk?', 'Run')) return;
  toast(dryRun ? 'Running dry run…' : 'Running garbage collection…');
  try {
    const res = await api(`/gc?dry_run=${dryRun}`, { method: 'POST' });
    toast(`${dryRun ? 'Would reclaim' : 'Reclaimed'} ${bytes(res.bytes_reclaimed)} from ${res.blobs_deleted} blobs`, 'success');
    route();
  } catch (ex) { toast(ex.message, 'error'); }
};

/* ----------------------------------------------------------------- boot */

(async function boot() {
  try {
    state.me = await api('/auth/me');
    showApp();
    route();
  } catch {
    showLogin();
  }
})();
