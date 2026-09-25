// view.js — secbin public page: the landing (no composer — creating needs an
// account) and the viewer for /p/<id>#<key>. The fragment key never leaves the
// browser: it is turned into two access proofs (SPEC §5.4) which the server
// checks before releasing ciphertext or spending a view. All content is
// rendered with DOM construction only.

import './kdf-progress.js';
import { deriveAccess, openPaste, PasswordRequired, DecryptError } from './crypto.js';
import { validateHead, validatePaste } from './format.js';
import { validateManifest, buildTree, basename } from './files.js';
import { fetchHead, openShare, expireShare, fetchConfig, session, ApiError, publicProfile, publicApi, setPublicAid } from './api.js';
import { ensureTracker } from './tracker.js';
import { renderMarkdown } from './markdown.js';
import { looksLikeCode, highlightInto } from './highlight.js';
import { $, showView, toast, copyText, pill } from './ui.js';
import { h, clear, showMsg, wirePeek, armConfirm, formatCoarse, formatDuration, formatBytes, friendlyError } from './common.js';
import { describeHost, parseSecret, parseShareUrl, ShareTypeError, totpCode } from './sharetypes.js';
import { ShareReader, saveFile, saveZip, MEMORY_WARN } from './downloads.js';
import { allowedRenderer, renderPreview } from './viewer.js';

let timer = null;
let totpTimer = null;

// ── boot ─────────────────────────────────────────────────────────────────────
const route = location.pathname.match(/^\/p\/([^/]+)\/?$/);
if (route) {
  let id = null;
  try { id = decodeURIComponent(route[1]); } catch { /* malformed */ }
  if (id === null) status('This link is malformed — check that it was copied completely.', true);
  else initView(id);
} else {
  initLanding();
}

// ── landing ──────────────────────────────────────────────────────────────────
async function initLanding() {
  showView('landing');
  const btn = $('#auth-link');
  let signedIn = false;
  try {
    const s = await session();
    if (s.authenticated) {
      signedIn = true;
      btn.textContent = 'Dashboard';
      btn.href = '/dashboard/';
    }
  } catch { /* offline: keep "Log in" */ }
  btn.hidden = false;
  if (!signedIn) await initPublicComposer();
}

/**
 * Public (anonymous) sharing, when the admin enabled it: the composer runs as
 * the built-in public account. The tracker is resolved first when the counting
 * mode uses one; any refusal leaves the plain landing page with a message.
 */
async function initPublicComposer() {
  let prof;
  try { prof = await publicProfile(); } catch { return; }
  if (!prof || prof.enabled !== true) return;
  try {
    const t = await ensureTracker();
    setPublicAid(t.aid);
  } catch (e) {
    const note = h('p.msg.error', { role: 'alert', text: e instanceof ApiError ? e.message : 'Anonymous sharing is unavailable right now.' });
    $('#view-landing .stack').appendChild(note);
    return;
  }
  const n = $('#public-notice');
  if (prof.notice) { n.textContent = prof.notice; n.hidden = false; }
  const { startComposer } = await import('./composer.js');
  startComposer(prof, publicApi, { publicMode: true });
}

// ── viewer ───────────────────────────────────────────────────────────────────
async function initView(id) {
  const newlink = $('#newlink');
  if (newlink) newlink.hidden = false;
  const fragment = location.hash.slice(1);
  if (!fragment) return status('This link is missing its decryption key.', true);
  const kind = id[0] === 'f' ? 'file' : 'paste';

  status('checking…');
  let head;
  try {
    head = validateHead(await fetchHead(kind, id));
  } catch (e) {
    if (e instanceof ApiError || e.name === 'TypeError') return readError(e);
    return status('This link was made by an older or incompatible version and can no longer be opened.', true);
  }
  if ((head.adata.fmt === 'files') !== (kind === 'file')) return status('This link is malformed.', true);

  const limited = head.adata.bar && head.meta.left !== null;
  const needsPassword = head.adata.kdf === 'argon2id-hkdf';
  const open = (password) => doOpen({ id, kind, head, fragment, password });

  if (needsPassword) return passwordScreen(head, limited, open);
  if (limited) {
    const left = head.meta.left ?? 1;
    const total = head.meta.views ?? 1;
    const what = kind === 'file' ? 'These files' : ({ url: 'This link', secret: 'This credential' })[head.adata.fmt] || 'This note';
    status(total === 1
      ? `${what} can only be opened once.`
      : left === 1 ? `This is the last remaining view (${total} in total). Opening it deletes the share.` : `${left} views left. Opening uses one.`,
    false, { reveal: true, revealLabel: kind === 'file' ? 'Open files' : ({ url: 'Reveal link', secret: 'Reveal credential' })[head.adata.fmt] || 'Reveal note' });
    const btn = $('#reveal-burn');
    btn.disabled = false;
    startExpiryTimer(head.meta, () => { btn.disabled = true; status('This share has expired — it can no longer be opened.', true); });
    btn.onclick = async () => {
      btn.disabled = true;
      $('#status-actions').hidden = true;
      try { await open(''); } catch (e) { openError(e); }
    };
    return;
  }
  try { await open(''); } catch (e) { openError(e); }
}

/** Derive proofs, open (spends a view if limited), decrypt and render. */
async function doOpen({ id, kind, head, fragment, password }) {
  if (!password) status('decrypting…');
  const access = await deriveAccess({ adata: head.adata, fragment, password });
  const res = await openShare(kind, id, access);
  if (head.adata.bar && location.hash) history.replaceState(null, '', location.pathname + location.search);
  const del = { kind, id, access };
  if (kind === 'paste') {
    const paste = validatePaste(res);
    renderNote(paste, await openPaste({ paste, access }));
    wireDeleteNow($('#paste-delete'), paste.meta, del, $('#paste-msg'));
    return;
  }
  const paste = validatePaste(res.paste);
  const { text } = await openPaste({ paste, access });
  let manifest;
  try { manifest = validateManifest(JSON.parse(text)); } catch { throw new DecryptError('malformed manifest'); }
  let viewerCfg = null;
  try { viewerCfg = (await fetchConfig()).viewer; } catch { /* viewing just stays off */ }
  const reader = await ShareReader.create({ id, grant: res.grant, chunks: res.chunks, manifest });
  renderFiles(paste, manifest, reader, viewerCfg, res.grantExpires);
  $('#files-delete-row').hidden = !canDeleteNow(paste.meta);
  wireDeleteNow($('#files-delete'), paste.meta, del, $('#files-msg'));
}

// ── "delete now" (the sender allowed recipients to delete) ───────────────────
const canDeleteNow = (meta) => meta.deletable === true && meta.left !== 0;

function wireDeleteNow(btn, meta, { kind, id, access }, msgEl) {
  btn.hidden = !canDeleteNow(meta);
  if (btn.hidden) return;
  btn.disabled = false;
  btn.textContent = 'Delete now';
  armConfirm(btn, 'Delete for everyone — irreversible?', async () => {
    btn.disabled = true;
    try {
      await expireShare(kind, id, access);
      stopTotp();
      clearInterval(timer);
      status('Deleted. This link no longer works for anyone.');
    } catch (e) {
      btn.disabled = false;
      showMsg(msgEl, e instanceof ApiError && e.status === 423 ? 'The administrator has locked this share; it cannot be deleted.' : friendlyError(e));
    }
  });
}

function openError(e) {
  if (e instanceof ApiError && e.code === 'bad_link') return status('This link is incomplete or corrupted. The share was not opened and still exists.', true);
  if (e instanceof ApiError || (e && e.name === 'TypeError')) return readError(e);
  if (e instanceof DecryptError) return status('Could not decrypt this share. The link may be corrupted or altered.', true);
  return status(friendlyError(e), true);
}

function readError(e) {
  if (!(e instanceof ApiError)) return status('Could not reach the server — check your connection and try again.', true);
  if (e.status === 429) return status('Too many invalid attempts from your network. Try again later.', true);
  if (e.status === 410 || e.status === 404) return status('This share has expired, has no views left, or never existed.', true);
  return status(friendlyError(e), true);
}

function passwordScreen(head, limited, open) {
  showView('password');
  wirePeek(['#decrypt-password', '#peek2']);
  $('#password-subtitle').textContent = limited
    ? 'This share is password-protected. A view is used only once the correct password unlocks it.'
    : 'This share is protected by a password in addition to the key in the link.';
  const input = $('#decrypt-password');
  const btn = $('#decrypt-btn');
  const msg = $('#password-msg');
  input.value = '';
  input.focus();
  let inFlight = false;
  const submit = async () => {
    if (inFlight) return;
    inFlight = true;
    msg.hidden = true;
    btn.disabled = true;
    const label = btn.textContent;
    btn.textContent = 'Unlocking…';
    try {
      await open(input.value);
      input.value = '';
    } catch (e) {
      inFlight = false;
      btn.disabled = false;
      btn.textContent = label;
      if (e instanceof PasswordRequired) { showMsg(msg, 'Please enter the password.'); input.focus(); return; }
      if (e instanceof ApiError && e.code === 'bad_password') { showMsg(msg, 'Wrong password — try again.'); input.select(); return; }
      openError(e);
    }
  };
  btn.onclick = submit;
  input.onkeydown = (e) => { if (e.key === 'Enter') submit(); };
}

// ── note rendering ───────────────────────────────────────────────────────────
function lifetimePills(pills, meta, bar) {
  let exists = true;
  if (bar) {
    const left = meta.left;
    if (left === 0) { exists = false; pills.appendChild(pill('last view · now deleted', 'bad')); }
    else if (left === null || left === undefined) pills.appendChild(pill('unlimited views'));
    else pills.appendChild(pill(`${left} ${left === 1 ? 'view' : 'views'} left`, 'warn'));
  } else {
    pills.appendChild(pill('unlimited views'));
  }
  if (exists && meta.expires) {
    const leftS = meta.expires - Math.floor(Date.now() / 1000);
    if (leftS > 0) pills.appendChild(pill(`deletes in ${formatCoarse(leftS)}`));
  }
}

function renderNote(paste, result) {
  showView('paste');
  stopTotp();
  $('#paste-msg').hidden = true;
  if (result.fmt === 'url' || result.fmt === 'secret') {
    const pills = clear($('#paste-pills'));
    pills.appendChild(pill(result.fmt === 'url' ? 'link' : 'credential'));
    lifetimePills(pills, paste.meta, result.bar);
    $('#toggle-raw').hidden = true;
    const container = clear($('#paste-content'));
    try {
      container.appendChild(result.fmt === 'url' ? linkCard(result.text) : secretCard(result.text));
      $('#copy-content').hidden = true;
      return;
    } catch (e) {
      if (!(e instanceof ShareTypeError)) throw e;
      // Malformed typed payload: show it inertly as plain text, never as a link.
      container.appendChild(h('p.msg.error', { text: `${e.message} It is shown as plain text below.` }));
      container.appendChild(h('pre.code', { text: result.text }));
      $('#copy-content').hidden = false;
      $('#copy-content').onclick = async () => { toast((await copyText(result.text)) ? 'copied to clipboard' : 'copy failed'); };
      return;
    }
  }
  $('#copy-content').hidden = false;
  const isMarkdown = result.fmt === 'markdown';
  const isCode = result.fmt === 'code' || (result.fmt === 'plaintext' && looksLikeCode(result.text));
  const pills = clear($('#paste-pills'));
  if (isMarkdown) pills.appendChild(pill('markdown'));
  else if (isCode) pills.appendChild(pill('code'));
  lifetimePills(pills, paste.meta, result.bar);

  const container = $('#paste-content');
  let raw = false;
  const draw = () => {
    clear(container);
    if (isMarkdown && !raw) {
      const div = h('div.md');
      renderMarkdown(div, result.text);
      container.appendChild(div);
      return;
    }
    const pre = h('pre.code');
    if (isCode) { const code = h('code'); highlightInto(code, result.text); pre.appendChild(code); } else pre.textContent = result.text;
    container.appendChild(pre);
  };
  draw();
  const rawBtn = $('#toggle-raw');
  rawBtn.hidden = !isMarkdown;
  rawBtn.textContent = 'Raw';
  rawBtn.onclick = () => { raw = !raw; rawBtn.textContent = raw ? 'Rendered' : 'Raw'; draw(); };
  $('#copy-content').onclick = async () => { toast((await copyText(result.text)) ? 'copied to clipboard' : 'copy failed'); };
}

// ── link & credential cards ─────────────────────────────────────────────────
function stopTotp() { clearInterval(totpTimer); totpTimer = null; }

/**
 * A shared link: never followed automatically. The real destination (the host
 * as the browser resolves it) is shown first; opening needs a second, explicit
 * click and uses noopener/noreferrer so the destination learns nothing of this
 * page, the share id or its key.
 */
function linkCard(text) {
  const u = parseShareUrl(text);
  const d = describeHost(u);
  const warn = [];
  // <bdi> isolates the Unicode form so right-to-left labels cannot reorder the sentence.
  if (d.idn) warn.push(['This address uses international characters and is displayed as “', h('bdi', { dir: 'ltr', text: d.unicode }), '”. Such names can imitate a well-known site — check the real address above.']);
  if (d.insecure) warn.push(['This link is not HTTPS: the connection to it is not encrypted.']);
  const open = h('button.send', { type: 'button' }, h('span.send-txt', { text: 'Open link' }));
  armConfirm(open, `Open ${d.ascii}?`, () => window.open(u.href, '_blank', 'noopener,noreferrer'));
  const copy = h('button.btn', { type: 'button', text: 'Copy link', on: { click: async () => toast((await copyText(u.href)) ? 'link copied' : 'copy failed') } });
  return h('div.link-card', {},
    h('p.field-label', { text: 'This share is a link to' }),
    h('p.link-host', { text: d.ascii }),
    h('p.link-full', { text: u.href }),
    ...warn.map((w) => h('p.type-hint.warn', { role: 'note' }, ...w)),
    h('div.btn-row', {}, open, copy));
}

const SECRET_LABELS = [['title', 'Title', false], ['username', 'User name', false], ['password', 'Password', true], ['url', 'Sign-in URL', false], ['totp', 'One-time-code seed', true], ['notes', 'Notes', false]];

/** A credential: each field with copy; the password and seed masked until revealed; a live one-time code. */
function secretCard(text) {
  const sec = parseSecret(text);
  const card = h('div.secret-card');
  for (const [key, label, masked] of SECRET_LABELS) {
    if (sec[key] === undefined) continue;
    const val = h('span.secret-val', { text: masked ? '••••••••' : sec[key] });
    if (masked) val.classList.add('masked');
    const btns = h('div.btn-row');
    if (masked) {
      const reveal = h('button.btn', { type: 'button', text: 'Reveal', 'aria-pressed': 'false', 'aria-label': `Reveal ${label.toLowerCase()}` });
      reveal.onclick = () => {
        const show = reveal.getAttribute('aria-pressed') !== 'true';
        val.textContent = show ? sec[key] : '••••••••';
        val.classList.toggle('masked', !show);
        reveal.textContent = show ? 'Hide' : 'Reveal';
        reveal.setAttribute('aria-pressed', String(show));
      };
      btns.appendChild(reveal);
    }
    btns.appendChild(h('button.btn', { type: 'button', text: 'Copy', 'aria-label': `Copy ${label.toLowerCase()}`, on: { click: async () => toast((await copyText(sec[key])) ? `${label.toLowerCase()} copied` : 'copy failed') } }));
    card.appendChild(h('div.secret-row', {}, h('span.field-label', { text: label }), val, btns));
  }
  if (sec.totp !== undefined) {
    const code = h('span.totp-code', { text: '······' });
    const left = h('span.mono.muted', { 'aria-live': 'off' });
    let current = '';
    const copy = h('button.btn', { type: 'button', text: 'Copy code', on: { click: async () => { if (current) toast((await copyText(current)) ? 'code copied' : 'copy failed'); } } });
    const tick = async () => {
      try {
        const r = await totpCode(sec.totp);
        current = r.code;
        code.textContent = r.code;
        left.textContent = `changes in ${r.remaining}s`;
      } catch (e) {
        stopTotp();
        code.textContent = '—';
        left.textContent = e instanceof ShareTypeError ? e.message : 'The one-time code could not be computed.';
      }
    };
    tick();
    totpTimer = setInterval(tick, 1000);
    card.appendChild(h('div.secret-row', {}, h('span.field-label', { text: 'One-time code' }), h('span', {}, code, ' ', left), h('div.btn-row', {}, copy)));
  }
  return card;
}

// ── file rendering ───────────────────────────────────────────────────────────
function renderFiles(paste, manifest, reader, viewerCfg, grantExpires) {
  showView('files');
  const pills = clear($('#files-pills'));
  lifetimePills(pills, paste.meta, paste.adata.bar);
  const files = manifest.entries.filter((e) => !e.dir);
  const hasDirs = manifest.entries.some((e) => e.dir || e.path.includes('/'));
  pills.appendChild(pill(`${files.length} ${files.length === 1 ? 'file' : 'files'} · ${formatBytes(manifest.total)}`));

  const windowEl = $('#files-window');
  const tick = () => {
    const left = grantExpires * 1000 - Date.now();
    windowEl.textContent = left > 0 ? `Downloads available for ${formatDuration(left)}` : 'The download window has closed — open the link again (if views remain).';
  };
  tick();
  clearInterval(timer);
  timer = setInterval(tick, 1000);

  const progress = $('#files-progress');
  const errMsg = $('#files-msg');
  let busy = false;
  async function run(label, total, fn) {
    if (busy) return;
    busy = true;
    errMsg.hidden = true;
    let done = 0;
    progress.hidden = false;
    progress.textContent = `${label}… 0%`;
    try {
      if (total > MEMORY_WARN && typeof window.showSaveFilePicker !== 'function') toast('Large download: this browser assembles it in memory.');
      await fn((n) => { done += n; progress.textContent = `${label}… ${total ? Math.floor((done / total) * 100) : 100}%`; });
      progress.textContent = `${label} — done`;
    } catch (e) {
      progress.hidden = true;
      if (e && e.name === 'AbortError') return;
      showMsg(errMsg, e instanceof ApiError && e.code === 'bad_grant' ? 'The download window has expired — open the link again.' : friendlyError(e));
    } finally {
      busy = false;
    }
  }

  const preview = $('#files-preview');
  const previewBody = $('#preview-body');
  let previewCleanup = null;
  const closePreview = () => { if (previewCleanup) previewCleanup(); previewCleanup = null; preview.hidden = true; };
  $('#preview-close').onclick = closePreview;

  const fileButtons = (entry) => {
    const out = [h('button.btn', { type: 'button', text: 'Download', on: { click: () => run(`Downloading ${basename(entry.path)}`, entry.size, (p) => saveFile(reader, entry, p)) } })];
    const renderer = allowedRenderer(entry, manifest.view, viewerCfg);
    if (renderer) {
      out.unshift(h('button.btn', {
        type: 'button', text: 'View',
        on: {
          click: () => run(`Loading ${basename(entry.path)}`, entry.size, async (p) => {
            closePreview();
            const bytes = await reader.bytes(entry, p);
            $('#preview-title').textContent = entry.path;
            preview.hidden = false;
            try {
              previewCleanup = await renderPreview(previewBody, entry, bytes, renderer);
            } catch (e) {
              clear(previewBody).appendChild(h('p.msg.error', { text: e.message || 'This file cannot be previewed.' }));
            }
            $('#preview-download').onclick = () => run(`Downloading ${basename(entry.path)}`, entry.size, (q) => saveFile(reader, entry, q));
            preview.scrollIntoView({ block: 'nearest' });
          }),
        },
      }));
    }
    return out;
  };

  const tree = clear($('#files-tree'));
  const all = $('#download-all');
  if (!hasDirs && files.length === 1) {
    all.hidden = true;
    const f = files[0];
    tree.appendChild(h('div.file-card', {},
      h('div.file-meta', {}, h('span.file-name', { text: f.path }), h('span.file-sub.mono', { text: `${formatBytes(f.size)} · ${f.type}` })),
      h('div.btn-row', {}, ...fileButtons(f))));
    return;
  }
  all.hidden = false;
  all.onclick = () => run('Preparing ZIP', manifest.total, (p) => saveZip(reader, '', 'secbin-files.zip', p));

  const size = (node) => node.files.reduce((n, f) => n + f.size, 0) + [...node.dirs.values()].reduce((n, d) => n + size(d), 0);
  const count = (node) => node.files.length + [...node.dirs.values()].reduce((n, d) => n + count(d), 0);
  const renderNode = (node, depth) => {
    const ul = h('ul.tree-list', { role: depth === 0 ? 'tree' : 'group' });
    for (const d of [...node.dirs.values()].sort((a, b) => a.name.localeCompare(b.name))) {
      const children = renderNode(d, depth + 1);
      const toggle = h('button.tree-toggle', { type: 'button', 'aria-expanded': 'true', 'aria-label': `Collapse ${d.name}`, text: '▾' });
      toggle.onclick = () => {
        const open = toggle.getAttribute('aria-expanded') !== 'true';
        toggle.setAttribute('aria-expanded', String(open));
        toggle.textContent = open ? '▾' : '▸';
        toggle.setAttribute('aria-label', `${open ? 'Collapse' : 'Expand'} ${d.name}`);
        children.hidden = !open;
      };
      ul.appendChild(h('li.tree-dir', { role: 'treeitem' },
        h('div.tree-row', {}, toggle, h('span.tree-name', { text: `${d.name}/` }), h('span.tree-sub.mono', { text: `${count(d)} · ${formatBytes(size(d))}` }),
          h('button.btn.tree-btn', { type: 'button', text: 'Download (.zip)', on: { click: () => run(`Preparing ${d.name}.zip`, size(d), (p) => saveZip(reader, d.path, `${d.name}.zip`, p)) } })),
        children));
    }
    for (const f of [...node.files].sort((a, b) => a.path.localeCompare(b.path))) {
      ul.appendChild(h('li.tree-file', { role: 'treeitem' },
        h('div.tree-row', {}, h('span.tree-spacer'), h('span.tree-name', { text: basename(f.path) }), h('span.tree-sub.mono', { text: formatBytes(f.size) }),
          h('span.tree-actions', {}, ...fileButtons(f).map((b) => { b.classList.add('tree-btn'); return b; })))));
    }
    return ul;
  };
  tree.appendChild(renderNode(buildTree(manifest.entries), 0));
}

// ── status + countdown ───────────────────────────────────────────────────────
function status(message, isError = false, { reveal = false, revealLabel = 'Reveal note' } = {}) {
  showView('status');
  stopExpiryTimer();
  const el = $('#status-msg');
  el.textContent = message;
  el.classList.toggle('error', isError);
  $('#status-ico').hidden = !isError;
  $('#status-actions').hidden = !reveal;
  if (reveal) $('#reveal-burn').textContent = revealLabel;
  $('#status-new').hidden = !isError;
}

function stopExpiryTimer() {
  if (timer !== null) { clearInterval(timer); timer = null; }
  const box = $('#status-timer');
  if (box) { box.hidden = true; box.classList.remove('ending'); }
}

function startExpiryTimer(meta, onExpire) {
  const box = $('#status-timer');
  const clock = $('#status-timer-clock');
  if (!box || !clock || !meta.expires) return;
  const at = meta.expires * 1000;
  const render = () => {
    const left = Math.max(0, at - Date.now());
    clock.textContent = formatDuration(left);
    box.classList.toggle('ending', left > 0 && left <= 600000);
    if (left <= 0) { stopExpiryTimer(); onExpire(); }
  };
  box.hidden = false;
  render();
  if (at > Date.now()) timer = setInterval(render, 1000);
}
