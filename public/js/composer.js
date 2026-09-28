// composer.js — the share composer, used by the dashboard (an account) and by
// the landing page (the built-in public account, when public access is on):
// encrypted notes and encrypted file/folder shares. Everything is encrypted here before any byte leaves the browser —
// note text, file contents, and the manifest (names, folders, MIME types,
// sizes). The key goes into the link's #fragment; the server gets ciphertext.
// Link ("url") and credential ("secret") shares are notes with a typed,
// validated payload (public/js/sharetypes.js); the server sees only the type.

import { encryptPaste } from './crypto.js';
import { ApiError } from './api.js';
import { expireSeconds, MAX_VIEWS } from './format.js';
import { layout, buildManifest, importFileKey, encryptChunk, readStreamChunk, checkPath, checkMime, buildTree, basename, cleanName } from './files.js';
import { detectMime, normalizeMime, COMMON_TYPES } from './mime.js';
import { $, showView, toast, copyText, flashCopied, tablistKeys } from './ui.js';
import { h, clear, showMsg, markInvalid, armConfirm, wirePeek, formatBytes, friendlyError, reducedMotion, wait, unencryptedHint, nameEl } from './common.js';
import { walkEntry } from './walk.js';
import { folderBrowser } from './tree.js';
import { buildSecret, describeHost, describeUrlRules, parseShareUrl, urlRulesOf, ShareTypeError } from './sharetypes.js';
import { declare, describeType, fileExt, refusedTypes, uncheckableExt } from './filepolicy.js';
import { captchaChoice, captchaHint, captchaValue } from './captcha.js';

const UNIT_WORDS = { m: ['minute', 'minutes'], h: ['hour', 'hours'], d: ['day', 'days'] };
const ARROW_LEAD_MS = 150;
const VIEW_EXIT_MS = 170;

let profile = null;
// { createNote, initFileShare, uploadChunk, finalizeFileShare, deleteShare } — the
// account API (api.js) or the public one (api.js publicApi).
let api = null;
let publicMode = false;
let captcha = { show: false };
let mode = 'note';
const MODES = ['note', 'url', 'secret', 'files'];
const SECRET_INPUTS = { title: '#sec-title', username: '#sec-username', password: '#sec-password', url: '#sec-url', totp: '#sec-totp', notes: '#sec-notes' };
const items = new Map(); // path → { path, file, size, type, mtime } | { path, dir: true }
let syncTabs = () => {};

/**
 * Start the composer on this page. `profile` has the shape of /api/private/me
 * (limits, caps, viewer); `opts.publicMode` adapts it for anonymous use: no
 * labels (there is no "my shares"), and the delete token is shown to keep.
 */
export function startComposer(p, a, opts = {}) {
  profile = p;
  api = a;
  publicMode = !!opts.publicMode;
  init();
}

function init() {
  const L = profile.limits;
  // The label is the one plaintext field in the composer — say so right under it.
  // Anonymous shares have no "my shares" list, so no label at all.
  const labelIn = $('#share-label');
  if (publicMode) labelIn.closest('.label-row').hidden = true;
  else labelIn.after(unencryptedHint('share-label-hint', labelIn));
  showView('create');
  // Which kinds this account may create (the server enforces the same limits).
  // Links and credentials are notes with a typed payload: they need both.
  const allowed = { note: !!L.text, url: !!(L.text && L.url), secret: !!(L.text && L.secret), files: !!L.files };
  for (const m of MODES) {
    const tab = $(`#tab-${m}`);
    tab.hidden = !allowed[m];
    tab.onclick = () => setMode(m);
  }
  // Arrow keys between the kinds; the focused tab is selected at once.
  syncTabs = tablistKeys($('#tab-note').parentElement, { automatic: true });
  const first = MODES.find((m) => allowed[m]);
  if (!first) {
    showMsg($('#create-msg'), 'Your account is not allowed to create shares. Ask the administrator.');
    $('#editor-box').hidden = true;
    return;
  }
  setMode(first);
  $('#deletable-opt').hidden = !L.openerDelete;
  // The CAPTCHA, as the role says (the signed-in composer only; the server decides again).
  captcha = publicMode ? captchaChoice(null, 'share') : captchaChoice(profile, 'share');
  const capBox = $('#captcha-opt');
  if (capBox) {
    capBox.hidden = !captcha.show;
    const c = $('#captcha');
    c.checked = captcha.checked;
    c.disabled = captcha.disabled;
    const hint = $('#captcha-hint');
    hint.textContent = captchaHint(captcha, 'share');
    hint.classList.toggle('warn', !captcha.active);
  }
  wireTypedPanels();

  // Limits → control bounds (the server remains authoritative).
  const views = $('#views');
  views.max = String(L.maxViews ?? MAX_VIEWS);
  const inf = $('#views-unlimited');
  if (!L.allowUnlimitedViews) { inf.disabled = true; inf.title = 'Unlimited views are not allowed for your account'; }
  if (profile.viewer.enabled) $('#viewer-opt').hidden = false;

  let pwRequired = false;
  const lock = $('#lock');
  lock.onclick = () => {
    pwRequired = lock.classList.toggle('active');
    lock.setAttribute('aria-pressed', String(pwRequired));
  };
  wireOptions();
  wireFiles();
  const pol = policyText();
  if (pol) { const el = $('#file-policy'); el.textContent = pol; el.hidden = false; }

  const createBtn = $('#create');
  const msg = $('#create-msg');
  const requestCreate = () => {
    if (createBtn.disabled) return;
    const opts = readOptions();
    if (opts.error) { showMsg(msg, opts.error); return; }
    if (mode === 'note' && !$('#editor').value.trim()) { showMsg(msg, 'Type something first.'); $('#editor').focus(); return; }
    if (mode === 'url' || mode === 'secret') {
      const t = typedPayload();
      if (t.error) { showMsg(msg, t.error); if (t.focus) $(t.focus).focus(); return; }
      opts.typed = t;
    }
    if (mode === 'files') {
      const err = filesProblem();
      if (err) { showMsg(msg, err); return; }
    }
    msg.hidden = true;
    const go = (password) => submit(password, opts);
    if (pwRequired) openPasswordModal(go); else go('');
  };
  createBtn.addEventListener('click', requestCreate);
  $('#editor').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); requestCreate(); }
  });
}

function setMode(m) {
  mode = m;
  for (const k of MODES) {
    $(`#tab-${k}`).setAttribute('aria-selected', String(k === m));
    $(`#panel-${k}`).hidden = k !== m;
  }
  syncTabs();
  $('#create').setAttribute('aria-label', m === 'files' ? 'Encrypt, upload and create link' : 'Encrypt and create link');
}

// ── link & credential payloads ──────────────────────────────────────────────
/** The account's URL rules (the admin's; checked here — the server cannot see the link). */
const urlRules = () => urlRulesOf(profile.limits.urlRules);

function wireTypedPanels() {
  const link = $('#link-in');
  const hostHint = $('#link-host');
  const defaultHint = hostHint.textContent;
  $('#link-label').textContent = `Link to share (${describeUrlRules(urlRules())})`;
  link.addEventListener('input', () => {
    hostHint.classList.remove('warn');
    if (!link.value.trim()) { hostHint.textContent = defaultHint; link.removeAttribute('aria-invalid'); return; }
    try {
      const d = describeHost(parseShareUrl(link.value, { rules: urlRules() }));
      link.removeAttribute('aria-invalid');
      const notes = [];
      if (d.external) notes.push(d.openable ? `opens another app (${d.scheme}:)` : `a ${d.scheme}: link: recipients can copy it but not open it from the page`);
      if (d.idn) notes.push(`shown to the recipient as ${d.ascii} — international characters can imitate another site`);
      if (d.insecure) notes.push('not HTTPS');
      clear(hostHint).append('Destination: ', h('bdi', { dir: 'ltr', text: d.unicode }), notes.length ? ` (${notes.join('; ')})` : '');
      if (notes.length) hostHint.classList.add('warn');
    } catch (e) {
      link.setAttribute('aria-invalid', 'true');
      hostHint.textContent = e.message;
      hostHint.classList.add('warn');
    }
  });
  for (const btn of document.querySelectorAll('.sec-show')) {
    const input = $(`#${btn.dataset.for}`);
    btn.onclick = () => {
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.textContent = show ? 'Hide' : 'Show';
      btn.setAttribute('aria-pressed', String(show));
    };
  }
}

/** The validated plaintext + format for a link or credential share, or { error, focus }. */
function typedPayload() {
  try {
    if (mode === 'url') {
      if (!$('#link-in').value.trim()) return { error: 'Enter the link to share.', focus: '#link-in' };
      return { text: parseShareUrl($('#link-in').value, { rules: urlRules() }).href, fmt: 'url' };
    }
    const fields = {};
    for (const [k, sel] of Object.entries(SECRET_INPUTS)) fields[k] = $(sel).value;
    fields.title = fields.title.trim();
    fields.url = fields.url.trim();
    fields.totp = fields.totp.trim();
    return { text: buildSecret(fields), fmt: 'secret' };
  } catch (e) {
    if (e instanceof ShareTypeError) return { error: e.message };
    throw e;
  }
}

function clearTyped() {
  $('#link-in').value = '';
  for (const sel of Object.values(SECRET_INPUTS)) { const el = $(sel); el.value = ''; if (el.type === 'text' && el.id !== 'sec-title' && el.id !== 'sec-username') el.type = 'password'; }
  for (const btn of document.querySelectorAll('.sec-show')) { btn.textContent = 'Show'; btn.setAttribute('aria-pressed', 'false'); }
}

// ── options ──────────────────────────────────────────────────────────────────
function readOptions() {
  const L = profile.limits;
  const unlimited = $('#views-unlimited').getAttribute('aria-pressed') === 'true';
  const vRaw = $('#views').value.trim();
  const nRaw = $('#expire-n').value.trim();
  const unit = $('#expire-unit').value;
  const maxViews = L.maxViews ?? MAX_VIEWS;
  let views = null;
  if (!unlimited) {
    if (!/^[1-9][0-9]{0,5}$/.test(vRaw) || Number(vRaw) > maxViews) return { error: `Views must be a whole number from 1 to ${maxViews.toLocaleString('en-US')}${L.allowUnlimitedViews ? ', or unlimited (∞)' : ''}.` };
    views = Number(vRaw);
  } else if (!L.allowUnlimitedViews) {
    return { error: 'Unlimited views are not allowed for your account.' };
  }
  const expire = nRaw + unit;
  const sec = /^[1-9][0-9]{0,6}$/.test(nRaw) && Object.prototype.hasOwnProperty.call(UNIT_WORDS, unit) ? expireSeconds(expire) : null;
  if (sec === null) return { error: 'Expiry must be a whole number between 1 minute and 365 days.' };
  if (L.maxExpireSec !== null && sec > L.maxExpireSec) return { error: `Your account allows an expiry of at most ${Math.floor(L.maxExpireSec / 60)} minutes.` };
  const n = Number(nRaw);
  const deletable = !!L.openerDelete && $('#deletable').checked;
  return { views, expire, expiryText: `${n} ${UNIT_WORDS[unit][n === 1 ? 0 : 1]}`, label: publicMode ? '' : $('#share-label').value.trim(), deletable,
    captcha: captchaValue(captcha, $('#captcha')) };
}

function wireOptions() {
  const viewsIn = $('#views');
  const inf = $('#views-unlimited');
  inf.addEventListener('click', () => {
    if (inf.disabled) return;
    const on = inf.getAttribute('aria-pressed') !== 'true';
    inf.setAttribute('aria-pressed', String(on));
    viewsIn.disabled = on;
  });
  const refresh = () => {
    const o = readOptions();
    viewsIn.setAttribute('aria-invalid', String(!!(o.error && /Views/.test(o.error))));
    $('#expire-n').setAttribute('aria-invalid', String(!!(o.error && /xpiry/.test(o.error))));
  };
  for (const el of [viewsIn, $('#expire-n')]) el.addEventListener('input', refresh);
  $('#expire-unit').addEventListener('change', refresh);
}

// ── files: pickers, drag & drop, folders ─────────────────────────────────────
function wireFiles() {
  const fileInput = $('#file-input');
  const folderInput = $('#folder-input');
  $('#add-files').onclick = () => fileInput.click();
  $('#add-folder').onclick = () => folderInput.click();
  // Copy the FileList before clearing the input (clearing empties it in place).
  fileInput.onchange = () => { const f = [...fileInput.files]; fileInput.value = ''; addFileList(f); };
  folderInput.onchange = () => { const f = [...folderInput.files]; folderInput.value = ''; addFileList(f); };

  const dz = $('#dropzone');
  dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('over'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('over'));
  dz.addEventListener('drop', async (e) => {
    e.preventDefault();
    dz.classList.remove('over');
    await addDataTransfer(e.dataTransfer);
  });
  renderList();
}

// Names that lost hidden characters (files.js cleanName) in the last add, told once.
let renamedInAdd = 0;
function tellRenamed() {
  if (renamedInAdd) toast(`${renamedInAdd === 1 ? '1 name' : `${renamedInAdd} names`} had hidden direction or spacing characters, removed: ${renamedInAdd === 1 ? 'it was' : 'they were'} renamed.`);
  renamedInAdd = 0;
}

async function addFileList(list) {
  for (const f of list) await addFile(f.webkitRelativePath || f.name, f);
  renderList();
  tellRenamed();
}

/** Walk a drop: files and whole folders (recursively, including empty ones). */
async function addDataTransfer(dt) {
  const entries = [];
  for (const item of dt.items || []) {
    const entry = typeof item.webkitGetAsEntry === 'function' ? item.webkitGetAsEntry() : null;
    if (entry) entries.push(entry);
    else if (item.kind === 'file') { const f = item.getAsFile(); if (f) await addFile(f.name, f); }
  }
  for (const entry of entries) await walkEntry(entry, addFile, addDirectory);
  renderList();
  tellRenamed();
}

/** The path to share: cleaned of spoofing characters (counted for the note). */
function cleaned(raw) {
  const path = cleanName(raw);
  if (path !== raw) renamedInAdd++;
  return path;
}

function addDirectory(raw) {
  const path = cleaned(raw);
  try { checkPath(path); } catch (e) { toast(`Skipped "${path}": ${e.message}`); return; }
  if (!items.has(path)) items.set(path, { path, dir: true });
}

async function addFile(raw, file) {
  const path = cleaned(raw);
  try { checkPath(path); } catch (e) { toast(`Skipped "${path}": ${e.message}`); return; }
  if (items.has(path) && !items.get(path).dir) { toast(`Already added: ${path}`); return; }
  let head = null;
  try { head = new Uint8Array(await file.slice(0, 64).arrayBuffer()); } catch { /* unreadable → octet-stream */ }
  items.set(path, { path, file, size: file.size, type: detectMime({ name: file.name, platformType: file.type, head }), mtime: file.lastModified || 0 });
  // A file inside a folder makes an explicit empty-folder entry for it redundant.
  const segs = path.split('/');
  for (let i = 1; i < segs.length; i++) {
    const p = segs.slice(0, i).join('/');
    if (items.has(p) && items.get(p).dir) items.delete(p);
  }
}

function removePrefix(prefix, rerender = true) {
  for (const k of [...items.keys()]) if (k === prefix || k.startsWith(prefix + '/')) items.delete(k);
  if (rerender) renderList();
}

function filesAndDirs() {
  const files = [...items.values()].filter((i) => !i.dir).sort((a, b) => a.path.localeCompare(b.path));
  const dirs = [...items.values()].filter((i) => i.dir).map((i) => i.path).sort();
  return { files, dirs };
}

function filesProblem() {
  const { files, dirs } = filesAndDirs();
  const L = profile.limits;
  if (!files.length && !dirs.length) return 'Add at least one file or folder.';
  const total = files.reduce((n, f) => n + f.size, 0);
  if (total > profile.caps.maxShareBytes) return `The share is ${formatBytes(total)}; your limit is ${formatBytes(profile.caps.maxShareBytes)}.`;
  if (L.maxFilesPerShare !== null && files.length > L.maxFilesPerShare) return `At most ${L.maxFilesPerShare} files per share.`;
  if (L.maxFileBytes !== null) {
    const big = files.find((f) => f.size > L.maxFileBytes);
    if (big) return `"${big.path}" is larger than your per-file limit of ${formatBytes(L.maxFileBytes)}.`;
  }
  for (const f of files) {
    try { checkMime(f.type); } catch { return `"${f.path}" has an invalid type — use the form type/subtype.`; }
  }
  const policy = policyProblem(files, dirs);
  if (policy) return policy;
  try { layout(files, dirs); } catch (e) { return e.message; }
  return null;
}

// ── file policy (set by the administrator) ───────────────────────────────────
const typePolicy = () => ['allow', 'block'].includes(profile.limits.fileTypeMode);
const depthPolicy = () => Number.isInteger(profile.limits.maxFolderDepth);

/** The administrator's file-type / folder-depth policy, checked before anything is encrypted. */
function policyProblem(files, dirs) {
  const L = profile.limits;
  const { types, depth } = declare([...files, ...dirs.map((d) => ({ path: d, dir: true }))]);
  if (depthPolicy() && depth > L.maxFolderDepth) {
    return `Folders may nest at most ${L.maxFolderDepth} level${L.maxFolderDepth === 1 ? '' : 's'} deep for your account; this share has ${depth}.`;
  }
  if (typePolicy()) {
    const odd = files.filter((f) => uncheckableExt(f.path));
    if (odd.length) return `"${odd[0].path}" has an unusual extension that cannot be checked against your administrator's file-type policy. Rename it or leave it out.`;
    const refused = refusedTypes(L.fileTypeMode, L.fileTypeRules, types);
    if (refused.length) {
      const bad = files.filter((f) => refused.some((t) => t.ext === fileExt(f.path) && t.mime === String(f.type).toLowerCase()));
      const names = bad.slice(0, 3).map((f) => `"${f.path}"`).join(', ') + (bad.length > 3 ? ` and ${bad.length - 3} more` : '');
      return `Your administrator does not allow ${refused.map(describeType).join(', ')} files: ${names}. Remove ${bad.length === 1 ? 'it' : 'them'} or change the type.`;
    }
  }
  return null;
}

/** A one-line description of the policy under the drop zone (empty when none applies). */
function policyText() {
  const L = profile.limits;
  const parts = [];
  if (typePolicy()) {
    const rules = L.fileTypeRules.map((r) => r.replace(/^ext:/, '.').replace(/^mime:/, '')).join(', ');
    parts.push(L.fileTypeMode === 'allow' ? `Allowed file types: ${rules || 'none'}.` : `Blocked file types: ${rules}.`);
  }
  if (depthPolicy()) parts.push(`Folders may nest at most ${L.maxFolderDepth} level${L.maxFolderDepth === 1 ? '' : 's'} deep.`);
  if (parts.length) parts.push('File types are declared to the server for this check; names stay encrypted.');
  return parts.join(' ');
}

// The file list's folder browser (tree + right pane); its state survives re-renders.
let fileBrowser = null;

function renderList() {
  const browserState = fileBrowser ? fileBrowser.state() : null;
  const list = clear($('#file-list'));
  const { files, dirs } = filesAndDirs();
  const total = files.reduce((n, f) => n + f.size, 0);
  const cap = profile ? profile.caps.maxShareBytes : Infinity;
  $('#file-total').textContent = files.length || dirs.length
    ? `${files.length} ${files.length === 1 ? 'file' : 'files'} · ${formatBytes(total)} of ${formatBytes(cap)}`
    : '';
  $('#file-total').classList.toggle('over', total > cap);
  if (!files.length && !dirs.length) { fileBrowser = null; return; }

  let dl = document.getElementById('mime-list');
  if (!dl) {
    dl = h('datalist', { id: 'mime-list' }, ...COMMON_TYPES.map((t) => h('option', { value: t })));
    document.body.appendChild(dl);
  }
  const entries = [...files.map((f) => ({ path: f.path, type: f.type, size: f.size })), ...dirs.map((d) => ({ path: d, dir: true }))];
  const size = (node) => node.files.reduce((n, f) => n + f.size, 0) + [...node.dirs.values()].reduce((n, d) => n + size(d), 0);
  const count = (node) => node.files.length + [...node.dirs.values()].reduce((n, d) => n + count(d), 0);
  // After a removal, focus the row that took its place (or the one before),
  // so keyboard users are not dropped to the top of the page.
  const removed = (ul, li, drop) => {
    const idx = [...ul.children].indexOf(li);
    drop();
    renderList();
    const rows = $('#file-list').querySelectorAll('.pane-list > li');
    const next = rows[idx] || rows[idx - 1];
    const target = next ? next.querySelector('button.tree-btn') : $('#file-list').querySelector('.tree-item[tabindex="0"]');
    if (target) target.focus();
  };
  // One folder's content: its sub-folders (open, remove) and files (type,
  // remove). With folders, a tree on the left picks the folder
  // (public/js/tree.js — collapsed by default).
  const renderPane = (node, { open } = {}) => {
    const ul = h('ul.tree-list.pane-list');
    for (const d of [...node.dirs.values()].sort((a, b) => a.name.localeCompare(b.name))) {
      const li = h('li.tree-dir', {},
        h('div.tree-row', {},
          h('button.tree-name.tree-open', { type: 'button', title: `Open ${d.name}`, on: { click: () => open(d.path) } }, nameEl(d.name, { suffix: '/' })),
          h('span.tree-sub.mono', { text: `${count(d)} ${count(d) === 1 ? 'file' : 'files'} · ${formatBytes(size(d))}` }),
          h('button.btn.tree-btn', { type: 'button', text: 'Remove folder', 'aria-label': `Remove folder ${d.path}`, on: { click: () => removed(ul, li, () => removePrefix(d.path, false)) } })));
      ul.appendChild(li);
    }
    for (const f of [...node.files].sort((a, b) => a.path.localeCompare(b.path))) {
      const it = items.get(f.path);
      const typeIn = h('input.input.mime-in', { value: it.type, list: 'mime-list', 'aria-label': `Type of ${f.path}`, maxlength: '255', spellcheck: 'false' });
      typeIn.addEventListener('change', () => {
        const t = normalizeMime(typeIn.value);
        if (t) { it.type = t; typeIn.value = t; typeIn.removeAttribute('aria-invalid'); } else { typeIn.setAttribute('aria-invalid', 'true'); it.type = typeIn.value; }
      });
      const li = h('li.tree-file', {},
        h('div.tree-row', {}, h('span.tree-name', {}, nameEl(basename(f.path))), h('span.tree-sub.mono', { text: formatBytes(f.size) }), typeIn,
          h('button.btn.tree-btn', { type: 'button', text: 'Remove', 'aria-label': `Remove ${f.path}`, on: { click: () => removed(ul, li, () => items.delete(f.path)) } })));
      ul.appendChild(li);
    }
    if (!ul.firstChild) return h('p.muted.pane-empty', { text: 'This folder is empty.' });
    return ul;
  };
  const root = buildTree(entries);
  if (!root.dirs.size) { fileBrowser = null; list.appendChild(renderPane(root)); return; }
  fileBrowser = folderBrowser({ label: 'Folders to share', rootName: 'All files', root, renderPane, state: browserState, paneLabel: 'Folder contents' });
  list.appendChild(fileBrowser.el);
}

// ── submit ───────────────────────────────────────────────────────────────────
async function submit(password, opts) {
  const createBtn = $('#create');
  const sendTxt = createBtn.querySelector('.send-txt');
  const label = sendTxt.textContent;
  createBtn.disabled = true;
  const animate = !reducedMotion();
  if (animate) createBtn.classList.add('sending');
  sendTxt.textContent = 'Encrypting…';
  const progress = $('#upload-progress');
  try {
    let result;
    if (mode !== 'files') {
      const { text, fmt } = mode === 'note' ? { text: $('#editor').value, fmt: 'plaintext' } : opts.typed;
      const { body, fragment } = await encryptPaste({ text, fmt, password, bar: opts.views !== null, expire: opts.expire, views: opts.views ?? undefined, deletable: opts.deletable });
      const r = await api.createNote(body, opts.label || undefined, opts.captcha === undefined ? {} : { captcha: opts.captcha });
      result = { kind: 'paste', id: r.id, deletetoken: r.deletetoken, fragment };
    } else {
      result = await uploadFiles(password, opts, (txt) => { progress.textContent = txt; sendTxt.textContent = 'Uploading…'; });
    }
    if (animate) await wait(ARROW_LEAD_MS);
    await leaveCreate();
    $('#editor').value = '';
    clearTyped();
    $('#deletable').checked = false;
    if ($('#captcha')) $('#captcha').checked = captcha.checked;
    items.clear();
    progress.textContent = '';
    showSuccess({ ...result, url: `${location.origin}/p/${result.id}#${result.fragment}`, views: opts.views, expiryText: opts.expiryText });
  } catch (e) {
    createBtn.classList.remove('sending');
    showMsg($('#create-msg'), friendlyError(e));
    progress.textContent = '';
    createBtn.disabled = false;
    sendTxt.textContent = label;
  }
}

async function uploadFiles(password, opts, report) {
  const { files, dirs } = filesAndDirs();
  const L = profile.limits;
  const l = layout(files.map((f) => ({ path: f.path, type: f.type, size: f.size, mtime: f.mtime })), dirs);
  const allowView = profile.viewer.enabled && $('#allow-view').checked;
  const manifest = buildManifest({ entries: l.entries, total: l.total, view: allowView ? { rules: profile.viewer.rules, maxBytes: profile.viewer.maxBytes } : null });

  const initBody = { views: opts.views, expire: opts.expire, padded: l.padded };
  if (opts.deletable) initBody.deletable = true;
  if (opts.captcha !== undefined) initBody.captcha = opts.captcha;
  // Only declared when a limit needs it — the server otherwise learns nothing
  // about how many files there are or how big any one of them is.
  if (L.maxFilesPerShare !== null) initBody.files = files.length;
  if (L.maxFileBytes !== null) initBody.maxFile = Math.max(0, ...files.map((f) => f.size));
  // Likewise the file-type set and folder depth, only when a policy applies.
  if (typePolicy() || depthPolicy()) {
    const d = declare([...files, ...dirs.map((p) => ({ path: p, dir: true }))]);
    if (typePolicy()) initBody.types = d.types;
    if (depthPolicy()) initBody.depth = d.depth;
  }
  const init = await api.initFileShare(initBody);

  const key = await importFileKey(manifest.fk);
  const sources = files.map((f, i) => ({
    off: l.entries[i].off, size: f.size,
    read: async (a, b) => new Uint8Array(await f.file.slice(a, b).arrayBuffer()),
  }));
  for (let i = 0; i < init.chunks; i++) {
    report(`Encrypting and uploading… ${Math.floor((i / init.chunks) * 100)}%`);
    const ct = await encryptChunk(key, i, init.chunks, await readStreamChunk(sources, i, l.total));
    try {
      await api.uploadChunk(init.id, i, ct, init.uploadtoken);
    } catch (e) {
      if (e instanceof ApiError && e.status < 500 && e.status !== 0) throw e;
      await wait(1000);
      await api.uploadChunk(init.id, i, ct, init.uploadtoken); // one retry for transient failures
    }
  }
  report('Sealing the manifest…');
  const { body, fragment } = await encryptPaste({ text: JSON.stringify(manifest), fmt: 'files', password, bar: opts.views !== null, views: opts.views ?? undefined, expire: opts.expire, deletable: opts.deletable });
  await api.finalizeFileShare(init.id, init.uploadtoken, body, opts.label || undefined);
  return { kind: 'file', id: init.id, deletetoken: init.deletetoken, fragment };
}

async function leaveCreate() {
  const view = $('#view-create');
  if (reducedMotion()) return;
  view.classList.add('view-leaving');
  await wait(VIEW_EXIT_MS);
  view.classList.remove('view-leaving');
}

// ── password modal ───────────────────────────────────────────────────────────
function openPasswordModal(onSubmit) {
  const scrim = $('#pw-modal');
  const input = $('#modal-password');
  const confirmInput = $('#modal-password-confirm');
  const create = $('#pw-create');
  const cancel = $('#pw-cancel');
  const mmsg = $('#pw-modal-msg');
  const dialog = $('#pw-modal-dialog');
  const opener = document.activeElement;
  wirePeek(['#modal-password', '#modal-peek'], ['#modal-password-confirm', '#modal-peek-confirm']);
  // Modal: everything outside the dialog is inert while it is open (no
  // focus, no pointer, out of the accessibility tree — screen readers'
  // virtual cursor cannot wander out of it either).
  const outside = [];
  for (let n = scrim; n && n !== document.body; n = n.parentElement) {
    for (const sib of n.parentElement.children) {
      if (sib !== n && !sib.inert && !['SCRIPT', 'STYLE'].includes(sib.tagName)) { sib.inert = true; outside.push(sib); }
    }
  }
  const invalid = (field, text) => {
    markInvalid(input, mmsg, false);
    markInvalid(confirmInput, mmsg, false);
    if (!field) return;
    showMsg(mmsg, text);
    markInvalid(field, mmsg);
    field.focus();
  };
  invalid(null);
  const close = () => {
    for (const el of outside) el.inert = false;
    scrim.hidden = true;
    input.value = '';
    confirmInput.value = '';
    invalid(null);
    create.onclick = cancel.onclick = scrim.onclick = input.onkeydown = confirmInput.onkeydown = null;
    document.removeEventListener('keydown', onKey);
    if (opener && typeof opener.focus === 'function') opener.focus();
  };
  const onKey = (e) => {
    if (e.key === 'Escape') { close(); return; }
    if (e.key !== 'Tab') return;
    const f = [...scrim.querySelectorAll('input, button')].filter((el) => !el.disabled && el.offsetParent !== null);
    if (!f.length) return;
    // Focus on the dialog itself (where it opens) counts as its start.
    const atStart = document.activeElement === f[0] || document.activeElement === dialog;
    if (e.shiftKey && (atStart || !scrim.contains(document.activeElement))) { e.preventDefault(); f[f.length - 1].focus(); }
    else if (!e.shiftKey && (document.activeElement === f[f.length - 1] || !scrim.contains(document.activeElement))) { e.preventDefault(); f[0].focus(); }
  };
  const submitPw = () => {
    if (!input.value) { invalid(input, 'Enter a password, or cancel.'); return; }
    if (input.value.length > 128) { invalid(input, 'Password is too long — 128 characters max.'); return; }
    if (input.value !== confirmInput.value) { invalid(confirmInput, 'Passwords do not match — repeat the same password in both fields.'); return; }
    const pw = input.value;
    close();
    onSubmit(pw);
  };
  create.onclick = submitPw;
  cancel.onclick = close;
  scrim.onclick = (e) => { if (e.target === scrim) close(); };
  input.onkeydown = confirmInput.onkeydown = (e) => { if (e.key === 'Enter') submitPw(); };
  document.addEventListener('keydown', onKey);
  mmsg.hidden = true;
  scrim.hidden = false;
  dialog.focus();
}

// ── success ──────────────────────────────────────────────────────────────────
function showSuccess({ kind, id, deletetoken, url, views, expiryText }) {
  showView('success');
  $('#paste-url').textContent = url;
  const what = kind === 'file' ? 'the files' : mode === 'url' ? 'the link' : mode === 'secret' ? 'the credential' : 'the note';
  $('#success-note').textContent = (views === null
    ? `Anyone with this link can open ${what} any number of times until it self-destructs in ${expiryText}.`
    : views === 1
      ? `Anyone with this link can open ${what} once. Unopened, it self-destructs in ${expiryText}.`
      : `Anyone with this link can open ${what} up to ${views} times. It self-destructs after the last view or in ${expiryText}, whichever comes first.`)
    + ' Keep the whole link private — the key that unlocks it is inside the link.'
    + (publicMode ? ' Without an account you cannot manage it later: to delete it before it expires, keep the delete token below.' : ' Manage it later under “my shares”.');
  const tokenBox = document.getElementById('delete-token-box');
  if (tokenBox) {
    tokenBox.hidden = !publicMode;
    if (publicMode) {
      $('#delete-token').textContent = deletetoken;
      $('#copy-token').onclick = async () => { flashCopied($('#copy-token'), (await copyText(deletetoken)) ? 'copied' : 'failed'); };
    }
  }
  $('#seal-label').textContent = `scan to open · ${views === null ? 'unlimited views' : views === 1 ? 'one-time' : `${views} views`}`;
  renderQr(url);
  $('#copy-url').onclick = async () => { flashCopied($('#copy-url'), (await copyText(url)) ? 'copied' : 'failed'); };
  const open = $('#open-link');
  if (views === null) { open.onblur = null; open.onclick = () => window.open(url, '_blank', 'noopener'); }
  else armConfirm(open, views === 1 ? 'Uses the one view — open?' : `Uses 1 of ${views} views — open?`, () => window.open(url, '_blank', 'noopener'));
  const del = $('#delete-btn');
  const sMsg = $('#success-msg');
  armConfirm(del, 'Permanently delete?', async () => {
    del.disabled = true;
    try {
      await api.deleteShare(kind, id, deletetoken);
      showMsg(sMsg, 'Deleted.', false);
      del.textContent = 'Deleted';
      open.disabled = true;
      $('#copy-url').disabled = true;
    } catch (e) {
      showMsg(sMsg, friendlyError(e));
      del.disabled = false;
    }
  });
}

function renderQr(url) {
  const img = $('#qr');
  try {
    if (typeof window.qrcode !== 'function') throw new Error('qr unavailable');
    const qr = window.qrcode(0, 'M');
    qr.addData(url);
    qr.make();
    img.src = qr.createDataURL(6, 12);
  } catch {
    img.closest('.qr')?.remove();
  }
}
