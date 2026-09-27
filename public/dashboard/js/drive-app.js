// drive-app.js — Dashboard → Drive (docs/DRIVE.md §8): the folder tree on the
// left (public/js/tree.js, collapsed by default), the selected folder's files
// and folders on the right (name, size, modified), and the actions: upload
// (files, folders, drag and drop), new folder, rename, move, delete, download,
// Share… (the composer's share options) and each item's shares with revoke.
// A capacity bar; an unlock prompt (password, passkey with PRF, recovery code)
// when the tab has no Drive key; a plain notice when the role has no Drive.
//
// Everything cryptographic lives behind the Drive client (public/js/
// driveclient.js, docs/DRIVE.md §3, §8.1), including the passkey unlock (its
// WebAuthn PRF helper is the sign-in's, public/js/passkeys.js); this module
// only moves names and bytes between it and the DOM, which is built with h()
// only (strict CSP + Trusted Types). `startDrive(mount, deps)` is the entry
// point (public/dashboard/js/drive.js passes the client module); it is
// separate from the boot so it can be tested.

import { h, clear, showMsg, armConfirm, formatBytes, formatDate, formatCoarse, friendlyError, unencryptedHint, KIND_NAMES, viewsText } from '../../js/common.js';
import { toast, copyText, flashCopied } from '../../js/ui.js';
import { createTree, crumbTrail } from '../../js/tree.js';
import { progressBar } from '../../js/progress.js';
import { walkEntry } from '../../js/walk.js';
import { expireSeconds, MAX_VIEWS } from '../../js/format.js';
import { passkeysSupported } from '../../js/passkeys.js';
import { utf8 } from '../../js/bytes.js';
import { normalizeRules } from '../../js/filepolicy.js';
import { confirmStep, confirmLabel, canUsePasskey } from './confirm.js';

export const ROOT = 'root';
const ROOT_NAME = 'My Drive';
const UNIT_WORDS = { m: ['minute', 'minutes'], h: ['hour', 'hours'], d: ['day', 'days'] };
const MAX_NAME_BYTES = 255; // as the client (driveclient.js checkName)

// ── pure helpers (unit-tested) ──────────────────────────────────────────────

/** A node name as typed → { name } (trimmed, NFC) or { error }. Names are encrypted, so only the client checks them. */
export function checkName(raw) {
  const name = String(raw ?? '').trim().normalize('NFC');
  if (!name) return { error: 'Enter a name.' };
  if (utf8(name).length > MAX_NAME_BYTES) return { error: `Names can be at most ${MAX_NAME_BYTES} bytes long.` };
  if (/[/\\]/.test(name)) return { error: 'Names cannot contain / or \\.' };
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(name)) return { error: 'Names cannot contain control characters.' };
  if (name === '.' || name === '..') return { error: 'That name is reserved.' };
  return { name };
}

/**
 * The share options → { views, expire, expiryText } or { error }, with the
 * same rules and wording as the composer (the server enforces the limits too).
 */
export function shareOptions({ views, unlimited, n, unit }, L = {}) {
  const maxViews = L.maxViews ?? MAX_VIEWS;
  let v = null;
  const vRaw = String(views ?? '').trim();
  const nRaw = String(n ?? '').trim();
  if (!unlimited) {
    if (!/^[1-9][0-9]{0,5}$/.test(vRaw) || Number(vRaw) > maxViews) return { error: `Views must be a whole number from 1 to ${maxViews.toLocaleString('en-US')}${L.allowUnlimitedViews ? ', or unlimited (∞)' : ''}.`, field: 'views' };
    v = Number(vRaw);
  } else if (!L.allowUnlimitedViews) {
    return { error: 'Unlimited views are not allowed for your account.', field: 'views' };
  }
  const expire = nRaw + unit;
  const sec = /^[1-9][0-9]{0,6}$/.test(nRaw) && Object.prototype.hasOwnProperty.call(UNIT_WORDS, unit) ? expireSeconds(expire) : null;
  if (sec === null) return { error: 'Expiry must be a whole number between 1 minute and 365 days.', field: 'expire' };
  if (L.maxExpireSec !== null && L.maxExpireSec !== undefined && sec > L.maxExpireSec) return { error: `Your account allows an expiry of at most ${Math.floor(L.maxExpireSec / 60)} minutes.`, field: 'expire' };
  const k = Number(nRaw);
  return { views: v, expire, expiryText: `${k} ${UNIT_WORDS[unit][k === 1 ? 0 : 1]}` };
}

const MiB = 1024 * 1024;
/** A size typed in MB ('' = no limit) → bytes, null, or undefined when invalid. */
function mbToBytes(raw) {
  const v = String(raw ?? '').trim();
  if (!v) return null;
  if (!/^\d{1,9}(\.\d{1,3})?$/.test(v) || Number(v) <= 0) return undefined;
  return Math.max(1, Math.round(Number(v) * MiB));
}

/**
 * The "Receive files…" options → { expire, maxFiles, maxBytes, maxFileBytes,
 * types } or { error, field }. `L` is the profile's limits (maxExpireSec,
 * reverseMaxBytes); the server checks them again.
 */
export function reverseOptions({ n, unit, maxFiles, maxMb, fileMb, typeMode, typeRules }, L = {}) {
  const nRaw = String(n ?? '').trim();
  const expire = nRaw + unit;
  const sec = /^[1-9][0-9]{0,6}$/.test(nRaw) && Object.prototype.hasOwnProperty.call(UNIT_WORDS, unit) ? expireSeconds(expire) : null;
  if (sec === null) return { error: 'Expiry must be a whole number between 1 minute and 365 days.', field: 'expire' };
  if (L.maxExpireSec !== null && L.maxExpireSec !== undefined && sec > L.maxExpireSec) return { error: `Your account allows an expiry of at most ${Math.floor(L.maxExpireSec / 60)} minutes.`, field: 'expire' };
  const fRaw = String(maxFiles ?? '').trim();
  let files = null;
  if (fRaw) {
    if (!/^[1-9][0-9]{0,4}$/.test(fRaw) || Number(fRaw) > 10000) return { error: 'Files must be a whole number from 1 to 10,000, or empty for no limit.', field: 'files' };
    files = Number(fRaw);
  }
  const maxBytes = mbToBytes(maxMb);
  if (maxBytes === undefined) return { error: 'The total size must be a number of MB, or empty.', field: 'bytes' };
  const roleMax = L.reverseMaxBytes ?? null;
  if (roleMax !== null && maxBytes !== null && maxBytes > roleMax) return { error: `Your account allows at most ${formatBytes(roleMax)} per link.`, field: 'bytes' };
  const maxFileBytes = mbToBytes(fileMb);
  if (maxFileBytes === undefined) return { error: 'The file size must be a number of MB, or empty.', field: 'file' };
  let types = null;
  if (typeMode === 'allow' || typeMode === 'block') {
    let rules;
    try { rules = normalizeRules(String(typeRules ?? '').split(/[\n,]+/).map((x) => x.trim()).filter(Boolean)); } catch (e) { return { error: e.message, field: 'types' }; }
    if (!rules.length) return { error: 'List at least one file type (for example ext:pdf), or accept any type.', field: 'types' };
    types = { mode: typeMode, rules };
  }
  const k = Number(nRaw);
  return { expire, maxFiles: files, maxBytes: maxBytes ?? roleMax, maxFileBytes, types, expiryText: `${k} ${UNIT_WORDS[unit][k === 1 ? 0 : 1]}` };
}

/** The client's progress, onProgress(bytesDone, total) → a fraction in [0, 1]. */
export function toFraction(done, total) {
  const d = Number(done);
  const t = Number(total);
  return Number.isFinite(d) && Number.isFinite(t) && t > 0 ? Math.max(0, Math.min(1, d / t)) : 0;
}

/** When a node was last modified, in seconds (mtime may be ms, updated s). */
export function modifiedOf(c) {
  const t = Number(c.kind === 'file' && c.mtime ? c.mtime : (c.updated || c.mtime || 0));
  return t > 1e11 ? Math.floor(t / 1000) : t;
}

/** Folders first, then by name. */
export const sortChildren = (list) => [...list].sort((a, b) => (a.kind === b.kind ? 0 : a.kind === 'dir' ? -1 : 1) || String(a.name).localeCompare(String(b.name)));

/** A listing's path, root first, always ending with the folder itself. */
export function pathOf(r) {
  const p = Array.isArray(r.path) ? r.path.map((x) => ({ id: x.id, name: x.name })) : [];
  if (!p.length || p[0].id !== ROOT) p.unshift({ id: ROOT, name: '' });
  if (r.node && p[p.length - 1].id !== r.node.id) p.push({ id: r.node.id, name: r.node.name });
  return p;
}
const display = (x) => (x.id === ROOT ? ROOT_NAME : x.name || '(unnamed)');
const dirsOf = (r) => sortChildren(r.children.filter((c) => c.kind === 'dir')).map((c) => ({ id: c.id, name: c.name || '(unnamed)' }));

/** The text under a new link — the composer's wording. */
export function successNote({ views, expiryText, what }) {
  return (views === null
    ? `Anyone with this link can open ${what} any number of times until it self-destructs in ${expiryText}.`
    : views === 1
      ? `Anyone with this link can open ${what} once. Unopened, it self-destructs in ${expiryText}.`
      : `Anyone with this link can open ${what} up to ${views} times. It self-destructs after the last view or in ${expiryText}, whichever comes first.`)
    + ' Keep the whole link private — the key that unlocks it is inside the link. Deleting the item from your Drive ends the link at once; ending the link keeps the item. Manage it later under “my shares”.';
}

// ── dialogs ─────────────────────────────────────────────────────────────────
let dlgSeq = 0;

/**
 * A modal dialog (the composer's .modal look): named by its title, focus moved
 * in and trapped, Escape or the scrim closes, the rest of the page inert, and
 * focus back on the opener (or `fallback()`) when it closes.
 */
export function openDialog({ title, sub = '', body = [], wide = false, fallback = null, onClose = null }) {
  const id = `dlg-${++dlgSeq}`;
  const titleEl = h('h2.modal-title', { id: `${id}-t`, text: title });
  const subEl = h('p.modal-sub', { id: `${id}-s`, text: sub, hidden: !sub });
  const bodyEl = h('div.modal-body', {}, ...body);
  const msg = h('p.msg.error.modal-msg', { id: `${id}-m`, role: 'alert', hidden: true });
  const actions = h('div.modal-actions');
  const box = h(`div.modal${wide ? '.modal-wide' : ''}`, { role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': `${id}-t`, 'aria-describedby': sub ? `${id}-s` : null, tabindex: '-1' },
    titleEl, subEl, bodyEl, msg, actions);
  const scrim = h('div.modal-scrim.drive-dialog', {}, box);
  const opener = document.activeElement;
  const inerted = [...document.body.children].filter((el) => el.id !== 'toast' && el.tagName !== 'SCRIPT' && !el.inert);
  let open = true;
  const onKey = (e) => {
    if (e.key === 'Escape') { e.preventDefault(); close(); return; }
    if (e.key !== 'Tab') return;
    const f = [...box.querySelectorAll('input, button, select, textarea, a[href]')].filter((el) => !el.disabled && !el.closest('[hidden]'));
    if (!f.length) { e.preventDefault(); return; }
    if (e.shiftKey && (document.activeElement === f[0] || !box.contains(document.activeElement))) { e.preventDefault(); f[f.length - 1].focus(); }
    else if (!e.shiftKey && (document.activeElement === f[f.length - 1] || !box.contains(document.activeElement))) { e.preventDefault(); f[0].focus(); }
  };
  function close() {
    if (!open) return;
    open = false;
    scrim.remove();
    for (const el of inerted) el.inert = false;
    document.removeEventListener('keydown', onKey, true);
    if (opener && opener.isConnected && !opener.disabled && typeof opener.focus === 'function') opener.focus();
    else if (fallback) fallback();
    if (onClose) onClose();
  }
  scrim.addEventListener('mousedown', (e) => { if (e.target === scrim) close(); });
  document.body.appendChild(scrim);
  for (const el of inerted) el.inert = true;
  document.addEventListener('keydown', onKey, true);
  const first = bodyEl.querySelector('input:not([type="checkbox"]):not([hidden]), select, textarea');
  (first || box).focus();
  return {
    box, msg, actions, titleEl, subEl,
    get open() { return open; },
    close,
    setTitle(t) { titleEl.textContent = t; },
    setBody(...nodes) { bodyEl.replaceChildren(...nodes); },
    setActions(...nodes) { actions.replaceChildren(...nodes); },
    error(text, field = null) {
      showMsg(msg, text);
      if (field) { field.setAttribute('aria-invalid', 'true'); field.setAttribute('aria-describedby', `${id}-m`); field.focus(); }
    },
    clearError() { msg.hidden = true; for (const el of box.querySelectorAll('[aria-invalid="true"]')) el.removeAttribute('aria-invalid'); },
  };
}

const btn = (text, onClick, cls = '') => h(`button.btn${cls ? `.${cls}` : ''}`, { type: 'button', text, on: { click: onClick } });
const primary = (text, onClick) => h('button.send', { type: 'button', on: { click: onClick } }, h('span.send-txt', { text }));
const field = (labelText, input, hint = null) => h('div.dfield', {}, h('label.field-label', { for: input.id, text: labelText }), input, hint);

/** A dialog with one name field: `submit(name)` returns an error string or nothing. */
function nameDialog({ title, sub, value = '', action, submit, fallback }) {
  const input = h('input.input', { id: `name-in-${dlgSeq + 1}`, value, maxlength: '255', autocomplete: 'off', spellcheck: 'false' });
  const d = openDialog({ title, sub, body: [field('Name', input)], fallback });
  // Select the name without its extension, like a file manager.
  const dot = value.lastIndexOf('.');
  input.setSelectionRange(0, dot > 0 ? dot : value.length);
  let busy = false;
  const go = async () => {
    if (busy) return;
    d.clearError();
    const c = checkName(input.value);
    if (c.error) { d.error(c.error, input); return; }
    busy = true;
    ok.disabled = true;
    try {
      const err = await submit(c.name);
      if (err) { d.error(err, input); return; }
      d.close();
    } catch (e) {
      d.error(friendlyError(e), input);
    } finally {
      busy = false;
      ok.disabled = false;
    }
  };
  const ok = primary(action, go);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); go(); } });
  d.setActions(btn('Cancel', () => d.close(), 'modal-btn'), ok);
  return d;
}

// ── entry ───────────────────────────────────────────────────────────────────

/**
 * Mount the Drive in `mount`. `deps`: { drive: the client module (openDrive,
 * unlockDrive, unlockDriveWithPasskey, DriveLocked, DriveDisabled), profile
 * (/api/private/me), user ({ id, role, impersonating }, from the profile),
 * revoke(shareId) }. Resolves to { state: 'open' | 'locked' | 'disabled' |
 * 'error', app?, unlocked? } (unlocked: a promise of the app once unlocked).
 */
export async function startDrive(mount, deps) {
  mount.replaceChildren(h('p.msg', { role: 'status', text: 'Opening your Drive…' }));
  let client;
  try {
    client = await deps.drive.openDrive({ user: deps.user });
  } catch (e) {
    if (deps.drive.DriveDisabled && e instanceof deps.drive.DriveDisabled) { mount.replaceChildren(disabledNotice()); return { state: 'disabled' }; }
    if (deps.drive.DriveLocked && e instanceof deps.drive.DriveLocked) return { state: 'locked', unlocked: unlockView(mount, deps, e) };
    mount.replaceChildren(h('div.card.drive-notice', {}, h('p.msg.error', { role: 'alert', text: `The Drive could not be opened: ${friendlyError(e)}` })));
    return { state: 'error' };
  }
  return { state: 'open', app: mountApp(mount, client, deps) };
}

function disabledNotice() {
  return h('div.card.drive-notice', { id: 'drive-disabled' },
    h('h2.section-title', { text: 'Drive is not enabled for your account' }),
    h('p.modal-sub', { text: 'Your role does not include a Drive. Ask the administrator if you need one. You can still share notes and files from “new”.' }),
    h('div.btn-row', {}, h('a.btn', { href: '/dashboard/', text: 'New share' })));
}

// ── unlock ──────────────────────────────────────────────────────────────────

/**
 * The unlock prompt (docs/DRIVE.md §3): the password, a passkey with a Drive
 * wrap (PRF) or a recovery code. The first time (`reason` 'setup': no key yet)
 * only the password can create the Drive's key.
 */
function unlockView(mount, deps, lockedErr) {
  const setup = !!lockedErr && lockedErr.reason === 'setup';
  const withPasskey = !setup && !(lockedErr && Array.isArray(lockedErr.credentialIds) && !lockedErr.credentialIds.length);
  return new Promise((resolve) => {
    const msg = h('p.msg.error', { id: 'drive-unlock-msg', role: 'alert', hidden: true });
    const pw = h('input.input', { id: 'drive-unlock-pw', type: 'password', autocomplete: 'current-password', maxlength: '1024', spellcheck: 'false' });
    const code = h('input.input.mono', { id: 'drive-unlock-code', autocomplete: 'off', spellcheck: 'false', maxlength: '64', placeholder: 'xxxx-xxxx-xxxx' });
    const pwBtn = h('button.cta', { type: 'submit', id: 'drive-unlock-btn', text: setup ? 'Set up with password' : 'Unlock with password' });
    const codeBtn = h('button.cta', { type: 'submit', id: 'drive-unlock-code-btn', text: 'Unlock with recovery code' });
    const pkBtn = h('button.btn', { type: 'button', id: 'drive-unlock-passkey', text: 'Unlock with a passkey', hidden: !withPasskey || !passkeysSupported() });
    const codeForm = h('form.form.drive-unlock-form', { id: 'drive-code-form', hidden: true, novalidate: true }, field('Recovery code', code), codeBtn);
    const codeToggle = h('button.linkbtn', { type: 'button', id: 'drive-code-toggle', 'aria-expanded': 'false', 'aria-controls': 'drive-code-form', text: 'Use a recovery code instead', hidden: setup });
    const pwForm = h('form.form.drive-unlock-form', { id: 'drive-pw-form', novalidate: true }, field('Account password', pw), pwBtn);
    const all = [pwBtn, codeBtn, pkBtn];
    let inFlight = false;
    const attempt = async (creds, input) => {
      if (inFlight) return;
      inFlight = true;
      msg.hidden = true;
      for (const b of all) b.disabled = true;
      pw.removeAttribute('aria-invalid');
      code.removeAttribute('aria-invalid');
      try {
        const client = creds === 'passkey'
          ? await deps.drive.unlockDriveWithPasskey({ user: deps.user })
          : await deps.drive.unlockDrive(creds, { user: deps.user });
        pw.value = '';
        code.value = '';
        resolve(mountApp(mount, client, deps));
      } catch (e) {
        inFlight = false;
        for (const b of all) b.disabled = false;
        showMsg(msg, deps.drive.DriveLocked && e instanceof deps.drive.DriveLocked && e.reason === 'wrong' ? 'That does not unlock your Drive — check it and try again.' : friendlyError(e));
        if (input) { input.setAttribute('aria-invalid', 'true'); input.setAttribute('aria-describedby', 'drive-unlock-msg'); input.focus(); input.select?.(); }
      }
    };
    pwForm.addEventListener('submit', (e) => {
      e.preventDefault();
      if (!pw.value) { showMsg(msg, 'Enter your password.'); pw.setAttribute('aria-invalid', 'true'); pw.focus(); return; }
      attempt({ password: pw.value }, pw);
    });
    codeForm.addEventListener('submit', (e) => {
      e.preventDefault();
      if (!code.value.trim()) { showMsg(msg, 'Enter one of your recovery codes.'); code.setAttribute('aria-invalid', 'true'); code.focus(); return; }
      attempt({ code: code.value.trim() }, code);
    });
    pkBtn.addEventListener('click', () => attempt('passkey', null));
    codeToggle.addEventListener('click', () => {
      const show = codeForm.hidden;
      codeForm.hidden = !show;
      codeToggle.setAttribute('aria-expanded', String(show));
      if (show) code.focus();
    });
    const waiting = !setup && lockedErr && Number(lockedErr.received) > 0 ? Number(lockedErr.received) : 0;
    mount.replaceChildren(h('div.card.drive-unlock', { id: 'drive-unlock' },
      h('h2.section-title', { text: setup ? 'Set up your Drive' : 'Unlock your Drive' }),
      waiting ? h('p.msg', { id: 'drive-received-waiting', role: 'status', text: `${waiting} new received file${waiting === 1 ? '' : 's'}: unlock your Drive to add ${waiting === 1 ? 'it' : 'them'} to your folders.` }) : null,
      h('p.modal-sub', {
        text: setup
          ? 'Your Drive is encrypted with a key that only you can open. Enter your account password to create it: the key is made here, in your browser, and kept only until you sign out or close the tab.'
          : 'Your Drive is encrypted with a key that only you can open, and this tab does not have it yet. Confirm it is you: the key is unlocked here, in your browser, and kept only until you sign out or close the tab.',
      }),
      pwForm,
      h('div.login-alt', {}, pkBtn, codeToggle),
      codeForm,
      msg));
    pw.focus();
  });
}

// ── the Drive ───────────────────────────────────────────────────────────────

function mountApp(mount, client, deps) {
  const L = (deps.profile && deps.profile.limits) || {};
  let current = ROOT;
  let listing = null;
  let busy = false;
  let openSeq = 0;
  const selected = new Set();
  const recent = new Map(); // id → { at, promise }: one fetch serves the tree and the pane

  const fetchList = (id) => {
    const r = recent.get(id);
    if (r && Date.now() - r.at < 1500) return r.promise;
    const promise = client.list(id);
    recent.set(id, { at: Date.now(), promise });
    promise.catch(() => recent.delete(id));
    return promise;
  };

  // capacity
  const capText = h('p.mono.drive-cap-text', { id: 'drive-cap-text' });
  const capMeter = h('meter.drive-cap-meter', { id: 'drive-cap-meter', min: '0', max: '1', low: '0.75', high: '0.9', optimum: '0', 'aria-labelledby': 'drive-cap-label', 'aria-describedby': 'drive-cap-text' });
  const cap = h('div.drive-cap', {}, h('span.field-label', { id: 'drive-cap-label', text: 'Storage used' }), capMeter, capText);
  async function refreshUsage() {
    try {
      const u = await client.usage();
      const used = Number(u.used) || 0;
      const total = u.capacity === null || u.capacity === undefined ? null : Number(u.capacity);
      capMeter.hidden = total === null;
      if (total !== null) { capMeter.max = Math.max(1, total); capMeter.low = 0.75 * total; capMeter.high = 0.9 * total; capMeter.value = Math.min(used, total); }
      capText.textContent = total === null ? `${formatBytes(used)} used · no limit` : `${formatBytes(used)} of ${formatBytes(total)} used · ${formatBytes(Math.max(0, total - used))} free`;
      capText.classList.toggle('over', total !== null && used >= 0.9 * total);
    } catch (e) {
      capText.textContent = `Storage use unavailable: ${friendlyError(e)}`;
    }
  }

  // toolbar
  const fileIn = h('input', { type: 'file', id: 'drive-file-input', multiple: true, hidden: true });
  const folderIn = h('input', { type: 'file', id: 'drive-folder-input', multiple: true, webkitdirectory: true, hidden: true });
  const B = {
    upload: btn('Upload files', () => fileIn.click()),
    uploadDir: btn('Upload folder', () => folderIn.click()),
    mkdir: btn('New folder', newFolder),
    rename: btn('Rename', renameSel),
    move: btn('Move…', moveSel),
    download: btn('Download', downloadSel),
    share: btn('Share…', shareSel),
    receive: btn('Receive files…', receiveSel),
    del: btn('Delete', deleteSel, 'danger'),
  };
  const canReceive = !!(deps.profile && deps.profile.caps && deps.profile.caps.reverseEnabled === true);
  B.receive.hidden = !canReceive;
  for (const [k, b] of Object.entries(B)) b.id = `drive-${k}`;
  const selInfo = h('span.mono.muted.drive-selinfo', { id: 'drive-selinfo' });
  const toolbar = h('div.drive-toolbar', { role: 'group', 'aria-label': 'Drive actions' },
    h('div.btn-row', {}, B.upload, B.uploadDir, B.mkdir),
    h('div.btn-row', {}, B.rename, B.move, B.download, B.share, B.receive, B.del), selInfo);
  fileIn.addEventListener('change', () => { const f = [...fileIn.files]; fileIn.value = ''; uploadFiles(f); });
  folderIn.addEventListener('change', () => {
    const f = [...folderIn.files];
    folderIn.value = '';
    uploadEntries(f.map((file) => ({ path: file.webkitRelativePath || file.name, file })));
  });

  // transfers
  const bar = progressBar();
  const cancelBtn = h('button.btn', { type: 'button', id: 'drive-cancel', text: 'Cancel', hidden: true });
  const msg = h('p.msg.error.drive-msg', { id: 'drive-msg', role: 'alert', hidden: true });
  const receivedMsg = h('p.msg.drive-received', { id: 'drive-received', role: 'status', hidden: true });
  const transferBox = h('div.drive-transfer', {}, bar.el, cancelBtn);

  // the folder tree
  const tree = createTree({
    label: 'Drive folders',
    root: { id: ROOT, name: ROOT_NAME },
    loadChildren: async (id) => dirsOf(await fetchList(id)),
    onSelect: (n) => open(n.id, { focus: false }),
    onError: (e) => toast(friendlyError(e), { error: true }),
  });
  const treeToggle = h('button.btn.drive-tree-toggle', { type: 'button', id: 'drive-tree-toggle', 'aria-expanded': 'false', 'aria-controls': 'drive-tree-pane', text: 'Folders' });
  const treePane = h('section.drive-tree-pane', { id: 'drive-tree-pane', 'aria-labelledby': 'drive-tree-title' },
    h('h2.drive-pane-h', { id: 'drive-tree-title', text: 'Folders' }), tree.el);

  // the right pane
  const crumbs = h('nav.crumbs', { 'aria-label': 'Folder path' });
  const title = h('h2.drive-pane-title', { id: 'drive-pane-title', tabindex: '-1' });
  const selAll = h('input', { type: 'checkbox', id: 'drive-select-all', 'aria-label': 'Select everything in this folder' });
  const caption = h('caption.sr-only', { id: 'drive-caption' });
  const tbody = h('tbody', { id: 'drive-rows' });
  const table = h('table.table.drive-table', { id: 'drive-table' }, caption,
    h('thead', {}, h('tr', {},
      h('th.cell-check', { scope: 'col' }, selAll),
      h('th', { scope: 'col', text: 'Name' }), h('th', { scope: 'col', text: 'Size' }), h('th', { scope: 'col', text: 'Modified' }),
      h('th', { scope: 'col' }, h('span.sr-only', { text: 'Shares' })))),
    tbody);
  const empty = h('p.msg.drive-empty', { id: 'drive-empty', hidden: true, text: 'This folder is empty. Upload files or drop them here.' });
  const paneMsg = h('p.msg.error', { id: 'drive-pane-msg', role: 'alert', hidden: true });
  const dropHint = h('p.mono.muted.drive-drop-hint', { text: 'Drop files or folders here to upload them to this folder. Names, folders and contents are encrypted in your browser.' });
  const pane = h('section.drive-pane', { id: 'drive-pane', 'aria-labelledby': 'drive-pane-title' },
    crumbs, title, h('div.table-wrap', {}, table), empty, paneMsg, dropHint);
  const layout = h('div.drive-layout', { id: 'drive-layout' }, treeToggle, treePane, pane);

  treeToggle.addEventListener('click', () => {
    const on = !layout.classList.contains('tree-open');
    layout.classList.toggle('tree-open', on);
    treeToggle.setAttribute('aria-expanded', String(on));
    if (on) tree.focus();
  });

  mount.replaceChildren(h('div.drive', { id: 'drive-app' }, cap, toolbar, fileIn, folderIn, transferBox, msg, receivedMsg, layout));

  // drag and drop onto the right pane
  pane.addEventListener('dragover', (e) => { if (!busy) { e.preventDefault(); pane.classList.add('over'); } });
  pane.addEventListener('dragleave', (e) => { if (!pane.contains(e.relatedTarget)) pane.classList.remove('over'); });
  pane.addEventListener('drop', async (e) => {
    e.preventDefault();
    pane.classList.remove('over');
    if (busy) return;
    const entries = [];
    const walks = [];
    for (const item of e.dataTransfer?.items || []) {
      const entry = typeof item.webkitGetAsEntry === 'function' ? item.webkitGetAsEntry() : null;
      if (entry) walks.push(entry);
      else if (item.kind === 'file') { const f = item.getAsFile(); if (f) entries.push({ path: f.name, file: f }); }
    }
    // Empty folders are kept (the client creates them: { path, dir: true }).
    for (const entry of walks) await walkEntry(entry, (path, file) => { entries.push({ path, file }); }, (path) => { entries.push({ path, dir: true }); });
    if (!walks.length && !entries.length) for (const f of e.dataTransfer?.files || []) entries.push({ path: f.name, file: f });
    if (entries.some((x) => x.dir || x.path.includes('/'))) uploadEntries(entries);
    else uploadFiles(entries.map((x) => x.file));
  });

  // ── listing ────────────────────────────────────────────────────────────
  async function open(id, { focus = false } = {}) {
    const n = ++openSeq;
    paneMsg.hidden = true;
    let r;
    try {
      r = await fetchList(id);
    } catch (e) {
      if (n !== openSeq) return false;
      // The tab's key does not open this Drive (the client dropped it): ask again.
      if (deps.drive.DriveLocked && e instanceof deps.drive.DriveLocked) { unlockView(mount, deps, e); return false; }
      showMsg(paneMsg, `This folder could not be opened: ${friendlyError(e)}`);
      return false;
    }
    if (n !== openSeq) return false;
    if (id !== current) selected.clear();
    current = id;
    listing = r;
    const path = pathOf(r);
    // Keep the tree in step: this folder's sub-folders, and the folder itself revealed and selected.
    if (tree.has(id)) tree.setChildren(id, dirsOf(r));
    await tree.reveal(path.map((p) => p.id));
    render();
    if (focus) title.focus();
    return true;
  }

  const kids = () => (listing ? sortChildren(listing.children) : []);
  const byId = (id) => kids().find((c) => c.id === id);

  function render() {
    const path = pathOf(listing);
    crumbTrail(crumbs, path.map((p) => ({ name: display(p), go: () => open(p.id, { focus: true }) })));
    const here = display(path[path.length - 1]);
    title.textContent = here;
    caption.textContent = `Contents of ${here}`;
    const list = kids();
    for (const id of [...selected]) if (!list.some((c) => c.id === id)) selected.delete(id);
    clear(tbody).append(...list.map(row));
    table.hidden = !list.length;
    empty.hidden = !!list.length;
    updateButtons();
  }

  function row(c) {
    const name = c.name || '(unnamed)';
    const check = h('input', { type: 'checkbox', 'aria-label': `Select ${name}`, checked: selected.has(c.id) });
    check.addEventListener('change', () => { if (check.checked) selected.add(c.id); else selected.delete(c.id); updateButtons(); });
    const nameCell = c.kind === 'dir'
      ? h('button.tree-open.drive-open', { type: 'button', title: `Open ${name}`, on: { click: () => open(c.id, { focus: true }) } }, h('span.tree-icon', { 'aria-hidden': 'true' }), h('span', { text: name }))
      : h('span.drive-fname', { text: name });
    const sharesBtn = h('button.btn.tree-btn', { type: 'button', text: 'Shares', 'aria-label': `Shares of ${name}`, on: { click: () => sharesDialog(c) } });
    return h('tr', { dataset: { id: c.id, kind: c.kind } },
      h('td.cell-check', {}, check),
      h('td', { dataset: { label: 'Name' } }, nameCell),
      h('td.mono', { dataset: { label: 'Size' }, text: c.kind === 'dir' ? '—' : formatBytes(Number(c.size) || 0) }),
      h('td.mono', { dataset: { label: 'Modified' }, text: formatDate(modifiedOf(c)) }),
      h('td.cell-actions', {}, sharesBtn));
  }

  function updateButtons() {
    const n = selected.size;
    const one = n === 1 ? byId([...selected][0]) : null;
    B.rename.disabled = busy || n !== 1;
    B.move.disabled = busy || n === 0;
    B.del.disabled = busy || n === 0;
    B.share.disabled = busy || n === 0;
    B.download.disabled = busy || !one;
    B.download.textContent = one && one.kind === 'dir' ? 'Download (.zip)' : 'Download';
    B.receive.disabled = busy || n > 1 || (n === 1 && (!one || one.kind !== 'dir'));
    for (const b of [B.upload, B.uploadDir, B.mkdir]) b.disabled = busy;
    const total = kids().length;
    selAll.checked = total > 0 && n === total;
    selAll.indeterminate = n > 0 && n < total;
    selAll.disabled = total === 0;
    selInfo.textContent = n ? `${n} selected` : '';
  }
  selAll.addEventListener('change', () => {
    selected.clear();
    if (selAll.checked) for (const c of kids()) selected.add(c.id);
    for (const cb of tbody.querySelectorAll('input[type="checkbox"]')) cb.checked = selAll.checked;
    updateButtons();
  });

  /** Re-read the shown folder (and `also` folders in the tree) after a change. */
  async function refresh(also = []) {
    recent.clear();
    await open(current);
    for (const id of also) if (id !== current) await tree.refresh(id);
    refreshUsage();
  }

  const focusPane = () => title.focus();
  const selectedItems = () => [...selected].map(byId).filter(Boolean);
  const nameTaken = (name, except = null) => kids().some((c) => c.name === name && c.id !== except);
  const describe = (items) => (items.length === 1 ? `“${items[0].name}”` : `${items.length} items`);

  // ── actions ────────────────────────────────────────────────────────────
  function newFolder() {
    const parent = current;
    nameDialog({
      title: 'New folder',
      sub: `In ${title.textContent}. The name is encrypted in your browser.`,
      action: 'Create',
      fallback: focusPane,
      submit: async (name) => {
        if (parent === current && nameTaken(name)) return `An item named “${name}” already exists here.`;
        await client.mkdir(parent, name);
        toast('Folder created.');
        await refresh();
        return null;
      },
    });
  }

  function renameSel() {
    const [it] = selectedItems();
    if (!it) return;
    nameDialog({
      title: `Rename ${it.kind === 'dir' ? 'folder' : 'file'}`,
      sub: `Currently “${it.name}”.`,
      value: it.name,
      action: 'Rename',
      fallback: focusPane,
      submit: async (name) => {
        if (name === it.name) return null;
        if (nameTaken(name, it.id)) return `An item named “${name}” already exists here.`;
        await client.rename(it.id, name);
        toast('Renamed.');
        await refresh();
        return null;
      },
    });
  }

  function moveSel() {
    const items = selectedItems();
    if (!items.length) return;
    const moving = new Set(items.map((i) => i.id));
    const from = current;
    let target = ROOT;
    const chosen = h('p.mono.drive-move-target', { id: 'drive-move-target', 'aria-live': 'polite', text: `Move to: ${ROOT_NAME}` });
    const picker = createTree({
      label: 'Move to folder',
      root: { id: ROOT, name: ROOT_NAME },
      // A folder cannot go into itself or anything inside it: those are left out.
      loadChildren: async (id) => dirsOf(await fetchList(id)).filter((d) => !moving.has(d.id)),
      onSelect: (n) => { target = n.id; chosen.textContent = `Move to: ${n.path.map((p) => (p.id === ROOT ? ROOT_NAME : p.name)).join(' / ')}`; ok.disabled = target === from; d.clearError(); },
      onError: (e) => d.error(friendlyError(e)),
    });
    const d = openDialog({ title: `Move ${describe(items)}`, sub: 'Pick the folder to move into. Shares of what you move keep working.', body: [h('div.drive-picker', {}, picker.el), chosen], wide: true, fallback: focusPane });
    const ok = primary('Move here', async () => {
      if (target === from) return;
      ok.disabled = true;
      d.clearError();
      const done = [];
      try {
        for (const it of items) { await client.move(it.id, target); done.push(it.id); }
        toast(`Moved ${describe(items)}.`);
        d.close();
      } catch (e) {
        d.error(done.length ? `Moved ${done.length} of ${items.length}; then: ${friendlyError(e)}` : friendlyError(e));
        ok.disabled = false;
      }
      if (done.length) { for (const id of done) selected.delete(id); await refresh([target]); }
    });
    ok.disabled = target === from;
    d.setActions(btn('Cancel', () => d.close(), 'modal-btn'), ok);
    picker.ready.then(() => picker.focus());
  }

  function deleteSel() {
    const items = selectedItems();
    if (!items.length) return;
    const dirs = items.filter((i) => i.kind === 'dir').length;
    const d = openDialog({
      title: `Delete ${describe(items)}?`,
      sub: `${dirs ? 'Folders are deleted with everything in them. ' : ''}Every share of ${items.length === 1 ? 'it' : 'them'} stops working at once. This cannot be undone.`,
      body: [h('ul.drive-del-list', {}, ...items.slice(0, 8).map((i) => h('li.mono', { text: i.kind === 'dir' ? `${i.name}/` : i.name })), items.length > 8 ? h('li.mono', { text: `… and ${items.length - 8} more` }) : null)],
      fallback: focusPane,
    });
    const cancel = btn('Cancel', () => d.close(), 'modal-btn');
    const ok = h('button.btn.danger.modal-btn', { type: 'button', id: 'drive-delete-confirm', text: 'Delete' });
    ok.addEventListener('click', async () => {
      ok.disabled = true;
      let n = 0;
      try {
        for (const it of items) { await client.remove(it.id); selected.delete(it.id); n++; }
        toast(`Deleted ${describe(items)}.`);
        d.close();
      } catch (e) {
        d.error(n ? `Deleted ${n} of ${items.length}; then: ${friendlyError(e)}` : friendlyError(e));
        ok.disabled = false;
      }
      if (n) await refresh();
    });
    d.setActions(cancel, ok);
    cancel.focus();
  }

  async function transfer(label, fn) {
    if (busy) { toast('Wait for the current transfer to finish.'); return false; }
    busy = true;
    updateButtons();
    msg.hidden = true;
    const ctl = new AbortController();
    cancelBtn.hidden = false;
    cancelBtn.onclick = () => ctl.abort();
    bar.set(`${label}…`, 0);
    try {
      await fn((done, total) => bar.set(`${label}…`, toFraction(done, total)), ctl.signal);
      bar.done(`${label}: done`);
      return true;
    } catch (e) {
      bar.hide();
      if (e && e.name === 'AbortError') toast('Cancelled.');
      else showMsg(msg, friendlyError(e));
      return false;
    } finally {
      busy = false;
      cancelBtn.hidden = true;
      cancelBtn.onclick = null;
      updateButtons();
    }
  }

  async function uploadFiles(files) {
    if (!files.length) return;
    const target = current;
    const total = files.reduce((n, f) => n + f.size, 0);
    let done = 0;
    const label = files.length === 1 ? `Uploading ${files[0].name}` : `Uploading ${files.length} files`;
    const ok = await transfer(label, async (progress, signal) => {
      for (const f of files) {
        await client.upload(target, f, { signal, onProgress: (d) => progress(done + d, total) });
        done += f.size;
      }
    });
    if (ok || done) await refresh([target]);
  }

  async function uploadEntries(entries) {
    if (!entries.length) return;
    const target = current;
    const top = new Set(entries.map((e) => e.path.split('/')[0]));
    const files = entries.filter((e) => !e.dir).length;
    const label = top.size === 1 && (entries[0].dir || entries[0].path.includes('/')) ? `Uploading ${[...top][0]}/` : `Uploading ${files} ${files === 1 ? 'file' : 'files'}`;
    await transfer(label, (progress, signal) => client.uploadTree(target, entries, { signal, onProgress: progress }));
    await refresh([target]);
  }

  function downloadSel() {
    const [it] = selectedItems();
    if (!it) return;
    if (it.kind === 'dir') transfer(`Preparing ${it.name}.zip`, (progress, signal) => client.downloadFolder(it.id, { onProgress: progress, signal }));
    else transfer(`Downloading ${it.name}`, async (progress, signal) => (await client.download(it.id, { onProgress: progress, signal })).save());
  }

  // ── share ──────────────────────────────────────────────────────────────
  function shareSel() {
    const items = selectedItems();
    if (!items.length) return;
    if (L.files === false) { showMsg(msg, 'Your account is not allowed to create file shares. Ask the administrator.'); return; }
    const views = h('input.input.opt-num', { id: 'drive-share-views', type: 'number', min: '1', max: String(L.maxViews ?? MAX_VIEWS), step: '1', value: '1', inputmode: 'numeric' });
    const inf = h('button.opt-toggle', { type: 'button', id: 'drive-share-unlimited', 'aria-pressed': 'false', 'aria-label': 'Unlimited views', title: 'Unlimited views', text: '∞', disabled: !L.allowUnlimitedViews });
    inf.addEventListener('click', () => { const on = inf.getAttribute('aria-pressed') !== 'true'; inf.setAttribute('aria-pressed', String(on)); views.disabled = on; });
    const expN = h('input.input.opt-num', { id: 'drive-share-expire', type: 'number', min: '1', step: '1', value: '24', inputmode: 'numeric' });
    const expU = h('select.input.opt-sel', { id: 'drive-share-unit', 'aria-label': 'Expiry unit' },
      h('option', { value: 'm', text: 'minutes' }), h('option', { value: 'h', text: 'hours', selected: true }), h('option', { value: 'd', text: 'days' }));
    const pwOn = h('input', { type: 'checkbox', id: 'drive-share-pw-on' });
    const pw1 = h('input.input', { id: 'drive-share-pw', type: 'password', autocomplete: 'new-password', maxlength: '128', 'data-lpignore': 'true', 'data-1p-ignore': true });
    const pw2 = h('input.input', { id: 'drive-share-pw2', type: 'password', autocomplete: 'new-password', maxlength: '128', 'data-lpignore': 'true', 'data-1p-ignore': true });
    const pwBox = h('div.drive-share-pw', { hidden: true }, field('Password', pw1), field('Repeat the password', pw2));
    pwOn.addEventListener('change', () => { pwBox.hidden = !pwOn.checked; if (pwOn.checked) pw1.focus(); });
    const del = h('input', { type: 'checkbox', id: 'drive-share-deletable' });
    const viewer = deps.profile && deps.profile.viewer;
    const allowView = h('input', { type: 'checkbox', id: 'drive-share-view' });
    const label = h('input.input', { id: 'drive-share-label', maxlength: '100', placeholder: 'e.g. Contract for ACME' });
    const hint = unencryptedHint('drive-share-label-hint', label);
    const form = h('div.drive-share-form', {},
      h('div.drive-share-opts', {},
        h('div.opt', { role: 'group', 'aria-labelledby': 'drive-share-views-l' }, h('label.opt-label', { id: 'drive-share-views-l', for: 'drive-share-views', text: 'Views' }), views, inf),
        h('div.opt', { role: 'group', 'aria-labelledby': 'drive-share-expire-l' }, h('label.opt-label', { id: 'drive-share-expire-l', for: 'drive-share-expire', text: 'Expires in' }), expN, expU)),
      h('label.viewer-opt', {}, pwOn, 'Protect with a password (recipients need it in addition to the link)'),
      pwBox,
      L.openerDelete ? h('label.viewer-opt', {}, del, 'Let the recipient delete it at once (“Delete now”)') : null,
      viewer && viewer.enabled ? h('label.viewer-opt', {}, allowView, 'Allow recipients to view files in the browser') : null,
      h('div.label-row', {}, h('label.field-label', { for: 'drive-share-label', text: 'Label (optional, for your own reference)' }), label, hint));
    const d = openDialog({
      title: `Share ${describe(items)}`,
      sub: 'A new link to what is in your Drive now: nothing is copied. Recipients see the names, folders and contents you share.',
      body: [form],
      wide: true,
      fallback: focusPane,
    });
    const create = primary('Create link', async () => {
      d.clearError();
      const o = shareOptions({ views: views.value, unlimited: inf.getAttribute('aria-pressed') === 'true', n: expN.value, unit: expU.value }, L);
      if (o.error) { d.error(o.error, o.field === 'views' ? views : expN); return; }
      let password = '';
      if (pwOn.checked) {
        if (!pw1.value) { d.error('Enter a password, or turn the password off.', pw1); return; }
        if (pw1.value.length > 128) { d.error('Password is too long — 128 characters max.', pw1); return; }
        if (pw1.value !== pw2.value) { d.error('Passwords do not match — repeat the same password in both fields.', pw2); return; }
        password = pw1.value;
      }
      create.disabled = true;
      create.querySelector('.send-txt').textContent = 'Creating…';
      try {
        // `limits` applies the administrator's file-type and folder-depth policy (as the composer
        // does); `view` is the viewer snapshot the composer's "view in the browser" option sends.
        const view = viewer && viewer.enabled && allowView.checked ? { rules: viewer.rules, maxBytes: viewer.maxBytes } : null;
        const r = await client.share(items.map((i) => i.id), { views: o.views, expire: o.expire, password, deletable: !!L.openerDelete && del.checked, label: label.value.trim(), limits: L, view });
        pw1.value = pw2.value = '';
        shareResult(d, r, o, items);
      } catch (e) {
        d.error(friendlyError(e));
        create.disabled = false;
        create.querySelector('.send-txt').textContent = 'Create link';
      }
    });
    d.setActions(btn('Cancel', () => d.close(), 'modal-btn'), create);
    views.focus();
  }

  function shareResult(d, r, o, items) {
    const what = items.length === 1 ? (items[0].kind === 'dir' ? 'the folder' : 'the file') : 'the files';
    d.setTitle('Share your link');
    d.subEl.textContent = successNote({ views: o.views, expiryText: o.expiryText, what });
    d.subEl.hidden = false;
    const url = h('div.url.mono', { id: 'drive-share-url', text: r.url });
    const copy = h('button.copy-btn', { type: 'button', id: 'drive-share-copy', text: 'copy link' });
    copy.addEventListener('click', async () => flashCopied(copy, (await copyText(r.url)) ? 'copied' : 'failed'));
    const nodes = [h('div.linkrow', {}, url, copy)];
    try {
      if (typeof window.qrcode !== 'function') throw new Error('qr unavailable');
      const qr = window.qrcode(0, 'M');
      qr.addData(r.url);
      qr.make();
      nodes.push(h('div.card.qr.drive-qr', {}, h('img', { src: qr.createDataURL(5, 10), alt: 'QR code for the share link' })));
    } catch { /* no QR on this page */ }
    d.setBody(...nodes);
    const done = primary('Done', () => d.close());
    d.setActions(done);
    copy.focus();
  }

  // ── receive files (reverse shares, docs/REVERSE.md) ────────────────────
  /** The folder "Receive files…" acts on: the selected folder, else the open one. */
  function receiveTarget() {
    const [it] = selectedItems();
    if (it && it.kind === 'dir') return { id: it.id, name: it.name || '(unnamed)' };
    return { id: current, name: title.textContent };
  }

  function receiveSel() {
    if (!canReceive) return;
    const folder = receiveTarget();
    const labelIn = h('input.input', { id: 'drive-rev-label', maxlength: '100', placeholder: 'e.g. Tax documents 2026' });
    const hint = unencryptedHint('drive-rev-label-hint', labelIn);
    const noteIn = h('textarea.input', { id: 'drive-rev-note', maxlength: '1000', rows: '3', placeholder: 'e.g. Please send the signed contract and your ID.' });
    const expN = h('input.input.opt-num', { id: 'drive-rev-expire', type: 'number', min: '1', step: '1', value: '7', inputmode: 'numeric' });
    const expU = h('select.input.opt-sel', { id: 'drive-rev-unit', 'aria-label': 'Expiry unit' },
      h('option', { value: 'm', text: 'minutes' }), h('option', { value: 'h', text: 'hours' }), h('option', { value: 'd', text: 'days', selected: true }));
    expU.value = 'd';
    const files = h('input.input', { id: 'drive-rev-files', type: 'number', min: '1', max: '10000', step: '1', inputmode: 'numeric', placeholder: 'no limit' });
    const roleMax = L.reverseMaxBytes ?? null;
    const maxMb = h('input.input', { id: 'drive-rev-bytes', inputmode: 'decimal', placeholder: roleMax ? `up to ${formatBytes(roleMax)}` : 'no limit' });
    const fileMb = h('input.input', { id: 'drive-rev-filesize', inputmode: 'decimal', placeholder: 'no limit' });
    const typeMode = h('select.input', { id: 'drive-rev-types' },
      h('option', { value: 'any', text: 'any type' }), h('option', { value: 'allow', text: 'only the listed types' }), h('option', { value: 'block', text: 'all but the listed types' }));
    const typeRules = h('textarea.input.rules-in', { id: 'drive-rev-rules', rows: '2', placeholder: 'ext:pdf\next:docx\nmime:image/*', hidden: true, 'aria-label': 'File types (one per line: ext:pdf, mime:image/*)' });
    typeMode.addEventListener('change', () => { typeRules.hidden = typeMode.value === 'any'; if (!typeRules.hidden) typeRules.focus(); });
    const pwOn = h('input', { type: 'checkbox', id: 'drive-rev-pw-on' });
    const pw1 = h('input.input', { id: 'drive-rev-pw', type: 'password', autocomplete: 'new-password', maxlength: '128', 'data-lpignore': 'true', 'data-1p-ignore': true });
    const pw2 = h('input.input', { id: 'drive-rev-pw2', type: 'password', autocomplete: 'new-password', maxlength: '128', 'data-lpignore': 'true', 'data-1p-ignore': true });
    const pwBox = h('div.drive-share-pw', { hidden: true }, field('Password', pw1), field('Repeat the password', pw2));
    pwOn.addEventListener('change', () => { pwBox.hidden = !pwOn.checked; if (pwOn.checked) pw1.focus(); });
    // A link adds key material to the Drive: confirmed like an API key (password, or a passkey).
    const confirmIn = h('input.input', { id: 'drive-rev-confirm', type: 'password', autocomplete: 'current-password', maxlength: '1024', spellcheck: 'false' });
    const confirmText = h('label.field-label', { for: 'drive-rev-confirm', text: 'Your account password (to confirm it is you)' });
    let withPasskey = false;
    (deps.canUsePasskey || canUsePasskey)().then((ok) => { withPasskey = !!ok; confirmText.textContent = confirmLabel('Your account password (to confirm it is you)', withPasskey); }).catch(() => {});
    const confirm = deps.confirm || ((input) => confirmStep(input, deps.profile?.user?.username, withPasskey));
    const listBox = h('div.drive-reverse-list', { id: 'drive-rev-list' }, h('p.msg', { role: 'status', text: 'Loading this folder’s links…' }));
    const form = h('div.drive-reverse-form', { id: 'drive-rev-form' },
      h('div.label-row', {}, h('label.field-label', { for: 'drive-rev-label', text: 'Label (optional, for your own reference)' }), labelIn, hint),
      field('Note to the people who upload (optional; encrypted, only link holders can read it)', noteIn),
      h('div.drive-reverse-grid', {},
        h('div.opt', { role: 'group', 'aria-labelledby': 'drive-rev-expire-l' }, h('label.opt-label', { id: 'drive-rev-expire-l', for: 'drive-rev-expire', text: 'Accept files for' }), expN, expU),
        field('Most files (empty: no limit)', files),
        field('Most in total, MB (empty: no limit)', maxMb),
        field('Largest file, MB (empty: no limit)', fileMb)),
      field('File types', typeMode), typeRules,
      h('label.viewer-opt', {}, pwOn, 'Ask uploaders for a password (it only lets them in; you never need it, and it does not encrypt anything)'),
      pwBox,
      h('div.dfield', {}, confirmText, confirmIn));
    const d = openDialog({
      title: `Receive files into “${folder.name}”`,
      sub: 'Anyone with the link can upload files and folders into this folder, without an account. They are encrypted in the uploader’s browser for you alone; you see them here the next time your Drive is unlocked. Uploads count towards your Drive’s storage.',
      body: [form, listBox],
      wide: true,
      fallback: focusPane,
    });
    const create = primary('Create link', async () => {
      d.clearError();
      const o = reverseOptions({ n: expN.value, unit: expU.value, maxFiles: files.value, maxMb: maxMb.value, fileMb: fileMb.value, typeMode: typeMode.value, typeRules: typeRules.value }, L);
      if (o.error) { d.error(o.error, { expire: expN, files, bytes: maxMb, file: fileMb, types: typeRules }[o.field] || null); return; }
      let password = '';
      if (pwOn.checked) {
        if (!pw1.value) { d.error('Enter a password, or turn the password off.', pw1); return; }
        if (pw1.value !== pw2.value) { d.error('Passwords do not match — repeat the same password in both fields.', pw2); return; }
        password = pw1.value;
      }
      create.disabled = true;
      create.querySelector('.send-txt').textContent = 'Creating…';
      confirmIn.removeAttribute('aria-invalid');
      try {
        const step = await confirm(confirmIn);
        const r = await client.createReverse(folder.id, { label: labelIn.value.trim(), note: noteIn.value.trim(), password, expire: o.expire, maxFiles: o.maxFiles, maxBytes: o.maxBytes, maxFileBytes: o.maxFileBytes, types: o.types, step });
        pw1.value = pw2.value = '';
        reverseResult(d, r, o, folder);
      } catch (e) {
        const confirmFailed = e && ['wrong_password', 'reauth_failed', 'reauth_required', 'invalid_credential'].includes(e.code);
        d.error(confirmFailed ? 'That did not confirm it is you — enter your account password again.' : friendlyError(e), confirmFailed ? confirmIn : null);
        create.disabled = false;
        create.querySelector('.send-txt').textContent = 'Create link';
      }
    });
    d.setActions(btn('Cancel', () => d.close(), 'modal-btn'), create);
    labelIn.focus();
    reverseList(d, listBox, folder);
  }

  /** The link, a copy button and a QR code. */
  function linkBlock(url, idBase) {
    const u = h('div.url.mono', { id: `${idBase}-url`, text: url });
    const copy = h('button.copy-btn', { type: 'button', id: `${idBase}-copy`, text: 'copy link' });
    copy.addEventListener('click', async () => flashCopied(copy, (await copyText(url)) ? 'copied' : 'failed'));
    const nodes = [h('div.linkrow', {}, u, copy)];
    try {
      if (typeof window.qrcode !== 'function') throw new Error('qr unavailable');
      const qr = window.qrcode(0, 'M');
      qr.addData(url);
      qr.make();
      nodes.push(h('div.card.qr.drive-qr', {}, h('img', { src: qr.createDataURL(4, 10), alt: 'QR code for the upload link' })));
    } catch { /* no QR on this page */ }
    return { nodes, copy };
  }

  function reverseResult(d, r, o, folder) {
    d.setTitle('Your upload link');
    d.subEl.textContent = `Anyone with this link can send files into “${folder.name}” for ${o.expiryText}, within the limits you chose. Keep it to the people you want files from — the key that encrypts their uploads for you is inside the link. Revoke it any time here or under “my shares”; files already received stay.`;
    d.subEl.hidden = false;
    const { nodes, copy } = linkBlock(r.url, 'drive-rev');
    d.setBody(...nodes);
    d.setActions(primary('Done', () => d.close()));
    copy.focus();
  }

  async function reverseList(d, box, folder) {
    let rows;
    try {
      rows = await client.reverseShares(folder.id);
    } catch (e) {
      box.replaceChildren(h('p.msg.error', { text: `This folder’s links could not be loaded: ${friendlyError(e)}` }));
      return;
    }
    if (!d.open) return;
    const draw = () => {
      if (!rows.length) { box.replaceChildren(h('p.mono.muted', { id: 'drive-rev-none', text: 'No upload links for this folder yet.' })); return; }
      const now = Math.floor(Date.now() / 1000);
      const tb = h('tbody');
      for (const s of rows) {
        const active = s.status === 'active';
        const cell = h('td.cell-actions');
        const row = h('div.btn-row');
        if (s.url && active) {
          row.appendChild(h('button.btn.tree-btn', { type: 'button', text: 'Copy link', 'aria-label': `Copy the link ${s.label || ''}`.trim(), on: { click: async (e) => flashCopied(e.currentTarget, (await copyText(s.url)) ? 'copied' : 'failed') } }));
        }
        if (active && s.locked) row.appendChild(h('span.mono.muted', { text: 'Locked by the administrator.' }));
        else if (active) {
          const rv = h('button.btn.danger.tree-btn', { type: 'button', text: 'Revoke', 'aria-label': `Revoke ${s.label || 'this link'}` });
          armConfirm(rv, 'Revoke now', async () => {
            rv.disabled = true;
            try { await deps.revoke(s.id); s.status = 'revoked'; toast('Link revoked. Files already received stay.'); draw(); d.box.focus(); } catch (e) { rv.disabled = false; d.error(friendlyError(e)); }
          });
          row.appendChild(rv);
        }
        cell.appendChild(row);
        tb.appendChild(h('tr', { dataset: { status: s.status || '' } },
          h('td', { dataset: { label: 'Label' }, text: s.label || '(no label)' }),
          h('td.mono', { dataset: { label: 'Created' }, text: formatDate(s.created) }),
          h('td.mono', { dataset: { label: 'Expires' }, text: s.expires ? (active && s.expires > now ? `in ${formatCoarse(s.expires - now)}` : formatDate(s.expires)) : '—' }),
          h('td.mono', { dataset: { label: 'Received' }, text: `${s.files} file${s.files === 1 ? '' : 's'}, ${formatBytes(s.bytes)}` }),
          h('td.mono', { dataset: { label: 'Status' }, text: `${s.status}${s.password ? ' · password' : ''}` }),
          cell));
      }
      box.replaceChildren(h('h3.field-label', { id: 'drive-rev-list-h', text: 'Upload links of this folder' }),
        h('div.table-wrap', {}, h('table.table', { id: 'drive-rev-table', 'aria-labelledby': 'drive-rev-list-h' },
          h('thead', {}, h('tr', {}, ...['Label', 'Created', 'Expires', 'Received', 'Status'].map((t) => h('th', { scope: 'col', text: t })), h('th', { scope: 'col' }, h('span.sr-only', { text: 'Actions' })))),
          tb)));
    };
    draw();
  }

  /** Take in what reverse shares have received (re-wrapped into this Drive's own format). */
  async function takeInReceived() {
    let added = 0;
    let failed = 0;
    try {
      for (let round = 0; round < 20; round++) {
        const r = await client.receivePending();
        added += r.added;
        failed = r.failed;
        if (!r.more || !r.added) break;
      }
    } catch (e) {
      showMsg(receivedMsg, `Received files could not be added now: ${friendlyError(e)}`);
      return;
    }
    if (added) {
      toast(`Added ${added} received file${added === 1 ? '' : 's'}.`);
      await refresh();
    }
    if (failed) showMsg(receivedMsg, `${failed} received file${failed === 1 ? '' : 's'} could not be opened with your Drive's key and ${failed === 1 ? 'was' : 'were'} not added.`, false);
    else if (added) showMsg(receivedMsg, `${added} new received file${added === 1 ? ' was' : 's were'} added to your folders.`, false);
  }

  // ── an item's shares ───────────────────────────────────────────────────
  async function sharesDialog(it) {
    const status = h('p.msg', { role: 'status', text: 'Loading…' });
    const d = openDialog({ title: `Shares of “${it.name}”`, sub: 'Links that include this item. Revoking a link ends it for everyone; the item stays in your Drive.', body: [status], wide: true, fallback: focusPane });
    d.setActions(h('a.btn.modal-btn', { href: '/dashboard/shares/', text: 'All my shares' }), btn('Close', () => d.close(), 'modal-btn'));
    let rows;
    try {
      rows = await client.shares(it.id);
    } catch (e) {
      status.textContent = '';
      d.error(friendlyError(e));
      return;
    }
    if (!d.open) return;
    const draw = () => {
      if (!rows.length) { d.setBody(h('p.msg', { id: 'drive-shares-empty', text: 'No shares of this item yet. Select it and choose Share… to create one.' })); return; }
      const now = Math.floor(Date.now() / 1000);
      const tb = h('tbody');
      for (const s of rows) {
        const active = s.status === 'active';
        const views = viewsText(s);
        const expires = s.expires ? (active && s.expires > now ? `in ${formatCoarse(s.expires - now)}` : formatDate(s.expires)) : '—';
        const cell = h('td.cell-actions');
        if (active && s.locked) cell.appendChild(h('span.mono.muted', { text: 'Locked by the administrator.' }));
        else if (active) {
          const rv = h('button.btn.danger.tree-btn', { type: 'button', text: 'Revoke', 'aria-label': `Revoke ${s.label || 'this share'}` });
          armConfirm(rv, 'Revoke now — irreversible', async () => {
            rv.disabled = true;
            try { await deps.revoke(s.id); s.status = 'revoked'; toast('Share revoked.'); draw(); d.box.focus(); } catch (e) { rv.disabled = false; d.error(friendlyError(e)); }
          });
          cell.appendChild(rv);
        }
        tb.appendChild(h('tr', { dataset: { status: s.status || '' } },
          h('td', { dataset: { label: 'Label' }, text: s.label || '(no label)' }),
          h('td.mono', { dataset: { label: 'Type' }, text: KIND_NAMES[s.kind] || 'drive' }),
          h('td.mono', { dataset: { label: 'Created' }, text: formatDate(s.created) }),
          h('td.mono', { dataset: { label: 'Expires' }, text: expires }),
          h('td.mono', { dataset: { label: 'Views' }, text: views }),
          h('td.mono', { dataset: { label: 'Status' }, text: s.status || '—' }),
          cell));
      }
      d.setBody(h('div.table-wrap', {}, h('table.table', { id: 'drive-shares-table' },
        h('caption.sr-only', { text: `Shares of ${it.name}` }),
        h('thead', {}, h('tr', {}, ...['Label', 'Type', 'Created', 'Expires', 'Views', 'Status'].map((t) => h('th', { scope: 'col', text: t })), h('th', { scope: 'col' }, h('span.sr-only', { text: 'Actions' })))),
        tb)));
    };
    draw();
  }

  // ── start ──────────────────────────────────────────────────────────────
  refreshUsage();
  const ready = tree.ready.then(() => open(ROOT));
  const received = ready.then(() => takeInReceived());
  return {
    el: mount.firstChild,
    ready,
    received,
    tree,
    open,
    refresh,
    get current() { return current; },
    get selected() { return new Set(selected); },
  };
}
