// drive-app.js — Dashboard → Drive (docs/DRIVE.md §8): the folder tree on the
// left (public/js/tree.js, collapsed by default), the selected folder's files
// and folders on the right (name, size, modified), and the actions: upload
// (files, folders, drag and drop), new folder, rename, move, delete, download,
// Share… (the composer's share options) and each item's shares with revoke.
// A capacity bar; a plain notice when the role has no Drive. The Drive opens
// with no prompt (the server hands the session its keys: docs/DRIVE.md §3);
// while the owner acts as a user it is that user's Drive. A Drive made before
// the key model v2 is upgraded here, with its progress shown (docs/DRIVE.md
// §3.3).
//
// Everything cryptographic lives behind the Drive client (public/js/
// driveclient.js, public/js/driveupgrade.js, docs/DRIVE.md §3, §8.1); this
// module only moves names and bytes between it and the DOM, which is built
// with h() only (strict CSP + Trusted Types). `startDrive(mount, deps)` is the
// entry point (public/dashboard/js/drive.js passes the client module); it is
// separate from the boot so it can be tested.

import { h, clear, showMsg, armConfirm, formatBytes, formatDate, formatCoarse, friendlyError, unencryptedHint, KIND_NAMES, viewsText, nameEl, shareLifetimeNote } from '../../js/common.js';
import { toast, copyText, flashCopied } from '../../js/ui.js';
import { createTree, crumbTrail } from '../../js/tree.js';
import { progressBar } from '../../js/progress.js';
import { walkEntry } from '../../js/walk.js';
import { expireSeconds, MAX_VIEWS } from '../../js/format.js';
import { utf8 } from '../../js/bytes.js';
import { normalizeRules } from '../../js/filepolicy.js';
import { confirmStep, confirmLabel, canUsePasskey } from './confirm.js';
import { cleanName } from '../../js/files.js';
import { captchaBox } from '../../js/captcha.js';
import { SESSION_CHANGED_EVENT } from '../../js/api.js';

export const ROOT = 'root';
const ROOT_NAME = 'My Drive';
const UNIT_WORDS = { m: ['minute', 'minutes'], h: ['hour', 'hours'], d: ['day', 'days'] };
const MAX_NAME_BYTES = 255; // as the client (driveclient.js checkName)

// ── pure helpers (unit-tested) ──────────────────────────────────────────────

/**
 * A node name as typed → { name, renamed? } or { error }: trimmed, cleaned
 * (files.js cleanName: bidi overrides and isolates, U+200B, U+FEFF and line
 * separators removed, NFC; `renamed` when that changed it). Hebrew, Arabic,
 * ZWNJ / ZWJ and LRM / RLM are kept. Names are encrypted, so only the client
 * checks them.
 */
export function checkName(raw) {
  const typed = String(raw ?? '').trim().normalize('NFC');
  const name = cleanName(typed).trim();
  if (!name) return { error: 'Enter a name.' };
  if (utf8(name).length > MAX_NAME_BYTES) return { error: `Names can be at most ${MAX_NAME_BYTES} bytes long.` };
  if (/[/\\]/.test(name)) return { error: 'Names cannot contain / or \\.' };
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(name)) return { error: 'Names cannot contain control characters.' };
  if (name === '.' || name === '..') return { error: 'That name is reserved.' };
  return name === typed ? { name } : { name, renamed: true };
}

/** How many of `names` lose characters to cleanName (told to the user after an upload). */
const renamedCount = (names) => names.filter((n) => cleanName(n) !== n).length;
const RENAMED = (n) => `${n === 1 ? '1 name' : `${n} names`} had hidden direction or spacing characters, removed: ${n === 1 ? 'it was' : 'they were'} renamed.`;

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
  // A Drive share is a file share: its download window can outlive the last view.
  return shareLifetimeNote({ what, views, expiryText, files: true })
    + ' Keep the whole link private — the key that unlocks it is inside the link. Deleting the item from your Drive ends the link at once; ending the link keeps the item. Manage it later under “my shares”.';
}

// ── dialogs ─────────────────────────────────────────────────────────────────
let dlgSeq = 0;

/**
 * A modal dialog (the composer's .modal look): named by its title, focus moved
 * in and trapped, Escape or the scrim closes, the rest of the page inert, and
 * focus back on the opener (or `fallback()`) when it closes.
 */
// The Drive dialogs open now (closed all at once when the session ends).
const openDialogs = new Set();

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
  // A toast from before the dialog (already said) is about the page behind it: put away, so that
  // nothing outside the modal dialog is shown or read (a toast raised while it is open still is).
  const oldToast = document.getElementById('toast');
  if (oldToast && oldToast.classList.contains('show')) { oldToast.classList.remove('show'); oldToast.textContent = ''; }
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
    openDialogs.delete(close);
    scrim.remove();
    for (const el of inerted) el.inert = false;
    document.removeEventListener('keydown', onKey, true);
    if (opener && opener.isConnected && !opener.disabled && typeof opener.focus === 'function') opener.focus();
    else if (fallback) fallback();
    if (onClose) onClose();
  }
  // A click on the scrim closes it, on the up-event and only when the press
  // also began there (WCAG 2.5.2): a drag out of a field never closes it.
  let downOnScrim = false;
  scrim.addEventListener('pointerdown', (e) => { downOnScrim = e.target === scrim; });
  scrim.addEventListener('click', (e) => { if (e.target === scrim && downOnScrim) close(); downOnScrim = false; });
  document.body.appendChild(scrim);
  for (const el of inerted) el.inert = true;
  document.addEventListener('keydown', onKey, true);
  openDialogs.add(close);
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
      if (c.renamed) toast(`Saved as “${c.name}”: hidden direction or spacing characters were removed.`);
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
 * DriveDisabled, DriveUnavailable), upgrade: driveupgrade.js (optional: the
 * page loads it when the Drive waits for its upgrade), profile
 * (/api/private/me), user ({ id, role, impersonating }, from the profile),
 * revoke(shareId) }. Resolves to { state: 'open' | 'disabled' |
 * 'unavailable' | 'error', app? }.
 */
export async function startDrive(mount, deps) {
  // The page's status line (in the page from the start: a live region that
  // appears together with its text is often not read) says "Opening…", then,
  // when the page shows a notice instead of the Drive, that notice's title
  // (WCAG 4.1.3); the notice itself is content, with its heading.
  const status = pageStatus(mount) || mount.querySelector(':scope > p.msg[role="status"]') || h('p.msg', { role: 'status' });
  status.dataset.driveStatus = '';
  status.textContent = 'Opening your Drive…';
  if (status.parentNode !== mount || mount.children.length !== 1) mount.replaceChildren(status);
  const notice = (card) => {
    status.className = 'sr-only';
    mount.append(card);
    const t = card.querySelector('h2');
    status.textContent = t ? t.textContent : '';
  };
  let client;
  try {
    client = await deps.drive.openDrive({ user: deps.user });
  } catch (e) {
    if (deps.drive.DriveDisabled && e instanceof deps.drive.DriveDisabled) { notice(disabledNotice()); return { state: 'disabled' }; }
    if (deps.drive.DriveUnavailable && e instanceof deps.drive.DriveUnavailable) { notice(unavailableNotice(e, deps)); return { state: 'unavailable', reason: e.reason }; }
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

/** The Drive's keys cannot be had now: what happened, and who can fix it. */
function unavailableNotice(e, deps) {
  const owner = deps.user && deps.user.role === 'owner' && !deps.user.impersonating;
  const text = e.reason === 'salt_missing'
    ? 'This account’s user salt, one of the values its Drive keys are made from, is missing on the server. Nothing was deleted. It comes back from your personal kit (Account → Drive personal kit → Restore) or from the administrator’s key kit.'
    : 'The server’s Drive keys are missing, so no Drive can be opened right now. Nothing was deleted. The administrator restores them from the key kit (Admin → Security → Keys).';
  return h('div.card.drive-notice', { id: 'drive-unavailable', dataset: { reason: e.reason || '' } },
    h('h2.section-title', { text: 'Your Drive cannot be opened right now' }),
    h('p.msg.error', { text }), // content: the page's status line says the title
    h('div.btn-row', {}, e.reason === 'salt_missing' ? h('a.btn', { href: '/dashboard/account/#drive-kit', text: 'Personal kit' }) : null,
      owner ? h('a.btn', { href: '/dashboard/admin/#keys', text: 'Admin → Security → Keys' }) : null));
}

/** The page's status line (startDrive), when there is one. */
const pageStatus = (mount) => mount.querySelector(':scope > [data-drive-status]');

/**
 * Show `nodes` in the mount instead of what is there, keeping the page's
 * status line in place (never removed and put back: it must be in the page
 * before what it says changes, WCAG 4.1.3); it is then visually hidden.
 */
function swap(mount, ...nodes) {
  const s = pageStatus(mount);
  if (!s) { mount.replaceChildren(...nodes); return null; }
  for (const c of [...mount.childNodes]) if (c !== s) c.remove();
  s.className = 'sr-only';
  mount.append(...nodes.filter(Boolean));
  return s;
}

// ── notices above the Drive ─────────────────────────────────────────────────

/** The banners over an open Drive: the owner acting as its user, and the upgrade of a Drive made before the key model v2. */
function banners(client, deps) {
  const out = [];
  if (deps.user && deps.user.impersonating) {
    const who = deps.profile && deps.profile.user ? deps.profile.user.username : 'this user';
    out.push(h('div.card.drive-notice.drive-imp-note', { id: 'drive-imp-note', role: 'note' },
      h('p', { text: `You are in ${who}’s Drive: browse, upload, download, move, rename, delete and share as they would.` }),
      h('p.muted', { text: `The server gave you ${who}’s Drive keys as the administrator; that is recorded in the admin audit. What you do here shows in their activity as their own, and in the admin audit as yours.` })));
  }
  if (client.migration) out.push(upgradeBox(client, deps));
  return out;
}

/**
 * A Drive made before the key model v2 (docs/DRIVE.md §3.3): its items are
 * re-sealed under the new keys here, with the progress shown. The old key
 * opened at sign-in is used when this tab has it; otherwise the account
 * password (or a recovery code), or a recovery kit of that release, opens it
 * once. Reverse links whose key the old key does not open are listed, to be
 * retired (with the step-up) so that the upgrade can finish. The owner acting
 * as a user upgrades that Drive from Admin → Security → Keys instead.
 */
function upgradeBox(client, deps) {
  const m = client.migration;
  const box = h('div.card.drive-notice', { id: 'drive-upgrade', role: 'status' }, h('h2.section-title', { text: 'Your Drive is being upgraded' }));
  const left = (m.v1Items || 0) + (m.v1Links || 0);
  const what = h('p', { text: `${left} item${left === 1 ? '' : 's'} still use${left === 1 ? 's' : ''} the Drive keys of the previous release. They are sealed again under the new keys, in this browser, and checked before the old keys are removed. Until then ${left === 1 ? 'it shows' : 'they show'} as “waiting for the upgrade”.` });
  const bar = progressBar();
  const msg = h('p.msg.error', { id: 'drive-upgrade-msg', role: 'alert', hidden: true });
  box.append(what, bar.el, msg);
  if (deps.user && deps.user.impersonating) {
    what.textContent = `${left} item${left === 1 ? '' : 's'} of this Drive still use${left === 1 ? 's' : ''} the Drive keys of the previous release: upgrade this Drive from Admin → Security → Keys (return to admin first).`;
    bar.hide();
    return box;
  }
  const loadUpgrade = async () => deps.upgrade || import('../../js/driveupgrade.js');
  const progress = (p) => bar.set(p.phase === 'verify' ? `Checking… ${p.done} verified` : `Upgrading… ${p.done} done, ${p.left} left`, p.phase === 'verify' ? 0.95 : toFraction(p.done, p.done + (p.left || 0)));
  const finished = (r) => {
    bar.done('Upgrade: done');
    box.replaceChildren(h('h2.section-title', { text: 'Your Drive is upgraded' }),
      h('p', { text: `Every item now uses the new Drive keys${r.damaged ? `; ${r.damaged} item${r.damaged === 1 ? '' : 's'} could not be opened with the old keys either and ${r.damaged === 1 ? 'was' : 'were'} kept as “damaged”` : ''}${r.retired ? `; ${r.retired} link${r.retired === 1 ? '' : 's'} whose key did not open ${r.retired === 1 ? 'was' : 'were'} ended` : ''}.` }));
    client.migration = null;
    if (deps.onUpgraded) deps.onUpgraded(r);
  };
  const run = async () => {
    msg.hidden = true;
    bar.set('Upgrading…', 0);
    try {
      const upgrade = await loadUpgrade();
      const cur = client.keys.current;
      const r = await upgrade.upgradeOwnDrive({ user: deps.user, current: cur, kek: client.keys.keks.get(cur)[0], onProgress: progress });
      if (r.unopened && r.unopened.length) { bar.hide(); box.append(retireForm(r)); return; }
      finished(r);
    } catch (e) {
      bar.hide();
      if (e && e.name === 'UpgradeBlocked' && (e.reason === 'locked' || e.reason === 'wrong')) { box.append(unlockForm()); return; } // no old key in the tab, or not this Drive's (removed)
      showMsg(msg, `The upgrade stopped: ${friendlyError(e)} It carries on where it stopped the next time this page opens.`);
    }
  };
  // Links of the previous release whose key the old key does not open: they hold the upgrade until retired.
  const retireForm = (r) => {
    const n = r.unopened.length;
    const pw = h('input.input', { id: 'drive-retire-pw', type: 'password', autocomplete: 'current-password', maxlength: '1024' });
    const label = h('label.field-label', { for: 'drive-retire-pw', text: 'Your password, to confirm' });
    let withPasskey = false;
    (deps.canUsePasskey || canUsePasskey)().then((ok) => { withPasskey = !!ok; label.textContent = confirmLabel('Your password, to confirm', ok); }).catch(() => {});
    const confirm = deps.confirm || ((input) => confirmStep(input, deps.profile?.user?.username, !input.value && withPasskey));
    const go = h('button.btn.danger', { type: 'submit', id: 'drive-retire-btn', text: `Retire ${n === 1 ? 'this link' : 'these links'}` });
    const form = h('form.form.drive-unlock-form', { id: 'drive-retire-form', novalidate: true },
      h('p', { text: `${n} “Receive files” link${n === 1 ? '' : 's'} of the previous release could not be opened with your Drive’s old key (${n === 1 ? 'its' : 'their'} key is damaged, or was sealed under a Drive you started over). The upgrade finishes once ${n === 1 ? 'it is' : 'they are'} retired: ${n === 1 ? 'the link ends, its key is removed' : 'the links end, their keys are removed'}, and files received but not taken in are listed as failed, to be deleted. Files already in your Drive are not affected.` }),
      h('ul.plan-list.mono', {}, ...r.unopened.map((id) => h('li', { text: id }))),
      h('div.dfield', {}, label, pw), go);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      go.disabled = true;
      try {
        const step = await confirm(pw);
        const upgrade = await loadUpgrade();
        bar.set('Finishing…', 0.9);
        const x = await upgrade.retireLinks({ ids: r.unopened, step, onProgress: progress });
        form.remove();
        if (x.done) finished({ ...r, retired: x.retired });
        else await run();
      } catch (err) {
        go.disabled = false;
        bar.hide();
        showMsg(msg, friendlyError(err));
      }
    });
    return form;
  };
  // The old key, when the sign-in could not open it (e.g. a passkey without PRF): the password once, or a recovery kit of that release.
  const unlockForm = () => {
    const pw = h('input.input', { id: 'drive-upgrade-pw', type: 'password', autocomplete: 'current-password', maxlength: '1024' });
    const go = h('button.btn', { type: 'submit', id: 'drive-upgrade-btn', text: 'Upgrade now' });
    const form = h('form.form.drive-unlock-form', { id: 'drive-upgrade-form', novalidate: true }, field('Your account password (or a recovery code), once, to open the old keys', pw), go);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!pw.value) { showMsg(msg, 'Enter your password.'); pw.focus(); return; }
      go.disabled = true;
      try {
        const upgrade = await loadUpgrade();
        const v = pw.value.trim();
        pw.value = '';
        await upgrade.legacyUnlock({ user: deps.user, ...(/^[0-9A-Za-z]{4}(-?[0-9A-Za-z]{4}){3}$/.test(v) ? { code: v, password: v } : { password: v }) });
        wrap.remove();
        await run();
      } catch (err) {
        go.disabled = false;
        showMsg(msg, friendlyError(err));
      }
    });
    const kitFile = h('input.input', { id: 'drive-upgrade-kit', type: 'file', accept: '.json,application/json' });
    const kitPass = h('input.input', { id: 'drive-upgrade-kit-pass', type: 'password', autocomplete: 'off', maxlength: '1024' });
    const kitGo = h('button.btn', { type: 'submit', id: 'drive-upgrade-kit-btn', text: 'Open with the kit' });
    const kitForm = h('form.form.drive-unlock-form', { id: 'drive-upgrade-kit-form', novalidate: true },
      h('p.type-hint', { text: 'No password, code or passkey opens the old keys any more? A Drive recovery kit you downloaded before this release does (the file never leaves this browser).' }),
      field('Recovery kit file of the previous release', kitFile), field('Its passphrase', kitPass), kitGo);
    kitForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = kitFile.files && kitFile.files[0];
      if (!f) { showMsg(msg, 'Choose the kit file.'); kitFile.focus(); return; }
      kitGo.disabled = true;
      try {
        const upgrade = await loadUpgrade();
        const passphrase = kitPass.value;
        kitPass.value = '';
        await upgrade.legacyUnlockWithKit({ user: deps.user, text: await f.text(), passphrase });
        wrap.remove();
        await run();
      } catch (err) {
        kitGo.disabled = false;
        showMsg(msg, friendlyError(err));
      }
    });
    const wrap = h('div.stack', { id: 'drive-upgrade-unlock' }, form, h('details', {}, h('summary', { text: 'Use a recovery kit of the previous release' }), kitForm));
    return wrap;
  };
  // At most once per page: it resumes where it stopped.
  queueMicrotask(run);
  return box;
}

// ── the Drive ───────────────────────────────────────────────────────────────

function mountApp(mount, client, deps) {
  const L = (deps.profile && deps.profile.limits) || {};
  let current = ROOT;
  // The folder being opened (current until it has loaded) and whether that open was asked to move
  // focus: a refresh in the background (received files taken in) re-lists where the person is
  // going, not where they were, and a superseded open's focus is not lost (WCAG 3.2.5, 2.4.3).
  let target = ROOT;
  let focusDue = false;
  let listing = null;
  let busy = false;
  let openSeq = 0;
  const selected = new Set();
  const recent = new Map(); // id → { at, promise }: one fetch serves the tree and the pane

  // The page stops acting for this session: it ended (session-timeout.js, which also clears the
  // tab's key slots: 'secbin:session-ended'), or the browser is now signed in as someone else
  // (another tab signed in, or started or ended impersonation: api.js SESSION_CHANGED_EVENT). The
  // Drive closes: its keys go from the client, and what it showed (decrypted names, open
  // dialogs) from the page; opening it again takes a reload (after signing in).
  const closeDrive = (changed) => () => {
    window.removeEventListener('secbin:session-ended', onEnded);
    window.removeEventListener(SESSION_CHANGED_EVENT, onChanged);
    client.forget();
    recent.clear();
    for (const close of [...openDialogs]) close();
    const said = swap(mount, h('div.card.drive-notice', { id: 'drive-closed', dataset: { why: changed ? 'changed' : 'ended' } },
      h('h2.section-title', { text: 'Your Drive was closed' }),
      h('p', { text: changed
        ? 'The browser is now signed in as someone else, so this page closed the Drive and dropped its keys. Reload to open the Drive of the account signed in now.'
        : 'Your session ended, so this page closed your Drive and dropped its keys. Sign in again, then reload this page to open your Drive.' }),
      h('div.btn-row', {}, h('button.btn', { type: 'button', id: 'drive-closed-reload', text: 'Reload', on: { click: () => location.reload() } }))));
    if (said) said.textContent = 'Your Drive was closed';
  };
  const onEnded = closeDrive(false);
  const onChanged = closeDrive(true);
  window.addEventListener('secbin:session-ended', onEnded);
  window.addEventListener(SESSION_CHANGED_EVENT, onChanged);

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
  // Inside a status line that is in the page from the start (a live region shown with its text is often not read).
  const receivedMsg = h('p.msg.drive-received', { id: 'drive-received', hidden: true });
  const receivedLive = h('div', { id: 'drive-received-live', role: 'status' }, receivedMsg);
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
  // The <label> around each box is its pointer target (at least 24×24 CSS px,
  // 44×44 on narrow screens: WCAG 2.5.8). "Select all" shows its text where the
  // table turns into cards (below 640px); its name is that text (2.5.3).
  const selAll = h('input', { type: 'checkbox', id: 'drive-select-all' });
  const caption = h('caption.sr-only', { id: 'drive-caption' });
  const tbody = h('tbody', { id: 'drive-rows' });
  const table = h('table.table.drive-table', { id: 'drive-table' }, caption,
    h('thead', {}, h('tr', {},
      h('th.cell-check', { scope: 'col' }, h('label.check-hit.drive-selall', {}, selAll, h('span.drive-selall-text', { text: 'Select all in this folder' }))),
      h('th', { scope: 'col', text: 'Name' }), h('th', { scope: 'col', text: 'Size' }), h('th', { scope: 'col', text: 'Modified' }),
      h('th', { scope: 'col' }, h('span.sr-only', { text: 'Shares' })))),
    tbody);
  const empty = h('p.msg.drive-empty', { id: 'drive-empty', hidden: true, text: 'This folder is empty. Upload files or drop them here.' });
  const paneMsg = h('p.msg.error', { id: 'drive-pane-msg', role: 'alert', hidden: true });
  const dropHint = h('p.mono.muted.drive-drop-hint', { text: 'Drop files or folders here to upload them to this folder. Contents, names and folders are encrypted in your browser before they are sent.' });
  const pane = h('section.drive-pane', { id: 'drive-pane', 'aria-labelledby': 'drive-pane-title' },
    crumbs, title, h('div.table-wrap', {}, table), empty, paneMsg, dropHint);
  const layout = h('div.drive-layout', { id: 'drive-layout' }, treeToggle, treePane, pane);

  treeToggle.addEventListener('click', () => {
    const on = !layout.classList.contains('tree-open');
    layout.classList.toggle('tree-open', on);
    treeToggle.setAttribute('aria-expanded', String(on));
    if (on) tree.focus();
  });

  // Once upgraded (a Drive of the previous release), the folder shows its items again.
  const withRefresh = { ...deps, onUpgraded: () => { refresh(); if (deps.onUpgraded) deps.onUpgraded(); } };
  // When focus is in what this replaces, focus goes to the folder's heading, not the page (WCAG
  // 2.4.3), unless the person moved it meanwhile.
  const hadFocus = !!deps.focusTitle || (mount.contains(document.activeElement) && document.activeElement !== mount);
  const app = h('div.drive', { id: 'drive-app' }, ...banners(client, withRefresh), cap, toolbar, fileIn, folderIn, transferBox, msg, receivedLive, layout);
  const said = swap(mount, app);
  // A notice above the Drive is said by the page's status line (its title), once.
  if (said) said.textContent = app.querySelector('[data-say]')?.dataset.say || '';

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
    target = id;
    if (focus) focusDue = true;
    paneMsg.hidden = true;
    let r;
    try {
      r = await fetchList(id);
    } catch (e) {
      if (n !== openSeq) return false;
      target = current; // nothing opened: a refresh stays where the person is
      focusDue = false;
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
    if (focusDue) { focusDue = false; title.focus(); }
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
    const name = c.name || (c.upgrading ? '(waiting for the upgrade)' : '(unnamed)');
    const check = h('input', { type: 'checkbox', 'aria-label': `Select ${name}`, checked: selected.has(c.id) });
    check.addEventListener('change', () => { if (check.checked) selected.add(c.id); else selected.delete(c.id); updateButtons(); });
    const nameCell = c.kind === 'dir'
      ? h('button.tree-open.drive-open', { type: 'button', title: `Open ${name}`, on: { click: () => open(c.id, { focus: true }) } }, h('span.tree-icon', { 'aria-hidden': 'true' }), c.name ? nameEl(name) : h('span', { text: name }))
      : h('span.drive-fname', {}, c.name ? nameEl(name) : h('span', { text: name }),
        // A received file whose name was cleaned when it was taken in (or an older name with such characters).
        c.renamed ? h('span.tree-sub.mono.renamed-note', { text: ' renamed: hidden characters removed' }) : null);
    const sharesBtn = h('button.btn.tree-btn', { type: 'button', text: 'Shares', 'aria-label': `Shares of ${name}`, on: { click: () => sharesDialog(c) } });
    return h('tr', { dataset: { id: c.id, kind: c.kind } },
      h('td.cell-check', {}, h('label.check-hit', {}, check)),
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
    await open(target);
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
      sub: `In ${title.textContent}. The name is encrypted in your browser before it is sent.`,
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
      body: [h('ul.drive-del-list', {}, ...items.slice(0, 8).map((i) => h('li.mono', {}, nameEl(i.name || '(unnamed)', { suffix: i.kind === 'dir' ? '/' : '' }))), items.length > 8 ? h('li.mono', { text: `… and ${items.length - 8} more` }) : null)],
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
      // A name already in the folder gets " (2)", " (3)"… (one read of the folder for the batch).
      const { names: taken } = await client.names(target);
      for (const f of files) {
        await client.upload(target, f, { signal, taken, onProgress: (d) => progress(done + d, total) });
        done += f.size;
      }
    });
    const renamed = renamedCount(files.map((f) => f.name));
    if (ok && renamed) toast(RENAMED(renamed));
    if (ok || done) await refresh([target]);
  }

  async function uploadEntries(entries) {
    if (!entries.length) return;
    const target = current;
    const top = new Set(entries.map((e) => e.path.split('/')[0]));
    const files = entries.filter((e) => !e.dir).length;
    const label = top.size === 1 && (entries[0].dir || entries[0].path.includes('/')) ? `Uploading ${[...top][0]}/` : `Uploading ${files} ${files === 1 ? 'file' : 'files'}`;
    const ok = await transfer(label, (progress, signal) => client.uploadTree(target, entries, { signal, onProgress: progress }));
    const renamed = renamedCount(entries.map((e) => e.path));
    if (ok && renamed) toast(RENAMED(renamed));
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
    const expU = h('select.input.opt-sel', { id: 'drive-share-unit', 'aria-label': 'Expires in: unit' },
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
    // The CAPTCHA, as the role says (public/js/captcha.js).
    const cap = captchaBox({ id: 'drive-share-captcha', profile: deps.profile, which: 'share' });
    const form = h('div.drive-share-form', {},
      h('div.drive-share-opts', {},
        h('div.opt', { role: 'group', 'aria-labelledby': 'drive-share-views-l' }, h('label.opt-label', { id: 'drive-share-views-l', for: 'drive-share-views', text: 'Views' }), views, inf),
        h('div.opt', { role: 'group', 'aria-labelledby': 'drive-share-expire-l' }, h('label.opt-label', { id: 'drive-share-expire-l', for: 'drive-share-expire', text: 'Expires in' }), expN, expU)),
      h('label.viewer-opt', {}, pwOn, 'Protect with a password (recipients need it in addition to the link)'),
      pwBox,
      L.openerDelete ? h('label.viewer-opt', {}, del, 'Let the recipient delete it at once (“Delete now”)') : null,
      viewer && viewer.enabled ? h('label.viewer-opt', {}, allowView, 'Allow recipients to view files in the browser') : null,
      cap.el,
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
        const r = await client.share(items.map((i) => i.id), { views: o.views, expire: o.expire, password, deletable: !!L.openerDelete && del.checked, label: label.value.trim(), limits: L, view, captcha: cap.value() });
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
    const expU = h('select.input.opt-sel', { id: 'drive-rev-unit', 'aria-label': 'Accept files for: unit' },
      h('option', { value: 'm', text: 'minutes' }), h('option', { value: 'h', text: 'hours' }), h('option', { value: 'd', text: 'days', selected: true }));
    expU.value = 'd';
    const files = h('input.input', { id: 'drive-rev-files', type: 'number', min: '1', max: '10000', step: '1', inputmode: 'numeric', placeholder: 'no limit' });
    const roleMax = L.reverseMaxBytes ?? null;
    const maxMb = h('input.input', { id: 'drive-rev-bytes', inputmode: 'decimal', placeholder: roleMax ? `up to ${formatBytes(roleMax)}` : 'no limit' });
    const fileMb = h('input.input', { id: 'drive-rev-filesize', inputmode: 'decimal', placeholder: 'no limit' });
    const typeMode = h('select.input', { id: 'drive-rev-types' },
      h('option', { value: 'any', text: 'any type' }), h('option', { value: 'allow', text: 'only the listed types' }), h('option', { value: 'block', text: 'all but the listed types' }));
    const typeRules = h('textarea.input.rules-in', { id: 'drive-rev-rules', rows: '2', placeholder: 'ext:pdf\next:docx\nmime:image/*' });
    // Its label is shown with it (WCAG 3.3.2), and both are hidden for "any type".
    const typeBox = field('The file types (one per line: ext:pdf, mime:image/*)', typeRules);
    typeBox.hidden = true;
    typeMode.addEventListener('change', () => { typeBox.hidden = typeMode.value === 'any'; if (!typeBox.hidden) typeRules.focus(); });
    const pwOn = h('input', { type: 'checkbox', id: 'drive-rev-pw-on' });
    const pw1 = h('input.input', { id: 'drive-rev-pw', type: 'password', autocomplete: 'new-password', maxlength: '128', 'data-lpignore': 'true', 'data-1p-ignore': true });
    const pw2 = h('input.input', { id: 'drive-rev-pw2', type: 'password', autocomplete: 'new-password', maxlength: '128', 'data-lpignore': 'true', 'data-1p-ignore': true });
    const pwBox = h('div.drive-share-pw', { hidden: true }, field('Password', pw1), field('Repeat the password', pw2));
    pwOn.addEventListener('change', () => { pwBox.hidden = !pwOn.checked; if (pwOn.checked) pw1.focus(); });
    // A link adds key material to the Drive: the user confirms it like an API
    // key (password, or a passkey). The owner acting as the user confirms nothing.
    const impersonating = !!(deps.user?.impersonating || deps.profile?.impersonatedBy);
    const confirmIn = h('input.input', { id: 'drive-rev-confirm', type: 'password', autocomplete: 'current-password', maxlength: '1024', spellcheck: 'false' });
    const confirmText = h('label.field-label', { for: 'drive-rev-confirm', text: 'Your account password (to confirm it is you)' });
    let withPasskey = false;
    if (!impersonating) (deps.canUsePasskey || canUsePasskey)().then((ok) => { withPasskey = !!ok; confirmText.textContent = confirmLabel('Your account password (to confirm it is you)', withPasskey); }).catch(() => {});
    const confirm = impersonating ? async () => ({}) : deps.confirm || ((input) => confirmStep(input, deps.profile?.user?.username, withPasskey));
    const listBox = h('div.drive-reverse-list', { id: 'drive-rev-list' }, h('p.msg', { role: 'status', text: 'Loading this folder’s links…' }));
    const cap = captchaBox({ id: 'drive-rev-captcha', profile: deps.profile, which: 'reverse' });
    const form = h('div.drive-reverse-form', { id: 'drive-rev-form' },
      h('div.label-row', {}, h('label.field-label', { for: 'drive-rev-label', text: 'Label (optional, for your own reference)' }), labelIn, hint),
      field('Note to the people who upload (optional; encrypted, only link holders can read it)', noteIn),
      h('div.drive-reverse-grid', {},
        h('div.opt', { role: 'group', 'aria-labelledby': 'drive-rev-expire-l' }, h('label.opt-label', { id: 'drive-rev-expire-l', for: 'drive-rev-expire', text: 'Accept files for' }), expN, expU),
        field('Most files (empty: no limit)', files),
        field('Most in total, MB (empty: no limit)', maxMb),
        field('Largest file, MB (empty: no limit)', fileMb)),
      field('File types', typeMode), typeBox,
      h('label.viewer-opt', {}, pwOn, 'Ask uploaders for a password (it only lets them in; you never need it, and it does not encrypt anything)'),
      pwBox,
      cap.el,
      h('div.dfield', { hidden: impersonating }, confirmText, confirmIn));
    const d = openDialog({
      title: `Receive files into “${folder.name}”`,
      sub: 'Anyone with the link can upload files and folders into this folder, without an account. They are encrypted in the uploader’s browser to this link’s key, which the server keeps under your Drive keys (so the server can open them, as it can your other Drive files); the next time your Drive opens they are taken in and sealed like your other files. Uploads count towards your Drive’s storage.',
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
      const failed = (text, el = null) => {
        d.error(text, el);
        create.disabled = false;
        create.querySelector('.send-txt').textContent = 'Create link';
      };
      let step;
      try {
        step = await confirm(confirmIn);
      } catch (e) {
        failed(e && e.code ? friendlyError(e) : (e && e.message) || 'Enter your account password.', confirmIn);
        return;
      }
      try {
        const r = await client.createReverse(folder.id, { label: labelIn.value.trim(), note: noteIn.value.trim(), password, expire: o.expire, maxFiles: o.maxFiles, maxBytes: o.maxBytes, maxFileBytes: o.maxFileBytes, types: o.types, step, captcha: cap.value() });
        pw1.value = pw2.value = '';
        reverseResult(d, r, o, folder);
      } catch (e) {
        const confirmFailed = e && ['wrong_password', 'reauth_failed', 'reauth_required', 'invalid_credential'].includes(e.code);
        failed(confirmFailed ? 'That did not confirm it is you — enter your account password again.' : friendlyError(e), confirmFailed ? confirmIn : null);
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
          row.appendChild(h('button.btn.tree-btn', { type: 'button', text: 'Copy link', 'aria-label': `Copy link${s.label ? ` ${s.label}` : ''}`, on: { click: async (e) => flashCopied(e.currentTarget, (await copyText(s.url)) ? 'copied' : 'failed') } }));
        }
        // A paused link (the owner started over) has not ended: it can be revoked too.
        const live = active || s.status === 'paused';
        if (live && s.locked) row.appendChild(h('span.mono.muted', { text: 'Locked by the administrator.' }));
        else if (live) {
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
          h('td.mono', { dataset: { label: 'Status' }, text: `${s.status}${s.password ? ' · password' : ''}${s.captcha ? ' · CAPTCHA' : ''}` }),
          cell));
      }
      box.replaceChildren(h('h3.field-label', { id: 'drive-rev-list-h', text: 'Upload links of this folder' }),
        h('div.table-wrap', {}, h('table.table', { id: 'drive-rev-table', 'aria-labelledby': 'drive-rev-list-h' },
          h('thead', {}, h('tr', {}, ...['Label', 'Created', 'Expires', 'Received', 'Status'].map((t) => h('th', { scope: 'col', text: t })), h('th', { scope: 'col' }, h('span.sr-only', { text: 'Actions' })))),
          tb)));
    };
    draw();
  }

  /**
   * Take in what reverse shares have received (re-wrapped into this Drive's
   * own format), then say what happened: added, renamed (hidden characters
   * removed), placed higher up (folders nested too deeply), and the files
   * that could not be added, with a way to review, delete or retry them.
   */
  async function takeInReceived() {
    let r;
    try {
      r = await client.receivePending();
    } catch (e) {
      showMsg(receivedMsg, `Received files could not be added now: ${friendlyError(e)}`);
      return;
    }
    if (r.added) {
      // The take-in runs in the background: a modal dialog opened meanwhile gets no toast about the
      // page behind it (nothing outside a modal dialog is shown or read); the status line below
      // says the same and stays.
      if (!document.querySelector('[aria-modal="true"]')) toast(`Added ${r.added} received file${r.added === 1 ? '' : 's'}.`);
      await refresh();
    }
    const n = (k, one, many) => `${k} ${k === 1 ? one : many}`;
    const parts = [];
    if (r.added) parts.push(`${n(r.added, 'new received file was', 'new received files were')} added to your folders.`);
    if (r.renamed) parts.push(`${n(r.renamed, 'name had', 'names had')} hidden direction or spacing characters, removed.`);
    if (r.flattened) parts.push(`${n(r.flattened, 'file was', 'files were')} in folders nested too deeply (or in too many new folders at once) and ${r.flattened === 1 ? 'was' : 'were'} put in the deepest folder allowed.`);
    if (r.deferred) parts.push(`${n(r.deferred, 'file', 'files')} could not be added now; ${r.deferred === 1 ? 'it is' : 'they are'} tried again the next time your Drive opens.`);
    await showReceived(parts);
  }

  /** The status line under the toolbar: `parts`, and the files that could not be added (with a Review button). */
  async function showReceived(parts) {
    let failed = { items: [], total: 0 };
    try { failed = await client.failedReceived(); } catch { /* the line says what it can */ }
    const count = Math.max(failed.items.length, failed.total || 0);
    const nodes = parts.length ? [h('span', { text: parts.join(' ') })] : [];
    if (count) {
      nodes.push(h('span', { text: `${nodes.length ? ' ' : ''}${count} received file${count === 1 ? '' : 's'} could not be added. ` }),
        h('button.linkbtn', { type: 'button', id: 'drive-received-review', text: 'Review them', on: { click: () => failedDialog() } }));
    }
    if (!nodes.length) { receivedMsg.hidden = true; receivedMsg.replaceChildren(); return; }
    receivedMsg.classList.remove('error');
    receivedMsg.replaceChildren(...nodes);
    receivedMsg.hidden = false;
  }

  const FAIL_TEXT = {
    unreadable: 'does not open with this Drive’s key (damaged, or not sent for this link)',
    name: 'its name or folder path cannot be used',
    place: 'your Drive refused it (full, or its folder is full)',
  };

  /** The received files that could not be added: link, size, time, why; delete or try again. */
  async function failedDialog() {
    const status = h('p.msg', { role: 'status', text: 'Loading…' });
    const d = openDialog({
      title: 'Received files that could not be added',
      sub: 'These uploads reached your Drive but could not be opened or placed. Their names are encrypted, so only the link, size and time are shown. Delete them to free the space, or try again (for example after making room).',
      body: [status], wide: true, fallback: focusPane,
    });
    d.setActions(btn('Close', () => d.close(), 'modal-btn'));
    let items = [];
    let more = false;
    let next = null;
    const load = async () => {
      const r = await client.failedReceived(next);
      items = items.concat(r.items);
      more = r.more;
      next = r.next;
    };
    try { await load(); } catch (e) { status.textContent = ''; d.error(friendlyError(e)); return; }
    const done = async (msgText) => { toast(msgText); await showReceived([]); };
    const draw = () => {
      if (!items.length) { d.setBody(h('p.msg', { id: 'drive-failed-none', text: 'Nothing left to review.' })); return; }
      const tb = h('tbody');
      for (const it of items) {
        const del = h('button.btn.danger.tree-btn', { type: 'button', text: 'Delete', 'aria-label': `Delete the ${formatBytes(it.size)} file received ${formatDate(it.created)}` });
        armConfirm(del, 'Delete now', async () => {
          del.disabled = true;
          try { await client.remove(it.id); items = items.filter((x) => x !== it); draw(); d.box.focus(); await done('Received file deleted.'); refreshUsage(); } catch (e) { del.disabled = false; d.error(friendlyError(e)); }
        });
        const again = h('button.btn.tree-btn', { type: 'button', text: 'Try again', 'aria-label': `Try again the ${formatBytes(it.size)} file received ${formatDate(it.created)}` });
        again.addEventListener('click', async () => {
          again.disabled = true;
          try {
            await client.retryReceived(it.id);
            items = items.filter((x) => x !== it);
            draw();
            d.box.focus();
            await takeInReceived();
          } catch (e) { again.disabled = false; d.error(friendlyError(e)); }
        });
        tb.appendChild(h('tr', { dataset: { id: it.id } },
          h('td', { dataset: { label: 'Link' }, text: it.label || '(no label)' }),
          h('td.mono', { dataset: { label: 'Size' }, text: formatBytes(Number(it.size) || 0) }),
          h('td.mono', { dataset: { label: 'Received' }, text: formatDate(it.created) }),
          h('td', { dataset: { label: 'Why' }, text: FAIL_TEXT[it.reason] || FAIL_TEXT.unreadable }),
          h('td.cell-actions', {}, h('div.btn-row', {}, again, del))));
      }
      const rows = [h('div.table-wrap', {}, h('table.table', { id: 'drive-failed-table' },
        h('caption.sr-only', { text: 'Received files that could not be added' }),
        h('thead', {}, h('tr', {}, ...['Link', 'Size', 'Received', 'Why'].map((t) => h('th', { scope: 'col', text: t })), h('th', { scope: 'col' }, h('span.sr-only', { text: 'Actions' })))),
        tb))];
      if (more) {
        rows.push(h('button.btn', { type: 'button', id: 'drive-failed-more', text: 'Show more', on: { click: async (e) => {
          e.currentTarget.disabled = true;
          const before = items.length;
          try {
            await load();
            draw();
            // The button is drawn again: focus goes to the first row just loaded, not the page (2.4.3).
            d.box.querySelector(`#drive-failed-table tbody tr:nth-child(${before + 1}) button`)?.focus();
          } catch (err) { d.error(friendlyError(err)); }
        } } }));
      }
      d.setBody(...rows);
    };
    draw();
  }

  // ── an item's shares ───────────────────────────────────────────────────
  async function sharesDialog(it) {
    const status = h('p.msg', { role: 'status', text: 'Loading…' });
    const d = openDialog({ title: `Shares of “${it.name}”`, sub: 'Links that include this item. Revoking a link ends it for everyone; the item stays in your Drive.', body: [status], wide: true, fallback: focusPane });
    d.setActions(h('a.btn.modal-btn', { href: '/dashboard/shares/', text: 'All my shares' }), btn('Close', () => d.close(), 'modal-btn'));
    // A folder's "Receive files" links are its shares too (they upload into it).
    const isDir = it.kind === 'dir';
    let rows;
    try {
      const [out, rev] = await Promise.all([client.shares(it.id), isDir ? client.reverseShares(it.id) : []]);
      rows = [...out, ...rev.map((r) => ({ ...r, kind: 'reverse' }))];
    } catch (e) {
      status.textContent = '';
      d.error(friendlyError(e));
      return;
    }
    if (!d.open) return;
    const draw = () => {
      if (!rows.length) {
        d.setBody(h('p.msg', { id: 'drive-shares-empty', text: isDir
          ? 'No shares or upload links of this folder yet. Select it and choose Share… or Receive files… to create one.'
          : 'No shares of this item yet. Select it and choose Share… to create one.' }));
        return;
      }
      const now = Math.floor(Date.now() / 1000);
      const tb = h('tbody');
      for (const s of rows) {
        const rev = s.kind === 'reverse';
        const active = s.status === 'active';
        // A paused upload link has not ended: it can be revoked too.
        const live = active || (rev && s.status === 'paused');
        const views = rev ? `${s.files} file${s.files === 1 ? '' : 's'} received` : viewsText(s);
        const expires = s.expires ? (active && s.expires > now ? `in ${formatCoarse(s.expires - now)}` : formatDate(s.expires)) : '—';
        const cell = h('td.cell-actions');
        const btns = h('div.btn-row');
        if (rev && s.url && active) {
          btns.appendChild(h('button.btn.tree-btn', { type: 'button', text: 'Copy link', 'aria-label': `Copy link${s.label ? ` ${s.label}` : ''}`, on: { click: async (e) => flashCopied(e.currentTarget, (await copyText(s.url)) ? 'copied' : 'failed') } }));
        }
        if (live && s.locked) btns.appendChild(h('span.mono.muted', { text: 'Locked by the administrator.' }));
        else if (live) {
          const rv = h('button.btn.danger.tree-btn', { type: 'button', text: 'Revoke', 'aria-label': `Revoke ${s.label || (rev ? 'this link' : 'this share')}` });
          armConfirm(rv, 'Revoke now — irreversible', async () => {
            rv.disabled = true;
            try { await deps.revoke(s.id); s.status = 'revoked'; toast(rev ? 'Link revoked. Files already received stay.' : 'Share revoked.'); draw(); d.box.focus(); } catch (e) { rv.disabled = false; d.error(friendlyError(e)); }
          });
          btns.appendChild(rv);
        }
        cell.appendChild(btns);
        tb.appendChild(h('tr', { dataset: { status: s.status || '', kind: s.kind || '' } },
          h('td', { dataset: { label: 'Label' }, text: s.label || '(no label)' }),
          h('td.mono', { dataset: { label: 'Type' }, text: KIND_NAMES[s.kind] || 'drive' }),
          h('td.mono', { dataset: { label: 'Created' }, text: formatDate(s.created) }),
          h('td.mono', { dataset: { label: 'Expires' }, text: expires }),
          h('td.mono', { dataset: { label: 'Views' }, text: views }),
          h('td.mono', { dataset: { label: 'Status' }, text: `${s.status || '—'}${s.captcha ? ' · CAPTCHA' : ''}` }),
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
  const ready = tree.ready.then(() => open(ROOT, { focus: hadFocus && (!document.activeElement || document.activeElement === document.body) }));
  const received = ready.then(() => takeInReceived());
  return {
    el: app,
    ready,
    received,
    tree,
    open,
    refresh,
    get current() { return current; },
    get selected() { return new Set(selected); },
    get client() { return client; },
  };
}
