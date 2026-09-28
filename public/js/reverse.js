// reverse.js — the uploader page of a reverse share, /r/<id>#<key>
// (docs/REVERSE.md §8): anyone with the link sends files and folders to the
// person who shared it, without an account. The page shows that person's
// note (decrypted here with the link's key), the link's limits, a password
// field when the link has one, a file picker, a folder picker and drag and
// drop, and progress. Files, their names, folders and types are encrypted in
// this browser (public/js/reverseclient.js); the server stores only
// ciphertext. DOM through h() only (strict CSP + Trusted Types).
//
// A link with the CAPTCHA (its user's role and choice): this page never loads
// the Turnstile script. It seals the link's key for this tab and goes to the
// check page first (public/js/pagekey.js), and comes back with a grant; each
// grant starts one upload session (a wrong password or a second batch of
// files needs the CAPTCHA again).

import { h, clear, showMsg, formatBytes, formatDate, friendlyError, nameEl } from './common.js';
import { ApiError } from './api.js';
import { progressBar } from './progress.js';
import { walkEntry } from './walk.js';
import { openLink as realOpenLink, checkFiles, LinkError } from './reverseclient.js';
import { tabStorage, readPageKey, takeKey, goToCheck as realGoToCheck, loadGrant, saveGrant, CHECK_REFUSED } from './pagekey.js';

// This document's page key (src/index.js, on a real navigation): read once.
const docPageKey = typeof document !== 'undefined' ? readPageKey(document) : null;

/** The limits as one sentence, e.g. "Up to 5 files · 1 GB in total · 100 MB per file · only .pdf files". */
export function limitsText(l = {}) {
  const parts = [];
  if (l.filesLeft !== null && l.filesLeft !== undefined) parts.push(`${l.filesLeft} more file${l.filesLeft === 1 ? '' : 's'} at most`);
  if (l.bytesLeft !== null && l.bytesLeft !== undefined) parts.push(`${formatBytes(l.bytesLeft)} in total`);
  if (l.maxFileBytes !== null && l.maxFileBytes !== undefined) parts.push(`${formatBytes(l.maxFileBytes)} per file`);
  if (l.types && Array.isArray(l.types.rules) && l.types.rules.length) {
    const list = l.types.rules.map((r) => r.replace(/^ext:/, '.').replace(/^mime:/, '')).join(', ');
    parts.push(l.types.mode === 'allow' ? `only ${list}` : `no ${list}`);
  }
  return parts.length ? `This link accepts ${parts.join(' · ')}.` : 'This link accepts any files.';
}

// A paused link (its user started their Drive over; docs/DRIVE.md §3.2): it may accept files again later.
const PAUSED_TITLE = 'This link is not accepting files right now';
const PAUSED_TEXT = 'Nothing you send can be received at the moment. Try again later, or ask the person who shared it.';

function errorCard(title, text) {
  return h('div.card.stack', { id: 'reverse-error' },
    h('h1.title', { text: title }),
    h('p.subtitle', { role: 'alert', text }));
}

/**
 * Mount the uploader in `root`. deps (for tests): { location, history,
 * openLink, storage, pageKey, goToCheck }. Resolves to
 * { state: 'ready' | 'error' | 'check', app? }.
 */
export async function mountUploader(root, deps = {}) {
  const loc = deps.location || globalThis.location;
  const win = { location: loc, history: deps.history || globalThis.history };
  const openLink = deps.openLink || realOpenLink;
  const storage = 'storage' in deps ? deps.storage : tabStorage();
  const pageKey = 'pageKey' in deps ? deps.pageKey : docPageKey;
  const goToCheck = deps.goToCheck || realGoToCheck;
  clear(root).append(h('p.msg', { role: 'status', text: 'Opening the upload link…' }));
  const id = (/^\/r\/([^/]+)\/?$/.exec(String(loc.pathname)) || [])[1] || '';
  let hash = loc.hash;
  // Back from the check page: the key sealed for this tab, back in the address bar.
  if (new URLSearchParams(loc.search || '').has('n')) {
    const f = storage && id ? await takeKey({ kind: 'r', id, pageKey, storage }) : null;
    win.history.replaceState(null, '', f ? `${loc.pathname}#${f}` : loc.pathname);
    hash = f ? `#${f}` : '';
  }
  let up;
  try {
    up = await openLink({ pathname: loc.pathname, hash });
  } catch (e) {
    if (e instanceof LinkError) root.replaceChildren(errorCard('This link does not work', e.message));
    else if (e instanceof ApiError && e.code === 'paused') root.replaceChildren(errorCard(PAUSED_TITLE, PAUSED_TEXT));
    else if (e instanceof ApiError && e.status === 410) root.replaceChildren(errorCard('This link no longer accepts files', 'It has expired or was revoked by the person who shared it. Ask them for a new link.'));
    else if (e instanceof ApiError && e.status === 423) root.replaceChildren(errorCard('This link is paused', 'The administrator has locked it. Try again later or ask the person who shared it.'));
    else root.replaceChildren(errorCard('The link could not be opened', friendlyError(e)));
    return { state: 'error' };
  }
  // The CAPTCHA (the link has it and the server has Turnstile keys): first the check page.
  const toCheck = async () => {
    saveGrant({ kind: 'r', id: up.id, storage, grant: null });
    root.replaceChildren(h('p.msg', { role: 'status', text: 'This link requires a CAPTCHA. Taking you to it…' }));
    const r = await goToCheck({ kind: 'r', id: up.id, fragment: hash.replace(/^#/, ''), pageKey, storage, win });
    if (r !== 'leaving') root.replaceChildren(errorCard('The CAPTCHA cannot be shown', CHECK_REFUSED[r]));
    return r;
  };
  if (up.head.captcha === true) {
    up.humanGrant = storage ? loadGrant({ kind: 'r', id: up.id, storage }) : null;
    if (!up.humanGrant) { await toCheck(); return { state: 'check' }; }
  }
  return { state: 'ready', app: buildApp(root, up, { storage, toCheck }) };
}

function buildApp(root, up, { storage, toCheck }) {
  let entries = []; // { path, file }
  let busy = false;

  const fileIn = h('input', { type: 'file', id: 'reverse-file-input', multiple: true, hidden: true });
  const folderIn = h('input', { type: 'file', id: 'reverse-folder-input', multiple: true, webkitdirectory: true, hidden: true });
  const pickFiles = h('button.btn', { type: 'button', id: 'reverse-pick-files', text: 'Choose files', on: { click: () => fileIn.click() } });
  const pickFolder = h('button.btn', { type: 'button', id: 'reverse-pick-folder', text: 'Choose a folder', on: { click: () => folderIn.click() } });
  const drop = h('div.dropzone', { id: 'reverse-drop', tabindex: '0', role: 'group', 'aria-labelledby': 'reverse-drop-title', 'aria-describedby': 'reverse-drop-hint' },
    h('p.dropzone-title', { id: 'reverse-drop-title', text: 'Drop files or folders here' }),
    h('p.mono.dropzone-hint', { id: 'reverse-drop-hint', text: 'Names, folders, types and contents are encrypted in your browser before they are sent.' }),
    h('div.btn-row.center', {}, pickFiles, pickFolder));
  const list = h('ul.reverse-list', { id: 'reverse-list', 'aria-label': 'Files to send' });
  const total = h('p.mono.file-total', { id: 'reverse-total', 'aria-live': 'polite' });
  const clearBtn = h('button.linkbtn', { type: 'button', id: 'reverse-clear', text: 'Clear the list', hidden: true });

  const pw = up.needsPassword ? h('input.input', { id: 'reverse-password', type: 'password', autocomplete: 'off', maxlength: '1024', spellcheck: 'false', 'data-lpignore': 'true', 'data-1p-ignore': true }) : null;
  const pwBox = pw ? h('div.dfield', { id: 'reverse-password-box' },
    h('label.field-label', { for: 'reverse-password', text: 'Password for this link' }), pw,
    h('p.mono.muted', { id: 'reverse-password-hint', text: 'The person who shared the link gave it to you. It only lets you upload; it does not encrypt your files.' })) : null;
  if (pw) pw.setAttribute('aria-describedby', 'reverse-password-hint');

  const send = h('button.cta', { type: 'button', id: 'reverse-send', text: 'Send files', disabled: true });
  // A link with the CAPTCHA: each session start spends the grant; the next needs the CAPTCHA again.
  const captcha = up.head.captcha === true;
  const recheck = h('button.btn', { type: 'button', id: 'reverse-recheck', text: 'Complete the CAPTCHA again', hidden: true, 'aria-describedby': 'reverse-msg' });
  recheck.addEventListener('click', () => toCheck());
  const spendGrant = () => {
    up.humanGrant = null;
    saveGrant({ kind: 'r', id: up.id, storage, grant: null });
  };
  const bar = progressBar();
  const cancel = h('button.btn', { type: 'button', id: 'reverse-cancel', text: 'Cancel', hidden: true });
  const msg = h('p.msg.error', { id: 'reverse-msg', role: 'alert', hidden: true });
  const done = h('p.msg', { id: 'reverse-done', role: 'status', hidden: true });

  const note = up.note ? h('div.card.reverse-note', { id: 'reverse-note' },
    h('p.field-label', { text: 'A note from the person who shared this link' }),
    h('p.reverse-note-text', { text: up.note })) : null;

  root.replaceChildren(h('div.stack.reverse', { id: 'reverse-page' },
    h('div.head', {},
      h('p.eyebrow', { text: 'encrypted upload' }),
      h('h1.title', { text: 'Send files' }),
      h('p.subtitle', { text: 'What you send here — the files, their names and their types — is encrypted in your browser before it is sent, to a key of the person who shared this link. The server keeps that key under their Drive keys, which it holds: the server can decrypt what you send, as it can their other Drive files. No account is needed.' })),
    note,
    h('p.mono.muted', { id: 'reverse-limits', text: `${limitsText(up.limits)} The link expires ${formatDate(up.head.expires)}.` }),
    drop, fileIn, folderIn, list, total, clearBtn,
    pwBox,
    send,
    h('div.drive-transfer', {}, bar.el, cancel),
    msg, recheck, done));
  const needCheck = (text) => {
    showMsg(msg, `${text} Your chosen files are not kept: choose them again after the CAPTCHA.`);
    recheck.hidden = false;
    recheck.focus();
  };

  const render = () => {
    clear(list).append(...entries.slice(0, 200).map((e) => h('li.mono', {}, nameEl(e.path), ` — ${formatBytes(e.file.size)}`)),
      ...(entries.length > 200 ? [h('li.mono', { text: `… and ${entries.length - 200} more` })] : []));
    const bytes = entries.reduce((n, e) => n + e.file.size, 0);
    total.textContent = entries.length ? `${entries.length} file${entries.length === 1 ? '' : 's'}, ${formatBytes(bytes)}` : '';
    clearBtn.hidden = !entries.length || busy;
    send.disabled = busy || !entries.length;
    for (const b of [pickFiles, pickFolder]) b.disabled = busy;
  };
  const add = (more) => {
    msg.hidden = true;
    done.hidden = true;
    entries = entries.concat(more.filter((e) => e.file));
    render();
  };
  fileIn.addEventListener('change', () => { const f = [...fileIn.files]; fileIn.value = ''; add(f.map((file) => ({ path: file.name, file }))); });
  folderIn.addEventListener('change', () => { const f = [...folderIn.files]; folderIn.value = ''; add(f.map((file) => ({ path: file.webkitRelativePath || file.name, file }))); });
  clearBtn.addEventListener('click', () => { entries = []; render(); drop.focus(); });
  drop.addEventListener('keydown', (e) => { if ((e.key === 'Enter' || e.key === ' ') && e.target === drop) { e.preventDefault(); fileIn.click(); } });
  drop.addEventListener('dragover', (e) => { if (!busy) { e.preventDefault(); drop.classList.add('over'); } });
  drop.addEventListener('dragleave', (e) => { if (!drop.contains(e.relatedTarget)) drop.classList.remove('over'); });
  drop.addEventListener('drop', async (e) => {
    e.preventDefault();
    drop.classList.remove('over');
    if (busy) return;
    const got = [];
    const walks = [];
    for (const item of e.dataTransfer?.items || []) {
      const entry = typeof item.webkitGetAsEntry === 'function' ? item.webkitGetAsEntry() : null;
      if (entry) walks.push(entry);
      else if (item.kind === 'file') { const f = item.getAsFile(); if (f) got.push({ path: f.name, file: f }); }
    }
    // Empty folders are not sent (only files can be received).
    for (const entry of walks) await walkEntry(entry, (path, file) => { got.push({ path, file }); }, () => {});
    if (!walks.length && !got.length) for (const f of e.dataTransfer?.files || []) got.push({ path: f.name, file: f });
    add(got);
  });

  let ctl = null;
  cancel.addEventListener('click', () => { if (ctl) ctl.abort(); });
  send.addEventListener('click', async () => {
    if (busy || !entries.length) return;
    msg.hidden = true;
    done.hidden = true;
    if (pw) pw.removeAttribute('aria-invalid');
    const c = checkFiles(entries, up.limits);
    if (!c.ok) { showMsg(msg, c.error); return; }
    if (pw && !pw.value) { showMsg(msg, 'Enter the password for this link.'); pw.setAttribute('aria-invalid', 'true'); pw.focus(); return; }
    if (captcha && !up.humanGrant) { needCheck('This link needs the CAPTCHA again before each sending.'); return; }
    recheck.hidden = true;
    busy = true;
    render();
    ctl = new AbortController();
    try {
      bar.set('Checking…', null);
      const humanGrant = up.humanGrant;
      if (captcha) spendGrant(); // used by this session start, whatever its answer
      await up.begin({ password: pw ? pw.value : '', humanGrant });
      cancel.hidden = false;
      const label = c.count === 1 ? `Sending ${entries[0].path}` : `Sending ${c.count} files`;
      const r = await up.upload(entries, { signal: ctl.signal, onProgress: (d, t) => bar.set(`${label}…`, t > 0 ? d / t : 1) });
      await up.done().catch(() => {});
      bar.done(`${label}: done`);
      if (up.limits.filesLeft !== null && up.limits.filesLeft !== undefined) up.limits.filesLeft = Math.max(0, up.limits.filesLeft - r.files);
      if (up.limits.bytesLeft !== null && up.limits.bytesLeft !== undefined) up.limits.bytesLeft = Math.max(0, up.limits.bytesLeft - r.bytes);
      document.getElementById('reverse-limits').textContent = `${limitsText(up.limits)} The link expires ${formatDate(up.head.expires)}.`;
      entries = [];
      showMsg(done, `Sent ${r.files} file${r.files === 1 ? '' : 's'} (${formatBytes(r.bytes)}), encrypted. The person who shared this link will find ${r.files === 1 ? 'it' : 'them'} in their Drive.${captcha ? ' To send more, complete the CAPTCHA again.' : ''}`, false);
      recheck.hidden = !captcha;
      if (pw) pw.value = '';
    } catch (e) {
      bar.hide();
      await up.done().catch(() => {});
      if (e && e.name === 'AbortError') showMsg(msg, 'Cancelled. Files not yet sent were not kept.');
      else if (e instanceof ApiError && e.code === 'bad_password') {
        if (captcha) needCheck('That password is not right. Complete the CAPTCHA again, then try again with the right password.');
        else showMsg(msg, 'That password is not right. Check it and try again.');
        if (pw) { pw.setAttribute('aria-invalid', 'true'); pw.setAttribute('aria-describedby', 'reverse-password-hint reverse-msg'); if (!captcha) { pw.focus(); pw.select?.(); } }
      } else if (e instanceof ApiError && e.code === 'captcha_required') needCheck('The CAPTCHA for this link has expired or was already used.');
      else if (e instanceof ApiError && e.code === 'password_locked') {
        const until = Number.isSafeInteger(e.extra.until) ? ` after ${formatDate(e.extra.until)}` : ' later';
        showMsg(msg, `Too many wrong passwords were tried for this link. Try again${until}.`);
      } else if (e instanceof ApiError && e.code === 'paused') showMsg(msg, `${PAUSED_TITLE}. ${PAUSED_TEXT}`);
      else if (e instanceof ApiError && e.status === 410) showMsg(msg, 'This link no longer accepts files: it has expired or was revoked.');
      else showMsg(msg, friendlyError(e));
    } finally {
      busy = false;
      ctl = null;
      cancel.hidden = true;
      render();
    }
  });
  render();
  return { root, get entries() { return entries; }, add, send, recheck };
}

// The page itself.
const mount = typeof document !== 'undefined' ? document.getElementById('reverse-app') : null;
if (mount) mountUploader(mount);
