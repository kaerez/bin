// reverse.js — the uploader page of a reverse share, /r/<id>#<key>
// (docs/REVERSE.md §8): anyone with the link sends files and folders — and,
// as the link accepts them, a note, a link or a credential — to the person
// who shared it, without an account. The page shows that person's note
// (decrypted here with the link's key), the link's limits, a password field
// when the link has one, one tab per kind the link accepts (a file picker, a
// folder picker and drag and drop; the composer's note editor with its
// format; a link field; the credential form), and progress. Everything sent
// is encrypted in this browser (public/js/reverseclient.js); the server
// stores only ciphertext. DOM through h() only (strict CSP + Trusted Types).
//
// A link with the CAPTCHA (its user's role and choice): this page never loads
// the Turnstile script. It seals the link's key for this tab and goes to the
// check page first (public/js/pagekey.js), and comes back with a grant; each
// grant starts one upload session (a wrong password or a second batch of
// files needs the CAPTCHA again).
//
// Accessibility (docs/WCAG22.md): the page title names the state; the kinds
// are an ARIA tablist (one Tab stop, arrow keys, as in the composer); the drop
// zone is a named group (not a Tab stop: its two buttons are the keyboard way,
// as in the composer); every field has a visible label; "Sent …" appears
// inside a status line that is in the page from the start; after a send,
// focus goes to the first control of the tab ("Choose files"), not the page.

import { h, clear, showMsg, formatBytes, formatDate, friendlyError, nameEl } from './common.js';
import { ApiError } from './api.js';
import { progressBar } from './progress.js';
import { walkEntry } from './walk.js';
import { tablistKeys } from './ui.js';
import { openLink as realOpenLink, checkFiles, checkItem, LinkError } from './reverseclient.js';
import { KIND_LABELS, KIND_PLURALS, NOTE_FORMATS, NOTE_FORMAT_LABELS, MAX_TITLE } from './receivekinds.js';
import { describeHost, parseShareUrl, SECRET_FIELDS } from './sharetypes.js';
import { tabStorage, readPageKey, takeKey, goToCheck as realGoToCheck, loadGrant, saveGrant, CHECK_REFUSED } from './pagekey.js';

// This document's page key (src/index.js, on a real navigation): read once.
const docPageKey = typeof document !== 'undefined' ? readPageKey(document) : null;

/** When the link stops taking files: its expiry, or none (the user revokes it). */
const expiryLine = (head) => (head.expires === null ? 'The link has no expiry: it takes files until it is revoked.' : `The link expires ${formatDate(head.expires)}.`);

/**
 * The limits as one sentence, e.g. "Up to 5 files · 1 GB in total · 100 MB per
 * file · only .pdf files". `accept`: what the link takes (a link that takes
 * more than files counts items: a note, link or credential is one each; the
 * per-file size and types are about files).
 */
export function limitsText(l = {}, accept = ['files']) {
  const onlyFiles = accept.length === 1 && accept[0] === 'files';
  const unit = onlyFiles ? 'file' : 'item';
  const parts = [];
  if (l.filesLeft !== null && l.filesLeft !== undefined) parts.push(`${l.filesLeft} more ${unit}${l.filesLeft === 1 ? '' : 's'} at most`);
  if (l.bytesLeft !== null && l.bytesLeft !== undefined) parts.push(`${formatBytes(l.bytesLeft)} in total`);
  if (accept.includes('files') && l.maxFileBytes !== null && l.maxFileBytes !== undefined) parts.push(`${formatBytes(l.maxFileBytes)} per file`);
  if (accept.includes('files') && l.types && Array.isArray(l.types.rules) && l.types.rules.length) {
    const list = l.types.rules.map((r) => r.replace(/^ext:/, '.').replace(/^mime:/, '')).join(', ');
    parts.push(l.types.mode === 'allow' ? `only ${list}` : `no ${list}`);
  }
  if (parts.length) return `This link accepts ${parts.join(' · ')}.`;
  return onlyFiles ? 'This link accepts any files.' : 'This link sets no limits on what you send.';
}

/** "files", "a note", … — what a page about sending names. */
const ONE = { files: 'files', note: 'a note', url: 'a link', secret: 'a credential' };
/** The page's heading from what the link accepts: "Send files", "Send a note or files", … */
export function sendTitle(accept) {
  const w = accept.map((k) => ONE[k]);
  return `Send ${w.length > 1 ? `${w.slice(0, -1).join(', ')} or ${w.at(-1)}` : w[0]}`;
}
/** The credential's warning on the uploader page (SECURITY.md, "Reverse shares"): the server can decrypt it. */
export const CREDENTIAL_WARNING = 'The recipient’s server can decrypt this. A credential sent here is encrypted in your browser, but to a key the server keeps under the recipient’s Drive keys, so it is not end-to-end encrypted: the server (and its administrator) could read it. If only the recipient may ever see it, send it another way.';

// A paused link (its user started their Drive over; docs/DRIVE.md §3.2): it may accept files again later.
const PAUSED_TITLE = 'This link is not accepting files right now';
const PAUSED_TEXT = 'Nothing you send can be received at the moment. Try again later, or ask the person who shared it.';

function errorCard(title, text) {
  document.title = `${title} · secbin`; // the page title names the state (WCAG 2.4.2)
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
    else if (e instanceof ApiError && e.status === 410) root.replaceChildren(errorCard('This link no longer accepts files', 'It has expired, was revoked, or has taken all the uploads the person who shared it allowed. Ask them for a new link.'));
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
  const accept = up.accept;
  let kind = accept[0];

  // ── files ──
  const fileIn = h('input', { type: 'file', id: 'reverse-file-input', multiple: true, hidden: true });
  const folderIn = h('input', { type: 'file', id: 'reverse-folder-input', multiple: true, webkitdirectory: true, hidden: true });
  const pickFiles = h('button.btn', { type: 'button', id: 'reverse-pick-files', text: 'Choose files', on: { click: () => fileIn.click() } });
  const pickFolder = h('button.btn', { type: 'button', id: 'reverse-pick-folder', text: 'Choose a folder', on: { click: () => folderIn.click() } });
  const drop = h('div.dropzone', { id: 'reverse-drop', role: 'group', 'aria-labelledby': 'reverse-drop-title', 'aria-describedby': 'reverse-drop-hint' },
    h('p.dropzone-title', { id: 'reverse-drop-title', text: 'Drop files or folders here' }),
    h('p.mono.dropzone-hint', { id: 'reverse-drop-hint', text: 'Names, folders, types and contents are encrypted in your browser before they are sent.' }),
    h('div.btn-row.center', {}, pickFiles, pickFolder));
  const list = h('ul.reverse-list', { id: 'reverse-list', 'aria-label': 'Files to send' });
  const total = h('p.mono.file-total', { id: 'reverse-total', 'aria-live': 'polite' });
  const clearBtn = h('button.linkbtn', { type: 'button', id: 'reverse-clear', text: 'Clear the list', hidden: true });

  // ── a note: the composer's editor, with its format and an optional title ──
  const noteTitle = h('input.input', { id: 'reverse-note-title', maxlength: String(MAX_TITLE), autocomplete: 'off', 'aria-describedby': 'reverse-note-title-hint' });
  const noteFmt = h('select.input', { id: 'reverse-note-fmt' }, ...NOTE_FORMATS.map((f) => h('option', { value: f, text: NOTE_FORMAT_LABELS[f] })));
  const noteText = h('textarea.input.reverse-editor', { id: 'reverse-note-text', rows: '10', spellcheck: 'false', 'aria-describedby': 'reverse-note-hint' });
  const notePanel = [
    field('Title (optional)', noteTitle, h('p.type-hint', { id: 'reverse-note-title-hint', text: 'The recipient’s Drive names the note after it; without one, “Note from” the date it arrives.' })),
    field('Format', noteFmt),
    field('Note', noteText, h('p.type-hint', { id: 'reverse-note-hint', text: 'Shown to the recipient as text: Markdown is rendered safely, code is highlighted. Nothing in it runs.' })),
  ];

  // ── a link ──
  const linkIn = h('input.input', { id: 'reverse-link-in', type: 'url', inputmode: 'url', maxlength: '2048', autocomplete: 'off', spellcheck: 'false', placeholder: 'https://example.com/document', 'aria-describedby': 'reverse-link-host' });
  const linkDefault = 'The recipient sees the real destination and must confirm before it opens — never an automatic redirect.';
  const linkHost = h('p.mono.type-hint', { id: 'reverse-link-host', 'aria-live': 'polite', text: linkDefault });
  linkIn.addEventListener('input', () => {
    linkHost.classList.remove('warn');
    if (!linkIn.value.trim()) { linkHost.textContent = linkDefault; linkIn.removeAttribute('aria-invalid'); return; }
    try {
      const d = describeHost(parseShareUrl(linkIn.value, { recipient: true }));
      linkIn.removeAttribute('aria-invalid');
      const notes = [];
      if (d.external) notes.push(d.openable ? `opens another app (${d.scheme}:)` : `a ${d.scheme}: link: the recipient can copy it but not open it from their page`);
      if (d.idn) notes.push(`shown to the recipient as ${d.ascii} — international characters can imitate another site`);
      if (d.insecure) notes.push('not HTTPS');
      clear(linkHost).append('Destination: ', h('bdi', { dir: 'ltr', text: d.unicode }), notes.length ? ` (${notes.join('; ')})` : '');
      if (notes.length) linkHost.classList.add('warn');
    } catch (e) {
      linkIn.setAttribute('aria-invalid', 'true');
      linkHost.textContent = e.message;
      linkHost.classList.add('warn');
    }
  });
  const linkPanel = [field('Link to send', linkIn, linkHost)];

  // ── a credential: the regular credential form ──
  const sec = {};
  const secRows = [];
  for (const [k, label, secret, attrs] of [
    ['title', 'Title', false, { placeholder: 'e.g. Staging database' }],
    ['username', 'User name', false, { spellcheck: 'false' }],
    ['password', 'Password', true, { autocomplete: 'new-password', spellcheck: 'false' }],
    ['url', 'Sign-in URL', false, { type: 'url', inputmode: 'url', spellcheck: 'false', placeholder: 'https://' }],
    ['totp', 'One-time-code seed', true, { spellcheck: 'false', placeholder: 'base32 seed or otpauth://totp/…' }],
  ]) {
    const input = h('input.input', { id: `reverse-sec-${k}`, maxlength: String(SECRET_FIELDS[k]), autocomplete: 'off', ...attrs, ...(secret ? { type: 'password' } : {}) });
    sec[k] = input;
    let ctl = input;
    if (secret) {
      const show = h('button.btn.sec-show', { type: 'button', id: `reverse-sec-${k}-show`, text: 'Show', 'aria-pressed': 'false', 'aria-label': `Show ${label.toLowerCase()}` });
      show.addEventListener('click', () => {
        const on = input.type === 'password';
        input.type = on ? 'text' : 'password';
        show.textContent = on ? 'Hide' : 'Show';
        show.setAttribute('aria-pressed', String(on));
      });
      ctl = h('span.inline-ctl', {}, input, show);
    }
    secRows.push(h('label.field-label', { for: input.id, text: label }), ctl);
  }
  sec.notes = h('textarea.input', { id: 'reverse-sec-notes', rows: '3', maxlength: String(SECRET_FIELDS.notes), spellcheck: 'false' });
  secRows.push(h('label.field-label', { for: 'reverse-sec-notes', text: 'Notes' }), sec.notes);
  const secretPanel = [
    h('p.type-hint.warn', { id: 'reverse-sec-warning', role: 'note', text: CREDENTIAL_WARNING }),
    h('p.mono.type-hint', { text: 'The recipient sees each field masked, with reveal and copy. Fill in the fields you need.' }),
    h('div.secret-grid', { role: 'group', 'aria-label': 'Credential', 'aria-describedby': 'reverse-sec-warning' }, ...secRows),
  ];
  const clearSecret = () => {
    for (const el of Object.values(sec)) { el.value = ''; if (el.id === 'reverse-sec-password' || el.id === 'reverse-sec-totp') el.type = 'password'; }
    for (const b of root.querySelectorAll('.sec-show')) { b.textContent = 'Show'; b.setAttribute('aria-pressed', 'false'); }
  };

  // One tab per kind the link accepts (none when it takes only one).
  const panels = {
    files: h('div', { id: 'reverse-panel-files' }, drop, fileIn, folderIn, list, total, clearBtn),
    note: h('div.type-panel.reverse-panel', { id: 'reverse-panel-note' }, ...notePanel),
    url: h('div.type-panel.reverse-panel', { id: 'reverse-panel-url' }, ...linkPanel),
    secret: h('div.type-panel.reverse-panel', { id: 'reverse-panel-secret' }, ...secretPanel),
  };
  const tabs = {};
  let tablist = null;
  if (accept.length > 1) {
    for (const k of accept) {
      tabs[k] = h('button.tab', { type: 'button', role: 'tab', id: `reverse-tab-${k}`, 'aria-controls': `reverse-panel-${k}`, 'aria-selected': String(k === kind), text: KIND_LABELS[k] });
      panels[k].setAttribute('role', 'tabpanel');
      panels[k].setAttribute('aria-labelledby', `reverse-tab-${k}`);
    }
    tablist = h('div.tabs', { role: 'tablist', id: 'reverse-tabs', 'aria-label': 'What to send' }, ...accept.map((k) => tabs[k]));
  }

  const pw = up.needsPassword ? h('input.input', { id: 'reverse-password', type: 'password', autocomplete: 'off', maxlength: '1024', spellcheck: 'false', 'data-lpignore': 'true', 'data-1p-ignore': true }) : null;
  const pwBox = pw ? h('div.dfield', { id: 'reverse-password-box' },
    h('label.field-label', { for: 'reverse-password', text: 'Password for this link' }), pw,
    h('p.mono.muted', { id: 'reverse-password-hint', text: 'The person who shared the link gave it to you. It only lets you upload; it does not encrypt what you send.' })) : null;
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
  // Inside a status line that is in the page from the start (a live region shown with its text is often not read).
  const done = h('p.msg', { id: 'reverse-done', hidden: true });
  const doneLive = h('div', { id: 'reverse-done-live', role: 'status' }, done);

  const note = up.note ? h('div.card.reverse-note', { id: 'reverse-note' },
    h('p.field-label', { text: 'A note from the person who shared this link' }),
    h('p.reverse-note-text', { text: up.note })) : null;

  const title = sendTitle(accept);
  document.title = `${title} · secbin`;
  root.replaceChildren(h('div.stack.reverse', { id: 'reverse-page', dataset: { accept: accept.join(' ') } },
    h('div.head', {},
      h('p.eyebrow', { text: 'encrypted upload' }),
      h('h1.title', { text: title }),
      h('p.subtitle', { text: accept.length === 1 && accept[0] === 'files'
        ? 'What you send here — the files, their names and their types — is encrypted in your browser before it is sent, to a key of the person who shared this link. The server keeps that key under their Drive keys, which it holds: the server can decrypt what you send, as it can their other Drive files. No account is needed.'
        : 'What you send here — files with their names and types, notes, links and credentials — is encrypted in your browser before it is sent, to a key of the person who shared this link. The server keeps that key under their Drive keys, which it holds: the server can decrypt what you send, as it can their other Drive files. No account is needed.' })),
    note,
    h('p.mono.muted', { id: 'reverse-limits', text: `${limitsText(up.limits, accept)} ${expiryLine(up.head)}` }),
    tablist,
    ...accept.map((k) => panels[k]),
    pwBox,
    send,
    h('div.drive-transfer', {}, bar.el, cancel),
    msg, recheck, doneLive));
  const needCheck = (text) => {
    showMsg(msg, `${text} ${kind === 'files' ? 'Your chosen files are not kept: choose them again after the CAPTCHA.' : 'What you typed is kept on this page until you leave it.'}`);
    recheck.hidden = false;
    recheck.focus();
  };

  const firstControl = () => ({ files: pickFiles, note: noteTitle, url: linkIn, secret: sec.title })[kind];
  const hasContent = () => (kind === 'files' ? entries.length > 0
    : kind === 'note' ? !!noteText.value.trim()
      : kind === 'url' ? !!linkIn.value.trim()
        : Object.values(sec).some((el) => el.value.trim()));
  const render = () => {
    clear(list).append(...entries.slice(0, 200).map((e) => h('li.mono', {}, nameEl(e.path), ` — ${formatBytes(e.file.size)}`)),
      ...(entries.length > 200 ? [h('li.mono', { text: `… and ${entries.length - 200} more` })] : []));
    const bytes = entries.reduce((n, e) => n + e.file.size, 0);
    total.textContent = entries.length ? `${entries.length} file${entries.length === 1 ? '' : 's'}, ${formatBytes(bytes)}` : '';
    clearBtn.hidden = !entries.length || busy;
    send.disabled = busy || !hasContent();
    for (const b of [pickFiles, pickFolder]) b.disabled = busy;
    for (const el of [noteTitle, noteFmt, noteText, linkIn, ...Object.values(sec), ...root.querySelectorAll('.sec-show')]) el.disabled = busy;
    for (const t of Object.values(tabs)) t.disabled = busy;
  };
  const setKind = (k) => {
    kind = k;
    for (const x of accept) {
      panels[x].hidden = x !== k;
      if (tabs[x]) tabs[x].setAttribute('aria-selected', String(x === k));
    }
    syncTabs();
    send.textContent = k === 'files' ? 'Send files' : `Send ${KIND_LABELS[k].toLowerCase()}`;
    msg.hidden = true;
    render();
  };
  let syncTabs = () => {};
  if (tablist) {
    for (const k of accept) tabs[k].addEventListener('click', () => { if (!busy) setKind(k); });
    syncTabs = tablistKeys(tablist, { automatic: true });
  }
  for (const el of [noteText, linkIn, ...Object.values(sec)]) el.addEventListener('input', () => { done.hidden = true; render(); });
  const add = (more) => {
    msg.hidden = true;
    done.hidden = true;
    entries = entries.concat(more.filter((e) => e.file));
    render();
  };
  fileIn.addEventListener('change', () => { const f = [...fileIn.files]; fileIn.value = ''; add(f.map((file) => ({ path: file.name, file }))); });
  folderIn.addEventListener('change', () => { const f = [...folderIn.files]; folderIn.value = ''; add(f.map((file) => ({ path: file.webkitRelativePath || file.name, file }))); });
  clearBtn.addEventListener('click', () => { entries = []; render(); pickFiles.focus(); });
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

  /** The form's values for a note, link or credential. */
  const values = () => (kind === 'note' ? { text: noteText.value, fmt: noteFmt.value, title: noteTitle.value }
    : kind === 'url' ? { url: linkIn.value }
      : Object.fromEntries(Object.entries(sec).map(([k, el]) => [k, el.value])));
  const invalidField = () => ({ note: noteText, url: linkIn, secret: sec.title })[kind];

  let ctl = null;
  let sent = false;
  cancel.addEventListener('click', () => { if (ctl) ctl.abort(); });
  send.addEventListener('click', async () => {
    if (busy || !hasContent()) return;
    msg.hidden = true;
    done.hidden = true;
    if (pw) pw.removeAttribute('aria-invalid');
    const sending = kind;
    const c = sending === 'files' ? checkFiles(entries, up.limits) : checkItem(sending, values(), up.limits);
    if (!c.ok) {
      showMsg(msg, c.error);
      if (sending !== 'files') {
        const f = invalidField();
        const by = (f.getAttribute('aria-describedby') || '').split(' ').filter(Boolean);
        f.setAttribute('aria-invalid', 'true');
        if (!by.includes('reverse-msg')) f.setAttribute('aria-describedby', [...by, 'reverse-msg'].join(' '));
        f.focus();
      }
      return;
    }
    invalidField()?.removeAttribute('aria-invalid');
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
      await up.begin({ password: pw ? pw.value : '', humanGrant, type: sending });
      cancel.hidden = false;
      // "Send" is disabled while it runs: focus goes to "Cancel", not the page (2.4.3).
      if (!document.activeElement || document.activeElement === document.body || document.activeElement === send) cancel.focus();
      const what = sending === 'files' ? null : KIND_LABELS[sending].toLowerCase();
      const label = what ? `Sending the ${what}` : c.count === 1 ? `Sending ${entries[0].path}` : `Sending ${c.count} files`;
      const onProgress = (d, t) => bar.set(`${label}…`, t > 0 ? d / t : 1);
      const r = sending === 'files' ? await up.upload(entries, { signal: ctl.signal, onProgress }) : await up.sendItem(sending, c, { signal: ctl.signal, onProgress });
      await up.done().catch(() => {});
      bar.done(`${label}: done`);
      if (up.limits.filesLeft !== null && up.limits.filesLeft !== undefined) up.limits.filesLeft = Math.max(0, up.limits.filesLeft - r.files);
      if (up.limits.bytesLeft !== null && up.limits.bytesLeft !== undefined) up.limits.bytesLeft = Math.max(0, up.limits.bytesLeft - r.bytes);
      document.getElementById('reverse-limits').textContent = `${limitsText(up.limits, accept)} ${expiryLine(up.head)}`;
      const again = captcha ? ' To send more, complete the CAPTCHA again.' : '';
      if (sending === 'files') {
        entries = [];
        showMsg(done, `Sent ${r.files} file${r.files === 1 ? '' : 's'} (${formatBytes(r.bytes)}), encrypted. The person who shared this link will find ${r.files === 1 ? 'it' : 'them'} in their Drive.${again}`, false);
      } else {
        if (sending === 'note') { noteText.value = ''; noteTitle.value = ''; noteFmt.value = 'plaintext'; }
        if (sending === 'url') { linkIn.value = ''; linkHost.textContent = linkDefault; linkHost.classList.remove('warn'); }
        if (sending === 'secret') clearSecret();
        showMsg(done, `Sent the ${what}, encrypted. The person who shared this link will find it in their Drive.${again}`, false);
      }
      recheck.hidden = !captcha;
      if (pw) pw.value = '';
      sent = true;
    } catch (e) {
      bar.hide();
      await up.done().catch(() => {});
      if (e && e.name === 'AbortError') showMsg(msg, sending === 'files' ? 'Cancelled. Files not yet sent were not kept.' : 'Cancelled. Nothing was kept.');
      else if (e instanceof ApiError && e.code === 'bad_password') {
        if (captcha) needCheck('That password is not right. Complete the CAPTCHA again, then try again with the right password.');
        else showMsg(msg, 'That password is not right. Check it and try again.');
        if (pw) { pw.setAttribute('aria-invalid', 'true'); pw.setAttribute('aria-describedby', 'reverse-password-hint reverse-msg'); if (!captcha) { pw.focus(); pw.select?.(); } }
      } else if (e instanceof ApiError && e.code === 'captcha_required') needCheck('The CAPTCHA for this link has expired or was already used.');
      else if (e instanceof ApiError && e.code === 'password_locked') {
        const until = Number.isSafeInteger(e.extra.until) ? ` after ${formatDate(e.extra.until)}` : ' later';
        showMsg(msg, `Too many wrong passwords were tried for this link. Try again${until}.`);
      } else if (e instanceof ApiError && e.code === 'kind_not_accepted') showMsg(msg, `This link does not accept ${KIND_PLURALS[sending]} now. Ask the person who shared it.`);
      else if (e instanceof ApiError && e.code === 'paused') showMsg(msg, `${PAUSED_TITLE}. ${PAUSED_TEXT}`);
      else if (e instanceof ApiError && e.status === 410) showMsg(msg, 'This link no longer accepts files: it has expired, was revoked, or has taken all the uploads it allows.');
      else showMsg(msg, friendlyError(e));
    } finally {
      busy = false;
      ctl = null;
      cancel.hidden = true;
      render();
      // Focus that fell to the page (the busy "Send", a hidden "Cancel") goes back: to the tab's first
      // control after a send (the form is empty, "Send" disabled), else to "Send" (2.4.3).
      const lost = !document.activeElement || document.activeElement === document.body || document.activeElement === cancel || document.activeElement === send;
      if (sent) firstControl().focus(); else if (lost) (send.disabled ? firstControl() : send).focus();
      sent = false;
    }
  });
  setKind(kind);
  return { root, get entries() { return entries; }, add, send, recheck, setKind, get kind() { return kind; } };
}

/** A field with its label above it (WCAG 3.3.2) and an optional hint. */
function field(label, input, hint = null) {
  return h('div.dfield', {}, h('label.field-label', { for: input.id, text: label }), input, hint);
}

// The page itself.
const mount = typeof document !== 'undefined' ? document.getElementById('reverse-app') : null;
if (mount) mountUploader(mount);
