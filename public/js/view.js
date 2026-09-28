// view.js — secbin public page: the landing (no composer — creating needs an
// account) and the viewer for /p/<id>#<key>. The fragment key never leaves the
// browser: it is turned into two access proofs (SPEC §5.4) which the server
// checks before releasing ciphertext or spending a view. All content is
// rendered with DOM construction only.
//
// A share with the CAPTCHA: this page never loads the Turnstile script (the
// strict CSP would refuse it anyway). On `captcha_required` it takes the key
// out of the address bar, seals it for this tab and goes to the check page;
// back from there (?n=…) it opens the sealed key and the share
// (public/js/pagekey.js, SECURITY.md "CAPTCHA on shares").

import './kdf-progress.js';
import { deriveAccess, openPaste, PasswordRequired, DecryptError } from './crypto.js';
import { validateHead, validatePaste } from './format.js';
import { validateManifest, buildTree, basename, cleanEntries } from './files.js';
import { fetchHead, openShare, expireShare, extendDownloads, session, ApiError, publicProfile, publicApi, setPublicAid, setPublicHumanCheck,
  setHumanGrant, humanGrantOf, setHumanGrantListener, shareHuman } from './api.js';
import { tabStorage, readPageKey, takeKey, goToCheck, loadGrant, saveGrant, CHECK_REFUSED } from './pagekey.js';
import { humanCheck } from './turnstile.js';
import { clearSessionKey } from './drivekeys.js';
import { ensureTracker } from './tracker.js';
import { $, showView, toast, copyText, pill, countdownSwitch } from './ui.js';
import { h, clear, showMsg, markInvalid, wirePeek, armConfirm, formatCoarse, formatDuration, formatBytes, friendlyError, nameEl } from './common.js';
import { ShareTypeError } from './sharetypes.js';
import { linkCard, secretCard, stopTotp, noteKind, drawNote } from './typedview.js';
import { itemExport, KIND_LABELS } from './receivekinds.js';
import { saveText } from './downloads.js';
import { ShareReader, RefsReader, saveFile, saveZip, MEMORY_WARN } from './downloads.js';
import { validateRefsManifest } from './refsmanifest.js';
import { allowedRenderer, renderPreview } from './viewer.js';
import { progressBar } from './progress.js';
import { folderBrowser } from './tree.js';

let timer = null;
let expirySwitch = null; // the share-expiry countdown's "Stop the countdown" switch
let expiryRender = null; // …and what it re-renders
/** The local date and time `ms` (the fixed form of a stopped countdown). */
const atTime = (ms) => new Date(ms).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
// The warning before a download window closes comes this long before (at least 20 s: WCAG 2.2.1).
const WINDOW_WARN_MS = 5 * 60 * 1000;
let keepAlive = null;
// This document's page key (src/index.js puts it in on a real navigation): read once, then gone from the DOM.
const pageKey = typeof document !== 'undefined' ? readPageKey(document) : null;

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
  // Loads alongside the composer; a share waits for the token only when created.
  // Its script (third-party) must never find a Drive key left in this tab.
  clearSessionKey();
  const check = humanCheck($('#public-turnstile'), 'public-share', { gate: [$('#create')] });
  setPublicHumanCheck(async () => (await check).take());
  const { startComposer } = await import('./composer.js');
  startComposer(prof, publicApi, { publicMode: true });
}

// ── viewer ───────────────────────────────────────────────────────────────────
/**
 * Back from the check page (?n=…): the key sealed for this tab, opened with
 * this document's page key, back in the address bar → the fragment, or null.
 */
async function keyFromCheck(id, storage) {
  const q = new URLSearchParams(location.search);
  if (!q.has('n')) return location.hash.slice(1);
  const fragment = storage ? await takeKey({ kind: 'p', id, pageKey, storage }) : null;
  history.replaceState(null, '', fragment ? `${location.pathname}#${fragment}` : location.pathname);
  return fragment;
}

/** The share has the CAPTCHA and this tab has no valid grant: to the check page. */
async function toCheck(id, fragment, storage) {
  stopKeepAlive();
  setHumanGrant(id, null);
  if (storage) saveGrant({ kind: 'p', id, storage, grant: null });
  status('This share requires a CAPTCHA. Taking you to it…');
  const r = await goToCheck({ kind: 'p', id, fragment, pageKey, storage });
  if (r !== 'leaving') status(CHECK_REFUSED[r], true);
}

function stopKeepAlive() { clearInterval(keepAlive); keepAlive = null; }
/** Keep the CAPTCHA grant alive while the share is open (downloads may come later). */
function startKeepAlive(kind, id) {
  stopKeepAlive();
  if (!humanGrantOf(id)) return;
  keepAlive = setInterval(() => { shareHuman(kind, id).catch(() => {}); }, 4 * 60 * 1000);
}

const captchaNeeded = (e) => e instanceof ApiError && e.code === 'captcha_required';

async function initView(id) {
  const newlink = $('#newlink');
  if (newlink) newlink.hidden = false;
  const storage = tabStorage();
  const fragment = await keyFromCheck(id, storage);
  if (!fragment) {
    return status(new URLSearchParams(location.search).has('n')
      ? 'This tab no longer holds the link\'s key. Open the whole link again (with the part after “#”).'
      : 'This link is missing its decryption key.', true);
  }
  const kind = id[0] === 'f' ? 'file' : 'paste';
  // A CAPTCHA grant this tab got on the check page (kept, renewed as it is used).
  if (storage) {
    setHumanGrant(id, loadGrant({ kind: 'p', id, storage }));
    setHumanGrantListener((sid, grant) => { if (sid === id) saveGrant({ kind: 'p', id, storage, grant }); });
  }

  status('checking…');
  let head;
  try {
    head = validateHead(await fetchHead(kind, id));
  } catch (e) {
    if (captchaNeeded(e)) return toCheck(id, fragment, storage);
    if (e instanceof ApiError || e.name === 'TypeError') return readError(e);
    return status('This link was made by an older or incompatible version and can no longer be opened.', true);
  }
  if ((head.adata.fmt === 'files') !== (kind === 'file')) return status('This link is malformed.', true);

  const limited = head.adata.bar && head.meta.left !== null;
  const needsPassword = head.adata.kdf === 'argon2id-hkdf';
  const open = async (password) => {
    try {
      await doOpen({ id, kind, head, fragment, password });
      startKeepAlive(kind, id);
    } catch (e) {
      // The grant lapsed before the open (nothing was spent): the CAPTCHA again.
      if (captchaNeeded(e)) { await toCheck(id, fragment, storage); return; }
      throw e;
    }
  };

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
      $('#receipt-note-reveal').hidden = true;
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
  // v2: one packed stream under one key; v3 (a Drive share): each file its own
  // chunk sequence under its own key (docs/DRIVE.md §7).
  let manifest;
  let reader;
  try {
    const m = JSON.parse(text);
    if (m && m.v === 3) {
      manifest = validateRefsManifest(m);
      reader = RefsReader.forShare({ id, grant: res.grant, refs: res.refs, manifest });
    } else {
      manifest = validateManifest(m);
    }
    // Clean first, then check again: a path that cleaning makes unsafe refuses the manifest.
    const cleaned = cleanManifest(manifest);
    if (cleaned !== manifest && reader) reader = RefsReader.forShare({ id, grant: res.grant, refs: res.refs, manifest: cleaned });
    manifest = cleaned;
  } catch { throw new DecryptError('malformed manifest'); }
  // The sender's role's viewer policy, sent with the open (off when absent).
  const viewerCfg = res.viewer && typeof res.viewer === 'object' ? res.viewer : null;
  if (!reader) reader = await ShareReader.create({ id, grant: res.grant, chunks: res.chunks, manifest });
  renderFiles(paste, manifest, reader, viewerCfg, res.grantExpires, { id, grant: res.grant, serverNow: res.now });
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
      showMsg(msgEl, e instanceof ApiError && e.status === 423 ? 'The administrator has locked this share; it cannot be deleted.'
        : captchaNeeded(e) ? 'The CAPTCHA for this share has expired. Reload the page to complete it again.' : friendlyError(e));
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
    markInvalid(input, msg, false);
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
      if (e instanceof PasswordRequired) { showMsg(msg, 'Please enter the password.'); markInvalid(input, msg); input.focus(); return; }
      if (e instanceof ApiError && e.code === 'bad_password') { showMsg(msg, 'Wrong password — try again.'); markInvalid(input, msg); input.select(); return; }
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
  $('#paste-title').textContent = ({ url: 'Shared link', secret: 'Shared credential' })[result.fmt] || 'Shared note';
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
  const { markdown: isMarkdown, code: isCode } = noteKind(result.fmt, result.text);
  const pills = clear($('#paste-pills'));
  if (isMarkdown) pills.appendChild(pill('markdown'));
  else if (isCode) pills.appendChild(pill('code'));
  lifetimePills(pills, paste.meta, result.bar);

  const container = $('#paste-content');
  let raw = false;
  const draw = () => drawNote(container, result.text, { markdown: isMarkdown, code: isCode, raw });
  draw();
  const rawBtn = $('#toggle-raw');
  rawBtn.hidden = !isMarkdown;
  rawBtn.textContent = 'Raw';
  rawBtn.onclick = () => { raw = !raw; rawBtn.textContent = raw ? 'Rendered' : 'Raw'; draw(); };
  $('#copy-content').onclick = async () => { toast((await copyText(result.text)) ? 'copied to clipboard' : 'copy failed'); };
}

// ── file rendering ───────────────────────────────────────────────────────────
/**
 * Received names without spoofing characters (files.js cleanEntries): each
 * entry whose path loses any is kept under the cleaned path, marked `renamed`
 * (shown on the item), and every cleaned path is checked again (checkPath,
 * duplicates, file/folder conflicts) — a path that is only safe before
 * cleaning (".", U+200B, "." → "..") refuses the manifest. Saving and zipping
 * use the cleaned paths.
 */
function cleanManifest(manifest) {
  const entries = cleanEntries(manifest.entries);
  return entries === manifest.entries ? manifest : { ...manifest, entries };
}

const renamedNote = (e) => (e.renamed ? h('span.tree-sub.mono.renamed-note', { text: 'renamed: hidden characters removed' }) : null);

function renderFiles(paste, manifest, reader, viewerCfg, grantExpires, { id, grant, serverNow } = {}) {

  showView('files');
  const pills = clear($('#files-pills'));
  lifetimePills(pills, paste.meta, paste.adata.bar);
  const files = manifest.entries.filter((e) => !e.dir);
  const hasDirs = manifest.entries.some((e) => e.dir || e.path.includes('/'));
  pills.appendChild(pill(`${files.length} ${files.length === 1 ? 'file' : 'files'} · ${formatBytes(manifest.total)}`));

  const windowEl = $('#files-window');
  // The countdown can be stopped (WCAG 2.2.2): it then shows the closing time.
  const windowSwitch = countdownSwitch(() => tick());
  // Before the window closes, a warning with "Keep downloads open" (WCAG
  // 2.2.1): the server moves the end again, up to ten times, without a view.
  const warn = h('p.msg.files-window-warn', { role: 'alert', hidden: true });
  const keep = h('button.btn', { type: 'button', text: 'Keep downloads open', hidden: true });
  let extendable = !!(id && grant);
  let warned = 0; // the end already warned about
  // The server's clock minus this browser's (the open and extend answers carry the server's
  // `now`): the window's end on this browser's clock, so a clock that is off does not move the
  // warning or the times shown.
  let skew = Number.isFinite(serverNow) ? serverNow * 1000 - Date.now() : 0;
  const endAt = () => grantExpires * 1000 - skew;
  keep.addEventListener('click', async () => {
    keep.disabled = true;
    try {
      const r = await extendDownloads(id, grant);
      grantExpires = r.grantExpires;
      if (Number.isFinite(r.now)) skew = r.now * 1000 - Date.now();
      extendable = r.extensionsLeft > 0;
      warn.hidden = true;
      keep.hidden = true;
      toast(`Downloads stay open until ${atTime(endAt())}.`);
    } catch (e) {
      extendable = false;
      keep.hidden = true;
      warn.textContent = friendlyError(e);
    } finally {
      keep.disabled = false;
      tick();
    }
  });
  clear($('#files-window-switch')).append(windowSwitch.el, warn, keep);
  const tick = () => {
    const left = endAt() - Date.now();
    windowEl.textContent = left <= 0 ? 'The download window has closed — open the link again (if views remain).'
      : windowSwitch.stopped() ? `Downloads available until ${atTime(endAt())}` : `Downloads available for ${formatDuration(left)}`;
    windowSwitch.el.hidden = left <= 0;
    if (left > 0 && left <= WINDOW_WARN_MS && warned !== grantExpires) {
      warned = grantExpires;
      warn.textContent = extendable
        ? `Downloads close at ${atTime(endAt())}, in under ${Math.ceil(WINDOW_WARN_MS / 60000)} minutes. Need more time?`
        : `Downloads close at ${atTime(endAt())} and cannot be kept open longer.`;
      warn.hidden = false;
      keep.hidden = !extendable;
    }
    if (left <= 0) { keep.hidden = true; warn.hidden = true; }
  };
  tick();
  clearInterval(timer);
  timer = setInterval(tick, 1000);

  const filesBar = progressBar();
  const previewBar = progressBar();
  clear($('#preview-progress')).appendChild(previewBar.el);
  // The preview card is hidden until a View press: keep its live status line
  // outside it, so the region exists before its first announcement.
  clear($('#files-progress')).append(filesBar.el, previewBar.live);
  const errMsg = $('#files-msg');
  let busy = false;
  /** Run a download or preview with a progress bar (bytes fetched and decrypted, in %). */
  async function run(label, total, fn, bar = filesBar) {
    if (busy) return;
    busy = true;
    errMsg.hidden = true;
    let done = 0;
    bar.set(`${label}…`, 0);
    try {
      if (total > MEMORY_WARN && typeof window.showSaveFilePicker !== 'function') toast('Large download: this browser assembles it in memory.');
      await fn((n) => { done += n; bar.set(`${label}…`, total ? done / total : 1); });
      if (bar === filesBar) bar.done(`${label}: done`);
    } catch (e) {
      bar.hide();
      if (e && e.name === 'AbortError') return;
      showMsg(errMsg, e instanceof ApiError && e.code === 'bad_grant' ? 'The download window has expired — open the link again.'
        : e instanceof ApiError && e.code === 'captcha_required' ? 'The CAPTCHA for this share has expired. Reload the page to complete it again (a share with limited views uses another view).'
          : friendlyError(e));
    } finally {
      busy = false;
    }
  }

  const preview = $('#files-preview');
  const previewBody = $('#preview-body');
  let previewCleanup = null;
  let previewOpener = null;
  const closePreview = () => {
    const hadFocus = preview.contains(document.activeElement);
    if (previewCleanup) previewCleanup();
    previewCleanup = null;
    previewBar.hide();
    preview.hidden = true;
    // Closing from inside the card: back to the View button that opened it.
    if (hadFocus && previewOpener && previewOpener.isConnected) previewOpener.focus();
  };
  $('#preview-close').onclick = closePreview;

  // A note, link or credential a Drive share carries (received through a "Receive" link): its
  // viewer, and a download as text (a credential as a plain-text export that says so).
  const saveItem = (entry) => run(`Downloading ${basename(entry.path)}`, entry.size, async (q) => {
    const bytes = await reader.bytes(entry, q);
    let out;
    try { out = itemExport(entry.item, basename(entry.path), bytes); } catch { out = null; }
    // One that does not parse is saved as it is (never rendered).
    if (out) saveText(out.filename, out.text); else await saveFile(reader, entry, () => {});
  });
  const itemButtons = (entry) => {
    const what = KIND_LABELS[entry.item.kind].toLowerCase();
    const openBtn = h('button.btn', {
      type: 'button', text: 'Open', 'aria-label': `Open the ${what} ${basename(entry.path)}`,
      on: {
        click: () => {
          if (busy) return undefined;
          closePreview();
          previewOpener = openBtn;
          $('#preview-title').replaceChildren(nameEl(entry.path));
          clear(previewBody);
          preview.hidden = false;
          preview.scrollIntoView({ block: 'nearest' });
          return run(`Loading ${basename(entry.path)}`, entry.size, async (p) => {
            const text = new TextDecoder('utf-8', { fatal: false }).decode(await reader.bytes(entry, p));
            try {
              if (entry.item.kind === 'note') drawNote(previewBody, text, noteKind(entry.item.fmt, text));
              else previewBody.replaceChildren(entry.item.kind === 'url' ? linkCard(text, { lead: 'This item is a link to' }) : secretCard(text));
            } catch (e) {
              clear(previewBody).appendChild(h('p.msg.error', { text: e instanceof ShareTypeError ? `${e.message} Download it to see what it holds.` : 'This item cannot be shown.' }));
            }
            previewCleanup = () => { stopTotp(); clear(previewBody); };
            $('#preview-download').onclick = () => saveItem(entry);
          }, previewBar);
        },
      },
    });
    return [openBtn, h('button.btn', { type: 'button', text: 'Download', on: { click: () => saveItem(entry) } })];
  };
  const fileButtons = (entry) => {
    if (entry.item) return itemButtons(entry);
    const out = [h('button.btn', { type: 'button', text: 'Download', on: { click: () => run(`Downloading ${basename(entry.path)}`, entry.size, (p) => saveFile(reader, entry, p)) } })];
    const renderer = allowedRenderer(entry, manifest.view, viewerCfg);
    if (renderer) {
      const viewBtn = h('button.btn', {
        type: 'button', text: 'View',
        on: {
          click: () => {
            // One transfer at a time: leave the open preview alone while busy.
            if (busy) return undefined;
            // The preview opens at once with its own bar: bytes (fetch +
            // decrypt) as a percentage, then a busy bar while it renders.
            closePreview();
            previewOpener = viewBtn;
            $('#preview-title').replaceChildren(nameEl(entry.path));
            clear(previewBody);
            preview.hidden = false;
            preview.scrollIntoView({ block: 'nearest' });
            return run(`Loading ${basename(entry.path)}`, entry.size, async (p) => {
              const bytes = await reader.bytes(entry, p);
              previewBar.set('Preparing the preview…', null);
              try {
                previewCleanup = await renderPreview(previewBody, entry, bytes, renderer);
              } catch (e) {
                clear(previewBody).appendChild(h('p.msg.error', { text: e.message || 'This file cannot be previewed.' }));
              }
              previewBar.hide();
              $('#preview-download').onclick = () => run(`Downloading ${basename(entry.path)}`, entry.size, (q) => saveFile(reader, entry, q));
            }, previewBar);
          },
        },
      });
      out.unshift(viewBtn);
    }
    return out;
  };

  const tree = clear($('#files-tree'));
  const all = $('#download-all');
  if (!hasDirs && files.length === 1) {
    all.hidden = true;
    const f = files[0];
    tree.appendChild(h('div.file-card', {},
      h('div.file-meta', {}, h('span.file-name', {}, nameEl(f.path)), h('span.file-sub.mono', { text: `${formatBytes(f.size)} · ${f.type}` }), renamedNote(f)),
      h('div.btn-row', {}, ...fileButtons(f))));
    return;
  }
  all.hidden = false;
  all.onclick = () => run('Preparing ZIP', manifest.total, (p) => saveZip(reader, '', 'secbin-files.zip', p));

  const size = (node) => node.files.reduce((n, f) => n + f.size, 0) + [...node.dirs.values()].reduce((n, d) => n + size(d), 0);
  const count = (node) => node.files.length + [...node.dirs.values()].reduce((n, d) => n + count(d), 0);
  // One folder's content: its sub-folders (open, or download as a ZIP) and
  // its files (view, download). With folders, a tree on the left picks the
  // folder (public/js/tree.js — collapsed by default).
  const renderPane = (node, { open } = {}) => {
    const ul = h('ul.tree-list.pane-list');
    for (const d of [...node.dirs.values()].sort((a, b) => a.name.localeCompare(b.name))) {
      ul.appendChild(h('li.tree-dir', {},
        h('div.tree-row', {},
          h('button.tree-name.tree-open', { type: 'button', title: `Open ${d.name}`, on: { click: () => open(d.path) } }, nameEl(d.name, { suffix: '/' })),
          h('span.tree-sub.mono', { text: `${count(d)} · ${formatBytes(size(d))}` }),
          h('button.btn.tree-btn', { type: 'button', text: 'Download (.zip)', on: { click: () => run(`Preparing ${d.name}.zip`, size(d), (p) => saveZip(reader, d.path, `${d.name}.zip`, p)) } }))));
    }
    for (const f of [...node.files].sort((a, b) => a.path.localeCompare(b.path))) {
      ul.appendChild(h('li.tree-file', {},
        h('div.tree-row', {}, h('span.tree-name', {}, nameEl(basename(f.path))), h('span.tree-sub.mono', { text: formatBytes(f.size) }), renamedNote(f),
          h('span.tree-actions', {}, ...fileButtons(f).map((b) => { b.classList.add('tree-btn'); return b; })))));
    }
    if (!ul.firstChild) return h('p.muted.pane-empty', { text: 'This folder is empty.' });
    return ul;
  };
  const root = buildTree(manifest.entries);
  if (!hasDirs) { tree.appendChild(renderPane(root)); return; }
  tree.appendChild(folderBrowser({ label: 'Folders', rootName: 'All files', root, renderPane, paneLabel: 'Folder contents' }).el);
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
  $('#receipt-note-reveal').hidden = !reveal;
  if (reveal) $('#reveal-burn').textContent = revealLabel;
  $('#status-new').hidden = !isError;
}

function stopExpiryTimer() {
  if (timer !== null) { clearInterval(timer); timer = null; }
  const box = $('#status-timer');
  if (box) { box.hidden = true; box.classList.remove('ending'); }
  if (expirySwitch) expirySwitch.el.hidden = true;
}

function startExpiryTimer(meta, onExpire) {
  const box = $('#status-timer');
  const clock = $('#status-timer-clock');
  if (!box || !clock || !meta.expires) return;
  const at = meta.expires * 1000;
  const label = box.querySelector('.status-timer-label');
  // The countdown can be stopped (WCAG 2.2.2): it then shows the fixed time.
  if (!expirySwitch) {
    expirySwitch = countdownSwitch(() => { if (expiryRender) expiryRender(); });
    box.insertAdjacentElement('afterend', expirySwitch.el);
  }
  expirySwitch.el.hidden = false;
  function render() {
    const left = Math.max(0, at - Date.now());
    const still = expirySwitch.stopped();
    if (label) label.textContent = still ? 'Deletes on' : 'Deletes in';
    clock.textContent = still ? atTime(at) : formatDuration(left);
    box.classList.toggle('ending', !still && left > 0 && left <= 600000);
    if (left <= 0) { stopExpiryTimer(); onExpire(); }
  }
  expiryRender = render;
  box.hidden = false;
  render();
  if (at > Date.now()) timer = setInterval(render, 1000);
}
