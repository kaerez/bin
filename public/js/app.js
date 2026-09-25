// app.js — secbin client controller. Routes between "create" and "view" based
// on the URL path (/p/<id>#<key>), drives encryption/decryption, and renders
// decrypted content via DOM construction only. The fragment key never leaves the
// browser and is never placed in a network request.

import { encryptPaste, decryptPaste, decryptContent, deriveContentKey, PasswordRequired } from './crypto.js';
import { createPaste, fetchPaste, fetchPasteMeta, consumePaste, deletePaste, ApiError } from './api.js';
import { validateHead, validatePaste, buildAAD, expireSeconds, MAX_VIEWS } from './format.js';
import { renderMarkdown } from './markdown.js';
import { looksLikeCode, highlightInto } from './highlight.js';
import { $, showView, toast, copyText, flashCopied, pill } from './ui.js';

// Module-level state referenced by helpers that may run during the top-level
// route dispatch below. Declared here (not near the timer helpers further down)
// because `let` in the temporal dead zone would throw if `status()` fired first
// and called `stopExpiryTimer()` before this line was reached — turning every
// view into a stuck "loading…" screen.
let expiryTimer = null;
// Create-option constants, declared up here for the same TDZ reason: the route
// dispatch below calls initCreate() → readCreateOptions() during module evaluation.
const UNIT_WORDS = { m: ['minute', 'minutes'], h: ['hour', 'hours'], d: ['day', 'days'] };
const EXPIRE_ERR = 'Expiry must be a whole number between 1 minute and 365 days.';
const VIEWS_ERR = `Views must be a whole number from 1 to ${MAX_VIEWS.toLocaleString('en-US')}, or unlimited (∞).`;

// ── boot ─────────────────────────────────────────────────────────────────────
const route = location.pathname.match(/^\/p\/([^/]+)\/?$/);
if (route) {
  let id = null;
  // Malformed percent-encoding must not throw during module evaluation (it
  // would leave every view hidden — a blank page). Show a proper error instead.
  try { id = decodeURIComponent(route[1]); } catch { /* fall through */ }
  if (id !== null) initView(id);
  else status('This link is malformed — check that it was copied completely.', true);
} else {
  initCreate();
}

// ── CREATE ─────────────────────────────────────────────────────────────────
function initCreate() {
  showView('create');
  // Format is uniform now — every note is stored as plaintext and any obvious
  // source code is syntax-highlighted at view time (see renderContent).
  const fmt = 'plaintext';
  // The lock toggle only records intent ("this note needs a password"); the
  // password itself is typed in the modal shown when Create link is pressed.
  let pwRequired = false;

  const lock = $('#lock');
  if (lock) {
    lock.addEventListener('click', () => {
      pwRequired = lock.classList.toggle('active');
      lock.setAttribute('aria-pressed', String(pwRequired));
    });
  }

  const createBtn = $('#create');
  const sendTxt = createBtn.querySelector('.send-txt');
  const msg = $('#create-msg');
  wireCreateOptions();

  const requestCreate = () => {
    if (createBtn.disabled) return;
    if (!$('#editor').value.trim()) { showMsg(msg, 'Type something first.'); $('#editor').focus(); return; }
    const opts = readCreateOptions();
    if (opts.viewsErr) { showMsg(msg, opts.viewsErr); $('#views').focus(); return; }
    if (opts.expireErr) { showMsg(msg, opts.expireErr); $('#expire-n').focus(); return; }
    msg.hidden = true;
    if (pwRequired) openPasswordModal((password) => submitPaste(password, opts));
    else submitPaste('', opts);
  };
  createBtn.addEventListener('click', requestCreate);
  // Editor convention: Ctrl/Cmd+Enter submits without leaving the textarea.
  $('#editor').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); requestCreate(); }
  });

  // View limit and expiry come from the composer controls (default: one view,
  // 24 hours). A finite view count is a view-limited paste (bar:true, served by
  // the Durable Object); unlimited views is an ordinary KV paste (bar:false).
  async function submitPaste(password, opts) {
    const bar = opts.views !== null;
    createBtn.disabled = true;
    const label = sendTxt ? sendTxt.textContent : '';
    // Press → the arrow leaves the button (`.sending`), then the composer follows
    // it out and the success view takes over, so the arrow leads the navigation.
    // Skipped under reduced motion: the CSS travel is off there, so the 32px jump
    // would just make the arrow vanish.
    const animate = !reducedMotion();
    let relabel = null;
    if (animate) {
      createBtn.classList.add('sending');
      // The label waits for the arrow to clear — swapping it mid-flight resizes
      // the button and jogs the icon the eye is following.
      relabel = setTimeout(() => { if (sendTxt) sendTxt.textContent = 'Encrypting…'; }, ARROW_LEAD_MS);
    } else if (sendTxt) {
      sendTxt.textContent = 'Encrypting…';
    }
    const arrowGone = animate ? wait(ARROW_LEAD_MS) : null;
    try {
      const { body, fragment } = await encryptPaste({
        text: $('#editor').value,
        password,
        fmt,
        bar,
        expire: opts.expire,
        views: bar ? opts.views : undefined,
      });
      const { id, deletetoken } = await createPaste(body);
      const url = `${location.origin}/p/${id}#${fragment}`;
      clearTimeout(relabel);
      if (arrowGone) await arrowGone; // never hand over ahead of the arrow
      await leaveCreateView();
      // Only after the server confirmed the create, and after the composer has
      // left the screen so the editor is never seen blanking. The plaintext has
      // served its purpose; don't leave it in the (now hidden) textarea. On any
      // failure it is deliberately kept — the user must not lose their note.
      $('#editor').value = '';
      showSuccess({ id, deletetoken, url, views: opts.views, expiryText: opts.expiryText });
    } catch (e) {
      clearTimeout(relabel);
      createBtn.classList.remove('sending'); // the arrow glides back in
      showMsg(msg, friendlyError(e));
      createBtn.disabled = false;
      if (sendTxt) sendTxt.textContent = label;
    }
  }
}

// Slide the composer out behind the departing arrow. The class is dropped before
// the caller swaps views, both within the same frame, so the faded sheet is never
// seen snapping back.
async function leaveCreateView() {
  const view = $('#view-create');
  if (!view || reducedMotion()) return;
  view.classList.add('view-leaving');
  await wait(VIEW_EXIT_MS);
  view.classList.remove('view-leaving');
}

// ── password modal ───────────────────────────────────────────────────────────
// The single popup: "Paste password" with Cancel / Create. Calls onSubmit(pw)
// once with a non-empty password; closes on backdrop click, Escape, or cancel.
// While open, Tab is trapped inside the dialog; on close, focus returns to the
// element that opened it (a11y — the modal is aria-modal="true").
function openPasswordModal(onSubmit) {
  const scrim = $('#pw-modal');
  if (!scrim) { onSubmit(''); return; }

  const input = $('#modal-password');
  const confirmInput = $('#modal-password-confirm');
  const create = $('#pw-create');
  const cancel = $('#pw-cancel');
  const mmsg = $('#pw-modal-msg');
  const opener = document.activeElement;
  // One group: the confirm field holds the same secret, so both eyes toggle together.
  wirePeek(
    ['#modal-password', '#modal-peek'],
    ['#modal-password-confirm', '#modal-peek-confirm'],
  );

  const close = () => {
    scrim.hidden = true;
    input.value = ''; // don't leave the password in the hidden DOM
    confirmInput.value = '';
    create.onclick = cancel.onclick = scrim.onclick = input.onkeydown = confirmInput.onkeydown = null;
    document.removeEventListener('keydown', onKey);
    if (opener && typeof opener.focus === 'function') opener.focus();
  };
  const onKey = (e) => {
    if (e.key === 'Escape') { close(); return; }
    if (e.key !== 'Tab') return;
    // Focus trap: cycle within the dialog's enabled, visible controls.
    const focusables = [...scrim.querySelectorAll('input, button')]
      .filter((el) => !el.disabled && el.offsetParent !== null);
    if (!focusables.length) return;
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    if (e.shiftKey && (document.activeElement === first || !scrim.contains(document.activeElement))) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && (document.activeElement === last || !scrim.contains(document.activeElement))) {
      e.preventDefault();
      first.focus();
    }
  };
  const submit = () => {
    if (!input.value) { showMsg(mmsg, 'Enter a password, or cancel.'); input.focus(); return; }
    // Practical cap, enforced VISIBLY — never via maxlength, whose silent
    // truncation could seal the note with a password the reader doesn't have.
    if (input.value.length > 128) {
      showMsg(mmsg, 'Password is too long — 128 characters max.');
      input.focus();
      return;
    }
    // A mistyped password permanently locks a one-time note (there is no safe
    // way to test it afterwards — opening the link consumes the note).
    if (input.value !== confirmInput.value) {
      showMsg(mmsg, 'Passwords do not match — repeat the same password in both fields.');
      confirmInput.focus();
      return;
    }
    const pw = input.value;
    close();
    onSubmit(pw);
  };

  create.onclick = submit;
  cancel.onclick = close;
  scrim.onclick = (e) => { if (e.target === scrim) close(); };
  input.onkeydown = confirmInput.onkeydown = (e) => { if (e.key === 'Enter') submit(); };
  document.addEventListener('keydown', onKey);

  mmsg.hidden = true;
  input.value = '';
  confirmInput.value = '';
  scrim.hidden = false;
  // Focus the dialog (not the input) so the modal is reachable and the focus
  // trap works, without painting a focus ring on the field before the user
  // has clicked or tabbed into it.
  $('#pw-modal-dialog').focus();
}

function showSuccess({ id, deletetoken, url, views, expiryText }) {
  showView('success');
  $('#paste-url').textContent = url;
  const keep = ' Keep the whole link private — the key that unlocks it is inside the link.';
  $('#success-note').textContent = (views === null
    ? `Anyone with this link can open the note any number of times until it self-destructs in ${expiryText}.`
    : views === 1
      ? `Anyone with this link can read the note once. Unread, it self-destructs in ${expiryText}.`
      : `Anyone with this link can open the note up to ${views} times. It self-destructs after the last view or in ${expiryText}, whichever comes first.`) + keep;
  const seal = $('#seal-label');
  if (seal) seal.textContent = `scan to open · ${views === null ? 'unlimited views' : views === 1 ? 'one-time read' : `${views} views`}`;
  renderQr(url);

  $('#copy-url').onclick = async () => {
    flashCopied($('#copy-url'), (await copyText(url)) ? 'copied' : 'failed');
  };
  // Both irreversible actions are two-step: opening a one-time link consumes it,
  // and delete is permanent. A stray click must not kill a note about to be shared.
  if (views === null) {
    const open = $('#open-link');
    open.onblur = null;
    open.onclick = () => { location.href = url; };
  } else {
    armConfirm($('#open-link'), views === 1 ? 'Uses the one view — open?' : `Uses 1 of ${views} views — open?`, () => { location.href = url; });
  }
  $('#another').onclick = () => { location.href = '/'; };

  const delBtn = $('#delete-btn');
  const sMsg = $('#success-msg');
  const delLabel = delBtn.textContent;
  armConfirm(delBtn, 'Permanently delete?', async () => {
    delBtn.disabled = true;
    delBtn.textContent = 'Deleting…';
    try {
      await deletePaste(id, deletetoken);
      showMsg(sMsg, 'This paste has been deleted.');
      toast('deleted');
      delBtn.textContent = 'Deleted';
      // The link is dead now — don't leave live-looking actions pointing at it.
      $('#open-link').disabled = true;
      $('#copy-url').disabled = true;
    } catch (e) {
      showMsg(sMsg, friendlyError(e));
      delBtn.disabled = false;
      delBtn.textContent = delLabel;
    }
  });
}

// Two-step confirmation for irreversible actions. The first activation "arms"
// the button — its label changes in place to name the destructive effect (the
// change is announced by screen readers since focus stays on the control); a
// second activation within the window confirms. Disarms on timeout or blur so
// an abandoned half-click can't linger as a landmine.
function armConfirm(btn, armedLabel, onConfirm) {
  const label = btn.textContent;
  let timer = null;
  const disarm = () => {
    if (timer === null) return;
    clearTimeout(timer);
    timer = null;
    btn.textContent = label;
    btn.classList.remove('armed');
  };
  btn.onclick = () => {
    if (timer !== null) { disarm(); onConfirm(); return; }
    btn.textContent = armedLabel;
    btn.classList.add('armed');
    timer = setTimeout(disarm, 5000);
  };
  btn.onblur = disarm;
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

// ── VIEW ─────────────────────────────────────────────────────────────────────
function initView(id) {
  // Only show the "new paste" shortcut when viewing someone's note, not on the
  // landing page (where the whole screen already is the composer).
  const newlink = $('#newlink');
  if (newlink) newlink.hidden = false;

  const fragment = location.hash.slice(1);
  if (!fragment) { status('This link is missing its decryption key.', true); return; }
  if (id[0] === 'b') initBurnView(id, fragment);
  else initNormalView(id, fragment);
}

// Normal (KV) paste: reads are idempotent, so fetch and decrypt directly.
async function initNormalView(id, fragment) {
  status('decrypting…');
  let paste;
  try { paste = await fetchPaste(id); } catch (e) { return handleReadError(e); }
  try {
    renderPaste(paste, await decryptPaste({ paste, fragment }));
  } catch (e) {
    if (e instanceof PasswordRequired) return promptPasswordNormal(paste, fragment);
    status('Could not decrypt this note. The link may be corrupted or altered.', true);
  }
}

// Burn paste: peek the head (adata + wrapped key, NO ciphertext) without
// consuming, so a password can be verified before the single destructive read.
// The paste is only consumed once we actually reveal it.
async function initBurnView(id, fragment) {
  status('checking…');
  let head;
  try { head = await fetchPasteMeta(id); } catch (e) { return handleReadError(e); }
  try {
    // Fail-closed validation of the peeked head BEFORE any key derivation, so a
    // hostile/buggy server can't demand an absurd PBKDF2 workload (adata.iter is
    // clamped) or feed malformed fields into the crypto path.
    head = validateHead(head);
  } catch {
    return status('Could not read this note — the server response was malformed.', true);
  }

  const total = head.meta.views ?? 1;
  const left = head.meta.left ?? 1;
  if (head.adata.kdf === 'pbkdf2-hkdf') {
    // Password-protected: prompt + verify against the wrapped key BEFORE consuming.
    promptPasswordBurn(id, fragment, head, total);
  } else {
    // No password: an explicit "reveal" click is the consent to spend a view.
    status(total === 1
      ? 'This note can only be viewed once.'
      : left === 1
        ? `This is the last remaining view of this note (${total} in total). Opening it deletes the note.`
        : `This note has ${left} views left. Opening it uses one.`, false, { reveal: true });
    const revealBtn = $('#reveal-burn');
    revealBtn.disabled = false;
    // When the countdown hits zero the note is gone server-side — leaving an
    // enabled Reveal pointing at a doomed 410 would be a lie. Transition to the
    // expired state immediately (status() also stops and hides the timer).
    startExpiryTimer(head.meta, () => {
      revealBtn.disabled = true;
      status('This note has expired — it can no longer be opened.', true);
    });
    revealBtn.onclick = async () => {
      revealBtn.disabled = true;
      $('#status-actions').hidden = true;
      // Verify the fragment key against the peeked wrapped key BEFORE the
      // destructive read: a truncated/corrupted link must not burn the note.
      let cek;
      try {
        cek = await deriveContentKey({ adata: head.adata, wk: head.wk, fragment });
      } catch {
        return status('Could not decrypt this note — the link may be incomplete or corrupted. The note was not opened and still exists.', true);
      }
      consumeBurn(id, head, cek);
    };
  }
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// Perform the single destructive read and render. The fragment key (and any
// password) has already been verified against the peeked head, and `cek` is the
// unwrapped content key from that verification — reused here so the password is
// never stretched (PBKDF2) twice and the consumed read cannot "fail late".
async function consumeBurn(id, head, cek) {
  status('decrypting…');
  let paste;
  try { paste = await consumePaste(id); } catch (e) { return handleReadError(e); }
  try {
    paste = validatePaste(paste);
    // Defense in depth: the consumed record must match the authenticated head we
    // verified the key against. (GCM would reject a swap anyway — the AAD and wk
    // are bound — but failing here is clearer and cheaper.)
    if (paste.wk !== head.wk || !bytesEqual(buildAAD(paste.adata), buildAAD(head.adata))) {
      throw new Error('head mismatch');
    }
    const result = await decryptContent({ adata: paste.adata, ct: paste.ct, cek });
    // The note is consumed; drop the key from the address bar so a reload or a
    // shared screenshot of the URL doesn't carry a now-useless (but real) secret.
    if (location.hash) history.replaceState(null, '', location.pathname + location.search);
    renderPaste(paste, result);
  } catch {
    status('Could not decrypt this note. The link may be corrupted or altered.', true);
  }
}

function promptPasswordNormal(paste, fragment) {
  wirePasswordScreen('normal', async (password) => {
    renderPaste(paste, await decryptPaste({ paste, fragment, password }));
  });
}

function promptPasswordBurn(id, fragment, head, total = 1) {
  wirePasswordScreen(total === 1 ? 'burn' : 'limited', async (password) => {
    // Verify the password against the peeked wrapped key WITHOUT consuming.
    // Throws PasswordRequired / DecryptError, leaving the paste intact.
    const cek = await deriveContentKey({ adata: head.adata, wk: head.wk, fragment, password });
    // Verified → the one destructive read, reusing the already-unwrapped CEK
    // (no second 310k-iteration PBKDF2 run).
    await consumeBurn(id, head, cek);
  });
}

// Shared password screen. `verify(password)` throws on a bad/empty password
// (paste untouched) and otherwise transitions the view itself.
function wirePasswordScreen(kind, verify) {
  showView('password');
  wirePeek(['#decrypt-password', '#peek2']);
  const sub = $('#password-subtitle');
  if (sub) {
    sub.textContent = kind === 'burn'
      ? 'This single-use note is password-protected. It is destroyed only once the correct password unlocks it.'
      : kind === 'limited'
        ? 'This view-limited note is password-protected. A view is used only once the correct password unlocks it.'
        : 'This note is protected by a password in addition to the key in the link.';
  }
  const input = $('#decrypt-password');
  const btn = $('#decrypt-btn');
  const msg = $('#password-msg');
  input.value = '';
  input.focus();

  // Guard the handler itself, not just the button: the Enter keydown path
  // bypasses `disabled`, and on a burn paste a second concurrent verify would
  // issue a second destructive read — the losing 410 could then overwrite the
  // decrypted view. Stays latched on success (verify() replaced the view).
  let inFlight = false;
  const submit = async () => {
    if (inFlight) return;
    inFlight = true;
    msg.hidden = true;
    btn.disabled = true;
    // Password key derivation (PBKDF2) takes real time — say so, like the
    // create button's "Encrypting…".
    const label = btn.textContent;
    btn.textContent = 'Decrypting…';
    try {
      await verify(input.value);
      input.value = ''; // verified — don't leave the password in the hidden DOM
    } catch (e) {
      // A GCM auth failure cannot distinguish a wrong password from a
      // corrupted/tampered link, so the message covers both honestly.
      showMsg(msg, e instanceof PasswordRequired
        ? 'Please enter a password.'
        : 'Wrong password — try again. If you are sure it is correct, the link may be corrupted or altered.');
      inFlight = false;
      btn.disabled = false;
      btn.textContent = label;
      input.focus();
    }
  };
  btn.onclick = submit;
  input.onkeydown = (e) => { if (e.key === 'Enter') submit(); };
}

function handleReadError(e) {
  // A fetch that never reached the server (offline, DNS, blocked) is NOT the
  // same as "gone" — telling a burn-note reader their note was consumed when
  // they are merely offline would be needlessly alarming.
  if (!(e instanceof ApiError)) {
    status('Could not reach the server — check your connection and try again.', true);
  } else if (e.status === 410) {
    status('This paste has expired or has no views left.', true);
  } else {
    status('This paste has expired, has no views left, or never existed.', true);
  }
}

function renderPaste(paste, result) {
  showView('paste');

  // Notes are uniform text now; source code is auto-detected and highlighted.
  // `isCode` also covers older pastes explicitly saved with fmt:'code'.
  const isMarkdown = result.fmt === 'markdown';
  const isCode = result.fmt === 'code' || (result.fmt === 'plaintext' && looksLikeCode(result.text));

  // Pills: (code|markdown) · (views) · (time left). Plain text gets no kind pill.
  // A note whose last view was just spent gets no expiry pill — it's gone.
  const pills = $('#paste-pills');
  pills.textContent = '';
  if (isMarkdown) pills.appendChild(pill('markdown'));
  else if (isCode) pills.appendChild(pill('code'));
  const meta = paste && paste.meta ? paste.meta : {};
  let stillExists = true;
  if (result.bar) {
    const total = Number.isInteger(meta.views) ? meta.views : 1;
    const left = Number.isInteger(meta.left) ? meta.left : 0;
    if (left <= 0) {
      stillExists = false;
      pills.appendChild(pill(total === 1 ? 'one-time view · now deleted' : 'last view · now deleted', 'bad'));
    } else {
      pills.appendChild(pill(`${left} ${left === 1 ? 'view' : 'views'} left`, 'warn'));
    }
  } else {
    pills.appendChild(pill('unlimited views'));
  }
  if (stillExists) {
    const ttl = expireSeconds(meta.expire) ?? 0;
    if (ttl > 0 && Number.isInteger(meta.created)) {
      const leftS = meta.created + ttl - Math.floor(Date.now() / 1000);
      if (leftS > 0) pills.appendChild(pill(`deletes in ${formatCoarse(leftS)}`));
    }
  }

  // Content (DOM construction only).
  const container = $('#paste-content');
  let showRaw = false;
  const draw = () => renderContent(container, result, isCode, showRaw);
  draw();

  const rawBtn = $('#toggle-raw');
  rawBtn.hidden = !isMarkdown;
  rawBtn.textContent = 'Raw';
  rawBtn.onclick = () => { showRaw = !showRaw; rawBtn.textContent = showRaw ? 'Rendered' : 'Raw'; draw(); };

  $('#copy-content').onclick = async () => {
    toast((await copyText(result.text)) ? 'copied to clipboard' : 'copy failed');
  };
}

function renderContent(container, result, isCode, showRaw) {
  container.textContent = '';
  if (result.fmt === 'markdown' && !showRaw) {
    const div = document.createElement('div');
    div.className = 'md';
    renderMarkdown(div, result.text);
    container.appendChild(div);
    return;
  }
  const pre = document.createElement('pre');
  pre.className = 'code';
  if (isCode) {
    // Highlight via createElement + textContent only (never innerHTML).
    const code = document.createElement('code');
    highlightInto(code, result.text);
    pre.appendChild(code);
  } else {
    pre.textContent = result.text;
  }
  container.appendChild(pre);
}

// ── shared helpers ───────────────────────────────────────────────────────────
// Timings for the create→success hand-off; both are bound to styles.css
// (`.send .send-ico` and `.view-leaving`) and must change with it. ARROW_LEAD_MS
// is not the arrow's full 300ms transition but the point it clears the button's
// edge: an ease-out over 32px covers the visible ~29px in under half that, so the
// view leaves here and overlaps the invisible tail instead of waiting it out.
const ARROW_LEAD_MS = 150;
const VIEW_EXIT_MS = 170;

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// The stylesheet turns every animation and transition off under
// `prefers-reduced-motion: reduce`, so don't sit through durations nothing spends.
const reducedMotion = () =>
  typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;

// Wire one or more [inputSel, btnSel] pairs to a shared reveal state, so a group
// of fields holding the *same* secret (the modal's password + confirm) unmasks
// as one — clicking either eye updates both fields and both icons. No secret is
// exposed that the user hasn't already asked to see: the pair is two entries of
// one password, on one screen, revealed only by explicit click.
function wirePeek(...pairs) {
  const fields = pairs
    .map(([inputSel, btnSel]) => ({ input: $(inputSel), btn: $(btnSel) }))
    .filter(({ input, btn }) => input && btn);
  if (!fields.length) return;

  // The eye / struck-eye icons are static markup in index.html; `revealed`
  // picks which one is visible (see .peek in styles.css) — never touch the
  // button's children, that would wipe them.
  const paint = (show) => {
    for (const { input, btn } of fields) {
      input.type = show ? 'text' : 'password';
      btn.classList.toggle('revealed', show);
      btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      btn.setAttribute('aria-pressed', String(show));
    }
  };

  // Re-wiring means a fresh entry (modal reopened, password screen shown):
  // always start masked, even if the field was left revealed last time.
  paint(false);
  for (const { btn } of fields) {
    // Read the state off the group, not this button, so both eyes agree even if
    // one was somehow left out of sync.
    btn.onclick = () => paint(fields[0].input.type === 'password');
  }
}

// `reveal` shows the burn "reveal once" action block; callers opt in explicitly
// rather than the function sniffing the message text (which broke on rewording).
function status(message, isError = false, { reveal = false } = {}) {
  showView('status');
  // Any status transition supersedes a running countdown; the reveal branch
  // restarts it explicitly. Prevents a stale timer ticking under a later screen.
  stopExpiryTimer();
  const el = $('#status-msg');
  el.textContent = message;
  el.classList.toggle('error', isError);
  // Error states get a warning glyph + a "Create new paste" action, like the
  // reference expired screen. The burn "reveal once" prompt keeps its own action.
  const ico = $('#status-ico');
  if (ico) ico.hidden = !isError;
  const actions = $('#status-actions');
  if (actions) actions.hidden = !reveal;
  const newActions = $('#status-new');
  if (newActions) newActions.hidden = !isError;
}

// ── self-destruct countdown ──────────────────────────────────────────────────
// Shown on the burn "reveal once" screen: how long until the note auto-expires.
// Purely informational — the authoritative expiry is the DO alarm server-side;
// this is derived from the non-secret meta (created + expire) in the peeked head.
// `expiryTimer` itself is declared near the top of the module (see the boot
// section) so it is initialized before `status()` can reference it.

function stopExpiryTimer() {
  if (expiryTimer !== null) { clearInterval(expiryTimer); expiryTimer = null; }
  const box = $('#status-timer');
  if (box) { box.hidden = true; box.classList.remove('ending'); }
}

// `meta.created` (unix seconds) is set by the server on create and echoed in the
// peek response; `expire` maps to a fixed TTL. A note with no expiry (never) or
// missing created gets no timer rather than a bogus one. `onExpire` fires once
// when the countdown reaches zero (possibly synchronously, if already past).
function startExpiryTimer(meta, onExpire) {
  const box = $('#status-timer');
  const clock = $('#status-timer-clock');
  if (!box || !clock || !meta) return;
  const ttl = expireSeconds(meta.expire) ?? 0;
  if (ttl <= 0 || !Number.isInteger(meta.created)) return;

  const expireAt = (meta.created + ttl) * 1000;
  let expired = false;
  const render = () => {
    const left = Math.max(0, expireAt - Date.now());
    clock.textContent = formatDuration(left);
    // Pulse under ten minutes — a quiet "hurry" cue without shouting.
    box.classList.toggle('ending', left > 0 && left <= 600000);
    if (left <= 0) {
      expired = true;
      if (expiryTimer !== null) { clearInterval(expiryTimer); expiryTimer = null; }
      box.classList.remove('ending');
      if (onExpire) onExpire();
    }
  };
  box.hidden = false;
  render();
  if (!expired) expiryTimer = setInterval(render, 1000);
}

// ms → H:MM:SS (or MM:SS under an hour). Clamps at 0 (shows "expired").
function formatDuration(ms) {
  const total = Math.floor(ms / 1000);
  if (total <= 0) return 'expired';
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const pad = (n) => String(n).padStart(2, '0');
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${pad(m)}:${pad(s)}`;
}

// Seconds → coarse "2d 3h" / "3h 12m" / "12m" / "<1m".
function formatCoarse(sec) {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return h > 0 ? `${d}d ${h}h` : `${d}d`;
  if (h > 0) return m > 0 ? `${h}h ${m}m` : `${h}h`;
  return m > 0 ? `${m}m` : '<1m';
}

// ── create options (view limit + expiry) ─────────────────────────────────────

/**
 * Read and validate the composer's view/expiry controls. Returns
 * { views: number|null (null = unlimited), expire: "<n>m|h|d", expiryText,
 *   viewsErr, expireErr }. The server re-validates everything (format.js).
 */
function readCreateOptions() {
  const unlimited = $('#views-unlimited')?.getAttribute('aria-pressed') === 'true';
  const vRaw = ($('#views')?.value ?? '1').trim();
  const nRaw = ($('#expire-n')?.value ?? '24').trim();
  const unit = $('#expire-unit')?.value ?? 'h';

  let views = null;
  let viewsErr = null;
  if (!unlimited) {
    if (/^[1-9][0-9]{0,5}$/.test(vRaw) && Number(vRaw) <= MAX_VIEWS) views = Number(vRaw);
    else viewsErr = VIEWS_ERR;
  }

  let expire = null;
  let expireErr = null;
  let expiryText = '';
  if (/^[1-9][0-9]{0,6}$/.test(nRaw) && Object.prototype.hasOwnProperty.call(UNIT_WORDS, unit)
      && expireSeconds(nRaw + unit) !== null) {
    expire = nRaw + unit;
    const n = Number(nRaw);
    expiryText = `${n} ${UNIT_WORDS[unit][n === 1 ? 0 : 1]}`;
  } else {
    expireErr = EXPIRE_ERR;
  }
  return { views, expire, expiryText, viewsErr, expireErr };
}

/** Wire the ∞ toggle and keep the ledger line + validity state live. */
function wireCreateOptions() {
  const viewsIn = $('#views');
  const inf = $('#views-unlimited');
  const expN = $('#expire-n');
  const expU = $('#expire-unit');
  if (!viewsIn || !inf || !expN || !expU) return;

  const refresh = () => {
    const o = readCreateOptions();
    viewsIn.setAttribute('aria-invalid', String(Boolean(o.viewsErr)));
    expN.setAttribute('aria-invalid', String(Boolean(o.expireErr)));
    const fv = $('#feat-views');
    if (fv && !o.viewsErr) {
      fv.textContent = o.views === null ? 'Unlimited views' : o.views === 1 ? 'One-time view' : `${o.views} views`;
    }
    const fe = $('#feat-expire');
    if (fe && !o.expireErr) fe.textContent = `Auto-deletes in ${o.expiryText}`;
  };

  inf.addEventListener('click', () => {
    const on = inf.getAttribute('aria-pressed') !== 'true';
    inf.setAttribute('aria-pressed', String(on));
    viewsIn.disabled = on;
    refresh();
  });
  for (const el of [viewsIn, expN]) el.addEventListener('input', refresh);
  expU.addEventListener('change', refresh);
  refresh();
}

function showMsg(el, message) {
  el.textContent = message;
  el.hidden = false;
}

function friendlyError(e) {
  if (e instanceof ApiError) {
    if (e.status === 429) return 'Too many pastes from your network — please wait a moment.';
    if (e.status === 413) return 'That document is too large.';
    return e.message || 'Server error. Please try again.';
  }
  if (e && /too large/.test(e.message || '')) return 'That document is too large (1 MiB max).';
  return 'Something went wrong. Please try again.';
}
