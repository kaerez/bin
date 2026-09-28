// drivekit-ui.js — the owner recovery kit (docs/DRIVE.md §3, "Recovery
// kits") on the export screen (Admin → Import / export), on the owner's
// Drive page and on its unlock screen: the same kit, the same status, the
// same check and the same restore everywhere. The kit is made, checked and
// read only in this browser (public/js/driveclient.js, public/js/drivekit.js);
// the file is never sent.
//
// - Status: the escrow key's version, fingerprint and creation date, and the
//   latest kit downloaded (its version and date, or never), with the notice
//   to download a fresh kit after a rotation or when there is none.
// - Download kit: always offered; an optional passphrase (warned when empty
//   or short) and the owner's password or a passkey (the step-up).
// - Verify kit / Restore from kit: a kit FILE the owner selects (never a copy
//   kept by this page), its passphrase; the file and passphrase are cleared
//   once done. Failed attempts are throttled here.
//
// Accessibility (docs/WCAG22.md): each form's message sits in a status line
// that is in the page from the start (a live region that appears together
// with its text is often not read); the passphrase warning describes the
// passphrase field while it shows; a check's verdict takes focus; statuses
// are words, not only colours.

import { prelogin } from '../../js/api.js';
import { stretch } from '../../js/pwauth.js';
import { h, showMsg, formatDate, friendlyError } from '../../js/common.js';
import { toast } from '../../js/ui.js';

const SHORT_PASSPHRASE = 12;
export const KIT_ANCHOR = 'owner-kit';
export const KIT_HREF = `/dashboard/admin/#${KIT_ANCHOR}`;

const when = (sec) => (Number.isFinite(sec) && sec > 0 ? formatDate(sec) : 'date not recorded');

// ── throttle (failed kit openings, shared by verify and restore) ────────────
const throttle = { fails: 0, until: 0 };
/** Seconds to wait before the next attempt (0: go ahead). */
export const throttleWait = () => Math.max(0, Math.ceil((throttle.until - Date.now()) / 1000));
function failed() {
  throttle.fails += 1;
  // Two free tries, then 5 s, 10 s, 20 s… up to a minute (Argon2id is slow as well).
  if (throttle.fails >= 3) throttle.until = Date.now() + Math.min(60, 5 * 2 ** (throttle.fails - 3)) * 1000;
}
const succeeded = () => { throttle.fails = 0; throttle.until = 0; };
/** Tests only. */
export const resetThrottle = succeeded;
const kitFailure = (e) => e && e.name === 'DriveKitError' && ['auth', 'format', 'kind', 'owner', 'payload'].includes(e.check);

// ── pieces ──────────────────────────────────────────────────────────────────
const field = (label, control) => h('label.field', {}, h('span.field-label', { text: label }), control);
const secret = (id, autocomplete) => h('input.input', { id, type: 'password', autocomplete, maxlength: '1024' });
const fileInput = (id) => h('input.input', { id, type: 'file', accept: '.json,application/json' });
/** A form's message, inside a status line that is in the page from the start (WCAG 4.1.3). */
const liveMsg = (id) => { const msg = h('p.msg', { id, hidden: true }); return { msg, live: h('div.kit-live', { role: 'status' }, msg) }; };
const userOf = (profile) => ({ id: profile.user.id, role: profile.user.role, impersonating: !!profile.impersonatedBy });

function saveFile(text, name) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  const a = h('a', { href: url, download: name, hidden: true });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

/** Read the selected file (never a copy kept by this page), then clear the input and the passphrase. */
async function takeFile(input, passInput, sync) {
  const file = input.files && input.files[0];
  const passphrase = passInput.value;
  passInput.value = '';
  input.value = '';
  sync();
  return { text: file ? await file.text() : null, passphrase };
}

const waitText = () => `Too many failed attempts: try again in ${throttleWait()} seconds.`;
function holdOff(btn, msg, sync) {
  showMsg(msg, waitText());
  btn.disabled = true;
  setTimeout(() => { sync(); msg.hidden = true; }, throttleWait() * 1000);
}

/**
 * The kit status (driveclient.js kitStatusOf) as an element. `alert`: the
 * notice was just caused here (a rotation, a start over) and is announced
 * once; otherwise it is a static note. `download`: the "Download kit"
 * control shown with the notice.
 */
export function kitStatus(st, { alert = false, download = null, id = 'kit-status' } = {}) {
  const lines = [];
  if (st.state === 'no_escrow') {
    lines.push(h('p', { text: 'There is no escrow key yet: it is created the first time you open your Drive.' }));
  } else {
    lines.push(h('p', { dataset: { kit: 'escrow' } }, h('strong', { text: 'Escrow key: ' }),
      `version ${st.version ?? '?'} · fingerprint `, h('span.mono', { text: st.fingerprint }), ` · created ${when(st.created)}`));
    lines.push(h('p', { dataset: { kit: 'latest' } }, h('strong', { text: 'Latest kit downloaded: ' }),
      st.kit ? `version ${st.kit.version ?? '?'} · ${when(st.kit.at)}` : 'never'));
  }
  let notice = null;
  if (st.state === 'stale' || st.state === 'none') {
    const text = st.state === 'stale'
      ? 'The escrow key was replaced. Download a fresh owner recovery kit: it holds all current and past escrow keys.'
      : 'No owner recovery kit has been downloaded yet. Download one and store it offline: it holds your Drive key and every escrow key.';
    notice = h('div.kit-notice', { id: `${id}-notice`, role: alert ? 'alert' : 'note', dataset: { state: st.state } },
      h('p.msg.warn', { text }),
      st.state === 'stale' ? h('p.muted', { text: 'Older kits still work through the Drive key, but only a fresh kit holds a complete snapshot.' }) : null,
      download);
  }
  return h('div.kit-status', { id }, ...lines, notice);
}

/** "Pass" / "Warning" / "Fail" / "Not applicable": the status in words, not only in colour. */
const STATUS = { pass: 'Pass', warn: 'Warning', fail: 'Fail', skip: 'Not applicable' };

/** A kit check's result list. */
export function verifyResults(res) {
  const verdict = res.verdict === 'complete' ? 'Complete backup' : res.verdict === 'failed' ? 'This kit cannot be used' : 'Incomplete backup';
  return h('section.kit-results', { id: 'kit-verify-results', 'aria-labelledby': 'kit-verify-verdict' },
    h('h3.section-title', { id: 'kit-verify-verdict', tabindex: '-1', dataset: { verdict: res.verdict }, text: verdict }),
    h('ul.kit-checks', {}, ...res.checks.map((c) => h('li', { dataset: { check: c.id, status: c.status } },
      h(`strong.kit-${c.status}`, { text: `${STATUS[c.status] || c.status}: ` }), `${c.label}. `, h('span.muted', { text: c.detail || '' })))),
    res.fixes.length ? h('ul.plan-list', { 'aria-label': 'What to do' }, ...res.fixes.map((f) => h('li', { text: f }))) : null,
    res.logged ? null : h('p.msg.warn', { text: 'The check could not be recorded in the admin audit.' }));
}

/** Download kit: `onDone(result)` after a download (the status changed). */
export function kitDownload({ profile, drive, onDone = () => {} }) {
  const user = userOf(profile);
  const pass1 = secret('kit-pass', 'new-password');
  const pass2 = secret('kit-pass2', 'new-password');
  const weak = h('p.type-hint.warn', { id: 'kit-pass-warn', role: 'note' });
  const syncWeak = () => {
    const n = [...pass1.value].length;
    weak.hidden = n >= SHORT_PASSPHRASE;
    // The warning describes the passphrase field while it shows (and only then).
    if (weak.hidden) pass1.removeAttribute('aria-describedby'); else pass1.setAttribute('aria-describedby', 'kit-pass-warn');
    weak.textContent = n === 0
      ? 'No passphrase: the kit is still encrypted, but with a key anyone can derive. It opens every user’s Drive: store it offline, like the AUTHN secret.'
      : `A short passphrase (under ${SHORT_PASSPHRASE} characters) is easy to guess offline. The kit opens every user’s Drive: store it offline, like the AUTHN secret.`;
  };
  pass1.addEventListener('input', syncWeak);
  syncWeak();
  const mine = secret('kit-confirm', 'current-password');
  const go = h('button.btn', { type: 'button', id: 'kit-download', text: 'Download kit' });
  const { msg, live } = liveMsg('kit-download-msg');
  go.addEventListener('click', async () => {
    if (pass1.value !== pass2.value) return showMsg(msg, 'The two passphrases differ.');
    go.disabled = true;
    showMsg(msg, 'Making the kit…', false);
    try {
      const { confirmStep, canUsePasskey } = await import('./confirm.js');
      const step = await confirmStep(mine, profile.user.username, !mine.value && await canUsePasskey());
      const r = await drive.buildOwnerKit({ user, passphrase: pass1.value, step });
      saveFile(r.text, `secbin-owner-kit-${location.hostname}-v${r.version ?? 'x'}-${new Date().toISOString().slice(0, 10)}.json`);
      const empty = pass1.value === '';
      pass1.value = pass2.value = '';
      syncWeak();
      showMsg(msg, `Kit for escrow key version ${r.version ?? '?'} downloaded. ${empty ? 'It has no passphrase: anyone with the file can open every user’s Drive. ' : ''}Store it offline, like the AUTHN secret, then verify the saved file.${r.unreadable.length ? ` Earlier keys that did not open were left out: ${r.unreadable.join(', ')}.` : ''}`, false);
      toast('Owner recovery kit downloaded.');
      await onDone(r);
    } catch (e) {
      showMsg(msg, friendlyError(e));
    } finally {
      go.disabled = false;
    }
  });
  const el = h('fieldset.range', { id: 'kit-download-set' }, h('legend', { text: 'Download kit' }),
    h('p.type-hint', { text: 'Each download is a new file with your Drive key and the whole current snapshot of escrow keys. Your Drive must be unlocked in this tab.' }),
    h('div.toolbar', {}, field('Kit passphrase (optional)', pass1), field('Repeat the kit passphrase', pass2)), weak,
    field('Your password (or leave it empty to confirm with a passkey)', mine),
    h('div.btn-row', {}, go), live);
  el.focusFirst = () => pass1.focus();
  return el;
}

/** Verify kit: a read-only check of a kit file the owner selects. */
export function kitVerify({ profile, drive }) {
  const user = userOf(profile);
  const file = fileInput('kit-verify-file');
  const pass = secret('kit-verify-pass', 'off');
  const go = h('button.btn', { type: 'button', id: 'kit-verify', text: 'Verify kit', disabled: true, 'aria-describedby': 'kit-verify-hint' });
  const hint = h('p.type-hint', { id: 'kit-verify-hint', text: 'Choose the kit file you saved (from your disk or backup) to check it. Nothing is changed and the file is not uploaded.' });
  const { msg, live } = liveMsg('kit-verify-msg');
  const out = h('div', { id: 'kit-verify-out' });
  const sync = () => { go.disabled = !file.files || !file.files.length; };
  file.addEventListener('change', sync);
  go.addEventListener('click', async () => {
    if (!file.files || !file.files.length) { sync(); return showMsg(msg, 'Choose the kit file first.'); }
    if (throttleWait()) return holdOff(go, msg, sync);
    go.disabled = true;
    out.replaceChildren();
    showMsg(msg, 'Checking the kit…', false);
    // The file's text and the passphrase live only in this call (the inputs are cleared).
    const { text, passphrase } = await takeFile(file, pass, sync);
    try {
      const res = await drive.verifyOwnerKit({ user, text, passphrase });
      if (res.checks.some((c) => (c.id === 'auth' || c.id === 'format') && c.status === 'fail')) failed(); else succeeded();
      msg.hidden = true;
      out.replaceChildren(verifyResults(res));
      out.querySelector('#kit-verify-verdict').focus();
    } catch (e) {
      showMsg(msg, friendlyError(e));
    } finally {
      sync();
    }
  });
  return h('fieldset.range', { id: 'kit-verify-set' }, h('legend', { text: 'Verify kit' }),
    field('Kit file to verify', file), field('Passphrase of the kit to verify', pass), hint,
    h('div.btn-row', {}, go), live, out);
}

/**
 * Restore from kit: everything the owner kit holds comes back — the owner's
 * Drive (a fresh password key), escrow access on current and past keys, and
 * an archived Drive when the kit is for the Drive before a start over.
 * `onRestored(result)` gets { client, restored, missing }.
 */
export function kitRestore({ profile, drive, onRestored = () => {} }) {
  const user = userOf(profile);
  const file = fileInput('kit-restore-file');
  const pass = secret('kit-restore-pass', 'off');
  const mine = secret('kit-restore-pw', 'current-password');
  const go = h('button.btn', { type: 'button', id: 'kit-restore', text: 'Restore from kit', disabled: true, 'aria-describedby': 'kit-restore-hint' });
  const hint = h('p.type-hint', { id: 'kit-restore-hint', text: 'Choose the kit file you saved. Your account password confirms it is you and makes the Drive’s new password key.' });
  const { msg, live } = liveMsg('kit-restore-msg');
  const sync = () => { go.disabled = !file.files || !file.files.length; };
  file.addEventListener('change', sync);
  go.addEventListener('click', async () => {
    if (!file.files || !file.files.length) { sync(); return showMsg(msg, 'Choose the kit file first.'); }
    if (!mine.value) { mine.focus(); return showMsg(msg, 'Enter your account password.'); }
    if (throttleWait()) return holdOff(go, msg, sync);
    go.disabled = true;
    showMsg(msg, 'Opening the kit and restoring…', false);
    const password = mine.value;
    mine.value = '';
    const { text, passphrase } = await takeFile(file, pass, sync);
    try {
      const { salt, t } = await prelogin(profile.user.username);
      const step = { current: await stretch(password, salt, t) };
      const r = await drive.restoreOwnerKit({ user, text, passphrase, password, step });
      succeeded();
      const put = [r.restored.escrow ? 'the escrow key' : '', r.restored.signing ? 'the signing key' : '', r.restored.earlier ? `${r.restored.earlier} earlier escrow key${r.restored.earlier === 1 ? '' : 's'}` : '',
        r.restored.archive ? `your Drive from before you started over (${r.restored.items} item${r.restored.items === 1 ? '' : 's'})` : ''].filter(Boolean);
      showMsg(msg, `Restored: your Drive is unlocked in this tab${r.restored.archive ? '' : ', with a new password key'}.${put.length ? ` Back from the kit: ${put.join(', ')}.` : ''}${r.missing.length ? ` Not in this kit: ${r.missing.join(', ')}.` : ''}`, false);
      toast('Restored from the kit.');
      await onRestored(r);
    } catch (e) {
      if (kitFailure(e)) failed();
      showMsg(msg, friendlyError(e));
    } finally {
      sync();
    }
  });
  return h('fieldset.range', { id: 'kit-restore-set' }, h('legend', { text: 'Restore from kit' }),
    field('Kit file to restore from', file), field('Passphrase of the kit to restore from', pass), field('Your account password', mine), hint,
    h('div.btn-row', {}, go), live);
}

const INTRO = 'A file with your Drive key and every escrow key, sealed with a passphrase in this browser: it is never sent to the server. If you lose your password and passkeys (for example after recovery with the AUTHN secret), the kit gives you back your Drive and access to every user’s Drive; after a start over, it also brings back your earlier Drive. It opens every user’s Drive, so store it offline, like the AUTHN secret; losing both your credentials and every kit loses the escrow. It is not part of the export file, and Drive content never is.';

/**
 * The owner recovery kit card: status, Download kit, Verify kit and Restore
 * from kit — the same on the export screen (`place` 'export') and on the
 * owner's Drive page ('drive': the forms in a disclosure). `status`: the kit
 * status when the caller has it (else read here); `alert`: announce its
 * notice; `onRestored(result)` after a restore.
 */
export function kitCard({ profile, drive, status = null, alert = false, place = 'export', onRestored = () => {} }) {
  const slot = h('div', { id: 'kit-status-slot' });
  const download = kitDownload({ profile, drive, onDone: () => refresh() });
  const forms = [download, kitVerify({ profile, drive }), kitRestore({ profile, drive, onRestored: async (r) => { await refresh(); await onRestored(r); } })];
  const box = place === 'drive' ? h('details', { id: 'kit-forms' }, h('summary', { text: 'Download, verify or restore the kit' }), ...forms) : null;
  const goDownload = () => { if (box) box.open = true; download.focusFirst(); };
  const render = (st, loud) => {
    const dl = h('button.btn.mini', { type: 'button', id: 'kit-notice-download', text: 'Download kit', on: { click: goDownload } });
    slot.replaceChildren(kitStatus(st, { alert: loud, download: dl }));
  };
  async function refresh() {
    try { render(await drive.ownerKitStatus({ user: userOf(profile) }), false); } catch (e) { slot.replaceChildren(h('p.msg.error', { text: `The kit status is unavailable: ${friendlyError(e)}` })); }
  }
  if (status) render(status, alert); else refresh();
  // A section named by its heading (a region): a name on a plain <div> is not allowed (ARIA 1.2).
  return h(`section.card.stack${place === 'drive' ? '.drive-notice' : ''}`, { id: place === 'drive' ? 'drive-kit' : KIT_ANCHOR, tabindex: '-1', 'aria-labelledby': 'kit-title' },
    h('h2.section-title', { id: 'kit-title', text: 'Owner recovery kit' }),
    h('p.subtitle', { text: INTRO }),
    slot,
    ...(box ? [box] : forms));
}
