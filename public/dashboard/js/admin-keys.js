// admin-keys.js — Admin → Security → Keys (docs/DRIVE.md §3, §3.1, §3.3):
// the Drive keyring (the root MEK and the sub-MEKs: generate, view, add,
// rotate, edit dates, set current, re-seal, delete, change the root), the key
// kit (download, verify with a date, restore), the upgrade of Drives made
// before the key model v2 (per user, with progress), one user's keys, and a
// restore from a user's personal kit (the only place one restores). Every change and every view needs the owner's password or a passkey (the
// step-up) and is in the admin audit by fingerprint only. Plain-language
// help sits next to every action. DOM through h() only (strict CSP).

import { keysApi, drive as driveApi, admin, SESSION_CHANGED_EVENT } from '../../js/api.js';
import { h, clear, showMsg, formatDate, formatBytes, friendlyError, armConfirm } from '../../js/common.js';
import { toast, copyText, flashCopied } from '../../js/ui.js';
import { progressBar } from '../../js/progress.js';
import { parseManualKey } from '../../js/drivekeys.js';
import { b64urlFromBytes } from '../../js/bytes.js';
import { buildKeyKit, verifyKeyKit, restoreKeyKit, restoreUserKit, fpText } from '../../js/keysclient.js';
import { confirmStep, canUsePasskey, confirmLabel } from './confirm.js';
import {
  field, secret, fileInput, datePicker, passphrasePair, saveText, takeFile, verifyResults, throttleWait, kitFailed, kitSucceeded, kitFailure, holdOff, liveMsg,
} from './kit-ui.js';

export const KEYS_ANCHOR = 'keys';
const SHOW_SEC = 60;
const STATUS_TEXT = { current: 'current', scheduled: 'scheduled', retired: 'retired', overlapped: 'overlapped (a later one wins)' };

const HELP = {
  intro: 'Every Drive file is encrypted in the browser with its own random key, and that key is sealed under the user’s Drive key (KEK). The server makes each user’s KEK from the root MEK, a sub-MEK and the user’s salt, all kept here, so the server can open every Drive: keep these keys, and the key kit, safe. Losing them loses every Drive file.',
  root: 'The root MEK is part of every user’s Drive key and seals the sub-MEKs. Changing it re-seals every item of every Drive under the new one (this page does it, with progress); nothing else changes for users.',
  subs: 'Sub-MEKs rotate over time. New items use the current one; older items keep theirs until they are re-sealed. Items name the sub-MEK they use, so the dates only decide which one is current.',
  add: 'Adds a sub-MEK that becomes the current one from the date you choose (now by default; a later date schedules it). Items made after that use it.',
  rotate: 'Rotating means new data uses a new sub-MEK from now on; old data stays readable with its old sub-MEK until it is re-sealed.',
  reseal: 'Re-sealing moves every item under this sub-MEK to the current one (the server opens and seals each item; nothing is downloaded). Users notice nothing.',
  remove: 'Deleting a sub-MEK first re-seals everything that uses it, then deletes it. Without the key kit, a deleted sub-MEK cannot come back.',
  current: 'Makes this sub-MEK the current one from now on: new items use it. Any other sub-MEK still running ends now (a scheduled one is cancelled).',
  dates: 'Change when a sub-MEK is in effect. There must always be exactly one open-ended sub-MEK and no gap from now on.',
  show: 'Shows the key’s value for 60 seconds (logged). Anyone who sees it, with the rest of the keyring, can open Drive files.',
  kit: 'After any change, download a fresh key kit and store it somewhere safe, offline. It holds the root MEK, every sub-MEK with its dates and every user salt, and restores everything.',
  manual: 'Generate a key out of band and paste it here (base64 or hex, exactly 32 bytes), for example: openssl rand -base64 32 — or in PowerShell: [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)) (not Get-Random, which is not a secure generator) — or from a hardware security module or secrets manager. Keep a copy in a secrets manager.',
};

/** The step-up for one action: the password in `input` (cleared), or a passkey when it is empty. */
async function stepFrom(input, profile) {
  return confirmStep(input, profile.user.username, !input.value && await canUsePasskey());
}

// Key values this page holds (one user's keys, a key shown): dropped when the session ends (the
// idle lock: 'secbin:session-ended') or the browser is now signed in as someone else (api.js
// SESSION_CHANGED_EVENT), as the Drive page drops its KEKs; seeing them again takes a new step-up
// (audit v2r N4). JavaScript strings cannot be overwritten: the references go.
const held = new Set();
function dropHeld() {
  for (const f of [...held]) f();
  held.clear();
}
if (typeof window !== 'undefined') {
  window.addEventListener('secbin:session-ended', dropHeld);
  window.addEventListener(SESSION_CHANGED_EVENT, dropHeld);
}

/** Show a key's value for SHOW_SEC seconds in `slot`, with a copy button; then it is hidden again. */
function reveal(slot, key, label) {
  const val = h('code.mono.key-value', { text: key });
  const copy = h('button.copy-btn', { type: 'button', text: 'copy', 'aria-label': `Copy ${label}` });
  copy.addEventListener('click', async () => flashCopied(copy, (await copyText(key)) ? 'copied' : 'failed'));
  const hide = h('button.btn.mini', { type: 'button', text: 'Hide' });
  const box = h('div.key-reveal', { role: 'status' }, h('span.field-label', { text: `${label} (hidden again in ${SHOW_SEC} seconds): ` }), val, copy, hide);
  const gone = () => { clearTimeout(t); box.remove(); held.delete(gone); };
  const t = setTimeout(gone, SHOW_SEC * 1000);
  hide.addEventListener('click', gone);
  held.add(gone);
  slot.replaceChildren(box);
  hide.focus();
}

/**
 * Choose the key for a new sub-MEK or a new root: "Generate securely" asks
 * the server for a candidate (shown here; nothing is stored until "Use this
 * key"), "Generate another", or "Enter manually" (a password-type field, with
 * the out-of-band tooltip). → a promise of { candidate } | { key } | null.
 */
function keyChooser({ purpose, profile, confirmIn, box }) {
  return new Promise((resolve) => {
    const { msg, live } = liveMsg();
    const shown = h('div.stack');
    const manualIn = h('input.input', { type: 'password', id: `${purpose}-manual`, autocomplete: 'off', spellcheck: 'false', maxlength: '200', 'aria-describedby': `${purpose}-manual-help` });
    const manualHelp = h('p.type-hint', { id: `${purpose}-manual-help`, text: HELP.manual });
    const gen = h('button.btn', { type: 'button', text: 'Generate securely' });
    const useManual = h('button.btn', { type: 'button', text: 'Use the key I entered' });
    const cancel = h('button.btn', { type: 'button', text: 'Cancel' });
    let cand = null;
    const done = (v) => { box.replaceChildren(); resolve(v); };
    gen.addEventListener('click', async () => {
      gen.disabled = true;
      showMsg(msg, 'Generating…', false);
      try {
        cand = await keysApi.candidate(purpose, await stepFrom(confirmIn, profile));
        msg.hidden = true;
        const use = h('button.btn', { type: 'button', text: 'Use this key' });
        const again = h('button.btn', { type: 'button', text: 'Generate another' });
        const copy = h('button.copy-btn', { type: 'button', text: 'copy', 'aria-label': 'Copy the generated key' });
        copy.addEventListener('click', async () => flashCopied(copy, (await copyText(cand.key)) ? 'copied' : 'failed'));
        use.addEventListener('click', () => done({ candidate: cand.id }));
        again.addEventListener('click', () => gen.click());
        shown.replaceChildren(
          h('p', {}, 'Generated key (fingerprint ', h('span.mono', { text: fpText(cand.fp) }), '): '),
          h('code.mono.key-value', { text: cand.key }), copy,
          h('p.type-hint', { text: 'Copy it somewhere safe (a secrets manager), or download the key kit afterwards. Nothing is stored until you choose “Use this key” (enter your password again above first, or leave it empty for a passkey); the server forgets it after 10 minutes.' }),
          h('div.btn-row', {}, use, again));
        use.focus();
      } catch (e) {
        showMsg(msg, friendlyError(e));
      } finally {
        gen.disabled = false;
      }
    });
    useManual.addEventListener('click', () => {
      try {
        const key = b64urlFromBytes(parseManualKey(manualIn.value));
        manualIn.value = '';
        done({ key });
      } catch (e) {
        showMsg(msg, e.message);
        manualIn.focus();
      }
    });
    cancel.addEventListener('click', () => done(null));
    box.replaceChildren(h('div.card.stack.key-chooser', { role: 'group', 'aria-label': purpose === 'root' ? 'The new root MEK' : 'The new sub-MEK' },
      h('div.btn-row', {}, gen), shown,
      h('details', {}, h('summary', { text: 'Enter manually' }), field('Key (32 bytes, base64 or hex)', manualIn, manualHelp), h('div.btn-row', {}, useManual)),
      h('div.btn-row', {}, cancel), live));
    gen.focus();
  });
}

/** A date-and-time field ("from"), empty = now. → { el, seconds() } (null when empty). */
function whenInput(id, label) {
  const el = h('input.input', { id, type: 'datetime-local', 'aria-label': label });
  return { el, seconds: () => (el.value ? Math.floor(new Date(el.value).getTime() / 1000) : null) };
}
const toLocal = (sec) => {
  if (!sec) return '';
  const d = new Date(sec * 1000);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
};

/**
 * The Security → Keys section: the keyring card, the key kit card, the
 * upgrade of old Drives and one user's keys.
 */
export function keysSection({ profile }) {
  const root = h('section.stack', { id: KEYS_ANCHOR, tabindex: '-1', 'aria-labelledby': 'keys-title' },
    h('h2.section-title', { id: 'keys-title', text: 'Keys' }), h('p.msg', { role: 'status', text: 'Loading the Drive keys…' }));
  let loud = false; // the fresh-kit notice is announced once, right after a change here
  const render = async () => {
    let st;
    try { st = await keysApi.status(); } catch (e) { root.replaceChildren(h('h2.section-title', { id: 'keys-title', text: 'Keys' }), h('p.msg.error', { role: 'alert', text: `The Drive keys are unavailable: ${friendlyError(e)}` })); return; }
    root.replaceChildren(h('h2.section-title', { id: 'keys-title', text: 'Keys' }),
      keyringCard(st, profile, { loud, changed: () => { loud = true; render(); } }),
      keyKitCard(st, profile, () => { loud = false; render(); }),
      upgradeCard(profile),
      userKeysCard(profile),
      userKitCard(profile));
    loud = false;
  };
  render();
  return root;
}

// ── the keyring ─────────────────────────────────────────────────────────────
function keyringCard(st, profile, { loud, changed }) {
  const confirmIn = h('input.input', { type: 'password', id: 'keys-confirm', autocomplete: 'current-password', maxlength: '1024' });
  const confirmText = h('span.field-label', { text: 'Your password (asked again for every action)' });
  canUsePasskey().then((ok) => { confirmText.textContent = confirmLabel('Your password (asked again for every action)', ok); }).catch(() => {});
  const { msg, live: msgLive } = liveMsg('keys-msg');
  const work = h('div', { id: 'keys-work' });
  const shown = h('div', { id: 'keys-shown' });
  const act = async (fn, ok) => {
    msg.hidden = true;
    try {
      const r = await fn(await stepFrom(confirmIn, profile));
      if (ok) toast(ok);
      return r;
    } catch (e) {
      showMsg(msg, friendlyError(e));
      return null;
    }
  };
  const card = h('div.card.stack', { id: 'keys-ring', 'aria-labelledby': 'keys-ring-title' },
    h('h3.section-title', { id: 'keys-ring-title', text: 'Drive keys' }), h('p.subtitle', { text: HELP.intro }));
  if (st.lost) {
    card.append(h('p.msg.error', { role: 'alert', text: 'The root MEK is missing: no Drive can be opened. Restore it from the key kit below. Nothing was deleted.' }));
    return card;
  }
  if (!st.kitFresh) {
    card.append(h('div.kit-notice', { id: 'keys-kit-notice', role: loud ? 'alert' : 'note' },
      h('p.msg.warn', { text: st.kit ? 'The keys changed since the last key kit (or users were added): download a fresh key kit and store it somewhere safe, offline.' : 'No key kit has been downloaded yet: download one (below) and store it somewhere safe, offline.' })));
  }
  card.append(h('label.field', {}, confirmText, confirmIn));
  // The root MEK.
  const r = st.root;
  const showRoot = h('button.btn', { type: 'button', text: 'Show', 'aria-describedby': 'keys-root-help' });
  showRoot.addEventListener('click', async () => { const x = await act((step) => keysApi.show(null, step)); if (x) reveal(shown, x.key, 'Root MEK'); });
  const change = h('button.btn.danger', { type: 'button', text: 'Change root…', 'aria-describedby': 'keys-root-help', disabled: !!r?.changing });
  change.addEventListener('click', async () => {
    const choice = await keyChooser({ purpose: 'root', profile, confirmIn, box: work });
    if (!choice) return;
    const x = await act((step) => keysApi.changeRoot({ ...choice, ...step }), 'The root MEK changed: every item is being re-sealed.');
    if (x) { await runJob(work); changed(); }
  });
  card.append(h('div.stack', { id: 'keys-root' },
    h('h4.field-label', { text: 'Root MEK' }),
    h('p', {}, 'Fingerprint ', h('span.mono', { text: fpText(r?.fp) }), ` · created ${formatDate(r?.created)}`, r?.changing ? ` · being changed (the old root ${fpText(r.oldFp)} stays until every item is re-sealed and checked)` : ''),
    h('p.type-hint', { id: 'keys-root-help', text: HELP.root }),
    h('div.btn-row', {}, showRoot, change)));
  // A root change whose re-seal ended with items that do not open under the new root: the three ways on.
  if (r?.changing && (!st.job || (st.job.finished && st.job.kind === 'root' && !st.job.result?.ok))) card.append(stuckRoot(st, { act, work, changed }));
  // The sub-MEKs.
  const usage = new Map();
  const tbody = h('tbody');
  const rows = st.subs.slice().sort((a, b) => b.from - a.from);
  const draw = () => {
    clear(tbody);
    for (const s of rows) {
      const items = usage.has(s.id) ? String(usage.get(s.id)) : '…';
      const acts = h('div.btn-row.row-actions');
      const btn = (text, help, fn, cls = '') => {
        const b = h(`button.btn.mini${cls}`, { type: 'button', text, title: help, 'aria-label': `${text} ${s.id}` });
        b.addEventListener('click', fn);
        acts.appendChild(b);
        return b;
      };
      btn('Show', HELP.show, async () => { const x = await act((step) => keysApi.show(s.id, step)); if (x) reveal(shown, x.key, `Sub-MEK ${s.id}`); });
      btn('Edit dates', HELP.dates, () => editDates(s));
      if (s.status !== 'current') btn('Set as current', HELP.current, async () => { if (await act((step) => keysApi.setCurrent(s.id, step), `${s.id} is the current sub-MEK.`)) changed(); });
      if (s.status !== 'current') {
        btn('Re-seal', HELP.reseal, async () => {
          if (await act((step) => keysApi.startJob({ from: s.id, ...step }))) { await runJob(work); changed(); }
        });
        const del = btn('Delete', HELP.remove, () => {}, '.danger');
        armConfirm(del, `Re-seal ${usage.get(s.id) ?? 'its'} item(s), then delete?`, async () => {
          if ((usage.get(s.id) || 0) === 0) { if (await act((step) => keysApi.remove(s.id, step), `${s.id} was deleted.`)) changed(); return; }
          if (await act((step) => keysApi.startJob({ from: s.id, remove: true, ...step }))) { await runJob(work); changed(); }
        });
      }
      tbody.appendChild(h('tr', { dataset: { id: s.id, status: s.status } },
        h('td.mono', { dataset: { label: 'Id' }, text: s.id }),
        h('td.mono', { dataset: { label: 'Fingerprint' }, text: fpText(s.fp) }),
        h('td.mono', { dataset: { label: 'From' }, text: formatDate(s.from) }),
        h('td.mono', { dataset: { label: 'Until' }, text: s.until === null ? 'open-ended' : formatDate(s.until) }),
        h('td', { dataset: { label: 'Status' } }, h(`span.pill.${s.status === 'current' ? 'ok' : s.status === 'scheduled' ? 'warn' : 'muted'}`, { text: STATUS_TEXT[s.status] || s.status }), s.opens ? null : h('span.msg.error', { text: ' does not open under the root: restore it' })),
        h('td.mono', { dataset: { label: 'Items' }, text: items }),
        h('td', { dataset: { label: 'Note' }, text: s.note || '' }),
        h('td.cell-actions', {}, acts)));
    }
  };
  draw();
  keysApi.usage().then((u) => { for (const s of rows) usage.set(s.id, u.counts[s.id] || 0); draw(); }).catch(() => {});
  const editDates = (s) => {
    const from = h('input.input', { type: 'datetime-local', id: 'keys-edit-from', value: toLocal(s.from) });
    const open = h('input', { type: 'checkbox', id: 'keys-edit-open', checked: s.until === null });
    const until = h('input.input', { type: 'datetime-local', id: 'keys-edit-until', value: toLocal(s.until), disabled: s.until === null });
    open.addEventListener('change', () => { until.disabled = open.checked; });
    const note = h('input.input', { id: 'keys-edit-note', maxlength: '100', value: s.note || '' });
    const save = h('button.btn', { type: 'button', text: 'Save dates' });
    save.addEventListener('click', async () => {
      const body = { from: Math.floor(new Date(from.value).getTime() / 1000), until: open.checked ? null : Math.floor(new Date(until.value).getTime() / 1000), note: note.value.trim() };
      if (!Number.isSafeInteger(body.from) || (body.until !== null && !Number.isSafeInteger(body.until))) return showMsg(msg, 'Enter valid dates.');
      if (await act((step) => keysApi.edit(s.id, { ...body, ...step }), 'Dates saved.')) changed();
    });
    work.replaceChildren(h('div.card.stack', { role: 'group', 'aria-label': `Dates of ${s.id}` },
      h('p.type-hint', { text: HELP.dates }),
      field('In effect from', from), h('label.inline', {}, open, h('span', { text: ' Open-ended (no end date)' })), field('Until', until), field('Note (for you)', note),
      h('div.btn-row', {}, save, h('button.btn', { type: 'button', text: 'Cancel', on: { click: () => work.replaceChildren() } }))));
    from.focus();
  };
  const addWhen = whenInput('keys-add-from', 'In effect from (empty: now)');
  const addNote = h('input.input', { id: 'keys-add-note', maxlength: '100', 'aria-label': 'Note for the new sub-MEK (optional)' });
  const addBtn = h('button.btn', { type: 'button', text: 'Add a sub-MEK…', 'aria-describedby': 'keys-add-help' });
  const rotateBtn = h('button.btn', { type: 'button', text: 'Rotate now…', 'aria-describedby': 'keys-rotate-help' });
  const add = async (rotate) => {
    const choice = await keyChooser({ purpose: 'sub', profile, confirmIn, box: work });
    if (!choice) return;
    const from = rotate ? null : addWhen.seconds();
    if (await act((step) => keysApi.add({ ...choice, rotate, ...(from ? { from } : {}), note: addNote.value.trim(), ...step }), rotate ? 'A new sub-MEK is current from now on.' : 'Sub-MEK added.')) changed();
  };
  addBtn.addEventListener('click', () => add(false));
  rotateBtn.addEventListener('click', () => add(true));
  card.append(h('div.stack', { id: 'keys-subs' },
    h('h4.field-label', { text: 'Sub-MEKs' }), h('p.type-hint', { text: HELP.subs }),
    h('div.table-wrap', {}, h('table.table', { id: 'keys-subs-table' }, h('caption.sr-only', { text: 'Sub-MEKs' }),
      h('thead', {}, h('tr', {}, ...['Id', 'Fingerprint', 'From', 'Until', 'Status', 'Items', 'Note'].map((t) => h('th', { scope: 'col', text: t })), h('th', { scope: 'col' }, h('span.sr-only', { text: 'Actions' })))),
      tbody)),
    h('div.toolbar', {}, field('New sub-MEK in effect from (empty: now)', addWhen.el), field('Note (optional)', addNote)),
    h('p.type-hint', { id: 'keys-add-help', text: HELP.add }), h('p.type-hint', { id: 'keys-rotate-help', text: HELP.rotate }),
    h('div.btn-row', {}, addBtn, rotateBtn)),
  shown, work, msgLive);
  // A job left running (a re-seal, a root change): it carries on here.
  if (st.job && !st.job.finished) queueMicrotask(() => runJob(work).then(changed));
  return card;
}

/**
 * A root change that could not finish (docs/DRIVE.md §3): the items listed
 * open under neither root, or only under the previous one. Run the re-seal
 * again (after putting them right: a kit, an import), go back to the previous
 * root (everything is re-sealed under it again), or remove the previous root
 * and leave those items unreadable (its fingerprint typed to confirm).
 */
function stuckRoot(st, { act, work, changed }) {
  // The count comes from the root change's own check, kept with it (the job can be cleared).
  const check = st.root.check;
  const ids = check?.ids || [];
  const retry = h('button.btn', { type: 'button', id: 'keys-root-retry', text: 'Run the re-seal again' });
  retry.addEventListener('click', async () => { if (await act((step) => keysApi.startJob({ kind: 'root', ...step }))) { await runJob(work); changed(); } });
  const undo = h('button.btn', { type: 'button', id: 'keys-root-undo', text: 'Go back to the previous root' });
  if (st.root.oldOrigin !== 'changed') undo.title = 'The previous root was put back from a key kit: going back first checks that it opens items here.';
  armConfirm(undo, 'Re-seal every item under the previous root?', async () => { if (await act((step) => keysApi.undoRoot(step), 'Going back to the previous root: every item is being re-sealed under it.')) { await runJob(work); changed(); } });
  const typed = h('input.input', { id: 'keys-root-drop-confirm', autocomplete: 'off', spellcheck: 'false', maxlength: '40' });
  const n = check ? check.failed : null;
  const drop = h('button.btn.danger', { type: 'button', id: 'keys-root-drop', text: n === null ? 'Remove the previous root' : `Remove the previous root (${n} item${n === 1 ? '' : 's'} stay${n === 1 ? 's' : ''} unreadable)`, disabled: n === null });
  drop.addEventListener('click', async () => {
    const x = await act((step) => keysApi.dropOldRoot({ confirm: typed.value.trim(), ...step }));
    if (x) { toast(`The previous root MEK was removed; ${x.lost} item${x.lost === 1 ? '' : 's'} stay${x.lost === 1 ? 's' : ''} unreadable.`); changed(); }
  });
  return h('div.card.stack.drive-notice', { id: 'keys-root-stuck', role: 'alert' },
    h('h4.field-label', { text: 'The root change could not finish' }),
    h('p', { id: 'keys-root-stuck-count', text: check ? `${check.failed} item(s) do not open under the new root MEK${ids.length ? ` (${ids.join(', ')}${check.failed > ids.length ? ', …' : ''})` : ''}. The previous root MEK is kept for them, and every session still gets both keys.` : 'The previous root MEK is still here, and no re-seal has checked the items under these two roots yet: run it again to finish the change (it checks every item).' }),
    h('p.type-hint', { text: 'Run the re-seal again once those items are put right (a key kit or an import brings back what is missing). Or go back to the previous root: every item is re-sealed under it again, then the new one goes. Or remove the previous root: the items that open only under it, or under neither, stay unreadable for good.' }),
    h('div.btn-row', {}, retry, undo),
    field(`To remove the previous root, type its fingerprint (${fpText(st.root.oldFp)})`, typed), h('div.btn-row', {}, drop));
}

/** Drive the re-seal job to its end, with its progress → its result. */
async function runJob(box) {
  const bar = progressBar();
  const text = h('p.mono', { role: 'status' });
  box.replaceChildren(h('div.card.stack', { id: 'keys-job' }, h('h4.field-label', { text: 'Re-sealing' }), bar.el, text));
  let job = null;
  for (let n = 0; n < 100000; n++) {
    try {
      ({ job } = await keysApi.stepJob());
    } catch (e) {
      text.textContent = `Stopped: ${friendlyError(e)} It carries on when this page is opened again.`;
      bar.hide();
      return null;
    }
    if (!job) break;
    text.textContent = job.verifying
      ? `Root change: checking Drive ${job.drive} of ${job.drives}${job.phase === 'verifyrest' ? ' (link keys)' : ''}, ${job.failed ? `${job.failed} do not open under the new root` : 'everything opens under the new root so far'}.`
      : `${job.kind === 'root' ? 'Root change' : `Sub-MEK ${job.from}`}: Drive ${job.drive} of ${job.drives}${job.phase === 'atrest' ? ' (link keys)' : ''}, ${job.done} re-sealed${job.failed ? `, ${job.failed} could not be opened` : ''}${job.pass > 1 ? ` (pass ${job.pass})` : ''}.`;
    bar.set('Re-sealing…', job.drives ? Math.min(1, (job.drive - 1) / job.drives) : 1);
    if (job.finished) break;
  }
  if (job && job.result) {
    bar.done('Re-seal: done');
    text.textContent = `${job.result.message}${!job.result.ok && job.failedIds?.length ? ` Items: ${job.failedIds.join(', ')}${job.failed > job.failedIds.length ? ', …' : ''}.` : ''}`;
    toast(job.result.message, job.result.ok ? {} : { error: true });
  }
  return job;
}

// ── the key kit ─────────────────────────────────────────────────────────────
function keyKitCard(st, profile, refreshed) {
  const ownerId = profile.user.id;
  const pp = passphrasePair('kkit', 'every Drive');
  const mine = secret('kkit-confirm', 'current-password');
  const go = h('button.btn', { type: 'button', id: 'kkit-download', text: 'Download key kit' });
  const { msg, live } = liveMsg('kkit-download-msg');
  go.addEventListener('click', async () => {
    if (pp.pass1.value !== pp.pass2.value) return showMsg(msg, 'The two passphrases differ.');
    go.disabled = true;
    showMsg(msg, 'Making the key kit…', false);
    try {
      const r = await buildKeyKit({ ownerId, passphrase: pp.pass1.value, step: await stepFrom(mine, profile) });
      saveText(r.text, `secbin-key-kit-${location.hostname}-${new Date().toISOString().slice(0, 10)}.json`);
      const empty = pp.pass1.value === '';
      pp.pass1.value = pp.pass2.value = '';
      pp.sync();
      showMsg(msg, `Key kit downloaded: the root MEK, ${r.subs} sub-MEK${r.subs === 1 ? '' : 's'} and ${r.users} user salt${r.users === 1 ? '' : 's'}. ${empty ? 'It has no passphrase: anyone with the file can open every Drive (with a copy of the stored files). ' : ''}Store it somewhere safe, offline, then verify the saved file.`, false);
      toast('Key kit downloaded.');
      refreshed();
    } catch (e) {
      showMsg(msg, friendlyError(e));
    } finally {
      go.disabled = false;
    }
  });
  const download = h('fieldset.range', { id: 'kkit-download-set' }, h('legend', { text: 'Download' }),
    h('p.type-hint', { text: 'Each download is a new file with every key as it is now. If a sub-MEK is lost and not in a kit, the items under it cannot be opened by anyone.' }),
    pp.el, field('Your password (or leave it empty to confirm with a passkey)', mine), h('div.btn-row', {}, go), live);
  // Verify.
  const vfile = fileInput('kkit-verify-file');
  const vpass = secret('kkit-verify-pass', 'off');
  const day = datePicker('kkit-verify-date');
  const vgo = h('button.btn', { type: 'button', id: 'kkit-verify', text: 'Verify key kit', disabled: true, 'aria-describedby': 'kkit-verify-hint' });
  const { msg: vmsg, live: vlive } = liveMsg('kkit-verify-msg');
  const vout = h('div', { id: 'kkit-verify-out' });
  const vsync = () => { vgo.disabled = !vfile.files || !vfile.files.length; };
  vfile.addEventListener('change', vsync);
  vgo.addEventListener('click', async () => {
    if (throttleWait()) return holdOff(vgo, vmsg, vsync);
    vgo.disabled = true;
    vout.replaceChildren();
    showMsg(vmsg, 'Checking the key kit…', false);
    const date = day.seconds();
    const { text, passphrase } = await takeFile(vfile, vpass, vsync);
    try {
      const res = await verifyKeyKit({ ownerId, text, passphrase, date });
      if (res.verdict === 'failed') kitFailed(); else kitSucceeded();
      vmsg.hidden = true;
      vout.replaceChildren(verifyResults(res, 'kkit-verify'));
      vout.querySelector('#kkit-verify-verdict').focus();
    } catch (e) {
      showMsg(vmsg, friendlyError(e));
    } finally {
      vsync();
    }
  });
  const verify = h('fieldset.range', { id: 'kkit-verify-set' }, h('legend', { text: 'Verify' }),
    field('Key kit file to verify', vfile), field('Its passphrase', vpass), field('The sub-MEK in effect on', day.el),
    h('p.type-hint', { id: 'kkit-verify-hint', text: 'Choose the key kit file you saved. Nothing is changed and the file is not uploaded: the server compares check values and answers match or no match. The date (today by default; a future date too) shows which sub-MEK is in effect then and whether the kit holds it.' }),
    h('div.btn-row', {}, vgo), vlive, vout);
  // Restore (a preview first).
  const rfile = fileInput('kkit-restore-file');
  const rpass = secret('kkit-restore-pass', 'off');
  const rmine = secret('kkit-restore-confirm', 'current-password');
  const useRoot = h('input', { type: 'checkbox', id: 'kkit-use-root' });
  const preview = h('button.btn', { type: 'button', id: 'kkit-preview', text: 'Preview the restore', disabled: true });
  const apply = h('button.btn.danger', { type: 'button', id: 'kkit-restore', text: 'Restore', disabled: true });
  const { msg: rmsg, live: rlive } = liveMsg('kkit-restore-msg');
  const plan = h('div', { id: 'kkit-restore-plan' });
  let held = null; // the file's text and passphrase, only between the preview and the restore
  const rsync = () => { preview.disabled = !rfile.files || !rfile.files.length; };
  rfile.addEventListener('change', () => { held = null; apply.disabled = true; plan.replaceChildren(); rsync(); });
  useRoot.addEventListener('change', () => { held = null; apply.disabled = true; plan.replaceChildren(); });
  const show = (r) => {
    const subs = (r.subs || []).map((s) => `${s.id}: ${s.result}`);
    plan.replaceChildren(h('ul.plan-list', {},
      h('li', { text: `Root MEK: ${r.root}` }), r.rootOld && r.rootOld !== 'absent' ? h('li', { text: `The previous root MEK (the kit was made during a root change): ${r.rootOld}${r.rootOld === 'restored' ? ' — then run the root change’s re-seal again (above)' : ''}` }) : null,
      h('li', { text: `Sub-MEKs: ${subs.join(', ') || 'none in the file'}` }),
      h('li', { text: `User salts: ${r.salts.restored} put back, ${r.salts.same} already here, ${r.salts.kept} kept (the server’s differ), ${r.salts.wrong ?? 0} left out (they do not open that user’s Drive), ${r.salts.unknown} for no account here` })),
    h('p.type-hint', { text: r.changed ? (r.dryRun ? 'Nothing changed yet: restore to apply.' : 'Restored.') : 'Nothing to restore: everything in the kit is already here (working keys are never replaced).' }));
  };
  preview.addEventListener('click', async () => {
    if (throttleWait()) return holdOff(preview, rmsg, rsync);
    preview.disabled = true;
    showMsg(rmsg, 'Opening the kit…', false);
    const { text, passphrase } = await takeFile(rfile, rpass, rsync);
    try {
      // The preview too needs the step-up: it tells which of the kit's keys match this server's.
      const step = await stepFrom(rmine, profile);
      const r = await restoreKeyKit({ ownerId, text, passphrase, dryRun: true, useRoot: useRoot.checked, step });
      kitSucceeded();
      held = { text, passphrase };
      rmsg.hidden = true;
      show(r);
      apply.disabled = !r.changed;
    } catch (e) {
      if (kitFailure(e)) kitFailed();
      showMsg(rmsg, friendlyError(e));
    } finally {
      rsync();
    }
  });
  apply.addEventListener('click', async () => {
    if (!held) return;
    apply.disabled = true;
    try {
      const r = await restoreKeyKit({ ownerId, ...held, dryRun: false, useRoot: useRoot.checked, step: await stepFrom(rmine, profile) });
      held = null;
      show(r);
      toast('Restored from the key kit.');
      refreshed();
    } catch (e) {
      showMsg(rmsg, friendlyError(e));
      apply.disabled = false;
    }
  });
  const restore = h('fieldset.range', { id: 'kkit-restore-set' }, h('legend', { text: 'Restore' }),
    field('Key kit file to restore from', rfile), field('Its passphrase', rpass),
    h('label.inline', {}, useRoot, h('span', { text: ' Use the kit’s root MEK (only on an empty instance: no Drive item yet)' })),
    h('p.type-hint', { text: 'Only what this server lost comes back: the root MEK when there is none (or none of the sub-MEKs opens under the one here), sub-MEKs that are missing or do not open, and user salts of accounts that have none. Working keys are never replaced.' }),
    field('Your password, for the preview and again for the restore (or leave it empty to confirm with a passkey)', rmine),
    h('div.btn-row', {}, preview), plan, h('div.btn-row', {}, apply), rlive);
  const last = st.kit ? `Latest key kit: ${formatDate(st.kit.at)}${st.kitFresh ? ' (it covers every key and user)' : ' (older than the latest change)'}.` : 'No key kit downloaded yet.';
  return h('div.card.stack', { id: 'keys-kit', 'aria-labelledby': 'keys-kit-title' },
    h('h3.section-title', { id: 'keys-kit-title', text: 'Key kit' }), h('p.subtitle', { text: HELP.kit }), h('p.mono', { id: 'keys-kit-last', text: last }),
    download, verify, restore);
}

// ── the upgrade of Drives made before the key model v2 ────────────────────
/**
 * The Drives still waiting, each with "Upgrade now" through the escrow of
 * that release (the step-up: the password, once for "Upgrade every waiting
 * Drive"), disabled accounts included; links a Drive's old key does not open
 * are listed with "Retire these links". The owner's archive of that release
 * (a start over) shows below it when there is one.
 */
function upgradeCard(profile) {
  const card = h('div.card.stack', { id: 'keys-upgrade', 'aria-labelledby': 'keys-upgrade-title', hidden: true },
    h('h3.section-title', { id: 'keys-upgrade-title', text: 'Drive upgrade' }));
  const confirmIn = secret('keys-upgrade-confirm', 'current-password');
  const draw = async () => {
    let r;
    try { r = await driveApi.migration(); } catch { card.hidden = true; return; }
    const drives = r.drives || [];
    const archive = await driveApi.archive().catch(() => null);
    const hasArchive = !!archive && (archive.items > 0 || archive.links.length > 0);
    if ((!drives.length || (!r.left && !r.legacyEscrow)) && !hasArchive) { card.hidden = true; return; }
    card.hidden = false;
    const tbody = h('tbody');
    const all = h('button.btn', { type: 'button', id: 'keys-upgrade-all', text: 'Upgrade every waiting Drive' });
    const bar = progressBar();
    const { msg, live } = liveMsg('keys-upgrade-msg');
    const extra = h('div', { id: 'keys-upgrade-links' });
    const one = async (d, btn, step) => {
      btn.disabled = true;
      bar.set(`Upgrading ${d.username}…`, 0);
      const onProgress = (p) => bar.set(`${d.username}: ${p.phase === 'verify' ? `${p.done} verified` : `${p.done} done, ${p.left} left`}`, p.phase === 'verify' ? 0.95 : p.done / Math.max(1, p.done + (p.left || 0)));
      try {
        const up = await import('../../js/driveupgrade.js');
        const x = await up.upgradeUserDrive({ ownerId: profile.user.id, userId: d.id, step, onProgress });
        if (x.unopened && x.unopened.length) {
          bar.hide();
          extra.replaceChildren(retireBox(d, x.unopened, up, onProgress));
          return false;
        }
        bar.done(`${d.username}: done`);
        toast(`${d.username}’s Drive is upgraded${x.damaged ? ` (${x.damaged} damaged item${x.damaged === 1 ? '' : 's'} kept)` : ''}.`);
        return true;
      } catch (e) {
        bar.hide();
        showMsg(msg, `${d.username}: ${friendlyError(e)}`);
        btn.disabled = false;
        return false;
      }
    };
    // A Drive's links that its old key does not open: they end (their keys go) so that its upgrade finishes.
    const retireBox = (d, ids, up, onProgress) => {
      const pw = secret('keys-retire-confirm', 'current-password');
      const go = h('button.btn.danger', { type: 'button', id: 'keys-retire', text: `Retire ${ids.length === 1 ? 'this link' : 'these links'}` });
      go.addEventListener('click', async () => {
        go.disabled = true;
        try {
          const x = await up.retireLinks({ ids, step: await stepFrom(pw, profile), target: d.id, onProgress });
          extra.replaceChildren();
          toast(`${d.username}: ${x.retired} link${x.retired === 1 ? '' : 's'} retired${x.done ? '; the Drive is upgraded' : ''}.`);
          draw();
        } catch (e) {
          go.disabled = false;
          showMsg(msg, `${d.username}: ${friendlyError(e)}`);
        }
      });
      return h('div.card.stack', { role: 'group', 'aria-label': `${d.username}’s links that do not open` },
        h('p', { text: `${d.username}’s Drive has ${ids.length} “Receive” link${ids.length === 1 ? '' : 's'} whose key the old Drive key does not open. Retiring ends ${ids.length === 1 ? 'it' : 'them'} and removes ${ids.length === 1 ? 'its key' : 'their keys'}; files received but not taken in are listed as failed in that Drive. Then the upgrade finishes.` }),
        h('ul.plan-list.mono', {}, ...ids.map((id) => h('li', { text: id }))),
        field('Your password (or leave it empty to confirm with a passkey)', pw), h('div.btn-row', {}, go));
    };
    for (const d of drives) {
      const btn = h('button.btn.mini', { type: 'button', text: d.id === profile.user.id ? 'On your Drive page' : 'Upgrade now', disabled: d.state === 'done' || d.id === profile.user.id, 'aria-label': `Upgrade ${d.username}’s Drive` });
      btn.addEventListener('click', async () => {
        msg.hidden = true;
        let step;
        try { step = await stepFrom(confirmIn, profile); } catch (e) { showMsg(msg, friendlyError(e)); return; }
        if (await one(d, btn, step)) draw();
      });
      tbody.appendChild(h('tr', { dataset: { id: d.id, state: d.state } },
        h('td', { dataset: { label: 'User' }, text: `${d.id === profile.user.id ? `${d.username} (you)` : d.username}${d.disabled ? ' (disabled)' : ''}` }),
        h('td', { dataset: { label: 'State' }, text: d.state === 'done' ? 'upgraded' : 'waiting' }),
        h('td.mono', { dataset: { label: 'Items left' }, text: d.state === 'done' ? '0' : String((d.v1Items ?? 0) + (d.v1Links ?? 0)) }),
        h('td.cell-actions', {}, btn)));
    }
    all.addEventListener('click', async () => {
      msg.hidden = true;
      all.disabled = true;
      // One confirmation for the whole run (a password is asked once; a passkey check serves one Drive).
      let step;
      try { step = await stepFrom(confirmIn, profile); } catch (e) { showMsg(msg, friendlyError(e)); all.disabled = false; return; }
      for (const d of drives.filter((x) => x.state !== 'done' && x.id !== profile.user.id)) {
        const btn = tbody.querySelector(`tr[data-id="${d.id}"] button`);
        if (!(await one(d, btn || all, step))) break;
      }
      draw();
    });
    const upgrading = drives.length && (r.left || r.legacyEscrow);
    card.replaceChildren(...[h('h3.section-title', { id: 'keys-upgrade-title', text: 'Drive upgrade' }),
      upgrading ? h('p.subtitle', { text: 'Drives made before this release use the old Drive keys until they are upgraded: each item is sealed again under its user’s new key and checked, then the old keys (and, once every Drive is upgraded, your escrow keys) are removed. A user’s own Drive page does it after their next sign-in; you can do it here, through your escrow key of that release, for users who have not signed in (disabled accounts too). Your own old Drive key must be open in this tab: it is when you signed in with your password. The root MEK cannot be changed while a Drive waits.' }) : null,
      upgrading ? h('div.table-wrap', {}, h('table.table', { id: 'keys-upgrade-table' }, h('caption.sr-only', { text: 'Drives and their upgrade' }),
        h('thead', {}, h('tr', {}, ...['User', 'State', 'Items left'].map((t) => h('th', { scope: 'col', text: t })), h('th', { scope: 'col' }, h('span.sr-only', { text: 'Actions' })))),
        tbody)) : null,
      upgrading ? field('Your password, to confirm “Upgrade now” (or leave it empty to confirm with a passkey)', confirmIn) : null,
      upgrading && r.left > 1 ? h('div.btn-row', {}, all) : null, bar.el, live, extra,
      hasArchive ? archiveBox(archive, profile, draw) : null].filter(Boolean));
  };
  draw();
  return card;
}

/**
 * The owner's Drive archive of the release before (a start over): kept as it
 * was, opened by nothing here. Deleting it removes its content and ends the
 * links it paused (the step-up, the username typed; admin audit).
 */
function archiveBox(a, profile, redraw) {
  const typed = h('input.input', { id: 'keys-archive-confirm', autocomplete: 'off', spellcheck: 'false', maxlength: '64' });
  const pw = secret('keys-archive-pw', 'current-password');
  const go = h('button.btn.danger', { type: 'button', id: 'keys-archive-delete', text: 'Delete the archive' });
  const { msg, live } = liveMsg('keys-archive-msg');
  go.addEventListener('click', async () => {
    msg.hidden = true;
    go.disabled = true;
    try {
      const r = await driveApi.deleteArchive({ confirm: typed.value.trim(), ...(await stepFrom(pw, profile)) });
      toast(`The archive was deleted (${r.items} item${r.items === 1 ? '' : 's'}${r.links ? `; ${r.links} paused link${r.links === 1 ? '' : 's'} ended` : ''}).`);
      redraw();
    } catch (e) {
      go.disabled = false;
      showMsg(msg, friendlyError(e));
    }
  });
  return h('div.card.stack', { id: 'keys-archive', role: 'group', 'aria-labelledby': 'keys-archive-title' },
    h('h4.field-label', { id: 'keys-archive-title', text: 'Your Drive archive of the previous release' }),
    h('p', { text: `When you started your Drive over in the previous release, its items were kept as an archive: ${a.items} item${a.items === 1 ? '' : 's'} (${formatBytes(a.bytes)}${a.received ? `, of which ${a.received} received through “Receive” links` : ''}), sealed under that release’s key, and ${a.links.length} link${a.links.length === 1 ? '' : 's'} paused with it. Nothing here opens it any more, and it does not count towards your Drive’s storage.` }),
    h('p.type-hint', { text: 'Deleting it removes its content from storage for good and ends the paused links; files received through them and not yet taken in are listed as failed. A recovery kit of that release can open the archive offline only as long as its content exists.' }),
    field(`Type your username (${profile.user.username}) to confirm`, typed), field('Your password (or leave it empty to confirm with a passkey)', pw),
    h('div.btn-row', {}, go), live);
}

// ── one user's keys ─────────────────────────────────────────────────────────
/**
 * A list of every account (the owner included, not the public one) for one
 * user's action; `label`: its accessible name when no visible label wraps it.
 * `onLoad()` once the accounts are in; `onError(e)` if they do not load.
 */
function userSelect(id, { label = null, onLoad = () => {}, onError = () => {} } = {}) {
  const el = h('select.input', { id, ...(label ? { 'aria-label': label } : {}) });
  admin.users().then((r) => {
    el.replaceChildren(...r.users.filter((u) => u.role !== 'public').map((u) => h('option', { value: u.id, dataset: { username: u.username }, text: u.role === 'owner' ? `${u.username} (you)` : u.username })));
    onLoad();
  }).catch(onError);
  return el;
}

function userKeysCard(profile) {
  const { msg, live } = liveMsg('keys-user-msg');
  const pick = userSelect('keys-user', { label: 'User', onError: (e) => showMsg(msg, friendlyError(e)) });
  const mine = secret('keys-user-confirm', 'current-password');
  const go = h('button.btn', { type: 'button', id: 'keys-user-view', text: 'View keys' });
  const deks = h('button.btn', { type: 'button', id: 'keys-user-deks', text: 'List file keys (DEKs)' });
  const out = h('div', { id: 'keys-user-out' });
  // The values fetched stay in this card only until the session ends or changes (dropHeld).
  const ref = { values: [] };
  const drop = () => {
    ref.values = [];
    if (out.childNodes.length) {
      out.replaceChildren(h('p.type-hint', { text: 'The keys shown here were cleared when your session ended or changed. Confirm again to see them.' }));
    }
  };
  held.add(drop);
  const masked = (label, value) => {
    const slot = h('span');
    const i = ref.values.push(value) - 1;
    const b = h('button.btn.mini', { type: 'button', text: 'Show', 'aria-label': `Show ${label}` });
    b.addEventListener('click', () => { const v = ref.values[i]; if (v) reveal(slot, v, label); });
    return h('span', {}, h('span.mono', { text: '••••••••' }), ' ', b, slot);
  };
  go.addEventListener('click', async () => {
    msg.hidden = true;
    try {
      const r = await keysApi.userView(pick.value, { what: 'keks', ...(await stepFrom(mine, profile)) });
      held.add(drop);
      ref.values = [];
      out.replaceChildren(h('ul.plan-list', {},
        h('li', {}, 'User salt: ', masked(`the salt of ${r.username}`, r.salt)),
        ...r.keks.map((k) => h('li', {}, `KEK for ${k.mekId} (${fpText(k.fp)})${k.inUse ? ', used by their items' : ''}${k.mekId === r.current ? ', current' : ''}: `, masked(`the KEK of ${r.username} for ${k.mekId}`, k.kek)))));
    } catch (e) {
      showMsg(msg, friendlyError(e));
    }
  });
  deks.addEventListener('click', async () => {
    msg.hidden = true;
    try {
      const step = await stepFrom(mine, profile);
      const r = await keysApi.userView(pick.value, { what: 'deks', ...step });
      held.add(drop);
      ref.values = [];
      out.replaceChildren(...[r.files.length ? h('ul.plan-list', {}, ...r.files.map((f) => h('li', {}, h('span.mono', { text: f.id }), ` ${f.name ?? '(name does not open)'}: `, f.dek ? masked(`the DEK of ${f.id}`, f.dek) : 'does not open')))
        : h('p.mono', { text: 'No files.' }), r.next ? h('p.type-hint', { text: 'More files: the first 100 are shown.' }) : null].filter(Boolean));
    } catch (e) {
      showMsg(msg, friendlyError(e));
    }
  });
  return h('div.card.stack', { id: 'keys-user-card', 'aria-labelledby': 'keys-user-title' },
    h('h3.section-title', { id: 'keys-user-title', text: 'A user’s Drive keys' }),
    h('p.subtitle', { text: 'Read-only: a user’s salt and KEKs, or their files’ keys (DEKs) with each file’s name. Each view is in the admin audit (ids and counts only); the values stay masked until you choose Show and hide again after 60 seconds.' }),
    h('div.toolbar', {}, field('User', pick), field('Your password (or leave it empty to confirm with a passkey)', mine)),
    h('div.btn-row', {}, go, deks), live, out);
}

// ── a user's personal kit, restored here ─────────────────────────────────────
const KIT_SALT = {
  restored: 'the user salt was put back', same: 'the user salt was already there',
  kept: 'the user salt on the server was kept (it is not the kit’s)', wrong: 'the kit’s salt does not open this user’s Drive, so it was not used', absent: '',
};

/**
 * Restore a user's personal kit: the owner only (no Account page restores),
 * so that no user can change what opens a Drive. The user is chosen here and
 * the kit opens in this browser for that user only; the server takes only
 * what it lost (the salt, items under a Drive key it no longer has) and never
 * replaces a working key. The step-up: a password is asked once; a passkey
 * again for each further call a large Drive needs.
 */
function userKitCard(profile) {
  const { msg, live } = liveMsg('ukr-msg');
  const file = fileInput('ukr-file');
  const pass = secret('ukr-pass', 'off');
  const mine = secret('ukr-confirm', 'current-password');
  const go = h('button.btn', { type: 'button', id: 'ukr-restore', text: 'Restore from the personal kit', disabled: true, 'aria-describedby': 'ukr-hint' });
  const pick = userSelect('ukr-user', { onLoad: () => sync(), onError: (e) => showMsg(msg, friendlyError(e)) });
  const sync = () => { go.disabled = !file.files || !file.files.length || !pick.value; };
  pick.addEventListener('change', sync);
  file.addEventListener('change', sync);
  go.addEventListener('click', async () => {
    if (!file.files || !file.files.length || !pick.value) { sync(); return showMsg(msg, 'Choose the user and their kit file first.'); }
    if (throttleWait()) return holdOff(go, msg, sync);
    go.disabled = true;
    const user = { id: pick.value, username: pick.selectedOptions[0]?.dataset.username || pick.value };
    showMsg(msg, 'Opening the kit and restoring…', false);
    try {
      const first = await stepFrom(mine, profile);
      const { text, passphrase } = await takeFile(file, pass, sync);
      const step = async (n) => (n === 0 || first.current ? first : stepFrom(mine, profile));
      const r = await restoreUserKit({ userId: user.id, text, passphrase, step, onProgress: (n) => showMsg(msg, `Restoring… ${n} item${n === 1 ? '' : 's'} sealed again`, false) });
      kitSucceeded();
      const parts = [KIT_SALT[r.salt] || '', r.unreadable.length ? `${r.done} item${r.done === 1 ? '' : 's'} sealed again under the current key` : 'nothing else was missing'].filter(Boolean);
      showMsg(msg, `Restore done for ${user.username}: ${parts.join('; ')}.${r.failed ? ` ${r.failed} did not open with the kit and stay as they are.` : ''}${r.left.length ? ` The kit has no key for ${r.left.length} of the Drive keys the server lost: the key kit may.` : ''}`, false);
      toast(`Restored from ${user.username}’s personal kit.`);
    } catch (e) {
      if (kitFailure(e)) kitFailed();
      showMsg(msg, friendlyError(e));
    } finally {
      sync();
    }
  });
  return h('div.card.stack', { id: 'keys-user-kit', 'aria-labelledby': 'keys-user-kit-title' },
    h('h3.section-title', { id: 'keys-user-kit-title', text: 'Restore a user’s personal kit' }),
    h('p.subtitle', { text: 'Only you restore from a personal kit, so no user can change what opens a Drive. Choose the user, then their kit file and its passphrase. The kit opens in this browser and must be that user’s; its file is not uploaded.' }),
    h('div.toolbar', {}, field('User whose kit it is', pick), field('Personal kit file', file), field('Its passphrase', pass)),
    h('p.type-hint', { id: 'ukr-hint', text: 'Only what the server lost comes back: the user’s salt if the server has none (and only if it opens their files), and files sealed under a Drive key the server no longer has, sealed again under the current key. A working key is never replaced. The restore is in the admin audit (ids and counts only).' }),
    field('Your password (or leave it empty to confirm with a passkey)', mine), h('div.btn-row', {}, go), live);
}
