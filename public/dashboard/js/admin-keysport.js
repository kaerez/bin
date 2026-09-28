// admin-keysport.js — Admin → Import / export → Drive keys (docs/DRIVE.md
// §3.1): the keys parts, in a file of their own (`secbin-keys-export/1`),
// never inside the account export above. Export: the root MEK, the sub-MEKs
// (all or chosen), the user salts and, for the users picked (search, select
// all / deselect all, upload or download an id list), their KEKs and, when
// asked, their files' DEKs (all, or only the file ids listed). The server
// builds the document after the step-up; it is shown here masked (each value
// behind "Show") and sealed in this browser under the export passphrase
// before it is saved. Verify (read-only): decrypt a saved file here; the
// server compares it with its own keys (check values; each DEK on its file's
// first chunk) after the step-up and changes nothing. Import: decrypt here,
// choose the parts, preview (a dry run), then import with the step-up.
// Imports never replace working keys: a
// KEK is only verified (it is derived), a DEK only restores a missing or
// broken seal after it opened the file's first chunk, a salt only comes back
// for an account that has none. DOM through h() only (strict CSP).

import { keysApi, admin, SESSION_CHANGED_EVENT } from '../../js/api.js';
import { h, showMsg, formatDate, friendlyError } from '../../js/common.js';
import { toast, copyText, flashCopied } from '../../js/ui.js';
import { exportKeys, openKeysExport, importKeys, verifyKeysExport, fpText } from '../../js/keysclient.js';
import { ExportCryptError } from '../../js/exportcrypt.js';
import { confirmStep, canUsePasskey } from './confirm.js';
import { field, secret, fileInput, saveText, liveMsg, datePicker, takeFile, verifyResults } from './kit-ui.js';
import { UID_RE, parseIds, idPicker } from './id-list.js';

const NODE_RE = /^[A-Za-z0-9_-]{22}$/;
const SHOW_SEC = 60;
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;

// The keys this page holds (an export built, an import opened) go when the session ends or the
// browser is now signed in as someone else, as on Security → Keys (audit v2r N4).
const onSessionGone = (fn) => {
  if (typeof window === 'undefined') return;
  window.addEventListener('secbin:session-ended', fn);
  window.addEventListener(SESSION_CHANGED_EVENT, fn);
};

async function stepFrom(input, profile) {
  return confirmStep(input, profile.user.username, !input.value && await canUsePasskey());
}

/** A value shown as dots until "Show" (for SHOW_SEC seconds, with copy). */
function masked(label, value) {
  const dots = h('span.mono', { text: '••••••••' });
  const slot = h('span');
  const b = h('button.btn.mini', { type: 'button', text: 'Show', 'aria-label': `Show ${label}` });
  b.addEventListener('click', () => {
    const copy = h('button.copy-btn', { type: 'button', text: 'copy', 'aria-label': `Copy ${label}` });
    copy.addEventListener('click', async () => flashCopied(copy, (await copyText(value)) ? 'copied' : 'failed'));
    const t = setTimeout(() => { slot.replaceChildren(); dots.hidden = false; b.hidden = false; }, SHOW_SEC * 1000);
    const hide = h('button.btn.mini', { type: 'button', text: 'Hide', on: { click: () => { clearTimeout(t); slot.replaceChildren(); dots.hidden = false; b.hidden = false; b.focus(); } } });
    dots.hidden = true;
    b.hidden = true;
    slot.replaceChildren(h('code.mono.key-value', { text: value }), copy, hide);
    hide.focus();
  });
  return h('span', {}, dots, ' ', b, slot);
}

/**
 * The account picker: one checkbox per account (the owner included), with the
 * search, Select all / Deselect all (of those shown), an uploaded id list and
 * a download of the chosen ids (id-list.js). → { el, chosen() }.
 */
function userPicker(accounts, prefix) {
  const rows = accounts.map((u) => {
    const box = h('input', { type: 'checkbox', 'aria-label': `Choose ${u.username}` });
    const el = h('li', { dataset: { id: u.id } },
      h('label.inline', {}, box, h('span', { text: ` ${u.username}` }), h('span.mono.muted', { text: ` ${u.id}${u.role === 'owner' ? ' (you)' : ''}` })));
    return { u, id: u.id, name: u.username, box, el };
  });
  const picker = idPicker(rows, {
    prefix,
    labels: { selectAll: 'Select all users shown', deselectAll: 'Deselect all users shown' },
    download: 'Download the chosen ids (a list of user ids, no keys)',
    hint: 'The downloaded list is a plain text file of the chosen user ids, one per line, with no keys: choose it here again later to pick the same users.',
  });
  return {
    chosen: () => picker.chosen().map((r) => r.u),
    el: h('div.stack', {}, picker.top, h('ul.plain-list.user-pick', { id: `${prefix}-users` }, ...rows.map((r) => r.el)), picker.bottom),
  };
}

/** The document's content, each key masked. */
function docView(doc) {
  const items = [];
  if (doc.root) items.push(h('li', {}, `Root MEK (${fpText(doc.root.fp)}): `, masked('the root MEK', doc.root.key)));
  for (const s of doc.subs || []) items.push(h('li', {}, `Sub-MEK ${s.id} (${fpText(s.fp)}), from ${formatDate(s.from)} ${s.until === null ? 'open-ended' : `until ${formatDate(s.until)}`}: `, masked(`sub-MEK ${s.id}`, s.key)));
  const salts = Object.entries(doc.salts || {});
  if (salts.length) items.push(h('li', {}, `User salts: ${salts.length}`, h('ul.plan-list', {}, ...salts.map(([uid, salt]) => h('li', {}, h('span.mono', { text: uid }), ': ', masked(`the salt of ${uid}`, salt))))));
  for (const u of doc.users || []) {
    const sub = [];
    for (const k of u.keks || []) sub.push(h('li', {}, `KEK for ${k.mekId} (${fpText(k.fp)}): `, masked(`the KEK of ${u.username} for ${k.mekId}`, k.kek)));
    if (u.deks) sub.push(h('li', {}, `File keys (DEKs): ${u.deks.length}`, u.deks.length ? h('ul.plan-list', {}, ...u.deks.slice(0, 200).map((d) => h('li', {}, h('span.mono', { text: d.id }), ': ', masked(`the DEK of ${d.id}`, d.dek))), u.deks.length > 200 ? h('li.muted', { text: `and ${u.deks.length - 200} more` }) : null) : null));
    items.push(h('li', {}, `${u.username ?? u.id} (${u.id})`, sub.length ? h('ul.plan-list', {}, ...sub) : h('span.muted', { text: ': nothing chosen' })));
  }
  return h('ul.plan-list', { 'aria-label': 'What the file holds' }, ...(items.length ? items : [h('li', { text: 'Nothing.' })]));
}

// ── export ──────────────────────────────────────────────────────────────────
function exportPart(profile, accounts, subs) {
  const root = h('input', { type: 'checkbox', id: 'kx-root' });
  const subsMode = h('select.input', { id: 'kx-subs' }, h('option', { value: 'none', text: 'none' }), h('option', { value: 'all', text: 'all' }), h('option', { value: 'some', text: 'the ones chosen below' }));
  const subBoxes = subs.map((s) => ({ s, box: h('input', { type: 'checkbox', 'aria-label': `Sub-MEK ${s.id}` }) }));
  const subList = h('ul.plain-list', { id: 'kx-sub-list', hidden: true }, ...subBoxes.map(({ s, box }) => h('li', {}, h('label.inline', {}, box, h('span.mono', { text: ` ${s.id} (${fpText(s.fp)}) · ${s.status}` })))));
  subsMode.addEventListener('change', () => { subList.hidden = subsMode.value !== 'some'; });
  const picker = userPicker(accounts, 'kx');
  const salts = h('input', { type: 'checkbox', id: 'kx-salts' });
  const keks = h('input', { type: 'checkbox', id: 'kx-keks' });
  const deksMode = h('select.input', { id: 'kx-deks' }, h('option', { value: 'none', text: 'none' }), h('option', { value: 'all', text: 'every file' }), h('option', { value: 'some', text: 'only the file ids listed' }));
  const deksIds = h('textarea.input', { id: 'kx-dek-ids', rows: '3', hidden: true, spellcheck: 'false', 'aria-label': 'File ids (one per line)' });
  deksMode.addEventListener('change', () => { deksIds.hidden = deksMode.value !== 'some'; });
  const mine = secret('kx-confirm', 'current-password');
  const pass1 = secret('kx-pass', 'new-password');
  const pass2 = secret('kx-pass2', 'new-password');
  const noPass = h('p.type-hint.warn', { id: 'kx-nopass', role: 'note', text: 'No passphrase: the file is still encrypted, but with a key anyone can derive. With the root MEK and a sub-MEK (or a KEK), it opens Drive files: store it offline.' });
  pass1.addEventListener('input', () => { noPass.hidden = pass1.value !== ''; });
  const build = h('button.btn', { type: 'button', id: 'kx-build', text: 'Build the export', 'aria-describedby': 'kx-build-hint' });
  const save = h('button.btn', { type: 'button', id: 'kx-save', text: 'Encrypt and download', disabled: true });
  const discard = h('button.btn', { type: 'button', text: 'Discard', disabled: true });
  const { msg, live } = liveMsg('kx-msg');
  const view = h('div', { id: 'kx-view' });
  let doc = null;
  const drop = () => { doc = null; view.replaceChildren(); save.disabled = discard.disabled = true; };
  onSessionGone(drop);
  build.addEventListener('click', async () => {
    const users = picker.chosen();
    const subsPick = subsMode.value === 'all' ? 'all' : subsMode.value === 'some' ? subBoxes.filter((x) => x.box.checked).map((x) => x.s.id) : [];
    const deks = deksMode.value === 'all' ? 'all' : deksMode.value === 'some' ? parseIds(deksIds.value, NODE_RE) : false;
    if (deksMode.value === 'some' && !deks.length) return showMsg(msg, 'List the file ids, one per line.');
    const parts = {
      root: root.checked,
      subs: subsPick,
      salts: salts.checked ? users.map((u) => u.id) : [],
      users: keks.checked || deks ? users.map((u) => ({ id: u.id, keks: keks.checked, deks })) : [],
    };
    if (!parts.root && !(parts.subs === 'all' || parts.subs.length) && !parts.salts.length && !parts.users.length) {
      return showMsg(msg, users.length || !(salts.checked || keks.checked || deks) ? 'Choose what to export.' : 'Choose the users whose keys to export.');
    }
    drop();
    build.disabled = true;
    showMsg(msg, 'Building…', false);
    try {
      // The passphrase is taken at download time; the step-up now.
      const step = await stepFrom(mine, profile);
      const r = await keysApi.exportKeys({ ...parts, ...step });
      doc = r.document;
      msg.hidden = true;
      view.replaceChildren(h('h4.field-label', { text: 'What the file will hold (masked: “Show” reveals a value for 60 seconds)' }), docView(doc));
      save.disabled = discard.disabled = false;
      save.focus();
    } catch (e) {
      showMsg(msg, friendlyError(e));
    } finally {
      build.disabled = false;
    }
  });
  save.addEventListener('click', async () => {
    if (!doc) return;
    if (pass1.value !== pass2.value) return showMsg(msg, 'The two passphrases differ.');
    save.disabled = true;
    try {
      const { text } = await exportKeys({ document: doc, passphrase: pass1.value });
      saveText(text, `secbin-drive-keys-${location.hostname}-${new Date().toISOString().slice(0, 10)}.json`);
      const empty = pass1.value === '';
      pass1.value = pass2.value = '';
      noPass.hidden = false;
      drop();
      showMsg(msg, `Drive keys exported.${empty ? ' It has no passphrase: anyone with the file can read the keys in it.' : ' Keep the file and its passphrase apart.'}`, false);
      toast('Drive keys exported.');
    } catch (e) {
      showMsg(msg, friendlyError(e));
      save.disabled = false;
    }
  });
  discard.addEventListener('click', () => { drop(); msg.hidden = true; });
  return h('fieldset.range', { id: 'kx-set' }, h('legend', { text: 'Export Drive keys' }),
    h('p.type-hint', { text: 'Choose the parts. The root MEK with the sub-MEKs and the user salts rebuilds every KEK; a user’s KEKs alone open that user’s files (with a copy of the stored files); a DEK opens one file. Nothing leaves this browser unencrypted.' }),
    h('label.inline', {}, root, h('span', { text: ' The root MEK' })),
    field('Sub-MEKs', subsMode), subList,
    h('h4.field-label', { text: 'Users' }), picker.el,
    h('label.inline', {}, salts, h('span', { text: ' The user salts of the chosen users' })),
    h('label.inline', {}, keks, h('span', { text: ' Their KEKs (one per sub-MEK)' })),
    field('Their file keys (DEKs)', deksMode), deksIds,
    field('Your password (or leave it empty to confirm with a passkey)', mine),
    h('div.btn-row', {}, build),
    h('p.type-hint', { id: 'kx-build-hint', text: 'Build the export puts the parts ticked above into it: the root MEK and the sub-MEKs chosen, and the chosen users’ salts, KEKs and DEKs (as ticked). It is shown below, masked; “Encrypt and download” then encrypts it with the export passphrase and saves the file.' }), view,
    h('div.toolbar', {}, field('Export passphrase (optional)', pass1), field('Repeat', pass2)), noPass,
    h('div.btn-row', {}, save, discard), live);
}

// ── verify (read-only) ──────────────────────────────────────────────────────
const VERDICTS = { complete: 'Everything in this file matches this server', incomplete: 'Not everything in this file matches this server', failed: 'This file cannot be used' };
function verifyPart(profile) {
  const file = fileInput('kv-file');
  const pass = secret('kv-pass', 'off');
  const day = datePicker('kv-date');
  const mine = secret('kv-confirm', 'current-password');
  const go = h('button.btn', { type: 'button', id: 'kv-verify', text: 'Verify', disabled: true, 'aria-describedby': 'kv-hint' });
  const { msg, live } = liveMsg('kv-msg');
  const out = h('div', { id: 'kv-out' });
  onSessionGone(() => out.replaceChildren());
  const sync = () => { go.disabled = !file.files || !file.files.length; };
  file.addEventListener('change', sync);
  go.addEventListener('click', async () => {
    const f = file.files && file.files[0];
    if (!f) return;
    if (f.size > 16 * 1024 * 1024) return showMsg(msg, 'That file is too large (max 16 MiB).');
    go.disabled = true;
    out.replaceChildren();
    showMsg(msg, 'Decrypting…', false);
    const date = day.seconds();
    // The selected file, never a copy kept by this page: the input and its passphrase are cleared.
    const { text, passphrase } = await takeFile(file, pass, sync);
    try {
      const doc = await openKeysExport(text, passphrase);
      showMsg(msg, 'Checking…', false);
      const res = await verifyKeysExport({ doc, step: await stepFrom(mine, profile), date });
      msg.hidden = true;
      out.replaceChildren(verifyResults(res, 'kv', VERDICTS));
      out.querySelector('#kv-verdict').focus();
    } catch (e) {
      showMsg(msg, e instanceof ExportCryptError ? e.message : friendlyError(e));
    } finally {
      sync();
    }
  });
  return h('fieldset.range', { id: 'kv-set' }, h('legend', { text: 'Verify a Drive keys export' }),
    h('p.type-hint', { id: 'kv-hint', text: 'Check a saved export before you rely on it. The file is decrypted in this browser; the server compares its keys with its own (check values for the root MEK, sub-MEKs, user salts and KEKs; each DEK is tried on its file’s first chunk), changes nothing and sends no key back. The date (today by default; a future date too) shows which sub-MEK is in effect then and whether the file holds it.' }),
    h('div.toolbar', {}, field('Drive keys export file to verify', file), field('Its passphrase', pass)),
    field('The sub-MEK in effect on', day.el),
    field('Your password (or leave it empty to confirm with a passkey)', mine),
    h('div.btn-row', {}, go), live, out);
}

// ── import ──────────────────────────────────────────────────────────────────
function importPart(profile) {
  const file = fileInput('ki-file');
  const pass = secret('ki-pass', 'off');
  const open = h('button.btn', { type: 'button', id: 'ki-open', text: 'Decrypt' });
  const { msg, live } = liveMsg('ki-msg');
  const review = h('div.stack', { id: 'ki-review' });
  onSessionGone(() => review.replaceChildren());
  open.addEventListener('click', async () => {
    const f = file.files && file.files[0];
    if (!f) return showMsg(msg, 'Choose a Drive keys export file.');
    if (f.size > 16 * 1024 * 1024) return showMsg(msg, 'That file is too large (max 16 MiB).');
    open.disabled = true;
    showMsg(msg, 'Decrypting…', false);
    try {
      const doc = await openKeysExport(await f.text(), pass.value);
      pass.value = '';
      msg.hidden = true;
      renderImport(review, doc, profile);
    } catch (e) {
      review.replaceChildren();
      showMsg(msg, e instanceof ExportCryptError ? e.message : friendlyError(e));
    } finally {
      open.disabled = false;
    }
  });
  return h('fieldset.range', { id: 'ki-set' }, h('legend', { text: 'Import Drive keys' }),
    h('p.type-hint', { text: 'Imports never replace keys that work here. The root MEK and sub-MEKs come back only when missing or broken (or, on an empty instance, the root when you ask for it); a user salt only for an account that has none. A KEK is made by the server from the other keys, so importing one only checks it. A DEK puts back a file key whose seal is missing or broken, after it opened the file’s first chunk.' }),
    h('div.toolbar', {}, field('Drive keys export file', file), field('Its passphrase', pass), open), live, review);
}

function renderImport(out, doc, profile) {
  const has = { root: !!doc.root, subs: !!doc.subs?.length, salts: !!Object.keys(doc.salts || {}).length, keks: (doc.users || []).some((u) => u.keks?.length), deks: (doc.users || []).some((u) => u.deks?.length) };
  const label = { root: 'The root MEK', subs: `Sub-MEKs (${doc.subs?.length ?? 0})`, salts: `User salts (${Object.keys(doc.salts || {}).length})`, keks: 'KEKs (checked only)', deks: 'File keys (DEKs)' };
  const take = {};
  const boxes = Object.keys(has).filter((k) => has[k]).map((k) => {
    take[k] = h('input', { type: 'checkbox', id: `ki-take-${k}`, checked: true });
    return h('label.inline', {}, take[k], h('span', { text: ` ${label[k]}` }));
  });
  const useRoot = h('input', { type: 'checkbox', id: 'ki-use-root' });
  const mine = secret('ki-confirm', 'current-password');
  const preview = h('button.btn', { type: 'button', id: 'ki-preview', text: 'Preview' });
  const apply = h('button.btn.danger', { type: 'button', id: 'ki-apply', text: 'Import', disabled: true });
  const { msg, live } = liveMsg('ki-plan-msg');
  const plan = h('div', { id: 'ki-plan' });
  let previewed = null;
  const chosen = () => ({ take: Object.fromEntries(Object.entries(take).map(([k, b]) => [k, b.checked])), useRoot: useRoot.checked });
  const invalidate = () => { previewed = null; apply.disabled = true; };
  for (const b of [...Object.values(take), useRoot]) b.addEventListener('change', invalidate);
  const show = (r) => {
    const li = [];
    if (r.keys) {
      li.push(`Root MEK: ${r.keys.root}`);
      if (r.keys.subs.length) li.push(`Sub-MEKs: ${r.keys.subs.map((s) => `${s.id} ${s.result}`).join(', ')}`);
      const s = r.keys.salts;
      li.push(`User salts: ${s.restored} put back, ${s.same} already here, ${s.kept} kept (the server’s differ), ${s.wrong ?? 0} left out (they do not open that user’s Drive), ${s.unknown} for no account here`);
    }
    for (const u of r.users) {
      const bits = [];
      if (u.error) bits.push(u.error);
      if (u.keks) bits.push(`KEKs: ${u.keks.match} match, ${u.keks.mismatch} differ, ${u.keks.unknown} for no sub-MEK here`);
      if (u.deks) bits.push(`DEKs: ${u.deks.restored} ${r.dryRun ? 'to restore' : 'restored'}, ${u.deks.working} already working, ${u.deks.failed} failed the check, ${u.deks.missing} for no file here`);
      li.push(`${u.username ?? u.id}: ${bits.join('; ') || 'nothing'}`);
    }
    plan.replaceChildren(h('h4.field-label', { text: r.dryRun ? 'Preview (nothing changed yet)' : 'Imported' }), h('ul.plan-list', {}, ...li.map((t) => h('li.mono', { text: t }))));
  };
  preview.addEventListener('click', async () => {
    preview.disabled = true;
    showMsg(msg, 'Checking…', false);
    try {
      const c = chosen();
      // The preview too needs the step-up: it checks the file's KEKs and names the users.
      const r = await importKeys({ doc, ...c, dryRun: true, step: await stepFrom(mine, profile) });
      show(r);
      previewed = JSON.stringify(c);
      apply.disabled = false;
      showMsg(msg, 'Preview ready: review it, then import.', false);
    } catch (e) {
      showMsg(msg, friendlyError(e));
    } finally {
      preview.disabled = false;
    }
  });
  apply.addEventListener('click', async () => {
    const c = chosen();
    if (previewed !== JSON.stringify(c)) return invalidate();
    apply.disabled = true;
    showMsg(msg, 'Importing…', false);
    try {
      const r = await importKeys({ doc, ...c, dryRun: false, step: await stepFrom(mine, profile) });
      show(r);
      previewed = null;
      showMsg(msg, 'Imported.', false);
      toast('Drive keys imported.');
    } catch (e) {
      showMsg(msg, friendlyError(e));
      apply.disabled = false;
    }
  });
  out.replaceChildren(
    h('p.mono.muted', { text: `Drive keys from ${doc.origin || 'an unknown origin'} · ${formatDate(doc.created)} · ${plural((doc.users || []).length, 'user')}` }),
    h('details', {}, h('summary', { text: 'What the file holds (masked)' }), docView(doc)),
    h('fieldset.range', {}, h('legend', { text: 'Parts to import' }), ...boxes,
      has.root ? h('label.inline', {}, useRoot, h('span', { text: ' Replace the root MEK here with the file’s (only on an empty instance: no Drive item yet)' })) : null),
    field('Your password, for the preview and again for the import (or leave it empty to confirm with a passkey)', mine),
    h('div.btn-row', {}, preview), plan,
    h('div.btn-row', {}, apply), live);
}

/** The Drive keys card of Import / export. */
export async function keysPortCard(profile) {
  const card = h('div.card.stack', { id: 'drive-keys-port', 'aria-labelledby': 'kport-title' },
    h('h2.section-title', { id: 'kport-title', text: 'Drive keys' }));
  let accounts;
  let subs;
  try {
    const [u, st] = await Promise.all([admin.users(), keysApi.status()]);
    accounts = u.users.filter((x) => x.role !== 'public' && UID_RE.test(x.id));
    subs = st.subs || [];
  } catch (e) {
    card.append(h('p.msg.error', { role: 'alert', text: `The Drive keys are unavailable: ${friendlyError(e)}` }));
    return card;
  }
  card.append(
    h('p.subtitle', { text: 'A file of its own, never part of the export above: the keys that open Drive files. The key kit (Security → Keys) holds everything at once; here you choose the parts. Every export, verify and import is in the admin audit (what, not the keys).' }),
    exportPart(profile, accounts, subs), verifyPart(profile), importPart(profile));
  return card;
}
