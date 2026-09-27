// admin-portable.js — Admin → Import / export. Exports are built by the
// server for the signed-in owner and encrypted HERE, with a passphrase, before
// they are saved (public/js/exportcrypt.js); imports are decrypted here,
// previewed (a dry run on the server) and then applied all-or-nothing. Both
// ask for the owner's password again. Every part is chosen per user (a table
// of users × parts) when exporting and again when importing. The owner's
// password and recovery codes are never exported; its passkeys only when
// asked. An import never changes an existing account's password, recovery
// codes, API keys or passkeys: it only sets its role and adds passkeys.

import { admin, ApiError } from '../../js/api.js';
import { loginProof } from '../../js/pwauth.js';
import { sealExport, openExport, ExportCryptError } from '../../js/exportcrypt.js';
import { h, clear, showMsg, formatDate, friendlyError } from '../../js/common.js';
import { toast } from '../../js/ui.js';

const field = (label, control, hint) => h('label.field', {}, h('span.field-label', { text: label }), control, hint ? h('span.mono.muted', { text: hint }) : null);
const check = (label, checked = false, note = '') => {
  const input = h('input', { type: 'checkbox', checked });
  return { input, el: h('label.inline.part-opt', {}, input, h('span', {}, ` ${label}`, note ? h('span.mono.muted.block', { text: note }) : null)) };
};
const box = (label, checked = false) => h('input', { type: 'checkbox', checked, 'aria-label': label });
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
// What each part holds, and what to know about it (shown on export and import).
const SYSTEM_PARTS = [
  ['settings', 'Settings', 'Server-wide settings (brute-force protection, lockout, logs, public access, accessibility statement…).'],
  ['roles', 'Roles', 'The Default role and every custom role (limits, quotas, viewer rules). On import, roles are created or replaced by name, never deleted.'],
  ['ipRules', 'IP rules', 'Manual allow / block rules. On import they are added, never removed.'],
  ['turnstile', 'Turnstile keys', 'The site key and SECRET set in Security → Human check (not the deployment\'s own). The widget must allow the target hostname.'],
  ['public', 'Public account', 'The anonymous account\'s limits, quotas and viewer rules.'],
];
const USER_PARTS = [
  ['credentials', 'Credentials', 'User name, password verifier (not the password), disabled flag. Needed to create an account on the target; an existing account keeps its own.'],
  ['role', 'Role', 'Which role the user has (by name; export the roles too). The only setting an import changes on an existing account (never the owner\'s).'],
  ['apiKeys', 'API keys', 'The stored key hashes, names, scopes and dates: the same keys keep working on the target. Revoking a key on one server does not revoke it on the other. Only for new accounts.'],
  ['passkeys', 'Passkeys', `Public keys and the "Password and passkey" choice. Passkeys work only on the same hostname (${location.hostname}). On import they are added (existing passkeys stay); an existing account keeps its own choice.`],
  ['recoveryCodes', 'Recovery codes', 'The recovery-code hashes. Recovery codes work anywhere (any hostname). Only for new accounts: an existing account keeps its own.'],
];
const OWNER_NOTE = `Your own passkeys (public keys). Off by default. Passkeys work only on the same hostname (${location.hostname}). Your password and recovery codes are never exported.`;
const pw = (label, autocomplete) => h('input.input', { type: 'password', autocomplete, 'aria-label': label, maxlength: '256' });

/** Select all / Deselect all for a set of checkboxes (a part column, or the users). */
function bulk(label, what, boxes) {
  const set = (on) => () => {
    for (const b of boxes()) {
      if (b.disabled || b.checked === on) continue;
      b.checked = on;
      b.dispatchEvent(new Event('change', { bubbles: true }));
    }
  };
  return h('div.toolbar.bulk-row', {}, h('span.field-label', { text: label }),
    h('button.btn.mini', { type: 'button', text: 'Select all', 'aria-label': `Select all: ${what}`, on: { click: set(true) } }),
    h('button.btn.mini', { type: 'button', text: 'Deselect all', 'aria-label': `Deselect all: ${what}`, on: { click: set(false) } }));
}
const partNotes = () => h('ul.plan-list.part-notes', {}, ...USER_PARTS.map(([, label, note]) => h('li.mono.muted', {}, h('strong', { text: `${label}: ` }), note)));

export async function renderPortable(panel, profile) {
  const p = clear(panel);
  let users = [];
  try { users = (await admin.users()).users.filter((u) => u.role === 'user'); } catch (e) { showMsg(p.appendChild(h('p.msg')), friendlyError(e)); }
  p.appendChild(exportCard(users, profile));
  p.appendChild(importCard(users, profile));
}

// ── export ───────────────────────────────────────────────────────────────────
function exportCard(users, profile) {
  const sysChecks = SYSTEM_PARTS.map(([k, label, note]) => ({ k, ...check(label, k !== 'turnstile', note) }));
  const ownerCheck = check('Owner passkeys', false, OWNER_NOTE);
  // One row per user: whether to export it, and each part (the role is on by default).
  const rows = users.map((u) => ({
    u,
    pick: box(`Export ${u.username}`),
    parts: Object.fromEntries(USER_PARTS.map(([k, label]) => [k, box(`${label} for ${u.username}`, k === 'role')])),
  }));
  const table = rows.length ? h('div.table-wrap', {}, h('table.table.part-table', {},
    h('thead', {}, h('tr', {}, h('th', { text: 'Export' }), h('th', { text: 'User' }), ...USER_PARTS.map(([, label]) => h('th', { text: label })))),
    h('tbody', {}, ...rows.map((r) => h('tr', {},
      h('td', { dataset: { label: 'Export' } }, r.pick), h('td', { dataset: { label: 'User' }, text: r.u.username }),
      ...USER_PARTS.map(([k, label]) => h('td', { dataset: { label } }, r.parts[k]))))))) : h('p.mono.muted', { text: 'No users to export.' });
  const bulks = rows.length ? h('div.stack.bulk', {},
    bulk('Users', 'users to export', () => rows.map((r) => r.pick)),
    ...USER_PARTS.map(([k, label]) => bulk(label, `${label} for every user`, () => rows.map((r) => r.parts[k])))) : null;
  const pass1 = pw('Export passphrase', 'new-password');
  const pass2 = pw('Repeat export passphrase', 'new-password');
  // An empty passphrase is allowed, but then the encryption protects nothing.
  const noPass = h('p.type-hint.warn', { role: 'note', text: 'No passphrase: the file is still encrypted, but with a key anyone can derive, so anyone who gets it can read the password verifiers (enough to test guesses offline), API-key hashes, passkeys, recovery-code hashes and the Turnstile secret in it.' });
  const syncNoPass = () => { noPass.hidden = pass1.value !== ''; };
  pass1.addEventListener('input', syncNoPass);
  syncNoPass();
  const mine = pw('Your password', 'current-password');
  const msg = h('p.msg', { role: 'status', hidden: true });
  const go = h('button.btn', { type: 'button', text: 'Encrypt and download' });

  go.onclick = async () => {
    const chosen = rows.filter((r) => r.pick.checked).map((r) => ({ r, parts: USER_PARTS.map(([k]) => k).filter((k) => r.parts[k].checked) }));
    const system = Object.fromEntries(sysChecks.map((c) => [c.k, c.input.checked]));
    const anySys = Object.values(system).some(Boolean);
    const ownerPasskeys = ownerCheck.input.checked;
    if (!anySys && !ownerPasskeys && !chosen.length) return showMsg(msg, 'Choose some system parts, your passkeys and/or some users.');
    const empty = chosen.find((c) => !c.parts.length);
    if (empty) return showMsg(msg, `Choose what to export for "${empty.r.u.username}", or leave it out.`);
    if (pass1.value !== pass2.value) return showMsg(msg, 'The two passphrases differ.');
    if (!mine.value) return showMsg(msg, 'Enter your password to confirm.');
    go.disabled = true;
    showMsg(msg, 'Exporting and encrypting…', false);
    try {
      const current = await loginProof(profile.user.username, mine.value);
      const { document } = await admin.exportData({ current, system: anySys ? system : false, ownerPasskeys, users: chosen.map((c) => ({ id: c.r.u.id, parts: c.parts })) });
      const text = await sealExport(document, pass1.value);
      download(text, `secbin-export-${location.hostname}-${new Date().toISOString().slice(0, 10)}.json`);
      const what = `Exported ${document.system ? 'the system configuration, ' : ''}${document.owner ? 'your passkeys, ' : ''}${plural(document.users.length, 'user')}.`;
      showMsg(msg, pass1.value ? `${what} Keep the file and its passphrase apart.` : `${what} No passphrase: anyone with the file can read it.`, false);
      toast('Export saved.');
      pass1.value = pass2.value = mine.value = '';
      syncNoPass();
    } catch (e) {
      showMsg(msg, e instanceof ExportCryptError ? e.message : friendlyError(e));
      toast(e instanceof ExportCryptError ? e.message : friendlyError(e), { error: true });
    } finally {
      go.disabled = false;
    }
  };

  return h('div.card.stack', {},
    h('h2.section-title', { text: 'Export' }),
    h('p.subtitle', { text: 'The file is encrypted in your browser (Argon2id + AES-256-GCM) with the passphrase below — without it, it cannot be read or imported. Sessions and shares are never exported, nor your own password and recovery codes. Credentials, API keys, passkeys and the Turnstile secret let accounts and services keep working on the target: treat the file as sensitive, and export only what you need.' }),
    h('fieldset.range', {}, h('legend', { text: 'System' }), ...sysChecks.map((c) => c.el)),
    h('fieldset.range', {}, h('legend', { text: 'Owner' }), ownerCheck.el),
    h('fieldset.range', {}, h('legend', { text: 'Users and what to export for each' }), bulks, table, partNotes()),
    h('div.toolbar', {}, field('Export passphrase (optional)', pass1), field('Repeat', pass2)), noPass,
    field('Your password (confirms it is you)', mine),
    h('div.btn-row', {}, go), msg);
}

function download(text, name) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  const a = h('a', { href: url, download: name, hidden: true });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

// ── import ───────────────────────────────────────────────────────────────────
function importCard(users, profile) {
  const file = h('input.input', { type: 'file', accept: '.json,application/json', 'aria-label': 'Export file' });
  const pass = pw('Export passphrase', 'off');
  const open = h('button.btn', { type: 'button', text: 'Decrypt' });
  const msg = h('p.msg', { role: 'status', hidden: true });
  const review = h('div.stack');
  let doc = null;

  open.onclick = async () => {
    const f = file.files[0];
    if (!f) return showMsg(msg, 'Choose an export file.');
    if (f.size > 8 * 1024 * 1024) return showMsg(msg, 'That file is too large for an export (max 8 MiB).');
    open.disabled = true;
    showMsg(msg, 'Decrypting…', false);
    try {
      doc = await openExport(await f.text(), pass.value);
      if (!doc || doc.format !== 'secbin-export/v1' || !Array.isArray(doc.users)) throw new ExportCryptError('The decrypted file is not a secbin export.');
      // Bound the review table before building it (the server re-validates everything).
      if (doc.users.length > 5000) throw new ExportCryptError('This export holds more than 5000 users, which is more than an import accepts.');
      msg.hidden = true;
      renderReview(review, doc, users, profile);
    } catch (e) {
      doc = null;
      clear(review);
      showMsg(msg, e instanceof ExportCryptError ? e.message : friendlyError(e));
    } finally {
      open.disabled = false;
    }
  };

  return h('div.card.stack', {},
    h('h2.section-title', { text: 'Import' }),
    h('p.subtitle', { text: 'Decrypt an export, choose what to take over, preview the changes, then import. Nothing changes until you import, and an import is applied completely or not at all. New accounts are created from the parts you choose. An account that already exists (yours included) keeps its password, recovery codes, API keys and passkeys: an import only sets its role and adds passkeys.' }),
    h('div.toolbar', {}, file, pass, open), msg, review);
}

/** What a user entry of the file holds for a part (shown next to its checkbox). */
function partSummary(u, k) {
  if (k === 'credentials') return u.credentials?.disabled ? 'disabled' : 'yes';
  if (k === 'role') return String(u.role ?? '');
  if (k === 'apiKeys') return String(u.apiKeys?.length ?? 0);
  if (k === 'passkeys') return String(u.passkeys?.keys?.length ?? 0);
  return String(u.recoveryCodes?.length ?? 0);
}

function renderReview(out, doc, users, profile) {
  clear(out);
  const existing = new Map(users.map((u) => [u.username.toLowerCase(), u]));
  const ownerName = profile.user.username.toLowerCase();
  // The system parts in the file, each chosen again here (off by default).
  const inFile = (k) => doc.system && (k === 'roles' ? doc.system.limits !== undefined : doc.system[k] !== undefined);
  const sysChecks = SYSTEM_PARTS.filter(([k]) => inFile(k)).map(([k, label, note]) => ({ k, ...check(label, false, note) }));
  const ownerKeys = doc.owner?.passkeys?.keys?.length;
  const ownerCheck = doc.owner?.passkeys ? check(`Owner passkeys (${ownerKeys ?? 0})`, false,
    `Adds the file owner's passkeys to your account (${profile.user.username}); your passkeys, password and recovery codes stay. Passkeys work only on the same hostname (${location.hostname}).`) : null;
  // The part columns: those any user in the file holds.
  const cols = USER_PARTS.filter(([k]) => doc.users.some((u) => u[k] !== undefined));
  const rows = [];
  const body = h('tbody');
  for (const u of doc.users) {
    const action = h('select.input', { 'aria-label': `Action for ${u.username}` });
    const as = h('input.input', { value: u.username, maxlength: '64', 'aria-label': `Import ${u.username} as`, spellcheck: 'false' });
    const status = h('span.mono.muted');
    // Each part the entry holds, on by default.
    const parts = Object.fromEntries(cols.filter(([k]) => u[k] !== undefined).map(([k, label]) => [k, box(`Import ${label} for ${u.username}`, true)]));
    let usual = 'skip'; // what "Select all" picks for this row
    const sync = () => {
      const name = as.value.trim().toLowerCase();
      const clash = name === ownerName ? 'owner' : existing.has(name) ? 'user' : null;
      const keep = action.value;
      clear(action).append(
        h('option', { value: 'skip', text: 'skip' }),
        clash === null && u.credentials ? h('option', { value: 'create', text: 'create' }) : null,
        clash === 'user' ? h('option', { value: 'update', text: 'update existing: role + add passkeys' }) : null,
        clash === 'owner' ? h('option', { value: 'update', text: 'update your account: add passkeys' }) : null);
      usual = clash ? 'update' : u.credentials ? 'create' : 'skip';
      action.value = [...action.options].some((o) => o.value === keep) ? keep : 'skip';
      status.textContent = clash === 'owner' ? 'your own (owner) account — only passkeys can be added; it keeps the Owner role'
        : clash === 'user' ? 'exists here — only its role and new passkeys can change'
          : u.credentials ? 'new here' : 'new here, but no credentials — cannot be created';
    };
    as.addEventListener('input', sync);
    sync();
    if ([...action.options].some((o) => o.value === 'create')) action.value = 'create';
    rows.push({ u, action, as, parts, usual: () => usual });
    body.appendChild(h('tr', {},
      h('td', { dataset: { label: 'User' }, text: u.username }),
      h('td', { dataset: { label: 'Import as' } }, as),
      h('td', { dataset: { label: 'Action' } }, action),
      ...cols.map(([k, label]) => h('td', { dataset: { label } }, parts[k] ? h('label.inline', {}, parts[k], h('span.mono', { text: partSummary(u, k) })) : h('span.muted', { text: '—', 'aria-label': 'not in the file' }))),
      h('td', { dataset: { label: 'Here' } }, status)));
  }
  const mine = pw('Your password', 'current-password');
  const msg = h('p.msg', { role: 'status', hidden: true });
  const planBox = h('div.stack');
  const preview = h('button.btn', { type: 'button', text: 'Preview' });
  const apply = h('button.btn.danger', { type: 'button', text: 'Import', disabled: true });
  let previewed = null;

  // Any change after a preview invalidates it.
  const invalidate = () => { previewed = null; apply.disabled = true; };
  // "Select all" users: each takes its usual action (create a new one, update an existing one).
  const setUsers = (on) => () => {
    for (const r of rows) {
      const v = on ? r.usual() : 'skip';
      if (r.action.value !== v && [...r.action.options].some((o) => o.value === v)) { r.action.value = v; invalidate(); }
    }
  };
  const userBulk = h('div.toolbar.bulk-row', {}, h('span.field-label', { text: 'Users' }),
    h('button.btn.mini', { type: 'button', text: 'Select all', 'aria-label': 'Select all: users to import', on: { click: setUsers(true) } }),
    h('button.btn.mini', { type: 'button', text: 'Deselect all', 'aria-label': 'Deselect all: users to import (skip them)', on: { click: setUsers(false) } }));

  const decisions = () => {
    const chosen = sysChecks.filter((c) => c.input.checked).map((c) => c.k);
    const out = { system: chosen.length ? Object.fromEntries(chosen.map((k) => [k, true])) : false, owner: ownerCheck?.input.checked ? { passkeys: true } : false, users: {} };
    for (const r of rows) {
      if (r.action.value === 'skip') continue;
      const parts = Object.keys(r.parts).filter((k) => r.parts[k].checked);
      if (!parts.length) return { empty: r.u.username };
      out.users[r.u.username] = { as: r.as.value.trim(), action: r.action.value, parts };
    }
    return out;
  };
  for (const r of rows) { r.action.addEventListener('change', invalidate); r.as.addEventListener('input', invalidate); }
  for (const c of [...sysChecks, ...(ownerCheck ? [ownerCheck] : [])]) c.input.addEventListener('change', invalidate);
  for (const r of rows) for (const b of Object.values(r.parts)) b.addEventListener('change', invalidate);

  const run = async (dryRun) => {
    const d = decisions();
    if (d.empty) return showMsg(msg, `Choose what to import for "${d.empty}", or skip it.`);
    if (!d.system && !d.owner && !Object.keys(d.users).length) return showMsg(msg, 'Nothing selected to import.');
    if (!mine.value) return showMsg(msg, 'Enter your password to confirm.');
    preview.disabled = apply.disabled = true;
    showMsg(msg, dryRun ? 'Checking…' : 'Importing…', false);
    try {
      const current = await loginProof(profile.user.username, mine.value);
      const r = await admin.importData({ current, document: doc, decisions: d, dryRun });
      renderPlan(planBox, r.plan);
      if (dryRun) {
        previewed = JSON.stringify(d);
        apply.disabled = r.plan.errors.length > 0;
        showMsg(msg, r.plan.errors.length ? 'Fix the problems below, then preview again.' : 'Preview ready — nothing has changed yet. Review it, then import.', r.plan.errors.length > 0);
      } else {
        showMsg(msg, 'Imported.', false);
        toast('Import applied.');
        mine.value = '';
        previewed = null;
      }
    } catch (e) {
      if (e instanceof ApiError && e.extra && e.extra.plan) renderPlan(planBox, e.extra.plan);
      showMsg(msg, friendlyError(e));
      if (!dryRun) toast(friendlyError(e), { error: true });
    } finally {
      preview.disabled = false;
      if (!dryRun || !previewed) apply.disabled = true;
    }
  };
  preview.onclick = () => run(true);
  apply.onclick = () => { if (previewed === JSON.stringify(decisions())) run(false); else invalidate(); };

  const bulks = doc.users.length ? h('div.stack.bulk', {}, userBulk,
    ...cols.map(([k, label]) => bulk(label, `${label} for every user`, () => rows.map((r) => r.parts[k]).filter(Boolean)))) : null;
  out.append(
    h('p.mono.muted', { text: `Export from ${doc.origin || 'an unknown origin'} · ${formatDate(doc.created)} · ${doc.system ? 'system configuration + ' : ''}${doc.owner ? 'owner passkeys + ' : ''}${plural(doc.users.length, 'user')}` }),
    sysChecks.length ? h('fieldset.range', {}, h('legend', { text: 'System parts to import' }), ...sysChecks.map((c) => c.el)) : null,
    ownerCheck ? h('fieldset.range', {}, h('legend', { text: 'Owner' }), ownerCheck.el) : null,
    doc.users.length ? h('fieldset.range', {}, h('legend', { text: 'Users and what to import for each' }), bulks,
      h('div.table-wrap', {}, h('table.table.part-table', {}, h('thead', {}, h('tr', {}, ...['User', 'Import as', 'Action', ...cols.map(([, label]) => label), 'Here'].map((t) => h('th', { text: t })))), body)),
      partNotes()) : null,
    field('Your password (confirms it is you)', mine),
    h('div.btn-row', {}, preview, apply), msg, planBox);
}

function renderPlan(out, plan) {
  clear(out);
  if (!plan) return;
  const items = [];
  if (plan.system) {
    const s = plan.system;
    if (s.settings) {
      items.push(`Settings: ${plural(s.settings.length, 'change')}.`);
      for (const c of s.settings) items.push(`  ${c.key}: ${JSON.stringify(c.from)} → ${JSON.stringify(c.to)}`);
    }
    if (s.roles) items.push(`Roles: the Default role's limits, quotas (${s.quotas}) and viewer rules (${s.viewerRules}) replaced${s.roles.length ? `; ${s.roles.map((r) => `${r.name} (${r.action})`).join(', ')}` : ''}.`);
    if (s.ipRulesAdded) {
      items.push(`IP rules: ${s.ipRulesAdded.length} added${s.ipRulesSkipped ? `, ${s.ipRulesSkipped} already present or expired` : ''}.`);
      for (const r of s.ipRulesAdded) items.push(`  + ${r}`);
    }
    if (s.turnstile) items.push(`Turnstile keys: ${s.turnstile}.`);
    if (s.public) items.push(`Public account: ${s.public.limits} limits, ${s.public.quotas} quotas, ${s.public.viewerRules} viewer rules.`);
  }
  const detail = (e) => {
    for (const c of e.changes ?? []) items.push(`  + ${c}`);
    if (e.changes && !e.changes.length && (e.action === 'update' || !e.action)) items.push('  nothing changes');
    for (const s of e.skipped ?? []) items.push(`  skipped: ${s}`);
  };
  if (plan.owner) {
    items.push(`Owner passkeys → ${plan.owner.as}:`);
    detail(plan.owner);
  }
  for (const u of plan.users) {
    if (u.action === 'skip') continue;
    const verb = u.action === 'update' ? `update existing${u.owner ? ' (owner)' : ''}` : u.action;
    items.push(`${u.username}${u.as && u.as !== u.username ? ` → ${u.as}` : ''}: ${verb}`);
    if (u.action === 'create' || u.action === 'update') detail(u);
  }
  out.append(h('h3.field-label', { text: 'Changes' }), h('ul.plan-list', {}, ...items.map((t) => h('li.mono', { text: t }))));
  if (plan.warnings?.length) out.append(h('h3.field-label', { text: 'Check these' }), h('ul.plan-list', {}, ...plan.warnings.map((t) => h('li.type-hint.warn', { text: t }))));
  if (plan.errors.length) out.append(h('h3.field-label', { text: 'Problems' }), h('ul.plan-list', {}, ...plan.errors.map((t) => h('li.msg.error', { text: t }))));
}
