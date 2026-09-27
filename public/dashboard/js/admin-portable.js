// admin-portable.js — Admin → Import / export. Exports are built by the
// server for the signed-in owner and encrypted HERE, with a passphrase, before
// they are saved (public/js/exportcrypt.js); imports are decrypted here,
// previewed (a dry run on the server) and then applied all-or-nothing. Both
// ask for the owner's password again. Every part is chosen when exporting and
// again when importing. The owner account and sessions are never exported.

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
// What each part holds, and what to know about it (shown on export and import).
const SYSTEM_PARTS = [
  ['settings', 'Settings', 'Server-wide settings (brute-force protection, lockout, logs, public access, accessibility statement…).'],
  ['roles', 'Roles', 'The Default role and every custom role (limits, quotas, viewer rules). On import, roles are created or replaced by name, never deleted.'],
  ['ipRules', 'IP rules', 'Manual allow / block rules. On import they are added, never removed.'],
  ['turnstile', 'Turnstile keys', 'The site key and SECRET set in Security → Human check (not the deployment\'s own). The widget must allow the target hostname.'],
  ['public', 'Public account', 'The anonymous account\'s limits, quotas and viewer rules.'],
];
const USER_PARTS = [
  ['credentials', 'Credentials', 'User name, password verifier (not the password), disabled flag. Needed to create an account on the target.'],
  ['config', 'Role', 'Which role the user has (by name; export the roles too).'],
  ['apiKeys', 'API keys', 'The stored key hashes, names, scopes and dates: the same keys keep working on the target. Revoking a key on one server does not revoke it on the other.'],
  ['passkeys', 'Passkeys and recovery codes', `Public keys, the "Password and passkey" choice and recovery-code hashes. Passkeys work only on the same hostname (${location.hostname}); recovery codes work anywhere.`],
];
const pw = (label, autocomplete) => h('input.input', { type: 'password', autocomplete, 'aria-label': label, maxlength: '256' });

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
  const scope = h('select.input', { 'aria-label': 'Users to export' },
    h('option', { value: 'none', text: 'no users' }), h('option', { value: 'all', text: `all users (${users.length})` }), h('option', { value: 'some', text: 'selected users' }));
  const pick = h('select.input.multi', { multiple: true, size: String(Math.min(8, Math.max(3, users.length))), 'aria-label': 'Selected users', hidden: true },
    ...users.map((u) => h('option', { value: u.id, text: u.username })));
  scope.onchange = () => { pick.hidden = scope.value !== 'some'; };
  const userChecks = USER_PARTS.map(([k, label, note]) => ({ k, ...check(label, k === 'config', note) }));
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
    const who = scope.value === 'all' ? 'all' : scope.value === 'some' ? [...pick.selectedOptions].map((o) => o.value) : [];
    const system = Object.fromEntries(sysChecks.map((c) => [c.k, c.input.checked]));
    const anySys = Object.values(system).some(Boolean);
    const parts = Object.fromEntries(userChecks.map((c) => [c.k, c.input.checked]));
    if (!anySys && (who === 'all' ? users.length === 0 : who.length === 0)) return showMsg(msg, 'Choose some system parts and/or some users.');
    if (who !== 'all' && scope.value === 'some' && !who.length) return showMsg(msg, 'Select at least one user.');
    if ((who === 'all' || who.length) && !Object.values(parts).some(Boolean)) return showMsg(msg, 'Choose what to export for the users.');
    if (pass1.value !== pass2.value) return showMsg(msg, 'The two passphrases differ.');
    if (!mine.value) return showMsg(msg, 'Enter your password to confirm.');
    go.disabled = true;
    showMsg(msg, 'Exporting and encrypting…', false);
    try {
      const current = await loginProof(profile.user.username, mine.value);
      const { document } = await admin.exportData({ current, system: anySys ? system : false, users: who, ...parts });
      const text = await sealExport(document, pass1.value);
      download(text, `secbin-export-${location.hostname}-${new Date().toISOString().slice(0, 10)}.json`);
      const what = `Exported ${document.system ? 'the system configuration and ' : ''}${document.users.length} user${document.users.length === 1 ? '' : 's'}.`;
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
    h('p.subtitle', { text: 'The file is encrypted in your browser (Argon2id + AES-256-GCM) with the passphrase below — without it, it cannot be read or imported. The owner account, sessions and shares are never exported, and neither is Drive content (files, folders, keys): Drive options travel with the roles. Credentials, API keys, passkeys and the Turnstile secret let accounts and services keep working on the target: treat the file as sensitive, and export only what you need.' }),
    h('fieldset.range', {}, h('legend', { text: 'System' }), ...sysChecks.map((c) => c.el)),
    h('div.toolbar', {}, h('span.field-label', { text: 'Users' }), scope), pick,
    h('fieldset.range', {}, h('legend', { text: 'For each exported user' }), ...userChecks.map((c) => c.el)),
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
    h('p.subtitle', { text: 'Decrypt an export, choose what to take over, preview the changes, then import. Nothing changes until you import, and an import is applied completely or not at all. The owner account can never be replaced.' }),
    h('div.toolbar', {}, file, pass, open), msg, review);
}

function renderReview(box, doc, users, profile) {
  clear(box);
  const existing = new Map(users.map((u) => [u.username.toLowerCase(), u]));
  const ownerName = profile.user.username.toLowerCase();
  // The system parts in the file, each chosen again here (off by default).
  const inFile = (k) => doc.system && (k === 'roles' ? doc.system.limits !== undefined : doc.system[k] !== undefined);
  const sysChecks = SYSTEM_PARTS.filter(([k]) => inFile(k)).map(([k, label, note]) => ({ k, ...check(label, false, note) }));
  // The user parts the file holds, chosen for every imported user.
  const userChecks = USER_PARTS.filter(([k]) => doc.users.some((u) => u[k] !== undefined)).map(([k, label, note]) => ({ k, ...check(label, true, note) }));
  const rows = [];
  const body = h('tbody');
  for (const u of doc.users) {
    const parts = [u.credentials ? 'credentials' : null, u.config?.role ? `role ${u.config.role}` : u.config ? 'old per-user settings (ignored)' : null,
      u.apiKeys ? `${u.apiKeys.length} API key${u.apiKeys.length === 1 ? '' : 's'}` : null, u.passkeys ? `${u.passkeys.keys?.length ?? 0} passkey${u.passkeys.keys?.length === 1 ? '' : 's'}` : null].filter(Boolean).join(' + ');
    const action = h('select.input', { 'aria-label': `Action for ${u.username}` });
    const as = h('input.input', { value: u.username, maxlength: '64', 'aria-label': `Import ${u.username} as`, spellcheck: 'false' });
    const status = h('span.mono.muted');
    const sync = () => {
      const name = as.value.trim().toLowerCase();
      const clash = name === ownerName ? 'owner' : existing.has(name) ? 'user' : null;
      const keep = action.value;
      clear(action).append(
        h('option', { value: 'skip', text: 'skip' }),
        clash === 'user' ? h('option', { value: 'overwrite', text: 'overwrite the existing user' }) : null,
        clash === null && u.credentials ? h('option', { value: 'create', text: 'create' }) : null);
      action.value = [...action.options].some((o) => o.value === keep) ? keep : 'skip';
      status.textContent = clash === 'owner' ? 'this is your own (owner) name — rename to import'
        : clash === 'user' ? 'exists here' : u.credentials ? 'new here' : 'new here, but no credentials — cannot be created';
    };
    as.addEventListener('input', sync);
    sync();
    if ([...action.options].some((o) => o.value === 'create')) action.value = 'create';
    rows.push({ u, action, as });
    body.appendChild(h('tr', {}, h('td', { dataset: { label: 'User' }, text: u.username }), h('td', { dataset: { label: 'Contains' }, text: parts }),
      h('td', { dataset: { label: 'Import as' } }, as), h('td', { dataset: { label: 'Action' } }, action), h('td', { dataset: { label: 'Here' } }, status)));
  }
  const mine = pw('Your password', 'current-password');
  const msg = h('p.msg', { role: 'status', hidden: true });
  const planBox = h('div.stack');
  const preview = h('button.btn', { type: 'button', text: 'Preview' });
  const apply = h('button.btn.danger', { type: 'button', text: 'Import', disabled: true });
  let previewed = null;

  const decisions = () => {
    const chosen = sysChecks.filter((c) => c.input.checked).map((c) => c.k);
    const out = { system: chosen.length ? Object.fromEntries(chosen.map((k) => [k, true])) : false, users: {} };
    const wanted = userChecks.filter((c) => c.input.checked).map((c) => c.k);
    for (const r of rows) {
      if (r.action.value === 'skip') continue;
      const parts = wanted.filter((k) => r.u[k] !== undefined);
      if (!parts.length) continue;
      out.users[r.u.username] = { as: r.as.value.trim(), parts, ...(r.action.value === 'overwrite' ? { overwrite: true } : {}) };
    }
    return out;
  };
  // Any change after a preview invalidates it.
  const invalidate = () => { previewed = null; apply.disabled = true; };
  for (const r of rows) { r.action.addEventListener('change', invalidate); r.as.addEventListener('input', invalidate); }
  for (const c of [...sysChecks, ...userChecks]) c.input.addEventListener('change', invalidate);

  const run = async (dryRun) => {
    const d = decisions();
    if (!d.system && !Object.keys(d.users).length) return showMsg(msg, 'Nothing selected to import.');
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

  box.append(
    h('p.mono.muted', { text: `Export from ${doc.origin || 'an unknown origin'} · ${formatDate(doc.created)} · ${doc.system ? 'system configuration + ' : ''}${doc.users.length} user${doc.users.length === 1 ? '' : 's'}` }),
    sysChecks.length ? h('fieldset.range', {}, h('legend', { text: 'System parts to import' }), ...sysChecks.map((c) => c.el)) : null,
    userChecks.length ? h('fieldset.range', {}, h('legend', { text: 'For each imported user' }), ...userChecks.map((c) => c.el)) : null,
    doc.users.length ? h('div.table-wrap', {}, h('table.table', {}, h('thead', {}, h('tr', {}, ...['User', 'Contains', 'Import as', 'Action', 'Here'].map((t) => h('th', { text: t })))), body)) : null,
    field('Your password (confirms it is you)', mine),
    h('div.btn-row', {}, preview, apply), msg, planBox);
}

function renderPlan(box, plan) {
  clear(box);
  if (!plan) return;
  const items = [];
  if (plan.system) {
    const s = plan.system;
    if (s.settings) {
      items.push(`Settings: ${s.settings.length} change${s.settings.length === 1 ? '' : 's'}.`);
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
  for (const u of plan.users) {
    if (u.action === 'skip') continue;
    items.push(`${u.username}${u.as && u.as !== u.username ? ` → ${u.as}` : ''}: ${u.action}${u.parts?.length ? ` (${u.parts.join(' + ')})` : ''}${u.note ? ` — ${u.note}` : ''}`);
  }
  box.append(h('h3.field-label', { text: 'Changes' }), h('ul.plan-list', {}, ...items.map((t) => h('li.mono', { text: t }))));
  if (plan.warnings?.length) box.append(h('h3.field-label', { text: 'Check these' }), h('ul.plan-list', {}, ...plan.warnings.map((t) => h('li.type-hint.warn', { text: t }))));
  if (plan.errors.length) box.append(h('h3.field-label', { text: 'Problems' }), h('ul.plan-list', {}, ...plan.errors.map((t) => h('li.msg.error', { text: t }))));
}
