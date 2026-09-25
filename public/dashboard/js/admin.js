// admin.js — owner administration: users (create, limits, API rules, viewer
// rules, reset password, impersonate, disable, unlock, delete), global
// defaults + quotas, settings (sessions, files, brute-force rules, lockout),
// viewer policy, security (blocks, tracking, manual IP rules) and the audit log.
// Every write is validated again by the server.

import { admin } from '../../js/api.js';
import { newCredential, checkNewPassword } from '../../js/pwauth.js';
import { h, clear, showMsg, armConfirm, formatDate, formatBytes, friendlyError, DURATION_UNITS, splitDuration, unitSeconds } from '../../js/common.js';
import { toast } from '../../js/ui.js';
import { ready } from './nav.js';
import { renderShares } from './admin-shares.js';

const $ = (s) => document.querySelector(s);
const panel = (name) => document.querySelector(`.admin-panel[data-panel="${name}"]`);
const MiB = 1024 * 1024;

const LIMIT_UI = [
  ['text', 'Notes allowed', 'bool'],
  ['files', 'File sharing allowed', 'bool'],
  ['maxViews', 'Max views per share', 'int'],
  ['allowUnlimitedViews', 'Unlimited views allowed', 'bool'],
  ['maxExpireSec', 'Max expiry', 'dur'],
  ['maxFilesPerShare', 'Max files per share', 'int'],
  ['maxShareBytes', 'Max share size', 'bytes'],
  ['maxFileBytes', 'Max single file size', 'bytes'],
  ['viewer', 'In-browser viewer', 'bool'],
  ['viewerCustomRules', 'Use per-user viewer rules', 'bool'],
  ['apiEnabled', 'API keys allowed', 'bool'],
  ['apiMaxKeys', 'Max API keys', 'int', { nullable: false }],
];
const API_KEYS = ['text', 'files', 'maxViews', 'allowUnlimitedViews', 'maxExpireSec', 'maxFilesPerShare', 'maxShareBytes', 'maxFileBytes'];
const VIEWER_PRESETS = {
  'Any file as plain text': [{ match: 'any', value: '', renderer: 'text' }],
  'Text & Markdown': [
    { match: 'mime', value: 'text/plain', renderer: 'text' }, { match: 'mime', value: 'text/markdown', renderer: 'markdown' },
    { match: 'ext', value: 'md', renderer: 'markdown' }, { match: 'ext', value: 'txt', renderer: 'text' },
    { match: 'ext', value: 'log', renderer: 'text' }, { match: 'ext', value: 'csv', renderer: 'text' }, { match: 'ext', value: 'json', renderer: 'code' },
  ],
  'Images (png/jpg/webp/bmp/gif/avif)': ['png', 'jpeg', 'webp', 'bmp', 'gif', 'avif'].map((t) => ({ match: 'mime', value: `image/${t}`, renderer: 'image' })),
  PDF: [{ match: 'mime', value: 'application/pdf', renderer: 'pdf' }],
  'Audio / video': [{ match: 'mime', value: 'audio/*', renderer: 'media' }, { match: 'mime', value: 'video/mp4', renderer: 'media' }, { match: 'mime', value: 'video/webm', renderer: 'media' }],
};
const RENDERERS = ['text', 'markdown', 'code', 'image', 'pdf', 'media'];

let overview = null;
const msg = (text, isError = false) => { showMsg($('#admin-msg'), text, isError); if (text && !isError) setTimeout(() => { $('#admin-msg').hidden = true; }, 3000); };
const guard = async (fn, okText) => {
  try { const r = await fn(); if (okText) msg(okText); return r; } catch (e) { msg(friendlyError(e), true); return null; }
};

(async () => {
  await ready;
  for (const t of document.querySelectorAll('.tab[data-tab]')) t.onclick = () => selectTab(t.dataset.tab);
  await refreshOverview();
  selectTab('users');
})();

async function refreshOverview() {
  overview = await guard(() => admin.overview());
  const b = $('#env-banner');
  const warn = [];
  if (overview?.env.authnSet) warn.push('The AUTHN setup token is still set — delete it (wrangler secret delete AUTHN) now that setup is done.');
  if (overview?.env.bfpDisabled) warn.push('DISABLE_BFP is on: all brute-force protection and IP rules are disabled.');
  else if (overview?.env.bfpSetupDisabled) warn.push('DISABLE_BFP_SETUP is on: brute-force protection is disabled for setup.');
  b.hidden = !warn.length;
  clear(b);
  for (const w of warn) b.appendChild(h('p', { text: w }));
}

function selectTab(name) {
  for (const t of document.querySelectorAll('.tab[data-tab]')) t.setAttribute('aria-selected', String(t.dataset.tab === name));
  for (const p of document.querySelectorAll('.admin-panel')) p.hidden = p.dataset.panel !== name;
  ({ users: renderUsers, shares: () => renderShares(panel('shares')), defaults: renderDefaults, settings: renderSettings, viewer: renderViewer, security: renderSecurity, audit: renderAudit })[name]();
}

// ── reusable controls ────────────────────────────────────────────────────────
function durationInput(sec, { allowNull = false } = {}) {
  const d = sec === null || sec === undefined ? { n: '', unit: 'h' } : splitDuration(sec);
  const n = h('input.input.opt-num', { type: 'number', min: '1', value: String(d.n), 'aria-label': 'Amount' });
  const u = h('select.input', { 'aria-label': 'Unit' }, ...DURATION_UNITS.map(([k, w]) => h('option', { value: k, text: w, selected: k === d.unit })));
  const wrap = h('span.inline-ctl', {}, n, u);
  wrap.read = () => (n.value === '' ? (allowNull ? null : NaN) : Number(n.value) * unitSeconds(u.value));
  return wrap;
}

function numberInput(v, { step = 1, scale = 1 } = {}) {
  const i = h('input.input.opt-num', { type: 'number', min: '0', step: String(step), value: v === null || v === undefined ? '' : String(v / scale) });
  i.read = () => (i.value === '' ? NaN : Math.round(Number(i.value) * scale));
  return i;
}

/** Limits editor for one scope/channel; `rows` = current overrides, `defaults` = what applies otherwise. */
function limitsEditor({ scope, channel, rows, effective }) {
  const box = h('div.limits-grid');
  const keys = channel === 'api' ? LIMIT_UI.filter(([k]) => API_KEYS.includes(k)) : LIMIT_UI;
  const ctls = [];
  for (const [key, label, type, opt = {}] of keys) {
    const has = Object.prototype.hasOwnProperty.call(rows, key);
    const v = has ? rows[key] : undefined;
    const mode = h('select.input', { 'aria-label': `${label} mode` },
      h('option', { value: 'inherit', text: scope === 'global' ? (channel === 'api' ? 'no extra restriction' : 'built-in default') : 'inherit', selected: !has }),
      ...(type === 'bool'
        ? [h('option', { value: 'true', text: 'yes', selected: has && v === true }), h('option', { value: 'false', text: 'no', selected: has && v === false })]
        : [...(opt.nullable === false ? [] : [h('option', { value: 'null', text: 'no limit', selected: has && v === null })]),
          h('option', { value: 'value', text: 'limit to', selected: has && v !== null })]));
    let val = null;
    if (type === 'int') val = numberInput(has && v !== null ? v : null);
    if (type === 'bytes') val = h('span.inline-ctl', {}, numberInput(has && v !== null ? v : null, { step: 0.1, scale: MiB }), h('span.mono', { text: 'MiB' }));
    if (type === 'dur') val = durationInput(has && v !== null ? v : null, { allowNull: true });
    const sync = () => { if (val) val.hidden = mode.value !== 'value'; };
    mode.onchange = sync;
    sync();
    const eff = effective && Object.prototype.hasOwnProperty.call(effective, key) ? effective[key] : undefined;
    const effText = eff === undefined ? '' : eff === null ? 'effective: no limit' : type === 'bytes' ? `effective: ${formatBytes(eff)}` : type === 'dur' ? `effective: ${eff}s` : `effective: ${eff}`;
    box.appendChild(h('div.limit-row', {}, h('span.field-label', { text: label }), mode, val, h('span.mono.muted', { text: effText })));
    ctls.push({ key, type, mode, val });
  }
  const save = h('button.btn', { type: 'button', text: `Save ${channel === 'api' ? 'API' : ''} limits` });
  save.onclick = async () => {
    const patch = {};
    for (const c of ctls) {
      if (c.mode.value === 'inherit') patch[c.key] = 'inherit';
      else if (c.mode.value === 'true' || c.mode.value === 'false') patch[c.key] = c.mode.value === 'true';
      else if (c.mode.value === 'null') patch[c.key] = null;
      else {
        const read = c.type === 'bytes' ? c.val.firstChild.read() : c.val.read();
        if (!Number.isFinite(read)) return msg(`Enter a value for ${c.key}.`, true);
        patch[c.key] = read;
      }
    }
    await guard(() => admin.limits(scope, channel, patch), 'Limits saved.');
  };
  box.appendChild(h('div.btn-row', {}, save));
  return box;
}

function quotasEditor(scope, list) {
  const box = h('div.stack');
  const rows = h('div.stack');
  const addRow = (q = { channel: 'all', kind: 'all', n: 1, unit: 'd', max: 10 }) => {
    const channel = h('select.input', { 'aria-label': 'Channel' }, ...[['all', 'GUI + API'], ['api', 'API only']].map(([v, t]) => h('option', { value: v, text: t, selected: q.channel === v })));
    const kind = h('select.input', { 'aria-label': 'Kind' }, ...[['all', 'all shares'], ['text', 'notes'], ['files', 'file shares']].map(([v, t]) => h('option', { value: v, text: t, selected: q.kind === v })));
    const max = h('input.input.opt-num', { type: 'number', min: '0', value: String(q.max), 'aria-label': 'Max' });
    const n = h('input.input.opt-num', { type: 'number', min: '1', value: String(q.n), 'aria-label': 'Period' });
    const unit = h('select.input', { 'aria-label': 'Period unit' }, ...[['s', 'seconds'], ['m', 'minutes'], ['h', 'hours'], ['d', 'days'], ['mo', 'months'], ['y', 'years']].map(([v, t]) => h('option', { value: v, text: t, selected: q.unit === v })));
    const row = h('div.toolbar.quota-row', {}, max, kind, h('span.mono', { text: 'per' }), n, unit, h('span.mono', { text: 'via' }), channel,
      h('button.btn', { type: 'button', text: 'Remove', on: { click: () => row.remove() } }));
    row.read = () => ({ channel: channel.value, kind: kind.value, n: Number(n.value), unit: unit.value, max: Number(max.value) });
    rows.appendChild(row);
  };
  for (const q of list) addRow(q);
  box.appendChild(rows);
  box.appendChild(h('div.btn-row', {},
    h('button.btn', { type: 'button', text: 'Add quota', on: { click: () => addRow() } }),
    h('button.btn', { type: 'button', text: 'Save quotas', on: { click: () => guard(() => admin.quotas(scope, [...rows.children].map((r) => r.read())), 'Quotas saved.') } })));
  box.appendChild(h('p.mono.muted', { text: 'Fixed windows (months/years are UTC calendar periods). GUI and API creations count together; an "API only" quota can only restrict API use further.' }));
  return box;
}

function rulesEditor(scope, list, { withPresets = true } = {}) {
  const box = h('div.stack');
  const rows = h('div.stack');
  const addRow = (r = { match: 'mime', value: '', renderer: 'text' }) => {
    const match = h('select.input', { 'aria-label': 'Match' }, ...[['mime', 'MIME type'], ['ext', 'extension'], ['any', 'any file']].map(([v, t]) => h('option', { value: v, text: t, selected: r.match === v })));
    const value = h('input.input', { value: r.value, placeholder: 'e.g. image/png, image/*, md', 'aria-label': 'Value', maxlength: '128' });
    const renderer = h('select.input', { 'aria-label': 'Show as' }, ...RENDERERS.map((v) => h('option', { value: v, text: v, selected: r.renderer === v })));
    const sync = () => { value.hidden = match.value === 'any'; };
    match.onchange = sync;
    sync();
    const row = h('div.toolbar', {}, match, value, h('span.mono', { text: '→' }), renderer, h('button.btn', { type: 'button', text: 'Remove', on: { click: () => row.remove() } }));
    row.read = () => ({ match: match.value, value: match.value === 'any' ? '' : value.value.trim(), renderer: renderer.value });
    rows.appendChild(row);
  };
  for (const r of list) addRow(r);
  if (withPresets) {
    box.appendChild(h('div.btn-row', {}, h('span.field-label', { text: 'Add preset:' }),
      ...Object.entries(VIEWER_PRESETS).map(([name, rs]) => h('button.btn', { type: 'button', text: name, on: { click: () => rs.forEach((r) => addRow(r)) } }))));
  }
  box.appendChild(rows);
  box.appendChild(h('div.btn-row', {},
    h('button.btn', { type: 'button', text: 'Add rule', on: { click: () => addRow() } }),
    h('button.btn', { type: 'button', text: 'Save rules', on: { click: () => guard(() => admin.viewerRules(scope, [...rows.children].map((r) => r.read())), 'Viewer rules saved.') } })));
  box.appendChild(h('p.mono.muted', { text: 'First matching rule wins. Renderers never execute content: images/media are decoded from sniffed signatures, SVG is never rendered, PDFs use a hardened pdf.js with scripting disabled.' }));
  return box;
}

// ── users ────────────────────────────────────────────────────────────────────
async function renderUsers() {
  const p = clear(panel('users'));
  const data = await guard(() => admin.users());
  if (!data) return;
  const user = h('input.input', { placeholder: 'username', maxlength: '64', 'aria-label': 'New username', autocomplete: 'off' });
  const pw = h('input.input', { type: 'password', placeholder: 'password (min. 12)', 'aria-label': 'New user password', autocomplete: 'new-password' });
  const pw2 = h('input.input', { type: 'password', placeholder: 'repeat password', 'aria-label': 'Repeat password', autocomplete: 'new-password' });
  const add = h('button.btn', { type: 'button', text: 'Create user' });
  add.onclick = async () => {
    const bad = checkNewPassword(pw.value, pw2.value);
    if (bad) return msg(bad, true);
    add.disabled = true;
    const cred = await newCredential(pw.value);
    const r = await guard(() => admin.createUser({ username: user.value.trim(), ...cred }), 'User created.');
    add.disabled = false;
    if (r) renderUsers();
  };
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'Create a user' }), h('div.toolbar', {}, user, pw, pw2, add)));

  const body = h('tbody');
  for (const u of data.users) {
    const actions = h('div.btn-row.row-actions');
    if (u.role !== 'owner') {
      actions.appendChild(h('button.btn', { type: 'button', text: 'Manage', on: { click: () => openUser(u.id) } }));
      actions.appendChild(h('button.btn', { type: 'button', text: 'Log in as', on: { click: async () => { if (await guard(() => admin.impersonate(u.id))) location.href = '/dashboard/'; } } }));
      actions.appendChild(h('button.btn', { type: 'button', text: u.disabled ? 'Enable' : 'Disable', on: { click: async () => { await guard(() => admin.updateUser(u.id, { disabled: !u.disabled }), 'Saved.'); renderUsers(); } } }));
      if (u.locked) actions.appendChild(h('button.btn', { type: 'button', text: 'Unlock', on: { click: async () => { await guard(() => admin.unlock(u.id), 'Unlocked.'); renderUsers(); } } }));
      const del = h('button.btn.danger', { type: 'button', text: 'Delete' });
      armConfirm(del, 'Delete user + revoke shares?', async () => { await guard(() => admin.deleteUser(u.id, true), 'User deleted.'); renderUsers(); });
      actions.appendChild(del);
    } else {
      actions.appendChild(h('button.btn', { type: 'button', text: 'Reset my password', on: { click: () => openUser(u.id, true) } }));
    }
    body.appendChild(h('tr', {}, h('td', { dataset: { label: 'User' }, text: u.username }), h('td.mono', { dataset: { label: 'Role' }, text: u.role }),
      h('td', { dataset: { label: 'Status' } }, h(`span.pill.${u.disabled ? 'bad' : u.locked ? 'warn' : 'ok'}`, { text: u.disabled ? 'disabled' : u.locked ? 'locked' : 'active' })),
      h('td.mono', { dataset: { label: 'Created' }, text: formatDate(u.created) }), h('td.cell-actions', {}, actions)));
  }
  p.appendChild(h('div.table-wrap', {}, h('table.table', {}, h('thead', {}, h('tr', {}, ...['User', 'Role', 'Status', 'Created', ''].map((t) => h('th', { text: t })))), body)));
  p.appendChild(h('div', { id: 'user-detail' }));
}

async function openUser(id, passwordOnly = false) {
  const box = clear($('#user-detail'));
  const d = await guard(() => admin.user(id));
  if (!d) return;
  box.appendChild(h('h2.section-title', { text: `Manage ${d.user.username}` }));
  const npw = h('input.input', { type: 'password', placeholder: 'new password (min. 12)', autocomplete: 'new-password', 'aria-label': 'New password' });
  const npw2 = h('input.input', { type: 'password', placeholder: 'repeat', autocomplete: 'new-password', 'aria-label': 'Repeat new password' });
  const setBtn = h('button.btn', { type: 'button', text: 'Set password' });
  setBtn.onclick = async () => {
    const bad = checkNewPassword(npw.value, npw2.value);
    if (bad) return msg(bad, true);
    setBtn.disabled = true;
    const cred = await newCredential(npw.value);
    await guard(() => admin.setPassword(id, cred), 'Password set. Their sessions were signed out.');
    setBtn.disabled = false;
    npw.value = npw2.value = '';
  };
  box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Set password (no current password needed)' }), h('div.toolbar', {}, npw, npw2, setBtn)));
  if (passwordOnly) return;

  box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Capabilities & limits (GUI + API)' }), limitsEditor({ scope: id, channel: 'all', rows: d.limits.all, effective: d.effective.all })));
  box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Extra API restrictions (can only narrow, never widen)' }), limitsEditor({ scope: id, channel: 'api', rows: d.limits.api, effective: d.effective.api })));
  box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Quotas for this user (in addition to global quotas)' }), quotasEditor(id, d.quotas)));
  box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Per-user viewer rules (used when "Use per-user viewer rules" is on)' }), rulesEditor(id, d.viewerRules)));
  const keys = h('tbody');
  for (const k of d.keys) {
    const rv = h('button.btn.danger', { type: 'button', text: 'Revoke' });
    armConfirm(rv, 'Revoke?', async () => { await guard(() => admin.revokeUserKey(id, k.id), 'Key revoked.'); openUser(id); });
    keys.appendChild(h('tr', {}, h('td', { dataset: { label: 'Name' }, text: k.name }), h('td.mono', { dataset: { label: 'Created' }, text: formatDate(k.created) }),
      h('td.mono', { dataset: { label: 'Last used' }, text: formatDate(k.last_used) }), h('td.cell-actions', {}, rv)));
  }
  box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'API keys' }),
    h('div.table-wrap', {}, h('table.table', {}, h('thead', {}, h('tr', {}, ...['Name', 'Created', 'Last used', ''].map((t) => h('th', { text: t })))), keys))));
  box.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ── defaults ─────────────────────────────────────────────────────────────────
async function renderDefaults() {
  const p = clear(panel('defaults'));
  await refreshOverview();
  if (!overview) return;
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'Default limits for every user' }),
    h('p.mono.muted', { text: 'Per-user settings override these. The owner is never limited.' }),
    limitsEditor({ scope: 'global', channel: 'all', rows: overview.limits.all })));
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'Default extra API restrictions' }),
    limitsEditor({ scope: 'global', channel: 'api', rows: overview.limits.api })));
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'Global quotas (apply to every user separately)' }), quotasEditor('global', overview.quotas)));
}

// ── settings ─────────────────────────────────────────────────────────────────
async function renderSettings() {
  const p = clear(panel('settings'));
  await refreshOverview();
  if (!overview) return;
  const s = overview.settings;
  const fields = [];
  const dur = (key, label) => { const c = durationInput(s[key]); fields.push([key, () => c.read()]); return h('div.limit-row', {}, h('span.field-label', { text: label }), c); };
  const int = (key, label) => { const c = numberInput(s[key]); fields.push([key, () => c.read()]); return h('div.limit-row', {}, h('span.field-label', { text: label }), c); };
  const mib = (key, label, max) => { const c = numberInput(s[key], { step: 1, scale: MiB }); fields.push([key, () => c.read()]); return h('div.limit-row', {}, h('span.field-label', { text: label }), c, h('span.mono', { text: `MiB (max ${max})` })); };
  const scopeRule = (scope, label) => h('div.card.stack', {}, h('h3.field-label', { text: label }),
    int(`guard.${scope}.max`, 'Failures allowed'), dur(`guard.${scope}.windowSec`, 'Within'), dur(`guard.${scope}.blockSec`, 'Then block the IP for'));
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'Sessions' }), dur('session.idleSec', 'Idle timeout'), dur('session.absSec', 'Absolute timeout')));
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'File shares' }),
    mib('files.maxShareBytes', 'Max share size (all files)', '2048'), dur('files.grantSec', 'Download window after opening'), dur('files.pendingSec', 'Unfinished upload deadline')));
  p.appendChild(h('div.stack', {}, h('h2.section-title', { text: 'Brute-force protection (per IP)' }),
    scopeRule('login', 'Login'), scopeRule('setup', 'Setup'), scopeRule('invalid', 'Invalid fetches (unknown links, wrong #key, wrong password, bad tokens)'),
    h('div.card.stack', {}, int('guard.v6Prefix', 'IPv6 tracking prefix (/n)'))));
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'Account lockout (owner excluded)' }),
    int('lockout.max', 'Failed logins allowed'), dur('lockout.windowSec', 'Within'), dur('lockout.lockSec', 'Then lock the account for')));
  const save = h('button.cta', { type: 'button', text: 'Save settings' });
  save.onclick = async () => {
    const patch = {};
    for (const [k, read] of fields) {
      const v = read();
      if (!Number.isFinite(v)) return msg(`Enter a value for ${k}.`, true);
      patch[k] = v;
    }
    await guard(() => admin.settings(patch), 'Settings saved.');
  };
  p.appendChild(save);
}

// ── viewer ───────────────────────────────────────────────────────────────────
async function renderViewer() {
  const p = clear(panel('viewer'));
  await refreshOverview();
  if (!overview) return;
  const s = overview.settings;
  const on = h('input', { type: 'checkbox', checked: s['viewer.enabled'], id: 'viewer-enabled' });
  const max = numberInput(s['viewer.maxBytes'], { step: 1, scale: MiB });
  const save = h('button.btn', { type: 'button', text: 'Save' });
  save.onclick = () => guard(() => admin.settings({ 'viewer.enabled': on.checked, 'viewer.maxBytes': max.read() }), 'Viewer settings saved.');
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'In-browser viewer' }),
    h('label.inline', {}, on, ' Enabled globally (turning it off takes effect for existing links immediately)'),
    h('div.limit-row', {}, h('span.field-label', { text: 'Max previewable file size' }), max, h('span.mono', { text: 'MiB' })),
    h('p.mono.muted', { text: 'Users also need the per-user "In-browser viewer" capability (Defaults or per user), and the sender opts in per share.' }),
    h('div.btn-row', {}, save)));
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'Global viewer rules' }), rulesEditor('global', overview.viewerRules)));
}

// ── security ─────────────────────────────────────────────────────────────────
async function renderSecurity() {
  const p = clear(panel('security'));
  const [g, rules] = await Promise.all([guard(() => admin.guard()), guard(() => admin.ipRules())]);
  // Manual rules.
  const cidr = h('input.input', { placeholder: 'IP or CIDR (v4 / v6)', 'aria-label': 'IP or CIDR', maxlength: '64' });
  const action = h('select.input', { 'aria-label': 'Action' }, h('option', { value: 'block', text: 'block' }), h('option', { value: 'allow', text: 'allow (never blocked or tracked)' }));
  const ttl = durationInput(null, { allowNull: true });
  const note = h('input.input', { placeholder: 'note (optional)', maxlength: '100', 'aria-label': 'Note' });
  const add = h('button.btn', { type: 'button', text: 'Add rule' });
  add.onclick = async () => {
    const exp = ttl.read();
    if (await guard(() => admin.addIpRule({ cidr: cidr.value.trim(), action: action.value, note: note.value, expiresInSec: exp || null }), 'Rule added.')) renderSecurity();
  };
  const rbody = h('tbody');
  for (const r of rules?.rules || []) {
    rbody.appendChild(h('tr', {}, h('td.mono', { dataset: { label: 'Range' }, text: r.cidr }),
      h('td', { dataset: { label: 'Action' } }, h(`span.pill.${r.action === 'allow' ? 'ok' : 'bad'}`, { text: r.action })),
      h('td.mono', { dataset: { label: 'Expires' }, text: r.expires ? formatDate(r.expires) : 'never' }), h('td', { dataset: { label: 'Note' }, text: r.note }),
      h('td.cell-actions', {}, h('button.btn', { type: 'button', text: 'Remove', on: { click: async () => { await guard(() => admin.removeIpRule(r.id), 'Rule removed.'); renderSecurity(); } } }))));
  }
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'Manual IP rules' }),
    h('p.mono.muted', { text: 'Block rules deny the whole API and dashboard. Allow beats block. Leave the duration empty for a permanent rule.' }),
    h('div.toolbar', {}, cidr, action, h('span.mono', { text: 'for' }), ttl, note, add),
    h('div.table-wrap', {}, h('table.table', {}, h('thead', {}, h('tr', {}, ...['Range', 'Action', 'Expires', 'Note', ''].map((t) => h('th', { text: t })))), rbody))));

  const bbody = h('tbody');
  for (const b of g?.blocks || []) {
    bbody.appendChild(h('tr', {}, h('td.mono', { dataset: { label: 'IP / prefix' }, text: b.key }), h('td.mono', { dataset: { label: 'Scope' }, text: b.scope }),
      h('td.mono', { dataset: { label: 'Since' }, text: formatDate(b.since) }), h('td.mono', { dataset: { label: 'Until' }, text: formatDate(b.until) }),
      h('td.cell-actions', {}, h('button.btn', { type: 'button', text: 'Unblock', on: { click: async () => { await guard(() => admin.unblock(b.scope, b.key), 'Unblocked.'); renderSecurity(); } } }))));
  }
  const tbody = h('tbody');
  for (const t of g?.tracking || []) {
    tbody.appendChild(h('tr', {}, h('td.mono', { dataset: { label: 'IP / prefix' }, text: t.key }), h('td.mono', { dataset: { label: 'Scope' }, text: t.scope }),
      h('td.mono', { dataset: { label: 'Failures' }, text: String(t.count) }), h('td.mono', { dataset: { label: 'Window ends' }, text: formatDate(t.expires) }),
      h('td.cell-actions', {}, h('div.btn-row.row-actions', {},
        h('button.btn', { type: 'button', text: 'Clear', on: { click: async () => { await guard(() => admin.unblock(t.scope, t.key), 'Cleared.'); renderSecurity(); } } }),
        h('button.btn.danger', { type: 'button', text: 'Block 24h', on: { click: async () => { await guard(() => admin.block(t.scope, t.key, 86400), 'Blocked.'); renderSecurity(); } } })))));
  }
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'Currently blocked' }),
    h('div.table-wrap', {}, h('table.table', {}, h('thead', {}, h('tr', {}, ...['IP / prefix', 'Scope', 'Since', 'Until', ''].map((x) => h('th', { text: x })))), bbody))));
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'Being tracked' }),
    h('div.table-wrap', {}, h('table.table', {}, h('thead', {}, h('tr', {}, ...['IP / prefix', 'Scope', 'Failures', 'Window ends', ''].map((x) => h('th', { text: x })))), tbody)),
    h('div.btn-row', {}, h('button.btn', { type: 'button', text: 'Refresh', on: { click: renderSecurity } }))));
}

// ── audit ────────────────────────────────────────────────────────────────────
async function renderAudit() {
  const p = clear(panel('audit'));
  const body = h('tbody');
  let before = null;
  const more = h('button.btn', { type: 'button', text: 'Load more', hidden: true });
  const load = async () => {
    const r = await guard(() => admin.audit(before));
    if (!r) return;
    for (const a of r.rows) {
      // imp: done while impersonating; adm: an admin's direct change to another
      // user's share (in this log only, never in the user's own activity).
      const who = a.imp ? `${a.actor} as ${a.subject}` : `${a.actor || 'system'}${a.adm ? ' (admin)' : ''}`;
      const on = !a.imp && a.subject && a.subject !== a.actor ? a.subject : '';
      body.appendChild(h('tr', {}, h('td.mono', { dataset: { label: 'When' }, text: formatDate(a.ts) }), h('td', { dataset: { label: 'Who' }, text: who }),
        h('td', { dataset: { label: 'On user' }, text: on }), h('td.mono', { dataset: { label: 'Action' }, text: a.action }), h('td', { dataset: { label: 'Details' }, text: a.detail })));
    }
    if (r.rows.length) before = r.rows[r.rows.length - 1].id;
    more.hidden = r.rows.length < 100;
  };
  more.onclick = load;
  p.appendChild(h('div.table-wrap', {}, h('table.table', {}, h('thead', {}, h('tr', {}, ...['When', 'Who', 'On user', 'Action', 'Details'].map((t) => h('th', { text: t })))), body)));
  p.appendChild(h('div.btn-row', {}, more));
  await load();
  void toast;
}
