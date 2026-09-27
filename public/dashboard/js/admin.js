// admin.js — owner administration: users (create, limits, API rules, viewer
// rules, reset password, impersonate, disable, unlock, delete), global
// defaults + quotas, settings (sessions, files, brute-force rules, lockout),
// viewer policy, security (blocks, tracking, manual IP rules) and the audit log.
// Every write is validated again by the server.

import '../../js/kdf-progress.js';
import { admin } from '../../js/api.js';
import { newCredential, checkOwnerPassword, describePolicy, loginProof } from '../../js/pwauth.js';
import { h, clear, showMsg, armConfirm, formatDate, formatBytes, friendlyError, DURATION_UNITS, splitDuration, unitSeconds } from '../../js/common.js';
import { toast, copyText, flashCopied } from '../../js/ui.js';
import { normalizeRules } from '../../js/filepolicy.js';
import { normalizeUrlRules, parseShareUrl, matchingUrlRule, unanchoredRules, DEFAULT_URL_RULES } from '../../js/sharetypes.js';
import { ready } from './nav.js';
import { confirmStep, confirmLabel, canUsePasskey } from './confirm.js';
import { renderShares } from './admin-shares.js';
import { renderPortable } from './admin-portable.js';

const $ = (s) => document.querySelector(s);
const panel = (name) => document.querySelector(`.admin-panel[data-panel="${name}"]`);
const MiB = 1024 * 1024;

const LIMIT_UI = [
  ['text', 'Notes allowed', 'bool'],
  ['files', 'File sharing allowed', 'bool'],
  ['url', 'Link shares allowed (needs notes)', 'bool'],
  ['urlRules', 'Links that may be shared', 'urlrules'],
  ['secret', 'Credential shares allowed (needs notes)', 'bool'],
  ['openerDelete', 'Recipients may “delete now” (sender opts in)', 'bool'],
  ['maxViews', 'Max views per share', 'int'],
  ['allowUnlimitedViews', 'Unlimited views allowed', 'bool'],
  ['maxExpireSec', 'Max expiry', 'dur'],
  ['maxFilesPerShare', 'Max files per share', 'int'],
  ['maxShareBytes', 'Max share size', 'bytes'],
  ['maxFileBytes', 'Max single file size', 'bytes'],
  ['viewer', 'In-browser viewer', 'bool'],
  ['viewerCustomRules', 'Use per-user viewer rules', 'bool'],
  ['apiEnabled', 'API keys allowed', 'bool'],
  ['apiMaxKeys', 'Max API keys', 'int'],
  ['fileTypeMode', 'File types', 'enum', { values: [['any', 'any type'], ['allow', 'only the listed types'], ['block', 'all but the listed types']] }],
  ['fileTypeRules', 'File type list', 'rules'],
  ['maxFolderDepth', 'Max folder depth', 'int'],
  ['receiptIp', 'Read receipts: sender sees the opener\'s address', 'bool'],
  ['receiptLocation', 'Read receipts: sender sees the approximate location', 'bool'],
  ['receiptBrowser', 'Read receipts: sender sees the browser and version', 'bool'],
  ['receiptOs', 'Read receipts: sender sees the operating system', 'bool'],
  ['receiptLanguages', 'Read receipts: sender sees the browser languages', 'bool'],
  ['logMaxAgeSec', 'Keep this account\'s log entries for at most', 'dur'],
  ['logMaxEntries', 'Keep at most this many log entries about the account', 'int'],
  ['pwMinLength', 'Password: minimum length', 'int', { nullable: false }],
  ['pwUpper', 'Password: needs an upper-case letter', 'bool'],
  ['pwLower', 'Password: needs a lower-case letter', 'bool'],
  ['pwDigit', 'Password: needs a digit', 'bool'],
  ['pwSymbol', 'Password: needs a symbol', 'bool'],
  ['passkeys', 'Passkeys', 'enum', { values: [['any', 'sign in alone or as a second factor'], ['second', 'only as a second factor after the password'], ['off', 'not allowed']] }],
];
const API_KEYS = ['text', 'files', 'url', 'secret', 'openerDelete', 'maxViews', 'allowUnlimitedViews', 'maxExpireSec', 'maxFilesPerShare', 'maxShareBytes', 'maxFileBytes', 'maxFolderDepth'];
const RULES_HINT = 'One per line: ext:pdf, mime:image/png or mime:image/*. Prefer ext: rules — senders can edit a file’s MIME type, so mime: rules are advisory. The mode and the list apply together: set both at the same level. File types are declared by the sender’s browser or CLI, so this stops honest mistakes, not a modified client.';
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
let profile = null;
const msg = (text, isError = false) => { showMsg($('#admin-msg'), text, isError); if (text && !isError) setTimeout(() => { $('#admin-msg').hidden = true; }, 3000); };
// Every save confirms with a toast (and failures with an error toast), so the
// result is visible wherever the page is scrolled.
const guard = async (fn, okText) => {
  try {
    const r = await fn();
    if (okText) { msg(okText); toast(okText); }
    return r;
  } catch (e) {
    msg(friendlyError(e), true);
    toast(friendlyError(e), { error: true });
    return null;
  }
};

(async () => {
  profile = await ready;
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
  ({ users: renderUsers, shares: () => renderShares(panel('shares')), defaults: renderDefaults, settings: renderSettings, viewer: renderViewer, security: renderSecurity, public: renderPublic, portable: () => renderPortable(panel('portable'), profile), audit: renderAudit })[name]();
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

function numberInput(v, { step = 1, scale = 1, label } = {}) {
  const i = h('input.input.opt-num', { type: 'number', min: '0', step: String(step), value: v === null || v === undefined ? '' : String(v / scale), 'aria-label': label });
  i.read = () => (i.value === '' ? NaN : Math.round(Number(i.value) * scale));
  return i;
}

/** How link rules work: shown in a help panel next to every rules editor. */
function urlRulesHelp() {
  const li = (...kids) => h('li', {}, ...kids);
  const code = (t) => h('code.mono', { text: t });
  return h('details.rules-help', {},
    h('summary', { text: 'How link rules work' }),
    h('p', {}, 'A link\'s ', h('strong', { text: 'scheme' }), ' is the part before the first colon: ', code('https'), ' in ', code('https://example.com/page'), ', ', code('mailto'), ' in ', code('mailto:a@example.com'), ', ', code('tel'), ' in ', code('tel:+15551234'), '. One rule per line; a link is allowed when any rule matches:'),
    h('ul', {},
      li(code('scheme:https'), ' allows every link with that scheme (', code('scheme:http'), ' and ', code('scheme:https'), ' are the built-in default).'),
      li(code('scheme:*'), ' allows every scheme except the dangerous ones below.'),
      li(code('re:<pattern>'), ' allows links a regular expression matches. The engine is the browser\'s (JavaScript ', code('RegExp'), ', flags ', code('i'), ' and ', code('u'), ': case-insensitive, Unicode), tested against the whole link as the browser normalizes it (e.g. ', code('https://example.com/a?b=1'), '). It matches ', h('em', { text: 'anywhere' }), ' in the link unless you anchor it: ', code('re:^https://([a-z0-9-]+\\.)*example\\.com(/|$)'), ' allows example.com and its subdomains only.')),
    h('p', {}, code('javascript:'), ', ', code('data:'), ', ', code('file:'), ', ', code('blob:'), ' and similar can never be allowed. The sender\'s browser or CLI checks the rules (the server never sees the link), and recipients can open only web, mail, phone and SMS links; others are shown for copying.'));
}

/**
 * Link rules: the rules in effect (inherited ones shown read-only), a textarea
 * when "set to" is chosen, the help panel, and a tester that is always there —
 * type a link and see which rule allows it, or why it is refused.
 */
function urlRulesInput(initial, label, inheritedRules) {
  const area = h('textarea.input.rules-in', { rows: '3', spellcheck: 'false', 'aria-label': label, placeholder: 'scheme:https\nscheme:tel\nre:^https://([a-z0-9-]+\\.)*example\\.com(/|$)' });
  area.value = initial.join('\n');
  const inheritedNote = h('p.mono.muted', { text: `In effect: ${(inheritedRules || DEFAULT_URL_RULES).join(', ')}` });
  const probe = h('input.input', { type: 'text', spellcheck: 'false', placeholder: 'test a link, e.g. https://example.com/page', 'aria-label': `${label}: test a link` });
  const result = h('span.mono.muted', { role: 'status', 'aria-live': 'polite' });
  const warn = h('p.mono.warn', { hidden: true });
  let own = false;
  const current = () => (own ? normalizeUrlRules(area.value.split('\n')) : (inheritedRules || [...DEFAULT_URL_RULES]));
  const test = () => {
    result.classList.remove('ok-text', 'warn');
    let rules;
    try { rules = current(); } catch (e) { result.textContent = `rules: ${e.message}`; result.classList.add('warn'); warn.hidden = true; return; }
    const loose = unanchoredRules(rules);
    warn.hidden = !loose.length;
    warn.textContent = loose.length ? `Not anchored, so it matches anywhere in a link: ${loose.join(', ')}. Start the pattern with ^ to match from the beginning.` : '';
    if (!probe.value.trim()) { result.textContent = ''; return; }
    try {
      const u = parseShareUrl(probe.value, { rules });
      result.textContent = `allowed by ${matchingUrlRule(u, rules)}`;
      result.classList.add('ok-text');
    } catch (e) {
      result.textContent = /not allowed for your account/.test(e.message) ? 'refused: no rule matches this link' : `refused: ${e.message}`;
      result.classList.add('warn');
    }
  };
  probe.addEventListener('input', test);
  area.addEventListener('input', test);
  const wrap = h('span.url-rules', {}, inheritedNote, area, warn, h('span.inline-ctl', {}, probe, result), urlRulesHelp());
  /** "set to" shows the textarea; otherwise the rules in effect are shown and tested. */
  wrap.setMode = (isOwn) => { own = isOwn; area.hidden = !isOwn; inheritedNote.hidden = isOwn; test(); };
  wrap.read = () => {
    const rules = normalizeUrlRules(area.value.split('\n'));
    if (!rules.length) throw new Error('add at least one rule (or turn link shares off)');
    return rules;
  };
  return wrap;
}

/** One limit value for display ("no limit", "100 MiB", "7 days", "yes"…). */
function limitText(type, v) {
  if (v === undefined) return '';
  if (type === 'rules' || type === 'urlrules') return v.length ? v.join(', ') : 'none';
  if (v === null) return 'no limit';
  if (type === 'bool') return v ? 'yes' : 'no';
  if (type === 'bytes') return formatBytes(v);
  if (type === 'dur') {
    const d = splitDuration(v);
    const unit = DURATION_UNITS.find(([k]) => k === d.unit);
    const word = unit ? unit[1] : d.unit;
    return `${d.n} ${d.n === 1 ? word.replace(/s$/, '') : word}`;
  }
  return String(v);
}

/**
 * Limits editor for one scope/channel. `rows` = the overrides set at this
 * level; `inherited` = what applies when a row is left on inherit (the
 * built-in defaults for the global level, the global values for a user),
 * shown next to the choice so every default is visible.
 */
function limitsEditor({ scope, channel, rows, effective, inherited, onSaved, omit = [] }) {
  const box = h('div.limits-grid');
  const keys = (channel === 'api' ? LIMIT_UI.filter(([k]) => API_KEYS.includes(k)) : LIMIT_UI).filter(([k]) => !omit.includes(k));
  const ctls = [];
  for (const [key, label, type, opt = {}] of keys) {
    const has = Object.prototype.hasOwnProperty.call(rows, key);
    const v = has ? rows[key] : undefined;
    const choices = {
      bool: () => [h('option', { value: 'true', text: 'yes', selected: has && v === true }), h('option', { value: 'false', text: 'no', selected: has && v === false })],
      enum: () => opt.values.map(([k, t]) => h('option', { value: `enum:${k}`, text: t, selected: has && v === k })),
      rules: () => [h('option', { value: 'value', text: 'set to', selected: has })],
      urlrules: () => [h('option', { value: 'value', text: 'set to', selected: has })],
    }[type] ?? (() => [...(opt.nullable === false ? [] : [h('option', { value: 'null', text: 'no limit', selected: has && v === null })]),
      h('option', { value: 'value', text: 'limit to', selected: has && v !== null })]);
    const inh = channel !== 'api' && inherited && Object.prototype.hasOwnProperty.call(inherited, key) ? ` (${limitText(type, inherited[key])})` : '';
    const inheritText = channel === 'api' ? 'no extra restriction' : scope === 'global' ? `built-in default${inh}` : `inherit${inh}`;
    const mode = h('select.input', { 'aria-label': `${label} mode` },
      h('option', { value: 'inherit', text: inheritText, selected: !has }),
      ...choices());
    let val = null;
    if (type === 'rules') {
      val = h('textarea.input.rules-in', { rows: '3', spellcheck: 'false', 'aria-label': label, placeholder: 'ext:pdf\nmime:image/*', title: RULES_HINT });
      val.value = has && Array.isArray(v) ? v.join('\n') : '';
      val.read = () => normalizeRules(val.value.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean));
    }
    if (type === 'urlrules') val = urlRulesInput(has && Array.isArray(v) ? v : (effective?.[key] ?? inherited?.[key] ?? [...DEFAULT_URL_RULES]), label, inherited?.[key] ?? (effective && !has ? effective[key] : undefined));
    if (type === 'int') val = numberInput(has && v !== null ? v : null, { label });
    if (type === 'bytes') val = h('span.inline-ctl', {}, numberInput(has && v !== null ? v : null, { step: 0.1, scale: MiB, label: `${label} (MiB)` }), h('span.mono', { text: 'MiB' }));
    if (type === 'dur') val = durationInput(has && v !== null ? v : null, { allowNull: true });
    const sync = () => {
      if (!val) return;
      if (val.setMode) val.setMode(mode.value === 'value'); // link rules: always shown, with the tester
      else val.hidden = mode.value !== 'value';
    };
    mode.onchange = sync;
    sync();
    const eff = effective && Object.prototype.hasOwnProperty.call(effective, key) ? effective[key] : undefined;
    const effText = eff === undefined ? '' : `effective: ${limitText(type, eff)}`;
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
      else if (c.mode.value.startsWith('enum:')) patch[c.key] = c.mode.value.slice(5);
      else if (c.type === 'rules') {
        try { patch[c.key] = c.val.read(); } catch (e) { return msg(`File type list: ${e.message}`, true); }
      } else if (c.type === 'urlrules') {
        try { patch[c.key] = c.val.read(); } catch (e) { return msg(`Links that may be shared: ${e.message}`, true); }
      } else {
        const read = c.type === 'bytes' ? c.val.firstChild.read() : c.val.read();
        if (!Number.isFinite(read)) return msg(`Enter a value for ${c.key}.`, true);
        patch[c.key] = read;
      }
    }
    const ok = await guard(() => admin.limits(scope, channel, patch), 'Limits saved.');
    if (ok && onSaved) onSaved(); // re-render so the "effective" column is current
  };
  if (keys.some(([k]) => k === 'fileTypeRules')) box.appendChild(h('p.mono.muted', { text: RULES_HINT }));
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
  await refreshOverview(); // the global password policy may have just changed
  const data = await guard(() => admin.users());
  if (!data) return;
  const user = h('input.input', { placeholder: 'username', maxlength: '64', 'aria-label': 'New username', autocomplete: 'off' });
  // The owner may set any password; the policy applies when users change their own.
  const newPolicy = overview?.defaults?.inherited;
  const pw = h('input.input', { type: 'password', placeholder: 'password', 'aria-label': 'New user password', autocomplete: 'new-password' });
  const pw2 = h('input.input', { type: 'password', placeholder: 'repeat password', 'aria-label': 'Repeat password', autocomplete: 'new-password' });
  const add = h('button.btn', { type: 'button', text: 'Create user' });
  add.onclick = async () => {
    const bad = checkOwnerPassword(pw.value, pw2.value);
    if (bad) return msg(bad, true);
    add.disabled = true;
    const cred = await newCredential(pw.value);
    const r = await guard(() => admin.createUser({ username: user.value.trim(), ...cred }), 'User created.');
    add.disabled = false;
    if (r) renderUsers();
  };
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'Create a user' }), h('div.toolbar', {}, user, pw, pw2, add),
    h('p.mono.muted', { text: `You may set any password. When users change their own, it must follow their policy (${describePolicy(newPolicy)}), checked in the browser only: the server never sees passwords.` })));

  const body = h('tbody');
  // The built-in public account is managed under Public access, and the owner
  // (you) on Account: neither is listed here.
  for (const u of data.users.filter((x) => x.role !== 'public' && x.role !== 'owner')) {
    const actions = h('div.btn-row.row-actions');
    actions.appendChild(h('button.btn', { type: 'button', text: 'Manage', on: { click: () => openUser(u.id) } }));
    actions.appendChild(h('button.btn', { type: 'button', text: 'Log in as', on: { click: async () => { if (await guard(() => admin.impersonate(u.id))) location.href = '/dashboard/'; } } }));
    actions.appendChild(h('button.btn', { type: 'button', text: u.disabled ? 'Enable' : 'Disable', on: { click: async () => { await guard(() => admin.updateUser(u.id, { disabled: !u.disabled }), u.disabled ? 'User enabled.' : 'User disabled.'); renderUsers(); } } }));
    if (u.locked) actions.appendChild(h('button.btn', { type: 'button', text: 'Unlock', on: { click: async () => { await guard(() => admin.unlock(u.id), 'Unlocked.'); renderUsers(); } } }));
    const del = h('button.btn.danger', { type: 'button', text: 'Delete' });
    armConfirm(del, 'Delete user + revoke shares?', async () => { await guard(() => admin.deleteUser(u.id, true), 'User deleted.'); renderUsers(); });
    actions.appendChild(del);
    body.appendChild(h('tr', {}, h('td', { dataset: { label: 'User' }, text: u.username }), h('td.mono', { dataset: { label: 'Role' }, text: u.role }),
      h('td', { dataset: { label: 'Status' } }, h(`span.pill.${u.disabled ? 'bad' : u.locked ? 'warn' : 'ok'}`, { text: u.disabled ? 'disabled' : u.locked ? 'locked' : 'active' })),
      h('td.mono', { dataset: { label: 'Created' }, text: formatDate(u.created) }), h('td.cell-actions', {}, actions)));
  }
  p.appendChild(h('div.table-wrap', {}, h('table.table', {}, h('thead', {}, h('tr', {}, ...['User', 'Role', 'Status', 'Created', ''].map((t) => h('th', { text: t })))), body)));
  p.appendChild(h('div', { id: 'user-detail' }));
}

async function openUser(id, passwordOnly = false, { scroll = true } = {}) {
  const box = clear($('#user-detail'));
  const d = await guard(() => admin.user(id));
  if (!d) return;
  box.appendChild(h('h2.section-title', { text: `Manage ${d.user.username}` }));
  const userPolicy = d.effective.all;
  const npw = h('input.input', { type: 'password', placeholder: 'new password', autocomplete: 'new-password', 'aria-label': 'New password' });
  const npw2 = h('input.input', { type: 'password', placeholder: 'repeat', autocomplete: 'new-password', 'aria-label': 'Repeat new password' });
  const setBtn = h('button.btn', { type: 'button', text: 'Set password' });
  setBtn.onclick = async () => {
    const bad = checkOwnerPassword(npw.value, npw2.value);
    if (bad) return msg(bad, true);
    setBtn.disabled = true;
    const cred = await newCredential(npw.value);
    await guard(() => admin.setPassword(id, cred), 'Password set. Their sessions were signed out; their passkeys and recovery codes still work.');
    setBtn.disabled = false;
    npw.value = npw2.value = '';
  };
  box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Set password (no current password needed)' }),
    h('p.mono.muted', { text: 'This is account recovery: it also signs the user out everywhere. Their passkeys and recovery codes keep working; remove them below if the account may have been taken over.' }), h('div.toolbar', {}, npw, npw2, setBtn),
    h('p.mono.muted', { text: `You may set any password. This user's own changes follow: ${describePolicy(userPolicy)}` })));
  if (passwordOnly) return;

  box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Capabilities & limits (GUI + API)' }), limitsEditor({ scope: id, channel: 'all', rows: d.limits.all, effective: d.effective.all, inherited: overview?.defaults.inherited, onSaved: () => openUser(id, false, { scroll: false }) })));
  box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Extra API restrictions (can only narrow, never widen)' }), limitsEditor({ scope: id, channel: 'api', rows: d.limits.api, effective: d.effective.api, onSaved: () => openUser(id, false, { scroll: false }) })));
  box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Quotas for this user (in addition to global quotas)' }), quotasEditor(id, d.quotas)));
  box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Per-user viewer rules (used when "Use per-user viewer rules" is on)' }), rulesEditor(id, d.viewerRules)));
  box.appendChild(userKeysCard(id, d.keys));
  const pk = d.passkeys || { count: 0, recoveryLeft: 0, mfa: false };
  const pkReset = h('button.btn.danger', { type: 'button', text: 'Remove all passkeys', disabled: !pk.count && !pk.recoveryLeft });
  armConfirm(pkReset, 'Remove passkeys and codes?', async () => {
    if (await guard(() => admin.resetPasskeys(id), 'Passkeys and recovery codes removed.')) openUser(id, false, { scroll: false });
  });
  box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Passkeys' }),
    h('p.mono', { text: pk.count ? `${pk.count} passkey${pk.count === 1 ? '' : 's'}, ${pk.recoveryLeft} recovery code${pk.recoveryLeft === 1 ? '' : 's'} left${pk.mfa ? '; password logins also need a passkey' : ''}.` : 'No passkeys.' }),
    h('p.mono.muted', { text: 'Removes every passkey and recovery code of this account (after a lost device or a takeover); the password alone then signs in. Passkeys can only be added by the user, on their own device.' }),
    h('div.btn-row', {}, pkReset)));
  if (scroll) box.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

const KEY_SCOPES = [['notes', 'create notes'], ['files', 'upload files'], ['policy', 'read the policy']];
const KEY_LIFE = [['', 'never expires'], ['604800', '7 days'], ['2592000', '30 days'], ['31536000', '365 days']];
const scopeBoxes = (checked) => KEY_SCOPES.map(([v, t]) => {
  const c = h('input', { type: 'checkbox', value: v, checked: checked.includes(v) });
  return { c, label: h('label.inline', {}, c, ` ${t}`) };
});

/** A user's API keys: the owner creates, changes and revokes them (no confirmation for other users). */
function userKeysCard(id, list) {
  const name = h('input.input', { placeholder: 'Key name', maxlength: '100', 'aria-label': 'Key name' });
  const life = h('select.input', { 'aria-label': 'Key lifetime' }, ...KEY_LIFE.map(([v, t]) => h('option', { value: v, text: t })));
  const boxes = scopeBoxes(KEY_SCOPES.map(([v]) => v));
  const shown = h('div.linkrow', { hidden: true });
  const create = h('button.btn', { type: 'button', text: 'Create key' });
  create.onclick = async () => {
    const scopes = boxes.filter((b) => b.c.checked).map((b) => b.c.value);
    if (!scopes.length) return msg('Choose at least one thing the key may do.', true);
    const r = await guard(() => admin.createUserKey(id, { name: name.value.trim(), expiresInSec: life.value ? Number(life.value) : null, scopes }), 'API key created. Copy it now: it is shown only once.');
    if (!r) return;
    // Shown once: hand it to the user over a safe channel.
    shown.replaceChildren(h('div.url.mono', { text: r.key }), h('button.copy-btn', { type: 'button', text: 'copy', on: { click: async (e) => flashCopied(e.target, (await copyText(r.key)) ? 'copied' : 'failed') } }));
    shown.hidden = false;
    name.value = '';
    rows();
  };
  const body = h('tbody');
  const rows = async () => {
    const d = await guard(() => admin.user(id));
    if (d) fill(d.keys);
  };
  const fill = (keys) => {
    body.replaceChildren();
    for (const k of keys) {
      const tr = h('tr');
      const edit = h('button.btn', { type: 'button', text: 'Edit' });
      edit.onclick = () => {
        const next = tr.nextElementSibling;
        if (next && next.classList.contains('key-edit-row')) { next.remove(); return; }
        const n = h('input.input', { value: k.name, maxlength: '100', 'aria-label': 'Key name' });
        const bs = scopeBoxes(k.scopes || []);
        const save = h('button.btn', { type: 'button', text: 'Save' });
        save.onclick = async () => {
          const scopes = bs.filter((b) => b.c.checked).map((b) => b.c.value);
          if (!scopes.length) return msg('Choose at least one thing the key may do.', true);
          if (await guard(() => admin.updateUserKey(id, k.id, { name: n.value.trim(), scopes }), 'API key updated.')) rows();
        };
        tr.after(h('tr.key-edit-row', {}, h('td.cell-full', { colspan: '5' }, h('div.toolbar', {}, n, h('fieldset.key-scopes', { 'aria-label': 'What the key may do' }, ...bs.map((b) => b.label)), save))));
      };
      const rv = h('button.btn.danger', { type: 'button', text: 'Revoke' });
      armConfirm(rv, 'Revoke?', async () => { if (await guard(() => admin.revokeUserKey(id, k.id), 'Key revoked.')) rows(); });
      tr.append(h('td', { dataset: { label: 'Name' }, text: k.name }), h('td.mono', { dataset: { label: 'Created' }, text: formatDate(k.created) }),
        h('td.mono', { dataset: { label: 'Last used' }, text: formatDate(k.last_used) }),
        h('td.mono', { dataset: { label: 'Scopes' }, text: (k.scopes || []).join(', ') }), h('td.cell-actions', {}, h('div.btn-row.row-actions', {}, edit, rv)));
      body.appendChild(tr);
    }
  };
  fill(list);
  return h('div.card.stack', {}, h('h3.field-label', { text: 'API keys' }),
    h('div.toolbar', {}, name, life, h('fieldset.key-scopes', { 'aria-label': 'What the key may do' }, ...boxes.map((b) => b.label)), create), shown,
    h('p.mono.muted', { text: 'Needs "API keys allowed" for this user. A new key is shown once: give it to the user over a safe channel.' }),
    h('div.table-wrap', {}, h('table.table', {}, h('thead', {}, h('tr', {}, ...['Name', 'Created', 'Last used', 'Scopes', ''].map((t) => h('th', { text: t })))), body)));
}

// ── defaults ─────────────────────────────────────────────────────────────────
async function renderDefaults() {
  const p = clear(panel('defaults'));
  await refreshOverview();
  if (!overview) return;
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'Default limits for every user' }),
    h('p.mono.muted', { text: 'Per-user settings override these; the built-in default is shown in brackets. Global settings never apply to the owner.' }),
    limitsEditor({ scope: 'global', channel: 'all', rows: overview.limits.all, inherited: overview.defaults.limits })));
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
  const defs = overview.defaults.settings;
  const dflt = (text) => h('span.mono.muted', { text: `default: ${text}` });
  const dur = (key, label) => { const c = durationInput(s[key]); fields.push([key, () => c.read()]); return h('div.limit-row', {}, h('span.field-label', { text: label }), c, dflt(limitText('dur', defs[key]))); };
  const int = (key, label) => { const c = numberInput(s[key], { label }); fields.push([key, () => c.read()]); return h('div.limit-row', {}, h('span.field-label', { text: label }), c, dflt(String(defs[key]))); };
  const mib = (key, label, max) => { const c = numberInput(s[key], { step: 1, scale: MiB, label: `${label} (MiB)` }); fields.push([key, () => c.read()]); return h('div.limit-row', {}, h('span.field-label', { text: label }), c, h('span.mono', { text: `MiB (max ${max})` }), dflt(formatBytes(defs[key]))); };
  const scopeRule = (scope, label) => h('div.card.stack', {}, h('h3.field-label', { text: label }),
    int(`guard.${scope}.max`, 'Failures allowed'), dur(`guard.${scope}.windowSec`, 'Within'), dur(`guard.${scope}.blockSec`, 'Then block the IP for'));
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'Sessions' }), dur('session.idleSec', 'Idle timeout'), dur('session.absSec', 'Absolute timeout')));
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'File shares' }),
    mib('files.maxShareBytes', 'Max share size (all files)', '2048'), dur('files.grantSec', 'Download window after opening'), dur('files.pendingSec', 'Unfinished upload deadline')));
  p.appendChild(h('div.stack', {}, h('h2.section-title', { text: 'Brute-force protection (per IP)' }),
    h('p.mono.muted', { text: 'Counts failures per network address (IPv6 per the tracking prefix below) and blocks that address for a while, whoever it is and whichever account it tries: it stops one source from guessing. Account lockout (below) is the other half: it counts wrong passwords per account, from any address, and locks only that account: it stops many sources guessing one account.' }),
    scopeRule('login', 'Login'), scopeRule('setup', 'Setup'),
    scopeRule('invalid', 'Invalid fetches: links that never existed, a wrong #key or password, bad tokens. Not counted: opening a share that expired, was used up, revoked or deleted with its correct link (#key); a wrong #key for such a share still counts'),
    h('div.card.stack', {}, int('guard.v6Prefix', 'IPv6 tracking prefix (/n)'))));
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'Activity log' }),
    h('p.mono.muted', { text: 'Older entries, and the oldest beyond the size limit, are deleted automatically. Per-user limits (Defaults & quotas or a user) can keep less about an account. Entries about the owner, entries the owner made (admin actions, impersonation) and server-wide changes (settings, global limits, IP rules, exports) are never deleted automatically. Check your retention obligations (e.g. audit trails) with Legal / Compliance.' }),
    dur('log.maxAgeSec', 'Keep entries for at most'), int('log.maxEntries', 'Keep at most this many entries')));
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'Account lockout (owner excluded)' }),
    h('p.mono.muted', { text: "Counts wrong passwords per account, from any network, and locks only that account. The owner is never locked out, but per-IP protection still guards the owner's login. A password change is never blocked by a lockout." }),
    int('lockout.max', 'Failed logins allowed'), dur('lockout.windowSec', 'Within'), dur('lockout.lockSec', 'Then lock the account for')));
  const contact = h('textarea.input', { rows: '2', maxlength: '500', 'aria-label': 'How to report an accessibility problem', placeholder: 'e.g. accessibility@example.com or +972-3-000-0000' });
  contact.value = s['a11y.contact'] || '';
  const coord = h('textarea.input', { rows: '2', maxlength: '500', 'aria-label': 'Accessibility coordinator (name and contact)', placeholder: 'Name, phone, email: only if you must appoint one' });
  coord.value = s['a11y.coordinator'] || '';
  const saveStatement = h('button.btn', { type: 'button', text: 'Save statement details' });
  saveStatement.onclick = () => guard(() => admin.settings({ 'a11y.contact': contact.value.trim(), 'a11y.coordinator': coord.value.trim() }), 'Accessibility statement saved.');
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'Accessibility statement' }),
    h('p.mono.muted', {}, 'Shown on the public ', h('a', { href: '/accessibility/', text: 'accessibility statement' }), ' page (English and Hebrew). A way to report a problem is required; list a coordinator only if the law requires you to appoint one (in Israel, from 25 employees). Have the statement reviewed by an accessibility professional or Legal before relying on it.'),
    h('label.field-label', { text: 'How to report a problem' }), contact,
    h('label.field-label', { text: 'Accessibility coordinator (optional)' }), coord, h('div.btn-row', {}, saveStatement)));
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

// ── public access ────────────────────────────────────────────────────────────
const PUBLIC_ID = 'public-user-0000';
// Not for the public account (no API keys, receipts page, password, passkeys
// or log of its own); the server refuses them too (PUBLIC_NA_LIMITS).
const PUBLIC_OMIT = ['apiEnabled', 'apiMaxKeys', 'receiptIp', 'receiptLocation', 'receiptBrowser', 'receiptOs', 'receiptLanguages',
  'logMaxAgeSec', 'logMaxEntries', 'pwMinLength', 'pwUpper', 'pwLower', 'pwDigit', 'pwSymbol', 'passkeys'];
const TRACKING = [
  ['tracker', 'Browser identifier only (default)', 'A random id kept in the browser (cookie, ETag cache, localStorage, IndexedDB), repaired from its other copies; if two ids that both created shares tie, that browser is blocked. Nothing about the network is used.'],
  ['ip', 'Network address only', 'Counts per IP address (IPv6 per the tracking prefix), stored only as a keyed hash. Nothing is stored in the browser; people behind one address share the limits.'],
  ['both-permissive', 'Both — permissive', 'Counts per browser and per network; refused only when both are over a limit (a shared office address alone does not block a new browser).'],
  ['both-restrictive', 'Both — restrictive', 'Counts per browser and per network; refused when either is over a limit (a new browser on an exhausted network is refused).'],
];

async function renderPublic() {
  const p = clear(panel('public'));
  await refreshOverview();
  if (!overview) return;
  const s = overview.settings;
  const data = await guard(() => admin.publicAccess());
  const detail = await guard(() => admin.user(PUBLIC_ID));
  if (!data || !detail) return;

  const on = h('input', { type: 'checkbox', checked: s['public.enabled'] });
  const radios = TRACKING.map(([v, label, hint]) => {
    const r = h('input', { type: 'radio', name: 'public-tracking', value: v, checked: s['public.tracking'] === v });
    return h('label.radio-opt', {}, r, h('span', {}, h('strong', { text: label }), h('span.mono.muted.block', { text: hint })));
  });
  const notice = h('input', { type: 'checkbox', checked: s['public.notice'] });
  const noticeText = h('textarea.input', { rows: '3', maxlength: '1000', 'aria-label': 'Notice text' });
  noticeText.value = s['public.noticeText'];
  const perIp = numberInput(s['public.newTrackersPerIp'], { label: 'New anonymous identifiers per network' });
  const perWin = durationInput(s['public.newTrackersWindowSec']);
  const idle = durationInput(s['public.trackerIdleSec']);
  const save = h('button.cta', { type: 'button', text: 'Save public access' });
  save.onclick = async () => {
    const mode = radios.map((l) => l.querySelector('input')).find((r) => r.checked)?.value || 'tracker';
    const patch = {
      'public.enabled': on.checked, 'public.tracking': mode, 'public.notice': notice.checked, 'public.noticeText': noticeText.value,
      'public.newTrackersPerIp': perIp.read(), 'public.newTrackersWindowSec': perWin.read(), 'public.trackerIdleSec': idle.read(),
    };
    for (const [k, v] of Object.entries(patch)) if (typeof v === 'number' && !Number.isFinite(v)) return msg(`Enter a value for ${k}.`, true);
    const ok = await guard(() => admin.settings(patch), 'Public access saved.');
    if (ok) renderPublic();
  };

  p.appendChild(h('div.card.stack', {},
    h('h2.section-title', { text: 'Public (anonymous) sharing' }),
    h('p.subtitle', { text: 'When on, the home page offers the composer to anyone, as the built-in public account: no password, no dashboard, no API keys. Its capabilities, limits and quotas are set below; quotas are counted per anonymous creator.' }),
    h('p.type-hint.warn', { role: 'note', text: 'Tracking anonymous visitors (cookies, browser storage, network addresses) is regulated (GDPR / ePrivacy and others). Have your Legal and Compliance team approve the mode and the notice before turning this on.' }),
    h('label.inline', {}, on, ' Allow anonymous sharing'),
    h('fieldset.range', {}, h('legend', { text: 'How anonymous creators are counted' }), ...radios),
    h('label.inline', {}, notice, ' Show a notice on the public composer'),
    h('label.field', {}, h('span.field-label', { text: 'Notice text' }), noticeText),
    h('div.limit-row', {}, h('span.field-label', { text: 'New senders (browser ids) per network' }), perIp, h('span.field-label', { text: 'per' }), perWin),
    h('div.limit-row', {}, h('span.field-label', { text: 'Forget idle browser ids after' }), idle),
    h('p.muted', { text: 'A browser id is stored only when it first creates a share; that is when the per-network limit is spent. Clearing browser storage gives a new id, so tracker mode allows up to (new senders × quota) shares per network per window.' }),
    h('div.btn-row', {}, save)));

  p.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Public account: capabilities & limits' }),
    limitsEditor({ scope: PUBLIC_ID, channel: 'all', rows: detail.limits.all, effective: detail.effective.all, inherited: overview.defaults.inherited, onSaved: renderPublic, omit: PUBLIC_OMIT })));
  p.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Public quotas (counted per anonymous creator, in addition to global quotas)' }), quotasEditor(PUBLIC_ID, detail.quotas)));

  const t = data.trackers;
  const body = h('tbody');
  for (const r of t.rows) {
    const act = (action, label, cls = 'btn') => h(`button.${cls}`, { type: 'button', text: label, on: { click: async () => { if (await guard(() => admin.tracker(r.id, action), `Browser id ${action === 'forget' ? 'forgotten' : `${action}ed`}.`)) renderPublic(); } } });
    body.appendChild(h('tr', {},
      h('td.mono', { dataset: { label: 'Id' }, text: r.id }),
      h('td.mono', { dataset: { label: 'First seen' }, text: formatDate(r.created) }),
      h('td.mono', { dataset: { label: 'Last seen' }, text: formatDate(r.last_seen) }),
      h('td.mono', { dataset: { label: 'Shares' }, text: String(r.uses) }),
      h('td', { dataset: { label: 'Status' } }, r.blocked ? h('span.pill.bad', { text: r.reason === 'conflict' ? 'blocked: conflicting copies' : 'blocked' }) : h('span.pill.ok', { text: 'ok' })),
      h('td.cell-actions', {}, h('div.btn-row', {}, r.blocked ? act('unblock', 'Unblock') : act('block', 'Block', 'btn.danger'), act('forget', 'Forget', 'btn')))));
  }
  p.appendChild(h('div.card.stack', {},
    h('h3.field-label', { text: `Anonymous browser ids (${t.total}, ${t.blocked} blocked)` }),
    h('p.mono.muted', { text: 'Ids are shown as a prefix of their keyed hash; the ids themselves are not stored. Forgetting one also resets its quota usage.' }),
    t.rows.length ? h('div.table-wrap', {}, h('table.table', {}, h('thead', {}, h('tr', {}, ...['Id', 'First seen', 'Last seen', 'Shares', 'Status', ''].map((x) => h('th', { text: x })))), body)) : h('p.mono.muted', { text: 'None yet.' })));
}

// ── viewer ───────────────────────────────────────────────────────────────────
async function renderViewer() {
  const p = clear(panel('viewer'));
  await refreshOverview();
  if (!overview) return;
  const s = overview.settings;
  const on = h('input', { type: 'checkbox', checked: s['viewer.enabled'], id: 'viewer-enabled' });
  const max = numberInput(s['viewer.maxBytes'], { step: 1, scale: MiB, label: 'Largest file the viewer opens (MiB)' });
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
/**
 * Cloudflare Turnstile (the human check on login, password change and public
 * sharing): keys entered here apply when the deployment sets none. The secret
 * is write-only: never shown again, only replaced or removed.
 */
async function turnstileCard() {
  const st = await guard(() => admin.turnstile());
  const card = h('div.card.stack', {}, h('h2.section-title', { text: 'Human check (Cloudflare Turnstile)' }));
  if (!st) return card;
  const state = st.active === 'env' ? 'On, with the deployment\'s keys (TURNSTILE_SITEKEY and TURNSTILE_SECRET).'
    : st.active === 'admin' ? 'On, with the keys set here.' : 'Off: no keys are set.';
  card.appendChild(h('p', { text: state }));
  card.appendChild(h('p.mono.muted', { text: 'When on, login, a password change and anonymous sharing ask for a Turnstile check. Create a widget in the Cloudflare dashboard (Turnstile → Add widget) for this hostname, then paste its site key and secret key. The deployment\'s keys (Worker variables or secrets) always win over the ones set here; a Worker secret is the safer place for the secret key.' }));
  if (st.deployment) {
    card.appendChild(h('p.mono.muted', { text: 'Set by the deployment: change or remove the keys there (wrangler secret put TURNSTILE_SECRET, TURNSTILE_SITEKEY in wrangler.toml or the dashboard).' }));
    return card;
  }
  const passkey = await canUsePasskey();
  const sitekey = h('input.input', { value: st.sitekey || '', placeholder: '0x4AAAAAAA…', maxlength: '100', spellcheck: 'false', autocomplete: 'off', 'aria-label': 'Turnstile site key' });
  const secret = h('input.input', { type: 'password', placeholder: st.secretSet ? 'saved: leave empty to keep it' : '0x4AAAAAAA…', maxlength: '100', autocomplete: 'off', 'aria-label': 'Turnstile secret key' });
  const mineLabel = confirmLabel('Your password', passkey);
  const mine = h('input.input', { type: 'password', autocomplete: 'current-password', 'aria-label': mineLabel, placeholder: mineLabel });
  const save = h('button.btn', { type: 'button', text: 'Save keys' });
  save.onclick = async () => {
    let step;
    try { step = await confirmStep(mine, profile.user.username, passkey); } catch (e) { return msg(friendlyError(e), true); }
    if (await guard(() => admin.setTurnstile({ sitekey: sitekey.value.trim(), secret: secret.value.trim(), ...step }), 'Turnstile keys saved. The human check is on (other servers pick it up within 30 seconds).')) renderSecurity();
  };
  const remove = h('button.btn.danger', { type: 'button', text: 'Remove keys', disabled: !st.sitekey && !st.secretSet });
  armConfirm(remove, 'Remove keys: turn the check off?', async () => {
    let step;
    try { step = await confirmStep(mine, profile.user.username, passkey); } catch (e) { return msg(friendlyError(e), true); }
    if (await guard(() => admin.setTurnstile({ clear: true, ...step }), 'Turnstile keys removed. The human check is off.')) renderSecurity();
  });
  card.append(
    h('label.field', {}, h('span.field-label', { text: 'Site key (public)' }), sitekey),
    h('label.field', {}, h('span.field-label', { text: st.secretSet ? 'Secret key (saved; never shown again)' : 'Secret key' }), secret),
    h('label.field', {}, h('span.field-label', { text: mineLabel }), mine),
    h('div.btn-row', {}, save, remove),
    h('p.mono.muted', { text: 'The secret key is stored in the server\'s database, never returned by any API and never logged. Test the keys by signing in from a private window before relying on them.' }));
  return card;
}

async function renderSecurity() {
  const p = clear(panel('security'));
  const [g, rules] = await Promise.all([guard(() => admin.guard()), guard(() => admin.ipRules())]);
  p.appendChild(await turnstileCard());
  // Manual rules.
  const cidr = h('input.input', { placeholder: 'IP, CIDR or range: 10.0.0.0/8, 10.0.0.5-10.0.0.20', 'aria-label': 'IP address, CIDR block or range', maxlength: '100' });
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
/**
 * Clear some or all of the activity log: everything, or one account's
 * entries, optionally only those older than a date. Needs the owner's
 * password again; nothing records that it happened.
 */
function clearLogsCard(onDone) {
  const scope = h('select.input', { 'aria-label': 'Which log entries' },
    h('option', { value: 'all', text: 'all accounts' }), h('option', { value: 'user', text: 'one account' }));
  const who = h('select.input', { 'aria-label': 'Account', hidden: true });
  const olderOn = h('input', { type: 'checkbox', 'aria-label': 'Only entries older than a date' });
  const date = h('input.input', { type: 'date', 'aria-label': 'Older than', disabled: true });
  const mine = h('input.input', { type: 'password', placeholder: 'your password', autocomplete: 'current-password', 'aria-label': 'Your password, to confirm' });
  const go = h('button.btn.danger', { type: 'button', text: 'Delete log entries' });
  scope.onchange = async () => {
    who.hidden = scope.value !== 'user';
    if (!who.hidden && !who.options.length) {
      const d = await guard(() => admin.users());
      for (const u of d?.users || []) who.appendChild(h('option', { value: u.id, text: `${u.username}${u.role === 'owner' ? ' (owner)' : ''}` }));
    }
  };
  olderOn.onchange = () => { date.disabled = !olderOn.checked; };
  armConfirm(go, 'Delete for good?', async () => {
    if (!mine.value) return msg('Enter your password to confirm.', true);
    if (olderOn.checked && !date.value) return msg('Pick the date.', true);
    const before = olderOn.checked ? Math.floor(Date.parse(`${date.value}T00:00:00Z`) / 1000) : null;
    const current = await loginProof(profile.user.username, mine.value);
    const r = await guard(() => admin.clearLogs({ current, scope: scope.value, user: scope.value === 'user' ? who.value : undefined, before }));
    mine.value = '';
    if (r) {
      toast(`${r.deleted} log entr${r.deleted === 1 ? 'y' : 'ies'} deleted.`);
      onDone();
    }
  });
  return h('div.card.stack', {}, h('h2.section-title', { text: 'Clear logs' }),
    h('p.mono.muted', { text: 'Deletes entries for good, without leaving a record that they existed. Audit trails may be subject to retention duties (e.g. SOX): check with Legal / Compliance before clearing.' }),
    h('div.toolbar', {}, scope, who, h('label.inline', {}, olderOn, ' older than'), date, mine, go));
}

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
  p.appendChild(clearLogsCard(() => renderAudit()));
  p.appendChild(h('div.table-wrap', {}, h('table.table', {}, h('thead', {}, h('tr', {}, ...['When', 'Who', 'On user', 'Action', 'Details'].map((t) => h('th', { text: t })))), body)));
  p.appendChild(h('div.btn-row', {}, more));
  await load();
  void toast;
}
