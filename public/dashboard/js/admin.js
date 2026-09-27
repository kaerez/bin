// admin.js — owner administration: users (create, limits, API rules, viewer
// rules, reset password, impersonate, disable, unlock, delete), global
// defaults + quotas, settings (sessions, files, brute-force rules, lockout),
// viewer policy, security (blocks, tracking, manual IP rules) and the audit log.
// Every write is validated again by the server.

import '../../js/kdf-progress.js';
import { admin } from '../../js/api.js';
import { newCredential, checkOwnerPassword, describePolicy, loginProof } from '../../js/pwauth.js';
import { h, clear, showMsg, armConfirm, formatDate, formatBytes, friendlyError, DURATION_UNITS, splitDuration, unitSeconds, reducedMotion } from '../../js/common.js';
import { toast, copyText, flashCopied, keepFocus, tablistKeys } from '../../js/ui.js';
import { normalizeRules } from '../../js/filepolicy.js';
import { normalizeUrlRules, parseShareUrl, matchingUrlRule, unanchoredRules, DEFAULT_URL_RULES } from '../../js/sharetypes.js';
import { STATEMENT_FIELDS, MAIN, ALT, guessDir } from '../../js/a11ystatement.js';
import { ready } from './nav.js';
import { confirmStep, confirmLabel, canUsePasskey } from './confirm.js';
import { renderShares } from './admin-shares.js';
import { renderPortable } from './admin-portable.js';

const $ = (s) => document.querySelector(s);
const panel = (name) => document.querySelector(`.admin-panel[data-panel="${name}"]`);
const MiB = 1024 * 1024;
/** A header cell; the actions column (no visible title) is named for screen readers. */
const th = (t) => (t ? h('th', { text: t }) : h('th', {}, h('span.sr-only', { text: 'Actions' })));
let syncTabs = () => {};

// Role options in sections (the editor shows a heading per section). Each row:
// [key, label, type, options]; the section is added as a fifth element.
const LIMIT_SECTIONS = [
  ['Sharing', [
    ['text', 'Notes allowed', 'bool'],
    ['files', 'File sharing allowed', 'bool'],
    ['secret', 'Credential shares allowed (needs notes)', 'bool'],
    ['openerDelete', 'Recipients may “delete now” (sender opts in)', 'bool'],
    ['maxViews', 'Max views per share', 'int'],
    ['allowUnlimitedViews', 'Unlimited views allowed', 'bool'],
    ['maxExpireSec', 'Max expiry', 'dur'],
  ]],
  ['Links', [
    ['url', 'Link shares allowed (needs notes)', 'bool'],
    ['urlRules', 'Links that may be shared', 'urlrules'],
  ]],
  ['Files', [
    ['maxFilesPerShare', 'Max files per share', 'int'],
    ['maxShareBytes', 'Max share size', 'bytes'],
    ['maxFileBytes', 'Max single file size', 'bytes'],
    ['fileTypeMode', 'File types', 'enum', { values: [['any', 'any type'], ['allow', 'only the listed types'], ['block', 'all but the listed types']] }],
    ['fileTypeRules', 'File type list', 'rules'],
    ['maxFolderDepth', 'Max folder depth', 'int'],
  ]],
  ['File shares', [
    ['fileGrantSec', 'File shares: recipients may download for this long after opening', 'dur', { nullable: false }],
    ['filePendingSec', 'File shares: an unfinished upload is discarded after', 'dur', { nullable: false }],
  ]],
  ['In-browser viewer', [
    ['viewer', 'In-browser viewer', 'bool'],
    ['viewerCustomRules', 'Use this role\'s own viewer rules (not Default\'s)', 'bool'],
    ['viewerMaxBytes', 'In-browser viewer: largest file', 'bytes', { nullable: false }],
  ]],
  ['API keys', [
    ['apiEnabled', 'API keys allowed', 'bool'],
    ['apiMaxKeys', 'Max API keys', 'int'],
  ]],
  ['Read receipts', [
    ['receiptIp', 'Read receipts: sender sees the opener\'s address', 'bool'],
    ['receiptLocation', 'Read receipts: sender sees the approximate location', 'bool'],
    ['receiptBrowser', 'Read receipts: sender sees the browser and version', 'bool'],
    ['receiptOs', 'Read receipts: sender sees the operating system', 'bool'],
    ['receiptLanguages', 'Read receipts: sender sees the browser languages', 'bool'],
  ]],
  ['Activity log', [
    ['logMaxAgeSec', 'Keep each user\'s entries for', 'dur', { nullText: 'keep forever' }],
    ['logMaxEntries', 'Keep at most this many entries per user', 'int', { nullText: 'keep forever' }],
  ]],
  ['Password', [
    ['pwMinLength', 'Password: minimum length', 'int', { nullable: false }],
    ['pwUpper', 'Password: needs an upper-case letter', 'bool'],
    ['pwLower', 'Password: needs a lower-case letter', 'bool'],
    ['pwDigit', 'Password: needs a digit', 'bool'],
    ['pwSymbol', 'Password: needs a symbol', 'bool'],
  ]],
  ['Passkeys', [
    ['passkeys', 'Passkeys', 'enum', { values: [['any', 'sign in alone or as a second factor'], ['second', 'only as a second factor after the password'], ['off', 'not allowed']] }],
    ['passkeysMax', 'Passkeys: at most', 'int', { nullable: false }],
  ]],
  ['Sessions', [
    ['sessionIdleSec', 'Session: sign out after being idle for', 'dur', { nullable: false }],
    ['sessionAbsSec', 'Session: sign out in any case after', 'dur', { nullable: false }],
  ]],
];
const LIMIT_UI = LIMIT_SECTIONS.flatMap(([section, list]) => list.map(([k, label, type, opt = {}]) => [k, label, type, opt, section]));
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
  for (const t of document.querySelectorAll('.tab[data-tab]')) {
    // Tab ↔ panel wiring (ids, aria-controls, role="tabpanel"); the panel is
    // also the focus fallback when a re-render removes the focused control.
    const p = panel(t.dataset.tab);
    t.id = `admin-tab-${t.dataset.tab}`;
    p.id = `admin-panel-${t.dataset.tab}`;
    t.setAttribute('aria-controls', p.id);
    p.setAttribute('role', 'tabpanel');
    p.setAttribute('aria-labelledby', t.id);
    p.tabIndex = -1;
    t.onclick = () => selectTab(t.dataset.tab);
  }
  // Arrow keys move between the tabs; Enter / Space opens one (panels load from the server).
  syncTabs = tablistKeys(document.querySelector('.tabs[role="tablist"]'));
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
  syncTabs();
  ({ users: renderUsers, roles: renderRoles, shares: () => renderShares(panel('shares')), settings: renderSettings, security: renderSecurity, public: renderPublic, portable: () => renderPortable(panel('portable'), profile), audit: renderAudit })[name]();
}

// ── reusable controls ────────────────────────────────────────────────────────
function durationInput(sec, { allowNull = false, label = '' } = {}) {
  const d = sec === null || sec === undefined ? { n: '', unit: 'h' } : splitDuration(sec);
  const n = h('input.input.opt-num', { type: 'number', min: '1', value: String(d.n), 'aria-label': label ? `${label}: amount` : 'Amount' });
  const u = h('select.input', { 'aria-label': label ? `${label}: unit` : 'Unit' }, ...DURATION_UNITS.map(([k, w]) => h('option', { value: k, text: w, selected: k === d.unit })));
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
      li(code('scheme:https://'), ' allows links of that scheme written with ', code('//'), ' (', code('https://example.com'), '). ', code('scheme:http://'), ' and ', code('scheme:https://'), ' are the built-in default; http and https links always have ', code('//'), '.'),
      li(code('scheme:tel:'), ' allows links of that scheme without ', code('//'), ' (', code('tel:+15551234'), ', ', code('mailto:a@example.com'), '). A scheme used both ways needs both rules: ', code('scheme:myapp://'), ' and ', code('scheme:myapp:'), '.'),
      li(code('scheme:*'), ' allows every scheme, either way, except the dangerous ones below.'),
      li(code('re:<pattern>'), ' allows links a regular expression matches. The engine is the browser\'s (JavaScript ', code('RegExp'), ', flags ', code('i'), ' and ', code('u'), ': case-insensitive, Unicode), tested against the whole link as the browser normalizes it (e.g. ', code('https://example.com/a?b=1'), '). It matches ', h('em', { text: 'anywhere' }), ' in the link unless you anchor it: ', code('re:^https://([a-z0-9-]+\\.)*example\\.com(/|$)'), ' allows example.com and its subdomains only.')),
    h('p', {}, code('javascript:'), ', ', code('data:'), ', ', code('file:'), ', ', code('blob:'), ' and similar can never be allowed. The sender\'s browser or CLI checks the rules (the server never sees the link), and recipients can open only web, mail, phone and SMS links; others are shown for copying.'));
}

/**
 * Link rules: the rules in effect (inherited ones shown read-only), a textarea
 * when "set to" is chosen, the help panel, and a tester that is always there —
 * type a link and see which rule allows it, or why it is refused.
 */
function urlRulesInput(initial, label, inheritedRules) {
  const area = h('textarea.input.rules-in', { rows: '3', spellcheck: 'false', 'aria-label': label, placeholder: 'scheme:https://\nscheme:tel:\nre:^https://([a-z0-9-]+\\.)*example\\.com(/|$)' });
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
// Explanations shown under a section heading in the role editors (as the
// Owner role editor has for the owner's own values).
const SECTION_NOTES = {
  Sessions: [() => h('p.mono.muted', { text: 'How long this role\'s users stay signed in: signed out after being idle, and in any case after the absolute time.' })],
  'File shares': [() => h('p.mono.muted', { text: 'For file shares this role\'s users send: how long recipients may keep downloading after opening one, and how long an unfinished upload is kept before it is discarded.' })],
  'Activity log': [
    () => h('p.mono.muted', { text: 'Entries about each user with this role (their own actions and events on their account). Keep them forever, or delete the older ones, and the oldest beyond a number, automatically; Settings → Activity log caps every account as well. The owner\'s actions on the account follow the Owner role, and server-wide configuration changes are never deleted automatically. The owner can always clear entries by hand under Activity log.' }),
  ],
};

// Role options whose built-in default is a server setting (the owner's value).
const SETTING_DEFAULT = { sessionIdleSec: 'session.idleSec', sessionAbsSec: 'session.absSec', fileGrantSec: 'files.grantSec', filePendingSec: 'files.pendingSec' };
/** A role option's value as text ("keep forever" rather than "no limit" where the option says so). */
const optText = (type, v, opt = {}) => (v === null && opt.nullText ? opt.nullText : limitText(type, v));

/** "default: …" for a role option: its built-in value on a new install. */
function defaultText(key, type, opt) {
  const d = overview?.defaults;
  if (!d) return '';
  const v = SETTING_DEFAULT[key] ? d.settings?.[SETTING_DEFAULT[key]] : d.limits?.[key];
  if (v === undefined) return '';
  if (type === 'enum') return `default: ${opt.values.find(([k]) => k === v)?.[1] ?? v}`;
  return `default: ${optText(type, v, opt)}`;
}

function limitsEditor({ scope, channel, rows, effective, inherited, onSaved, omit = [], explicit = false }) {
  const box = h('div.limits-grid');
  const keys = (channel === 'api' ? LIMIT_UI.filter(([k]) => API_KEYS.includes(k)) : LIMIT_UI).filter(([k]) => !omit.includes(k));
  const ctls = [];
  let section = null;
  for (const [key, label, type, opt, sec] of keys) {
    if (sec !== section) {
      section = sec;
      box.appendChild(h('h4.limit-section', { text: sec }));
      if (channel !== 'api') for (const n of SECTION_NOTES[sec] || []) box.appendChild(n());
    }
    // The Default role (explicit) holds a value for every option: no "inherit".
    let has = Object.prototype.hasOwnProperty.call(rows, key);
    let v = has ? rows[key] : undefined;
    if (explicit && !has) { has = true; v = inherited?.[key]; }
    const choices = {
      bool: () => [h('option', { value: 'true', text: 'yes', selected: has && v === true }), h('option', { value: 'false', text: 'no', selected: has && v === false })],
      enum: () => opt.values.map(([k, t]) => h('option', { value: `enum:${k}`, text: t, selected: has && v === k })),
      rules: () => [h('option', { value: 'value', text: 'set to', selected: has })],
      urlrules: () => [h('option', { value: 'value', text: 'set to', selected: has })],
    }[type] ?? (() => [...(opt.nullable === false ? [] : [h('option', { value: 'null', text: opt.nullText || 'no limit', selected: has && v === null })]),
      h('option', { value: 'value', text: 'limit to', selected: has && v !== null })]);
    const inh = channel !== 'api' && inherited && Object.prototype.hasOwnProperty.call(inherited, key) ? ` (${optText(type, inherited[key], opt)})` : '';
    const inheritText = channel === 'api' ? 'no extra restriction' : `same as Default${inh}`;
    const mode = h('select.input', { 'aria-label': `${label} mode` },
      ...(explicit && channel !== 'api' ? [] : [h('option', { value: 'inherit', text: inheritText, selected: !has })]),
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
    if (type === 'dur') val = durationInput(has && v !== null ? v : null, { allowNull: true, label });
    const sync = () => {
      if (!val) return;
      if (val.setMode) val.setMode(mode.value === 'value'); // link rules: always shown, with the tester
      else val.hidden = mode.value !== 'value';
    };
    mode.onchange = sync;
    sync();
    const eff = effective && Object.prototype.hasOwnProperty.call(effective, key) ? effective[key] : undefined;
    const effText = eff === undefined ? '' : `effective: ${optText(type, eff, opt)}`;
    const note = [channel === 'api' ? '' : defaultText(key, type, opt), effText].filter(Boolean).join(' · ');
    box.appendChild(h('div.limit-row', {}, h('span.field-label', { text: label }), mode, val, h('span.mono.muted', { text: note })));
    ctls.push({ key, type, mode, val });
  }
  const save = h('button.btn', { type: 'button', text: `Save ${channel === 'api' ? 'API' : ''} limits`, dataset: { focusKey: `limits:${scope}:${channel}:save` } });
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
/** `focusKey`: where focus goes if the re-render loses it (see keepFocus). */
async function renderUsers(focusKey = null) {
  const refocus = keepFocus(panel('users'), { key: focusKey });
  try { await renderUsersInto(); } finally { refocus(); }
}

async function renderUsersInto() {
  const p = clear(panel('users'));
  await refreshOverview(); // the global password policy may have just changed
  const [data, roleList] = await Promise.all([guard(() => admin.users()), guard(() => admin.roles())]);
  if (!data) return;
  const assignable = (roleList?.roles || []).filter((r) => !r.locked && !r.fixed);
  const user = h('input.input', { placeholder: 'username', maxlength: '64', 'aria-label': 'New username', autocomplete: 'off' });
  // The owner may set any password; the policy applies when users change their own.
  const newPolicy = overview?.defaults?.inherited;
  const pw = h('input.input', { type: 'password', placeholder: 'password', 'aria-label': 'New user password', autocomplete: 'new-password' });
  const pw2 = h('input.input', { type: 'password', placeholder: 'repeat password', 'aria-label': 'Repeat password', autocomplete: 'new-password' });
  const add = h('button.btn', { type: 'button', text: 'Create user', dataset: { focusKey: 'users:create' } });
  add.onclick = async () => {
    const bad = checkOwnerPassword(pw.value, pw2.value);
    if (bad) return msg(bad, true);
    add.disabled = true;
    const cred = await newCredential(pw.value);
    const r = await guard(() => admin.createUser({ username: user.value.trim(), ...cred }), 'User created.');
    add.disabled = false;
    if (r) renderUsers('users:create');
    else add.focus();
  };
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'Create a user' }), h('div.toolbar', {}, user, pw, pw2, add),
    h('p.mono.muted', { text: `You may set any password. When users change their own, it must follow their policy (${describePolicy(newPolicy)}), checked in the browser only: the server never sees passwords.` })));

  const body = h('tbody');
  // The built-in public account is managed on the Public role, and the owner
  // (you) on Account: neither is listed here.
  for (const u of data.users.filter((x) => x.role !== 'public' && x.role !== 'owner')) {
    const actions = h('div.btn-row.row-actions', { dataset: { focusKey: `user:${u.id}` } });
    actions.appendChild(h('button.btn', { type: 'button', text: 'Manage', dataset: { focusKey: `user:${u.id}:manage` }, on: { click: () => openUser(u.id) } }));
    actions.appendChild(h('button.btn', { type: 'button', text: 'Log in as', on: { click: async () => { if (await guard(() => admin.impersonate(u.id))) location.href = '/dashboard/'; } } }));
    actions.appendChild(h('button.btn', { type: 'button', text: u.disabled ? 'Enable' : 'Disable', dataset: { focusKey: `user:${u.id}:toggle` }, on: { click: async () => { await guard(() => admin.updateUser(u.id, { disabled: !u.disabled }), u.disabled ? 'User enabled.' : 'User disabled.'); renderUsers(); } } }));
    if (u.locked) actions.appendChild(h('button.btn', { type: 'button', text: 'Unlock', on: { click: async () => { await guard(() => admin.unlock(u.id), 'Unlocked.'); renderUsers(); } } }));
    const del = h('button.btn.danger', { type: 'button', text: 'Delete' });
    armConfirm(del, 'Delete user + revoke shares?', async () => { await guard(() => admin.deleteUser(u.id, true), 'User deleted.'); renderUsers(); });
    actions.appendChild(del);
    // One role per user; changing it applies at once.
    const pick = h('select.input', { 'aria-label': `Role of ${u.username}`, dataset: { focusKey: `user:${u.id}:role` } }, ...assignable.map((r) => h('option', { value: r.id, text: r.name, selected: r.id === u.roleId })));
    pick.onchange = async () => { if (!(await guard(() => admin.setUserRole(u.id, pick.value), `${u.username} now has the role ${pick.selectedOptions[0].textContent}.`))) renderUsers(); };
    body.appendChild(h('tr', {}, h('td', { dataset: { label: 'User' }, text: u.username }), h('td', { dataset: { label: 'Role' } }, pick),
      h('td', { dataset: { label: 'Status' } }, h(`span.pill.${u.disabled ? 'bad' : u.locked ? 'warn' : 'ok'}`, { text: u.disabled ? 'disabled' : u.locked ? 'locked' : 'active' })),
      h('td.mono', { dataset: { label: 'Created' }, text: formatDate(u.created) }), h('td.cell-actions', {}, actions)));
  }
  p.appendChild(h('div.table-wrap', {}, h('table.table', {}, h('thead', {}, h('tr', {}, ...['User', 'Role', 'Status', 'Created', ''].map(th))), body)));
  p.appendChild(h('div', { id: 'user-detail' }));
}

async function openUser(id, passwordOnly = false, { scroll = true } = {}) {
  const refocus = keepFocus($('#user-detail'), { fallback: () => $('#user-detail h2') });
  const box = clear($('#user-detail'));
  const d = await guard(() => admin.user(id));
  if (!d) return;
  const title = h('h2.section-title', { text: `Manage ${d.user.username}`, tabindex: '-1' });
  box.appendChild(title);
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

  // Capabilities, limits and quotas come from the user's role.
  const goRole = h('button.btn', { type: 'button', text: `Edit the role ${d.role?.name || 'Default'}`, on: { click: () => { selectTab('roles'); renderRoles(d.role?.id || 'default'); } } });
  box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: `Role: ${d.role?.name || 'Default'}` }),
    h('p.mono.muted', { text: 'What this user may do comes from their role. Change the role in the list above, or edit the role itself.' }), h('div.btn-row', {}, goRole)));
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
  if (scroll) {
    box.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth', block: 'start' });
    title.focus({ preventScroll: true }); // just opened: start reading at its heading
  } else refocus();
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
    h('div.table-wrap', {}, h('table.table', {}, h('thead', {}, h('tr', {}, ...['Name', 'Created', 'Last used', 'Scopes', ''].map(th))), body)));
}

// ── defaults ─────────────────────────────────────────────────────────────────
// ── roles ─────────────────────────────────────────────────────────────────────
// Every user has one role (Default unless given another). Owner: built in,
// locked (everything allowed, no limits), the owner's only. Default: built in,
// cannot be deleted, holds a value for every option. Custom roles leave
// options on "same as Default" until set.
async function renderRoles(openId = null) {
  const refocus = keepFocus(panel('roles'));
  try { await renderRolesInto(openId); } finally { refocus(); }
}

async function renderRolesInto(openId) {
  const p = clear(panel('roles'));
  await refreshOverview();
  const data = await guard(() => admin.roles());
  if (!data || !overview) return;
  const name = h('input.input', { placeholder: 'Role name, e.g. Contractors', maxlength: '64', 'aria-label': 'New role name' });
  const create = h('button.btn', { type: 'button', text: 'Create role' });
  create.onclick = async () => {
    const r = await guard(() => admin.createRole({ name: name.value.trim() }), 'Role created. Its options start as "same as Default".');
    if (r) renderRoles(r.id);
  };
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'Create a role' }), h('div.toolbar', {}, name, create),
    h('p.mono.muted', { text: 'Every user has exactly one role: Default unless you choose another (Users). A new role starts with every option on "same as Default", so it follows Default until you change an option.' })));

  const body = h('tbody');
  for (const r of data.roles) {
    const actions = h('div.btn-row.row-actions');
    if (r.locked) {
      actions.appendChild(h('button.btn', { type: 'button', text: 'Edit', on: { click: () => openRole(r.id) } }));
      actions.appendChild(h('span.mono.muted', { text: 'everything allowed, no limits; the owner only' }));
    } else if (r.fixed) {
      actions.appendChild(h('button.btn', { type: 'button', text: 'Edit', on: { click: () => openRole(r.id) } }));
      actions.appendChild(h('span.mono.muted', { text: 'anonymous visitors only; cannot be renamed, deleted or assigned' }));
    } else {
      actions.appendChild(h('button.btn', { type: 'button', text: 'Edit', on: { click: () => openRole(r.id) } }));
      const dup = h('button.btn', { type: 'button', text: 'Duplicate' });
      dup.onclick = async () => {
        const c = await guard(() => admin.createRole({ from: r.id, name: uniqueName(`${r.name} copy`, data.roles) }), 'Role duplicated.');
        if (c) renderRoles(c.id);
      };
      actions.appendChild(dup);
      if (!r.builtin) {
        const del = h('button.btn.danger', { type: 'button', text: 'Delete' });
        armConfirm(del, r.users ? `Delete; ${r.users} user${r.users === 1 ? '' : 's'} move${r.users === 1 ? 's' : ''} to Default?` : 'Delete?', async () => {
          if (await guard(() => admin.deleteRole(r.id), 'Role deleted.')) renderRoles();
        });
        actions.appendChild(del);
      }
    }
    body.appendChild(h('tr', {}, h('td', { dataset: { label: 'Role' }, text: r.name }),
      h('td.mono', { dataset: { label: 'Users' }, text: r.fixed ? 'anonymous' : String(r.users) }),
      h('td.mono', { dataset: { label: 'Kind' }, text: r.locked ? 'built in, locked' : r.builtin ? 'built in' : 'custom' }),
      h('td.cell-actions', {}, actions)));
  }
  p.appendChild(h('div.table-wrap', {}, h('table.table', {}, h('thead', {}, h('tr', {}, ...['Role', 'Users', 'Kind', ''].map(th))), body)));
  p.appendChild(h('div', { id: 'role-detail' }));
  if (openId) await openRole(openId);
}

/**
 * The Owner role: everything is allowed with no limits and that cannot
 * change; only the owner's own session timeouts, file-share windows and
 * activity-log retention can (they are server settings, since the owner has
 * no role options).
 */
async function ownerRole(box) {
  await refreshOverview();
  if (!overview) return;
  const s = overview.settings;
  const defs = overview.defaults.settings;
  const fields = [];
  const dur = (key, label) => {
    const c = durationInput(s[key]);
    fields.push([key, label, () => c.read()]);
    return h('div.limit-row', {}, h('span.field-label', { text: label }), c, h('span.mono.muted', { text: `default: ${limitText('dur', defs[key])}` }));
  };
  // A limit that may be off: "keep forever" (null) or "limit to" a value.
  const keep = (key, label, type) => {
    const mode = h('select.input', { 'aria-label': `${label}: mode` },
      h('option', { value: 'null', text: 'keep forever', selected: s[key] === null }),
      h('option', { value: 'value', text: 'limit to', selected: s[key] !== null }));
    const c = type === 'dur' ? durationInput(s[key]) : numberInput(s[key], { label });
    const sync = () => { c.hidden = mode.value !== 'value'; };
    mode.onchange = sync;
    sync();
    fields.push([key, label, () => (mode.value === 'null' ? null : c.read())]);
    return h('div.limit-row', {}, h('span.field-label', { text: label }), mode, c, h('span.mono.muted', { text: `default: ${defs[key] === null ? 'keep forever' : limitText(type, defs[key])}` }));
  };
  const save = h('button.cta', { type: 'button', text: 'Save' });
  box.append(h('h2.section-title', { text: 'Owner role' }),
    h('p.mono.muted', { text: 'Belongs to the owner only. Everything is allowed, with no limits, quotas or password policy, and that cannot be changed. Only these apply to your own account:' }),
    h('div.card.stack', {},
      h('h3.field-label', { text: 'Your sessions' }), dur('session.idleSec', 'Sign out after being idle for'), dur('session.absSec', 'Sign out in any case after'),
      h('h3.field-label', { text: 'Your file shares' }), dur('files.grantSec', 'Recipients may download for this long after opening'), dur('files.pendingSec', 'An unfinished upload is discarded after'),
      h('h3.field-label', { text: 'Your activity log' }),
      h('p.mono.muted', { text: 'Entries about you and entries you made (admin actions, including while logged in as a user) are never removed by the Settings or role limits. Keep them forever (the default), or delete the older ones, and the oldest beyond a number, automatically. Server-wide configuration changes (settings, roles and limits, IP rules, exports and imports, Turnstile) are never deleted automatically. You can always clear entries by hand under Activity log.' }),
      keep('log.ownerMaxAgeSec', 'Keep your entries for', 'dur'), keep('log.ownerMaxEntries', 'Keep at most this many of your entries', 'int'),
      h('div.btn-row', {}, save)));
  save.onclick = async () => {
    const patch = {};
    for (const [k, label, read] of fields) {
      const v = read();
      if (v !== null && !Number.isFinite(v)) return msg(`Enter a value for "${label}".`, true);
      patch[k] = v;
    }
    await guard(() => admin.settings(patch), 'Owner role saved.');
  };
}

/**
 * The Public role: the built-in public (anonymous) account's capabilities,
 * limits, quotas and viewer rules, and how anonymous senders are counted.
 * Cannot be renamed, deleted or given to a user. The on/off switch stays
 * under Public access.
 */
async function publicRole(box, reopen) {
  await refreshOverview();
  if (!overview) return;
  const s = overview.settings;
  const data = await guard(() => admin.publicAccess());
  const detail = await guard(() => admin.user(PUBLIC_ID));
  if (!data || !detail) return;
  box.append(h('h2.section-title', { text: 'Public role' }),
    h('p.mono.muted', { text: `The built-in public account's role: what anonymous senders on the home page may do. It cannot be renamed, deleted or given to a user. Anonymous sharing is ${s['public.enabled'] ? 'on' : 'off'} (Public access).` }));

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
  const save = h('button.cta', { type: 'button', text: 'Save tracking and notice' });
  save.onclick = async () => {
    const mode = radios.map((l) => l.querySelector('input')).find((r) => r.checked)?.value || 'tracker';
    const patch = {
      'public.tracking': mode, 'public.notice': notice.checked, 'public.noticeText': noticeText.value,
      'public.newTrackersPerIp': perIp.read(), 'public.newTrackersWindowSec': perWin.read(), 'public.trackerIdleSec': idle.read(),
    };
    for (const [k, v] of Object.entries(patch)) if (typeof v === 'number' && !Number.isFinite(v)) return msg(`Enter a value for ${k}.`, true);
    if (await guard(() => admin.settings(patch), 'Public role saved.')) reopen();
  };
  box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Counting anonymous senders' }),
    h('fieldset.range', {}, h('legend', { text: 'How anonymous creators are counted' }), ...radios),
    h('label.inline', {}, notice, ' Show a notice on the public composer'),
    h('label.field', {}, h('span.field-label', { text: 'Notice text' }), noticeText),
    h('div.limit-row', {}, h('span.field-label', { text: 'New senders (browser ids) per network' }), perIp, h('span.field-label', { text: 'per' }), perWin),
    h('div.limit-row', {}, h('span.field-label', { text: 'Forget idle browser ids after' }), idle),
    h('p.muted', { text: 'A browser id is stored only when it first creates a share; that is when the per-network limit is spent. Clearing browser storage gives a new id, so tracker mode allows up to (new senders × quota) shares per network per window.' }),
    h('div.btn-row', {}, save)));

  box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Capabilities, limits, viewer, file shares' }),
    limitsEditor({ scope: PUBLIC_ID, channel: 'all', rows: detail.limits.all, effective: detail.effective.all, inherited: overview.defaults.inherited, onSaved: reopen, omit: PUBLIC_OMIT })));
  box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Quotas (counted per anonymous sender, in addition to global quotas)' }), quotasEditor(PUBLIC_ID, detail.quotas)));
  box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Viewer rules (used when "Use this role\'s own viewer rules" is yes)' }), rulesEditor(PUBLIC_ID, detail.viewerRules)));

  const t = data.trackers;
  const body = h('tbody');
  for (const r of t.rows) {
    const act = (action, label, cls = 'btn') => h(`button.${cls}`, { type: 'button', text: label, on: { click: async () => { if (await guard(() => admin.tracker(r.id, action), `Browser id ${action === 'forget' ? 'forgotten' : `${action}ed`}.`)) reopen(); } } });
    body.appendChild(h('tr', {},
      h('td.mono', { dataset: { label: 'Id' }, text: r.id }),
      h('td.mono', { dataset: { label: 'First seen' }, text: formatDate(r.created) }),
      h('td.mono', { dataset: { label: 'Last seen' }, text: formatDate(r.last_seen) }),
      h('td.mono', { dataset: { label: 'Shares' }, text: String(r.uses) }),
      h('td', { dataset: { label: 'Status' } }, r.blocked ? h('span.pill.bad', { text: r.reason === 'conflict' ? 'blocked: conflicting copies' : 'blocked' }) : h('span.pill.ok', { text: 'ok' })),
      h('td.cell-actions', {}, h('div.btn-row', {}, r.blocked ? act('unblock', 'Unblock') : act('block', 'Block', 'btn.danger'), act('forget', 'Forget', 'btn')))));
  }
  box.appendChild(h('div.card.stack', {},
    h('h3.field-label', { text: `Anonymous browser ids (${t.total}, ${t.blocked} blocked)` }),
    h('p.mono.muted', { text: 'Ids are shown as a prefix of their keyed hash; the ids themselves are not stored. Forgetting one also resets its quota usage.' }),
    t.rows.length ? h('div.table-wrap', {}, h('table.table', {}, h('thead', {}, h('tr', {}, ...['Id', 'First seen', 'Last seen', 'Shares', 'Status', ''].map(th))), body)) : h('p.mono.muted', { text: 'None yet.' })));
}

const uniqueName = (base, roles) => {
  const taken = new Set(roles.map((r) => r.name.toLowerCase()));
  let n = base.slice(0, 60);
  for (let i = 2; taken.has(n.toLowerCase()); i++) n = `${base.slice(0, 56)} ${i}`;
  return n;
};

/** The editor for one role: Default (explicit values) or a custom role. */
async function openRole(id, { scroll = true } = {}) {
  const refocus = keepFocus($('#role-detail'), { fallback: () => $('#role-detail h2') });
  const box = clear($('#role-detail'));
  const reopen = () => openRole(id, { scroll: false });
  if (id === 'owner') {
    await ownerRole(box);
  } else if (id === 'public') {
    await publicRole(box, reopen);
  } else if (id === 'default') {
    await refreshOverview();
    box.appendChild(h('h2.section-title', { text: 'Default role', tabindex: '-1' }));
    box.appendChild(h('p.mono.muted', { text: 'Applies to every user without another role, and is what other roles follow for the options they leave on "same as Default". Every option has a value here. The owner is never affected.' }));
    box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Capabilities, limits, passkeys, password policy, sessions' }),
      limitsEditor({ scope: 'global', channel: 'all', rows: overview.limits.all, inherited: overview.defaults.limits, explicit: true, onSaved: () => renderRoles('default') })));
    box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Extra API restrictions (can only narrow, never widen)' }),
      limitsEditor({ scope: 'global', channel: 'api', rows: overview.limits.api, onSaved: () => renderRoles('default') })));
    box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Quotas (each user counted separately)' }), quotasEditor('global', overview.quotas)));
    box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Viewer rules' }), rulesEditor('global', overview.viewerRules)));
  } else {
    const d = await guard(() => admin.role(id));
    if (!d) return;
    const scope = `role:${id}`;
    const rename = h('input.input', { value: d.role.name, maxlength: '64', 'aria-label': 'Role name' });
    const save = h('button.btn', { type: 'button', text: 'Rename' });
    save.onclick = async () => { if (await guard(() => admin.updateRole(id, { name: rename.value.trim() }), 'Role renamed.')) renderRoles(id); };
    box.appendChild(h('h2.section-title', { text: `Role: ${d.role.name}`, tabindex: '-1' }));
    box.appendChild(h('div.card.stack', {}, h('div.toolbar', {}, rename, save),
      h('p.mono.muted', { text: d.users.length ? `Users: ${d.users.map((u) => u.username).join(', ')}` : 'No users have this role yet (assign it under Users).' })));
    box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Capabilities, limits, passkeys, password policy, sessions' }),
      limitsEditor({ scope, channel: 'all', rows: d.limits.all, effective: d.effective.all, inherited: d.inherited, onSaved: reopen })));
    box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Extra API restrictions (can only narrow, never widen)' }),
      limitsEditor({ scope, channel: 'api', rows: d.limits.api, effective: d.effective.api, onSaved: reopen })));
    const own = [h('input', { type: 'radio', name: `own-quotas-${id}`, value: 'default', checked: !d.role.ownQuotas }), h('input', { type: 'radio', name: `own-quotas-${id}`, value: 'own', checked: d.role.ownQuotas })];
    const quotaBox = h('div', { hidden: !d.role.ownQuotas }, quotasEditor(scope, d.quotas));
    for (const r of own) {
      r.onchange = async () => {
        if (!r.checked) return;
        const ownQuotas = r.value === 'own';
        quotaBox.hidden = !ownQuotas;
        await guard(() => admin.updateRole(id, { ownQuotas }), ownQuotas ? 'This role now uses its own quota list (save it below).' : 'This role now uses Default\'s quotas.');
      };
    }
    box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Quotas' }),
      h('fieldset.range', {}, h('legend', { text: 'Which quotas apply' }),
        h('label.radio-opt', {}, own[0], h('span', { text: 'Same as Default' })), h('label.radio-opt', {}, own[1], h('span', { text: 'This role\'s own list (instead of Default\'s)' }))),
      quotaBox));
    box.appendChild(h('div.card.stack', {}, h('h3.field-label', { text: 'Viewer rules (used when "Use this role\'s own viewer rules" is yes)' }), rulesEditor(scope, d.viewerRules)));
  }
  if (scroll) {
    box.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth', block: 'start' });
    box.querySelector('h2')?.focus({ preventScroll: true }); // just opened: start reading at its heading
  } else refocus();
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
  const dur = (key, label, ctx = '') => { const c = durationInput(s[key], { label: ctx ? `${ctx}: ${label}` : label }); fields.push([key, () => c.read()]); return h('div.limit-row', {}, h('span.field-label', { text: label }), c, dflt(limitText('dur', defs[key]))); };
  const int = (key, label, ctx = '') => { const c = numberInput(s[key], { label: ctx ? `${ctx}: ${label}` : label }); fields.push([key, () => c.read()]); return h('div.limit-row', {}, h('span.field-label', { text: label }), c, dflt(String(defs[key]))); };
  const scopeRule = (scope, label) => h('div.card.stack', {}, h('h3.field-label', { text: label }),
    int(`guard.${scope}.max`, 'Failures allowed', label.split(':')[0]), dur(`guard.${scope}.windowSec`, 'Within', label.split(':')[0]), dur(`guard.${scope}.blockSec`, 'Then block the IP for', label.split(':')[0]));
  p.appendChild(h('p.mono.muted', { text: 'Server-wide settings only. What accounts may do (sessions, file shares, the viewer, passkeys, password policy, quotas) is set per role under Roles; the owner\'s own session timeouts and file-share windows are on the Owner role, and anonymous sharing on the Public role.' }));
  p.appendChild(h('div.stack', {}, h('h2.section-title', { text: 'Brute-force protection (per IP)' }),
    h('p.mono.muted', { text: 'Counts failures per network address (IPv6 per the tracking prefix below) and blocks that address for a while, whoever it is and whichever account it tries: it stops one source from guessing. Account lockout (below) is the other half: it counts wrong passwords per account, from any address, and locks only that account: it stops many sources guessing one account.' }),
    scopeRule('login', 'Login'), scopeRule('setup', 'Setup'),
    scopeRule('invalid', 'Invalid fetches: links that never existed, a wrong #key or password, bad tokens. Not counted: opening a share that expired, was used up, revoked or deleted with its correct link (#key); a wrong #key for such a share still counts'),
    h('div.card.stack', {}, int('guard.v6Prefix', 'IPv6 tracking prefix (/n)'))));
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'Activity log' }),
    h('p.mono.muted', { text: 'Older entries, and the oldest beyond the size limit, are deleted automatically. A role\'s log limits (Roles) can keep less about its users. Entries about the owner and entries the owner made (admin actions, impersonation) follow the owner\'s own limits instead (Roles → Owner; kept forever by default). Server-wide configuration changes (settings, roles and limits, IP rules, exports and imports, Turnstile) are never deleted automatically.' }),
    dur('log.maxAgeSec', 'Keep entries for at most'), int('log.maxEntries', 'Keep at most this many entries')));
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'Account lockout (owner excluded)' }),
    h('p.mono.muted', { text: "Counts wrong passwords per account, from any network, and locks only that account. The owner is never locked out, but per-IP protection still guards the owner's login. A password change is never blocked by a lockout." }),
    int('lockout.max', 'Failed logins allowed'), dur('lockout.windowSec', 'Within', 'Account lockout'), dur('lockout.lockSec', 'Then lock the account for')));
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
  // Its own section, saved with its own button.
  p.appendChild(statementEditor(s, defs));
}

/**
 * Settings → Accessibility: the whole public statement as plain-text fields
 * (public/js/a11ystatement.js), in the main language and optionally a second
 * one, with the contact and coordinator both languages show. The server
 * validates and normalises every field; the form shows what it stored.
 */
function statementEditor(s, defs) {
  const HELP = 'st-edit-help';
  const LANG_RE = /^[a-z]{2,3}(-[a-z0-9]{1,8}){0,4}$/i;
  const field = (label, control) => h('label.field', {}, h('span.field-label', { text: label }), control);
  const text = (key, { rows = '2', max = 500, placeholder } = {}) => {
    const el = h('textarea.input', { rows, maxlength: String(max), placeholder, dataset: { setting: key } });
    el.value = s[key] ?? '';
    return el;
  };
  const contact = text('a11y.contact', { placeholder: 'e.g. accessibility@example.com or +972-3-000-0000' });
  const coord = text('a11y.coordinator', { placeholder: 'Name, phone, email: only if you must appoint one' });
  const reviewed = h('input.input', { type: 'date', value: s['a11y.reviewed'] || '', dataset: { setting: 'a11y.reviewed' } });

  // One language block: its code, direction and every text field.
  const block = (prefix, legend, alt) => {
    const lang = h('input.input', { type: 'text', maxlength: '35', autocomplete: 'off', spellcheck: 'false', placeholder: alt ? 'e.g. he' : 'en', dataset: { setting: `${prefix}lang` } });
    const dir = h('select.input', { dataset: { setting: `${prefix}dir` } }, h('option', { value: 'ltr', text: 'Left to right' }), h('option', { value: 'rtl', text: 'Right to left' }));
    const ctl = {};
    const rows = [];
    for (const [k, f] of Object.entries(STATEMENT_FIELDS)) {
      const key = `${prefix}${k}`;
      const el = f.oneLine
        ? h('input.input', { type: 'text', maxlength: String(f.max), dataset: { setting: key }, placeholder: alt ? s[`${MAIN}${k}`] : undefined })
        : h('textarea.input', { rows: f.items ? '6' : '3', maxlength: String(f.max), 'aria-describedby': HELP, dataset: { setting: key } });
      ctl[k] = el;
      rows.push(field(`${f.label}${alt && !f.oneLine ? ' (optional)' : alt && k !== 'title' ? ' (empty: the main language’s)' : ''}`, el));
    }
    // Typing in the statement's language: its lang and dir on every field.
    const mark = () => {
      const code = lang.value.trim();
      for (const el of Object.values(ctl)) {
        if (LANG_RE.test(code)) el.setAttribute('lang', code); else el.removeAttribute('lang');
        el.setAttribute('dir', dir.value);
      }
    };
    lang.addEventListener('change', () => { if (LANG_RE.test(lang.value.trim())) dir.value = guessDir(lang.value.trim()); mark(); });
    dir.addEventListener('change', mark);
    const fill = (v) => {
      lang.value = v[`${prefix}lang`] ?? '';
      dir.value = v[`${prefix}dir`] || 'ltr';
      for (const k of Object.keys(ctl)) ctl[k].value = v[`${prefix}${k}`] ?? '';
      mark();
    };
    fill(s);
    const read = () => ({ [`${prefix}lang`]: lang.value.trim(), [`${prefix}dir`]: dir.value, ...Object.fromEntries(Object.entries(ctl).map(([k, el]) => [`${prefix}${k}`, el.value])) });
    const box = h('fieldset.st-lang', {}, h('legend', { text: legend }),
      h('div.st-row', {}, field('Language code', lang), field('Direction', dir)), ...rows);
    return { box, fill, read, lang };
  };

  const main = block(MAIN, 'Main language', false);
  const alt = block(ALT, 'Second language', true);
  const altOn = h('input', { type: 'checkbox', checked: !!s['a11y.alt.lang'], 'aria-controls': 'st-alt-fields' });
  alt.box.id = 'st-alt-fields';
  alt.box.hidden = !altOn.checked;
  altOn.onchange = () => { alt.box.hidden = !altOn.checked; if (altOn.checked) alt.lang.focus(); };

  let restored = false; // set by "Restore the default statement" until the next save
  const saveBtn = h('button.cta', { type: 'button', text: 'Save accessibility statement' });
  saveBtn.onclick = async () => {
    // With the second language off, its text is kept for later, unless the
    // default was restored (then it is cleared too).
    const patch = { 'a11y.contact': contact.value, 'a11y.coordinator': coord.value, 'a11y.reviewed': reviewed.value, ...main.read(), ...(altOn.checked || restored ? alt.read() : { 'a11y.alt.lang': '' }) };
    if (altOn.checked && !patch['a11y.alt.lang']) { alt.lang.focus(); return msg('Enter the second language’s code (for example he), or turn the second language off.', true); }
    const r = await guard(() => admin.settings(patch), 'Accessibility statement saved.');
    if (!r) return;
    // Show what the server stored (trimmed, blank lines removed).
    contact.value = r.settings['a11y.contact']; coord.value = r.settings['a11y.coordinator']; reviewed.value = r.settings['a11y.reviewed'];
    main.fill(r.settings);
    if (r.settings['a11y.alt.lang'] || restored) alt.fill(r.settings);
    restored = false;
  };
  // The default statement (English only, no second language) back in the
  // form; the contact and coordinator are this server's own and stay.
  const resetBtn = h('button.btn', { type: 'button', text: 'Restore the default statement' });
  resetBtn.onclick = () => {
    main.fill(defs); alt.fill(defs); reviewed.value = defs['a11y.reviewed'];
    altOn.checked = false; alt.box.hidden = true;
    restored = true;
    msg('The default statement (English only) is back in the form. Save to publish it.');
  };

  return h('div.card.stack.st-editor', {}, h('h2.section-title', { text: 'Accessibility' }),
    h('p.mono.muted', {}, 'The public ', h('a', { href: '/accessibility/', text: 'accessibility statement' }), '. A way to report a problem is required; list a coordinator only if the law requires you to appoint one (in Israel, from 25 employees).'),
    h('p.mono.muted', { id: HELP, text: 'Plain text only (no HTML or formatting). In paragraphs, each line is a paragraph; in lists, each line is one item. Empty sections are left out.' }),
    field('How to report a problem (both languages)', contact),
    field('Accessibility coordinator (optional; both languages)', coord),
    field('Last technical review (date; empty for none)', reviewed),
    main.box,
    h('label.inline', {}, altOn, ' Also show the statement in a second language'),
    alt.box,
    h('div.btn-row', {}, saveBtn, resetBtn,
      h('a.btn', { href: '/accessibility/', target: '_blank', rel: 'noopener', text: 'Preview (opens in a new tab)' })),
    h('p.mono.muted', { text: 'The preview shows the statement as last saved.' }));
}

// ── public access ────────────────────────────────────────────────────────────
const PUBLIC_ID = 'public-user-0000';
// Not for the public account (no API keys, receipts page, password, passkeys
// or log of its own); the server refuses them too (PUBLIC_NA_LIMITS).
const PUBLIC_OMIT = ['apiEnabled', 'apiMaxKeys', 'receiptIp', 'receiptLocation', 'receiptBrowser', 'receiptOs', 'receiptLanguages',
  'logMaxAgeSec', 'logMaxEntries', 'pwMinLength', 'pwUpper', 'pwLower', 'pwDigit', 'pwSymbol', 'passkeys', 'passkeysMax', 'sessionIdleSec', 'sessionAbsSec'];
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
  const on = h('input', { type: 'checkbox', checked: overview.settings['public.enabled'] });
  const save = h('button.cta', { type: 'button', text: 'Save' });
  save.onclick = () => guard(() => admin.settings({ 'public.enabled': on.checked }), on.checked ? 'Anonymous sharing is on.' : 'Anonymous sharing is off.');
  const toRole = h('button.btn', { type: 'button', text: 'Edit the Public role', on: { click: () => { selectTab('roles'); renderRoles('public'); } } });
  p.appendChild(h('div.card.stack', {},
    h('h2.section-title', { text: 'Public (anonymous) sharing' }),
    h('p.subtitle', { text: 'When on, the home page offers the composer to anyone, as the built-in public account: no password, no dashboard, no API keys. What anonymous senders may do, how they are counted, the notice they see and their browser ids are set on the Public role (Roles).' }),
    h('label.inline', {}, on, ' Allow anonymous sharing'),
    h('div.btn-row', {}, save, toRole)));
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
  const ttl = durationInput(null, { allowNull: true, label: 'Rule duration' });
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
    h('div.table-wrap', {}, h('table.table', {}, h('thead', {}, h('tr', {}, ...['Range', 'Action', 'Expires', 'Note', ''].map(th))), rbody))));

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
    h('div.table-wrap', {}, h('table.table', {}, h('thead', {}, h('tr', {}, ...['IP / prefix', 'Scope', 'Since', 'Until', ''].map(th))), bbody))));
  p.appendChild(h('div.card.stack', {}, h('h2.section-title', { text: 'Being tracked' }),
    h('div.table-wrap', {}, h('table.table', {}, h('thead', {}, h('tr', {}, ...['IP / prefix', 'Scope', 'Failures', 'Window ends', ''].map(th))), tbody)),
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
    h('p.mono.muted', { text: 'Deletes entries for good, without leaving a record that they existed.' }),
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
