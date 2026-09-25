// settings.js — admin-configurable global settings and per-user capability
// limits: the schema (types, bounds, defaults) and pure resolution helpers.
// Storage lives in the Directory DO; everything written is validated here.

import { MAX_TTL, MAX_VIEWS } from '../../public/js/format.js';
import { HARD_MAX_SHARE_BYTES, RENDERERS } from '../../public/js/files.js';
import { FILE_TYPE_MODES, MAX_FOLDER_DEPTH, normalizeRules } from '../../public/js/filepolicy.js';
import { DEFAULT_URL_RULES, normalizeUrlRules } from '../../public/js/sharetypes.js';

const MIN = 60;
const HOUR = 3600;
const DAY = 86400;
const MiB = 1024 * 1024;

export const PUBLIC_TRACKING = ['tracker', 'ip', 'both-permissive', 'both-restrictive'];
export const DEFAULT_PUBLIC_NOTICE = 'Anonymous sharing is limited. To enforce the limits, this site keeps a random identifier in your browser (a cookie and similar storage) and/or uses your network address. It is used only for these limits and is not shared with anyone.';

// ── global settings ──────────────────────────────────────────────────────────
export const SETTINGS = {
  'session.idleSec':     { type: 'int', min: 5 * MIN, max: 90 * DAY, def: 12 * HOUR },
  'session.absSec':      { type: 'int', min: 5 * MIN, max: 365 * DAY, def: 7 * DAY },
  'files.maxShareBytes': { type: 'int', min: 1 * MiB, max: HARD_MAX_SHARE_BYTES, def: 100 * MiB },
  'files.grantSec':      { type: 'int', min: 5 * MIN, max: 7 * DAY, def: HOUR },
  'files.pendingSec':    { type: 'int', min: 5 * MIN, max: DAY, def: HOUR },
  'viewer.enabled':      { type: 'bool', def: false },
  'viewer.maxBytes':     { type: 'int', min: 64 * 1024, max: 500 * MiB, def: 50 * MiB },
  'guard.login.max':     { type: 'int', min: 1, max: 100000, def: 10 },
  'guard.login.windowSec': { type: 'int', min: 1, max: 30 * DAY, def: 10 * MIN },
  'guard.login.blockSec':  { type: 'int', min: 1, max: 365 * DAY, def: 15 * MIN },
  'guard.setup.max':     { type: 'int', min: 1, max: 100000, def: 5 },
  'guard.setup.windowSec': { type: 'int', min: 1, max: 30 * DAY, def: HOUR },
  'guard.setup.blockSec':  { type: 'int', min: 1, max: 365 * DAY, def: HOUR },
  'guard.invalid.max':   { type: 'int', min: 1, max: 100000, def: 60 },
  'guard.invalid.windowSec': { type: 'int', min: 1, max: 30 * DAY, def: 10 * MIN },
  'guard.invalid.blockSec':  { type: 'int', min: 1, max: 365 * DAY, def: 30 * MIN },
  'guard.v6Prefix':      { type: 'int', min: 32, max: 128, def: 64 },
  'lockout.max':         { type: 'int', min: 1, max: 100000, def: 10 },
  'lockout.windowSec':   { type: 'int', min: 1, max: 30 * DAY, def: 10 * MIN },
  'lockout.lockSec':     { type: 'int', min: 1, max: 365 * DAY, def: 15 * MIN },
  // Public (anonymous) share creation — off by default. See SECURITY.md §6
  // "Public access": tracking anonymous creators is a regulated activity.
  // Activity log retention (everything except entries about the owner).
  'log.maxAgeSec':       { type: 'int', min: DAY, max: 3650 * DAY, def: 365 * DAY },
  'log.maxEntries':      { type: 'int', min: 1000, max: 5000000, def: 500000 },
  // The accessibility statement (/accessibility/): how to report a problem,
  // and the coordinator (only where the law requires one). Plain text.
  'a11y.contact':        { type: 'text', max: 500, def: '' },
  'a11y.coordinator':    { type: 'text', max: 500, def: '' },
  'public.enabled':      { type: 'bool', def: false },
  // How anonymous creators are counted against the public quotas:
  //   tracker          — a random ID the browser keeps (cookie, ETag cache,
  //                      localStorage, IndexedDB), self-healing;
  //   ip               — the network address (IPv6 by guard.v6Prefix), salted
  //                      and hashed; nothing is stored in the browser;
  //   both-permissive  — both are counted; refused only when BOTH are over;
  //   both-restrictive — both are counted; refused when EITHER is over.
  'public.tracking':     { type: 'enum', values: PUBLIC_TRACKING, def: 'tracker' },
  'public.notice':       { type: 'bool', def: true },
  'public.noticeText':   { type: 'text', max: 1000, def: DEFAULT_PUBLIC_NOTICE },
  // New browser ids that may start creating shares, per network per window
  // (spent on an id's first creation, never on page visits).
  'public.newTrackersPerIp': { type: 'int', min: 1, max: 10000, def: 5 },
  'public.newTrackersWindowSec': { type: 'int', min: MIN, max: 30 * DAY, def: DAY },
  'public.trackerIdleSec': { type: 'int', min: DAY, max: 730 * DAY, def: 90 * DAY },
};

export const GUARD_SCOPES = ['login', 'setup', 'invalid'];

/** Validate one setting value; returns the coerced value or throws Error(message). */
export function checkSetting(key, value) {
  const s = Object.prototype.hasOwnProperty.call(SETTINGS, key) ? SETTINGS[key] : null;
  if (!s) throw new Error(`unknown setting "${key}"`);
  if (s.type === 'bool') {
    if (typeof value !== 'boolean') throw new Error(`${key} must be true or false`);
    return value;
  }
  if (s.type === 'enum') {
    if (!s.values.includes(value)) throw new Error(`${key} must be one of ${s.values.join(', ')}`);
    return value;
  }
  if (s.type === 'text') {
    if (typeof value !== 'string') throw new Error(`${key} must be text`);
    // eslint-disable-next-line no-control-regex
    const v = value.replace(/[\u0000-\u0009\u000b-\u001f\u007f]/g, ' ').trim();
    if (v.length > s.max) throw new Error(`${key} is at most ${s.max} characters`);
    return v;
  }
  if (!Number.isSafeInteger(value) || value < s.min || value > s.max) {
    throw new Error(`${key} must be an integer between ${s.min} and ${s.max}`);
  }
  return value;
}

export function settingsWithDefaults(rows) {
  const out = {};
  for (const [k, s] of Object.entries(SETTINGS)) out[k] = Object.prototype.hasOwnProperty.call(rows, k) ? rows[k] : s.def;
  return out;
}

// ── per-user capability limits ───────────────────────────────────────────────
// Each key resolves: user override → global default row → code default.
// `null` on a numeric key means "no limit" (still bounded by hard ceilings).
export const PASSKEY_MODES = ['any', 'second', 'off'];

export const LIMITS = {
  text:                { type: 'bool', def: true },
  files:               { type: 'bool', def: true },
  // Structured share types and recipient "delete now": off unless the admin allows them.
  url:                 { type: 'bool', def: false },
  secret:              { type: 'bool', def: false },
  openerDelete:        { type: 'bool', def: false },
  maxViews:            { type: 'int', min: 1, max: MAX_VIEWS, nullable: true, def: null },
  allowUnlimitedViews: { type: 'bool', def: true },
  maxExpireSec:        { type: 'int', min: 60, max: MAX_TTL, nullable: true, def: null },
  maxFilesPerShare:    { type: 'int', min: 1, max: 10000, nullable: true, def: null },
  maxShareBytes:       { type: 'int', min: 1, max: HARD_MAX_SHARE_BYTES, nullable: true, def: null },
  maxFileBytes:        { type: 'int', min: 1, max: HARD_MAX_SHARE_BYTES, nullable: true, def: null },
  viewer:              { type: 'bool', def: false },
  viewerCustomRules:   { type: 'bool', def: false },
  apiEnabled:          { type: 'bool', def: false },
  // null = no limit (still bounded by MAX_API_KEYS).
  apiMaxKeys:          { type: 'int', min: 0, max: 100, nullable: true, def: 5 },
  // File policy (public/js/filepolicy.js): allow/block list of types, folder depth.
  fileTypeMode:        { type: 'enum', values: FILE_TYPE_MODES, def: 'any' },
  fileTypeRules:       { type: 'rules', def: [] },
  maxFolderDepth:      { type: 'int', min: 0, max: MAX_FOLDER_DEPTH, nullable: true, def: null },
  // Which links a URL share may carry (public/js/sharetypes.js): scheme:… and
  // re:… rules, checked by the sender's browser / CLI (the server cannot see
  // the URL). The owner may share any safe link.
  urlRules:            { type: 'urlrules', def: [...DEFAULT_URL_RULES], owner: ['scheme:*'] },
  // Read receipts: senders always see when each open happened; these let the
  // account also see what the opener's request revealed (the admin always
  // sees everything).
  receiptIp:           { type: 'bool', def: false },
  receiptLocation:     { type: 'bool', def: false },
  receiptBrowser:      { type: 'bool', def: false },
  receiptOs:           { type: 'bool', def: false },
  receiptLanguages:    { type: 'bool', def: false },
  // Activity-log retention for entries about this account (null: only the
  // global log.* settings apply).
  logMaxAgeSec:        { type: 'int', min: DAY, max: 3650 * DAY, nullable: true, def: null },
  logMaxEntries:       { type: 'int', min: 10, max: 5000000, nullable: true, def: null },
  // Password policy (public/js/pwauth.js). Enforced by the browser only: the
  // server receives an Argon2id proof, never the password. `owner` is what
  // applies to the owner (global settings never do): the built-in minimum.
  pwMinLength:         { type: 'int', min: 12, max: 128, nullable: false, def: 12, owner: 12 },
  pwUpper:             { type: 'bool', def: false, owner: false },
  pwLower:             { type: 'bool', def: false, owner: false },
  pwDigit:             { type: 'bool', def: false, owner: false },
  pwSymbol:            { type: 'bool', def: false, owner: false },
  // Passkeys (WebAuthn): "any" — sign in with a passkey alone, or use it as a
  // second factor after the password (the user chooses); "second" — only as a
  // second factor (every password login then needs one); "off" — none.
  // Recovery codes stand in for a passkey wherever one is accepted.
  passkeys:            { type: 'enum', values: PASSKEY_MODES, def: 'any', owner: 'any' },
};

/** The password-policy keys of the limits (see public/js/pwauth.js). */
export const PASSWORD_POLICY_KEYS = ['pwMinLength', 'pwUpper', 'pwLower', 'pwDigit', 'pwSymbol'];

/** Hard ceiling on API keys per account, whatever the limit says. */
export const MAX_API_KEYS = 1000;

// Keys the API channel may restrict further (never widen).
export const API_LIMIT_KEYS = ['text', 'files', 'url', 'secret', 'openerDelete', 'maxViews', 'allowUnlimitedViews', 'maxExpireSec',
  'maxFilesPerShare', 'maxShareBytes', 'maxFileBytes', 'maxFolderDepth'];

export function checkLimit(key, value, channel = 'all') {
  const s = Object.prototype.hasOwnProperty.call(LIMITS, key) ? LIMITS[key] : null;
  if (!s) throw new Error(`unknown limit "${key}"`);
  if (channel === 'api' && !API_LIMIT_KEYS.includes(key)) throw new Error(`"${key}" cannot be set for the API channel`);
  if (s.type === 'enum') {
    if (!s.values.includes(value)) throw new Error(`${key} must be one of ${s.values.join(', ')}`);
    return value;
  }
  if (s.type === 'rules') return normalizeRules(value);
  if (s.type === 'urlrules') {
    const rules = normalizeUrlRules(value);
    if (!rules.length) throw new Error('urlRules needs at least one rule (turn link shares off instead)');
    return rules;
  }
  if (value === null) {
    if (s.type === 'bool' || !s.nullable) throw new Error(`${key} cannot be empty`);
    return null;
  }
  if (s.type === 'bool') {
    if (typeof value !== 'boolean') throw new Error(`${key} must be true or false`);
    return value;
  }
  if (!Number.isSafeInteger(value) || value < s.min || value > s.max) {
    throw new Error(`${key} must be an integer between ${s.min} and ${s.max}`);
  }
  return value;
}

/** Resolve the all-channel limits from row maps { key: value }. */
export function resolveLimits(globalRows, userRows) {
  const out = {};
  for (const [k, s] of Object.entries(LIMITS)) {
    if (Object.prototype.hasOwnProperty.call(userRows, k)) out[k] = userRows[k];
    else if (Object.prototype.hasOwnProperty.call(globalRows, k)) out[k] = globalRows[k];
    else out[k] = s.def;
  }
  // The file-type mode and its rule list mean something only together: take
  // both from the most specific level that sets either, so a per-user
  // "allow" never inherits the global *block* list (or vice versa).
  const has = (r, k) => Object.prototype.hasOwnProperty.call(r, k);
  const src = has(userRows, 'fileTypeMode') || has(userRows, 'fileTypeRules') ? userRows
    : has(globalRows, 'fileTypeMode') || has(globalRows, 'fileTypeRules') ? globalRows : {};
  out.fileTypeMode = has(src, 'fileTypeMode') ? src.fileTypeMode : LIMITS.fileTypeMode.def;
  out.fileTypeRules = has(src, 'fileTypeRules') ? src.fileTypeRules : LIMITS.fileTypeRules.def;
  return out;
}

const minNullable = (a, b) => (a === null ? b : b === null ? a : Math.min(a, b));

/** API-channel limits: the all-channel limits, further restricted (never widened). */
export function restrictForApi(all, apiGlobalRows, apiUserRows) {
  const out = { ...all };
  for (const k of API_LIMIT_KEYS) {
    const has = (r) => Object.prototype.hasOwnProperty.call(r, k);
    const v = has(apiUserRows) ? apiUserRows[k] : has(apiGlobalRows) ? apiGlobalRows[k] : undefined;
    if (v === undefined) continue;
    out[k] = LIMITS[k].type === 'bool' ? all[k] && v : minNullable(all[k], v);
  }
  return out;
}

export const UNLIMITED = Object.freeze(Object.fromEntries(Object.entries(LIMITS).map(([k, s]) => [k,
  'owner' in s ? s.owner : s.type === 'bool' ? true : s.type === 'enum' ? 'any' : s.type === 'rules' ? [] : (s.nullable ? null : 100)])));

// ── quotas ───────────────────────────────────────────────────────────────────
export const QUOTA_UNITS = { s: 1, m: MIN, h: HOUR, d: DAY, mo: null, y: null };
export const QUOTA_KINDS = ['all', 'text', 'files'];

export function checkQuota(q) {
  if (!q || typeof q !== 'object') throw new Error('invalid quota');
  if (!['all', 'api'].includes(q.channel)) throw new Error('quota channel must be all or api');
  if (!QUOTA_KINDS.includes(q.kind)) throw new Error('quota kind must be all, text or files');
  if (!Object.prototype.hasOwnProperty.call(QUOTA_UNITS, q.unit)) throw new Error('quota unit must be s, m, h, d, mo or y');
  if (!Number.isSafeInteger(q.n) || q.n < 1 || q.n > 100000) throw new Error('quota period must be 1–100000');
  if (!Number.isSafeInteger(q.max) || q.max < 0 || q.max > 10000000) throw new Error('quota max must be 0–10000000');
  return { channel: q.channel, kind: q.kind, n: q.n, unit: q.unit, max: q.max };
}

/** Fixed-window bucket index for a quota at `nowSec` (UTC calendar for mo / y). */
export function quotaBucket(q, nowSec) {
  if (q.unit === 'mo' || q.unit === 'y') {
    const d = new Date(nowSec * 1000);
    const idx = q.unit === 'mo' ? d.getUTCFullYear() * 12 + d.getUTCMonth() : d.getUTCFullYear();
    return Math.floor(idx / q.n);
  }
  return Math.floor(nowSec / (q.n * QUOTA_UNITS[q.unit]));
}

// ── viewer rules ─────────────────────────────────────────────────────────────
export function checkViewerRule(r) {
  if (!r || typeof r !== 'object') throw new Error('invalid viewer rule');
  if (!['mime', 'ext', 'any'].includes(r.match)) throw new Error('rule match must be mime, ext or any');
  if (!RENDERERS.includes(r.renderer)) throw new Error(`renderer must be one of ${RENDERERS.join(', ')}`);
  const value = typeof r.value === 'string' ? r.value.trim().toLowerCase() : '';
  if (r.match === 'mime' && !/^[a-z0-9.+-]+\/([a-z0-9.+-]+|\*)$/.test(value)) throw new Error('mime rule must look like type/subtype or type/*');
  if (r.match === 'ext' && !/^[a-z0-9]{1,16}$/.test(value)) throw new Error('ext rule must be letters/digits, no dot');
  if (r.match === 'any' && value !== '') throw new Error('an "any" rule takes no value');
  return { match: r.match, value, renderer: r.renderer };
}

// Default global rules seeded on first run (admin can edit freely).
export const DEFAULT_VIEWER_RULES = [
  { match: 'mime', value: 'text/plain', renderer: 'text' },
  { match: 'mime', value: 'text/markdown', renderer: 'markdown' },
  { match: 'ext', value: 'md', renderer: 'markdown' },
  { match: 'ext', value: 'txt', renderer: 'text' },
  { match: 'ext', value: 'log', renderer: 'text' },
  { match: 'ext', value: 'csv', renderer: 'text' },
  { match: 'ext', value: 'json', renderer: 'code' },
  { match: 'mime', value: 'image/png', renderer: 'image' },
  { match: 'mime', value: 'image/jpeg', renderer: 'image' },
  { match: 'mime', value: 'image/webp', renderer: 'image' },
  { match: 'mime', value: 'image/bmp', renderer: 'image' },
  { match: 'mime', value: 'image/gif', renderer: 'image' },
  { match: 'mime', value: 'application/pdf', renderer: 'pdf' },
];
