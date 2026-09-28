// settings.js — admin-configurable global settings and per-user capability
// limits: the schema (types, bounds, defaults) and pure resolution helpers.
// Storage lives in the Directory DO; everything written is validated here.

import { MAX_TTL, MAX_VIEWS } from '../../public/js/format.js';
import { HARD_MAX_SHARE_BYTES, RENDERERS } from '../../public/js/files.js';
import { FILE_TYPE_MODES, MAX_FOLDER_DEPTH, normalizeRules } from '../../public/js/filepolicy.js';
import { DEFAULT_URL_RULES, normalizeUrlRules } from '../../public/js/sharetypes.js';
import { A11Y_SETTINGS, checkStatement } from '../../public/js/a11ystatement.js';

const MIN = 60;
const HOUR = 3600;
const DAY = 86400;
const MiB = 1024 * 1024;
const GiB = 1024 * MiB;
/** Hard ceiling on a Drive's capacity (and on any file in it), whatever the role says. */
export const HARD_MAX_DRIVE_BYTES = 100 * GiB;

export const PUBLIC_TRACKING = ['tracker', 'ip', 'both-permissive', 'both-restrictive'];
export const DEFAULT_PUBLIC_NOTICE = 'Anonymous sharing is limited. To enforce the limits, this site keeps a random identifier in your browser (a cookie and similar storage) and/or uses your network address. It is used only for these limits and is not shared with anyone.';

// ── global settings ──────────────────────────────────────────────────────────
export const SETTINGS = {
  'session.idleSec':     { type: 'int', min: 5 * MIN, max: 90 * DAY, def: 12 * HOUR },
  'session.absSec':      { type: 'int', min: 5 * MIN, max: 365 * DAY, def: 7 * DAY },
  // The owner's own session timeouts and file-share windows (edited on the
  // Owner role); every other account takes its role's values, which start
  // from these.
  'files.grantSec':      { type: 'int', min: 5 * MIN, max: 7 * DAY, def: HOUR },
  'files.pendingSec':    { type: 'int', min: 5 * MIN, max: DAY, def: HOUR },
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
  // CSRF tokens (src/lib/csrf.js): cookie-authenticated changes must echo the
  // session's token in X-Secbin-CSRF. Off, every other CSRF guard still applies
  // (SameSite=Strict cookies, the Sec-Fetch-Site check, JSON or X-Secbin-Intent).
  csrfTokens:            { type: 'bool', def: true },
  // Public (anonymous) share creation — off by default. See SECURITY.md §6
  // "Public access": tracking anonymous creators is a regulated activity.
  // Activity log retention (everything except the owner's entries and
  // server-wide configuration changes).
  'log.maxAgeSec':       { type: 'int', min: DAY, max: 3650 * DAY, def: 365 * DAY },
  'log.maxEntries':      { type: 'int', min: 1000, max: 5000000, def: 500000 },
  // The owner's own log retention (edited on the Owner role): entries about
  // the owner and entries the owner made (admin actions, impersonation).
  // null = keep them until cleared by hand. Server-wide configuration changes
  // are never pruned automatically, whatever these say.
  'log.ownerMaxAgeSec':  { type: 'int', min: DAY, max: 3650 * DAY, nullable: true, def: null },
  'log.ownerMaxEntries': { type: 'int', min: 1000, max: 5000000, nullable: true, def: null },
  // The accessibility statement (/accessibility/), all plain text: the main
  // language (English by default) and an optional second one, with the
  // contact for reporting problems and the coordinator. See
  // public/js/a11ystatement.js for the fields and their limits.
  ...A11Y_SETTINGS,
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
    let v = value.replace(/\r\n?/g, '\n').replace(/[\u0000-\u0009\u000b-\u001f\u007f]/g, ' ').trim();
    if (s.oneLine) v = v.replace(/\s*\n\s*/g, ' ');
    // Paragraphs and list items: one per line, blank lines dropped.
    if (s.paragraphs || s.items) v = v.split('\n').map((x) => x.trim()).filter(Boolean).join('\n');
    if (s.items) {
      const items = v ? v.split('\n') : [];
      if (items.length > s.items) throw new Error(`${key} has at most ${s.items} items (one per line)`);
      if (items.some((x) => x.length > s.itemMax)) throw new Error(`each item of ${key} is at most ${s.itemMax} characters`);
    }
    if (v.length > s.max) throw new Error(`${key} is at most ${s.max} characters`);
    if (s.required && !v) throw new Error(`${key} cannot be empty`);
    return v;
  }
  if (s.type === 'lang') {
    // A BCP 47 language tag (en, he, ar-EG…), stored canonical; '' only where optional.
    if (typeof value !== 'string') throw new Error(`${key} must be a language code`);
    const v = value.trim();
    if (!v && s.optional) return '';
    let tag = null;
    try { if (/^[a-z]{2,3}(-[a-z0-9]{1,8}){0,4}$/i.test(v)) tag = Intl.getCanonicalLocales(v)[0]; } catch { /* invalid */ }
    if (!tag) throw new Error(`${key} must be a language code such as en or he`);
    return tag;
  }
  if (s.type === 'date') {
    // A calendar date (YYYY-MM-DD) or '' (none).
    if (typeof value !== 'string') throw new Error(`${key} must be a date`);
    const v = value.trim();
    if (!v) return '';
    const d = /^\d{4}-\d{2}-\d{2}$/.test(v) ? new Date(`${v}T00:00:00Z`) : null;
    if (!d || Number.isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== v) throw new Error(`${key} must be a date (YYYY-MM-DD)`);
    return v;
  }
  if (value === null) {
    if (!s.nullable) throw new Error(`${key} cannot be empty`);
    return null;
  }
  if (!Number.isSafeInteger(value) || value < s.min || value > s.max) {
    throw new Error(`${key} must be an integer between ${s.min} and ${s.max}`);
  }
  return value;
}

/**
 * Rules across settings, on the merged values (after a patch or an import):
 * returns an error message, or null when they fit together.
 */
export function crossCheckSettings(merged) {
  if (merged['session.idleSec'] > merged['session.absSec']) return 'The idle timeout cannot exceed the absolute timeout.';
  return checkStatement(merged);
}

/** A setting's value as the activity log shows it: long text by its length only. */
export function logValue(v) {
  return typeof v === 'string' && (v.length > 60 || v.includes('\n')) ? `(${v.length} characters)` : JSON.stringify(v);
}

export function settingsWithDefaults(rows) {
  const out = {};
  for (const [k, s] of Object.entries(SETTINGS)) out[k] = Object.prototype.hasOwnProperty.call(rows, k) ? rows[k] : s.def;
  return out;
}

// ── capability limits (per role) ─────────────────────────────────────────────
// Each key resolves: the account's role → the Default role (the global rows)
// → code default. The public account has its own rows instead of a role.
// `null` on a numeric key means "no limit" (still bounded by hard ceilings).
export const PASSKEY_MODES = ['any', 'second', 'off'];
/** Passkeys per account, at most (the passkeysMax limit can lower it). */
export const MAX_PASSKEYS = 10;

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
  maxShareBytes:       { type: 'int', min: 1, max: HARD_MAX_SHARE_BYTES, nullable: true, def: 100 * MiB },
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
  // Any minimum from 1 (the admin's call); new installs start at 12.
  pwMinLength:         { type: 'int', min: 1, max: 128, nullable: false, def: 12, owner: 12 },
  pwUpper:             { type: 'bool', def: false, owner: false },
  pwLower:             { type: 'bool', def: false, owner: false },
  pwDigit:             { type: 'bool', def: false, owner: false },
  pwSymbol:            { type: 'bool', def: false, owner: false },
  // Passkeys (WebAuthn): "any" — sign in with a passkey alone, or use it as a
  // second factor after the password (the user chooses); "second" — only as a
  // second factor (every password login then needs one); "off" — none.
  // Recovery codes stand in for a passkey wherever one is accepted.
  passkeys:            { type: 'enum', values: PASSKEY_MODES, def: 'any', owner: 'any' },
  // How many passkeys an account may register.
  passkeysMax:         { type: 'int', min: 1, max: MAX_PASSKEYS, nullable: false, def: MAX_PASSKEYS, owner: MAX_PASSKEYS },
  // Per-role values of server-wide settings (null: the Settings / Viewer
  // value applies). The owner always has the server-wide values.
  sessionIdleSec:      { type: 'int', min: SETTINGS['session.idleSec'].min, max: SETTINGS['session.idleSec'].max, nullable: true, def: null, owner: null },
  sessionAbsSec:       { type: 'int', min: SETTINGS['session.absSec'].min, max: SETTINGS['session.absSec'].max, nullable: true, def: null, owner: null },
  viewerMaxBytes:      { type: 'int', min: 64 * 1024, max: 500 * MiB, nullable: true, def: 50 * MiB },
  // File shares sent by the role's users: how long recipients may download
  // after opening, and how long an unfinished upload is kept (null: the
  // server-wide value, which is also the owner's).
  fileGrantSec:        { type: 'int', min: SETTINGS['files.grantSec'].min, max: SETTINGS['files.grantSec'].max, nullable: true, def: null, owner: null },
  filePendingSec:      { type: 'int', min: SETTINGS['files.pendingSec'].min, max: SETTINGS['files.pendingSec'].max, nullable: true, def: null, owner: null },
  // Drive (docs/DRIVE.md): the user's private encrypted folder tree. Capacity
  // null = no limit up to HARD_MAX_DRIVE_BYTES; the largest file null = only
  // the capacity applies. The public account never has a Drive.
  driveEnabled:        { type: 'bool', def: false, owner: true },
  driveMaxBytes:       { type: 'int', min: 1, max: HARD_MAX_DRIVE_BYTES, nullable: true, def: GiB, owner: null },
  driveMaxFileBytes:   { type: 'int', min: 1, max: HARD_MAX_DRIVE_BYTES, nullable: true, def: null, owner: null },
  // Reverse shares (docs/REVERSE.md): links that let anyone upload to a Drive
  // folder of the user. Also needs driveEnabled. Active ones at once (null: up
  // to MAX_REVERSE_ACTIVE) and the most bytes one may receive (null: only the
  // Drive's capacity).
  reverseEnabled:      { type: 'bool', def: false, owner: true },
  reverseMaxActive:    { type: 'int', min: 1, max: 1000, nullable: true, def: 10, owner: null },
  reverseMaxBytes:     { type: 'int', min: 1, max: HARD_MAX_DRIVE_BYTES, nullable: true, def: GiB, owner: null },
};

/** Hard ceiling on active reverse shares per account, whatever the role says. */
export const MAX_REVERSE_ACTIVE = 1000;

/** The password-policy keys of the limits (see public/js/pwauth.js). */
export const PASSWORD_POLICY_KEYS = ['pwMinLength', 'pwUpper', 'pwLower', 'pwDigit', 'pwSymbol'];

/** Hard ceiling on API keys per account, whatever the limit says. */
export const MAX_API_KEYS = 1000;
/**
 * What an API key may do (chosen when it is created or edited):
 *   notes  — create notes (every format)       files  — upload file shares
 *   policy — read the account's policy (GET /api/private/policy, used by the CLI)
 *   read   — list the key user's shares, one share, and its read receipts
 *   manage — label, extend (views / expiry) and revoke the key user's shares
 * A key created without a choice gets DEFAULT_KEY_SCOPES (creation only —
 * least privilege): read and manage are always opted into. No scope reaches
 * the account, its keys or credentials, or the admin panel.
 */
export const API_SCOPES = Object.freeze(['notes', 'files', 'policy', 'read', 'manage']);
export const DEFAULT_KEY_SCOPES = Object.freeze(['notes', 'files', 'policy']);

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
