// settings.js — admin-configurable global settings and per-user capability
// limits: the schema (types, bounds, defaults) and pure resolution helpers.
// Storage lives in the Directory DO; everything written is validated here.

import { MAX_TTL, MAX_VIEWS } from '../../public/js/format.js';
import { HARD_MAX_SHARE_BYTES, RENDERERS } from '../../public/js/files.js';
import { FILE_TYPE_MODES, MAX_FOLDER_DEPTH, normalizeRules } from '../../public/js/filepolicy.js';

const MIN = 60;
const HOUR = 3600;
const DAY = 86400;
const MiB = 1024 * 1024;

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
  apiMaxKeys:          { type: 'int', min: 0, max: 100, nullable: false, def: 5 },
  // File policy (public/js/filepolicy.js): allow/block list of types, folder depth.
  fileTypeMode:        { type: 'enum', values: FILE_TYPE_MODES, def: 'any' },
  fileTypeRules:       { type: 'rules', def: [] },
  maxFolderDepth:      { type: 'int', min: 0, max: MAX_FOLDER_DEPTH, nullable: true, def: null },
};

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
  s.type === 'bool' ? true : s.type === 'enum' ? 'any' : s.type === 'rules' ? [] : (s.nullable ? null : 100)])));

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
