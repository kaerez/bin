// format.js — secbin paste format v1 (wire labels keep the original "binthere/v1"): canonical AAD construction and strict,
// fail-closed, prototype-pollution-safe validation. Single source of truth for
// the frozen wire/storage format (SPEC.md §4, §5). Shared by the browser client
// (validates on read) and the Worker (validates on create).

import { bytesFromB64url } from './bytes.js';

export const FORMAT_VERSION = 1;

/** Preset expiry option → TTL seconds (0 = never). See expireSeconds() for custom values. */
export const EXPIRE_SECONDS = {
  '5min': 300, '10min': 600, '1hour': 3600, '1day': 86400,
  '1week': 604800, '1month': 2592000, '1year': 31536000, 'never': 0,
};
export const EXPIRE_OPTIONS = Object.keys(EXPIRE_SECONDS);

// Custom expiry: "<n><unit>" with unit m (minutes), h (hours) or d (days),
// e.g. "90m", "36h", "7d". Bounded to [MIN_TTL, MAX_TTL]: KV's expirationTtl
// minimum is 60 s, and the upper bound matches the longest preset ('1year').
export const MIN_TTL = 60;
export const MAX_TTL = 31536000;
export const DEFAULT_EXPIRE = '24h';
const CUSTOM_EXPIRE_RE = /^([1-9][0-9]{0,6})([mhd])$/;
const UNIT_SECONDS = { m: 60, h: 3600, d: 86400 };

/**
 * Expiry value → TTL seconds (0 = never), or null if invalid. Accepts a preset
 * key (EXPIRE_OPTIONS) or a custom "<n>m|h|d" duration within bounds.
 * Own-property lookup only, so "__proto__"/"constructor" never resolve.
 */
export function expireSeconds(expire) {
  if (typeof expire !== 'string') return null;
  if (Object.prototype.hasOwnProperty.call(EXPIRE_SECONDS, expire)) return EXPIRE_SECONDS[expire];
  const m = CUSTOM_EXPIRE_RE.exec(expire);
  if (!m) return null;
  const s = Number(m[1]) * UNIT_SECONDS[m[2]];
  return s >= MIN_TTL && s <= MAX_TTL ? s : null;
}

// View limit for view-limited pastes (adata.bar === true). Absent ⇒ 1 (the
// original burn-after-read). Unlimited views are ordinary pastes (bar: false),
// which carry no `views`. `left` is server-set on reads: views remaining.
export const MAX_VIEWS = 100000;
export const FORMATS = ['plaintext', 'code', 'markdown'];
export const COMP = ['gzip', 'none'];
export const KDFS = ['hkdf', 'pbkdf2-hkdf'];

export const ITER_V1 = 310000;
export const ITER_MIN = 100000;
export const ITER_MAX = 1000000;

export const MAX_CT_B64 = 3000000; // ~2.25 MiB of ciphertext
export const MAX_WK_B64 = 128;     // wrapped CEK is 48 bytes → ~64 b64url chars

const ADATA_KEYS = ['alg', 'kdf', 'iter', 'comp', 'fmt', 'bar', 'ivc', 'ivw', 'skdf'];
const DANGEROUS_KEYS = ['__proto__', 'constructor', 'prototype'];

/** Thrown for any format violation. Callers map this to HTTP 400 / a UI error. */
export class FormatError extends Error {
  constructor(message) {
    super(message);
    this.name = 'FormatError';
  }
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/** Reject objects carrying prototype-pollution-shaped own keys. */
function assertNoDangerousKeys(obj, where) {
  for (const k of DANGEROUS_KEYS) {
    if (Object.prototype.hasOwnProperty.call(obj, k)) {
      throw new FormatError(`illegal key "${k}" in ${where}`);
    }
  }
}

/** Exact key-set check: obj must have exactly `allowed` own keys, no more, no less. */
function assertExactKeys(obj, allowed, where) {
  assertNoDangerousKeys(obj, where);
  const keys = Object.keys(obj);
  for (const k of keys) {
    if (!allowed.includes(k)) throw new FormatError(`unknown field "${k}" in ${where}`);
  }
  for (const k of allowed) {
    if (!Object.prototype.hasOwnProperty.call(obj, k)) {
      throw new FormatError(`missing field "${k}" in ${where}`);
    }
  }
}

function b64urlByteLength(str, where) {
  try {
    return bytesFromB64url(str).length;
  } catch {
    throw new FormatError(`invalid base64url in ${where}`);
  }
}

/**
 * Build the canonical Additional Authenticated Data for a paste's adata.
 * Fixed field order, newline-terminated — never depends on JSON key order.
 * (SPEC.md §4.) Returns UTF-8 bytes.
 */
export function buildAAD(adata) {
  const lines = [
    'binthere/v1',
    'alg=' + adata.alg,
    'kdf=' + adata.kdf,
    'iter=' + adata.iter,
    'comp=' + adata.comp,
    'fmt=' + adata.fmt,
    'bar=' + (adata.bar ? '1' : '0'),
    'ivc=' + adata.ivc,
    'ivw=' + adata.ivw,
    'skdf=' + adata.skdf,
  ];
  return new TextEncoder().encode(lines.join('\n') + '\n');
}

function validateWk(wk) {
  if (typeof wk !== 'string' || wk.length === 0 || wk.length > MAX_WK_B64) {
    throw new FormatError('invalid wk');
  }
  if (b64urlByteLength(wk, 'wk') !== 48) throw new FormatError('invalid wk length');
}

/** Validate adata and return a clean, allowlisted copy. Throws FormatError. */
function validateAdata(a) {
  if (!isPlainObject(a)) throw new FormatError('adata must be an object');
  assertExactKeys(a, ADATA_KEYS, 'adata');

  if (a.alg !== 'A256GCM') throw new FormatError('unsupported alg');
  if (!KDFS.includes(a.kdf)) throw new FormatError('unsupported kdf');
  if (!COMP.includes(a.comp)) throw new FormatError('unsupported comp');
  if (!FORMATS.includes(a.fmt)) throw new FormatError('unsupported fmt');
  if (typeof a.bar !== 'boolean') throw new FormatError('bar must be boolean');

  if (!Number.isInteger(a.iter)) throw new FormatError('iter must be an integer');
  if (a.kdf === 'hkdf') {
    if (a.iter !== 0) throw new FormatError('iter must be 0 for hkdf');
  } else {
    if (a.iter < ITER_MIN || a.iter > ITER_MAX) throw new FormatError('iter out of range');
  }

  if (typeof a.ivc !== 'string' || b64urlByteLength(a.ivc, 'ivc') !== 12) {
    throw new FormatError('invalid ivc');
  }
  if (typeof a.ivw !== 'string' || b64urlByteLength(a.ivw, 'ivw') !== 12) {
    throw new FormatError('invalid ivw');
  }
  if (typeof a.skdf !== 'string') throw new FormatError('invalid skdf');
  if (a.kdf === 'pbkdf2-hkdf') {
    if (b64urlByteLength(a.skdf, 'skdf') !== 16) throw new FormatError('invalid skdf length');
  } else if (a.skdf !== '') {
    throw new FormatError('skdf must be empty for hkdf');
  }

  return {
    alg: a.alg, kdf: a.kdf, iter: a.iter, comp: a.comp, fmt: a.fmt,
    bar: a.bar, ivc: a.ivc, ivw: a.ivw, skdf: a.skdf,
  };
}

/** Validate meta and return a clean copy. Throws FormatError. */
function validateMeta(m) {
  if (!isPlainObject(m)) throw new FormatError('meta must be an object');
  assertNoDangerousKeys(m, 'meta');
  for (const k of Object.keys(m)) {
    if (k !== 'expire' && k !== 'created' && k !== 'views' && k !== 'left') {
      throw new FormatError(`unknown field "${k}" in meta`);
    }
  }
  if (expireSeconds(m.expire) === null) throw new FormatError('invalid expire');
  const out = { expire: m.expire };
  const has = (k) => Object.prototype.hasOwnProperty.call(m, k);
  if (has('created')) {
    if (!Number.isInteger(m.created) || m.created < 0) throw new FormatError('invalid created');
    out.created = m.created;
  }
  if (has('views')) {
    if (!Number.isInteger(m.views) || m.views < 1 || m.views > MAX_VIEWS) throw new FormatError('invalid views');
    out.views = m.views;
  }
  if (has('left')) {
    if (!Number.isInteger(m.left) || m.left < 0 || m.left > (out.views ?? 1)) throw new FormatError('invalid left');
    out.left = m.left;
  }
  return out;
}

/** A view limit only makes sense on a view-limited (bar) paste. */
function assertViewsConsistent(adata, meta) {
  if (!adata.bar && (meta.views !== undefined || meta.left !== undefined)) {
    throw new FormatError('views requires a view-limited paste');
  }
}

/**
 * Validate a paste object against format v1 and return a freshly-built, clean
 * copy containing ONLY allowlisted fields (untrusted input is never spread into
 * the result). Throws FormatError on any violation. `meta.created` is accepted
 * when present (reads) and ignored otherwise (the server sets it on create).
 */
export function validatePaste(input) {
  if (!isPlainObject(input)) throw new FormatError('paste must be an object');
  assertExactKeys(input, ['v', 'ct', 'wk', 'adata', 'meta'], 'paste');

  if (input.v !== FORMAT_VERSION) throw new FormatError('unsupported version');

  if (typeof input.ct !== 'string' || input.ct.length === 0 || input.ct.length > MAX_CT_B64) {
    throw new FormatError('invalid ct');
  }
  b64urlByteLength(input.ct, 'ct');
  validateWk(input.wk);

  const adata = validateAdata(input.adata);
  const meta = validateMeta(input.meta);
  assertViewsConsistent(adata, meta);
  return { v: FORMAT_VERSION, ct: input.ct, wk: input.wk, adata, meta };
}

/**
 * Validate a burn paste *head* — the non-consuming peek response (SPEC.md §8):
 * a full paste minus the ciphertext `ct`. Fail-closed like validatePaste; in
 * particular `iter` stays within [ITER_MIN, ITER_MAX], so a hostile or buggy
 * server cannot demand an absurd PBKDF2 workload before key derivation.
 */
export function validateHead(input) {
  if (!isPlainObject(input)) throw new FormatError('head must be an object');
  assertExactKeys(input, ['v', 'wk', 'adata', 'meta'], 'head');

  if (input.v !== FORMAT_VERSION) throw new FormatError('unsupported version');
  validateWk(input.wk);

  const adata = validateAdata(input.adata);
  const meta = validateMeta(input.meta);
  assertViewsConsistent(adata, meta);
  return { v: FORMAT_VERSION, wk: input.wk, adata, meta };
}
