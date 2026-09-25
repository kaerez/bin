// format.js — secbin paste format v2: canonical AAD construction and strict,
// fail-closed, prototype-pollution-safe validation. Single source of truth for
// the wire/storage format (SPEC.md §4, §5). Shared by the browser client
// (validates on read), the CLI (vendored copy) and the Worker (validates on create).

import { bytesFromB64url } from './bytes.js';

export const FORMAT_VERSION = 2;

// Expiry: "<n><unit>" with unit m (minutes), h (hours) or d (days), e.g. "90m",
// "36h", "7d". Bounded to [MIN_TTL, MAX_TTL]: KV's expirationTtl minimum is 60 s;
// 365 days is the hard ceiling (an admin may configure a lower per-user cap).
export const MIN_TTL = 60;
export const MAX_TTL = 31536000;
export const DEFAULT_EXPIRE = '24h';
const EXPIRE_RE = /^([1-9][0-9]{0,6})([mhd])$/;
const UNIT_SECONDS = { m: 60, h: 3600, d: 86400 };

/** Expiry value → TTL seconds, or null if invalid. */
export function expireSeconds(expire) {
  if (typeof expire !== 'string') return null;
  const m = EXPIRE_RE.exec(expire);
  if (!m) return null;
  const s = Number(m[1]) * UNIT_SECONDS[m[2]];
  return s >= MIN_TTL && s <= MAX_TTL ? s : null;
}

// View limit for view-limited pastes (adata.bar === true). Unlimited views are
// ordinary pastes (bar: false), which carry no `views`. `left` is server-set on
// reads: views remaining (null on a view-limited share raised to unlimited).
export const MAX_VIEWS = 100000;
export const FORMATS = ['plaintext', 'code', 'markdown', 'files'];
export const COMP = ['gzip', 'none'];
export const KDFS = ['hkdf', 'argon2id-hkdf'];

// Argon2id parameters for password-protected shares. The kdf label fixes memory
// and lanes; adata.iter carries the time cost t (bound by the AAD).
export const ARGON2 = Object.freeze({ mKiB: 65536, p: 1, tDefault: 3, tMin: 1, tMax: 10 });

export const MAX_CT_B64 = 3000000; // ~2.25 MiB of ciphertext
export const MAX_WK_B64 = 128;     // wrapped CEK is 48 bytes → 64 b64url chars

const ADATA_KEYS = ['alg', 'kdf', 'iter', 'comp', 'fmt', 'bar', 'ivc', 'ivw', 'skdf'];
const META_KEYS = ['expire', 'created', 'expires', 'views', 'left'];
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
  for (const k of Object.keys(obj)) {
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
    'secbin/v2',
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

function validateCt(ct) {
  if (typeof ct !== 'string' || ct.length === 0 || ct.length > MAX_CT_B64) {
    throw new FormatError('invalid ct');
  }
  b64urlByteLength(ct, 'ct');
}

/** A 32-byte proof (or proof hash) in canonical unpadded base64url. */
export function isProof(v) {
  if (typeof v !== 'string' || v.length !== 43) return false;
  try {
    return bytesFromB64url(v).length === 32;
  } catch {
    return false;
  }
}

/** Validate adata and return a clean, allowlisted copy. Throws FormatError. */
export function validateAdata(a) {
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
  } else if (a.iter < ARGON2.tMin || a.iter > ARGON2.tMax) {
    // Bounded so a hostile server cannot demand an absurd Argon2 workload.
    throw new FormatError('iter out of range');
  }

  if (typeof a.ivc !== 'string' || b64urlByteLength(a.ivc, 'ivc') !== 12) {
    throw new FormatError('invalid ivc');
  }
  if (typeof a.ivw !== 'string' || b64urlByteLength(a.ivw, 'ivw') !== 12) {
    throw new FormatError('invalid ivw');
  }
  if (typeof a.skdf !== 'string') throw new FormatError('invalid skdf');
  if (a.kdf === 'argon2id-hkdf') {
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
    if (!META_KEYS.includes(k)) throw new FormatError(`unknown field "${k}" in meta`);
  }
  if (expireSeconds(m.expire) === null) throw new FormatError('invalid expire');
  const out = { expire: m.expire };
  const has = (k) => Object.prototype.hasOwnProperty.call(m, k);
  for (const k of ['created', 'expires']) {
    if (has(k)) {
      if (!Number.isInteger(m[k]) || m[k] < 0) throw new FormatError(`invalid ${k}`);
      out[k] = m[k];
    }
  }
  if (has('views')) {
    if (m.views !== null && (!Number.isInteger(m.views) || m.views < 1 || m.views > MAX_VIEWS)) {
      throw new FormatError('invalid views');
    }
    out.views = m.views;
  }
  if (has('left')) {
    const cap = out.views ?? MAX_VIEWS;
    if (m.left !== null && (!Number.isInteger(m.left) || m.left < 0 || m.left > cap)) {
      throw new FormatError('invalid left');
    }
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
 * Validate a paste as released by an open (`{v, ct, wk, adata, meta}`) and
 * return a freshly-built clean copy. Untrusted input is never spread into the
 * result. Throws FormatError on any violation.
 */
export function validatePaste(input) {
  if (!isPlainObject(input)) throw new FormatError('paste must be an object');
  assertExactKeys(input, ['v', 'ct', 'wk', 'adata', 'meta'], 'paste');
  if (input.v !== FORMAT_VERSION) throw new FormatError('unsupported version');
  validateCt(input.ct);
  validateWk(input.wk);
  const adata = validateAdata(input.adata);
  const meta = validateMeta(input.meta);
  assertViewsConsistent(adata, meta);
  return { v: FORMAT_VERSION, ct: input.ct, wk: input.wk, adata, meta };
}

/**
 * Validate a create body: a paste plus the two access-proof hashes
 * `acc: { lh, kh }` (SPEC.md §5.4). Server-set meta fields are rejected.
 */
export function validateCreate(input) {
  if (!isPlainObject(input)) throw new FormatError('paste must be an object');
  assertExactKeys(input, ['v', 'ct', 'wk', 'adata', 'meta', 'acc'], 'paste');
  const { acc, ...rest } = input;
  if (isPlainObject(input.meta)) {
    for (const k of ['created', 'expires', 'left']) {
      if (Object.prototype.hasOwnProperty.call(input.meta, k)) throw new FormatError(`meta.${k} is server-set`);
    }
  }
  const clean = validatePaste(rest);
  if (!isPlainObject(acc)) throw new FormatError('acc must be an object');
  assertExactKeys(acc, ['lh', 'kh'], 'acc');
  if (!isProof(acc.lh) || !isProof(acc.kh)) throw new FormatError('invalid acc');
  return { ...clean, acc: { lh: acc.lh, kh: acc.kh } };
}

/**
 * Validate a paste *head* — the public, non-secret part (`{v, adata, meta}`)
 * a reader needs to derive its access proofs. It never carries `wk` or `ct`.
 */
export function validateHead(input) {
  if (!isPlainObject(input)) throw new FormatError('head must be an object');
  assertExactKeys(input, ['v', 'adata', 'meta'], 'head');
  if (input.v !== FORMAT_VERSION) throw new FormatError('unsupported version');
  const adata = validateAdata(input.adata);
  const meta = validateMeta(input.meta);
  assertViewsConsistent(adata, meta);
  return { v: FORMAT_VERSION, adata, meta };
}
