// files.js — secbin file-share format v2 (SPEC.md §12): the encrypted manifest,
// path rules, the packed/padded stream layout and per-chunk AES-256-GCM.
// Shared by the browser (dashboard + viewer) and the CLI (vendored copy).
//
// Everything that describes the content — names, folder structure, MIME types,
// sizes, mtimes, the viewer policy — lives in the manifest, which is itself a
// v2 paste (fmt:"files") and therefore end-to-end encrypted. All files are
// concatenated into ONE stream, zero-padded to a PAD multiple, then cut into
// CHUNK-sized pieces: the server sees only the padded total and chunk count.

import { randomBytes, utf8, b64urlFromBytes, bytesFromB64url } from './bytes.js';

export const CHUNK = 8 * 1024 * 1024;       // plaintext bytes per chunk
export const PAD = 64 * 1024;               // stream padded to a multiple of this
export const TAG = 16;                      // GCM tag per chunk
export const MAX_CHUNK_CT = CHUNK + TAG;    // server-side cap per uploaded chunk
export const HARD_MAX_SHARE_BYTES = 2 * 1024 * 1024 * 1024; // 2 GiB ceiling (SPEC §6)
export const MAX_ENTRIES = 10000;
const MAX_SEGMENT_BYTES = 255;
const MAX_PATH_BYTES = 4096;
const MIME_RE = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$/;
export const RENDERERS = ['text', 'markdown', 'code', 'image', 'pdf', 'media'];

export class ManifestError extends Error {
  constructor(message) { super(message); this.name = 'ManifestError'; }
}

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

// ── paths ─────────────────────────────────────────────────────────────────────

/**
 * Validate a relative POSIX path and return it unchanged, or throw. Rejects
 * empty/"."/".." segments, absolute paths, backslashes, NUL and all control
 * characters, over-long segments and paths. Never "repairs" a path — a manifest
 * carrying one of these is malformed (fail closed; no zip-slip, no traversal).
 */
export function checkPath(p) {
  if (typeof p !== 'string' || p.length === 0) throw new ManifestError('empty path');
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f\\]/.test(p)) throw new ManifestError('illegal character in path');
  if (utf8(p).length > MAX_PATH_BYTES) throw new ManifestError('path too long');
  if (p.startsWith('/')) throw new ManifestError('absolute path');
  for (const seg of p.split('/')) {
    if (seg === '' || seg === '.' || seg === '..') throw new ManifestError('illegal path segment');
    if (utf8(seg).length > MAX_SEGMENT_BYTES) throw new ManifestError('path segment too long');
  }
  return p;
}

/** Lowercased `type/subtype` or throw. Parameters (";charset=…") are not allowed. */
export function checkMime(t) {
  if (typeof t !== 'string' || !MIME_RE.test(t)) throw new ManifestError('invalid MIME type');
  return t;
}

export const basename = (p) => p.slice(p.lastIndexOf('/') + 1);

// ── layout ────────────────────────────────────────────────────────────────────

/** Padded stream length for `total` content bytes (always ≥ one PAD block). */
export function paddedLength(total) {
  return Math.max(PAD, Math.ceil(total / PAD) * PAD);
}

export function chunkCount(total) {
  return Math.ceil(paddedLength(total) / CHUNK);
}

/**
 * Lay out file entries back to back. `files` = [{path, type, size, mtime}],
 * `dirs` = [path] (explicit, e.g. empty folders). Returns the manifest entries
 * (with offsets) and totals. Throws ManifestError on duplicates/conflicts.
 */
export function layout(files, dirs = []) {
  const entries = [];
  let off = 0;
  for (const f of files) {
    if (!Number.isSafeInteger(f.size) || f.size < 0) throw new ManifestError('invalid size');
    entries.push({ path: f.path, type: f.type, size: f.size, mtime: f.mtime ?? 0, off });
    off += f.size;
  }
  for (const d of dirs) entries.push({ path: d, dir: true });
  const manifestEntries = checkEntries(entries, off);
  return { entries: manifestEntries, total: off, padded: paddedLength(off), chunks: chunkCount(off) };
}

function checkEntries(entries, total) {
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > MAX_ENTRIES) {
    throw new ManifestError('invalid entry count');
  }
  const filePaths = new Set();
  const dirPaths = new Set();
  const out = [];
  let expectOff = 0;
  for (const e of entries) {
    if (!isPlainObject(e)) throw new ManifestError('invalid entry');
    const path = checkPath(e.path);
    if (own(e, 'dir')) {
      if (e.dir !== true || Object.keys(e).length !== 2) throw new ManifestError('invalid dir entry');
      if (dirPaths.has(path)) throw new ManifestError('duplicate path');
      dirPaths.add(path);
      out.push({ path, dir: true });
      continue;
    }
    const keys = Object.keys(e).sort().join(',');
    if (keys !== 'mtime,off,path,size,type') throw new ManifestError('invalid file entry');
    checkMime(e.type);
    if (!Number.isSafeInteger(e.size) || e.size < 0) throw new ManifestError('invalid size');
    if (!Number.isSafeInteger(e.mtime) || e.mtime < 0) throw new ManifestError('invalid mtime');
    if (e.off !== expectOff) throw new ManifestError('invalid offset'); // contiguous, in order
    expectOff += e.size;
    if (filePaths.has(path)) throw new ManifestError('duplicate path');
    filePaths.add(path);
    out.push({ path, type: e.type, size: e.size, mtime: e.mtime, off: e.off });
  }
  if (expectOff !== total) throw new ManifestError('size mismatch');
  // A file may not also be a folder (explicit, or implied by another path).
  for (const p of [...filePaths, ...dirPaths]) {
    const segs = p.split('/');
    for (let i = 1; i < segs.length; i++) {
      if (filePaths.has(segs.slice(0, i).join('/'))) throw new ManifestError('file/folder conflict');
    }
  }
  for (const d of dirPaths) if (filePaths.has(d)) throw new ManifestError('file/folder conflict');
  return out;
}

/** Validate a viewer-policy snapshot (or null). */
function checkViewPolicy(v) {
  if (v === null) return null;
  if (!isPlainObject(v) || Object.keys(v).sort().join(',') !== 'maxBytes,rules') throw new ManifestError('invalid view policy');
  if (!Number.isSafeInteger(v.maxBytes) || v.maxBytes < 0) throw new ManifestError('invalid view policy');
  if (!Array.isArray(v.rules) || v.rules.length > 200) throw new ManifestError('invalid view policy');
  const rules = v.rules.map((r) => {
    if (!isPlainObject(r) || Object.keys(r).sort().join(',') !== 'match,renderer,value') throw new ManifestError('invalid view rule');
    if (!['mime', 'ext', 'any'].includes(r.match) || !RENDERERS.includes(r.renderer)) throw new ManifestError('invalid view rule');
    if (typeof r.value !== 'string' || r.value.length > 128) throw new ManifestError('invalid view rule');
    return { match: r.match, value: r.value, renderer: r.renderer };
  });
  return { maxBytes: v.maxBytes, rules };
}

/** Validate a decrypted manifest object and return a clean copy. */
export function validateManifest(m) {
  if (!isPlainObject(m)) throw new ManifestError('manifest must be an object');
  if (Object.keys(m).sort().join(',') !== 'chunk,entries,fk,total,v,view') throw new ManifestError('invalid manifest keys');
  if (m.v !== 2 || m.chunk !== CHUNK) throw new ManifestError('unsupported manifest');
  let fk;
  try { fk = bytesFromB64url(m.fk); } catch { throw new ManifestError('invalid fk'); }
  if (fk.length !== 32) throw new ManifestError('invalid fk');
  if (!Number.isSafeInteger(m.total) || m.total < 0 || m.total > HARD_MAX_SHARE_BYTES) throw new ManifestError('invalid total');
  const entries = checkEntries(m.entries, m.total);
  return { v: 2, fk: m.fk, chunk: CHUNK, total: m.total, entries, view: checkViewPolicy(m.view) };
}

/** Build a manifest (the plaintext of the fmt:"files" paste). */
export function buildManifest({ entries, total, view = null }) {
  return validateManifest({ v: 2, fk: b64urlFromBytes(randomBytes(32)), chunk: CHUNK, total, entries, view });
}

// ── chunk crypto ──────────────────────────────────────────────────────────────

/** 96-bit big-endian chunk index — unique per chunk under a per-share key. */
export function chunkIv(i) {
  const iv = new Uint8Array(12);
  let v = BigInt(i);
  for (let k = 11; k >= 0; k--) { iv[k] = Number(v & 0xffn); v >>= 8n; }
  return iv;
}

export const chunkAAD = (i, n) => utf8(`secbin-file/v2\nidx=${i}\ntotal=${n}\n`);

export async function importFileKey(fkB64) {
  return crypto.subtle.importKey('raw', bytesFromB64url(fkB64), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export async function encryptChunk(key, i, n, plain) {
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: chunkIv(i), additionalData: chunkAAD(i, n), tagLength: 128 }, key, plain);
  return new Uint8Array(ct);
}

/** Throws ManifestError('chunk authentication failed') on tamper/reorder/truncation. */
export async function decryptChunk(key, i, n, ct) {
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: chunkIv(i), additionalData: chunkAAD(i, n), tagLength: 128 }, key, ct);
    return new Uint8Array(pt);
  } catch {
    throw new ManifestError('chunk authentication failed');
  }
}

/**
 * Plaintext of stream chunk `i`: the bytes of every source overlapping
 * [i·CHUNK, (i+1)·CHUNK), zero-filled beyond the content (padding). `sources`
 * are [{off, size, read(start, end) → Promise<Uint8Array>}] in stream order.
 */
export async function readStreamChunk(sources, i, total) {
  const padded = paddedLength(total);
  const start = i * CHUNK;
  const end = Math.min(start + CHUNK, padded);
  if (start >= padded) throw new RangeError('chunk out of range');
  const out = new Uint8Array(end - start); // zero-filled: padding stays zero
  for (const s of sources) {
    const a = Math.max(start, s.off);
    const b = Math.min(end, s.off + s.size);
    if (a >= b) continue;
    const bytes = await s.read(a - s.off, b - s.off);
    if (bytes.length !== b - a) throw new Error('short read');
    out.set(bytes, a - start);
  }
  return out;
}

/** Chunk indexes [first, last] covering stream bytes [off, off+size). Empty → null. */
export function chunkSpan(off, size) {
  if (size === 0) return null;
  return [Math.floor(off / CHUNK), Math.floor((off + size - 1) / CHUNK)];
}

/**
 * Tree view of manifest entries: { name, path, dirs: Map, files: [] } with
 * implied parent folders filled in. Pure data — rendering stays in the UI.
 */
export function buildTree(entries) {
  const root = { name: '', path: '', dirs: new Map(), files: [] };
  const dirFor = (segs) => {
    let node = root;
    for (let i = 0; i < segs.length; i++) {
      const name = segs[i];
      if (!node.dirs.has(name)) node.dirs.set(name, { name, path: segs.slice(0, i + 1).join('/'), dirs: new Map(), files: [] });
      node = node.dirs.get(name);
    }
    return node;
  };
  for (const e of entries) {
    const segs = e.path.split('/');
    if (e.dir) dirFor(segs);
    else dirFor(segs.slice(0, -1)).files.push(e);
  }
  return root;
}

/** All file entries under a folder path ('' = everything). */
export function filesUnder(entries, dirPath) {
  if (!dirPath) return entries.filter((e) => !e.dir);
  const prefix = dirPath + '/';
  return entries.filter((e) => !e.dir && e.path.startsWith(prefix));
}
