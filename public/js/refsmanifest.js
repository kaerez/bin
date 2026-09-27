// refsmanifest.js — manifest v3 (docs/DRIVE.md §7): the encrypted manifest of
// a Drive share. Unlike a v2 file share (one packed stream under one key), each
// file is its own chunk sequence in the Drive, with its own key:
//   { v: 3, kind: 'refs', entries: [{ path, size, type, mtime, ref, fk }], dirs: [path], view }
// `ref` indexes the share's `refs` (the server's list of referenced files, in
// the order the client sent them) and `fk` is that file's key (base64url).
// `view` is the sender's viewer-policy snapshot, as in v2 (null = no viewing).
//
// validateRefsManifest() returns the shape the readers use for v2 as well:
// { v: 3, entries: [...files, ...{ path, dir: true }], total, view }.

import { bytesFromB64url } from './bytes.js';
import { checkPath, checkMime, ManifestError, MAX_ENTRIES, RENDERERS, CHUNK } from './files.js';

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const keysAre = (o, list) => Object.keys(o).sort().join(',') === [...list].sort().join(',');

/** Chunks of a Drive file of `size` bytes (an empty file has none). */
export const refChunks = (size) => Math.ceil(size / CHUNK);

function checkView(v) {
  if (v === null || v === undefined) return null;
  if (!isPlainObject(v) || !keysAre(v, ['maxBytes', 'rules'])) throw new ManifestError('invalid view policy');
  if (!Number.isSafeInteger(v.maxBytes) || v.maxBytes < 0) throw new ManifestError('invalid view policy');
  if (!Array.isArray(v.rules) || v.rules.length > 200) throw new ManifestError('invalid view policy');
  const rules = v.rules.map((r) => {
    if (!isPlainObject(r) || !keysAre(r, ['match', 'renderer', 'value'])) throw new ManifestError('invalid view rule');
    if (!['mime', 'ext', 'any'].includes(r.match) || !RENDERERS.includes(r.renderer)) throw new ManifestError('invalid view rule');
    if (typeof r.value !== 'string' || r.value.length > 128) throw new ManifestError('invalid view rule');
    return { match: r.match, value: r.value, renderer: r.renderer };
  });
  return { maxBytes: v.maxBytes, rules };
}

/** Validate a decrypted v3 manifest → { v: 3, entries, total, view }, or throw ManifestError. */
export function validateRefsManifest(m) {
  if (!isPlainObject(m)) throw new ManifestError('manifest must be an object');
  const keys = Object.keys(m);
  if (!keysAre(m, keys.includes('view') ? ['v', 'kind', 'entries', 'dirs', 'view'] : ['v', 'kind', 'entries', 'dirs'])) throw new ManifestError('invalid manifest keys');
  if (m.v !== 3 || m.kind !== 'refs') throw new ManifestError('unsupported manifest');
  if (!Array.isArray(m.entries) || !Array.isArray(m.dirs) || m.entries.length + m.dirs.length === 0
    || m.entries.length + m.dirs.length > MAX_ENTRIES) throw new ManifestError('invalid entry count');
  const files = [];
  const filePaths = new Set();
  const refs = new Set();
  let total = 0;
  for (const e of m.entries) {
    if (!isPlainObject(e) || !keysAre(e, ['path', 'size', 'type', 'mtime', 'ref', 'fk'])) throw new ManifestError('invalid file entry');
    const path = checkPath(e.path);
    checkMime(e.type);
    if (!Number.isSafeInteger(e.size) || e.size < 0) throw new ManifestError('invalid size');
    if (!Number.isSafeInteger(e.mtime) || e.mtime < 0) throw new ManifestError('invalid mtime');
    if (!Number.isInteger(e.ref) || e.ref < 0 || e.ref >= m.entries.length || refs.has(e.ref)) throw new ManifestError('invalid ref');
    let fk;
    try { fk = bytesFromB64url(e.fk); } catch { throw new ManifestError('invalid fk'); }
    if (fk.length !== 32) throw new ManifestError('invalid fk');
    if (filePaths.has(path)) throw new ManifestError('duplicate path');
    filePaths.add(path);
    refs.add(e.ref);
    total += e.size;
    if (!Number.isSafeInteger(total)) throw new ManifestError('invalid size');
    files.push({ path, size: e.size, type: e.type, mtime: e.mtime, ref: e.ref, fk: e.fk });
  }
  const dirPaths = new Set();
  for (const d of m.dirs) {
    const path = checkPath(d);
    if (dirPaths.has(path) || filePaths.has(path)) throw new ManifestError('duplicate path');
    dirPaths.add(path);
  }
  // A file may not also be a folder (explicit, or implied by another path).
  for (const p of [...filePaths, ...dirPaths]) {
    const segs = p.split('/');
    for (let i = 1; i < segs.length; i++) {
      if (filePaths.has(segs.slice(0, i).join('/'))) throw new ManifestError('file/folder conflict');
    }
  }
  return { v: 3, entries: [...files, ...[...dirPaths].map((path) => ({ path, dir: true }))], total, view: checkView(m.view) };
}

/**
 * Build a v3 manifest from `files` = [{ path, size, type, mtime, fk }] (in the
 * order their node ids are sent: `ref` = position), `dirs` = [path] and the
 * viewer snapshot. Returns the plain object to seal (validated first).
 */
export function buildRefsManifest({ files, dirs = [], view = null }) {
  const m = {
    v: 3,
    kind: 'refs',
    entries: files.map((f, ref) => ({ path: f.path, size: f.size, type: f.type, mtime: f.mtime ?? 0, ref, fk: f.fk })),
    dirs: [...dirs],
    view,
  };
  validateRefsManifest(m);
  return m;
}
