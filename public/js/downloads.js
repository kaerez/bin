// downloads.js — read an opened file share: fetch encrypted chunks under the
// download grant, decrypt them (files.js), slice files out of the packed
// stream (v2) or read each file's own chunk sequence (v3, Drive shares and the
// Drive itself), and save a single file or a ZIP of any folder. Large saves stream to
// disk through the File System Access API where available (Chromium); other
// browsers assemble a Blob in memory.

import { fetchChunk, fetchRefChunk } from './api.js';
import { decryptChunk, importFileKey, chunkSpan, CHUNK, basename, filesUnder, ManifestError, cleanName } from './files.js';
import { refChunks } from './refsmanifest.js';
import { createZipWriter } from './zip.js';

export const STREAM_THRESHOLD = 64 * 1024 * 1024;
export const MEMORY_WARN = 500 * 1024 * 1024;

export class ShareReader {
  constructor({ id, grant, chunks, manifest, key }) {
    this.id = id;
    this.grant = grant;
    this.chunks = chunks;
    this.manifest = manifest;
    this.key = key;
    this.cache = new Map(); // tiny LRU: files straddling a boundary reuse a chunk
  }

  static async create({ id, grant, chunks, manifest }) {
    return new ShareReader({ id, grant, chunks, manifest, key: await importFileKey(manifest.fk) });
  }

  async chunk(i) {
    if (this.cache.has(i)) return this.cache.get(i);
    const ct = await fetchChunk(this.id, i, this.grant);
    const pt = await decryptChunk(this.key, i, this.chunks, ct);
    this.cache.set(i, pt);
    while (this.cache.size > 2) this.cache.delete(this.cache.keys().next().value);
    return pt;
  }

  /** Yield the plaintext of `entry` in chunk-sized slices. */
  async *stream(entry, onBytes) {
    const span = chunkSpan(entry.off, entry.size);
    if (!span) return;
    for (let i = span[0]; i <= span[1]; i++) {
      const c = await this.chunk(i);
      const start = Math.max(entry.off, i * CHUNK) - i * CHUNK;
      const end = Math.min(entry.off + entry.size, (i + 1) * CHUNK) - i * CHUNK;
      const slice = c.subarray(start, end);
      if (onBytes) onBytes(slice.length);
      yield slice;
    }
  }

  async bytes(entry, onBytes) {
    const out = new Uint8Array(entry.size);
    let o = 0;
    for await (const s of this.stream(entry, onBytes)) { out.set(s, o); o += s.length; }
    return out;
  }
}

/**
 * A reader over files that are each their own chunk sequence under their own
 * key (manifest v3; docs/DRIVE.md §7): chunk i of an n-chunk file is
 * encryptChunk(fk, i, n, bytes) with exactly min(CHUNK, size − i·CHUNK) bytes.
 * The same interface as ShareReader (stream / bytes / manifest), so saveFile
 * and saveZip work unchanged. `fetch(entry, i)` → the ciphertext of chunk i;
 * `refs` (optional) is the server's [{ chunks }] per ref, checked against the
 * sizes in the encrypted manifest.
 */
export class RefsReader {
  constructor({ manifest, fetch, refs = null }) {
    this.manifest = manifest;
    this.fetch = fetch;
    this.refs = refs;
    this.keys = new Map(); // fk → CryptoKey
  }

  /** A reader for an opened v3 share: chunks come from /api/file/<id>/chunk/<ref>/<i>. */
  static forShare({ id, grant, refs, manifest }) {
    if (!Array.isArray(refs)) throw new ManifestError('missing refs');
    for (const e of manifest.entries) if (!e.dir && !(e.ref < refs.length)) throw new ManifestError('invalid ref');
    return new RefsReader({ manifest, refs, fetch: (entry, i) => fetchRefChunk(id, entry.ref, i, grant) });
  }

  async key(entry) {
    if (!this.keys.has(entry.fk)) this.keys.set(entry.fk, importFileKey(entry.fk));
    return this.keys.get(entry.fk);
  }

  /** Yield the plaintext of `entry` chunk by chunk. */
  async *stream(entry, onBytes) {
    const n = refChunks(entry.size);
    const ref = this.refs && this.refs[entry.ref];
    if (ref && ref.chunks !== n) throw new ManifestError('size mismatch');
    const key = await this.key(entry);
    for (let i = 0; i < n; i++) {
      const pt = await decryptChunk(key, i, n, await this.fetch(entry, i));
      if (pt.length !== Math.min(CHUNK, entry.size - i * CHUNK)) throw new ManifestError('size mismatch');
      if (onBytes) onBytes(pt.length);
      yield pt;
    }
  }

  async bytes(entry, onBytes) {
    const out = new Uint8Array(entry.size);
    let o = 0;
    for await (const s of this.stream(entry, onBytes)) { out.set(s, o); o += s.length; }
    return out;
  }
}

/** A filesystem-safe download name, without spoofing characters (files.js cleanName; the browser sanitizes further). */
export function safeName(name) {
  // eslint-disable-next-line no-control-regex
  const n = cleanName(name).replace(/[\u0000-\u001f\u007f/\\]/g, '_').replace(/^\.+/, '_').slice(0, 200);
  return n || 'download';
}

function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = safeName(filename);
  a.rel = 'noopener';
  a.hidden = true;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

/** A sink over a File System Access handle (streams to disk), or null. */
async function diskSink(filename, size) {
  if (size < STREAM_THRESHOLD || typeof window.showSaveFilePicker !== 'function') return null;
  try {
    const handle = await window.showSaveFilePicker({ suggestedName: safeName(filename) });
    const w = await handle.createWritable();
    return { write: (b) => w.write(b), close: () => w.close(), abort: () => w.abort() };
  } catch (e) {
    if (e && e.name === 'AbortError') throw e; // user cancelled
    return null;
  }
}

function memorySink() {
  const parts = [];
  return { parts, write: async (b) => { parts.push(b.slice()); }, close: async () => {}, abort: async () => {} };
}

/** Save `text` as a UTF-8 text file named `filename` (a note, link or credential export: small, in memory). */
export function saveText(filename, text) {
  triggerDownload(new Blob([text], { type: 'text/plain;charset=utf-8' }), filename);
}

/** Save one file (raw, not zipped). */
export async function saveFile(reader, entry, onBytes) {
  const name = basename(entry.path);
  const disk = await diskSink(name, entry.size);
  const sink = disk || memorySink();
  try {
    for await (const s of reader.stream(entry, onBytes)) await sink.write(s);
    await sink.close();
  } catch (e) {
    await sink.abort().catch(() => {});
    throw e;
  }
  if (!disk) triggerDownload(new Blob(sink.parts, { type: 'application/octet-stream' }), name);
}

/**
 * Save a ZIP of folder `dirPath` ('' = the whole share), preserving the tree
 * below it (and its empty folders).
 */
export async function saveZip(reader, dirPath, zipName, onBytes) {
  const entries = reader.manifest.entries;
  const files = filesUnder(entries, dirPath);
  const prefix = dirPath ? dirPath + '/' : '';
  const dirs = entries.filter((e) => e.dir && (e.path + '/').startsWith(prefix) && e.path !== dirPath);
  const total = files.reduce((n, f) => n + f.size, 0);
  const disk = await diskSink(zipName, total);
  const sink = disk || memorySink();
  const zip = createZipWriter(sink);
  const rel = (p) => cleanName(prefix ? p.slice(prefix.length) : p);
  try {
    for (const d of dirs) await zip.addDir(rel(d.path));
    for (const f of files) await zip.addFile(rel(f.path), f.mtime, reader.stream(f, onBytes));
    await zip.finish();
    await sink.close();
  } catch (e) {
    await sink.abort().catch(() => {});
    throw e;
  }
  if (!disk) triggerDownload(new Blob(sink.parts, { type: 'application/zip' }), zipName);
}
