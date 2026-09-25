// downloads.js — read an opened file share: fetch encrypted chunks under the
// download grant, decrypt them (files.js), slice files out of the packed
// stream, and save a single file or a ZIP of any folder. Large saves stream to
// disk through the File System Access API where available (Chromium); other
// browsers assemble a Blob in memory.

import { fetchChunk } from './api.js';
import { decryptChunk, importFileKey, chunkSpan, CHUNK, basename, filesUnder } from './files.js';
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

/** A filesystem-safe download name (the browser sanitizes further). */
export function safeName(name) {
  // eslint-disable-next-line no-control-regex
  const n = String(name).replace(/[\u0000-\u001f\u007f/\\]/g, '_').replace(/^\.+/, '_').slice(0, 200);
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
  const rel = (p) => (prefix ? p.slice(prefix.length) : p);
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
