// zip.js — minimal streaming ZIP writer (store-only, no compression) for
// "download folder" in the viewer and the CLI. Shared, dependency-free.
//
// Each member uses general-purpose flag bit 3 (sizes/CRC in a trailing data
// descriptor) so file data can stream through without buffering, and bit 11
// (UTF-8 names). No ZIP64: the 2 GiB share ceiling keeps every offset and size
// below 4 GiB, and writing past that is refused rather than silently corrupted.
// Member names come from validated manifest paths (files.js checkPath), so an
// archive can never contain absolute or "../" entries.

import { utf8 } from './bytes.js';

const LIMIT = 0xffffffff;

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

/** Incremental CRC-32 (IEEE). Call with the previous value (start at 0). */
export function crc32(bytes, prev = 0) {
  let c = ~prev >>> 0;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return ~c >>> 0;
}

function dosDateTime(ms) {
  const d = new Date(ms > 0 ? ms : Date.UTC(1980, 0, 1));
  const year = Math.max(1980, Math.min(2107, d.getUTCFullYear()));
  const time = (d.getUTCHours() << 11) | (d.getUTCMinutes() << 5) | (d.getUTCSeconds() >> 1);
  const date = ((year - 1980) << 9) | ((d.getUTCMonth() + 1) << 5) | d.getUTCDate();
  return { time, date };
}

function le(view, off, v, bytes) {
  if (bytes === 2) view.setUint16(off, v, true);
  else view.setUint32(off, v, true);
}

/**
 * Create a writer over `sink` — an object with `async write(Uint8Array)`.
 * Usage: `await z.addDir(path)`, `await z.addFile(path, mtime, asyncIterable)`,
 * then `await z.finish()`. Members must be added sequentially.
 */
export function createZipWriter(sink) {
  let offset = 0;
  const central = [];

  const emit = async (bytes) => {
    if (offset + bytes.length > LIMIT) throw new Error('archive exceeds 4 GiB (ZIP64 unsupported)');
    await sink.write(bytes);
    offset += bytes.length;
  };

  const localHeader = (nameBytes, time, date) => {
    const h = new Uint8Array(30 + nameBytes.length);
    const v = new DataView(h.buffer);
    le(v, 0, 0x04034b50, 4);
    le(v, 4, 20, 2);          // version needed
    le(v, 6, 0x0808, 2);      // bit 3 (data descriptor) + bit 11 (UTF-8)
    le(v, 8, 0, 2);           // method: store
    le(v, 10, time, 2);
    le(v, 12, date, 2);
    // crc / sizes = 0 here; real values follow in the data descriptor
    le(v, 26, nameBytes.length, 2);
    h.set(nameBytes, 30);
    return h;
  };

  async function addEntry(name, mtimeMs, chunks) {
    const nameBytes = utf8(name);
    const { time, date } = dosDateTime(mtimeMs);
    const headerOffset = offset;
    await emit(localHeader(nameBytes, time, date));
    let crc = 0;
    let size = 0;
    if (chunks) {
      for await (const c of chunks) {
        crc = crc32(c, crc);
        size += c.length;
        await emit(c);
      }
    }
    const dd = new Uint8Array(16);
    const dv = new DataView(dd.buffer);
    le(dv, 0, 0x08074b50, 4);
    le(dv, 4, crc, 4);
    le(dv, 8, size, 4);
    le(dv, 12, size, 4);
    await emit(dd);
    central.push({ nameBytes, time, date, crc, size, headerOffset, dir: name.endsWith('/') });
  }

  return {
    addDir: (path, mtimeMs = 0) => addEntry(path.endsWith('/') ? path : path + '/', mtimeMs, null),
    addFile: (path, mtimeMs, chunks) => addEntry(path, mtimeMs, chunks),
    async finish() {
      const cdStart = offset;
      for (const e of central) {
        const h = new Uint8Array(46 + e.nameBytes.length);
        const v = new DataView(h.buffer);
        le(v, 0, 0x02014b50, 4);
        le(v, 4, 0x031e, 2);    // made by: Unix, spec 3.0
        le(v, 6, 20, 2);
        le(v, 8, 0x0808, 2);
        le(v, 10, 0, 2);
        le(v, 12, e.time, 2);
        le(v, 14, e.date, 2);
        le(v, 16, e.crc, 4);
        le(v, 20, e.size, 4);
        le(v, 24, e.size, 4);
        le(v, 28, e.nameBytes.length, 2);
        // external attrs: Unix mode (dir 040755 / file 0100644) in the high word
        le(v, 38, ((e.dir ? 0o040755 : 0o100644) << 16) >>> 0, 4);
        le(v, 42, e.headerOffset, 4);
        h.set(e.nameBytes, 46);
        await emit(h);
      }
      const cdSize = offset - cdStart;
      if (central.length > 0xffff) throw new Error('too many archive members (ZIP64 unsupported)');
      const end = new Uint8Array(22);
      const v = new DataView(end.buffer);
      le(v, 0, 0x06054b50, 4);
      le(v, 8, central.length, 2);
      le(v, 10, central.length, 2);
      le(v, 12, cdSize, 4);
      le(v, 16, cdStart, 4);
      await emit(end);
    },
  };
}
