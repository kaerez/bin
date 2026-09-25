// reader.js — read an opened file share: fetch encrypted chunks under the
// download grant, authenticate + decrypt them (files.js), and slice files out
// of the packed stream. A Node port of ShareReader in public/js/downloads.js.
//
// Only the chunks that cover the requested entries are fetched; a tiny cache
// lets files that straddle a chunk boundary (or several small files sharing a
// chunk) reuse it instead of downloading it again.
import { CHUNK, chunkSpan, decryptChunk, importFileKey } from '../vendor/files.js';

export class ShareReader {
  constructor({ client, id, grant, chunks, key }) {
    this.client = client;
    this.id = id;
    this.grant = grant;
    this.chunks = chunks;
    this.key = key;
    this.cache = new Map(); // tiny LRU (insertion order)
    this.fetched = 0;       // chunk downloads performed (for tests / progress)
  }

  static async create({ client, id, grant, chunks, manifest }) {
    return new ShareReader({ client, id, grant, chunks, key: await importFileKey(manifest.fk) });
  }

  async chunk(i) {
    if (this.cache.has(i)) return this.cache.get(i);
    const ct = await this.client.chunk(this.id, i, this.grant);
    // GCM authenticates index and total (chunkAAD): a reordered, truncated or
    // substituted chunk throws ManifestError here instead of yielding bytes.
    const pt = await decryptChunk(this.key, i, this.chunks, ct);
    this.fetched++;
    this.cache.set(i, pt);
    while (this.cache.size > 2) this.cache.delete(this.cache.keys().next().value);
    return pt;
  }

  /** Yield the plaintext of `entry` in chunk-sized slices. */
  async *stream(entry) {
    const span = chunkSpan(entry.off, entry.size);
    if (!span) return;
    for (let i = span[0]; i <= span[1]; i++) {
      const c = await this.chunk(i);
      const start = Math.max(entry.off, i * CHUNK) - i * CHUNK;
      const end = Math.min(entry.off + entry.size, (i + 1) * CHUNK) - i * CHUNK;
      if (end > c.length) throw new RangeError('chunk shorter than the manifest says');
      yield c.subarray(start, end);
    }
  }
}
