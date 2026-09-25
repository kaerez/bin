// fileshare-do.js — FileShare Durable Object: one instance per file share (id
// prefix "f"). It owns the share's lifecycle and its R2 objects:
//
//   pending  — created by an authenticated init; the uploader streams encrypted
//              chunks (checked against the exact expected sizes) and finalizes
//              with the encrypted manifest. Purged at the upload deadline.
//   active   — readable. `open` verifies both access proofs, spends a view
//              (atomically) and issues a time-limited download grant.
//   closed   — the last view was spent: no more opens, but outstanding grants
//              keep working until they expire, then everything is purged.
//
// Every expiry path (deadline, share expiry, last grant) runs through the alarm,
// which deletes the R2 objects — R2 has no per-object TTL. The server never sees
// file names, types, sizes or structure: only the padded stream length.

import { DurableObject } from 'cloudflare:workers';
import { verifyToken } from './lib/ids.js';
import { timingSafeEqualHex } from '../public/js/bytes.js';
import { CHUNK, TAG } from '../public/js/files.js';

const KEY = 'rec';
// Download grants live under their own key, not inside the (up to ~1.9 MB)
// record, and at most MAX_ACTIVE_GRANTS may be live at once — so repeated
// opens of an unlimited share can never push the record past the storage
// value limit and wedge the share.
const GRANTS_KEY = 'grants';
export const MAX_ACTIVE_GRANTS = 2000;
// One client (tracking key: an IP, or an IPv6 /64) holds at most this many live
// grants; opening again replaces its oldest. So a single link holder cannot
// fill the table and lock everyone else out — that takes 100 distinct networks.
export const MAX_GRANTS_PER_CLIENT = 20;
const nowSec = () => Math.floor(Date.now() / 1000);
const safeEq = (a, b) => typeof a === 'string' && typeof b === 'string' && timingSafeEqualHex(a, b);

/** Exact ciphertext size of chunk i for a padded stream of `padded` bytes. */
export function expectedChunkSize(padded, i) {
  return Math.min(CHUNK, padded - i * CHUNK) + TAG;
}

export const r2Key = (id, i) => `f/${id}/${i}`;

export class FileShare extends DurableObject {
  async #rec() {
    return (await this.ctx.storage.get(KEY)) || null;
  }

  /** Live grants (records written before grants moved out keep theirs inline). */
  async #grants(rec, t = nowSec()) {
    const stored = await this.ctx.storage.get(GRANTS_KEY);
    const all = Array.isArray(stored) ? stored : Array.isArray(rec?.grants) ? rec.grants : [];
    return all.filter((g) => g.exp > t);
  }

  async #put(rec) {
    await this.ctx.storage.put(KEY, rec);
  }

  async #purge(rec) {
    if (rec) {
      const r2 = this.env.FILES;
      if (r2 && typeof r2.delete === 'function') {
        const keys = Array.from({ length: rec.chunks }, (_, i) => r2Key(rec.id, i));
        for (let i = 0; i < keys.length; i += 1000) await r2.delete(keys.slice(i, i + 1000));
      } else if (Array.isArray(rec.sizes) && rec.sizes.some((n) => n > 0)) {
        // Ciphertext was stored but R2 is unbound now: fail (the alarm retries)
        // rather than forget the share and leave its chunks behind.
        throw new Error('FILES binding missing: cannot delete stored chunks');
      }
    }
    await this.ctx.storage.deleteAll();
    await this.ctx.storage.deleteAlarm();
  }

  async #live() {
    const rec = await this.#rec();
    if (!rec) return null;
    const t = nowSec();
    const dead = (rec.state === 'pending' && t >= rec.deadline)
      || (rec.state !== 'pending' && rec.expires && t >= rec.expires)
      || (rec.state === 'closed' && t >= rec.purgeAt);
    if (dead) { await this.#purge(rec); return null; }
    return rec;
  }

  // ── upload ────────────────────────────────────────────────────────────────
  async init({ id, uid, uth, dth, padded, views, expire, ttl, pendingSec, deletable = false }) {
    return this.ctx.blockConcurrencyWhile(async () => {
      if (await this.#rec()) return false;
      const chunks = Math.ceil(padded / CHUNK);
      const deadline = nowSec() + pendingSec;
      await this.#put({ id, state: 'pending', uid, uth, dth, padded, chunks, sizes: [], views, left: views, expire, ttl, deadline, grants: [], deletable: !!deletable });
      await this.ctx.storage.setAlarm(deadline * 1000);
      return true;
    });
  }

  /** May `uid` holding upload token hash `uth` write chunk i of `len` bytes? */
  async authorizeChunk(uid, uth, i, len) {
    const rec = await this.#live();
    if (!rec || rec.state !== 'pending') return { status: 'gone' };
    if (rec.uid !== uid || !safeEq(uth, rec.uth)) return { status: 'forbidden' };
    if (!Number.isInteger(i) || i < 0 || i >= rec.chunks) return { status: 'bad_index' };
    if (len !== expectedChunkSize(rec.padded, i)) return { status: 'bad_size', expected: expectedChunkSize(rec.padded, i) };
    return { status: 'ok' };
  }

  async commitChunk(uid, uth, i, len) {
    return this.ctx.blockConcurrencyWhile(async () => {
      const rec = await this.#live();
      if (!rec || rec.state !== 'pending' || rec.uid !== uid || !safeEq(uth, rec.uth)) return { status: 'gone' };
      if (len !== expectedChunkSize(rec.padded, i)) return { status: 'bad_size' };
      rec.sizes[i] = len;
      await this.#put(rec);
      return { status: 'ok' };
    });
  }

  /** Activate the share with its encrypted manifest (a v2 fmt:"files" paste). */
  async finalize(uid, uth, { paste, acc }) {
    return this.ctx.blockConcurrencyWhile(async () => {
      const rec = await this.#live();
      if (!rec || rec.state !== 'pending') return { status: 'gone' };
      if (rec.uid !== uid || !safeEq(uth, rec.uth)) return { status: 'forbidden' };
      // The encrypted manifest must declare what the upload was authorized for.
      if (paste.adata.bar !== (rec.views !== null) || paste.meta.expire !== rec.expire
          || (paste.meta.views ?? null) !== (rec.views === null ? null : rec.views)
          || (paste.meta.deletable === true) !== !!rec.deletable) return { status: 'mismatch' };
      for (let i = 0; i < rec.chunks; i++) {
        if (rec.sizes[i] !== expectedChunkSize(rec.padded, i)) return { status: 'incomplete', missing: i };
      }
      const created = nowSec();
      const expires = created + rec.ttl;
      const meta = { expire: rec.expire, created, expires };
      if (rec.views !== null) meta.views = rec.views;
      if (rec.deletable) meta.deletable = true;
      const next = {
        id: rec.id, state: 'active', dth: rec.dth, padded: rec.padded, chunks: rec.chunks, views: rec.views, left: rec.left,
        expire: rec.expire, ttl: rec.ttl, expires, acc, grants: [],
        paste: { v: paste.v, ct: paste.ct, wk: paste.wk, adata: paste.adata, meta },
      }; // uid + upload token dropped: the share is no longer linked to the uploader here
      await this.#put(next);
      await this.ctx.storage.setAlarm(expires * 1000);
      return { status: 'ok', created, expires };
    });
  }

  // ── read ──────────────────────────────────────────────────────────────────
  #metaOut(rec) {
    const m = { ...rec.paste.meta, expires: rec.expires };
    if (rec.paste.adata.bar) { m.views = rec.views; m.left = rec.left; }
    return m;
  }

  async head() {
    const rec = await this.#live();
    if (!rec || rec.state !== 'active') return { status: 'gone' };
    return { status: 'ok', head: { v: rec.paste.v, adata: rec.paste.adata, meta: this.#metaOut(rec) }, padded: rec.padded, chunks: rec.chunks };
  }

  /**
   * Verify proofs, spend a view, register a grant (hash) valid for grantSec.
   * `client` is an opaque hash of the caller's tracking key (never an IP).
   */
  async open(lh, kh, grantHash, grantSec, client = '') {
    return this.ctx.blockConcurrencyWhile(async () => {
      const rec = await this.#live();
      if (!rec || rec.state !== 'active') return { status: 'gone' };
      if (!safeEq(lh, rec.acc.lh)) return { status: 'bad_link' };
      if (!safeEq(kh, rec.acc.kh)) return { status: 'bad_password' };
      const t = nowSec();
      let grants = await this.#grants(rec, t);
      const mine = grants.filter((g) => client && g.c === client);
      if (mine.length >= MAX_GRANTS_PER_CLIENT) {
        const oldest = mine.reduce((a, b) => (b.exp < a.exp ? b : a));
        grants = grants.filter((g) => g !== oldest);
      } else if (grants.length >= MAX_ACTIVE_GRANTS) {
        return { status: 'busy' };
      }
      const gexp = Math.min(t + grantSec, rec.expires);
      grants.push({ h: grantHash, exp: gexp, c: client });
      // Grants now live under GRANTS_KEY; an empty inline array keeps records
      // readable by the previous release if a deploy is rolled back.
      rec.grants = [];
      if (rec.left !== null) {
        rec.left -= 1;
        if (rec.left <= 0) {
          rec.left = 0;
          rec.state = 'closed';
          rec.purgeAt = grants.reduce((m, g) => Math.max(m, g.exp), t);
          await this.ctx.storage.setAlarm(rec.purgeAt * 1000);
        }
      }
      await this.ctx.storage.put(GRANTS_KEY, grants);
      await this.#put(rec);
      const p = rec.paste;
      return {
        status: 'ok',
        paste: { v: p.v, ct: p.ct, wk: p.wk, adata: p.adata, meta: this.#metaOut(rec) },
        grantExpires: gexp, chunks: rec.chunks, padded: rec.padded,
      };
    });
  }

  /** "Delete now" by someone holding both proofs, when the sender allowed it. */
  async expireByOpener(lh, kh) {
    return this.ctx.blockConcurrencyWhile(async () => {
      // Only an active share: after its last view, downloads already granted
      // run out on their own and are not cut short by a recipient.
      const rec = await this.#live();
      if (!rec || rec.state !== 'active') return { status: 'gone' };
      if (!safeEq(lh, rec.acc.lh)) return { status: 'bad_link' };
      if (!safeEq(kh, rec.acc.kh)) return { status: 'bad_password' };
      if (rec.paste.meta.deletable !== true) return { status: 'not_allowed' };
      await this.#purge(rec);
      return { status: 'ok' };
    });
  }

  /** Is `grantHash` currently valid for chunk i? */
  async chunkAccess(grantHash, i) {
    const rec = await this.#live();
    if (!rec || rec.state === 'pending') return { status: 'gone' };
    if (!Number.isInteger(i) || i < 0 || i >= rec.chunks) return { status: 'bad_index' };
    if (!(await this.#grants(rec)).some((g) => safeEq(g.h, grantHash))) return { status: 'bad_grant' };
    return { status: 'ok', key: r2Key(rec.id, i) };
  }

  // ── owner / delete ────────────────────────────────────────────────────────
  async status() {
    const rec = await this.#live();
    if (!rec) return { status: 'gone' };
    if (rec.state === 'pending') return { status: 'pending' };
    return { status: rec.state === 'closed' ? 'gone' : 'ok', views: rec.views, left: rec.left, expires: rec.expires };
  }

  async extend({ views, expires }) {
    return this.ctx.blockConcurrencyWhile(async () => {
      const rec = await this.#live();
      if (!rec || rec.state !== 'active') return { status: 'gone' };
      if (views !== undefined) {
        if (!rec.paste.adata.bar && views !== null) return { status: 'invalid', message: 'This share already has unlimited views.' };
        if (rec.views === null && views !== null) return { status: 'invalid', message: 'Views are already unlimited.' };
        if (views !== null && views <= rec.views) return { status: 'invalid', message: 'Views can only be increased.' };
        const used = rec.views === null ? 0 : rec.views - rec.left;
        rec.views = views;
        rec.left = views === null ? null : views - used;
        if (rec.paste.meta.views !== undefined || views !== null) rec.paste.meta.views = views;
      }
      if (expires !== undefined) {
        if (expires <= rec.expires) return { status: 'invalid', message: 'Expiry can only be extended.' };
        rec.expires = expires;
        rec.paste.meta.expires = expires;
        await this.ctx.storage.setAlarm(expires * 1000);
      }
      await this.#put(rec);
      return { status: 'ok', views: rec.views, left: rec.left, expires: rec.expires };
    });
  }

  async remove(token) {
    return this.ctx.blockConcurrencyWhile(async () => {
      const rec = await this.#live();
      if (!rec) return { status: 'notfound' };
      if (!(await verifyToken(token, rec.dth))) return { status: 'bad' };
      await this.#purge(rec);
      return { status: 'ok' };
    });
  }

  async revoke() {
    return this.ctx.blockConcurrencyWhile(async () => {
      await this.#purge(await this.#rec());
      return { status: 'ok' };
    });
  }

  async alarm() {
    const rec = await this.#rec();
    if (!rec) { await this.ctx.storage.deleteAll(); return; }
    const t = nowSec();
    const due = (rec.state === 'pending' && t >= rec.deadline)
      || (rec.state === 'active' && t >= rec.expires)
      || (rec.state === 'closed' && t >= rec.purgeAt);
    if (due) { await this.#purge(rec); return; }
    const next = rec.state === 'pending' ? rec.deadline : rec.state === 'closed' ? rec.purgeAt : rec.expires;
    await this.ctx.storage.setAlarm(next * 1000);
  }
}
