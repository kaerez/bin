// burn-do.js — BurnPaste Durable Object: view-limited notes (SPEC.md §8). One
// instance per paste id. Every read-and-decrement runs inside
// blockConcurrencyWhile, so exactly `views` openers get the ciphertext, every
// later opener gets "gone", and the record is purged on the last view.
//
// Access proofs (SPEC.md §5.4) are checked here, atomically with the view
// spend: a wrong link or wrong password never consumes a view. The stored
// record never leaves the object except as the released paste, and the proof
// hashes, the delete-token hash and the owner id never leave it at all.

import { DurableObject } from 'cloudflare:workers';
import { verifyToken } from './lib/ids.js';
import { timingSafeEqualHex } from '../public/js/bytes.js';

const KEY = 'rec';

const safeEq = (a, b) => typeof a === 'string' && typeof b === 'string' && timingSafeEqualHex(a, b);

function metaOut(rec) {
  const m = rec.paste.meta;
  const out = { expire: m.expire, created: m.created, expires: m.expires };
  out.views = rec.views;           // null = raised to unlimited
  out.left = rec.left;
  return out;
}

export class BurnPaste extends DurableObject {
  async #get() {
    const rec = await this.ctx.storage.get(KEY);
    if (!rec || !rec.acc) return null; // pre-v2 records are unreadable by design
    if (rec.exp && Date.now() > rec.exp) { await this.#purge(); return null; }
    return rec;
  }

  /** Store a view-limited paste; false on id collision. */
  async create(record, ttlSec, views) {
    return this.ctx.blockConcurrencyWhile(async () => {
      if (await this.ctx.storage.get(KEY)) return false;
      const exp = ttlSec > 0 ? Date.now() + ttlSec * 1000 : 0;
      await this.ctx.storage.put(KEY, { ...record, exp, views, left: views });
      if (exp > 0) await this.ctx.storage.setAlarm(exp);
      return true;
    });
  }

  /** Non-secret head: { v, adata, meta } — never wk/ct. */
  async head() {
    return this.ctx.blockConcurrencyWhile(async () => {
      const rec = await this.#get();
      if (!rec) return { status: 'gone' };
      const p = rec.paste;
      return { status: 'ok', head: { v: p.v, adata: p.adata, meta: metaOut(rec) } };
    });
  }

  /** Verify both proof hashes, then atomically spend one view and release. */
  async open(lh, kh) {
    return this.ctx.blockConcurrencyWhile(async () => {
      const rec = await this.#get();
      if (!rec) return { status: 'gone' };
      if (!safeEq(lh, rec.acc.lh)) return { status: 'bad_link' };
      if (!safeEq(kh, rec.acc.kh)) return { status: 'bad_password' };
      let left = rec.left;
      if (left !== null) {
        left -= 1;
        if (left <= 0) await this.#purge();
        else await this.ctx.storage.put(KEY, { ...rec, left });
      }
      const p = rec.paste;
      return { status: 'ok', uid: rec.uid, paste: { v: p.v, ct: p.ct, wk: p.wk, adata: p.adata, meta: metaOut({ ...rec, left: left === null ? null : Math.max(0, left) }) } };
    });
  }

  /** Live status for the owner's share list. */
  async status() {
    const rec = await this.#get();
    if (!rec) return { status: 'gone' };
    return { status: 'ok', views: rec.views, left: rec.left, expires: rec.paste.meta.expires };
  }

  /** Raise views (total, or null = unlimited) and/or push expiry later. Never lowers. */
  async extend({ views, expires }) {
    return this.ctx.blockConcurrencyWhile(async () => {
      const rec = await this.#get();
      if (!rec) return { status: 'gone' };
      const next = { ...rec, paste: { ...rec.paste, meta: { ...rec.paste.meta } } };
      if (views !== undefined) {
        if (rec.views === null && views !== null) return { status: 'invalid', message: 'Views are already unlimited.' };
        if (views !== null && views <= rec.views) return { status: 'invalid', message: 'Views can only be increased.' };
        const used = rec.views === null ? 0 : rec.views - rec.left;
        next.views = views;
        next.left = views === null ? null : views - used;
        next.paste.meta.views = views;
      }
      if (expires !== undefined) {
        if (rec.paste.meta.expires && expires <= rec.paste.meta.expires) return { status: 'invalid', message: 'Expiry can only be extended.' };
        next.exp = expires * 1000;
        next.paste.meta.expires = expires;
        await this.ctx.storage.setAlarm(next.exp);
      }
      await this.ctx.storage.put(KEY, next);
      return { status: 'ok', views: next.views, left: next.left, expires: next.paste.meta.expires };
    });
  }

  /** Delete via delete token. 'ok' | 'bad' | 'notfound'. */
  async remove(token) {
    return this.ctx.blockConcurrencyWhile(async () => {
      const rec = await this.#get();
      if (!rec) return { status: 'notfound' };
      if (!(await verifyToken(token, rec.dth))) return { status: 'bad' };
      await this.#purge();
      return { status: 'ok' };
    });
  }

  /** Owner revocation (authorization is checked by the Worker). */
  async revoke() {
    return this.ctx.blockConcurrencyWhile(async () => {
      await this.#purge();
      return { status: 'ok' };
    });
  }

  async alarm() {
    await this.#purge();
  }

  async #purge() {
    await this.ctx.storage.deleteAll();
    await this.ctx.storage.deleteAlarm();
  }
}
