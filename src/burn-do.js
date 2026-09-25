// burn-do.js — BurnPaste Durable Object: view-limited pastes (SPEC.md §8,
// extended). One DO instance per paste id. Because a DO is single-threaded and
// every mutation runs inside blockConcurrencyWhile, each read-and-decrement is
// atomic: exactly `views` consumers get the ciphertext, everyone after that
// gets "gone", and the record is purged on the last view.

import { DurableObject } from 'cloudflare:workers';
import { verifyToken } from './lib/ids.js';
import { MAX_VIEWS } from '../public/js/format.js';

const KEY = 'rec';

/** Views remaining on a stored record. Records written before view limits existed hold no `left` → 1. */
function leftOf(rec) {
  return Number.isInteger(rec.left) && rec.left > 0 ? rec.left : 1;
}

/** Copy of the stored meta with the live remaining-view count attached. */
function metaWithLeft(meta, left) {
  const out = { expire: meta.expire, created: meta.created };
  if (meta.views !== undefined) out.views = meta.views;
  out.left = left;
  return out;
}

export class BurnPaste extends DurableObject {
  /**
   * Store a view-limited paste. Returns false if this instance already holds one
   * (an id collision), so the caller can regenerate the id. `paste` excludes
   * `dth`, which is stored separately and never returned to a reader.
   */
  async create(paste, dth, ttlSec, views = 1) {
    return this.ctx.blockConcurrencyWhile(async () => {
      if (await this.ctx.storage.get(KEY)) return false;
      const left = Number.isInteger(views) && views >= 1 && views <= MAX_VIEWS ? views : 1;
      const exp = ttlSec > 0 ? Date.now() + ttlSec * 1000 : 0;
      await this.ctx.storage.put(KEY, { paste, dth, exp, left });
      if (exp > 0) await this.ctx.storage.setAlarm(exp);
      return true;
    });
  }

  /**
   * Non-consuming metadata read: returns the paste head (everything EXCEPT the
   * ciphertext `ct`) so the client can verify a password before spending a
   * view. Does not decrement. The content itself is never released here.
   */
  async peek() {
    return this.ctx.blockConcurrencyWhile(async () => {
      const rec = await this.ctx.storage.get(KEY);
      if (!rec) return { status: 'gone' };
      if (rec.exp && Date.now() > rec.exp) { await this.#purge(); return { status: 'gone' }; }
      const p = rec.paste;
      return { status: 'ok', head: { v: p.v, wk: p.wk, adata: p.adata, meta: metaWithLeft(p.meta, leftOf(rec)) } };
    });
  }

  /**
   * Atomically spend one view and return the paste. The last view purges the
   * record. { status:'ok', paste } while views remain, then 'gone'.
   */
  async consume() {
    return this.ctx.blockConcurrencyWhile(async () => {
      const rec = await this.ctx.storage.get(KEY);
      if (!rec) return { status: 'gone' };
      if (rec.exp && Date.now() > rec.exp) { await this.#purge(); return { status: 'gone' }; }
      const left = leftOf(rec) - 1;
      if (left <= 0) await this.#purge();
      else await this.ctx.storage.put(KEY, { ...rec, left });
      const p = rec.paste;
      return { status: 'ok', paste: { v: p.v, ct: p.ct, wk: p.wk, adata: p.adata, meta: metaWithLeft(p.meta, Math.max(0, left)) } };
    });
  }

  /** Delete via delete token. 'ok' | 'bad' (wrong token) | 'notfound'. */
  async remove(token) {
    return this.ctx.blockConcurrencyWhile(async () => {
      const rec = await this.ctx.storage.get(KEY);
      if (!rec) return { status: 'notfound' };
      if (!(await verifyToken(token, rec.dth))) return { status: 'bad' };
      await this.#purge();
      return { status: 'ok' };
    });
  }

  /** Alarm fires at expiry → drop the paste. */
  async alarm() {
    await this.#purge();
  }

  async #purge() {
    await this.ctx.storage.deleteAll();
    await this.ctx.storage.deleteAlarm();
  }
}
