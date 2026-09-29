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
//
// A Drive share (docs/DRIVE.md §7) is the same record with `refs` — the Drive
// files it references ({ key: 'd/<uid>/<node>', chunks, size }) — instead of
// an uploaded stream: created active, its purge deletes only this record
// (never a d/ object: the Drive owns those), and chunks are read by (ref, i).
//
// A share with the CAPTCHA (`hc`, from the sender's role at creation) serves
// nothing — head, open, "delete now", chunks — unless the Worker has verified
// a CAPTCHA grant for it (`human`); the answer is then 'captcha' and no view
// is spent (src/lib/human.js).
//
// Wrong passwords (a share with one) are counted here, from any network, with
// the proofs (src/lib/sharepw.js): at the rule's count the password is locked,
// and while it is every open and "delete now" is refused ('pw_locked') before
// its password is checked, the right one too. The count has its own key.

import { DurableObject } from 'cloudflare:workers';
import { verifyToken } from './lib/ids.js';
import { timingSafeEqualHex } from '../public/js/bytes.js';
import { CHUNK, TAG } from '../public/js/files.js';
import { PASSWORD_KDF, pwLockedUntil, pwFailed, pwDirty } from './lib/sharepw.js';

const KEY = 'rec';
const PW_KEY = 'pw';
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
// The person downloading may keep their window open longer, this many times
// (WCAG 2.2.1 asks for at least ten), each time by the role's window, never
// past the share's own expiry. It spends no view. When the grant table is full,
// a grant past its first window gives way to a new open (open()).
export const MAX_GRANT_EXTENSIONS = 10;
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
    if (rec && !Array.isArray(rec.refs)) {
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
  async init({ id, uid, uth, dth, padded, views, expire, ttl, pendingSec, deletable = false, hc = false }) {
    return this.ctx.blockConcurrencyWhile(async () => {
      if (await this.#rec()) return false;
      const chunks = Math.ceil(padded / CHUNK);
      const deadline = nowSec() + pendingSec;
      await this.#put({ id, state: 'pending', uid, uth, dth, padded, chunks, sizes: [], views, left: views, expire, ttl, deadline, grants: [], deletable: !!deletable, hc: hc === true });
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
        expire: rec.expire, ttl: rec.ttl, expires, acc, grants: [], hc: rec.hc === true,
        paste: { v: paste.v, ct: paste.ct, wk: paste.wk, adata: paste.adata, meta },
      }; // uid + upload token dropped: the share is no longer linked to the uploader here
      await this.#put(next);
      await this.ctx.storage.setAlarm(expires * 1000);
      return { status: 'ok', created, expires, hc: next.hc };
    });
  }

  /**
   * A Drive share: active at once, referencing Drive files (`refs`) instead of
   * an upload. The encrypted manifest must declare what was authorized.
   */
  async initRefs({ id, dth, refs, views, expire, ttl, deletable = false, paste, acc, hc = false, kinds = null }) {
    return this.ctx.blockConcurrencyWhile(async () => {
      if (await this.#rec()) return { status: 'exists' };
      if (paste.adata.bar !== (views !== null) || paste.meta.expire !== expire
          || (paste.meta.views ?? null) !== views || (paste.meta.deletable === true) !== !!deletable) return { status: 'mismatch' };
      const created = nowSec();
      const expires = created + ttl;
      const meta = { expire, created, expires };
      if (views !== null) meta.views = views;
      if (deletable) meta.deletable = true;
      await this.#put({
        id, state: 'active', dth, padded: 0, chunks: 0, views, left: views, expire, ttl, expires, acc, grants: [], hc: hc === true,
        refs: refs.map((r) => ({ key: r.key, chunks: r.chunks, size: r.size })),
        paste: { v: paste.v, ct: paste.ct, wk: paste.wk, adata: paste.adata, meta },
        // What the sender's role allowed it to share as notes, links and credentials when it was
        // made (the manifest's `item` markers are the sender's; the recipient's page obeys this).
        kinds: { note: kinds?.note === true, url: kinds?.url === true, secret: kinds?.secret === true },
      });
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

  async head(human = false) {
    const rec = await this.#live();
    if (!rec || rec.state !== 'active') return { status: 'gone' };
    if (rec.hc && human !== true) return { status: 'captcha' };
    return { status: 'ok', head: { v: rec.paste.v, adata: rec.paste.adata, meta: this.#metaOut(rec) }, padded: rec.padded, chunks: rec.chunks };
  }

  /**
   * The key proof, after the link proof, under the share's password lockout
   * (`rule`: src/lib/sharepw.js) → null when it is right (the count cleared),
   * else the refusal: { status: 'pw_locked', until } before any check while
   * locked, or { status: 'bad_password', locked } (locked: { until, strike }
   * when this failure locked it). Callers are inside blockConcurrencyWhile.
   */
  async #keyProof(rec, kh, rule) {
    if (rec.paste?.adata?.kdf !== PASSWORD_KDF) return safeEq(kh, rec.acc.kh) ? null : { status: 'bad_password', locked: null };
    const t = nowSec();
    const st = await this.ctx.storage.get(PW_KEY);
    const until = pwLockedUntil(st, t);
    if (until) return { status: 'pw_locked', until };
    if (safeEq(kh, rec.acc.kh)) {
      if (pwDirty(st)) await this.ctx.storage.delete(PW_KEY);
      return null;
    }
    const f = pwFailed(st, rule, t);
    await this.ctx.storage.put(PW_KEY, f.next);
    return { status: 'bad_password', locked: f.locked };
  }

  /**
   * Verify proofs, spend a view, register a grant (hash) valid for grantSec.
   * `client` is an opaque hash of the caller's tracking key (never an IP).
   * `rule`: the password lockout's (#keyProof).
   */
  async open(lh, kh, grantHash, grantSec, client = '', human = false, rule = null) {
    return this.ctx.blockConcurrencyWhile(async () => {
      const rec = await this.#live();
      if (!rec || rec.state !== 'active') return { status: 'gone' };
      if (rec.hc && human !== true) return { status: 'captcha' };
      if (!safeEq(lh, rec.acc.lh)) return { status: 'bad_link' };
      const refused = await this.#keyProof(rec, kh, rule);
      if (refused) return refused;
      const t = nowSec();
      let grants = await this.#grants(rec, t);
      const mine = grants.filter((g) => client && g.c === client);
      if (mine.length >= MAX_GRANTS_PER_CLIENT) {
        const oldest = mine.reduce((a, b) => (b.exp < a.exp ? b : a));
        grants = grants.filter((g) => g !== oldest);
      } else if (grants.length >= MAX_ACTIVE_GRANTS) {
        // A full table: a grant living on an extension (past its first window) gives way to a new
        // open. So keeping a share "busy" still takes a fresh open per slot in every window, as it
        // did before extensions existed; extensions never make that cheaper.
        const extended = grants.filter((g) => Number.isInteger(g.f) && g.f <= t);
        if (!extended.length) return { status: 'busy' };
        const first = extended.reduce((a, b) => (b.exp < a.exp ? b : a));
        grants = grants.filter((g) => g !== first);
      }
      const gexp = Math.min(t + grantSec, rec.expires);
      // `f`: the end of the grant's first window (extensions move `exp`, never `f`).
      grants.push({ h: grantHash, exp: gexp, f: gexp, c: client });
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
      const out = {
        status: 'ok',
        paste: { v: p.v, ct: p.ct, wk: p.wk, adata: p.adata, meta: this.#metaOut(rec) },
        grantExpires: gexp, chunks: rec.chunks, padded: rec.padded,
      };
      if (Array.isArray(rec.refs)) {
        out.refs = rec.refs.map((r) => ({ chunks: r.chunks, size: r.size }));
        // A Drive share made before this record: none of its entries is shown as a note, link or credential.
        out.kinds = { note: rec.kinds?.note === true, url: rec.kinds?.url === true, secret: rec.kinds?.secret === true };
      }
      return out;
    });
  }

  /** "Delete now" by someone holding both proofs, when the sender allowed it. */
  async expireByOpener(lh, kh, human = false, rule = null) {
    return this.ctx.blockConcurrencyWhile(async () => {
      // Only an active share: after its last view, downloads already granted
      // run out on their own and are not cut short by a recipient.
      const rec = await this.#live();
      if (!rec || rec.state !== 'active') return { status: 'gone' };
      if (rec.hc && human !== true) return { status: 'captcha' };
      if (!safeEq(lh, rec.acc.lh)) return { status: 'bad_link' };
      const refused = await this.#keyProof(rec, kh, rule);
      if (refused) return refused;
      if (rec.paste.meta.deletable !== true) return { status: 'not_allowed' };
      await this.#purge(rec);
      return { status: 'ok' };
    });
  }

  /**
   * Keep a live download window open longer (WCAG 2.2.1 Timing Adjustable: the
   * viewer is warned before it closes and may extend it): the grant then ends
   * `grantSec` from now, never past the share's expiry, at most
   * MAX_GRANT_EXTENSIONS times. Spends no view. After the last view (closed)
   * the purge waits for the extended grant.
   */
  async extendGrant(grantHash, grantSec, human = false) {
    return this.ctx.blockConcurrencyWhile(async () => {
      const rec = await this.#live();
      if (!rec || rec.state === 'pending') return { status: 'gone' };
      // A share with the CAPTCHA: only with a CAPTCHA grant, as for its chunks.
      if (rec.hc && human !== true) return { status: 'captcha' };
      const t = nowSec();
      const grants = await this.#grants(rec, t);
      const g = grants.find((x) => safeEq(x.h, grantHash));
      if (!g) return { status: 'bad_grant' };
      const used = Number.isInteger(g.n) ? g.n : 0;
      if (used >= MAX_GRANT_EXTENSIONS) return { status: 'limit', grantExpires: g.exp, extensionsLeft: 0 };
      g.exp = Math.max(g.exp, Math.min(t + grantSec, rec.expires));
      g.n = used + 1;
      await this.ctx.storage.put(GRANTS_KEY, grants);
      if (rec.state === 'closed' && g.exp > rec.purgeAt) {
        rec.purgeAt = g.exp;
        await this.#put(rec);
        await this.ctx.storage.setAlarm(rec.purgeAt * 1000);
      }
      return { status: 'ok', grantExpires: g.exp, extensions: g.n, extensionsLeft: MAX_GRANT_EXTENSIONS - g.n };
    });
  }

  // The grant is checked before the index: without a valid one every chunk
  // request gets the same 'bad_grant' (counted as invalid by the Worker), so
  // the layout (a file share's chunk count, a Drive share's files and theirs)
  // is never told to someone who has not opened the share.

  /** Is `grantHash` currently valid for chunk i? */
  async chunkAccess(grantHash, i, human = false) {
    const rec = await this.#live();
    if (!rec || rec.state === 'pending') return { status: 'gone' };
    if (rec.hc && human !== true) return { status: 'captcha' };
    if (!(await this.#grants(rec)).some((g) => safeEq(g.h, grantHash))) return { status: 'bad_grant' };
    if (!Number.isInteger(i) || i < 0 || i >= rec.chunks) return { status: 'bad_index' };
    return { status: 'ok', key: r2Key(rec.id, i) };
  }

  /** Drive shares: is `grantHash` valid for chunk i of ref `ref`? Returns the Drive object's key. */
  async chunkAccessRef(grantHash, ref, i, human = false) {
    const rec = await this.#live();
    if (!rec || rec.state === 'pending') return { status: 'gone' };
    if (rec.hc && human !== true) return { status: 'captcha' };
    if (!(await this.#grants(rec)).some((g) => safeEq(g.h, grantHash))) return { status: 'bad_grant' };
    if (!Array.isArray(rec.refs) || !Number.isInteger(ref) || ref < 0 || ref >= rec.refs.length) return { status: 'bad_index' };
    const r = rec.refs[ref];
    if (!Number.isInteger(i) || i < 0 || i >= r.chunks) return { status: 'bad_index' };
    return { status: 'ok', key: `${r.key}/${i}` };
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
