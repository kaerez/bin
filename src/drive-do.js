// drive-do.js — the Drive Durable Object: one SQLite-backed instance per user
// (idFromName('drive:' + userId)) holding that user's private folder tree, the
// wraps of their Drive key, and which shares reference which items. See
// docs/DRIVE.md.
//
// What it stores is opaque: names, file metadata and file keys arrive already
// encrypted by the browser ({iv, ct}); the key wraps cannot be opened here.
// It sees only the tree's shape, each file's size and chunk count, and times.
//
// It is the only code that deletes Drive ciphertext in R2
// (d/<userId>/<nodeId>/<i>): on delete (recursive), on the pending-upload
// purge (alarm) and when the whole Drive goes (account deleted). File-share
// purges never touch d/ objects.
//
// Every method runs its SQL synchronously; the ones that also touch R2 run
// inside blockConcurrencyWhile, so the tree never changes between choosing
// what to delete and deleting it.

import { DurableObject } from 'cloudflare:workers';
import { timingSafeEqualHex } from '../public/js/bytes.js';
import { CHUNK, TAG } from '../public/js/files.js';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY, parent TEXT, kind TEXT NOT NULL CHECK(kind IN ('dir','file')),
  name TEXT NOT NULL, meta TEXT, size INTEGER NOT NULL DEFAULT 0, chunks INTEGER NOT NULL DEFAULT 0, fk TEXT,
  state TEXT NOT NULL CHECK(state IN ('pending','ready')), done INTEGER NOT NULL DEFAULT 0, upload_hash TEXT,
  created INTEGER NOT NULL, updated INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS nodes_parent ON nodes(parent);
CREATE INDEX IF NOT EXISTS nodes_state ON nodes(state, updated);
CREATE TABLE IF NOT EXISTS wraps (kind TEXT NOT NULL, ref TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (kind, ref));
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS refs (share_id TEXT NOT NULL, node_id TEXT NOT NULL, PRIMARY KEY (share_id, node_id));
CREATE INDEX IF NOT EXISTS refs_node ON refs(node_id);
CREATE TABLE IF NOT EXISTS upchunks (node_id TEXT NOT NULL, i INTEGER NOT NULL, PRIMARY KEY (node_id, i));
`;

export const ROOT = 'root';
/** Node ids: 16 random bytes, base64url (chosen by the browser so it can bind encrypted fields to them). */
export const NODE_ID_RE = /^[A-Za-z0-9_-]{22}$/;
/** Hard ceilings per Drive: items, items in one folder, folder nesting, key wraps. */
export const MAX_NODES = 100000;
export const MAX_CHILDREN = 10000;
export const MAX_DEPTH = 64;
export const MAX_WRAPS = 64;
/** Shares referencing one item at most (each share is a separate link). */
export const MAX_SHARES_PER_NODE = 1000;

const nowSec = () => Math.floor(Date.now() / 1000);
const safeEq = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && timingSafeEqualHex(a, b);

/** Chunks of a Drive file of `size` plaintext bytes (an empty file has none). */
export const driveChunks = (size) => Math.ceil(size / CHUNK);
/** Exact ciphertext size of chunk i (files are not padded). */
export const driveChunkSize = (size, i) => Math.min(CHUNK, size - i * CHUNK) + TAG;
/** R2 prefix of a Drive file, and one chunk's key. */
export const driveKey = (uid, node) => `d/${uid}/${node}`;
export const driveChunkKey = (uid, node, i) => `${driveKey(uid, node)}/${i}`;

const fail = (status, error, message, extra) => ({ ok: false, status, error, message, ...(extra || {}) });

export class Drive extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    /** Chunk writes in flight per node id (finalize waits for them: they may be retries of a chunk already stored). */
    this.inflight = new Map();
    ctx.blockConcurrencyWhile(async () => this.#init());
  }

  /** The tables and the root (again after destroy(), so a late call finds an empty Drive, not missing tables). */
  #init() {
    this.sql.exec(SCHEMA);
    const t = nowSec();
    this.sql.exec("INSERT OR IGNORE INTO nodes (id, parent, kind, name, state, created, updated) VALUES (?, NULL, 'dir', 'null', 'ready', ?, ?)", ROOT, t, t);
  }

  // ── helpers ───────────────────────────────────────────────────────────────
  #meta(k) {
    const r = this.sql.exec('SELECT v FROM meta WHERE k = ?', k).toArray()[0];
    return r ? r.v : null;
  }
  #setMeta(k, v) {
    if (v === null) this.sql.exec('DELETE FROM meta WHERE k = ?', k);
    else this.sql.exec('INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v', k, v);
  }
  /**
   * Every call names the user; the first one binds this object to it. The
   * Worker derives the object from the same id, so a mismatch is a bug —
   * refuse rather than mix two users' data.
   */
  #bind(uid) {
    if (typeof uid !== 'string' || !uid) throw new Error('drive: missing user');
    if (this.destroyed) { this.destroyed = false; this.#init(); } // a call after destroy(): an empty Drive again
    const have = this.#meta('uid');
    if (have === null) this.#setMeta('uid', uid);
    else if (have !== uid) throw new Error('drive: wrong user');
  }
  #node(id) {
    return this.sql.exec('SELECT * FROM nodes WHERE id = ?', id).toArray()[0] || null;
  }
  /**
   * Bytes charged to the Drive's capacity: every file's size plus the sealed
   * names, metadata and file keys of every item (docs/DRIVE.md §10), so the
   * encrypted fields cannot store data outside the capacity.
   */
  #used() {
    return this.sql.exec(`SELECT COALESCE(SUM(CASE WHEN kind = 'file' THEN size ELSE 0 END), 0)
      + COALESCE(SUM(LENGTH(name) + COALESCE(LENGTH(meta), 0) + COALESCE(LENGTH(fk), 0)), 0) AS s FROM nodes WHERE id != ?`, ROOT).one().s;
  }
  /** Refused when `extra` more bytes would not fit in `capacity` (null: no check). */
  #fits(extra, capacity) {
    if (capacity === null || capacity === undefined) return null;
    const used = this.#used();
    return used + extra > capacity ? fail(413, 'drive_full', 'Not enough space left in your Drive.', { max: capacity, used }) : null;
  }
  #count() {
    return this.sql.exec('SELECT COUNT(*) AS c FROM nodes').one().c;
  }
  /** Ancestors of `id` from the root down (excluding `id`). */
  #ancestors(id) {
    const rows = this.sql.exec(`WITH RECURSIVE anc(id, parent, lvl) AS (
        SELECT id, parent, 0 FROM nodes WHERE id = ?
        UNION ALL SELECT n.id, n.parent, anc.lvl + 1 FROM nodes n JOIN anc ON n.id = anc.parent WHERE anc.lvl < ?)
      SELECT n.* FROM anc JOIN nodes n ON n.id = anc.id WHERE anc.lvl > 0 ORDER BY anc.lvl DESC`, id, MAX_DEPTH + 2).toArray();
    return rows;
  }
  /** Depth of a folder (the root is 0). */
  #depth(id) {
    return this.#ancestors(id).length;
  }
  /** `id` and every node below it. */
  #subtree(id) {
    return this.sql.exec(`WITH RECURSIVE sub(id) AS (SELECT ? UNION ALL SELECT n.id FROM nodes n JOIN sub ON n.parent = sub.id)
      SELECT n.* FROM sub JOIN nodes n ON n.id = sub.id`, id).toArray();
  }
  /** How many folder levels a subtree adds below its top (a lone file or empty folder: 0). */
  #height(id) {
    return this.sql.exec(`WITH RECURSIVE sub(id, lvl) AS (SELECT ?, 0 UNION ALL SELECT n.id, sub.lvl + 1 FROM nodes n JOIN sub ON n.parent = sub.id)
      SELECT MAX(lvl) AS h FROM sub`, id).one().h ?? 0;
  }
  #out(r) {
    const parse = (v) => { try { return JSON.parse(v); } catch { return null; } };
    const o = {
      id: r.id, parent: r.parent, kind: r.kind, name: r.id === ROOT ? null : parse(r.name), created: r.created, updated: r.updated,
    };
    if (r.kind === 'file') {
      Object.assign(o, { meta: r.meta ? parse(r.meta) : null, size: r.size, chunks: r.chunks, fk: r.fk ? parse(r.fk) : null, state: r.state });
      if (r.state === 'pending') o.done = this.sql.exec('SELECT COUNT(*) AS c FROM upchunks WHERE node_id = ?', r.id).one().c;
    } else {
      o.meta = r.meta ? parse(r.meta) : null;
    }
    return o;
  }
  /** Can `parent` take one more child? Returns a failure or null. */
  #checkParent(parent) {
    const p = this.#node(parent);
    if (!p) return fail(404, 'not_found', 'The folder does not exist.');
    if (p.kind !== 'dir') return fail(400, 'not_a_folder', 'Items can only be put in a folder.');
    if (this.sql.exec('SELECT COUNT(*) AS c FROM nodes WHERE parent = ?', parent).one().c >= MAX_CHILDREN) {
      return fail(409, 'folder_full', `A folder holds at most ${MAX_CHILDREN} items.`);
    }
    return null;
  }
  #checkNew(id) {
    if (this.#count() >= MAX_NODES) return fail(409, 'drive_full', `A Drive holds at most ${MAX_NODES} items.`);
    if (this.#node(id)) return fail(409, 'exists', 'An item with this id already exists.');
    return null;
  }
  /** Delete R2 objects of the given file rows (every chunk slot, uploaded or not). */
  async #deleteObjects(uid, files) {
    const keys = [];
    for (const f of files) for (let i = 0; i < f.chunks; i++) keys.push(driveChunkKey(uid, f.id, i));
    if (!keys.length) return;
    const r2 = this.env.FILES;
    if (!r2 || typeof r2.delete !== 'function') throw new Error('FILES binding missing: cannot delete Drive chunks');
    for (let i = 0; i < keys.length; i += 1000) await r2.delete(keys.slice(i, i + 1000));
  }
  async #schedulePurge() {
    const sec = Number(this.#meta('pendingSec')) || 3600;
    const r = this.sql.exec("SELECT MIN(updated) AS t FROM nodes WHERE state = 'pending'").one();
    if (r.t === null) return;
    const at = (r.t + sec) * 1000;
    const cur = await this.ctx.storage.getAlarm();
    if (cur === null || cur > at) await this.ctx.storage.setAlarm(at);
  }
  async #reportUsage() {
    try {
      const ns = this.env.DIRECTORY;
      const uid = this.#meta('uid');
      if (ns && uid) await ns.get(ns.idFromName('directory')).setDriveUsed(uid, this.#used());
    } catch (e) {
      console.warn('secbin: drive usage not reported', e && e.message ? e.message : e);
    }
  }

  // ── summary and keys ──────────────────────────────────────────────────────
  async summary(uid) {
    this.#bind(uid);
    const wraps = this.sql.exec('SELECT kind, ref, data FROM wraps ORDER BY kind, ref').toArray().map((w) => ({ kind: w.kind, ref: w.ref, data: w.data }));
    return {
      used: this.#used(),
      items: this.#count() - 1,
      driveSalt: this.#meta('driveSalt'),
      wraps,
      escrowPriv: this.#meta('escrowPriv'),
      escrowPin: this.#meta('escrowPin'),
      handoffKey: this.#meta('handoffKey'),
      pwStale: this.#meta('pwStale') === '1',
      content: this.#hasContent(),
    };
  }

  #hasContent() {
    return this.sql.exec('SELECT 1 FROM nodes WHERE parent = ? LIMIT 1', ROOT).toArray().length > 0;
  }

  /**
   * Change the key material: `set` / `remove` wraps, the Drive salt, the
   * sealed escrow pin (the escrow key this Drive trusts), the one-time
   * hand-over key and (the owner's Drive only — the Worker checks) the
   * encrypted escrow private key. Values arrive validated; `data`,
   * `escrowPriv` and `escrowPin` are opaque. Writing a `pw` wrap ends a
   * pending hand-over and the "stale password wrap" mark. A change that would
   * leave a Drive with content and no wrap at all is refused: nothing could
   * open it again.
   */
  async setKeys(uid, { driveSalt, set = [], remove = [], escrowPriv, escrowPin, handoffKey } = {}) {
    this.#bind(uid);
    const has = (k, r) => this.sql.exec('SELECT 1 FROM wraps WHERE kind = ? AND ref = ?', k, r).toArray().length > 0;
    const newPw = set.some((w) => w.kind === 'pw');
    const dropHandoff = newPw && has('handoff', 'handoff') && !set.some((w) => w.kind === 'handoff');
    const rm = dropHandoff ? [...remove, { kind: 'handoff', ref: 'handoff' }] : remove;
    const total = this.sql.exec('SELECT COUNT(*) AS c FROM wraps').one().c;
    const removed = rm.filter((w) => has(w.kind, w.ref) && !set.some((x) => x.kind === w.kind && x.ref === w.ref)).length;
    const added = set.filter((w) => !has(w.kind, w.ref)).length;
    const after = total - removed + added;
    if (after > MAX_WRAPS) return fail(409, 'too_many_wraps', `At most ${MAX_WRAPS} key wraps.`);
    if (after === 0 && total > 0 && this.#hasContent()) return fail(409, 'last_wrap', 'This would leave your Drive with no way to open it.');
    this.ctx.storage.transactionSync(() => {
      for (const w of rm) this.sql.exec('DELETE FROM wraps WHERE kind = ? AND ref = ?', w.kind, w.ref);
      for (const w of set) {
        this.sql.exec('INSERT INTO wraps (kind, ref, data) VALUES (?, ?, ?) ON CONFLICT(kind, ref) DO UPDATE SET data = excluded.data', w.kind, w.ref, w.data);
      }
      if (driveSalt !== undefined) this.#setMeta('driveSalt', driveSalt);
      if (escrowPriv !== undefined) this.#setMeta('escrowPriv', escrowPriv);
      if (escrowPin !== undefined) this.#setMeta('escrowPin', escrowPin);
      if (handoffKey !== undefined) this.#setMeta('handoffKey', handoffKey);
      if (newPw) this.#setMeta('pwStale', null);
      if (dropHandoff) this.#setMeta('handoffKey', null);
    });
    return { ok: true };
  }

  /**
   * The account's password changed (`reset`: set by the owner). The `pw` wrap
   * still opens with the old password, which may be the compromised one: after
   * a reset it goes at once when another wrap the user can open (a passkey or
   * a recovery code) remains, else it is marked stale; after the user's own
   * change it is marked stale (their browser writes the new one right away).
   * A stale wrap may be replaced without the step-up, and goes when it is.
   */
  async passwordChanged(uid, { reset = false } = {}) {
    this.#bind(uid);
    if (!this.sql.exec("SELECT 1 FROM wraps WHERE kind = 'pw'").toArray().length) return { ok: true, pw: 'none' };
    const other = this.sql.exec("SELECT COUNT(*) AS c FROM wraps WHERE kind IN ('passkey', 'recovery')").one().c > 0;
    if (reset && other) {
      this.ctx.storage.transactionSync(() => {
        this.sql.exec("DELETE FROM wraps WHERE kind = 'pw'");
        this.#setMeta('pwStale', '1'); // no pw wrap: the next one is written without a step-up
      });
      return { ok: true, pw: 'removed' };
    }
    this.#setMeta('pwStale', '1');
    return { ok: true, pw: 'stale' };
  }

  /** Remove wraps by kind (and optionally one ref) — the server's side of passkey / code removal. */
  async removeWraps(uid, kind, ref = null) {
    this.#bind(uid);
    if (ref === null) this.sql.exec('DELETE FROM wraps WHERE kind = ?', kind);
    else this.sql.exec('DELETE FROM wraps WHERE kind = ? AND ref = ?', kind, ref);
    return { ok: true };
  }

  /** Keep only the passkey / recovery wraps whose credential the account still has; → the wraps removed. */
  async pruneWraps(uid, { passkey = [], recovery = [] } = {}) {
    this.#bind(uid);
    const keep = { passkey: new Set(passkey), recovery: new Set(recovery) };
    const gone = [];
    for (const w of this.sql.exec("SELECT kind, ref, data FROM wraps WHERE kind IN ('passkey', 'recovery')").toArray()) {
      if (!keep[w.kind].has(w.ref)) { this.sql.exec('DELETE FROM wraps WHERE kind = ? AND ref = ?', w.kind, w.ref); gone.push({ kind: w.kind, ref: w.ref, data: w.data }); }
    }
    return { ok: true, removed: gone.length, wraps: gone };
  }

  /** The escrow wrap and the list of wraps, for the owner's escrow route. */
  async escrowView(uid) {
    this.#bind(uid);
    const s = await this.summary(uid);
    return { wrap: s.wraps.find((w) => w.kind === 'escrow') || null, wraps: s.wraps };
  }

  // ── tree ──────────────────────────────────────────────────────────────────
  async getNode(uid, id) {
    this.#bind(uid);
    const n = this.#node(id);
    if (!n) return fail(404, 'not_found', 'No such item.');
    const children = n.kind === 'dir'
      ? this.sql.exec("SELECT * FROM nodes WHERE parent = ? ORDER BY kind = 'file', created, id", id).toArray().map((r) => this.#out(r))
      : [];
    const path = this.#ancestors(id).map((r) => this.#out(r));
    return { ok: true, node: this.#out(n), children, path };
  }

  /** A folder; its sealed name (and meta) count towards the capacity. */
  async createFolder(uid, { id, parent, name, meta = null, capacity = null }) {
    this.#bind(uid);
    const bad = this.#checkNew(id) || this.#checkParent(parent) || this.#fits(name.length + (meta ? meta.length : 0), capacity);
    if (bad) return bad;
    if (this.#depth(parent) + 1 > MAX_DEPTH) return fail(409, 'too_deep', `Folders nest at most ${MAX_DEPTH} levels.`);
    const t = nowSec();
    this.sql.exec("INSERT INTO nodes (id, parent, kind, name, meta, state, created, updated) VALUES (?, ?, 'dir', ?, ?, 'ready', ?, ?)", id, parent, name, meta, t, t);
    return { ok: true, id, used: this.#used() };
  }

  /**
   * Reserve a file: capacity and the largest-file limit are checked here, at
   * once, against every file already stored or being uploaded (and the
   * sealed fields of every item, this one's included).
   */
  async createFile(uid, { id, parent, name, meta = null, size, fk, uploadHash, capacity, maxFile, pendingSec }) {
    this.#bind(uid);
    const bad = this.#checkNew(id) || this.#checkParent(parent);
    if (bad) return bad;
    if (size > maxFile) return fail(413, 'file_too_large', `A Drive file may be at most ${maxFile} bytes.`, { max: maxFile });
    const used = this.#used();
    const extra = size + name.length + (meta ? meta.length : 0) + fk.length;
    if (used + extra > capacity) return fail(413, 'drive_full', 'Not enough space left in your Drive.', { max: capacity, used });
    const chunks = driveChunks(size);
    const t = nowSec();
    this.sql.exec("INSERT INTO nodes (id, parent, kind, name, meta, size, chunks, fk, state, upload_hash, created, updated) VALUES (?, ?, 'file', ?, ?, ?, ?, ?, 'pending', ?, ?, ?)",
      id, parent, name, meta, size, chunks, fk, uploadHash, t, t);
    this.#setMeta('pendingSec', String(pendingSec));
    await this.#schedulePurge();
    return { ok: true, id, chunks, used: used + extra };
  }

  #pending(id, uploadHash) {
    const n = this.#node(id);
    if (!n || n.kind !== 'file' || n.state !== 'pending') return { status: 'gone' };
    if (!safeEq(uploadHash, n.upload_hash)) return { status: 'forbidden' };
    return { status: 'ok', n };
  }

  /**
   * Store chunk i of a pending file (exact size), then record it — or undo the
   * write if the upload ended meanwhile (deleted, purged, the Drive
   * destroyed). While the write is in flight the file cannot be finalized
   * (finalize answers "busy"), so a late retry never lands on a complete file.
   */
  async putChunk(uid, id, uploadHash, i, bytes) {
    this.#bind(uid);
    const c = this.#pending(id, uploadHash);
    if (c.status !== 'ok') return c;
    if (!Number.isInteger(i) || i < 0 || i >= c.n.chunks) return { status: 'bad_index' };
    const expected = driveChunkSize(c.n.size, i);
    if (!bytes || bytes.byteLength !== expected) return { status: 'bad_size', expected };
    const key = driveChunkKey(uid, id, i);
    this.inflight.set(id, (this.inflight.get(id) || 0) + 1);
    try {
      await this.env.FILES.put(key, bytes, { httpMetadata: { contentType: 'application/octet-stream' } });
      let again;
      try { again = this.destroyed ? { status: 'gone' } : this.#pending(id, uploadHash); } catch { again = { status: 'gone' }; } // tables dropped by destroy()
      if (again.status !== 'ok') {
        // The upload ended while the write was in flight: leave nothing behind
        // (a file that is complete keeps its chunks — it cannot be, see finalize).
        let ready = false;
        try { const n = this.destroyed ? null : this.#node(id); ready = !!n && n.state === 'ready'; } catch { /* the Drive is gone */ }
        if (!ready) await this.env.FILES.delete(key);
        return { status: 'gone' };
      }
      this.sql.exec('INSERT OR IGNORE INTO upchunks (node_id, i) VALUES (?, ?)', id, i);
      this.sql.exec('UPDATE nodes SET done = (SELECT COUNT(*) FROM upchunks WHERE node_id = ?), updated = ? WHERE id = ?', id, nowSec(), id);
    } finally {
      const left = (this.inflight.get(id) || 1) - 1;
      if (left > 0) this.inflight.set(id, left); else this.inflight.delete(id);
    }
    await this.#schedulePurge();
    return { status: 'ok' };
  }

  async finalize(uid, id, uploadHash) {
    this.#bind(uid);
    const c = this.#pending(id, uploadHash);
    if (c.status !== 'ok') return c;
    // A chunk still being written (e.g. the first attempt of a chunk the client retried): not yet.
    if (this.inflight.get(id)) return { status: 'busy' };
    const have = new Set(this.sql.exec('SELECT i FROM upchunks WHERE node_id = ?', id).toArray().map((r) => r.i));
    for (let i = 0; i < c.n.chunks; i++) if (!have.has(i)) return { status: 'incomplete', missing: i };
    this.ctx.storage.transactionSync(() => {
      this.sql.exec("UPDATE nodes SET state = 'ready', done = chunks, upload_hash = NULL, updated = ? WHERE id = ?", nowSec(), id);
      this.sql.exec('DELETE FROM upchunks WHERE node_id = ?', id);
    });
    return { status: 'ok' };
  }

  /** The R2 key of chunk i of a ready file of this Drive. */
  async chunkKey(uid, id, i) {
    this.#bind(uid);
    const n = this.#node(id);
    if (!n || n.kind !== 'file' || n.state !== 'ready') return { status: 'gone' };
    if (!Number.isInteger(i) || i < 0 || i >= n.chunks) return { status: 'bad_index' };
    return { status: 'ok', key: driveChunkKey(uid, id, i), size: driveChunkSize(n.size, i) };
  }

  /** Move (`parent`) and / or rename (`name`, `meta`) an item. The root can do neither. */
  async patchNode(uid, id, { parent, name, meta, capacity = null }) {
    this.#bind(uid);
    if (id === ROOT) return fail(400, 'root', 'The top folder cannot be moved or renamed.');
    const n = this.#node(id);
    if (!n) return fail(404, 'not_found', 'No such item.');
    // Longer sealed fields take more of the capacity.
    const grow = (name !== undefined ? name.length - n.name.length : 0) + (meta !== undefined ? (meta ? meta.length : 0) - (n.meta ? n.meta.length : 0) : 0);
    if (grow > 0) {
      const full = this.#fits(grow, capacity);
      if (full) return full;
    }
    if (parent !== undefined && parent !== n.parent) {
      const bad = this.#checkParent(parent);
      if (bad) return bad;
      // A folder cannot go into itself or anything below it.
      if (parent === id || this.#ancestors(parent).some((a) => a.id === id)) return fail(409, 'cycle', 'A folder cannot be moved into itself or one of its sub-folders.');
      if (this.#depth(parent) + 1 + this.#height(id) > MAX_DEPTH) return fail(409, 'too_deep', `Folders nest at most ${MAX_DEPTH} levels.`);
    }
    const t = nowSec();
    this.ctx.storage.transactionSync(() => {
      if (parent !== undefined) this.sql.exec('UPDATE nodes SET parent = ?, updated = ? WHERE id = ?', parent, t, id);
      if (name !== undefined) this.sql.exec('UPDATE nodes SET name = ?, updated = ? WHERE id = ?', name, t, id);
      if (meta !== undefined) this.sql.exec('UPDATE nodes SET meta = ?, updated = ? WHERE id = ?', meta, t, id);
    });
    return { ok: true, used: this.#used() };
  }

  /**
   * Delete an item and everything below it: its R2 objects first, then the
   * rows. Returns the shares that referenced any of it (the Worker ends them)
   * and the Drive's new usage.
   */
  async deleteNode(uid, id) {
    this.#bind(uid);
    if (id === ROOT) return fail(400, 'root', 'The top folder cannot be deleted.');
    return this.ctx.blockConcurrencyWhile(async () => {
      if (!this.#node(id)) return fail(404, 'not_found', 'No such item.');
      const rows = this.#subtree(id);
      await this.#deleteObjects(uid, rows.filter((r) => r.kind === 'file'));
      const ids = rows.map((r) => r.id);
      const shares = new Set();
      this.ctx.storage.transactionSync(() => {
        for (let k = 0; k < ids.length; k += 100) {
          const part = ids.slice(k, k + 100);
          const q = part.map(() => '?').join(', ');
          for (const r of this.sql.exec(`SELECT DISTINCT share_id FROM refs WHERE node_id IN (${q})`, ...part).toArray()) shares.add(r.share_id);
          this.sql.exec(`DELETE FROM upchunks WHERE node_id IN (${q})`, ...part);
          this.sql.exec(`DELETE FROM nodes WHERE id IN (${q})`, ...part);
        }
        // An ended share references nothing any more.
        for (const s of shares) this.sql.exec('DELETE FROM refs WHERE share_id = ?', s);
      });
      return { ok: true, deleted: ids.length, shares: [...shares], used: this.#used() };
    });
  }

  // ── shares ────────────────────────────────────────────────────────────────
  /**
   * The share's refs for `ids` — files of this Drive (the browser flattens
   * folders), refs[i] for ids[i]: { node, key, chunks, size }. Every file must
   * exist and be complete; no id twice.
   */
  async shareRefs(uid, ids) {
    this.#bind(uid);
    if (new Set(ids).size !== ids.length) return fail(400, 'duplicate', 'An item is listed twice.');
    const refs = [];
    for (const id of ids) {
      const n = this.#node(id);
      if (!n) return fail(404, 'not_found', 'A file to share does not exist.');
      if (n.kind !== 'file') return fail(400, 'not_a_file', 'List the files to share (a folder\'s files, not the folder).');
      if (n.state !== 'ready') return fail(409, 'not_ready', 'A file to share has not finished uploading.');
      refs.push({ node: n.id, key: driveKey(uid, n.id), chunks: n.chunks, size: n.size });
      if (this.sql.exec('SELECT COUNT(*) AS c FROM refs WHERE node_id = ?', id).one().c >= MAX_SHARES_PER_NODE) {
        return fail(409, 'too_many_shares', `An item can have at most ${MAX_SHARES_PER_NODE} shares.`);
      }
    }
    return { ok: true, refs };
  }

  /** Record that share `shareId` references `ids` — refused if any of them is gone by now. */
  async addRefs(uid, shareId, ids) {
    this.#bind(uid);
    for (const id of ids) if (!this.#node(id)) return fail(409, 'gone', 'An item to share was deleted meanwhile.');
    this.ctx.storage.transactionSync(() => {
      for (const id of ids) this.sql.exec('INSERT OR IGNORE INTO refs (share_id, node_id) VALUES (?, ?)', shareId, id);
    });
    return { ok: true };
  }

  /**
   * Share ids that reference `id` or, for a folder, any file below it (shares
   * reference files only: the browser flattens a shared folder to its files).
   */
  async sharesOf(uid, id) {
    this.#bind(uid);
    if (!this.#node(id)) return fail(404, 'not_found', 'No such item.');
    const rows = this.sql.exec(`WITH RECURSIVE sub(id) AS (SELECT ? UNION ALL SELECT n.id FROM nodes n JOIN sub ON n.parent = sub.id)
      SELECT DISTINCT share_id FROM refs WHERE node_id IN (SELECT id FROM sub)`, id).toArray();
    return { ok: true, shares: rows.map((r) => r.share_id) };
  }

  /** Forget shares that have ended (their rows only; the data stays). */
  async dropRefs(uid, shareIds) {
    this.#bind(uid);
    for (const s of shareIds) this.sql.exec('DELETE FROM refs WHERE share_id = ?', s);
    return { ok: true };
  }

  async usage(uid) {
    this.#bind(uid);
    return { used: this.#used(), items: this.#count() - 1 };
  }

  /** Every share that references this Drive (the account is being deleted: they end first). */
  async allShares(uid) {
    this.#bind(uid);
    return { ok: true, shares: this.sql.exec('SELECT DISTINCT share_id FROM refs').toArray().map((r) => r.share_id) };
  }

  /**
   * The account is deleted: remove every R2 object and all state. Returns the
   * shares that referenced it. Safe to repeat: a failure part-way leaves the
   * rows (a retry deletes the objects again), and a call after it finds an
   * empty Drive.
   */
  async destroy(uid) {
    this.#bind(uid);
    return this.ctx.blockConcurrencyWhile(async () => {
      await this.#deleteObjects(uid, this.sql.exec("SELECT id, chunks FROM nodes WHERE kind = 'file'").toArray());
      const shares = this.sql.exec('SELECT DISTINCT share_id FROM refs').toArray().map((r) => r.share_id);
      await this.ctx.storage.deleteAlarm();
      await this.ctx.storage.deleteAll();
      this.destroyed = true;
      this.inflight.clear();
      return { ok: true, shares };
    });
  }

  // ── pending-upload purge ──────────────────────────────────────────────────
  /** Uploads with no progress for the role's filePendingSec are deleted, with their chunks. */
  async alarm() {
    if (this.destroyed) return;
    const uid = this.#meta('uid');
    if (!uid) return;
    const sec = Number(this.#meta('pendingSec')) || 3600;
    let purged = 0;
    await this.ctx.blockConcurrencyWhile(async () => {
      const stale = this.sql.exec("SELECT id, chunks FROM nodes WHERE kind = 'file' AND state = 'pending' AND updated <= ?", nowSec() - sec).toArray();
      if (!stale.length) return;
      await this.#deleteObjects(uid, stale);
      this.ctx.storage.transactionSync(() => {
        for (const f of stale) {
          this.sql.exec('DELETE FROM upchunks WHERE node_id = ?', f.id);
          this.sql.exec("DELETE FROM nodes WHERE id = ? AND state = 'pending'", f.id);
        }
      });
      purged = stale.length;
    });
    if (purged) await this.#reportUsage();
    await this.#schedulePurge();
  }
}
