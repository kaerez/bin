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
CREATE TABLE IF NOT EXISTS reverse (id TEXT PRIMARY KEY, folder TEXT NOT NULL, priv TEXT NOT NULL, lh TEXT NOT NULL,
  ph TEXT, salt TEXT, t INTEGER, note TEXT, opts TEXT NOT NULL, files INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0,
  created INTEGER NOT NULL, expires INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'active', ended INTEGER);
CREATE TABLE IF NOT EXISTS rsessions (hash TEXT PRIMARY KEY, rid TEXT NOT NULL, expires INTEGER NOT NULL,
  files INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS rsessions_rid ON rsessions(rid);
`;
// Columns added after the Drive first shipped (fresh objects get them from here too).
const COLUMNS = [['nodes', 'rs', 'TEXT']];

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
/** Reverse shares per Drive (ended ones included until their files are taken in), open upload sessions per share, files per share. */
export const MAX_REVERSE = 1000;
export const MAX_SESSIONS = 100;
export const MAX_REVERSE_FILES = 10000;
/** An ended reverse share is kept (for its lists) this long — as long as the share index keeps its row. */
const REVERSE_KEEP_SEC = 30 * 86400;

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
    ctx.blockConcurrencyWhile(async () => {
      this.sql.exec(SCHEMA);
      for (const [table, col, decl] of COLUMNS) {
        const have = new Set(this.sql.exec(`PRAGMA table_info(${table})`).toArray().map((c) => c.name));
        if (!have.has(col)) this.sql.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${decl}`);
      }
      this.sql.exec('CREATE INDEX IF NOT EXISTS nodes_rs ON nodes(rs)');
      const t = nowSec();
      this.sql.exec("INSERT OR IGNORE INTO nodes (id, parent, kind, name, state, created, updated) VALUES (?, NULL, 'dir', 'null', 'ready', ?, ?)", ROOT, t, t);
    });
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
    const have = this.#meta('uid');
    if (have === null) this.#setMeta('uid', uid);
    else if (have !== uid) throw new Error('drive: wrong user');
  }
  #node(id) {
    return this.sql.exec('SELECT * FROM nodes WHERE id = ?', id).toArray()[0] || null;
  }
  #used() {
    return this.sql.exec("SELECT COALESCE(SUM(size), 0) AS s FROM nodes WHERE kind = 'file'").one().s;
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
    const s = this.sql.exec('SELECT MIN(expires) AS t FROM rsessions').one();
    const times = [r.t === null ? null : r.t + sec, s.t].filter((x) => x !== null);
    if (!times.length) return;
    const at = Math.min(...times) * 1000;
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
    return { used: this.#used(), items: this.#count() - 1, driveSalt: this.#meta('driveSalt'), wraps, escrowPriv: this.#meta('escrowPriv'), received: this.#receivedCount() };
  }

  /**
   * Change the key material: `set` / `remove` wraps, the Drive salt and (the
   * owner's Drive only — the Worker checks) the encrypted escrow private key.
   * Values arrive validated; `data` and `escrowPriv` are opaque strings.
   */
  async setKeys(uid, { driveSalt, set = [], remove = [], escrowPriv } = {}) {
    this.#bind(uid);
    const has = (k, r) => this.sql.exec('SELECT 1 FROM wraps WHERE kind = ? AND ref = ?', k, r).toArray().length > 0;
    const total = this.sql.exec('SELECT COUNT(*) AS c FROM wraps').one().c;
    const removed = remove.filter((w) => has(w.kind, w.ref)).length;
    const added = set.filter((w) => !has(w.kind, w.ref) && !remove.some((x) => x.kind === w.kind && x.ref === w.ref)).length;
    if (total - removed + added > MAX_WRAPS) return fail(409, 'too_many_wraps', `At most ${MAX_WRAPS} key wraps.`);
    this.ctx.storage.transactionSync(() => {
      for (const w of remove) this.sql.exec('DELETE FROM wraps WHERE kind = ? AND ref = ?', w.kind, w.ref);
      for (const w of set) {
        this.sql.exec('INSERT INTO wraps (kind, ref, data) VALUES (?, ?, ?) ON CONFLICT(kind, ref) DO UPDATE SET data = excluded.data', w.kind, w.ref, w.data);
      }
      if (driveSalt !== undefined) this.#setMeta('driveSalt', driveSalt);
      if (escrowPriv !== undefined) this.#setMeta('escrowPriv', escrowPriv);
    });
    return { ok: true };
  }

  /** Remove wraps by kind (and optionally one ref) — the server's side of passkey / code removal. */
  async removeWraps(uid, kind, ref = null) {
    this.#bind(uid);
    if (ref === null) this.sql.exec('DELETE FROM wraps WHERE kind = ?', kind);
    else this.sql.exec('DELETE FROM wraps WHERE kind = ? AND ref = ?', kind, ref);
    return { ok: true };
  }

  /** Keep only the passkey / recovery wraps whose credential the account still has. */
  async pruneWraps(uid, { passkey = [], recovery = [] } = {}) {
    this.#bind(uid);
    const keep = { passkey: new Set(passkey), recovery: new Set(recovery) };
    let n = 0;
    for (const w of this.sql.exec("SELECT kind, ref FROM wraps WHERE kind IN ('passkey', 'recovery')").toArray()) {
      if (!keep[w.kind].has(w.ref)) { this.sql.exec('DELETE FROM wraps WHERE kind = ? AND ref = ?', w.kind, w.ref); n++; }
    }
    return { ok: true, removed: n };
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
    // A received file is not part of the tree until the user's browser has re-wrapped it.
    if (!n || n.rs) return fail(404, 'not_found', 'No such item.');
    const children = n.kind === 'dir'
      ? this.sql.exec("SELECT * FROM nodes WHERE parent = ? AND rs IS NULL ORDER BY kind = 'file', created, id", id).toArray().map((r) => this.#out(r))
      : [];
    const path = this.#ancestors(id).map((r) => this.#out(r));
    return { ok: true, node: this.#out(n), children, path };
  }

  async createFolder(uid, { id, parent, name, meta = null }) {
    this.#bind(uid);
    const bad = this.#checkNew(id) || this.#checkParent(parent);
    if (bad) return bad;
    if (this.#depth(parent) + 1 > MAX_DEPTH) return fail(409, 'too_deep', `Folders nest at most ${MAX_DEPTH} levels.`);
    const t = nowSec();
    this.sql.exec("INSERT INTO nodes (id, parent, kind, name, meta, state, created, updated) VALUES (?, ?, 'dir', ?, ?, 'ready', ?, ?)", id, parent, name, meta, t, t);
    return { ok: true, id };
  }

  /**
   * Reserve a file: capacity and the largest-file limit are checked here, at
   * once, against every file already stored or being uploaded.
   */
  async createFile(uid, { id, parent, name, meta = null, size, fk, uploadHash, capacity, maxFile, pendingSec }) {
    this.#bind(uid);
    const bad = this.#checkNew(id) || this.#checkParent(parent);
    if (bad) return bad;
    if (size > maxFile) return fail(413, 'file_too_large', `A Drive file may be at most ${maxFile} bytes.`, { max: maxFile });
    const used = this.#used();
    if (used + size > capacity) return fail(413, 'drive_full', 'Not enough space left in your Drive.', { max: capacity, used });
    const chunks = driveChunks(size);
    const t = nowSec();
    this.sql.exec("INSERT INTO nodes (id, parent, kind, name, meta, size, chunks, fk, state, upload_hash, created, updated) VALUES (?, ?, 'file', ?, ?, ?, ?, ?, 'pending', ?, ?, ?)",
      id, parent, name, meta, size, chunks, fk, uploadHash, t, t);
    this.#setMeta('pendingSec', String(pendingSec));
    await this.#schedulePurge();
    return { ok: true, id, chunks, used: used + size };
  }

  #pending(id, uploadHash) {
    const n = this.#node(id);
    if (!n || n.kind !== 'file' || n.state !== 'pending') return { status: 'gone' };
    if (!safeEq(uploadHash, n.upload_hash)) return { status: 'forbidden' };
    return { status: 'ok', n };
  }

  /** Store chunk i of a pending file (exact size), then record it — or undo the write if the upload ended meanwhile. */
  async putChunk(uid, id, uploadHash, i, bytes) {
    this.#bind(uid);
    const c = this.#pending(id, uploadHash);
    if (c.status !== 'ok') return c;
    if (!Number.isInteger(i) || i < 0 || i >= c.n.chunks) return { status: 'bad_index' };
    const expected = driveChunkSize(c.n.size, i);
    if (!bytes || bytes.byteLength !== expected) return { status: 'bad_size', expected };
    const key = driveChunkKey(uid, id, i);
    await this.env.FILES.put(key, bytes, { httpMetadata: { contentType: 'application/octet-stream' } });
    const again = this.#pending(id, uploadHash);
    if (again.status !== 'ok') {
      // Deleted or purged while the write was in flight: leave nothing behind.
      await this.env.FILES.delete(key);
      return { status: 'gone' };
    }
    this.sql.exec('INSERT OR IGNORE INTO upchunks (node_id, i) VALUES (?, ?)', id, i);
    this.sql.exec('UPDATE nodes SET done = (SELECT COUNT(*) FROM upchunks WHERE node_id = ?), updated = ? WHERE id = ?', id, nowSec(), id);
    await this.#schedulePurge();
    return { status: 'ok' };
  }

  async finalize(uid, id, uploadHash) {
    this.#bind(uid);
    const c = this.#pending(id, uploadHash);
    if (c.status !== 'ok') return c;
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
    if (!n || n.kind !== 'file' || n.state !== 'ready' || n.rs) return { status: 'gone' };
    if (!Number.isInteger(i) || i < 0 || i >= n.chunks) return { status: 'bad_index' };
    return { status: 'ok', key: driveChunkKey(uid, id, i), size: driveChunkSize(n.size, i) };
  }

  /** Move (`parent`) and / or rename (`name`, `meta`) an item. The root can do neither. */
  async patchNode(uid, id, { parent, name, meta }) {
    this.#bind(uid);
    if (id === ROOT) return fail(400, 'root', 'The top folder cannot be moved or renamed.');
    const n = this.#node(id);
    if (!n || n.rs) return fail(404, 'not_found', 'No such item.');
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
    return { ok: true };
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
      // Reverse shares whose folder goes end with it (their received files go too).
      const dirs = new Set(rows.filter((r) => r.kind === 'dir').map((r) => r.id));
      const reverse = this.sql.exec("SELECT id, folder FROM reverse WHERE status = 'active'").toArray().filter((r) => dirs.has(r.folder)).map((r) => r.id);
      this.ctx.storage.transactionSync(() => {
        for (const rid of reverse) {
          this.sql.exec("UPDATE reverse SET status = 'revoked', ended = ? WHERE id = ?", nowSec(), rid);
          this.sql.exec('DELETE FROM rsessions WHERE rid = ?', rid);
        }
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
      this.#dropEndedReverse();
      return { ok: true, deleted: ids.length, shares: [...shares], reverse, used: this.#used() };
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
      if (n.state !== 'ready' || n.rs) return fail(409, 'not_ready', 'A file to share has not finished uploading.');
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

  /** The account is deleted: remove every R2 object and all state. Returns the shares that referenced it. */
  async destroy(uid) {
    this.#bind(uid);
    return this.ctx.blockConcurrencyWhile(async () => {
      await this.#deleteObjects(uid, this.sql.exec("SELECT id, chunks FROM nodes WHERE kind = 'file'").toArray());
      const shares = this.sql.exec('SELECT DISTINCT share_id FROM refs').toArray().map((r) => r.share_id);
      const reverse = this.sql.exec("SELECT id FROM reverse WHERE status = 'active'").toArray().map((r) => r.id);
      await this.ctx.storage.deleteAlarm();
      await this.ctx.storage.deleteAll();
      return { ok: true, shares, reverse };
    });
  }

  // ── reverse shares (docs/REVERSE.md) ─────────────────────────────────────
  #receivedCount() {
    return this.sql.exec("SELECT COUNT(*) AS c FROM nodes WHERE rs IS NOT NULL AND state = 'ready'").one().c;
  }
  #reverse(id) {
    return this.sql.exec('SELECT * FROM reverse WHERE id = ?', id).toArray()[0] || null;
  }
  /** A reverse share's state now: 'active' | 'expired' | 'revoked' (the row may say active past its expiry). */
  #reverseState(r) {
    if (!r) return 'gone';
    if (r.status !== 'active') return r.status;
    if (r.expires <= nowSec()) return 'expired';
    if (!this.#node(r.folder)) return 'revoked';
    return 'active';
  }
  #reverseOut(r, { priv = true } = {}) {
    let opts = {};
    try { opts = JSON.parse(r.opts); } catch { /* none */ }
    const o = {
      id: r.id, folder: r.folder, created: r.created, expires: r.expires, status: this.#reverseState(r),
      password: !!r.ph, note: !!r.note, maxFiles: opts.maxFiles ?? null, maxBytes: opts.maxBytes ?? null,
      maxFileBytes: opts.maxFileBytes ?? null, types: opts.types ?? null, files: r.files, bytes: r.bytes,
      pending: this.sql.exec("SELECT COUNT(*) AS c FROM nodes WHERE rs = ? AND state = 'ready'", r.id).one().c,
    };
    if (priv) o.priv = JSON.parse(r.priv);
    return o;
  }
  /** Give a pending (reserved) upload's allowance back and delete its rows (inside a transaction). */
  #dropPending(f) {
    this.sql.exec('DELETE FROM upchunks WHERE node_id = ?', f.id);
    const gone = this.sql.exec("DELETE FROM nodes WHERE id = ? AND state = 'pending'", f.id).rowsWritten;
    if (gone && f.rs) this.sql.exec('UPDATE reverse SET files = MAX(0, files - 1), bytes = MAX(0, bytes - ?) WHERE id = ?', f.size, f.rs);
  }
  /**
   * Reverse shares that ended more than REVERSE_KEEP_SEC ago (as long as the
   * share index lists them) and whose received files have all been taken in:
   * their key is no longer needed.
   */
  #dropEndedReverse() {
    const before = nowSec() - REVERSE_KEEP_SEC;
    this.sql.exec(`DELETE FROM reverse WHERE ((status != 'active' AND COALESCE(ended, 0) < ?) OR expires < ?)
      AND id NOT IN (SELECT rs FROM nodes WHERE rs IS NOT NULL)`, before, before);
    this.sql.exec('DELETE FROM rsessions WHERE rid NOT IN (SELECT id FROM reverse)');
  }
  /** Upload sessions past their time: log what they received (count and size), then forget them. */
  async #lapseSessions() {
    const stale = this.sql.exec('SELECT * FROM rsessions WHERE expires <= ?', nowSec()).toArray();
    if (!stale.length) return;
    this.sql.exec('DELETE FROM rsessions WHERE expires <= ?', nowSec());
    const ns = this.env.DIRECTORY;
    for (const x of stale) {
      if (!x.files) continue;
      try { await ns.get(ns.idFromName('directory')).reverseEvent(x.rid, 'received', { files: x.files, bytes: x.bytes }); } catch (e) {
        console.warn('secbin: reverse upload not logged', e && e.message ? e.message : e);
      }
    }
  }

  /** A new reverse share on folder `rec.folder` (values arrive validated). */
  async createReverse(uid, rec) {
    this.#bind(uid);
    const f = this.#node(rec.folder);
    if (!f || f.rs) return fail(404, 'not_found', 'The folder does not exist.');
    if (f.kind !== 'dir') return fail(400, 'not_a_folder', 'Files can only be received into a folder.');
    if (this.#reverse(rec.id)) return fail(409, 'exists', 'A reverse share with this id already exists.');
    this.#dropEndedReverse();
    if (this.sql.exec('SELECT COUNT(*) AS c FROM reverse').one().c >= MAX_REVERSE) return fail(409, 'too_many_reverse', `A Drive holds at most ${MAX_REVERSE} reverse shares.`);
    const t = nowSec();
    this.sql.exec(`INSERT INTO reverse (id, folder, priv, lh, ph, salt, t, note, opts, created, expires, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')`,
      rec.id, rec.folder, rec.priv, rec.lh, rec.ph ?? null, rec.salt ?? null, rec.t ?? null, rec.note ?? null, JSON.stringify(rec.opts), t, t + rec.ttl);
    return { ok: true, id: rec.id, created: t, expires: t + rec.ttl };
  }

  /** Every reverse share (or one folder's), newest first, with its sealed private key. */
  async listReverse(uid, folder = null) {
    this.#bind(uid);
    const rows = folder === null
      ? this.sql.exec('SELECT * FROM reverse ORDER BY created DESC').toArray()
      : this.sql.exec('SELECT * FROM reverse WHERE folder = ? ORDER BY created DESC', folder).toArray();
    return { ok: true, reverse: rows.map((r) => this.#reverseOut(r)) };
  }

  /** A reverse share's state and counters (My shares' live status). */
  async reverseStatus(uid, id) {
    this.#bind(uid);
    const r = this.#reverse(id);
    if (!r) return { status: 'gone' };
    const st = this.#reverseState(r);
    return st === 'active' ? { status: 'ok', files: r.files, bytes: r.bytes, expires: r.expires } : { status: 'gone', state: st, files: r.files, bytes: r.bytes };
  }

  /**
   * End a reverse share (revoked, or its account's role no longer allows it):
   * no more uploads; unfinished uploads are deleted now, received files stay.
   */
  async endReverse(uid, id, status = 'revoked') {
    this.#bind(uid);
    return this.ctx.blockConcurrencyWhile(async () => {
      const r = this.#reverse(id);
      if (!r) return { ok: true, ended: false };
      const pending = this.sql.exec("SELECT id, chunks, size, rs FROM nodes WHERE rs = ? AND state = 'pending'", id).toArray();
      await this.#deleteObjects(uid, pending);
      this.ctx.storage.transactionSync(() => {
        for (const f of pending) this.#dropPending(f);
        this.sql.exec('UPDATE reverse SET status = ?, ended = ? WHERE id = ?', status, nowSec(), id);
        this.sql.exec('DELETE FROM rsessions WHERE rid = ?', id);
      });
      this.#dropEndedReverse();
      if (pending.length) await this.#reportUsage();
      return { ok: true, ended: true, used: this.#used() };
    });
  }

  /** A later expiry (My shares' Extend). */
  async extendReverse(uid, id, expires) {
    this.#bind(uid);
    const r = this.#reverse(id);
    if (!r || this.#reverseState(r) !== 'active') return { status: 'gone' };
    if (!Number.isSafeInteger(expires) || expires <= r.expires) return { status: 'invalid', message: 'Expiry can only be extended.' };
    this.sql.exec('UPDATE reverse SET expires = ? WHERE id = ?', expires, id);
    return { status: 'ok', expires };
  }

  /**
   * What the uploader's page needs (after the Worker checked the link proof
   * against `lh`): the sealed note, the password parameters and the limits
   * left. 'gone' unless active.
   */
  async reverseOpen(uid, id) {
    this.#bind(uid);
    const r = this.#reverse(id);
    const st = this.#reverseState(r);
    if (st !== 'active') return { status: st === 'gone' ? 'unknown' : 'gone', lh: r ? r.lh : null };
    const o = this.#reverseOut(r, { priv: false });
    return {
      status: 'ok', lh: r.lh, ph: r.ph,
      head: {
        note: r.note ? JSON.parse(r.note) : null,
        password: r.ph ? { salt: r.salt, t: r.t } : null,
        expires: r.expires,
        limits: { maxFiles: o.maxFiles, maxBytes: o.maxBytes, maxFileBytes: o.maxFileBytes, types: o.types,
          filesLeft: o.maxFiles === null ? null : Math.max(0, o.maxFiles - r.files), bytesLeft: o.maxBytes === null ? null : Math.max(0, o.maxBytes - r.bytes) },
      },
    };
  }

  /** A new upload session (the Worker checked link, password and human check) → { status, expires }. */
  async reverseBegin(uid, id, hash, ttl) {
    this.#bind(uid);
    const r = this.#reverse(id);
    if (this.#reverseState(r) !== 'active') return { status: 'gone' };
    const t = nowSec();
    this.sql.exec('DELETE FROM rsessions WHERE rid = ? AND expires <= ? AND files = 0', id, t);
    if (this.sql.exec('SELECT COUNT(*) AS c FROM rsessions WHERE rid = ? AND expires > ?', id, t).one().c >= MAX_SESSIONS) return { status: 'busy' };
    const expires = Math.min(r.expires, t + ttl);
    this.sql.exec('INSERT INTO rsessions (hash, rid, expires) VALUES (?, ?, ?)', hash, id, expires);
    await this.#schedulePurge();
    return { status: 'ok', expires };
  }

  #session(id, hash) {
    const x = this.sql.exec('SELECT * FROM rsessions WHERE hash = ?', hash).toArray()[0];
    return x && x.rid === id && x.expires > nowSec() ? x : null;
  }
  #touch(x, ttl) {
    const r = this.#reverse(x.rid);
    this.sql.exec('UPDATE rsessions SET expires = ? WHERE hash = ?', Math.min(r.expires, Math.max(x.expires, nowSec() + ttl)), x.hash);
  }

  /**
   * Reserve one received file in the share's folder: every limit is checked
   * here at once — the share's (files, bytes, file size, declared types, as
   * checked by the Worker), the Drive's capacity and largest file, and the
   * tree's ceilings.
   */
  async reverseCreateFile(uid, id, hash, { node, name, meta, size, wrap, uploadHash, capacity, maxFile, pendingSec }) {
    this.#bind(uid);
    const r = this.#reverse(id);
    if (this.#reverseState(r) !== 'active') return fail(410, 'gone', 'This link no longer accepts files.');
    const x = this.#session(id, hash);
    if (!x) return fail(403, 'bad_grant', 'This upload session has ended. Reload the page to start again.');
    const opts = JSON.parse(r.opts);
    if (opts.maxFiles !== null && opts.maxFiles !== undefined && r.files + 1 > opts.maxFiles) return fail(409, 'too_many_files', `This link accepts at most ${opts.maxFiles} files.`, { max: opts.maxFiles });
    if (r.files + 1 > MAX_REVERSE_FILES) return fail(409, 'too_many_files', `A link accepts at most ${MAX_REVERSE_FILES} files.`, { max: MAX_REVERSE_FILES });
    if (opts.maxFileBytes !== null && opts.maxFileBytes !== undefined && size > opts.maxFileBytes) return fail(413, 'file_too_large', `Each file may be at most ${opts.maxFileBytes} bytes.`, { max: opts.maxFileBytes });
    if (size > maxFile) return fail(413, 'file_too_large', `Each file may be at most ${maxFile} bytes.`, { max: maxFile });
    if (opts.maxBytes !== null && opts.maxBytes !== undefined && r.bytes + size > opts.maxBytes) return fail(413, 'share_full', 'This link has no room left for that file.', { max: opts.maxBytes, used: r.bytes });
    const bad = this.#checkNew(node) || this.#checkParent(r.folder);
    if (bad) return bad.error === 'exists' ? bad : fail(bad.status === 404 ? 410 : bad.status, bad.status === 404 ? 'gone' : bad.error, bad.message);
    const fk = JSON.stringify({ kind: 'rs', data: wrap });
    // The sealed fields take room too: they count against the capacity.
    const used = this.#used();
    if (used + size + name.length + meta.length + fk.length > capacity) return fail(413, 'drive_full', 'There is not enough space left for that file.');
    const chunks = driveChunks(size);
    const t = nowSec();
    this.ctx.storage.transactionSync(() => {
      this.sql.exec("INSERT INTO nodes (id, parent, kind, name, meta, size, chunks, fk, state, upload_hash, created, updated, rs) VALUES (?, ?, 'file', ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)",
        node, r.folder, name, meta, size, chunks, fk, uploadHash, t, t, id);
      this.sql.exec('UPDATE reverse SET files = files + 1, bytes = bytes + ? WHERE id = ?', size, id);
      this.#touch(x, pendingSec);
    });
    this.#setMeta('pendingSec', String(pendingSec));
    await this.#schedulePurge();
    return { ok: true, id: node, chunks, used: used + size };
  }

  /**
   * A chunk of a received file being uploaded (only one of this share's).
   * While its write to R2 is in flight the file cannot be finalized (so a
   * late write never lands on, or is removed from, a finished file); if the
   * upload ended meanwhile (cancelled, revoked, purged) the object is deleted.
   */
  async reversePutChunk(uid, id, node, uploadHash, i, bytes) {
    this.#bind(uid);
    const n = this.#node(node);
    if (!n || n.rs !== id || this.#reverseState(this.#reverse(id)) !== 'active') return { status: 'gone' };
    const c = this.#pending(node, uploadHash);
    if (c.status !== 'ok') return c;
    if (!Number.isInteger(i) || i < 0 || i >= c.n.chunks) return { status: 'bad_index' };
    const expected = driveChunkSize(c.n.size, i);
    if (!bytes || bytes.byteLength !== expected) return { status: 'bad_size', expected };
    const key = driveChunkKey(uid, node, i);
    this.inflight ??= new Map();
    this.inflight.set(node, (this.inflight.get(node) ?? 0) + 1);
    try {
      await this.env.FILES.put(key, bytes, { httpMetadata: { contentType: 'application/octet-stream' } });
    } finally {
      const left = this.inflight.get(node) - 1;
      if (left > 0) this.inflight.set(node, left); else this.inflight.delete(node);
    }
    const again = this.#pending(node, uploadHash);
    if (again.status !== 'ok') {
      // Still pending is the only way here to finish; anything else means the upload ended.
      await this.env.FILES.delete(key);
      return { status: 'gone' };
    }
    this.sql.exec('INSERT OR IGNORE INTO upchunks (node_id, i) VALUES (?, ?)', node, i);
    this.sql.exec('UPDATE nodes SET done = (SELECT COUNT(*) FROM upchunks WHERE node_id = ?), updated = ? WHERE id = ?', node, nowSec(), node);
    await this.#schedulePurge();
    return { status: 'ok' };
  }

  /** Finish a received file: counted in the session (for the log). */
  async reverseFinalize(uid, id, hash, node, uploadHash, pendingSec) {
    this.#bind(uid);
    const x = this.#session(id, hash);
    if (!x) return { status: 'bad_grant' };
    const n = this.#node(node);
    if (!n || n.rs !== id) return { status: 'gone' };
    if (this.#reverseState(this.#reverse(id)) !== 'active') return { status: 'gone' };
    if (this.inflight?.get(node)) return { status: 'busy' };
    const r = await this.finalize(uid, node, uploadHash);
    if (r.status !== 'ok') return r;
    this.sql.exec('UPDATE rsessions SET files = files + 1, bytes = bytes + ? WHERE hash = ?', n.size, hash);
    this.#touch(x, pendingSec);
    return { status: 'ok' };
  }

  /** The uploader cancels an unfinished file: its reservation is given back. */
  async reverseCancel(uid, id, hash, node, uploadHash) {
    this.#bind(uid);
    if (!this.#session(id, hash)) return { status: 'bad_grant' };
    return this.ctx.blockConcurrencyWhile(async () => {
      const n = this.#node(node);
      if (!n || n.rs !== id || n.state !== 'pending') return { status: 'gone' };
      if (!safeEq(uploadHash, n.upload_hash)) return { status: 'forbidden' };
      await this.#deleteObjects(uid, [n]);
      this.ctx.storage.transactionSync(() => this.#dropPending(n));
      await this.#reportUsage();
      return { status: 'ok' };
    });
  }

  /** The uploader is done: → { files, bytes } finalized in the session (the Worker logs them); the session ends. */
  async reverseDone(uid, id, hash) {
    this.#bind(uid);
    const x = this.#session(id, hash);
    if (!x) return { status: 'bad_grant' };
    this.sql.exec('DELETE FROM rsessions WHERE hash = ?', hash);
    return { status: 'ok', files: x.files, bytes: x.bytes };
  }

  /** Received files the user's browser has not re-wrapped yet (finished uploads only), with their shares' sealed keys. */
  async received(uid, limit = 500) {
    this.#bind(uid);
    const rows = this.sql.exec("SELECT * FROM nodes WHERE rs IS NOT NULL AND state = 'ready' ORDER BY created, id LIMIT ?", limit + 1).toArray();
    const more = rows.length > limit;
    const items = rows.slice(0, limit).map((r) => ({
      id: r.id, parent: r.parent, rs: r.rs, name: JSON.parse(r.name), meta: r.meta ? JSON.parse(r.meta) : null,
      fk: JSON.parse(r.fk), size: r.size, chunks: r.chunks, created: r.created,
    }));
    const keys = [...new Set(items.map((i) => i.rs))].map((rid) => this.#reverse(rid)).filter(Boolean).map((r) => ({ id: r.id, priv: JSON.parse(r.priv) }));
    return { ok: true, items, keys, more };
  }

  /** A received file re-wrapped by the user's browser: from now on an ordinary Drive file (in `parent`). */
  async acceptReceived(uid, node, { parent, name, meta, fk }) {
    this.#bind(uid);
    const n = this.#node(node);
    if (!n || !n.rs || n.state !== 'ready') return fail(409, 'not_received', 'This is not a received file waiting to be added.');
    if (parent !== n.parent) {
      const bad = this.#checkParent(parent);
      if (bad) return bad;
    }
    this.sql.exec('UPDATE nodes SET parent = ?, name = ?, meta = ?, fk = ?, rs = NULL, updated = ? WHERE id = ?', parent, name, meta, fk, nowSec(), node);
    this.#dropEndedReverse();
    return { ok: true };
  }

  // ── pending-upload purge ──────────────────────────────────────────────────
  /** Uploads with no progress for the role's filePendingSec are deleted, with their chunks. */
  async alarm() {
    const uid = this.#meta('uid');
    if (!uid) return;
    const sec = Number(this.#meta('pendingSec')) || 3600;
    let purged = 0;
    await this.ctx.blockConcurrencyWhile(async () => {
      const stale = this.sql.exec("SELECT id, chunks, size, rs FROM nodes WHERE kind = 'file' AND state = 'pending' AND updated <= ?", nowSec() - sec).toArray();
      if (!stale.length) return;
      await this.#deleteObjects(uid, stale);
      this.ctx.storage.transactionSync(() => {
        for (const f of stale) this.#dropPending(f);
      });
      purged = stale.length;
    });
    if (purged) await this.#reportUsage();
    await this.#lapseSessions();
    this.#dropEndedReverse();
    await this.#schedulePurge();
  }
}
