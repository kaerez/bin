// drive-do.js — the Drive Durable Object: one SQLite-backed instance per user
// (idFromName('drive:' + userId)) holding that user's private folder tree and
// which shares reference which items. See docs/DRIVE.md.
//
// What it stores arrives sealed (docs/DRIVE.md §3, key model v2): each item's
// name and metadata and each file's DEK, sealed under the user's KEK for the
// item's sub-MEK (`mek`) with the item's random salt (`ks`); the content in R2
// is encrypted with the DEK. This object holds no key: it cannot open any of
// it. The Worker, which can derive the KEKs, re-seals items here (rotation,
// sub-MEK removal, a root change) with a compare-and-set on (mek, ks). It also
// keeps, per file, a hash of the ciphertext chunks (`ch`), never of the
// plaintext. Drives made before the key model v2 keep their old fields (`fk`,
// the wraps) until their upgrade (docs/DRIVE.md §3.3) re-seals and verifies
// every item; then those go.
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
import { timingSafeEqualHex, utf8, b64urlFromBytes } from '../public/js/bytes.js';
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
CREATE TABLE IF NOT EXISTS archive_nodes (gen INTEGER NOT NULL, id TEXT NOT NULL, parent TEXT, kind TEXT NOT NULL,
  name TEXT NOT NULL, meta TEXT, size INTEGER NOT NULL DEFAULT 0, chunks INTEGER NOT NULL DEFAULT 0, fk TEXT,
  state TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0, upload_hash TEXT, created INTEGER NOT NULL, updated INTEGER NOT NULL,
  PRIMARY KEY (gen, id));
CREATE TABLE IF NOT EXISTS archive_wraps (gen INTEGER NOT NULL, kind TEXT NOT NULL, ref TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY (gen, kind, ref));
CREATE TABLE IF NOT EXISTS archive_meta (gen INTEGER NOT NULL, k TEXT NOT NULL, v TEXT NOT NULL, PRIMARY KEY (gen, k));
`;
// Columns added after the Drive first shipped (fresh objects get them from here too).
// nodes.rs: the reverse share of a received file not yet re-wrapped; nodes.rsess:
// the upload session that reserved it (its chunks keep that session open);
// nodes.rfail / rwhy: when and why the user's browser could not take it in
// (it then leaves the queue, docs/REVERSE.md §3). reverse.sealed: the sealed
// paths, metadata and wraps received (they count towards the link's bytes);
// reverse.pwfails / pwsince / pwlock: wrong passwords in the current window,
// and a lock after too many. rsessions.net: 24 bits of a hash of the
// uploader's network (per-network session cap); rsessions.started: its start.
// reverse.agen: the owner's archive (after starting over) whose Drive key
// seals this link's private key — the link is paused while that archive
// exists (docs/DRIVE.md §3.2); archive_nodes.rs / rfail / rwhy: a received
// item archived as it was, sealed to its link's key.
// The key model v2 (docs/DRIVE.md §3): nodes.ks — the item's random salt (the
// per-DEK salt; folders have one for their names); nodes.mek / mfp — the
// sub-MEK the item is sealed under and its fingerprint; nodes.dek — the
// sealed DEK of a file; nodes.ch — a hash of its ciphertext chunks
// (upchunks.h, one per chunk, while it uploads). reverse.mek — the sub-MEK
// its link key is sealed under (null: sealed by the release before).
// archive_*: an owner's Drive started over in the release before; kept as it
// is (it still takes its space), nothing opens it any more.
const COLUMNS = [
  ['nodes', 'rs', 'TEXT'], ['nodes', 'rsess', 'TEXT'], ['nodes', 'rfail', 'INTEGER'], ['nodes', 'rwhy', 'TEXT'],
  ['reverse', 'sealed', 'INTEGER NOT NULL DEFAULT 0'], ['reverse', 'pwfails', 'INTEGER NOT NULL DEFAULT 0'],
  ['reverse', 'pwsince', 'INTEGER'], ['reverse', 'pwlock', 'INTEGER'],
  ['rsessions', 'net', 'TEXT'], ['rsessions', 'started', 'INTEGER'],
  ['reverse', 'agen', 'INTEGER'],
  ['archive_nodes', 'rs', 'TEXT'], ['archive_nodes', 'rfail', 'INTEGER'], ['archive_nodes', 'rwhy', 'TEXT'],
  ['nodes', 'ks', 'TEXT'], ['nodes', 'mek', 'TEXT'], ['nodes', 'mfp', 'TEXT'], ['nodes', 'dek', 'TEXT'], ['nodes', 'ch', 'TEXT'],
  ['upchunks', 'h', 'TEXT'], ['reverse', 'mek', 'TEXT'],
];
/** The Drive's meta of the release before (the key wraps' salt, pin and records): dropped by its upgrade. */
const LEGACY_META = ['driveSalt', 'escrowPin', 'pwStale', 'kcv', 'kit', 'escrowVer', 'archiveGen', 'upgradeVerify'];
/** The owner's sealed escrow keys of the release before: dropped once every Drive is upgraded. */
const LEGACY_OWNER_META = ['escrowPriv', 'escrowSignPriv', 'escrowPrivOld'];
/** Items per page of the upgrade and of a re-seal. */
export const KEYS_PAGE = 200;
/** Ciphertext bytes the alarm hashes per run for files uploaded before the chunk hashes (docs/DRIVE.md §3). */
const HASH_BUDGET = 256 * 1024 * 1024;

export const ROOT = 'root';
/** Node ids: 16 random bytes, base64url (chosen by the browser so it can bind encrypted fields to them). */
export const NODE_ID_RE = /^[A-Za-z0-9_-]{22}$/;
/** Hard ceilings per Drive: items, items in one folder, folder nesting. */
export const MAX_NODES = 100000;
export const MAX_CHILDREN = 10000;
export const MAX_DEPTH = 64;
/** Shares referencing one item at most (each share is a separate link). */
export const MAX_SHARES_PER_NODE = 1000;
/**
 * Reverse shares per Drive (ended ones included until their files are taken
 * in); open upload sessions per share, and per uploader network per share;
 * files per share.
 */
export const MAX_REVERSE = 1000;
export const MAX_SESSIONS = 100;
export const MAX_SESSIONS_PER_NET = 5;
export const MAX_REVERSE_FILES = 10000;
/** An upload session with no unfinished file lapses after this long without activity. */
export const SESSION_IDLE_SEC = 600;
/** A received file must be finished, and a session ends, at most this long after it started (keep-alives included). */
export const RECEIVE_MAX_SEC = 86400;
/** Wrong passwords for one link (from any network) within PW_WINDOW_SEC lock it for PW_LOCK_SEC. */
export const PW_MAX_FAILS = 10;
export const PW_WINDOW_SEC = 900;
export const PW_LOCK_SEC = 900;
/** Received files per page of GET /received. */
export const RECEIVED_PAGE = 500;
/** Why the user's browser could not take a received file in (nodes.rwhy). */
export const RECEIVED_FAIL_REASONS = ['unreadable', 'name', 'place'];
/** An ended reverse share is kept (for its lists) this long — as long as the share index keeps its row. */
const REVERSE_KEEP_SEC = 30 * 86400;
/**
 * SQL condition on a `nodes` row: its link's private key is not sealed under
 * an archive's Drive key (only the key of the Drive now can take it in).
 */
const NOT_ARCHIVED_KEY = 'rs NOT IN (SELECT id FROM reverse WHERE agen IS NOT NULL)';

const nowSec = () => Math.floor(Date.now() / 1000);
const safeEq = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && timingSafeEqualHex(a, b);
/** The smaller of two byte limits (null: none). */
const capBytes = (a, b) => (a === null || a === undefined ? b ?? null : b === null || b === undefined ? a : Math.min(a, b));

/** Chunks of a Drive file of `size` plaintext bytes (an empty file has none). */
export const driveChunks = (size) => Math.ceil(size / CHUNK);
/** Exact ciphertext size of chunk i (files are not padded). */
export const driveChunkSize = (size, i) => Math.min(CHUNK, size - i * CHUNK) + TAG;
/** R2 prefix of a Drive file, and one chunk's key. */
export const driveKey = (uid, node) => `d/${uid}/${node}`;
export const driveChunkKey = (uid, node, i) => `${driveKey(uid, node)}/${i}`;

const fail = (status, error, message, extra) => ({ ok: false, status, error, message, ...(extra || {}) });

/** One ciphertext chunk's SHA-256, base64url. */
export async function chunkHash(bytes) {
  return b64urlFromBytes(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
}
/**
 * A file's ciphertext hash (nodes.ch): SHA-256 over "secbin-ch/v1", the chunk
 * count and each chunk's SHA-256 in order — of what is stored, never of the
 * plaintext (a plaintext hash would tell when two users hold the same file).
 */
export async function ciphertextHash(n, hashOf) {
  const parts = [];
  for (let i = 0; i < n; i++) parts.push(hashOf(i) ?? '');
  return b64urlFromBytes(new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(`secbin-ch/v1\n${n}\n${parts.join('\n')}`))));
}

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
    for (const [table, col, decl] of COLUMNS) {
      const have = new Set(this.sql.exec(`PRAGMA table_info(${table})`).toArray().map((c) => c.name));
      if (!have.has(col)) this.sql.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${decl}`);
    }
    this.sql.exec('CREATE INDEX IF NOT EXISTS nodes_rs ON nodes(rs)');
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
    // Every item's sealed name, metadata and file key count, received files
    // included (the anonymous uploader chose them; docs/REVERSE.md §4).
    const bytes = `COALESCE(SUM(CASE WHEN kind = 'file' THEN size ELSE 0 END), 0)
      + COALESCE(SUM(LENGTH(name) + COALESCE(LENGTH(meta), 0) + COALESCE(LENGTH(fk), 0)), 0)`;
    // The sealed DEK and the salt count too (docs/DRIVE.md §10).
    const keys = 'COALESCE(SUM(COALESCE(LENGTH(dek), 0) + COALESCE(LENGTH(ks), 0)), 0)';
    // An archived Drive (the owner's, after a start over in the release before) still takes its space.
    return this.sql.exec(`SELECT ${bytes} + ${keys} AS s FROM nodes WHERE id != ?`, ROOT).one().s + this.sql.exec(`SELECT ${bytes} AS s FROM archive_nodes`).one().s;
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
    // The keys it is sealed under (key model v2); none: sealed by the release before, waiting for its upgrade.
    if (r.id !== ROOT) Object.assign(o, r.mek ? { ks: r.ks, mek: r.mek, mfp: r.mfp } : { v1: true });
    if (r.kind === 'file') {
      Object.assign(o, { meta: r.meta ? parse(r.meta) : null, size: r.size, chunks: r.chunks, state: r.state });
      if (r.mek) Object.assign(o, { dek: r.dek ? parse(r.dek) : null, ch: r.ch || null });
      else o.fk = r.fk ? parse(r.fk) : null;
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
    const q = this.sql.exec("SELECT MIN(created) AS t FROM nodes WHERE state = 'pending' AND rs IS NOT NULL").one();
    const times = [r.t === null ? null : r.t + sec, s.t, q.t === null ? null : q.t + RECEIVE_MAX_SEC].filter((x) => x !== null);
    if (!times.length) return;
    const at = Math.min(...times) * 1000;
    const cur = await this.ctx.storage.getAlarm();
    if (cur === null || cur > at) await this.ctx.storage.setAlarm(at);
  }
  /**
   * Files that have no ciphertext hash yet (uploaded before chunk hashes were
   * kept, or received before): the alarm hashes their stored chunks, a
   * budget per run, soon.
   */
  async #scheduleHashes() {
    if (!this.sql.exec("SELECT 1 FROM nodes WHERE kind = 'file' AND state = 'ready' AND ch IS NULL LIMIT 1").toArray().length) return;
    const at = Date.now() + 30 * 1000;
    const cur = await this.ctx.storage.getAlarm();
    if (cur === null || cur > at) await this.ctx.storage.setAlarm(at);
  }

  /**
   * One run of the ciphertext hashes (see #scheduleHashes): at most
   * HASH_BUDGET bytes read from R2. A file with a chunk missing gets "" (no
   * hash: a damaged file is not given one). → whether more are waiting.
   */
  async #hashStored(uid) {
    const r2 = this.env.FILES;
    if (!r2 || typeof r2.get !== 'function') return false;
    let budget = HASH_BUDGET;
    for (const f of this.sql.exec("SELECT id, size, chunks FROM nodes WHERE kind = 'file' AND state = 'ready' AND ch IS NULL ORDER BY id LIMIT 100").toArray()) {
      if (budget < HASH_BUDGET && f.size > budget) break;
      budget -= f.size;
      const hs = [];
      let whole = true;
      for (let i = 0; i < f.chunks; i++) {
        const obj = await r2.get(driveChunkKey(uid, f.id, i));
        if (!obj) { whole = false; break; }
        hs.push(await chunkHash(new Uint8Array(await obj.arrayBuffer())));
      }
      const ch = whole ? await ciphertextHash(f.chunks, (i) => hs[i]) : '';
      this.sql.exec("UPDATE nodes SET ch = ? WHERE id = ? AND ch IS NULL AND state = 'ready'", ch, f.id);
    }
    return this.sql.exec("SELECT 1 FROM nodes WHERE kind = 'file' AND state = 'ready' AND ch IS NULL LIMIT 1").toArray().length > 0;
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
    return {
      used: this.#used(),
      items: this.#count() - 1,
      content: this.#hasContent(),
      received: this.#receivedCount(),
      receivedFailed: this.#receivedFailedCount(),
      meks: this.#meksInUse(),
      migration: this.#migrationState(),
    };
  }

  /** The sub-MEKs this Drive's items and link keys are sealed under. */
  #meksInUse() {
    return this.sql.exec('SELECT mek FROM nodes WHERE mek IS NOT NULL UNION SELECT mek FROM reverse WHERE mek IS NOT NULL').toArray().map((r) => r.mek);
  }

  /** How many items and link keys each sub-MEK seals here → { counts: { mekId: n }, v1 } (v1: sealed by the release before). */
  async mekUsage(uid) {
    this.#bind(uid);
    const counts = {};
    for (const r of this.sql.exec('SELECT mek, COUNT(*) AS c FROM (SELECT mek FROM nodes WHERE mek IS NOT NULL UNION ALL SELECT mek FROM reverse WHERE mek IS NOT NULL) GROUP BY mek').toArray()) counts[r.mek] = r.c;
    return { ok: true, counts, v1: this.#migrationState().v1Items };
  }

  #hasContent() {
    return this.sql.exec('SELECT 1 FROM nodes WHERE parent = ? LIMIT 1', ROOT).toArray().length > 0;
  }

  /**
   * What the upgrade to the key model v2 still has to do here: items (not
   * received ones: those stay sealed to their link until they are taken in)
   * and link keys sealed by the release before, and whether its key wraps
   * are still here.
   */
  #migrationState() {
    return {
      v1Items: this.sql.exec('SELECT COUNT(*) AS c FROM nodes WHERE id != ? AND mek IS NULL AND rs IS NULL', ROOT).one().c,
      v1Links: this.sql.exec('SELECT COUNT(*) AS c FROM reverse WHERE mek IS NULL').one().c,
      wraps: this.sql.exec('SELECT COUNT(*) AS c FROM wraps').one().c,
      archived: this.sql.exec('SELECT COUNT(*) AS c FROM archive_nodes').one().c,
    };
  }

  /**
   * The key wraps of the release before and what the upgrade needs to open
   * them: the wraps, their salt and pin, and for the owner the sealed escrow
   * keys. Only while the Drive has them.
   */
  async legacyKeys(uid) {
    this.#bind(uid);
    const old = this.#json('escrowPrivOld') || {};
    const { v1Items, v1Links, archived } = this.#migrationState();
    return {
      ok: true,
      wraps: this.sql.exec('SELECT kind, ref, data FROM wraps ORDER BY kind, ref').toArray().map((w) => ({ kind: w.kind, ref: w.ref, data: w.data })),
      driveSalt: this.#meta('driveSalt'),
      kcv: this.#meta('kcv'),
      escrowPriv: this.#meta('escrowPriv'),
      escrowPrivOld: old,
      v1Items, v1Links, archived,
    };
  }

  /** A page of the items the release before sealed (id order): their sealed fields as stored, for the upgrade. */
  async legacyPage(uid, { after = '', limit = KEYS_PAGE } = {}) {
    this.#bind(uid);
    const lim = Math.max(1, Math.min(KEYS_PAGE, limit | 0));
    const rows = this.sql.exec('SELECT id, kind, name, meta, fk, size FROM nodes WHERE id != ? AND mek IS NULL AND rs IS NULL AND id > ? ORDER BY id LIMIT ?', ROOT, after, lim).toArray();
    const parse = (v) => { try { return v ? JSON.parse(v) : null; } catch { return null; } };
    const links = after ? [] : this.sql.exec('SELECT id, priv FROM reverse WHERE mek IS NULL ORDER BY id').toArray().map((r) => ({ id: r.id, priv: r.priv }));
    return {
      ok: true,
      items: rows.map((r) => ({ id: r.id, kind: r.kind, name: parse(r.name), meta: parse(r.meta), fk: parse(r.fk), size: r.size })),
      links,
      next: rows.length === lim ? rows[rows.length - 1].id : null,
    };
  }

  /**
   * Upgraded items (the Worker opened each under the user's KEK first): the
   * v2 fields replace the old ones, only for an item still sealed by the
   * release before (a compare-and-set: a repeat, or an item upgraded
   * meanwhile, changes nothing). `links`: link keys the same way.
   * → { done, skipped }.
   */
  async applyLegacy(uid, { items = [], links = [] } = {}) {
    this.#bind(uid);
    let done = 0;
    let skipped = 0;
    this.ctx.storage.transactionSync(() => {
      for (const x of items) {
        const w = this.sql.exec("UPDATE nodes SET ks = ?, mek = ?, mfp = ?, name = ?, meta = ?, dek = ?, fk = NULL WHERE id = ? AND mek IS NULL AND rs IS NULL AND kind = ?",
          x.ks, x.mek, x.mfp, x.name, x.meta ?? null, x.dek ?? null, x.id, x.dek ? 'file' : 'dir').rowsWritten;
        if (w) done++; else skipped++;
      }
      for (const l of links) {
        const w = this.sql.exec('UPDATE reverse SET priv = ?, mek = ? WHERE id = ? AND mek IS NULL', l.priv, l.mek, l.id).rowsWritten;
        if (w) done++; else skipped++;
      }
    });
    if (done) await this.#scheduleHashes(); // the ciphertext hashes of the upgraded files
    return { ok: true, done, skipped, ...this.#migrationState() };
  }

  /**
   * Where the upgrade's verification is (the Worker's cursor over the items,
   * "n.<id>" / "r.<id>"), kept here so that no page can be skipped: read
   * with `value` undefined, set (or, with null, reset) otherwise.
   */
  async upgradeCursor(uid, value) {
    this.#bind(uid);
    if (value === undefined) return { ok: true, cursor: this.#meta('upgradeVerify') };
    this.#setMeta('upgradeVerify', value);
    return { ok: true };
  }

  /**
   * The upgrade is verified (the Worker opened every item under v2): the key
   * wraps of the release before go, with their salt, pin and records; for
   * the owner, the sealed escrow keys go too once every Drive is upgraded
   * (`owner`). Refused while anything is still sealed the old way.
   */
  async dropLegacy(uid, { owner = false } = {}) {
    this.#bind(uid);
    const st = this.#migrationState();
    if (st.v1Items || st.v1Links) return fail(409, 'not_upgraded', 'Some items are still sealed by the release before.', st);
    this.ctx.storage.transactionSync(() => {
      this.sql.exec('DELETE FROM wraps');
      for (const k of [...LEGACY_META, ...(owner ? LEGACY_OWNER_META : [])]) this.#setMeta(k, null);
    });
    return { ok: true };
  }

  /**
   * A page of what is sealed under the sub-MEKs in `meks` (null: under any)
   * for a re-seal: items (their salt, mek and sealed fields) and link keys,
   * in id order after `after` ({ kind: 'n' | 'r', id }).
   */
  async sealedPage(uid, { meks = null, after = null, limit = KEYS_PAGE } = {}) {
    this.#bind(uid);
    const lim = Math.max(1, Math.min(KEYS_PAGE, limit | 0));
    const list = Array.isArray(meks) ? meks.slice(0, 50) : null;
    const inMeks = list ? `AND mek IN (${list.map(() => '?').join(', ') || "''"})` : 'AND mek IS NOT NULL';
    const out = { ok: true, items: [], links: [], next: null };
    const parse = (v) => { try { return v ? JSON.parse(v) : null; } catch { return null; } };
    if (!after || after.kind === 'n') {
      const rows = this.sql.exec(`SELECT id, kind, ks, mek, name, meta, dek FROM nodes WHERE id != ? ${inMeks} AND id > ? ORDER BY id LIMIT ?`, ROOT, ...(list || []), after?.id ?? '', lim).toArray();
      out.items = rows.map((r) => ({ id: r.id, kind: r.kind, ks: r.ks, mek: r.mek, name: parse(r.name), meta: parse(r.meta), dek: parse(r.dek) }));
      if (rows.length === lim) { out.next = { kind: 'n', id: rows[rows.length - 1].id }; return out; }
    }
    const rows = this.sql.exec(`SELECT id, mek, priv FROM reverse WHERE 1 = 1 ${inMeks} AND id > ? ORDER BY id LIMIT ?`, ...(list || []), after?.kind === 'r' ? after.id : '', lim).toArray();
    out.links = rows.map((r) => ({ id: r.id, mek: r.mek, priv: r.priv }));
    if (rows.length === lim) out.next = { kind: 'r', id: rows[rows.length - 1].id };
    return out;
  }

  /**
   * Re-sealed items and link keys (the Worker opened each under the old KEK
   * and sealed it under the new one): written only where the row is still
   * as read (same mek and salt; a link: same mek and sealed key), so a change
   * made meanwhile is never overwritten (it is picked up by the next pass).
   * → { done, skipped }.
   */
  async applySealed(uid, { items = [], links = [] } = {}) {
    this.#bind(uid);
    let done = 0;
    let skipped = 0;
    this.ctx.storage.transactionSync(() => {
      for (const x of items) {
        const w = this.sql.exec('UPDATE nodes SET ks = ?, mek = ?, mfp = ?, name = ?, meta = ?, dek = ? WHERE id = ? AND mek = ? AND ks = ?',
          x.ks, x.mek, x.mfp, x.name, x.meta ?? null, x.dek ?? null, x.id, x.fromMek, x.fromKs).rowsWritten;
        if (w) done++; else skipped++;
      }
      for (const l of links) {
        const w = this.sql.exec('UPDATE reverse SET priv = ?, mek = ? WHERE id = ? AND mek IS ? AND priv = ?', l.priv, l.mek, l.id, l.fromMek, l.fromPriv).rowsWritten;
        if (w) done++; else skipped++;
      }
    });
    return { ok: true, done, skipped };
  }

  /**
   * What the field layer seals at rest here (link keys and received items'
   * sealed fields), a page at a time for a root change → { links, received, next }.
   */
  async atRestPage(uid, { after = null, limit = KEYS_PAGE } = {}) {
    this.#bind(uid);
    const lim = Math.max(1, Math.min(KEYS_PAGE, limit | 0));
    const out = { ok: true, links: [], received: [], next: null };
    if (!after || after.kind === 'r') {
      const rows = this.sql.exec('SELECT id, priv FROM reverse WHERE id > ? ORDER BY id LIMIT ?', after?.id ?? '', lim).toArray();
      out.links = rows.map((r) => ({ id: r.id, priv: r.priv }));
      if (rows.length === lim) { out.next = { kind: 'r', id: rows[rows.length - 1].id }; return out; }
    }
    const rows = this.sql.exec('SELECT id, name, meta, fk FROM nodes WHERE rs IS NOT NULL AND id > ? ORDER BY id LIMIT ?', after?.kind === 'n' ? after.id : '', lim).toArray();
    out.received = rows.map((r) => ({ id: r.id, name: r.name, meta: r.meta, fk: r.fk }));
    if (rows.length === lim) out.next = { kind: 'n', id: rows[rows.length - 1].id };
    return out;
  }

  /** Field-layer values re-sealed under a new root (compare-and-set on the value read). */
  async applyAtRest(uid, { links = [], received = [] } = {}) {
    this.#bind(uid);
    let done = 0;
    this.ctx.storage.transactionSync(() => {
      for (const l of links) done += this.sql.exec('UPDATE reverse SET priv = ? WHERE id = ? AND priv = ?', l.priv, l.id, l.from).rowsWritten;
      for (const r of received) {
        done += this.sql.exec('UPDATE nodes SET name = ?, meta = ?, fk = ? WHERE id = ? AND rs IS NOT NULL AND name = ? AND meta IS ? AND fk IS ?',
          r.name, r.meta, r.fk, r.id, r.from.name, r.from.meta, r.from.fk).rowsWritten;
      }
    });
    return { ok: true, done };
  }

  /**
   * An item whose DEK seal is missing or does not open (a keys import, the
   * Worker checked the DEK against the file's first chunk): its fields as
   * re-sealed by the Worker, for this one item.
   */
  async restoreItem(uid, x) {
    this.#bind(uid);
    const w = this.sql.exec("UPDATE nodes SET ks = ?, mek = ?, mfp = ?, name = ?, meta = ?, dek = ?, fk = NULL WHERE id = ? AND kind = 'file' AND rs IS NULL AND (mek IS ? AND ks IS ?)",
      x.ks, x.mek, x.mfp, x.name, x.meta, x.dek, x.id, x.fromMek, x.fromKs).rowsWritten;
    return w ? { ok: true } : fail(409, 'changed', 'The item changed meanwhile.');
  }

  /** One item's stored fields (for a keys view or import): id, kind, ks, mek, sealed fields, size, chunks. */
  async itemKeys(uid, id) {
    this.#bind(uid);
    const n = this.#node(id);
    if (!n || n.id === ROOT || n.rs) return fail(404, 'not_found', 'No such item.');
    const parse = (v) => { try { return v ? JSON.parse(v) : null; } catch { return null; } };
    return { ok: true, item: { id: n.id, kind: n.kind, ks: n.ks, mek: n.mek, name: parse(n.name), meta: parse(n.meta), dek: parse(n.dek), size: n.size, chunks: n.chunks, state: n.state } };
  }

  /**
   * The account's password changed (`reset`: set by the owner). A Drive
   * still waiting for its upgrade keeps the key wraps of the release before
   * (its upgrade may open the old Drive key with one): after a reset, the
   * password wrap goes when another wrap of the user's own remains (it opens
   * only with the old password, which may be the compromised one).
   */
  async passwordChanged(uid, { reset = false } = {}) {
    this.#bind(uid);
    if (!this.sql.exec("SELECT 1 FROM wraps WHERE kind = 'pw'").toArray().length) return { ok: true, pw: 'none' };
    const other = this.sql.exec("SELECT COUNT(*) AS c FROM wraps WHERE kind IN ('passkey', 'recovery')").one().c > 0;
    if (reset && other) {
      this.sql.exec("DELETE FROM wraps WHERE kind = 'pw'");
      return { ok: true, pw: 'removed' };
    }
    this.#setMeta('pwStale', '1');
    return { ok: true, pw: 'stale' };
  }

  /** Keep only the passkey / recovery wraps (of the release before) whose credential the account still has; → the wraps removed. */
  async pruneWraps(uid, { passkey = [], recovery = [] } = {}) {
    this.#bind(uid);
    const keep = { passkey: new Set(passkey), recovery: new Set(recovery) };
    const gone = [];
    for (const w of this.sql.exec("SELECT kind, ref, data FROM wraps WHERE kind IN ('passkey', 'recovery')").toArray()) {
      if (!keep[w.kind].has(w.ref)) { this.sql.exec('DELETE FROM wraps WHERE kind = ? AND ref = ?', w.kind, w.ref); gone.push({ kind: w.kind, ref: w.ref, data: w.data }); }
    }
    return { ok: true, removed: gone.length, wraps: gone };
  }

  /**
   * A fixed-window counter for `key` (a route of this Drive's user, or of one
   * of their sessions): one more hit → { ok } (false once `max` hits fall in
   * the current `windowSec`). Kept in the Drive's meta; windows that are over
   * are dropped, and at most 64 keys are kept (the oldest go first).
   */
  async hit(uid, key, max, windowSec) {
    this.#bind(uid);
    const t = nowSec();
    const all = this.#json('rl') || {};
    for (const [k, v] of Object.entries(all)) if (!v || !Number.isSafeInteger(v.start) || t - v.start >= (v.win || 0)) delete all[k];
    const cur = all[key] || { start: t, n: 0, win: windowSec };
    cur.n += 1;
    all[key] = cur;
    const keys = Object.keys(all).sort((a, b) => all[a].start - all[b].start);
    for (const k of keys.slice(0, Math.max(0, keys.length - 64))) delete all[k];
    this.#setMeta('rl', JSON.stringify(all));
    return { ok: cur.n <= max, retryAfter: cur.start + cur.win - t };
  }

  /** A meta value stored as JSON, or null. */
  #json(k) {
    try { return JSON.parse(this.#meta(k) || 'null'); } catch { return null; }
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

  /** A folder (its name sealed under `mek` with salt `ks`); its sealed name (and meta) count towards the capacity. */
  async createFolder(uid, { id, parent, name, meta = null, ks, mek, mfp, capacity = null }) {
    this.#bind(uid);
    const bad = this.#checkNew(id) || this.#checkParent(parent) || this.#fits(name.length + (meta ? meta.length : 0) + ks.length, capacity);
    if (bad) return bad;
    if (this.#depth(parent) + 1 > MAX_DEPTH) return fail(409, 'too_deep', `Folders nest at most ${MAX_DEPTH} levels.`);
    const t = nowSec();
    this.sql.exec("INSERT INTO nodes (id, parent, kind, name, meta, state, created, updated, ks, mek, mfp) VALUES (?, ?, 'dir', ?, ?, 'ready', ?, ?, ?, ?, ?)",
      id, parent, name, meta, t, t, ks, mek, mfp);
    return { ok: true, id, used: this.#used() };
  }

  /**
   * Reserve a file: capacity and the largest-file limit are checked here, at
   * once, against every file already stored or being uploaded (and the
   * sealed fields of every item, this one's included).
   */
  async createFile(uid, { id, parent, name, meta = null, size, dek, ks, mek, mfp, uploadHash, capacity, maxFile, pendingSec }) {
    this.#bind(uid);
    const bad = this.#checkNew(id) || this.#checkParent(parent);
    if (bad) return bad;
    if (size > maxFile) return fail(413, 'file_too_large', `A Drive file may be at most ${maxFile} bytes.`, { max: maxFile });
    const used = this.#used();
    const extra = size + name.length + (meta ? meta.length : 0) + dek.length + ks.length;
    if (used + extra > capacity) return fail(413, 'drive_full', 'Not enough space left in your Drive.', { max: capacity, used });
    const chunks = driveChunks(size);
    const t = nowSec();
    this.sql.exec("INSERT INTO nodes (id, parent, kind, name, meta, size, chunks, dek, ks, mek, mfp, state, upload_hash, created, updated) VALUES (?, ?, 'file', ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)",
      id, parent, name, meta, size, chunks, dek, ks, mek, mfp, uploadHash, t, t);
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
      const h = await chunkHash(bytes);
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
      // Sent again: the new chunk replaces the old one, and its hash too.
      this.sql.exec('INSERT INTO upchunks (node_id, i, h) VALUES (?, ?, ?) ON CONFLICT(node_id, i) DO UPDATE SET h = excluded.h', id, i, h);
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
    const rows = this.sql.exec('SELECT i, h FROM upchunks WHERE node_id = ? ORDER BY i', id).toArray();
    const have = new Map(rows.map((r) => [r.i, r.h]));
    for (let i = 0; i < c.n.chunks; i++) if (!have.has(i)) return { status: 'incomplete', missing: i };
    // The ciphertext hash: over the chunks' own hashes, in order (never the plaintext's).
    const ch = await ciphertextHash(c.n.chunks, (i) => have.get(i));
    // Nothing may have changed while it was computed (a chunk sent again, the upload ended).
    if (this.inflight.get(id)) return { status: 'busy' };
    const again = this.#pending(id, uploadHash);
    if (again.status !== 'ok') return again;
    const still = this.sql.exec('SELECT i, h FROM upchunks WHERE node_id = ? ORDER BY i', id).toArray();
    if (still.length !== rows.length || still.some((r, k) => r.i !== rows[k].i || r.h !== rows[k].h)) return { status: 'busy' };
    this.ctx.storage.transactionSync(() => {
      this.sql.exec("UPDATE nodes SET state = 'ready', done = chunks, upload_hash = NULL, ch = ?, updated = ? WHERE id = ?", ch, nowSec(), id);
      this.sql.exec('DELETE FROM upchunks WHERE node_id = ?', id);
    });
    return { status: 'ok', ch };
  }

  /** The R2 key of chunk i of a ready file of this Drive. */
  async chunkKey(uid, id, i) {
    this.#bind(uid);
    const n = this.#node(id);
    if (!n || n.kind !== 'file' || n.state !== 'ready' || n.rs) return { status: 'gone' };
    if (!Number.isInteger(i) || i < 0 || i >= n.chunks) return { status: 'bad_index' };
    return { status: 'ok', key: driveChunkKey(uid, id, i), size: driveChunkSize(n.size, i) };
  }

  /**
   * Move (`parent`) and / or rename (`name`, `meta`) an item. The root can
   * do neither. A new name or metadata is sealed under the item's own keys:
   * `mek` and `ks` must still be the item's (else `409 stale_keys`: it was
   * re-sealed meanwhile, and the browser seals again).
   */
  async patchNode(uid, id, { parent, name, meta, mek, ks, capacity = null }) {
    this.#bind(uid);
    if (id === ROOT) return fail(400, 'root', 'The top folder cannot be moved or renamed.');
    const n = this.#node(id);
    if (!n || n.rs) return fail(404, 'not_found', 'No such item.');
    if ((name !== undefined || meta !== undefined) && (!n.mek || n.mek !== mek || n.ks !== ks)) {
      return fail(409, 'stale_keys', 'This item was re-sealed meanwhile: open it again and retry.');
    }
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

  /** Every share that references this Drive (the account is being deleted: they end first). */
  async allShares(uid) {
    this.#bind(uid);
    return {
      ok: true,
      shares: this.sql.exec('SELECT DISTINCT share_id FROM refs').toArray().map((r) => r.share_id),
      reverse: this.sql.exec("SELECT id FROM reverse WHERE status = 'active'").toArray().map((r) => r.id),
    };
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
      await this.#deleteObjects(uid, this.sql.exec("SELECT id, chunks FROM nodes WHERE kind = 'file' UNION ALL SELECT id, chunks FROM archive_nodes WHERE kind = 'file'").toArray());
      const shares = this.sql.exec('SELECT DISTINCT share_id FROM refs').toArray().map((r) => r.share_id);
      const reverse = this.sql.exec("SELECT id FROM reverse WHERE status IN ('active', 'paused')").toArray().map((r) => r.id);
      await this.ctx.storage.deleteAlarm();
      await this.ctx.storage.deleteAll();
      this.destroyed = true;
      this.inflight.clear();
      return { ok: true, shares, reverse };
    });
  }

  // ── reverse shares (docs/REVERSE.md) ─────────────────────────────────────
  /** Received files waiting to be taken in (not those the browser could not take in: they left the queue). */
  #receivedCount() {
    return this.sql.exec(`SELECT COUNT(*) AS c FROM nodes WHERE rs IS NOT NULL AND state = 'ready' AND rfail IS NULL AND ${NOT_ARCHIVED_KEY}`).one().c;
  }
  #receivedFailedCount() {
    return this.sql.exec(`SELECT COUNT(*) AS c FROM nodes WHERE rs IS NOT NULL AND state = 'ready' AND rfail IS NOT NULL AND ${NOT_ARCHIVED_KEY}`).one().c;
  }
  #reverse(id) {
    return this.sql.exec('SELECT * FROM reverse WHERE id = ?', id).toArray()[0] || null;
  }
  /**
   * A reverse share's state now: 'active' | 'paused' | 'expired' | 'revoked'
   * (the row may say active past its expiry). 'paused': the owner started
   * over and the link's key is sealed under the archived Drive's key.
   */
  #reverseState(r) {
    if (!r) return 'gone';
    if (r.status === 'paused') return r.expires <= nowSec() ? 'expired' : 'paused';
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
      pending: this.sql.exec("SELECT COUNT(*) AS c FROM nodes WHERE rs = ? AND state = 'ready' AND rfail IS NULL", r.id).one().c,
      failed: this.sql.exec("SELECT COUNT(*) AS c FROM nodes WHERE rs = ? AND state = 'ready' AND rfail IS NOT NULL", r.id).one().c,
      // Received items kept in an archive (the owner started over), sealed as they arrived.
      kept: r.agen === null || r.agen === undefined ? 0 : this.sql.exec('SELECT COUNT(*) AS c FROM archive_nodes WHERE rs = ?', r.id).one().c,
    };
    // The link key as stored (sealed under the KEK of `mek`, and at rest by the Worker; mek null: the release before).
    if (priv) Object.assign(o, { priv: r.priv, mek: r.mek ?? null });
    return o;
  }
  /** Give a pending (reserved) upload's allowance back and delete its rows (inside a transaction). */
  #dropPending(f) {
    this.sql.exec('DELETE FROM upchunks WHERE node_id = ?', f.id);
    const row = this.sql.exec("SELECT LENGTH(name) + COALESCE(LENGTH(meta), 0) + COALESCE(LENGTH(fk), 0) AS o FROM nodes WHERE id = ? AND state = 'pending'", f.id).toArray()[0];
    const gone = this.sql.exec("DELETE FROM nodes WHERE id = ? AND state = 'pending'", f.id).rowsWritten;
    if (gone && f.rs) {
      this.sql.exec('UPDATE reverse SET files = MAX(0, files - 1), bytes = MAX(0, bytes - ?), sealed = MAX(0, sealed - ?) WHERE id = ?', f.size, row ? row.o : 0, f.rs);
    }
  }
  /** The sealed path, metadata and wrap of a reserved file: they count towards the link's byte limit. */
  #bytesUsed(r) {
    return r.bytes + (r.sealed || 0);
  }
  /**
   * The uploader's network (the Guard's key: an IPv4 address or an IPv6
   * prefix) as the per-network session cap counts it: 24 bits of SHA-256 over
   * the link id and the network. No key is involved, and the value does not
   * give the address back (about 256 IPv4 addresses share each value per link).
   */
  async #netTag(id, net) {
    if (typeof net !== 'string' || !net) return null;
    const d = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(`secbin-reverse/v1 net\n${id}\n${net}`)));
    return b64urlFromBytes(d.slice(0, 3));
  }
  /**
   * Reverse shares that ended more than REVERSE_KEEP_SEC ago (as long as the
   * share index lists them) and whose received files have all been taken in:
   * their key is no longer needed. A link whose key is sealed under an
   * archive's Drive key stays while that archive exists (a restore needs it).
   */
  #dropEndedReverse() {
    const before = nowSec() - REVERSE_KEEP_SEC;
    this.sql.exec(`DELETE FROM reverse WHERE ((status NOT IN ('active', 'paused') AND COALESCE(ended, 0) < ?) OR expires < ?)
      AND id NOT IN (SELECT rs FROM nodes WHERE rs IS NOT NULL)
      AND id NOT IN (SELECT rs FROM archive_nodes WHERE rs IS NOT NULL)
      AND (agen IS NULL OR agen NOT IN (SELECT gen FROM archive_meta))`, before, before);
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

  /** A new reverse share on folder `rec.folder` (values arrive validated; `priv` sealed under the KEK of `rec.mek`). */
  async createReverse(uid, rec) {
    this.#bind(uid);
    const f = this.#node(rec.folder);
    if (!f || f.rs) return fail(404, 'not_found', 'The folder does not exist.');
    if (f.kind !== 'dir') return fail(400, 'not_a_folder', 'Files can only be received into a folder.');
    if (this.#reverse(rec.id)) return fail(409, 'exists', 'A reverse share with this id already exists.');
    this.#dropEndedReverse();
    if (this.sql.exec('SELECT COUNT(*) AS c FROM reverse').one().c >= MAX_REVERSE) return fail(409, 'too_many_reverse', `A Drive holds at most ${MAX_REVERSE} reverse shares.`);
    const t = nowSec();
    this.sql.exec(`INSERT INTO reverse (id, folder, priv, mek, lh, ph, salt, t, note, opts, created, expires, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')`,
      rec.id, rec.folder, rec.priv, rec.mek, rec.lh, rec.ph ?? null, rec.salt ?? null, rec.t ?? null, rec.note ?? null, JSON.stringify(rec.opts), t, t + rec.ttl);
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
    // Paused (the owner started over) is not ended: the link resumes when the archive is restored.
    if (st === 'paused') return { status: 'ok', paused: true, files: r.files, bytes: r.bytes, expires: r.expires };
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

  /** A later expiry (My shares' Extend; a paused link too: it has not ended). */
  async extendReverse(uid, id, expires) {
    this.#bind(uid);
    const r = this.#reverse(id);
    if (!r || !['active', 'paused'].includes(this.#reverseState(r))) return { status: 'gone' };
    if (!Number.isSafeInteger(expires) || expires <= r.expires) return { status: 'invalid', message: 'Expiry can only be extended.' };
    this.sql.exec('UPDATE reverse SET expires = ? WHERE id = ?', expires, id);
    return { status: 'ok', expires };
  }

  /**
   * What the uploader's page needs (after the Worker checked the link proof
   * against `lh`): the sealed note, the password parameters and the limits
   * left. 'paused' while the owner's archive holds the link's key (no
   * session, no upload); 'gone' unless active.
   */
  async reverseOpen(uid, id, { roleMaxBytes = null } = {}) {
    this.#bind(uid);
    const r = this.#reverse(id);
    const st = this.#reverseState(r);
    if (st === 'paused') return { status: 'paused', lh: r.lh };
    if (st !== 'active') return { status: st === 'gone' ? 'unknown' : 'gone', lh: r ? r.lh : null };
    const o = this.#reverseOut(r, { priv: false });
    o.maxBytes = capBytes(o.maxBytes, roleMaxBytes);
    return {
      status: 'ok', lh: r.lh, ph: r.ph,
      head: {
        note: r.note ? JSON.parse(r.note) : null,
        password: r.ph ? { salt: r.salt, t: r.t, lockedUntil: r.pwlock && r.pwlock > nowSec() ? r.pwlock : null } : null,
        expires: r.expires,
        limits: { maxFiles: o.maxFiles, maxBytes: o.maxBytes, maxFileBytes: o.maxFileBytes, types: o.types,
          filesLeft: o.maxFiles === null ? null : Math.max(0, o.maxFiles - r.files), bytesLeft: o.maxBytes === null ? null : Math.max(0, o.maxBytes - this.#bytesUsed(r)) },
      },
    };
  }

  /**
   * A new upload session (the Worker checked the link proof and the human
   * check) → { status, expires }. The password is checked here, atomically
   * with the link's lockout: PW_MAX_FAILS wrong ones within PW_WINDOW_SEC,
   * from any network, lock the link's password for PW_LOCK_SEC (the right one
   * too: 'pw_locked'). A session with no unfinished file lapses after
   * SESSION_IDLE_SEC; at most MAX_SESSIONS_PER_NET are open per uploader
   * network (`net`, the Guard's key) and MAX_SESSIONS per link.
   */
  async reverseBegin(uid, id, hash, ttl, { net = null, proofHash = null } = {}) {
    this.#bind(uid);
    const tag = await this.#netTag(id, net); // before any check: nothing below awaits
    const r = this.#reverse(id);
    const st = this.#reverseState(r);
    if (st === 'paused') return { status: 'paused' };
    if (st !== 'active') return { status: 'gone' };
    const t = nowSec();
    if (r.ph) {
      if (r.pwlock && r.pwlock > t) return { status: 'pw_locked', until: r.pwlock };
      if (typeof proofHash !== 'string' || !safeEq(proofHash, r.ph)) {
        const fails = (r.pwsince && r.pwsince > t - PW_WINDOW_SEC ? r.pwfails : 0) + 1;
        if (fails >= PW_MAX_FAILS) {
          this.sql.exec('UPDATE reverse SET pwfails = 0, pwsince = NULL, pwlock = ? WHERE id = ?', t + PW_LOCK_SEC, id);
          return { status: 'bad_password', until: t + PW_LOCK_SEC };
        }
        this.sql.exec('UPDATE reverse SET pwfails = ?, pwsince = ? WHERE id = ?', fails, fails === 1 ? t : r.pwsince, id);
        return { status: 'bad_password', until: null };
      }
      if (r.pwfails || r.pwlock) this.sql.exec('UPDATE reverse SET pwfails = 0, pwsince = NULL, pwlock = NULL WHERE id = ?', id);
    }
    this.sql.exec('DELETE FROM rsessions WHERE rid = ? AND expires <= ? AND files = 0', id, t);
    if (this.sql.exec('SELECT COUNT(*) AS c FROM rsessions WHERE rid = ? AND expires > ?', id, t).one().c >= MAX_SESSIONS) return { status: 'busy' };
    if (tag && this.sql.exec('SELECT COUNT(*) AS c FROM rsessions WHERE rid = ? AND net = ? AND expires > ?', id, tag, t).one().c >= MAX_SESSIONS_PER_NET) {
      return { status: 'busy' };
    }
    const expires = Math.min(r.expires, t + Math.min(ttl, SESSION_IDLE_SEC));
    this.sql.exec('INSERT INTO rsessions (hash, rid, expires, net, started) VALUES (?, ?, ?, ?, ?)', hash, id, expires, tag, t);
    await this.#schedulePurge();
    return { status: 'ok', expires };
  }

  #session(id, hash) {
    const x = this.sql.exec('SELECT * FROM rsessions WHERE hash = ?', hash).toArray()[0];
    return x && x.rid === id && x.expires > nowSec() ? x : null;
  }
  /**
   * Session `x` now ends `ttl` seconds from now: later (a file reserved, a
   * chunk received) or sooner (nothing left unfinished: idle again), never
   * past the link's expiry or RECEIVE_MAX_SEC after it started.
   */
  #touch(x, ttl) {
    const r = this.#reverse(x.rid);
    const cap = Math.min(r.expires, (x.started ?? nowSec()) + RECEIVE_MAX_SEC);
    this.sql.exec('UPDATE rsessions SET expires = ? WHERE hash = ?', Math.min(cap, nowSec() + ttl), x.hash);
  }
  /** Session `x` after a file finished or was cancelled: open for pendingSec while it has another unfinished file, else idle. */
  #settle(x, pendingSec) {
    this.#touch(x, this.#sessionBusy(x.hash) ? pendingSec : Math.min(pendingSec, SESSION_IDLE_SEC));
  }
  /** Does session `hash` still have a file reserved and not finished? */
  #sessionBusy(hash) {
    return this.sql.exec("SELECT 1 FROM nodes WHERE rsess = ? AND state = 'pending' LIMIT 1", hash).toArray().length > 0;
  }

  /**
   * Reserve one received file in the share's folder: every limit is checked
   * here at once — the share's (files, bytes, file size, declared types, as
   * checked by the Worker), the Drive's capacity and largest file, and the
   * tree's ceilings.
   */
  async reverseCreateFile(uid, id, hash, { node, name, meta, size, wrap, uploadHash, capacity, maxFile, pendingSec, roleMaxBytes = null }) {
    this.#bind(uid);
    const r = this.#reverse(id);
    if (this.#reverseState(r) !== 'active') return fail(410, 'gone', 'This link no longer accepts files.');
    const x = this.#session(id, hash);
    if (!x) return fail(403, 'bad_grant', 'This upload session has ended. Reload the page to start again.');
    const opts = JSON.parse(r.opts);
    // The link's byte limit, or the role's current one when that is smaller (lowered since the link was made).
    const maxBytes = capBytes(opts.maxBytes, roleMaxBytes);
    if (opts.maxFiles !== null && opts.maxFiles !== undefined && r.files + 1 > opts.maxFiles) return fail(409, 'too_many_files', `This link accepts at most ${opts.maxFiles} files.`, { max: opts.maxFiles });
    if (r.files + 1 > MAX_REVERSE_FILES) return fail(409, 'too_many_files', `A link accepts at most ${MAX_REVERSE_FILES} files.`, { max: MAX_REVERSE_FILES });
    if (opts.maxFileBytes !== null && opts.maxFileBytes !== undefined && size > opts.maxFileBytes) return fail(413, 'file_too_large', `Each file may be at most ${opts.maxFileBytes} bytes.`, { max: opts.maxFileBytes });
    if (size > maxFile) return fail(413, 'file_too_large', `Each file may be at most ${maxFile} bytes.`, { max: maxFile });
    // The wrap as the Worker stores it (sealed at rest; before the field layer: the JSON { kind: 'rs', data }).
    const fk = wrap;
    // The sealed path, metadata and wrap count towards the link's bytes too (an empty file is not free).
    const sealed = name.length + meta.length + fk.length;
    if (maxBytes !== null && this.#bytesUsed(r) + size + sealed > maxBytes) {
      return fail(413, 'share_full', 'This link has no room left for that file.', { max: maxBytes, used: this.#bytesUsed(r) });
    }
    const bad = this.#checkNew(node) || this.#checkParent(r.folder);
    if (bad) return bad.error === 'exists' ? bad : fail(bad.status === 404 ? 410 : bad.status, bad.status === 404 ? 'gone' : bad.error, bad.message);
    // The sealed fields take room too: they count against the capacity (#used).
    if (this.#used() + size + sealed > capacity) return fail(413, 'drive_full', 'There is not enough space left for that file.');
    const chunks = driveChunks(size);
    const t = nowSec();
    this.ctx.storage.transactionSync(() => {
      this.sql.exec("INSERT INTO nodes (id, parent, kind, name, meta, size, chunks, fk, state, upload_hash, created, updated, rs, rsess) VALUES (?, ?, 'file', ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)",
        node, r.folder, name, meta, size, chunks, fk, uploadHash, t, t, id, hash);
      this.sql.exec('UPDATE reverse SET files = files + 1, bytes = bytes + ?, sealed = sealed + ? WHERE id = ?', size, sealed, id);
      this.#touch(x, pendingSec);
    });
    this.#setMeta('pendingSec', String(pendingSec));
    await this.#schedulePurge();
    return { ok: true, id: node, chunks, used: this.#used() };
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
    // Re-sent chunks keep a reservation alive, but not past RECEIVE_MAX_SEC.
    if (c.n.created + RECEIVE_MAX_SEC <= nowSec()) return { status: 'gone' };
    if (!Number.isInteger(i) || i < 0 || i >= c.n.chunks) return { status: 'bad_index' };
    const expected = driveChunkSize(c.n.size, i);
    if (!bytes || bytes.byteLength !== expected) return { status: 'bad_size', expected };
    const key = driveChunkKey(uid, node, i);
    this.inflight ??= new Map();
    this.inflight.set(node, (this.inflight.get(node) ?? 0) + 1);
    let h;
    try {
      h = await chunkHash(bytes);
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
    this.sql.exec('INSERT INTO upchunks (node_id, i, h) VALUES (?, ?, ?) ON CONFLICT(node_id, i) DO UPDATE SET h = excluded.h', node, i, h);
    this.sql.exec('UPDATE nodes SET done = (SELECT COUNT(*) FROM upchunks WHERE node_id = ?), updated = ? WHERE id = ?', node, nowSec(), node);
    // A large file's progress keeps the session that reserved it open (for its finalize).
    const x = c.n.rsess ? this.#session(id, c.n.rsess) : null;
    if (x) this.#touch(x, Number(this.#meta('pendingSec')) || 3600);
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
    // Only the session that reserved the file finishes it.
    if (n.state === 'pending' && !safeEq(n.rsess, hash)) return { status: 'bad_grant' };
    if (this.#reverseState(this.#reverse(id)) !== 'active') return { status: 'gone' };
    if (this.inflight?.get(node)) return { status: 'busy' };
    const r = await this.finalize(uid, node, uploadHash);
    if (r.status !== 'ok') return r;
    this.sql.exec('UPDATE nodes SET rsess = NULL WHERE id = ?', node);
    this.sql.exec('UPDATE rsessions SET files = files + 1, bytes = bytes + ? WHERE hash = ?', n.size, hash);
    // With nothing left unfinished, the session is idle again.
    this.#settle(x, pendingSec);
    return { status: 'ok' };
  }

  /** The uploader cancels an unfinished file: its reservation is given back. */
  async reverseCancel(uid, id, hash, node, uploadHash) {
    this.#bind(uid);
    if (!this.#session(id, hash)) return { status: 'bad_grant' };
    return this.ctx.blockConcurrencyWhile(async () => {
      const n = this.#node(node);
      if (!n || n.rs !== id || n.state !== 'pending') return { status: 'gone' };
      if (!safeEq(n.rsess, hash)) return { status: 'bad_grant' }; // only the session that reserved it
      if (!safeEq(uploadHash, n.upload_hash)) return { status: 'forbidden' };
      await this.#deleteObjects(uid, [n]);
      this.ctx.storage.transactionSync(() => this.#dropPending(n));
      // Nothing left unfinished: idle again (a reserve-and-cancel does not keep the session open).
      const x = this.#session(id, hash);
      if (x) this.#settle(x, Number(this.#meta('pendingSec')) || 3600);
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

  /**
   * Received files the user's browser has not re-wrapped yet (finished
   * uploads only), oldest first, with their shares' sealed keys → { items,
   * keys, more, next }. `after` ({ created, id }, from `next`) pages on, so
   * items that cannot be taken in never hide the ones behind them. `failed`:
   * the items the browser could not take in instead (no sealed fields: they
   * are shown with their link, size and time, to be deleted or tried again).
   */
  async received(uid, { after = null, limit = RECEIVED_PAGE, failed = false } = {}) {
    this.#bind(uid);
    const lim = Math.max(1, Math.min(RECEIVED_PAGE, limit | 0));
    // Not the items of a link whose key is still sealed under an archive's DK (a restore in progress).
    const cond = `rs IS NOT NULL AND state = 'ready' AND rfail IS ${failed ? 'NOT ' : ''}NULL AND ${NOT_ARCHIVED_KEY}`;
    const rows = after
      ? this.sql.exec(`SELECT * FROM nodes WHERE ${cond} AND (created > ? OR (created = ? AND id > ?)) ORDER BY created, id LIMIT ?`,
        after.created, after.created, after.id, lim + 1).toArray()
      : this.sql.exec(`SELECT * FROM nodes WHERE ${cond} ORDER BY created, id LIMIT ?`, lim + 1).toArray();
    const more = rows.length > lim;
    const page = rows.slice(0, lim);
    const last = page[page.length - 1];
    const next = more && last ? `${last.created}.${last.id}` : null;
    if (failed) {
      return { ok: true, items: page.map((r) => ({ id: r.id, rs: r.rs, size: r.size, created: r.created, failed: r.rfail, reason: r.rwhy })), more, next };
    }
    // The sealed fields as stored (the Worker opens the field layer), with the link keys.
    const items = page.map((r) => ({
      id: r.id, parent: r.parent, rs: r.rs, name: r.name, meta: r.meta, fk: r.fk, size: r.size, chunks: r.chunks, created: r.created,
    }));
    const keys = [...new Set(items.map((i) => i.rs))].map((rid) => this.#reverse(rid)).filter(Boolean).map((r) => ({ id: r.id, priv: r.priv, mek: r.mek ?? null }));
    return { ok: true, items, keys, more, next };
  }

  /**
   * The user's browser could not take received file `node` in (`failed`,
   * with a reason of RECEIVED_FAIL_REASONS): it leaves the queue and is listed
   * as failed; `failed: false` puts it back (try again).
   */
  async markReceived(uid, node, { failed, reason = null }) {
    this.#bind(uid);
    const n = this.#node(node);
    if (!n || !n.rs || n.state !== 'ready' || (this.#reverse(n.rs)?.agen ?? null) !== null) return fail(409, 'not_received', 'This is not a received file waiting to be added.');
    if (failed) this.sql.exec('UPDATE nodes SET rfail = ?, rwhy = ? WHERE id = ?', nowSec(), RECEIVED_FAIL_REASONS.includes(reason) ? reason : 'unreadable', node);
    else this.sql.exec('UPDATE nodes SET rfail = NULL, rwhy = NULL WHERE id = ?', node);
    return { ok: true, received: this.#receivedCount(), failed: this.#receivedFailedCount(), rs: n.rs };
  }

  /**
   * A received file taken in by the user's browser (its DEK, name and
   * metadata sealed under the KEK of the current sub-MEK, checked by the
   * Worker): from now on an ordinary Drive file (in `parent`).
   */
  async acceptReceived(uid, node, { parent, name, meta, dek, ks, mek, mfp }) {
    this.#bind(uid);
    const n = this.#node(node);
    if (!n || !n.rs || n.state !== 'ready' || (this.#reverse(n.rs)?.agen ?? null) !== null) return fail(409, 'not_received', 'This is not a received file waiting to be added.');
    if (parent !== n.parent) {
      const bad = this.#checkParent(parent);
      if (bad) return bad;
    }
    this.sql.exec('UPDATE nodes SET parent = ?, name = ?, meta = ?, fk = NULL, dek = ?, ks = ?, mek = ?, mfp = ?, rs = NULL, rfail = NULL, rwhy = NULL, updated = ? WHERE id = ?',
      parent, name, meta, dek, ks, mek, mfp, nowSec(), node);
    if (!n.ch) await this.#scheduleHashes(); // received before the chunk hashes were kept
    this.#dropEndedReverse();
    return { ok: true, used: this.#used(), rs: n.rs };
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
      const stale = this.sql.exec(`SELECT id, chunks, size, rs FROM nodes WHERE kind = 'file' AND state = 'pending'
        AND (updated <= ? OR (rs IS NOT NULL AND created <= ?))`, nowSec() - sec, nowSec() - RECEIVE_MAX_SEC).toArray();
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
    const more = await this.#hashStored(uid).catch((e) => { console.warn('secbin: drive hashes not computed', e && e.message ? e.message : e); return false; });
    await this.#schedulePurge();
    if (more) await this.#scheduleHashes();
  }
}
