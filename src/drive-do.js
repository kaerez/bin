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
CREATE TABLE IF NOT EXISTS rhuman (j TEXT PRIMARY KEY, exp INTEGER NOT NULL);
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
// item archived as it was, sealed to its link's key. reverse.captcha: the
// uploader passes the CAPTCHA before a session starts (links made before the
// option existed always had it: default 1). rhuman: the CAPTCHA grants
// (src/lib/human.js, their random id `j`) a session start has used, until
// they lapse, so each grant starts one session.
const COLUMNS = [
  ['nodes', 'rs', 'TEXT'], ['nodes', 'rsess', 'TEXT'], ['nodes', 'rfail', 'INTEGER'], ['nodes', 'rwhy', 'TEXT'],
  ['reverse', 'sealed', 'INTEGER NOT NULL DEFAULT 0'], ['reverse', 'pwfails', 'INTEGER NOT NULL DEFAULT 0'],
  ['reverse', 'pwsince', 'INTEGER'], ['reverse', 'pwlock', 'INTEGER'],
  ['rsessions', 'net', 'TEXT'], ['rsessions', 'started', 'INTEGER'],
  ['reverse', 'agen', 'INTEGER'],
  ['archive_nodes', 'rs', 'TEXT'], ['archive_nodes', 'rfail', 'INTEGER'], ['archive_nodes', 'rwhy', 'TEXT'],
  ['reverse', 'captcha', 'INTEGER NOT NULL DEFAULT 1'],
];
const NODE_COLS = 'id, parent, kind, name, meta, size, chunks, fk, state, done, upload_hash, created, updated';
/** The columns an archive keeps of each item: a received item keeps its link (rs) and failure (rfail, rwhy). */
const ARCHIVE_COLS = `${NODE_COLS}, rs, rfail, rwhy`;
/** What an archive keeps of the Drive's meta (everything sealed under the old DK, and its records). */
const ARCHIVED_META = ['driveSalt', 'escrowPriv', 'escrowSignPriv', 'escrowPrivOld', 'escrowPin', 'pwStale', 'kit', 'kcv'];

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
    // An archived Drive (the owner's, after starting over) still takes its space.
    return this.sql.exec(`SELECT ${bytes} AS s FROM nodes WHERE id != ?`, ROOT).one().s + this.sql.exec(`SELECT ${bytes} AS s FROM archive_nodes`).one().s;
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
    const s = this.sql.exec('SELECT MIN(expires) AS t FROM rsessions').one();
    const q = this.sql.exec("SELECT MIN(created) AS t FROM nodes WHERE state = 'pending' AND rs IS NOT NULL").one();
    const times = [r.t === null ? null : r.t + sec, s.t, q.t === null ? null : q.t + RECEIVE_MAX_SEC].filter((x) => x !== null);
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
    return {
      used: this.#used(),
      items: this.#count() - 1,
      driveSalt: this.#meta('driveSalt'),
      wraps,
      escrowPriv: this.#meta('escrowPriv'),
      escrowPin: this.#meta('escrowPin'),
      escrowSignPriv: this.#meta('escrowSignPriv'),
      escrowPrivOld: this.#oldEscrow(),
      pwStale: this.#meta('pwStale') === '1',
      content: this.#hasContent(),
      received: this.#receivedCount(),
      receivedFailed: this.#receivedFailedCount(),
      escrowVer: this.#json('escrowVer'),
      kit: this.#json('kit'),
      archives: this.#archives(),
      kcv: this.#meta('kcv'),
    };
  }

  /** The owner's archived Drives (after starting over): [{ gen, at, items, bytes, paused (reverse links) }]. */
  #archives() {
    return this.sql.exec(`SELECT m.gen AS gen, CAST(m.v AS INTEGER) AS at,
        (SELECT COUNT(*) FROM archive_nodes n WHERE n.gen = m.gen) AS items,
        (SELECT COALESCE(SUM(CASE WHEN n.kind = 'file' THEN n.size ELSE 0 END), 0) FROM archive_nodes n WHERE n.gen = m.gen) AS bytes,
        (SELECT COUNT(*) FROM reverse r WHERE r.agen = m.gen AND r.status = 'paused') AS paused
      FROM archive_meta m WHERE m.k = 'at' ORDER BY m.gen`).toArray().map((r) => ({ gen: r.gen, at: r.at, items: r.items, bytes: r.bytes, paused: r.paused }));
  }

  /** A meta value stored as JSON, or null. */
  #json(k) {
    try { return JSON.parse(this.#meta(k) || 'null'); } catch { return null; }
  }

  /** The owner's earlier escrow private keys (sealed, by kid), kept while a user's wrap may still need one. */
  #oldEscrow() {
    try { return JSON.parse(this.#meta('escrowPrivOld') || '{}'); } catch { return {}; }
  }

  /**
   * The owner's Drive: keep only the earlier escrow keys whose kid is in
   * `inUse` (the kids users' escrow wraps are still made for).
   */
  async pruneOldEscrow(uid, inUse = []) {
    this.#bind(uid);
    const keep = new Set(inUse);
    const old = this.#oldEscrow();
    const next = Object.fromEntries(Object.entries(old).filter(([kid]) => keep.has(kid)));
    if (Object.keys(next).length !== Object.keys(old).length) this.#setMeta('escrowPrivOld', Object.keys(next).length ? JSON.stringify(next) : null);
    return { ok: true, escrowPrivOld: next };
  }

  #hasContent() {
    return this.sql.exec('SELECT 1 FROM nodes WHERE parent = ? LIMIT 1', ROOT).toArray().length > 0;
  }

  /**
   * No wrap, but something that only an earlier DK made: content, the key
   * check value, or (the owner's) sealed escrow or signing keys. Such a Drive
   * is broken, not new: it never takes a first set-up (a new DK), only the
   * same DK back (a recovery kit) or, for the owner, starting over.
   */
  #keyless() {
    if (this.sql.exec('SELECT COUNT(*) AS c FROM wraps').one().c) return false;
    return this.#hasContent() || this.#meta('kcv') !== null || this.#meta('escrowPriv') !== null || this.#meta('escrowSignPriv') !== null;
  }

  /**
   * Change the key material: `set` / `remove` wraps, the Drive salt, the
   * sealed escrow pin (the escrow key this Drive trusts) and (the owner's
   * Drive only — the Worker checks) the sealed escrow and signing private
   * keys. Values arrive validated; `data`, `escrowPriv`, `escrowSignPriv` and
   * `escrowPin` are opaque. A replaced escrow private key is kept, sealed as
   * it was, under its kid (`oldKid`) until no user's escrow wrap needs it.
   * Writing a `pw` wrap clears the "stale password wrap" mark. A change that
   * would leave a Drive with wraps but none of the user's own (pw, recovery,
   * passkey) is refused, and so is one that leaves a Drive with content and
   * no wrap at all: nothing could open it again.
   *
   * Every check below and the write run with no await in between, so each
   * call is atomic against any other call of this object (R5-L2):
   * - `onlyIfEmpty` (every first set-up: the user's own, the owner's, one the
   *   owner makes for a user) is a compare-and-set on "a new Drive": no wrap,
   *   no content, no key check value, no sealed owner key (`409 drive_exists`,
   *   or `409 drive_keyless` for a Drive that has content or keys of an
   *   earlier DK); it needs `kcv`, which is stored with the first wraps and
   *   never replaced (only starting over, below, sets a new one);
   * - `expectKcv` (every later change of wraps or the pin): the stored key
   *   check value must exist and be this value (`409 kcv_missing`,
   *   `409 kcv_mismatch`), compared in constant time;
   * - `noEscrowYet` (the owner's very first escrow key, exempt from the
   *   step-up): refused once a sealed escrow or signing key exists
   *   (`409 escrow_exists`).
   * `newEscrowKid` (the owner's Drive, a new escrow key pair) moves the escrow
   * key's version (docs/DRIVE.md §3, owner recovery kit): 1 at the first
   * creation (`firstEscrow`), one more at each rotation, with its kid and the
   * time it was created. Not secret.
   */
  async setKeys(uid, { driveSalt, set = [], remove = [], escrowPriv, escrowSignPriv, escrowPin, oldKid, newEscrowKid, firstEscrow = false, kcv, expectKcv, noEscrowYet = false, onlyIfEmpty = false } = {}) {
    this.#bind(uid);
    // A first set-up never lands on a Drive that has keys (or had them: content, a check value, sealed keys).
    if (onlyIfEmpty) {
      if (this.sql.exec('SELECT COUNT(*) AS c FROM wraps').one().c) return fail(409, 'drive_exists', 'This Drive already has keys: they are never replaced.');
      if (this.#keyless()) return fail(409, 'drive_keyless', 'This Drive has content or keys but no key wrap: restore it from a recovery kit (or, the owner, start over).');
      if (typeof kcv !== 'string' || !kcv) return fail(400, 'kcv_required', 'A new Drive needs its key check value.');
    } else if (expectKcv !== undefined) {
      const have = this.#meta('kcv');
      if (have === null) return fail(409, 'kcv_missing', 'This Drive has no key check value: no key can be added to it.');
      if (!safeEq(expectKcv, have)) return fail(409, 'kcv_mismatch', 'That key is not this Drive’s key.');
    }
    if (noEscrowYet && escrowPriv !== undefined && (this.#meta('escrowPriv') !== null || this.#meta('escrowSignPriv') !== null)) {
      return fail(409, 'escrow_exists', 'An escrow key exists already: replacing it needs your confirmation.');
    }
    const has = (k, r) => this.sql.exec('SELECT 1 FROM wraps WHERE kind = ? AND ref = ?', k, r).toArray().length > 0;
    const newPw = set.some((w) => w.kind === 'pw');
    const total = this.sql.exec('SELECT COUNT(*) AS c FROM wraps').one().c;
    const removed = remove.filter((w) => has(w.kind, w.ref) && !set.some((x) => x.kind === w.kind && x.ref === w.ref)).length;
    const added = set.filter((w) => !has(w.kind, w.ref)).length;
    const after = total - removed + added;
    if (after > MAX_WRAPS) return fail(409, 'too_many_wraps', `At most ${MAX_WRAPS} key wraps.`);
    if (after === 0 && total > 0 && this.#hasContent()) return fail(409, 'last_wrap', 'This would leave your Drive with no way to open it.');
    const own = new Set(this.sql.exec("SELECT kind, ref FROM wraps WHERE kind IN ('pw', 'recovery', 'passkey')").toArray().map((w) => `${w.kind}\n${w.ref}`));
    for (const w of remove) own.delete(`${w.kind}\n${w.ref}`);
    for (const w of set) if (['pw', 'recovery', 'passkey'].includes(w.kind)) own.add(`${w.kind}\n${w.ref}`);
    if (after > 0 && own.size === 0 && total > 0) return fail(409, 'last_own_wrap', 'Your Drive must keep a password, passkey or recovery-code key of yours.');
    const old = this.#oldEscrow();
    const prev = this.#meta('escrowPriv');
    this.ctx.storage.transactionSync(() => {
      for (const w of remove) this.sql.exec('DELETE FROM wraps WHERE kind = ? AND ref = ?', w.kind, w.ref);
      for (const w of set) {
        this.sql.exec('INSERT INTO wraps (kind, ref, data) VALUES (?, ?, ?) ON CONFLICT(kind, ref) DO UPDATE SET data = excluded.data', w.kind, w.ref, w.data);
      }
      if (driveSalt !== undefined) this.#setMeta('driveSalt', driveSalt);
      if (escrowPriv !== undefined) {
        if (prev && oldKid && escrowPriv !== prev) this.#setMeta('escrowPrivOld', JSON.stringify({ ...old, [oldKid]: prev }));
        this.#setMeta('escrowPriv', escrowPriv);
      }
      if (escrowSignPriv !== undefined) this.#setMeta('escrowSignPriv', escrowSignPriv);
      if (escrowPin !== undefined) this.#setMeta('escrowPin', escrowPin);
      if (onlyIfEmpty) this.#setMeta('kcv', kcv); // with the first wraps; never replaced
      if (newPw) this.#setMeta('pwStale', null);
      if (newEscrowKid) {
        const ver = this.#json('escrowVer');
        // A key made before versions were recorded counts as version 1.
        const next = ver && Number.isSafeInteger(ver.version) ? ver.version + 1 : firstEscrow ? 1 : 2;
        if (!ver || ver.kid !== newEscrowKid) this.#setMeta('escrowVer', JSON.stringify({ version: next, kid: newEscrowKid, created: nowSec() }));
      }
    });
    return { ok: true };
  }

  /**
   * The owner downloaded a recovery kit for escrow key `version` / `kid`
   * (the Worker checked the step-up): recorded, with the time, for the kit
   * status and the "download a fresh kit" notice. Not secret.
   */
  async recordKit(uid, { version, kid }) {
    this.#bind(uid);
    const kit = { version, kid, at: nowSec() };
    this.#setMeta('kit', JSON.stringify(kit));
    return { ok: true, kit };
  }

  /**
   * AUTHN owner recovery replaced the owner's password: the `pw` wrap (if
   * any) opens only with the old one, so it is marked stale and the owner's
   * browser writes the new one, once the recovery kit has opened the Drive,
   * without a second confirmation (docs/DRIVE.md §3).
   */
  async markPwStale(uid) {
    this.#bind(uid);
    this.#setMeta('pwStale', '1');
    return { ok: true };
  }

  /**
   * The owner's recovery kit puts back sealed escrow keys (the Worker checks
   * each against the escrow public key, the signing key or a kid in use, and
   * the step-up for replacing one that is there): `escrowPriv`,
   * `escrowSignPriv`, and earlier keys `old` { kid: sealed }. Values are
   * opaque (sealed under the owner's DK).
   */
  async restoreEscrowKeys(uid, { escrowPriv, escrowSignPriv, old = {} } = {}) {
    this.#bind(uid);
    const cur = this.#oldEscrow();
    this.ctx.storage.transactionSync(() => {
      if (escrowPriv !== undefined) this.#setMeta('escrowPriv', escrowPriv);
      if (escrowSignPriv !== undefined) this.#setMeta('escrowSignPriv', escrowSignPriv);
      if (Object.keys(old).length) this.#setMeta('escrowPrivOld', JSON.stringify({ ...cur, ...old }));
    });
    return { ok: true };
  }

  /**
   * The account's password changed (`reset`: set by the owner, from Admin or
   * while acting as the user). The `pw` wrap still opens with the old
   * password, which may be the compromised one: after a reset it goes at once
   * when another wrap of the user's own remains (a passkey or a recovery
   * code), else it is marked stale; after the user's own change it is marked
   * stale (their browser writes the new one right away). A stale wrap may be
   * replaced without the step-up, and goes when it is.
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
    if (!n || n.kind !== 'file' || n.state !== 'ready' || n.rs) return { status: 'gone' };
    if (!Number.isInteger(i) || i < 0 || i >= n.chunks) return { status: 'bad_index' };
    return { status: 'ok', key: driveChunkKey(uid, id, i), size: driveChunkSize(n.size, i) };
  }

  /** Move (`parent`) and / or rename (`name`, `meta`) an item. The root can do neither. */
  async patchNode(uid, id, { parent, name, meta, capacity = null }) {
    this.#bind(uid);
    if (id === ROOT) return fail(400, 'root', 'The top folder cannot be moved or renamed.');
    const n = this.#node(id);
    if (!n || n.rs) return fail(404, 'not_found', 'No such item.');
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
      password: !!r.ph, note: !!r.note, captcha: r.captcha !== 0, maxFiles: opts.maxFiles ?? null, maxBytes: opts.maxBytes ?? null,
      maxFileBytes: opts.maxFileBytes ?? null, types: opts.types ?? null, files: r.files, bytes: r.bytes,
      pending: this.sql.exec("SELECT COUNT(*) AS c FROM nodes WHERE rs = ? AND state = 'ready' AND rfail IS NULL", r.id).one().c,
      failed: this.sql.exec("SELECT COUNT(*) AS c FROM nodes WHERE rs = ? AND state = 'ready' AND rfail IS NOT NULL", r.id).one().c,
      // Received items kept in an archive (the owner started over), sealed as they arrived.
      kept: r.agen === null || r.agen === undefined ? 0 : this.sql.exec('SELECT COUNT(*) AS c FROM archive_nodes WHERE rs = ?', r.id).one().c,
    };
    if (priv) o.priv = JSON.parse(r.priv);
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

  /** A new reverse share on folder `rec.folder` (values arrive validated). */
  async createReverse(uid, rec) {
    this.#bind(uid);
    // The link's private key is sealed with the Drive's key (DK): a Drive without one has nothing to seal it with.
    if (!this.sql.exec('SELECT 1 FROM wraps LIMIT 1').toArray().length) return fail(409, 'drive_not_set_up', 'Set up the Drive before receiving files into it.');
    const f = this.#node(rec.folder);
    if (!f || f.rs) return fail(404, 'not_found', 'The folder does not exist.');
    if (f.kind !== 'dir') return fail(400, 'not_a_folder', 'Files can only be received into a folder.');
    if (this.#reverse(rec.id)) return fail(409, 'exists', 'A reverse share with this id already exists.');
    this.#dropEndedReverse();
    if (this.sql.exec('SELECT COUNT(*) AS c FROM reverse').one().c >= MAX_REVERSE) return fail(409, 'too_many_reverse', `A Drive holds at most ${MAX_REVERSE} reverse shares.`);
    const t = nowSec();
    this.sql.exec(`INSERT INTO reverse (id, folder, priv, lh, ph, salt, t, note, opts, created, expires, status, captcha) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)`,
      rec.id, rec.folder, rec.priv, rec.lh, rec.ph ?? null, rec.salt ?? null, rec.t ?? null, rec.note ?? null, JSON.stringify(rec.opts), t, t + rec.ttl, rec.captcha === true ? 1 : 0);
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

  // ── the owner's archived Drive (starting over without a kit) ─────────────
  /**
   * The owner starts over without a recovery kit (docs/DRIVE.md §3): the
   * Drive as it is — items, R2 objects (untouched), wraps, the salt and the
   * sealed escrow keys, all still sealed under the old DK — becomes archive
   * `gen`, which nothing here can open; the Drive is empty again (only the
   * escrow key's version record and the account binding stay) and set up
   * with the new keys (`keys`: the `pw` wrap, the salt, the sealed escrow and
   * signing keys, the new escrow kid and the key check value) in the same
   * transaction. Unfinished uploads go, as the alarm would drop them. Shares
   * of archived items keep working (their keys are in their links).
   *
   * Reverse links (docs/REVERSE.md): their private keys are sealed under the
   * old DK, so each link now belongs to the archive (`agen`); the active ones
   * are **paused** in the same transaction — no new session or upload; their
   * open sessions end (what those sessions received is logged) and their
   * unfinished uploads go — and the items they received stay in the archive
   * exactly as they arrived, sealed to the link's key. A restore of the
   * archive resumes them; deleting it revokes them.
   *
   * Atomic (R5-L2): it runs inside blockConcurrencyWhile, and first re-checks
   * that nothing the owner signs in with opens the Drive (no passkey or
   * recovery-code wrap, no `pw` wrap or only a stale one). A second start
   * over at the same moment finds the first one's fresh `pw` wrap and gets
   * `409 drive_unlockable`: one archive, one key check value, one set of keys
   * (and no link paused twice). → { gen, paused: [link ids] }.
   */
  async startOver(uid, { driveSalt, set = [], escrowPriv, escrowSignPriv, newEscrowKid, kcv } = {}) {
    this.#bind(uid);
    if (typeof driveSalt !== 'string' || set.length !== 1 || set[0].kind !== 'pw' || typeof escrowPriv !== 'string' || typeof escrowSignPriv !== 'string' || typeof kcv !== 'string' || typeof newEscrowKid !== 'string') {
      throw new Error('drive: startOver needs the new keys');
    }
    return this.ctx.blockConcurrencyWhile(async () => {
      const stale = this.#meta('pwStale') === '1';
      const usable = this.sql.exec('SELECT kind FROM wraps').toArray().some((w) => w.kind === 'passkey' || w.kind === 'recovery' || (w.kind === 'pw' && !stale));
      if (usable) return fail(409, 'drive_unlockable', 'Your Drive can still be unlocked (a password, passkey or recovery-code key of yours opens it): unlock it instead.');
      const pending = this.sql.exec("SELECT id, chunks, size, rs FROM nodes WHERE kind = 'file' AND state = 'pending'").toArray();
      await this.#deleteObjects(uid, pending);
      // Archive numbers never repeat (one restored or deleted keeps its number).
      const gen = Math.max(Number(this.#meta('archiveGen')) || 0, this.sql.exec('SELECT MAX(gen) AS g FROM archive_meta').one().g ?? 0) + 1;
      let paused = [];
      this.ctx.storage.transactionSync(() => {
        // A reserved received file gives its link's allowance back, as when the alarm purges it.
        for (const f of pending) this.#dropPending(f);
        // Links whose key an earlier archive seals keep that archive (the key is under its DK).
        this.sql.exec('UPDATE reverse SET agen = ? WHERE agen IS NULL', gen);
        paused = this.sql.exec("SELECT id FROM reverse WHERE status = 'active' AND agen = ? AND expires > ?", gen, nowSec()).toArray().map((r) => r.id);
        this.sql.exec("UPDATE reverse SET status = 'paused' WHERE status = 'active' AND agen = ?", gen);
        // Their sessions end now (#lapseSessions below logs what they received).
        this.sql.exec("UPDATE rsessions SET expires = 0 WHERE rid IN (SELECT id FROM reverse WHERE status = 'paused')");
        this.sql.exec(`INSERT INTO archive_nodes (gen, ${ARCHIVE_COLS}) SELECT ?, ${ARCHIVE_COLS} FROM nodes WHERE id != ?`, gen, ROOT);
        this.sql.exec('DELETE FROM nodes WHERE id != ?', ROOT);
        this.sql.exec('INSERT INTO archive_wraps (gen, kind, ref, data) SELECT ?, kind, ref, data FROM wraps', gen);
        this.sql.exec('DELETE FROM wraps');
        for (const k of ARCHIVED_META) {
          const v = this.#meta(k);
          if (v === null) continue;
          this.sql.exec('INSERT INTO archive_meta (gen, k, v) VALUES (?, ?, ?)', gen, k, v);
          this.#setMeta(k, null);
        }
        this.sql.exec("INSERT INTO archive_meta (gen, k, v) VALUES (?, 'at', ?)", gen, String(nowSec()));
        this.#setMeta('archiveGen', String(gen));
        // The new keys, in the same step.
        this.sql.exec('INSERT INTO wraps (kind, ref, data) VALUES (?, ?, ?)', set[0].kind, set[0].ref, set[0].data);
        this.#setMeta('driveSalt', driveSalt);
        this.#setMeta('escrowPriv', escrowPriv);
        this.#setMeta('escrowSignPriv', escrowSignPriv);
        this.#setMeta('kcv', kcv);
        const ver = this.#json('escrowVer');
        const next = ver && Number.isSafeInteger(ver.version) ? ver.version + 1 : 2;
        if (!ver || ver.kid !== newEscrowKid) this.#setMeta('escrowVer', JSON.stringify({ version: next, kid: newEscrowKid, created: nowSec() }));
      });
      await this.#lapseSessions();
      await this.ctx.storage.deleteAlarm();
      return { ok: true, gen, paused };
    });
  }

  #archiveMeta(gen) {
    const rows = this.sql.exec('SELECT k, v FROM archive_meta WHERE gen = ?', gen).toArray();
    return rows.length ? Object.fromEntries(rows.map((r) => [r.k, r.v])) : null;
  }

  /**
   * Archive `gen` for the owner's browser to restore it with a recovery kit:
   * its sealed escrow keys and a page of its items (sealed fields as stored),
   * by id after `after`. A received item (`rs`, its link) is restored as
   * it is: it is sealed to its link's key, not the DK. The first page lists
   * the reverse links whose private keys the archive's DK seals (`reverse`:
   * [{ id, priv, status }]), for the browser to re-seal them under the
   * Drive's DK now. → { gen, at, escrowPriv, escrowSignPriv, escrowPrivOld,
   * items, nodes, reverse?, next }.
   */
  async archiveView(uid, gen, { after = '', limit = 500 } = {}) {
    this.#bind(uid);
    const m = this.#archiveMeta(gen);
    if (!m) return fail(404, 'not_found', 'No such archive.');
    const parse = (v) => { try { return JSON.parse(v); } catch { return null; } };
    const lim = Math.max(1, Math.min(1000, limit | 0));
    const rows = this.sql.exec('SELECT * FROM archive_nodes WHERE gen = ? AND id > ? ORDER BY id LIMIT ?', gen, after, lim).toArray();
    return {
      ok: true, gen, at: Number(m.at) || null,
      escrowPriv: m.escrowPriv ?? null, escrowSignPriv: m.escrowSignPriv ?? null, escrowPrivOld: parse(m.escrowPrivOld || '{}') || {},
      items: this.sql.exec('SELECT COUNT(*) AS c FROM archive_nodes WHERE gen = ?', gen).one().c,
      nodes: rows.map((r) => ({
        id: r.id, parent: r.parent, kind: r.kind, name: parse(r.name), meta: r.meta ? parse(r.meta) : null, fk: r.fk ? parse(r.fk) : null,
        size: r.size, chunks: r.chunks, state: r.state, created: r.created, updated: r.updated, ...(r.rs ? { rs: r.rs } : {}),
      })),
      ...(after ? {} : { reverse: this.#archiveLinks(gen).map((r) => ({ id: r.id, priv: parse(r.priv), status: this.#reverseState(r) })) }),
      next: rows.length === lim ? rows[rows.length - 1].id : null,
    };
  }

  /** The reverse links whose private keys archive `gen`'s DK seals. */
  #archiveLinks(gen) {
    return this.sql.exec('SELECT * FROM reverse WHERE agen = ? ORDER BY id', gen).toArray();
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
  async reverseBegin(uid, id, hash, ttl, { net = null, proofHash = null, human = null } = {}) {
    this.#bind(uid);
    const tag = await this.#netTag(id, net); // before any check: nothing below awaits
    const r = this.#reverse(id);
    const st = this.#reverseState(r);
    if (st === 'paused') return { status: 'paused' };
    if (st !== 'active') return { status: 'gone' };
    const t = nowSec();
    // A CAPTCHA grant (checked by the Worker) starts one session, whatever
    // follows (a wrong password included): each attempt costs a CAPTCHA.
    if (human) {
      this.sql.exec('DELETE FROM rhuman WHERE exp <= ?', t);
      if (this.sql.exec('SELECT 1 FROM rhuman WHERE j = ?', human.j).toArray().length) return { status: 'captcha_used' };
      this.sql.exec('INSERT INTO rhuman (j, exp) VALUES (?, ?)', human.j, human.exp);
    }
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
    const fk = JSON.stringify({ kind: 'rs', data: wrap });
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
    const items = page.map((r) => ({
      id: r.id, parent: r.parent, rs: r.rs, name: JSON.parse(r.name), meta: r.meta ? JSON.parse(r.meta) : null,
      fk: JSON.parse(r.fk), size: r.size, chunks: r.chunks, created: r.created,
    }));
    const keys = [...new Set(items.map((i) => i.rs))].map((rid) => this.#reverse(rid)).filter(Boolean).map((r) => ({ id: r.id, priv: JSON.parse(r.priv) }));
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

  /** A received file re-wrapped by the user's browser: from now on an ordinary Drive file (in `parent`). */
  async acceptReceived(uid, node, { parent, name, meta, fk }) {
    this.#bind(uid);
    const n = this.#node(node);
    if (!n || !n.rs || n.state !== 'ready' || (this.#reverse(n.rs)?.agen ?? null) !== null) return fail(409, 'not_received', 'This is not a received file waiting to be added.');
    if (parent !== n.parent) {
      const bad = this.#checkParent(parent);
      if (bad) return bad;
    }
    this.sql.exec('UPDATE nodes SET parent = ?, name = ?, meta = ?, fk = ?, rs = NULL, rfail = NULL, rwhy = NULL, updated = ? WHERE id = ?', parent, name, meta, fk, nowSec(), node);
    this.#dropEndedReverse();
    return { ok: true, used: this.#used(), rs: n.rs };
  }

  /**
   * Bring archived items back into the Drive, their sealed fields re-sealed
   * by the owner's browser under the Drive's DK now (`nodes`: [{ id, name,
   * meta?, fk? }], stored JSON text; a field left out keeps its archived
   * value). Parents first: an item whose folder is still archived is refused.
   * The archive's top-level items land in the Drive's top level. Content (R2)
   * is not touched: each file's chunks are under its own key. A received item
   * (reverse shares) comes back exactly as it was, sealed to its link's key
   * (`{ id }` only): the browser takes it in once the link's key is re-sealed
   * (finishArchive).
   */
  async restoreArchiveNodes(uid, gen, list) {
    this.#bind(uid);
    if (!this.#archiveMeta(gen)) return fail(404, 'not_found', 'No such archive.');
    const rows = [];
    for (const x of list) {
      const r = this.sql.exec('SELECT * FROM archive_nodes WHERE gen = ? AND id = ?', gen, x.id).toArray()[0];
      if (!r) return fail(404, 'not_found', 'An item is not in the archive.');
      if (this.#node(r.id)) return fail(409, 'exists', 'An item with this id already exists.');
      const given = x.name !== undefined || x.meta !== undefined || x.fk !== undefined;
      if (r.rs && given) return fail(400, 'received_as_is', 'A received item comes back as it is: send only its id.');
      if (!r.rs && x.name === undefined) return fail(400, 'invalid', 'Each item needs its name re-sealed under the Drive key.');
      rows.push({ r, x });
    }
    const moving = new Set(rows.map(({ r }) => r.id));
    for (const { r } of rows) {
      if (r.parent !== ROOT && !moving.has(r.parent) && !this.#node(r.parent)) return fail(409, 'parent_first', 'Restore an item’s folder before the item.');
    }
    if (this.#count() + rows.length > MAX_NODES) return fail(409, 'drive_full', `A Drive holds at most ${MAX_NODES} items.`);
    const top = rows.filter(({ r }) => r.parent === ROOT).length;
    if (top && this.sql.exec('SELECT COUNT(*) AS c FROM nodes WHERE parent = ?', ROOT).one().c + top > MAX_CHILDREN) return fail(409, 'folder_full', `A folder holds at most ${MAX_CHILDREN} items.`);
    this.ctx.storage.transactionSync(() => {
      for (const { r, x } of rows) {
        this.sql.exec(`INSERT INTO nodes (${ARCHIVE_COLS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          r.id, r.parent, r.kind, x.name ?? r.name, x.meta === undefined ? r.meta : x.meta, r.size, r.chunks, x.fk === undefined ? r.fk : x.fk,
          r.state, r.done, r.upload_hash, r.created, nowSec(), r.rs ?? null, r.rfail ?? null, r.rwhy ?? null);
        this.sql.exec('DELETE FROM archive_nodes WHERE gen = ? AND id = ?', gen, r.id);
      }
    });
    return { ok: true, restored: rows.length, left: this.sql.exec('SELECT COUNT(*) AS c FROM archive_nodes WHERE gen = ?', gen).one().c, used: this.#used() };
  }

  /**
   * The archive's items are all back: its earlier escrow keys, re-sealed by
   * the owner's browser under the Drive's DK (`old` { kid: sealed }, checked
   * by the Worker), join escrowPrivOld, and the archive (its old wraps and
   * sealed keys) goes. Its reverse links' private keys, re-sealed by the
   * browser under the Drive's DK (`reverse` { linkId: sealed }, one for each
   * link of the archive, none other), replace the old ones: the paused links
   * resume (uploads again) and their received items can be taken in.
   * → { resumed: [link ids] }.
   */
  async finishArchive(uid, gen, { old = {}, reverse = {} } = {}) {
    this.#bind(uid);
    if (!this.#archiveMeta(gen)) return fail(404, 'not_found', 'No such archive.');
    if (this.sql.exec('SELECT COUNT(*) AS c FROM archive_nodes WHERE gen = ?', gen).one().c) return fail(409, 'archive_not_empty', 'Restore every archived item first.');
    const links = this.#archiveLinks(gen);
    if (Object.keys(reverse).length !== links.length || links.some((l) => typeof reverse[l.id] !== 'string')) {
      return fail(409, 'reverse_keys_required', 'Re-seal the private key of every reverse link of this archive under the Drive key.', { links: links.map((l) => l.id) });
    }
    const t = nowSec();
    const resumed = links.filter((l) => l.status === 'paused' && l.expires > t).map((l) => l.id);
    const cur = this.#oldEscrow();
    this.ctx.storage.transactionSync(() => {
      if (Object.keys(old).length) this.#setMeta('escrowPrivOld', JSON.stringify({ ...cur, ...old }));
      for (const l of links) {
        this.sql.exec("UPDATE reverse SET priv = ?, agen = NULL, status = CASE WHEN status = 'paused' THEN 'active' ELSE status END WHERE id = ?", reverse[l.id], l.id);
      }
      this.sql.exec('DELETE FROM archive_wraps WHERE gen = ?', gen);
      this.sql.exec('DELETE FROM archive_meta WHERE gen = ?', gen);
    });
    return { ok: true, resumed };
  }

  /**
   * The owner deletes archive `gen` (no kit could restore it afterwards): its
   * R2 objects, items, wraps and sealed keys. Its paused reverse links are
   * revoked, and the items they received (in the archive) go with it.
   * → the shares that referenced its items (the Worker ends them) and the
   * revoked links (the Worker ends them in the share index).
   */
  async deleteArchive(uid, gen) {
    this.#bind(uid);
    if (!this.#archiveMeta(gen)) return fail(404, 'not_found', 'No such archive.');
    return this.ctx.blockConcurrencyWhile(async () => {
      await this.#deleteObjects(uid, this.sql.exec("SELECT id, chunks FROM archive_nodes WHERE gen = ? AND kind = 'file'", gen).toArray());
      const shares = this.sql.exec('SELECT DISTINCT share_id FROM refs WHERE node_id IN (SELECT id FROM archive_nodes WHERE gen = ?)', gen).toArray().map((r) => r.share_id);
      const revoked = this.#archiveLinks(gen).filter((l) => l.status === 'paused').map((l) => l.id);
      this.ctx.storage.transactionSync(() => {
        this.sql.exec("UPDATE reverse SET status = 'revoked', ended = ? WHERE agen = ? AND status = 'paused'", nowSec(), gen);
        this.sql.exec('DELETE FROM refs WHERE node_id IN (SELECT id FROM archive_nodes WHERE gen = ?)', gen);
        this.sql.exec('DELETE FROM archive_nodes WHERE gen = ?', gen);
        this.sql.exec('DELETE FROM archive_wraps WHERE gen = ?', gen);
        this.sql.exec('DELETE FROM archive_meta WHERE gen = ?', gen);
      });
      return { ok: true, shares, revoked, used: this.#used() };
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
    await this.#schedulePurge();
  }
}
