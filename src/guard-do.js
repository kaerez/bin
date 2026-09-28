// guard-do.js — Guard Durable Object: per-network brute-force tracking and
// blocks for the login / setup / invalid (enumeration, wrong link, wrong
// password) scopes and the rate limits. Sharded by hash(key) across
// GUARD_SHARDS instances so no single object sees all traffic; the admin view
// fans out to every shard.
//
// A row's key is a keyed hash of the network (src/lib/records.js guardTag),
// never the address: the address itself is kept only for the owner's view,
// sealed by the Worker under the Guard's record key (`addr`, with its key id
// in `rk`), or in the clear (`rk` NULL) while the instance has no keyring yet.
// The Directory's background pass seals those, re-seals rows under an
// earlier root's key and re-keys rows from before the tags (SECURITY.md, "Records at rest").
// This object never holds a key and never opens an address.
//
// Rule semantics (admin-configurable, see settings.js): X failures within a
// fixed window that opens at the first failure → block that key for N seconds.
// Rows expire by themselves; an alarm prunes them.

import { DurableObject } from 'cloudflare:workers';

export const GUARD_SHARDS = 8;

/** The shard (0 … GUARD_SHARDS − 1) that holds `key` (FNV-1a). */
export function guardShardIndex(key) {
  let h = 0x811c9dc5;
  for (let i = 0; i < key.length; i++) { h ^= key.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
  return h % GUARD_SHARDS;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS tracking (scope TEXT NOT NULL, key TEXT NOT NULL, count INTEGER NOT NULL, start INTEGER NOT NULL,
  expires INTEGER NOT NULL, addr TEXT, rk TEXT, PRIMARY KEY (scope, key));
CREATE TABLE IF NOT EXISTS blocks (scope TEXT NOT NULL, key TEXT NOT NULL, until INTEGER NOT NULL, since INTEGER NOT NULL,
  addr TEXT, rk TEXT, PRIMARY KEY (scope, key));
`;
const TABLES = ['tracking', 'blocks'];
/** Rows the Directory's pass asks for at once. */
const MAX_PENDING = 500;

const now = () => Math.floor(Date.now() / 1000);
const str = (v) => (typeof v === 'string' ? v : null);

export class Guard extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    ctx.blockConcurrencyWhile(async () => {
      this.sql.exec(SCHEMA);
      // Shards made before the addresses were sealed: their rows are keyed by the address (re-keyed by the Directory's pass).
      for (const t of TABLES) {
        const cols = new Set(this.sql.exec(`PRAGMA table_info(${t})`).toArray().map((c) => c.name));
        for (const c of ['addr', 'rk']) if (!cols.has(c)) this.sql.exec(`ALTER TABLE ${t} ADD COLUMN ${c} TEXT`);
      }
    });
  }

  async #schedule(atSec) {
    const cur = await this.ctx.storage.getAlarm();
    const at = atSec * 1000 + 1000;
    if (cur === null || cur > at) await this.ctx.storage.setAlarm(at);
  }

  /** { blocked: boolean, until } for one scope + key. */
  async check(scope, key) {
    const r = this.sql.exec('SELECT until FROM blocks WHERE scope = ? AND key = ?', scope, key).toArray()[0];
    return r && r.until > now() ? { blocked: true, until: r.until } : { blocked: false };
  }

  /**
   * Record one failure; returns the (possibly new) block state. `sealed`:
   * the network's address for the owner's view ({ addr, rk }: sealed under
   * key id `rk`, or in the clear with rk null), kept with the row.
   */
  async fail(scope, key, rule, sealed = null) {
    const ts = now();
    const blocked = await this.check(scope, key);
    if (blocked.blocked) return blocked;
    const addr = str(sealed?.addr);
    const rk = addr === null ? null : str(sealed?.rk);
    const r = this.sql.exec('SELECT count, start FROM tracking WHERE scope = ? AND key = ?', scope, key).toArray()[0];
    const fresh = !r || ts - r.start >= rule.windowSec;
    const count = fresh ? 1 : r.count + 1;
    const start = fresh ? ts : r.start;
    if (count >= rule.max) {
      const until = ts + rule.blockSec;
      this.sql.exec('INSERT OR REPLACE INTO blocks (scope, key, until, since, addr, rk) VALUES (?, ?, ?, ?, ?, ?)', scope, key, until, ts, addr, rk);
      this.sql.exec('DELETE FROM tracking WHERE scope = ? AND key = ?', scope, key);
      await this.#schedule(until);
      return { blocked: true, until, newlyBlocked: true };
    }
    const expires = start + rule.windowSec;
    this.sql.exec('INSERT OR REPLACE INTO tracking (scope, key, count, start, expires, addr, rk) VALUES (?, ?, ?, ?, ?, ?, ?)', scope, key, count, start, expires, addr, rk);
    await this.#schedule(expires);
    return { blocked: false, count };
  }

  /** Every live row, with its address as stored (sealed or not): the Worker has the Directory open them for the owner. */
  async list() {
    const ts = now();
    return {
      blocks: this.sql.exec('SELECT scope, key, until, since, addr, rk FROM blocks WHERE until > ? ORDER BY since DESC', ts).toArray(),
      tracking: this.sql.exec('SELECT scope, key, count, start, expires, addr, rk FROM tracking WHERE expires > ? ORDER BY count DESC', ts).toArray(),
    };
  }

  /** One key's stored address ({ addr, rk } from its block, else its tracking row) or null. */
  async row(scope, key) {
    for (const t of ['blocks', 'tracking']) {
      const r = this.sql.exec(`SELECT addr, rk FROM ${t} WHERE scope = ? AND key = ?`, scope, key).toArray()[0];
      if (r) return r;
    }
    return null;
  }

  async unblock(scope, key) {
    this.sql.exec('DELETE FROM blocks WHERE scope = ? AND key = ?', scope, key);
    this.sql.exec('DELETE FROM tracking WHERE scope = ? AND key = ?', scope, key);
    return { ok: true };
  }

  /** The owner blocks a key (from the tracking list): the block keeps the row's address. */
  async block(scope, key, until) {
    const r = await this.row(scope, key);
    this.sql.exec('INSERT OR REPLACE INTO blocks (scope, key, until, since, addr, rk) VALUES (?, ?, ?, ?, ?, ?)', scope, key, until, now(), r?.addr ?? null, r?.rk ?? null);
    await this.#schedule(until);
    return { ok: true };
  }

  // ── the Directory's background pass (SECURITY.md, "Records at rest") ─────────────────────

  /**
   * Live rows the pass has work for: keyed by the address (from before the
   * tags), with an address in the clear, or sealed under another key id than
   * `kid` (the current one; null: no keyring, so only the re-keying).
   */
  async pending({ kid = null, limit = MAX_PENDING } = {}) {
    const ts = now();
    const lim = Math.max(1, Math.min(MAX_PENDING, limit | 0));
    const cond = kid ? "(key NOT LIKE 'h:%' OR (addr IS NOT NULL AND (rk IS NULL OR rk != ?)))" : "key NOT LIKE 'h:%'";
    const args = kid ? [kid] : [];
    return [
      ...this.sql.exec(`SELECT 'blocks' AS t, scope, key, until, since, addr, rk FROM blocks WHERE until > ? AND ${cond} LIMIT ?`, ts, ...args, lim).toArray(),
      ...this.sql.exec(`SELECT 'tracking' AS t, scope, key, count, start, expires, addr, rk FROM tracking WHERE expires > ? AND ${cond} LIMIT ?`, ts, ...args, lim).toArray(),
    ];
  }

  /**
   * The pass's results for rows of this shard: `reseal` [{ t, scope, key,
   * addr, rk, was: { addr, rk } }] (only if the row still holds `was`);
   * `adopt` [row with its new key] (a re-keyed row that lands here: a block
   * keeps the later end, a tracking row already here is kept); `drop` [{ t,
   * scope, key }] (the re-keyed rows' old keys).
   */
  async apply({ reseal = [], adopt = [], drop = [] } = {}) {
    let next = null;
    this.ctx.storage.transactionSync(() => {
      for (const r of reseal) {
        if (!TABLES.includes(r.t)) continue;
        this.sql.exec(`UPDATE ${r.t} SET addr = ?, rk = ? WHERE scope = ? AND key = ? AND addr IS ? AND rk IS ?`,
          str(r.addr), str(r.rk), r.scope, r.key, str(r.was?.addr), str(r.was?.rk));
      }
      for (const r of adopt) {
        if (r.t === 'blocks') {
          this.sql.exec(`INSERT INTO blocks (scope, key, until, since, addr, rk) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(scope, key) DO UPDATE SET until = MAX(until, excluded.until)`, r.scope, r.key, r.until, r.since, str(r.addr), str(r.rk));
          next = Math.min(next ?? r.until, r.until);
        } else if (r.t === 'tracking') {
          this.sql.exec('INSERT OR IGNORE INTO tracking (scope, key, count, start, expires, addr, rk) VALUES (?, ?, ?, ?, ?, ?, ?)',
            r.scope, r.key, r.count, r.start, r.expires, str(r.addr), str(r.rk));
          next = Math.min(next ?? r.expires, r.expires);
        }
      }
      for (const r of drop) if (TABLES.includes(r.t)) this.sql.exec(`DELETE FROM ${r.t} WHERE scope = ? AND key = ?`, r.scope, r.key);
    });
    if (next !== null) await this.#schedule(next);
    return { ok: true };
  }

  async alarm() {
    const ts = now();
    this.sql.exec('DELETE FROM blocks WHERE until <= ?', ts);
    this.sql.exec('DELETE FROM tracking WHERE expires <= ?', ts);
    const next = this.sql.exec('SELECT MIN(t) AS t FROM (SELECT MIN(until) AS t FROM blocks UNION ALL SELECT MIN(expires) AS t FROM tracking)').toArray()[0];
    if (next && next.t) await this.ctx.storage.setAlarm(next.t * 1000 + 1000);
  }
}
