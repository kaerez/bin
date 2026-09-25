// guard-do.js — Guard Durable Object: per-IP brute-force tracking and blocks
// for the login / setup / invalid (enumeration, wrong link, wrong password)
// scopes. Sharded by hash(tracking key) across GUARD_SHARDS instances so no
// single object sees all traffic; the admin view fans out to every shard.
//
// Rule semantics (admin-configurable, see settings.js): X failures within a
// fixed window that opens at the first failure → block that key for N seconds.
// Rows expire by themselves; an alarm prunes them.

import { DurableObject } from 'cloudflare:workers';

export const GUARD_SHARDS = 8;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS tracking (scope TEXT NOT NULL, key TEXT NOT NULL, count INTEGER NOT NULL, start INTEGER NOT NULL,
  expires INTEGER NOT NULL, PRIMARY KEY (scope, key));
CREATE TABLE IF NOT EXISTS blocks (scope TEXT NOT NULL, key TEXT NOT NULL, until INTEGER NOT NULL, since INTEGER NOT NULL,
  PRIMARY KEY (scope, key));
`;

const now = () => Math.floor(Date.now() / 1000);

export class Guard extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    ctx.blockConcurrencyWhile(async () => { this.sql.exec(SCHEMA); });
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

  /** Record one failure; returns the (possibly new) block state. */
  async fail(scope, key, rule) {
    const ts = now();
    const blocked = await this.check(scope, key);
    if (blocked.blocked) return blocked;
    const r = this.sql.exec('SELECT count, start FROM tracking WHERE scope = ? AND key = ?', scope, key).toArray()[0];
    const fresh = !r || ts - r.start >= rule.windowSec;
    const count = fresh ? 1 : r.count + 1;
    const start = fresh ? ts : r.start;
    if (count >= rule.max) {
      const until = ts + rule.blockSec;
      this.sql.exec('INSERT OR REPLACE INTO blocks (scope, key, until, since) VALUES (?, ?, ?, ?)', scope, key, until, ts);
      this.sql.exec('DELETE FROM tracking WHERE scope = ? AND key = ?', scope, key);
      await this.#schedule(until);
      return { blocked: true, until, newlyBlocked: true };
    }
    const expires = start + rule.windowSec;
    this.sql.exec('INSERT OR REPLACE INTO tracking (scope, key, count, start, expires) VALUES (?, ?, ?, ?, ?)', scope, key, count, start, expires);
    await this.#schedule(expires);
    return { blocked: false, count };
  }

  async list() {
    const ts = now();
    return {
      blocks: this.sql.exec('SELECT scope, key, until, since FROM blocks WHERE until > ? ORDER BY since DESC', ts).toArray(),
      tracking: this.sql.exec('SELECT scope, key, count, start, expires FROM tracking WHERE expires > ? ORDER BY count DESC', ts).toArray(),
    };
  }

  async unblock(scope, key) {
    this.sql.exec('DELETE FROM blocks WHERE scope = ? AND key = ?', scope, key);
    this.sql.exec('DELETE FROM tracking WHERE scope = ? AND key = ?', scope, key);
    return { ok: true };
  }

  async block(scope, key, until) {
    this.sql.exec('INSERT OR REPLACE INTO blocks (scope, key, until, since) VALUES (?, ?, ?, ?)', scope, key, until, now());
    await this.#schedule(until);
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
