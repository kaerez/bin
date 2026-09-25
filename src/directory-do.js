// directory-do.js — the Directory Durable Object: one strongly-consistent,
// SQLite-backed instance (idFromName('directory')) holding accounts, sessions
// revocation, API keys, capability limits, quotas + usage counters, global
// settings, viewer rules, manual IP rules, the "My shares" index, and the
// activity/audit log.
//
// Why a DO and not KV: quotas, lockouts and counters need atomic
// read-modify-write and admin changes must apply immediately; KV is eventually
// consistent (~60 s) and has no transactions. Every RPC method below runs its
// SQL synchronously (no awaits between statements), so each call is atomic
// with respect to every other request.
//
// Secrets never enter this object in usable form: passwords arrive as
// client-side Argon2id outputs and are stored only as SHA-256 verifiers; API
// keys and the setup token as SHA-256 hashes.

import { DurableObject } from 'cloudflare:workers';
import { b64urlFromBytes, randomBytes, utf8, timingSafeEqualHex } from '../public/js/bytes.js';
import { ARGON2 } from '../public/js/format.js';
import {
  SETTINGS, checkSetting, settingsWithDefaults, LIMITS, checkLimit, resolveLimits, restrictForApi,
  UNLIMITED, checkQuota, quotaBucket, checkViewerRule, DEFAULT_VIEWER_RULES,
} from './lib/settings.js';
import { normalizeRule } from './lib/ip.js';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, role TEXT NOT NULL,
  pw_salt TEXT NOT NULL, pw_t INTEGER NOT NULL, pw_verifier TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0,
  sess_ver INTEGER NOT NULL DEFAULT 1, created INTEGER NOT NULL, updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS limits (user_id TEXT NOT NULL, channel TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL,
  PRIMARY KEY (user_id, channel, key));
CREATE TABLE IF NOT EXISTS quotas (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, channel TEXT NOT NULL, kind TEXT NOT NULL,
  n INTEGER NOT NULL, unit TEXT NOT NULL, max INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS usage (quota_id TEXT NOT NULL, user_id TEXT NOT NULL, bucket INTEGER NOT NULL,
  count INTEGER NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY (quota_id, user_id, bucket));
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS viewer_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, match TEXT NOT NULL,
  value TEXT NOT NULL, renderer TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS api_keys (key_hash TEXT PRIMARY KEY, id TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL,
  name TEXT NOT NULL, created INTEGER NOT NULL, last_used INTEGER, expires INTEGER);
CREATE TABLE IF NOT EXISTS revoked_sessions (sid TEXT PRIMARY KEY, exp INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS failures (user_id TEXT PRIMARY KEY, count INTEGER NOT NULL, start INTEGER NOT NULL,
  locked_until INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS pwchange_failures (user_id TEXT PRIMARY KEY, count INTEGER NOT NULL, start INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS activity (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, actor_id TEXT,
  subject_id TEXT, action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', imp INTEGER NOT NULL DEFAULT 0,
  adm INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS activity_subject ON activity(subject_id, id);
CREATE TABLE IF NOT EXISTS shares (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, kind TEXT NOT NULL, label TEXT NOT NULL DEFAULT '',
  created INTEGER NOT NULL, expires INTEGER NOT NULL, views_total INTEGER, status TEXT NOT NULL,
  locked INTEGER NOT NULL DEFAULT 0, locked_by TEXT, locked_at INTEGER);
CREATE INDEX IF NOT EXISTS shares_user ON shares(user_id, created);
CREATE TABLE IF NOT EXISTS ip_rules (id TEXT PRIMARY KEY, cidr TEXT NOT NULL, action TEXT NOT NULL, expires INTEGER,
  note TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
`;

// Ordered, idempotent schema migrations for Directories created by an older
// release. SCHEMA above always describes the latest shape (fresh instances need
// nothing); each step only adds what an older instance lacks, and the applied
// version is recorded in meta so a step runs at most once. Never edit a
// shipped step — append a new one.
const MIGRATIONS = [
  // 1: activity.imp (impersonation flag)
  (m) => m.addColumn('activity', 'imp', 'INTEGER NOT NULL DEFAULT 0'),
  // 2: admin share locks + admin-direct-action flag + share filters' indexes
  (m) => {
    m.addColumn('shares', 'locked', 'INTEGER NOT NULL DEFAULT 0');
    m.addColumn('shares', 'locked_by', 'TEXT');
    m.addColumn('shares', 'locked_at', 'INTEGER');
    m.addColumn('activity', 'adm', 'INTEGER NOT NULL DEFAULT 0');
    m.sql.exec('CREATE INDEX IF NOT EXISTS shares_created ON shares(created)');
    m.sql.exec('CREATE INDEX IF NOT EXISTS shares_expires ON shares(expires)');
  },
];
export const SCHEMA_VERSION = MIGRATIONS.length;

function migrator(sql) {
  const columns = (table) => new Set(sql.exec(`PRAGMA table_info(${table})`).toArray().map((c) => c.name));
  return {
    sql,
    addColumn(table, name, decl) {
      if (!columns(table).has(name)) sql.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${decl}`);
    },
  };
}

const USERNAME_RE = /^[A-Za-z0-9][A-Za-z0-9._@-]{2,63}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const B64_16_RE = /^[A-Za-z0-9_-]{22}$/;
const SHARE_PRUNE_SEC = 30 * 86400;

const now = () => Math.floor(Date.now() / 1000);
const newId = () => b64urlFromBytes(randomBytes(12));
const fail = (status, error, message, extra) => ({ ok: false, status, error, message, ...(extra || {}) });

function cleanLabel(s) {
  if (s === undefined || s === null) return '';
  if (typeof s !== 'string') return null;
  // eslint-disable-next-line no-control-regex
  const v = s.replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  return v.length <= 100 ? v : null;
}

function cleanDetail(s) {
  // eslint-disable-next-line no-control-regex
  return String(s ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 500);
}

export class Directory extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    ctx.blockConcurrencyWhile(async () => {
      this.sql.exec(SCHEMA);
      this.#migrate();
      if (!this.#meta('secret')) this.#setMeta('secret', b64urlFromBytes(randomBytes(32)));
      if (!this.#meta('viewer_seeded')) {
        for (const r of DEFAULT_VIEWER_RULES) {
          this.sql.exec('INSERT INTO viewer_rules (user_id, match, value, renderer) VALUES (?, ?, ?, ?)', '', r.match, r.value, r.renderer);
        }
        this.#setMeta('viewer_seeded', '1');
      }
      if ((await ctx.storage.getAlarm()) === null) await ctx.storage.setAlarm(Date.now() + 3600 * 1000);
    });
  }

  #migrate() {
    const from = Number(this.#meta('schema_version')) || 0;
    if (from >= SCHEMA_VERSION) return;
    const m = migrator(this.sql);
    for (let v = from; v < SCHEMA_VERSION; v++) MIGRATIONS[v](m);
    this.#setMeta('schema_version', String(SCHEMA_VERSION));
  }

  async schemaVersion() {
    return Number(this.#meta('schema_version')) || 0;
  }

  // ── small helpers ─────────────────────────────────────────────────────────
  #meta(k) {
    const r = this.sql.exec('SELECT v FROM meta WHERE k = ?', k).toArray()[0];
    return r ? r.v : null;
  }
  #setMeta(k, v) {
    this.sql.exec('INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v', k, v);
  }
  #user(id) {
    return this.sql.exec('SELECT * FROM users WHERE id = ?', id).toArray()[0] || null;
  }
  #userByName(name) {
    return this.sql.exec('SELECT * FROM users WHERE username = ? COLLATE NOCASE', name).toArray()[0] || null;
  }
  #owner() {
    return this.sql.exec("SELECT * FROM users WHERE role = 'owner'").toArray()[0] || null;
  }
  #publicUser(u) {
    return u && { id: u.id, username: u.username, role: u.role, disabled: !!u.disabled, created: u.created, updated: u.updated };
  }
  /**
   * `actor` is a user id, or { id, imp: true } when the owner acted while
   * impersonating `subject` (the user's own log shows it as theirs; the audit
   * shows the truth), or { id, adm: true } when the owner acted directly from
   * the admin panel on the subject's data (never shown in the user's own log).
   */
  #log(actor, subject, action, detail = '') {
    const obj = actor && typeof actor === 'object';
    const imp = !!(obj && actor.imp);
    const adm = !!(obj && actor.adm);
    const actorIdValue = obj ? actor.id : actor;
    this.sql.exec('INSERT INTO activity (ts, actor_id, subject_id, action, detail, imp, adm) VALUES (?, ?, ?, ?, ?, ?, ?)',
      now(), actorIdValue ?? null, subject ?? null, action, cleanDetail(detail), imp ? 1 : 0, adm ? 1 : 0);
  }
  #settings() {
    const rows = {};
    for (const r of this.sql.exec('SELECT key, value FROM settings').toArray()) {
      try { rows[r.key] = JSON.parse(r.value); } catch { /* ignore a corrupt row: default applies */ }
    }
    return settingsWithDefaults(rows);
  }
  #limitRows(userId, channel) {
    const out = {};
    for (const r of this.sql.exec('SELECT key, value FROM limits WHERE user_id = ? AND channel = ?', userId, channel).toArray()) {
      try { out[r.key] = JSON.parse(r.value); } catch { /* ignore */ }
    }
    return out;
  }
  #effective(u) {
    if (u.role === 'owner') return { all: { ...UNLIMITED, apiMaxKeys: 100 }, api: { ...UNLIMITED } };
    const all = resolveLimits(this.#limitRows('', 'all'), this.#limitRows(u.id, 'all'));
    const api = restrictForApi(all, this.#limitRows('', 'api'), this.#limitRows(u.id, 'api'));
    return { all, api };
  }
  #viewerRules(u, limits) {
    const scope = u.role !== 'owner' && limits.viewerCustomRules ? u.id : '';
    return this.sql.exec('SELECT match, value, renderer FROM viewer_rules WHERE user_id = ? ORDER BY id', scope).toArray()
      .map((r) => ({ match: r.match, value: r.value, renderer: r.renderer }));
  }
  #checkCredential(salt, t, verifier) {
    if (typeof salt !== 'string' || !B64_16_RE.test(salt)) return 'invalid salt';
    // Account passwords all use the default time cost: prelogin answers with
    // `t`, so a per-account value would reveal which usernames exist (unknown
    // names get the default with their fake salt).
    if (t !== ARGON2.tDefault) return `time cost must be ${ARGON2.tDefault}`;
    if (typeof verifier !== 'string' || !HEX64_RE.test(verifier)) return 'invalid verifier';
    return null;
  }

  // ── setup / recovery ─────────────────────────────────────────────────────
  async setupStatus(authnHash) {
    return {
      enabled: typeof authnHash === 'string' && !this.#meta(`authn_used:${authnHash}`),
      ownerExists: !!this.#owner(),
    };
  }

  async setup({ authnHash, username, salt, t, verifier }) {
    if (typeof authnHash !== 'string' || !HEX64_RE.test(authnHash)) return fail(404, 'setup_disabled', 'Setup is disabled.');
    if (this.#meta(`authn_used:${authnHash}`)) {
      return fail(410, 'token_used', 'This setup token was already used. Set a new AUTHN value to run setup again.');
    }
    if (typeof username !== 'string' || !USERNAME_RE.test(username)) return fail(400, 'invalid_username', 'Username must be 3–64 characters: letters, digits, . _ @ -');
    const bad = this.#checkCredential(salt, t, verifier);
    if (bad) return fail(400, 'invalid_credential', bad);
    const ts = now();
    const owner = this.#owner();
    const clash = this.#userByName(username);
    if (clash && (!owner || clash.id !== owner.id)) return fail(409, 'username_taken', 'That username belongs to another account.');
    let recovered = false;
    this.ctx.storage.transactionSync(() => {
      if (owner) {
        recovered = true;
        this.sql.exec('UPDATE users SET username = ?, pw_salt = ?, pw_t = ?, pw_verifier = ?, disabled = 0, sess_ver = sess_ver + 1, updated = ? WHERE id = ?',
          username, salt, t, verifier, ts, owner.id);
        this.sql.exec('DELETE FROM failures WHERE user_id = ?', owner.id);
        this.#log(owner.id, owner.id, 'owner.recovered', `username=${username}`);
      } else {
        const id = newId();
        this.sql.exec("INSERT INTO users (id, username, role, pw_salt, pw_t, pw_verifier, created, updated) VALUES (?, ?, 'owner', ?, ?, ?, ?, ?)",
          id, username, salt, t, verifier, ts, ts);
        this.#log(id, id, 'owner.created', `username=${username}`);
      }
      this.#setMeta(`authn_used:${authnHash}`, String(ts));
    });
    return { ok: true, recovered };
  }

  // ── login / sessions ─────────────────────────────────────────────────────
  async prelogin(username) {
    const u = typeof username === 'string' ? this.#userByName(username) : null;
    if (u) return { salt: u.pw_salt, t: u.pw_t };
    // Unknown user: a stable, secret-keyed fake salt, so the response does not
    // reveal whether the account exists.
    const key = await crypto.subtle.importKey('raw', utf8(this.#meta('secret')), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, utf8(String(username).toLowerCase())));
    return { salt: b64urlFromBytes(mac.subarray(0, 16)), t: ARGON2.tDefault };
  }

  async login({ username, verifier, lockoutOff = false }) {
    const u = typeof username === 'string' ? this.#userByName(username) : null;
    const ts = now();
    const s = this.#settings();
    if (!u) {
      timingSafeEqualHex(String(verifier), '0'.repeat(64)); // similar work either way
      return fail(401, 'invalid_login', 'Wrong username or password.');
    }
    const locked = this.#lockedUntil(u, ts, lockoutOff);
    if (locked) return fail(423, 'account_locked', 'This account is temporarily locked after too many failed logins.', { until: locked });
    if (typeof verifier !== 'string' || !timingSafeEqualHex(verifier, u.pw_verifier)) {
      this.#passwordFailure(u, ts, s, lockoutOff);
      return fail(401, 'invalid_login', 'Wrong username or password.');
    }
    if (u.disabled) return fail(403, 'account_disabled', 'This account is disabled.');
    this.sql.exec('DELETE FROM failures WHERE user_id = ?', u.id);
    this.#log(u.id, u.id, 'login');
    return { ok: true, user: { id: u.id, username: u.username, role: u.role, ver: u.sess_ver }, settings: this.#sessionSettings(s) };
  }

  /** Account lockout end time, or 0. The owner is never locked out. */
  #lockedUntil(u, ts, lockoutOff) {
    if (u.role === 'owner' || lockoutOff) return 0;
    const f = this.sql.exec('SELECT locked_until FROM failures WHERE user_id = ?', u.id).toArray()[0];
    return f && f.locked_until > ts ? f.locked_until : 0;
  }

  /** Count one wrong password (login or password change) toward lockout. */
  #passwordFailure(u, ts, s, lockoutOff) {
    if (u.role === 'owner' || lockoutOff) return;
    const f = this.sql.exec('SELECT * FROM failures WHERE user_id = ?', u.id).toArray()[0];
    const fresh = !f || ts - f.start > s['lockout.windowSec'];
    const count = fresh ? 1 : f.count + 1;
    const start = fresh ? ts : f.start;
    const lockedUntil = count >= s['lockout.max'] ? ts + s['lockout.lockSec'] : 0;
    this.sql.exec('INSERT INTO failures (user_id, count, start, locked_until) VALUES (?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET count = excluded.count, start = excluded.start, locked_until = excluded.locked_until',
      u.id, lockedUntil ? 0 : count, lockedUntil ? ts : start, lockedUntil);
    if (lockedUntil) this.#log(null, u.id, 'account.locked', `until=${lockedUntil}`);
  }

  #sessionSettings(s = this.#settings()) {
    return { idleSec: s['session.idleSec'], absSec: s['session.absSec'] };
  }

  /**
   * Validate a decoded session token against current state. Returns the
   * session, null (invalid/revoked/expired version), or { disabled: true }
   * when the account itself is disabled — so the client can say why.
   */
  async resolveSession({ sid, uid, act, ver }) {
    if (typeof sid !== 'string' || typeof uid !== 'string') return null;
    if (this.sql.exec('SELECT 1 FROM revoked_sessions WHERE sid = ?', sid).toArray().length) return null;
    const u = this.#user(uid);
    if (!u) return null;
    // While impersonating, a disabled target simply ends the impersonated
    // session — it must not tell the owner that *their* account is disabled.
    if (u.disabled) return act ? null : { disabled: true };
    let actor = null;
    if (act) {
      // Impersonation: the actor must still be the (enabled) owner, and `ver`
      // binds to the actor's session version (their password change ends it).
      actor = this.#user(act);
      if (!actor || actor.role !== 'owner' || actor.disabled || actor.sess_ver !== ver) return null;
    } else if (u.sess_ver !== ver) {
      return null;
    }
    return { user: this.#publicUser(u), actor: this.#publicUser(actor), settings: this.#sessionSettings() };
  }

  async revokeSession(sid, exp, actorId, subjectId) {
    if (typeof sid !== 'string') return;
    this.sql.exec('INSERT OR REPLACE INTO revoked_sessions (sid, exp) VALUES (?, ?)', sid, Number(exp) || now() + 86400 * 400);
    if (subjectId) this.#log(actorId, subjectId, 'logout');
  }

  async impersonate(ownerId, targetId) {
    const o = this.#user(ownerId);
    const t = this.#user(targetId);
    if (!o || o.role !== 'owner') return fail(403, 'forbidden', 'Only the owner can impersonate.');
    if (!t || t.id === o.id) return fail(404, 'not_found', 'User not found.');
    if (t.disabled) return fail(409, 'account_disabled', 'That account is disabled.');
    this.#log(o.id, t.id, 'impersonate.start', `as=${t.username}`);
    return { ok: true, target: this.#publicUser(t), ver: o.sess_ver, settings: this.#sessionSettings() };
  }

  async endImpersonation(ownerId, targetId) {
    const o = this.#user(ownerId);
    if (!o || o.role !== 'owner' || o.disabled) return fail(403, 'forbidden', 'Not impersonating.');
    this.#log(o.id, targetId, 'impersonate.end');
    return { ok: true, user: this.#publicUser(o), ver: o.sess_ver, settings: this.#sessionSettings() };
  }

  // ── the signed-in user ───────────────────────────────────────────────────
  async me(uid, { impersonating = false } = {}) {
    const u = this.#user(uid);
    if (!u) return null;
    const eff = this.#effective(u);
    const s = this.#settings();
    const keyCount = this.sql.exec('SELECT COUNT(*) AS c FROM api_keys WHERE user_id = ?', u.id).one().c;
    return {
      user: this.#publicUser(u),
      impersonating,
      limits: eff.all,
      apiLimits: eff.api,
      caps: {
        maxShareBytes: Math.min(s['files.maxShareBytes'], eff.all.maxShareBytes ?? Infinity),
        grantSec: s['files.grantSec'],
      },
      viewer: {
        enabled: s['viewer.enabled'] && eff.all.viewer,
        maxBytes: s['viewer.maxBytes'],
        rules: s['viewer.enabled'] && eff.all.viewer ? this.#viewerRules(u, eff.all) : [],
      },
      apiKeys: { enabled: eff.all.apiEnabled, max: eff.all.apiMaxKeys, count: keyCount },
      quotas: u.role === 'owner' ? [] : this.#quotaStatus(u.id),
    };
  }

  #applicableQuotas(uid) {
    return this.sql.exec("SELECT * FROM quotas WHERE user_id = '' OR user_id = ?", uid).toArray();
  }

  #quotaStatus(uid) {
    const ts = now();
    return this.#applicableQuotas(uid).map((q) => {
      const bucket = quotaBucket(q, ts);
      const row = this.sql.exec('SELECT count FROM usage WHERE quota_id = ? AND user_id = ? AND bucket = ?', q.id, uid, bucket).toArray()[0];
      return { scope: q.user_id ? 'user' : 'global', channel: q.channel, kind: q.kind, n: q.n, unit: q.unit, max: q.max, used: row ? row.count : 0 };
    });
  }

  /**
   * Change the signed-in user's password. The account lockout never blocks
   * this (a stranger failing logins must not stop a user from changing a
   * password they fear is compromised). Instead, a stolen session cannot guess
   * the current password without limit: after `lockout.max` wrong attempts
   * within `lockout.windowSec`, every session of the account is ended —
   * owner included — and the holder must log in again.
   */
  async changePassword(uid, { current, salt, t, verifier, lockoutOff = false }) {
    const u = this.#user(uid);
    if (!u) return fail(404, 'not_found', 'User not found.');
    const ts = now();
    if (typeof current !== 'string' || !timingSafeEqualHex(current, u.pw_verifier)) {
      if (!lockoutOff) {
        const st = this.#settings();
        const f = this.sql.exec('SELECT * FROM pwchange_failures WHERE user_id = ?', u.id).toArray()[0];
        const fresh = !f || ts - f.start > st['lockout.windowSec'];
        const count = fresh ? 1 : f.count + 1;
        if (count >= st['lockout.max']) {
          this.sql.exec('DELETE FROM pwchange_failures WHERE user_id = ?', u.id);
          this.sql.exec('UPDATE users SET sess_ver = sess_ver + 1, updated = ? WHERE id = ?', ts, u.id);
          this.#log(null, u.id, 'sessions.revoked', 'too many wrong current passwords');
          return fail(401, 'session_revoked', 'Too many wrong passwords: you have been signed out everywhere. Log in again.');
        }
        this.sql.exec('INSERT INTO pwchange_failures (user_id, count, start) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET count = excluded.count, start = excluded.start',
          u.id, count, fresh ? ts : f.start);
      }
      return fail(403, 'wrong_password', 'The current password is incorrect.');
    }
    this.sql.exec('DELETE FROM pwchange_failures WHERE user_id = ?', u.id);
    const bad = this.#checkCredential(salt, t, verifier);
    if (bad) return fail(400, 'invalid_credential', bad);
    this.sql.exec('UPDATE users SET pw_salt = ?, pw_t = ?, pw_verifier = ?, sess_ver = sess_ver + 1, updated = ? WHERE id = ?', salt, t, verifier, now(), uid);
    this.#log(uid, uid, 'password.changed');
    return { ok: true, ver: u.sess_ver + 1 };
  }

  async activity(uid, { before = null, limit = 50 } = {}) {
    const lim = Math.max(1, Math.min(200, limit | 0));
    const rows = before
      ? this.sql.exec('SELECT id, ts, action, detail FROM activity WHERE subject_id = ? AND adm = 0 AND id < ? ORDER BY id DESC LIMIT ?', uid, before, lim).toArray()
      : this.sql.exec('SELECT id, ts, action, detail FROM activity WHERE subject_id = ? AND adm = 0 ORDER BY id DESC LIMIT ?', uid, lim).toArray();
    // The user's own view never names the actor: actions the owner took while
    // impersonating appear as the user's own (the admin audit shows the truth).
    // Direct admin-panel actions on the user's shares (adm) are not shown.
    return rows;
  }

  // ── API keys ─────────────────────────────────────────────────────────────
  async listKeys(uid) {
    return this.sql.exec('SELECT id, name, created, last_used, expires FROM api_keys WHERE user_id = ? ORDER BY created DESC', uid).toArray();
  }

  async createKey(uid, { name, hash, expires }) {
    const u = this.#user(uid);
    if (!u) return fail(404, 'not_found', 'User not found.');
    const eff = this.#effective(u).all;
    if (!eff.apiEnabled) return fail(403, 'api_disabled', 'API keys are not enabled for this account.');
    const count = this.sql.exec('SELECT COUNT(*) AS c FROM api_keys WHERE user_id = ?', uid).one().c;
    if (count >= eff.apiMaxKeys) return fail(409, 'too_many_keys', `This account may hold at most ${eff.apiMaxKeys} API keys.`);
    const label = cleanLabel(name);
    if (label === null || label === '') return fail(400, 'invalid_name', 'Give the key a name (up to 100 characters).');
    if (typeof hash !== 'string' || !HEX64_RE.test(hash)) return fail(400, 'invalid_key', 'invalid key');
    if (expires !== null && expires !== undefined && (!Number.isSafeInteger(expires) || expires <= now())) return fail(400, 'invalid_expiry', 'Expiry must be in the future.');
    const id = newId();
    this.sql.exec('INSERT INTO api_keys (key_hash, id, user_id, name, created, expires) VALUES (?, ?, ?, ?, ?, ?)', hash, id, uid, label, now(), expires ?? null);
    this.#log(uid, uid, 'apikey.created', `name=${label}`);
    return { ok: true, id };
  }

  async revokeKey(uid, id, actorId = uid) {
    const r = this.sql.exec('SELECT name FROM api_keys WHERE user_id = ? AND id = ?', uid, id).toArray()[0];
    if (!r) return fail(404, 'not_found', 'Key not found.');
    this.sql.exec('DELETE FROM api_keys WHERE user_id = ? AND id = ?', uid, id);
    this.#log(actorId, uid, 'apikey.revoked', `name=${r.name}`);
    return { ok: true };
  }

  async authKey(hash) {
    if (typeof hash !== 'string' || !HEX64_RE.test(hash)) return null;
    const k = this.sql.exec('SELECT * FROM api_keys WHERE key_hash = ?', hash).toArray()[0];
    if (!k) return null;
    const ts = now();
    if (k.expires && k.expires <= ts) return null;
    const u = this.#user(k.user_id);
    if (!u) return null;
    if (u.disabled) return { disabled: true };
    if (!this.#effective(u).all.apiEnabled) return null; // disallowing API use stops existing keys at once
    if (!k.last_used || ts - k.last_used > 60) this.sql.exec('UPDATE api_keys SET last_used = ? WHERE key_hash = ?', ts, hash);
    return { user: this.#publicUser(u) };
  }

  // ── creation authorization + quotas ──────────────────────────────────────
  /**
   * Check capabilities/limits and consume quota for one creation, atomically.
   * req: { kind:'text'|'files', views:int|null, expireSec, bytes?, files?, maxFile? }
   * Returns { ok, refund, limits } or a failure with a specific reason.
   */
  async authorizeCreate(uid, channel, req) {
    const u = this.#user(uid);
    if (!u || u.disabled) return fail(403, 'forbidden', 'Account unavailable.');
    const s = this.#settings();
    const ch = channel === 'api' ? 'api' : 'all';
    const eff = this.#effective(u);
    const L = ch === 'api' ? eff.api : eff.all;
    const via = ch === 'api' ? ' via the API' : '';
    if (req.kind === 'text' && !L.text) return fail(403, 'text_disabled', `Creating notes is not allowed for this account${via}.`);
    if (req.kind === 'files' && !L.files) return fail(403, 'files_disabled', `File sharing is not allowed for this account${via}.`);
    if (req.views === null) {
      if (!L.allowUnlimitedViews) return fail(403, 'unlimited_views_disabled', `Unlimited views are not allowed for this account${via}.`);
    } else if (L.maxViews !== null && req.views > L.maxViews) {
      return fail(403, 'too_many_views', `At most ${L.maxViews} views are allowed${via}.`, { max: L.maxViews });
    }
    if (L.maxExpireSec !== null && req.expireSec > L.maxExpireSec) {
      return fail(403, 'expiry_too_long', `Expiry may be at most ${L.maxExpireSec} seconds${via}.`, { max: L.maxExpireSec });
    }
    if (req.kind === 'files') {
      const cap = Math.min(s['files.maxShareBytes'], L.maxShareBytes ?? Infinity);
      if (!(req.bytes <= cap)) return fail(413, 'share_too_large', `A file share may be at most ${cap} bytes${via}.`, { max: cap });
      if (L.maxFilesPerShare !== null && !(Number.isSafeInteger(req.files) && req.files <= L.maxFilesPerShare)) {
        return fail(403, 'too_many_files', `At most ${L.maxFilesPerShare} files per share${via}.`, { max: L.maxFilesPerShare });
      }
      if (L.maxFileBytes !== null && !(Number.isSafeInteger(req.maxFile) && req.maxFile <= L.maxFileBytes)) {
        return fail(413, 'file_too_large', `Each file may be at most ${L.maxFileBytes} bytes${via}.`, { max: L.maxFileBytes });
      }
    }
    if (u.role === 'owner') return { ok: true, refund: [] };

    const ts = now();
    const applicable = this.#applicableQuotas(uid).filter((q) => (q.kind === 'all' || q.kind === req.kind) && (q.channel === 'all' || ch === 'api'));
    const hits = [];
    for (const q of applicable) {
      const bucket = quotaBucket(q, ts);
      const row = this.sql.exec('SELECT count FROM usage WHERE quota_id = ? AND user_id = ? AND bucket = ?', q.id, uid, bucket).toArray()[0];
      const used = row ? row.count : 0;
      if (used >= q.max) {
        const what = q.kind === 'all' ? 'shares' : q.kind === 'text' ? 'notes' : 'file shares';
        return fail(429, 'quota_exceeded', `Quota reached: ${q.max} ${what} per ${q.n}${q.unit}${q.channel === 'api' ? ' via the API' : ''}.`, { quota: { channel: q.channel, kind: q.kind, n: q.n, unit: q.unit, max: q.max } });
      }
      hits.push({ quota_id: q.id, bucket });
    }
    this.ctx.storage.transactionSync(() => {
      for (const h of hits) {
        this.sql.exec('INSERT INTO usage (quota_id, user_id, bucket, count, ts) VALUES (?, ?, ?, 1, ?) ON CONFLICT(quota_id, user_id, bucket) DO UPDATE SET count = count + 1',
          h.quota_id, uid, h.bucket, ts);
      }
    });
    return { ok: true, refund: hits };
  }

  async refund(uid, hits) {
    if (!Array.isArray(hits)) return;
    for (const h of hits) {
      this.sql.exec('UPDATE usage SET count = MAX(0, count - 1) WHERE quota_id = ? AND user_id = ? AND bucket = ?', h.quota_id, uid, h.bucket);
    }
  }

  /** Limits check for raising views/expiry on an existing share (no quota use). */
  async authorizeIncrease(uid, { views, expireAt }) {
    const u = this.#user(uid);
    if (!u || u.disabled) return fail(403, 'forbidden', 'Account unavailable.');
    const L = this.#effective(u).all;
    if (views !== undefined) {
      if (views === null && !L.allowUnlimitedViews) return fail(403, 'unlimited_views_disabled', 'Unlimited views are not allowed for this account.');
      if (views !== null && L.maxViews !== null && views > L.maxViews) return fail(403, 'too_many_views', `At most ${L.maxViews} views are allowed.`, { max: L.maxViews });
    }
    if (expireAt !== undefined && L.maxExpireSec !== null && expireAt > now() + L.maxExpireSec) {
      return fail(403, 'expiry_too_long', `Expiry may be at most ${L.maxExpireSec} seconds from now.`, { max: L.maxExpireSec });
    }
    return { ok: true };
  }

  // ── shares index ("My shares") ───────────────────────────────────────────
  async recordShare({ id, uid, kind, label, created, expires, views }, actorId = uid) {
    const l = cleanLabel(label) ?? '';
    this.sql.exec("INSERT OR REPLACE INTO shares (id, user_id, kind, label, created, expires, views_total, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'active')",
      id, uid, kind, l, created, expires, views ?? null);
    this.#log(actorId, uid, `share.created`, `id=${id} kind=${kind}`);
  }

  async listShares(uid, { q = '', status = '', limit = 50, offset = 0 } = {}) {
    const lim = Math.max(1, Math.min(100, limit | 0));
    const off = Math.max(0, offset | 0);
    const like = `%${String(q).replace(/[%_\\]/g, (c) => '\\' + c)}%`;
    const where = `WHERE user_id = ? AND label LIKE ? ESCAPE '\\' ${status ? 'AND status = ?' : ''}`;
    const args = status ? [uid, like, String(status)] : [uid, like];
    const rows = this.sql.exec(
      `SELECT id, kind, label, created, expires, views_total, status, locked FROM shares ${where} ORDER BY created DESC LIMIT ? OFFSET ?`,
      ...args, lim, off).toArray();
    // The total counts what the filters match, so pagination is correct.
    const total = this.sql.exec(`SELECT COUNT(*) AS c FROM shares ${where}`, ...args).one().c;
    return { rows, total };
  }

  async getShare(uid, id) {
    return this.sql.exec('SELECT id, user_id, kind, label, created, expires, views_total, status, locked FROM shares WHERE user_id = ? AND id = ?', uid, id).toArray()[0] || null;
  }

  /** Any user's share, for the admin (no owner scoping). */
  async adminShare(id) {
    return this.sql.exec(`SELECT s.id, s.user_id, u.username, s.kind, s.label, s.created, s.expires, s.views_total, s.status,
      s.locked, s.locked_at, lu.username AS locked_by
      FROM shares s LEFT JOIN users u ON u.id = s.user_id LEFT JOIN users lu ON lu.id = s.locked_by WHERE s.id = ?`, id).toArray()[0] || null;
  }

  /** Is this share locked by the admin? (Used by the public delete-by-token path.) */
  async isShareLocked(id) {
    const r = this.sql.exec('SELECT locked FROM shares WHERE id = ?', id).toArray()[0];
    return !!(r && r.locked);
  }

  /**
   * Change a share's index row. `uid` scopes it to its owner; the admin passes
   * { admin: ownerId } instead, which bypasses the owner scope and the lock and
   * logs the action as a direct admin action (hidden from the user's log).
   */
  async updateShare(uid, id, { label, expires, views, status }, actorId = uid, { admin = null } = {}) {
    const row = admin ? await this.adminShare(id) : await this.getShare(uid, id);
    if (!row) return fail(404, 'not_found', 'Share not found.');
    if (row.locked && !admin) return fail(423, 'share_locked', 'The administrator has locked this share; it cannot be changed.');
    const subject = row.user_id;
    const actor = admin ? { id: admin, adm: true } : actorId;
    const parts = [];
    if (label !== undefined) {
      const l = cleanLabel(label);
      if (l === null) return fail(400, 'invalid_label', 'Labels are up to 100 characters.');
      this.sql.exec('UPDATE shares SET label = ? WHERE id = ?', l, id);
      parts.push('label');
    }
    if (expires !== undefined) { this.sql.exec('UPDATE shares SET expires = ? WHERE id = ?', expires, id); parts.push(`expires=${expires}`); }
    if (views !== undefined) { this.sql.exec('UPDATE shares SET views_total = ? WHERE id = ?', views, id); parts.push(`views=${views ?? 'unlimited'}`); }
    if (status !== undefined) { this.sql.exec('UPDATE shares SET status = ? WHERE id = ?', status, id); parts.push(`status=${status}`); }
    this.#log(actor, subject, status === 'revoked' ? 'share.revoked' : 'share.updated', `id=${id} ${parts.join(' ')}`);
    return { ok: true };
  }

  /** Admin: lock (freeze) or unlock a share. */
  async setShareLock(ownerId, id, locked) {
    const o = this.#user(ownerId);
    if (!o || o.role !== 'owner') return fail(403, 'forbidden', 'Only the owner can lock shares.');
    const row = await this.adminShare(id);
    if (!row) return fail(404, 'not_found', 'Share not found.');
    const on = !!locked;
    this.sql.exec('UPDATE shares SET locked = ?, locked_by = ?, locked_at = ? WHERE id = ?', on ? 1 : 0, on ? ownerId : null, on ? now() : null, id);
    this.#log({ id: ownerId, adm: true }, row.user_id, on ? 'share.locked' : 'share.unlocked', `id=${id}`);
    return { ok: true, locked: on };
  }

  /**
   * Admin: every user's shares with filters. Times are unix seconds;
   * `users` is a list of user ids; each range bound is optional.
   */
  async adminListShares({ users = [], kind = '', status = '', q = '', locked = null, createdFrom = null, createdTo = null, expiresFrom = null, expiresTo = null, limit = 50, offset = 0 } = {}) {
    const lim = Math.max(1, Math.min(200, limit | 0));
    const off = Math.max(0, offset | 0);
    const where = [];
    const args = [];
    const ids = (Array.isArray(users) ? users : []).filter((u) => typeof u === 'string').slice(0, 100);
    if (ids.length) { where.push(`s.user_id IN (${ids.map(() => '?').join(', ')})`); args.push(...ids); }
    if (kind) { where.push('s.kind = ?'); args.push(String(kind)); }
    if (status) { where.push('s.status = ?'); args.push(String(status)); }
    if (q) { where.push("s.label LIKE ? ESCAPE '\\'"); args.push(`%${String(q).slice(0, 100).replace(/[%_\\]/g, (c) => '\\' + c)}%`); }
    if (locked === true || locked === false) { where.push('s.locked = ?'); args.push(locked ? 1 : 0); }
    const range = (col, from, to) => {
      if (Number.isSafeInteger(from)) { where.push(`${col} >= ?`); args.push(from); }
      if (Number.isSafeInteger(to)) { where.push(`${col} <= ?`); args.push(to); }
    };
    range('s.created', createdFrom, createdTo);
    range('s.expires', expiresFrom, expiresTo);
    const w = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const rows = this.sql.exec(`SELECT s.id, s.user_id, u.username, s.kind, s.label, s.created, s.expires, s.views_total, s.status,
      s.locked, s.locked_at, lu.username AS locked_by
      FROM shares s LEFT JOIN users u ON u.id = s.user_id LEFT JOIN users lu ON lu.id = s.locked_by
      ${w} ORDER BY s.created DESC LIMIT ? OFFSET ?`, ...args, lim, off).toArray();
    const total = this.sql.exec(`SELECT COUNT(*) AS c FROM shares s ${w}`, ...args).one().c;
    return { rows, total };
  }

  async markShareEnded(id, status) {
    this.sql.exec("UPDATE shares SET status = ? WHERE id = ? AND status = 'active'", status, id);
  }

  // ── admin: users ─────────────────────────────────────────────────────────
  async listUsers() {
    const ts = now();
    return this.sql.exec('SELECT u.*, f.locked_until FROM users u LEFT JOIN failures f ON f.user_id = u.id ORDER BY u.role DESC, u.username').toArray()
      .map((u) => ({ ...this.#publicUser(u), locked: !!(u.locked_until && u.locked_until > ts), lockedUntil: u.locked_until || 0 }));
  }

  async createUser({ username, salt, t, verifier }, actorId) {
    if (typeof username !== 'string' || !USERNAME_RE.test(username)) return fail(400, 'invalid_username', 'Username must be 3–64 characters: letters, digits, . _ @ -');
    if (this.#userByName(username)) return fail(409, 'username_taken', 'That username is taken.');
    const bad = this.#checkCredential(salt, t, verifier);
    if (bad) return fail(400, 'invalid_credential', bad);
    const id = newId();
    const ts = now();
    this.sql.exec("INSERT INTO users (id, username, role, pw_salt, pw_t, pw_verifier, created, updated) VALUES (?, ?, 'user', ?, ?, ?, ?, ?)",
      id, username, salt, t, verifier, ts, ts);
    this.#log(actorId, id, 'user.created', `username=${username}`);
    return { ok: true, user: this.#publicUser(this.#user(id)) };
  }

  async updateUser(id, { username, disabled }, actorId) {
    const u = this.#user(id);
    if (!u) return fail(404, 'not_found', 'User not found.');
    if (disabled !== undefined) {
      if (typeof disabled !== 'boolean') return fail(400, 'invalid', 'disabled must be true or false');
      if (u.role === 'owner' && disabled) return fail(403, 'forbidden', 'The owner cannot be disabled.');
      this.sql.exec('UPDATE users SET disabled = ?, sess_ver = sess_ver + ?, updated = ? WHERE id = ?', disabled ? 1 : 0, disabled ? 1 : 0, now(), id);
      this.#log(actorId, id, disabled ? 'user.disabled' : 'user.enabled');
    }
    if (username !== undefined) {
      if (typeof username !== 'string' || !USERNAME_RE.test(username)) return fail(400, 'invalid_username', 'Username must be 3–64 characters: letters, digits, . _ @ -');
      const clash = this.#userByName(username);
      if (clash && clash.id !== id) return fail(409, 'username_taken', 'That username is taken.');
      this.sql.exec('UPDATE users SET username = ?, updated = ? WHERE id = ?', username, now(), id);
      this.#log(actorId, id, 'user.renamed', `username=${username}`);
    }
    return { ok: true, user: this.#publicUser(this.#user(id)) };
  }

  /** Delete a user. Returns the ids of their still-active shares (the Worker may purge them). */
  async deleteUser(id, actorId) {
    const u = this.#user(id);
    if (!u) return fail(404, 'not_found', 'User not found.');
    if (u.role === 'owner') return fail(403, 'forbidden', 'The owner cannot be deleted.');
    const shares = this.sql.exec("SELECT id FROM shares WHERE user_id = ? AND status = 'active'", id).toArray().map((r) => r.id);
    this.ctx.storage.transactionSync(() => {
      for (const t of ['limits', 'quotas', 'usage', 'api_keys', 'failures', 'viewer_rules', 'shares']) this.sql.exec(`DELETE FROM ${t} WHERE user_id = ?`, id);
      this.sql.exec('DELETE FROM users WHERE id = ?', id);
      this.#log(actorId, id, 'user.deleted', `username=${u.username}`);
    });
    return { ok: true, shares };
  }

  async setPassword(id, { salt, t, verifier }, actorId) {
    const u = this.#user(id);
    if (!u) return fail(404, 'not_found', 'User not found.');
    const bad = this.#checkCredential(salt, t, verifier);
    if (bad) return fail(400, 'invalid_credential', bad);
    this.sql.exec('UPDATE users SET pw_salt = ?, pw_t = ?, pw_verifier = ?, sess_ver = sess_ver + 1, updated = ? WHERE id = ?', salt, t, verifier, now(), id);
    this.sql.exec('DELETE FROM failures WHERE user_id = ?', id);
    this.#log(actorId, id, 'password.reset_by_admin');
    return { ok: true, ver: u.sess_ver + 1 };
  }

  async unlockUser(id, actorId) {
    this.sql.exec('DELETE FROM failures WHERE user_id = ?', id);
    this.#log(actorId, id, 'account.unlocked');
    return { ok: true };
  }

  async userDetail(id) {
    const u = this.#user(id);
    if (!u) return null;
    return {
      user: this.#publicUser(u),
      limits: { all: this.#limitRows(id, 'all'), api: this.#limitRows(id, 'api') },
      effective: this.#effective(u),
      quotas: this.sql.exec('SELECT id, channel, kind, n, unit, max FROM quotas WHERE user_id = ?', id).toArray(),
      viewerRules: this.sql.exec('SELECT match, value, renderer FROM viewer_rules WHERE user_id = ? ORDER BY id', id).toArray(),
      keys: await this.listKeys(id),
    };
  }

  // ── admin: limits / quotas / viewer rules / settings ─────────────────────
  async setLimits(scopeUserId, channel, patch, actorId) {
    if (scopeUserId && !this.#user(scopeUserId)) return fail(404, 'not_found', 'User not found.');
    if (channel !== 'all' && channel !== 'api') return fail(400, 'invalid', 'channel must be all or api');
    if (!patch || typeof patch !== 'object') return fail(400, 'invalid', 'patch must be an object');
    const ops = [];
    try {
      for (const [k, v] of Object.entries(patch)) {
        if (!Object.prototype.hasOwnProperty.call(LIMITS, k)) throw new Error(`unknown limit "${k}"`);
        // `undefined`-like sentinel "inherit" removes the override.
        ops.push(v === 'inherit' ? [k, undefined] : [k, checkLimit(k, v, channel)]);
      }
    } catch (e) {
      return fail(400, 'invalid_limit', e.message);
    }
    this.ctx.storage.transactionSync(() => {
      for (const [k, v] of ops) {
        if (v === undefined) this.sql.exec('DELETE FROM limits WHERE user_id = ? AND channel = ? AND key = ?', scopeUserId, channel, k);
        else this.sql.exec('INSERT INTO limits (user_id, channel, key, value) VALUES (?, ?, ?, ?) ON CONFLICT(user_id, channel, key) DO UPDATE SET value = excluded.value',
          scopeUserId, channel, k, JSON.stringify(v));
      }
    });
    this.#log(actorId, scopeUserId || null, 'limits.updated', `${scopeUserId ? 'user' : 'global'} ${channel}: ${ops.map(([k, v]) => `${k}=${v === undefined ? 'inherit' : JSON.stringify(v)}`).join(', ')}`);
    return { ok: true };
  }

  async setQuotas(scopeUserId, list, actorId) {
    if (scopeUserId && !this.#user(scopeUserId)) return fail(404, 'not_found', 'User not found.');
    if (!Array.isArray(list) || list.length > 50) return fail(400, 'invalid', 'quotas must be a list (max 50)');
    let clean;
    try { clean = list.map(checkQuota); } catch (e) { return fail(400, 'invalid_quota', e.message); }
    this.ctx.storage.transactionSync(() => {
      const old = this.sql.exec('SELECT id FROM quotas WHERE user_id = ?', scopeUserId).toArray();
      for (const o of old) this.sql.exec('DELETE FROM usage WHERE quota_id = ?', o.id);
      this.sql.exec('DELETE FROM quotas WHERE user_id = ?', scopeUserId);
      for (const q of clean) {
        this.sql.exec('INSERT INTO quotas (id, user_id, channel, kind, n, unit, max) VALUES (?, ?, ?, ?, ?, ?, ?)', newId(), scopeUserId, q.channel, q.kind, q.n, q.unit, q.max);
      }
    });
    this.#log(actorId, scopeUserId || null, 'quotas.updated', `${scopeUserId ? 'user' : 'global'}: ${clean.map((q) => `${q.max}/${q.n}${q.unit} ${q.kind} ${q.channel}`).join('; ') || 'none'}`);
    return { ok: true };
  }

  async setViewerRules(scopeUserId, list, actorId) {
    if (scopeUserId && !this.#user(scopeUserId)) return fail(404, 'not_found', 'User not found.');
    if (!Array.isArray(list) || list.length > 200) return fail(400, 'invalid', 'rules must be a list (max 200)');
    let clean;
    try { clean = list.map(checkViewerRule); } catch (e) { return fail(400, 'invalid_rule', e.message); }
    this.ctx.storage.transactionSync(() => {
      this.sql.exec('DELETE FROM viewer_rules WHERE user_id = ?', scopeUserId);
      for (const r of clean) this.sql.exec('INSERT INTO viewer_rules (user_id, match, value, renderer) VALUES (?, ?, ?, ?)', scopeUserId, r.match, r.value, r.renderer);
    });
    this.#log(actorId, scopeUserId || null, 'viewer_rules.updated', `${scopeUserId ? 'user' : 'global'}: ${clean.length} rules`);
    return { ok: true };
  }

  async adminGlobal() {
    return {
      settings: this.#settings(),
      limits: { all: this.#limitRows('', 'all'), api: this.#limitRows('', 'api') },
      quotas: this.sql.exec("SELECT id, channel, kind, n, unit, max FROM quotas WHERE user_id = ''").toArray(),
      viewerRules: this.sql.exec("SELECT match, value, renderer FROM viewer_rules WHERE user_id = '' ORDER BY id").toArray(),
    };
  }

  async getSettings() {
    return this.#settings();
  }

  async setSettings(patch, actorId) {
    if (!patch || typeof patch !== 'object') return fail(400, 'invalid', 'patch must be an object');
    const ops = [];
    try {
      for (const [k, v] of Object.entries(patch)) ops.push([k, checkSetting(k, v)]);
    } catch (e) {
      return fail(400, 'invalid_setting', e.message);
    }
    const merged = { ...this.#settings(), ...Object.fromEntries(ops) };
    if (merged['session.idleSec'] > merged['session.absSec']) return fail(400, 'invalid_setting', 'The idle timeout cannot exceed the absolute timeout.');
    this.ctx.storage.transactionSync(() => {
      for (const [k, v] of ops) this.sql.exec('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', k, JSON.stringify(v));
    });
    this.#log(actorId, null, 'settings.updated', ops.map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(', '));
    return { ok: true, settings: this.#settings() };
  }

  /** Public, non-secret viewer policy (the recipient page intersects with it). */
  async publicConfig() {
    const s = this.#settings();
    return {
      viewer: { enabled: s['viewer.enabled'], maxBytes: s['viewer.maxBytes'], rules: s['viewer.enabled'] ? this.sql.exec("SELECT match, value, renderer FROM viewer_rules WHERE user_id = '' ORDER BY id").toArray() : [] },
    };
  }

  // ── admin: IP rules ──────────────────────────────────────────────────────
  async ipRules() {
    const ts = now();
    return this.sql.exec('SELECT id, cidr, action, expires, note, created FROM ip_rules WHERE expires IS NULL OR expires > ? ORDER BY created DESC', ts).toArray();
  }

  async addIpRule({ cidr, action, expires, note }, actorId) {
    const c = normalizeRule(cidr);
    if (!c) return fail(400, 'invalid_cidr', 'Enter an IPv4/IPv6 address or CIDR range.');
    if (action !== 'allow' && action !== 'block') return fail(400, 'invalid_action', 'action must be allow or block');
    if (expires !== null && expires !== undefined && (!Number.isSafeInteger(expires) || expires <= now())) return fail(400, 'invalid_expiry', 'Expiry must be in the future.');
    const n = cleanLabel(note);
    if (n === null) return fail(400, 'invalid_note', 'Notes are up to 100 characters.');
    const id = newId();
    this.sql.exec('INSERT INTO ip_rules (id, cidr, action, expires, note, created) VALUES (?, ?, ?, ?, ?, ?)', id, c, action, expires ?? null, n, now());
    this.#log(actorId, null, 'iprule.added', `${action} ${c}${n ? ` (${n})` : ''}`);
    return { ok: true, id, cidr: c };
  }

  async removeIpRule(id, actorId) {
    const r = this.sql.exec('SELECT cidr, action FROM ip_rules WHERE id = ?', id).toArray()[0];
    if (!r) return fail(404, 'not_found', 'Rule not found.');
    this.sql.exec('DELETE FROM ip_rules WHERE id = ?', id);
    this.#log(actorId, null, 'iprule.removed', `${r.action} ${r.cidr}`);
    return { ok: true };
  }

  async adminLog(entry, actorId) {
    this.#log(actorId, entry.subject ?? null, entry.action, entry.detail ?? '');
  }

  async audit({ before = null, limit = 100, subject = null } = {}) {
    const lim = Math.max(1, Math.min(500, limit | 0));
    const where = [];
    const args = [];
    if (before) { where.push('a.id < ?'); args.push(before); }
    if (subject) { where.push('a.subject_id = ?'); args.push(subject); }
    return this.sql.exec(
      `SELECT a.id, a.ts, a.action, a.detail, a.actor_id, a.subject_id, a.imp, a.adm, ua.username AS actor, us.username AS subject
       FROM activity a LEFT JOIN users ua ON ua.id = a.actor_id LEFT JOIN users us ON us.id = a.subject_id
       ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY a.id DESC LIMIT ?`, ...args, lim).toArray();
  }

  // ── housekeeping ─────────────────────────────────────────────────────────
  async alarm() {
    const ts = now();
    this.sql.exec('DELETE FROM revoked_sessions WHERE exp < ?', ts);
    this.sql.exec('DELETE FROM usage WHERE ts < ?', ts - 400 * 86400);
    this.sql.exec('DELETE FROM ip_rules WHERE expires IS NOT NULL AND expires < ?', ts);
    this.sql.exec("UPDATE shares SET status = 'expired' WHERE status = 'active' AND expires > 0 AND expires < ?", ts);
    this.sql.exec("DELETE FROM shares WHERE status != 'active' AND locked = 0 AND expires < ?", ts - SHARE_PRUNE_SEC);
    await this.ctx.storage.setAlarm(Date.now() + 3600 * 1000);
  }
}

export const SETTING_KEYS = Object.keys(SETTINGS);
