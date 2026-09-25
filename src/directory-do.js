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
import { b64urlFromBytes, bytesFromB64url, randomBytes, utf8, timingSafeEqualHex } from '../public/js/bytes.js';
import { ARGON2 } from '../public/js/format.js';
import {
  SETTINGS, checkSetting, settingsWithDefaults, LIMITS, checkLimit, resolveLimits, restrictForApi,
  UNLIMITED, checkQuota, quotaBucket, checkViewerRule, DEFAULT_VIEWER_RULES,
} from './lib/settings.js';
import { normalizeRule, parseIp, parseCidr, cidrContains } from './lib/ip.js';
import { EXPORT_FORMAT, MAX_EXPORT_USERS } from './lib/portable.js';
import { refusedTypes, checkDeclaredTypes, describeType, MAX_FOLDER_DEPTH } from '../public/js/filepolicy.js';

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
CREATE TABLE IF NOT EXISTS trackers (id_hash TEXT PRIMARY KEY, created INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  uses INTEGER NOT NULL DEFAULT 0, ip_hash TEXT NOT NULL, blocked INTEGER NOT NULL DEFAULT 0, reason TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS trackers_ip ON trackers(ip_hash, created);
CREATE INDEX IF NOT EXISTS trackers_seen ON trackers(last_seen);
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
  // 3: anonymous-creator trackers (public access)
  (m) => {
    m.sql.exec(`CREATE TABLE IF NOT EXISTS trackers (id_hash TEXT PRIMARY KEY, created INTEGER NOT NULL, last_seen INTEGER NOT NULL,
      uses INTEGER NOT NULL DEFAULT 0, ip_hash TEXT NOT NULL, blocked INTEGER NOT NULL DEFAULT 0, reason TEXT NOT NULL DEFAULT '')`);
    m.sql.exec('CREATE INDEX IF NOT EXISTS trackers_ip ON trackers(ip_hash, created)');
    m.sql.exec('CREATE INDEX IF NOT EXISTS trackers_seen ON trackers(last_seen)');
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
/**
 * The built-in public (anonymous) account: owns shares created without an
 * account. It has no password, cannot sign in, cannot be deleted, renamed,
 * disabled, impersonated or exported, and never holds API keys. Its name is
 * outside USERNAME_RE, so no real account can take it.
 */
export const PUBLIC_ID = 'public-user-0000';
const PUBLIC_NAME = '(public)';
// Anonymous tracker ids are stateless until first used to create a share:
// 12 random bytes ‖ issued-at (u32 BE seconds) ‖ HMAC tag (8 bytes) → 32 chars.
const TRACKER_RE = /^[A-Za-z0-9_-]{32}$/;
// Hard ceiling on stored trackers (each costs one row in this singleton).
const MAX_TRACKERS = 200000;
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
      this.#seedPublic();
      if (!this.#meta('viewer_seeded')) {
        for (const r of DEFAULT_VIEWER_RULES) {
          this.sql.exec('INSERT INTO viewer_rules (user_id, match, value, renderer) VALUES (?, ?, ?, ?)', '', r.match, r.value, r.renderer);
        }
        this.#setMeta('viewer_seeded', '1');
      }
      if ((await ctx.storage.getAlarm()) === null) await ctx.storage.setAlarm(Date.now() + 3600 * 1000);
    });
  }

  /**
   * The public account and conservative defaults for it (created once; the
   * admin can change them — public access itself stays off until enabled).
   */
  #seedPublic() {
    const ts = now();
    this.sql.exec("INSERT OR IGNORE INTO users (id, username, role, pw_salt, pw_t, pw_verifier, created, updated) VALUES (?, ?, 'public', '', 0, '', ?, ?)",
      PUBLIC_ID, PUBLIC_NAME, ts, ts);
    if (this.#meta('public_seeded')) return;
    const defaults = { files: false, url: false, secret: false, openerDelete: false, maxViews: 10, allowUnlimitedViews: false, maxExpireSec: 7 * 86400, apiEnabled: false };
    for (const [k, v] of Object.entries(defaults)) {
      this.sql.exec('INSERT OR IGNORE INTO limits (user_id, channel, key, value) VALUES (?, ?, ?, ?)', PUBLIC_ID, 'all', k, JSON.stringify(v));
    }
    this.sql.exec('INSERT INTO quotas (id, user_id, channel, kind, n, unit, max) VALUES (?, ?, ?, ?, ?, ?, ?)', newId(), PUBLIC_ID, 'all', 'all', 1, 'd', 10);
    this.#setMeta('public_seeded', '1');
  }

  #migrate() {
    const from = Number(this.#meta('schema_version')) || 0;
    if (from >= SCHEMA_VERSION) return;
    const m = migrator(this.sql);
    // All steps and the version bump commit together, or not at all.
    this.ctx.storage.transactionSync(() => {
      for (let v = from; v < SCHEMA_VERSION; v++) MIGRATIONS[v](m);
      this.#setMeta('schema_version', String(SCHEMA_VERSION));
    });
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
  /** An account that can sign in (never the public account). */
  #loginUser(name) {
    const u = typeof name === 'string' ? this.#userByName(name) : null;
    return u && (u.role === 'owner' || u.role === 'user') ? u : null;
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
    const u = this.#loginUser(username);
    if (u) return { salt: u.pw_salt, t: u.pw_t };
    // Unknown user: a stable, secret-keyed fake salt, so the response does not
    // reveal whether the account exists.
    const key = await crypto.subtle.importKey('raw', utf8(this.#meta('secret')), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, utf8(String(username).toLowerCase())));
    return { salt: b64urlFromBytes(mac.subarray(0, 16)), t: ARGON2.tDefault };
  }

  async login({ username, verifier, lockoutOff = false }) {
    const u = this.#loginUser(username);
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
    if (!u || u.role === 'public') return null;
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
    if (!t || t.id === o.id || t.role === 'public') return fail(404, 'not_found', 'User not found.');
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
    const wrong = this.#checkCurrent(u, current, lockoutOff);
    if (wrong) return wrong;
    const bad = this.#checkCredential(salt, t, verifier);
    if (bad) return fail(400, 'invalid_credential', bad);
    this.sql.exec('UPDATE users SET pw_salt = ?, pw_t = ?, pw_verifier = ?, sess_ver = sess_ver + 1, updated = ? WHERE id = ?', salt, t, verifier, now(), uid);
    this.#log(uid, uid, 'password.changed');
    return { ok: true, ver: u.sess_ver + 1 };
  }

  /**
   * Step-up check of a signed-in account's current password (password change,
   * admin export/import). Wrong answers count toward the same threshold as a
   * login lockout; reaching it ends every session of the account.
   */
  async verifyCurrent(uid, current, { lockoutOff = false } = {}) {
    const u = this.#user(uid);
    if (!u) return fail(404, 'not_found', 'User not found.');
    return this.#checkCurrent(u, current, lockoutOff) ?? { ok: true };
  }

  #checkCurrent(u, current, lockoutOff) {
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
    return null;
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
    if (u.role === 'public') return fail(403, 'api_disabled', 'The public account never has API keys.');
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
    if (!u || u.role === 'public') return null;
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
    // Public (anonymous) creation: only while enabled, and quotas are counted
    // per anonymous subject (tracker and/or network), never for the account.
    const pub = u.role === 'public';
    if (pub && !s['public.enabled']) return fail(403, 'public_disabled', 'Anonymous sharing is not enabled on this server.');
    if (pub && !(req.subjects && Array.isArray(req.subjects.keys) && req.subjects.keys.length)) return fail(400, 'subject_required', 'Missing anonymous subject.');
    const ch = channel === 'api' ? 'api' : 'all';
    const eff = this.#effective(u);
    const L = ch === 'api' ? eff.api : eff.all;
    const via = ch === 'api' ? ' via the API' : '';
    if (req.kind === 'text' && !L.text) return fail(403, 'text_disabled', `Creating notes is not allowed for this account${via}.`);
    if (req.fmt === 'url' && !L.url) return fail(403, 'url_disabled', `Sharing links is not allowed for this account${via}.`);
    if (req.fmt === 'secret' && !L.secret) return fail(403, 'secret_disabled', `Sharing secrets is not allowed for this account${via}.`);
    if (req.deletable && !L.openerDelete) return fail(403, 'opener_delete_disabled', `Letting recipients delete shares is not allowed for this account${via}.`);
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
      // File policy: checked against what the client declares — and it only
      // declares when a policy applies (the declaration is never stored).
      const typed = L.fileTypeMode === 'allow' || L.fileTypeMode === 'block';
      const deep = L.maxFolderDepth !== null;
      if ((typed && req.types === undefined) || (deep && req.depth === undefined)) {
        return fail(400, 'declaration_required', 'This account has a file policy: declare the file types and folder depth.', {
          policy: { mode: L.fileTypeMode, rules: typed ? L.fileTypeRules : [], maxFolderDepth: L.maxFolderDepth },
        });
      }
      if (typed) {
        const types = checkDeclaredTypes(req.types);
        if (!types) return fail(400, 'invalid_declaration', 'Invalid file type declaration.');
        const refused = refusedTypes(L.fileTypeMode, L.fileTypeRules, types);
        if (refused.length) {
          return fail(403, 'file_type_not_allowed', `These file types may not be shared${via}: ${refused.slice(0, 5).map(describeType).join(', ')}${refused.length > 5 ? ', …' : ''}.`,
            { refused: refused.slice(0, 50) });
        }
      }
      if (deep && !(Number.isSafeInteger(req.depth) && req.depth >= 0 && req.depth <= MAX_FOLDER_DEPTH && req.depth <= L.maxFolderDepth)) {
        return fail(403, 'folder_too_deep', `Folders may be nested at most ${L.maxFolderDepth} levels deep${via}.`, { max: L.maxFolderDepth });
      }
    }
    if (u.role === 'owner') return { ok: true, refund: [] };

    const ts = now();
    const applicable = this.#applicableQuotas(uid).filter((q) => (q.kind === 'all' || q.kind === req.kind) && (q.channel === 'all' || ch === 'api'));
    // Who is counted: the account itself, or — for the public account — each
    // anonymous subject. `mode: 'all'` refuses when every subject is over
    // (both-permissive); otherwise any subject over refuses.
    const keys = pub ? req.subjects.keys.slice(0, 4).map(String) : [uid];
    const needAll = pub && req.subjects.mode === 'all';
    const hits = [];
    for (const q of applicable) {
      const bucket = quotaBucket(q, ts);
      const over = keys.map((k) => {
        const row = this.sql.exec('SELECT count FROM usage WHERE quota_id = ? AND user_id = ? AND bucket = ?', q.id, k, bucket).toArray()[0];
        return (row ? row.count : 0) >= q.max;
      });
      if (needAll ? over.every(Boolean) : over.some(Boolean)) {
        const what = q.kind === 'all' ? 'shares' : q.kind === 'text' ? 'notes' : 'file shares';
        return fail(429, 'quota_exceeded', `Quota reached: ${q.max} ${what} per ${q.n}${q.unit}${q.channel === 'api' ? ' via the API' : ''}.`, { quota: { channel: q.channel, kind: q.kind, n: q.n, unit: q.unit, max: q.max } });
      }
      for (const k of keys) hits.push({ quota_id: q.id, bucket, key: k });
    }
    this.ctx.storage.transactionSync(() => {
      for (const h of hits) {
        this.sql.exec('INSERT INTO usage (quota_id, user_id, bucket, count, ts) VALUES (?, ?, ?, 1, ?) ON CONFLICT(quota_id, user_id, bucket) DO UPDATE SET count = count + 1',
          h.quota_id, h.key, h.bucket, ts);
      }
    });
    return { ok: true, refund: hits };
  }

  async refund(uid, hits) {
    if (!Array.isArray(hits)) return;
    for (const h of hits) {
      // Public hits carry their subject key; the account's own hits use uid.
      const key = typeof h.key === 'string' && uid === PUBLIC_ID && h.key.startsWith('pub:') ? h.key : uid;
      this.sql.exec('UPDATE usage SET count = MAX(0, count - 1) WHERE quota_id = ? AND user_id = ? AND bucket = ?', h.quota_id, key, h.bucket);
    }
  }

  // ── public access: profile, trackers, subjects ────────────────────────────
  /** What the public composer needs (no secrets). */
  async publicProfile() {
    const s = this.#settings();
    const u = this.#user(PUBLIC_ID);
    const L = this.#effective(u).all;
    return {
      enabled: s['public.enabled'],
      tracking: s['public.tracking'],
      notice: s['public.notice'] ? s['public.noticeText'] : null,
      limits: { ...L, apiEnabled: false },
      caps: { maxShareBytes: Math.min(s['files.maxShareBytes'], L.maxShareBytes ?? Infinity), grantSec: s['files.grantSec'] },
      viewer: { enabled: s['viewer.enabled'] && L.viewer, maxBytes: s['viewer.maxBytes'], rules: s['viewer.enabled'] && L.viewer ? this.#viewerRules(u, L) : [] },
      quotas: this.#applicableQuotas(PUBLIC_ID).map((q) => ({ kind: q.kind, n: q.n, unit: q.unit, max: q.max })),
    };
  }

  async #subjectHash(kind, value) {
    const key = await crypto.subtle.importKey('raw', utf8(this.#meta('secret')), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return b64urlFromBytes(new Uint8Array(await crypto.subtle.sign('HMAC', key, utf8(`secbin-public/${kind}:${value}`))).subarray(0, 18));
  }

  /** The quota subject for a network key (salted, keyed hash — the address itself is never stored). */
  async ipSubject(ipKey) {
    return `pub:ip:${await this.#subjectHash('ip', String(ipKey))}`;
  }

  async #hmacTag(data) {
    const key = await crypto.subtle.importKey('raw', utf8(this.#meta('secret')), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', key, data)).subarray(0, 8);
  }

  /** A fresh, stateless tracker id (nothing is stored until it creates a share). */
  async #issueTracker(ts) {
    const b = new Uint8Array(24);
    b.set(randomBytes(12), 0);
    new DataView(b.buffer).setUint32(12, ts >>> 0);
    const body = b.subarray(0, 16);
    b.set(await this.#hmacTag(utf8('secbin-public/tid:' + b64urlFromBytes(body))), 16);
    return b64urlFromBytes(b);
  }

  /** A presented id → { h, issued } when this server issued it, else null. */
  async #checkTracker(value) {
    if (typeof value !== 'string' || !TRACKER_RE.test(value)) return null;
    let b;
    try { b = bytesFromB64url(value); } catch { return null; }
    if (b.length !== 24) return null;
    const tag = await this.#hmacTag(utf8('secbin-public/tid:' + b64urlFromBytes(b.subarray(0, 16))));
    let diff = 0;
    for (let i = 0; i < 8; i++) diff |= tag[i] ^ b[16 + i];
    if (diff) return null;
    return { h: await this.#subjectHash('tracker', value), issued: new DataView(b.buffer, b.byteOffset).getUint32(12) };
  }

  /**
   * Resolve the anonymous tracker from every copy the browser presented
   * (`candidates`: [{ src, value }], at most one per source). A copy is valid
   * when this server issued it (HMAC tag) and it has not been idle for
   * `public.trackerIdleSec`. The id presented most often wins and the caller
   * re-seeds every missing or corrupt copy from it. A tie is broken in favour
   * of the only tied id that has created shares, or else the oldest; when two
   * or more tied ids have each created shares, the right one cannot be
   * determined and all of them are blocked. With no valid copy a new id is
   * issued — statelessly, so page visits store nothing and cannot exhaust any
   * per-network budget (that is spent when an id first creates a share).
   */
  async resolveTracker({ candidates = [] }) {
    const idle = this.#settings()['public.trackerIdleSec'];
    const ts = now();
    const votes = new Map();
    const seenSrc = new Set();
    let invalid = 0;
    let presented = 0;
    for (const c of (Array.isArray(candidates) ? candidates : []).slice(0, 8)) {
      if (!c || typeof c.value !== 'string' || !c.value || seenSrc.has(c.src)) continue;
      seenSrc.add(c.src);
      presented++;
      const t = await this.#checkTracker(c.value);
      if (!t) { invalid++; continue; }
      const row = this.sql.exec('SELECT * FROM trackers WHERE id_hash = ?', t.h).toArray()[0] || null;
      if ((row ? row.last_seen : t.issued) < ts - idle) { invalid++; continue; }
      const v = votes.get(t.h) ?? { h: t.h, value: c.value, row, issued: t.issued, n: 0 };
      v.n++;
      votes.set(t.h, v);
    }
    if (!votes.size) return { ok: true, id: await this.#issueTracker(ts), status: 'new' };
    const all = [...votes.values()];
    const top = Math.max(...all.map((v) => v.n));
    const tied = all.filter((v) => v.n === top);
    let win = tied[0];
    if (tied.length > 1) {
      const used = tied.filter((v) => v.row);
      if (used.length > 1) {
        this.ctx.storage.transactionSync(() => {
          for (const v of used) this.sql.exec("UPDATE trackers SET blocked = 1, reason = 'conflict' WHERE id_hash = ?", v.h);
        });
        this.#log(null, PUBLIC_ID, 'tracker.conflict', `${used.length} ids that created shares disagree`);
        return fail(403, 'tracker_conflict', 'Your browser presented conflicting identifiers, so anonymous sharing is blocked for it. Contact the administrator.');
      }
      win = used[0] ?? tied.reduce((a, b) => (b.issued < a.issued ? b : a));
    }
    if (win.row?.blocked) return fail(403, 'tracker_blocked', 'Anonymous sharing is blocked for this browser. Contact the administrator.');
    if (win.row) this.sql.exec('UPDATE trackers SET last_seen = ? WHERE id_hash = ?', ts, win.h);
    const healed = invalid > 0 || win.n < presented;
    return { ok: true, id: win.value, status: healed ? 'healed' : 'ok' };
  }

  /**
   * The quota subject for a create request's tracker. The first create by an
   * id stores it, at most `public.newTrackersPerIp` new ids per network per
   * `public.newTrackersWindowSec` (and `MAX_TRACKERS` in all).
   */
  async trackerSubject(value, ipKey) {
    const t = await this.#checkTracker(value);
    const ipHash = await this.#subjectHash('ip', String(ipKey));
    // No awaits below: the checks and the insert are one atomic step.
    const s = this.#settings();
    const ts = now();
    if (!t) return fail(428, 'tracker_required', 'Reload the page to continue.');
    const row = this.sql.exec('SELECT * FROM trackers WHERE id_hash = ?', t.h).toArray()[0];
    if (row) {
      if (row.last_seen < ts - s['public.trackerIdleSec']) return fail(428, 'tracker_required', 'Reload the page to continue.');
      if (row.blocked) return fail(403, 'tracker_blocked', 'Anonymous sharing is blocked for this browser. Contact the administrator.');
      this.sql.exec('UPDATE trackers SET last_seen = ? WHERE id_hash = ?', ts, t.h);
      return { ok: true, subject: `pub:t:${t.h}` };
    }
    if (t.issued < ts - s['public.trackerIdleSec']) return fail(428, 'tracker_required', 'Reload the page to continue.');
    const recent = this.sql.exec('SELECT COUNT(*) AS c FROM trackers WHERE ip_hash = ? AND created > ?', ipHash, ts - s['public.newTrackersWindowSec']).one().c;
    if (recent >= s['public.newTrackersPerIp']) {
      return fail(429, 'tracker_rate_limited', 'Too many new anonymous senders from your network. Try again later.');
    }
    if (this.sql.exec('SELECT COUNT(*) AS c FROM trackers').one().c >= MAX_TRACKERS) {
      return fail(429, 'busy', 'Anonymous sharing is at capacity. Try again later.');
    }
    this.sql.exec('INSERT INTO trackers (id_hash, created, last_seen, ip_hash) VALUES (?, ?, ?, ?)', t.h, ts, ts, ipHash);
    return { ok: true, subject: `pub:t:${t.h}` };
  }

  /** Count one share created under a tracker subject (after it succeeded). */
  async trackerUsed(subject) {
    if (typeof subject !== 'string' || !subject.startsWith('pub:t:')) return;
    this.sql.exec('UPDATE trackers SET uses = uses + 1 WHERE id_hash = ?', subject.slice(6));
  }

  async listTrackers({ limit = 100, blocked = null } = {}) {
    const lim = Math.max(1, Math.min(500, limit | 0));
    const rows = blocked === true
      ? this.sql.exec('SELECT id_hash, created, last_seen, uses, blocked, reason FROM trackers WHERE blocked = 1 ORDER BY last_seen DESC LIMIT ?', lim).toArray()
      : this.sql.exec('SELECT id_hash, created, last_seen, uses, blocked, reason FROM trackers ORDER BY last_seen DESC LIMIT ?', lim).toArray();
    const total = this.sql.exec('SELECT COUNT(*) AS c, SUM(blocked) AS b FROM trackers').one();
    return { rows: rows.map((r) => ({ ...r, id: r.id_hash.slice(0, 12) })), total: total.c, blocked: total.b ?? 0 };
  }

  /** Admin: unblock, block or forget a tracker (by its hash prefix shown in the list). */
  async adminTracker(prefix, action, actorId) {
    if (typeof prefix !== 'string' || !/^[A-Za-z0-9_-]{12}$/.test(prefix)) return fail(400, 'invalid', 'Unknown tracker.');
    const rows = this.sql.exec("SELECT id_hash FROM trackers WHERE substr(id_hash, 1, 12) = ?", prefix).toArray();
    if (rows.length !== 1) return fail(404, 'not_found', 'Unknown tracker.');
    const h = rows[0].id_hash;
    if (action === 'unblock') this.sql.exec("UPDATE trackers SET blocked = 0, reason = '' WHERE id_hash = ?", h);
    else if (action === 'block') this.sql.exec("UPDATE trackers SET blocked = 1, reason = 'admin' WHERE id_hash = ?", h);
    else if (action === 'forget') {
      this.sql.exec('DELETE FROM trackers WHERE id_hash = ?', h);
      this.sql.exec('DELETE FROM usage WHERE user_id = ?', `pub:t:${h}`);
    } else return fail(400, 'invalid', 'action must be unblock, block or forget');
    this.#log(actorId, PUBLIC_ID, `tracker.${action}`, `id=${prefix}`);
    return { ok: true };
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
    // Upsert that never touches the lock columns: re-recording an id must not
    // silently unlock it.
    this.sql.exec(`INSERT INTO shares (id, user_id, kind, label, created, expires, views_total, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
      ON CONFLICT(id) DO UPDATE SET user_id = excluded.user_id, kind = excluded.kind, label = excluded.label, created = excluded.created,
        expires = excluded.expires, views_total = excluded.views_total, status = 'active'`,
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
  /**
   * May a recipient "delete now" this share at this moment? The sender's
   * opt-in is in the share itself; this is the rest: not locked, and the
   * sender's account still has the `openerDelete` permission (an admin who
   * turns it off also stops shares created earlier).
   */
  async recipientDeleteStatus(id) {
    const r = this.sql.exec('SELECT user_id, locked FROM shares WHERE id = ?', id).toArray()[0];
    if (!r) return 'unknown';
    if (r.locked) return 'locked';
    const u = this.#user(r.user_id);
    if (!u || u.disabled || !this.#effective(u).all.openerDelete) return 'not_allowed';
    return 'ok';
  }

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
    if (admin) {
      const o = this.#user(admin);
      if (!o || o.role !== 'owner') return fail(403, 'forbidden', 'Only the owner can change other users’ shares.');
    }
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

  /** A recipient used "delete now" (the sender allowed it): end the row and tell the sender. */
  async shareDeletedByRecipient(id) {
    const row = this.sql.exec('SELECT user_id FROM shares WHERE id = ?', id).toArray()[0];
    this.sql.exec("UPDATE shares SET status = 'deleted' WHERE id = ? AND status = 'active'", id);
    if (row) this.#log(null, row.user_id, 'share.deleted_by_recipient', `id=${id}`);
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
    if (u.role === 'public') return fail(403, 'forbidden', 'The public account is built in: turn public access on or off in its settings.');
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
    if (u.role === 'public') return fail(403, 'forbidden', 'The public account is built in and cannot be deleted.');
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
    if (u.role === 'public') return fail(403, 'forbidden', 'The public account has no password.');
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

  // ── admin: export / import (secbin-export/v1, see src/lib/portable.js) ──
  /**
   * The plaintext export document. `users` is 'all' or a list of user ids;
   * the owner is never included. The caller encrypts it before it is stored.
   */
  async exportData({ system = false, users = [], credentials = false, config = false, origin }, actorId) {
    const doc = { format: EXPORT_FORMAT, created: now(), users: [] };
    if (typeof origin === 'string') doc.origin = origin.slice(0, 200);
    if (system) {
      doc.system = {
        settings: this.#settings(),
        limits: { all: this.#limitRows('', 'all'), api: this.#limitRows('', 'api') },
        quotas: this.#quotaRows(''),
        viewerRules: this.sql.exec("SELECT match, value, renderer FROM viewer_rules WHERE user_id = '' ORDER BY id").toArray(),
        ipRules: (await this.ipRules()).map((r) => ({ cidr: r.cidr, action: r.action, expires: r.expires ?? null, note: r.note || '' })),
      };
    }
    const rows = users === 'all'
      ? this.sql.exec("SELECT * FROM users WHERE role = 'user' ORDER BY username LIMIT ?", MAX_EXPORT_USERS + 1).toArray()
      : (Array.isArray(users) ? users : []).slice(0, MAX_EXPORT_USERS + 1).map((id) => this.#user(id)).filter((u) => u && u.role === 'user');
    // Never produce a file that the import would refuse.
    if (rows.length > MAX_EXPORT_USERS && (credentials || config)) {
      return fail(413, 'too_many_users', `An export holds at most ${MAX_EXPORT_USERS} users — export them in parts.`);
    }
    if (credentials || config) {
      for (const u of rows) {
        const e = { username: u.username };
        if (credentials) e.credentials = { salt: u.pw_salt, t: u.pw_t, verifier: u.pw_verifier, disabled: !!u.disabled };
        if (config) {
          e.config = {
            limits: { all: this.#limitRows(u.id, 'all'), api: this.#limitRows(u.id, 'api') },
            quotas: this.#quotaRows(u.id),
            viewerRules: this.sql.exec('SELECT match, value, renderer FROM viewer_rules WHERE user_id = ? ORDER BY id', u.id).toArray(),
          };
        }
        doc.users.push(e);
      }
    }
    this.#log(actorId, null, 'export.created',
      `system=${system ? 1 : 0} users=${doc.users.length} credentials=${credentials ? 1 : 0} config=${config ? 1 : 0}`);
    // Which accounts left the system (and whether with verifiers), in chunks
    // that fit the audit detail field.
    this.#logChunks(actorId, null, 'export.users', `${[credentials ? 'credentials' : null, config ? 'config' : null].filter(Boolean).join('+')}: `, doc.users.map((e) => e.username));
    return { ok: true, doc };
  }

  /** Log `items` as as many entries as needed to fit the detail field (nothing truncated). */
  #logChunks(actorId, subject, action, prefix, items) {
    let cur = [];
    const flush = () => { if (cur.length) this.#log(actorId, subject, action, `${prefix}${cur.join(', ')}`); cur = []; };
    for (const it of items) {
      if (cur.length && `${prefix}${[...cur, it].join(', ')}`.length > 480) flush();
      cur.push(String(it).slice(0, 400));
    }
    flush();
  }

  #quotaRows(userId) {
    return this.sql.exec('SELECT channel, kind, n, unit, max FROM quotas WHERE user_id = ? ORDER BY id', userId).toArray();
  }

  /**
   * Plan (dryRun) or apply an import of a validated document with validated
   * decisions (portable.js). Applying is all-or-nothing: one storage
   * transaction, and any planning error refuses the whole import.
   */
  async importData(doc, decisions, { dryRun = true, callerIp = null } = {}, actorId) {
    const plan = { system: null, users: [], errors: [], warnings: [] };
    if (decisions.system) {
      const cur = this.#settings();
      const existingRules = new Set((await this.ipRules()).map((r) => `${r.action} ${r.cidr}`));
      const ts = now();
      const ipAdd = doc.system.ipRules.filter((r) => (r.expires === null || r.expires > ts) && !existingRules.has(`${r.action} ${r.cidr}`));
      const merged = { ...cur, ...doc.system.settings };
      if (merged['session.idleSec'] > merged['session.absSec']) plan.errors.push('system: the idle timeout would exceed the absolute timeout');
      // Never lock out the owner who is importing: a new block rule covering
      // the caller (with no allow rule for it) refuses the import.
      const me = parseIp(callerIp ?? '');
      if (me) {
        const after = [...(await this.ipRules()), ...ipAdd].map((r) => ({ action: r.action, c: parseCidr(r.cidr) }));
        const allowed = after.some((r) => r.action === 'allow' && cidrContains(r.c, me));
        const blocking = ipAdd.find((r) => r.action === 'block' && cidrContains(parseCidr(r.cidr), me));
        if (blocking && !allowed) plan.errors.push(`system: the IP rule "block ${blocking.cidr}" would block your own address — remove it from the file or add an allow rule for yourself first`);
      }
      // Security-relevant changes are called out in the preview.
      for (const [k, v] of Object.entries(doc.system.settings)) {
        if (/^(guard|lockout|public)\./.test(k) && cur[k] !== v) plan.warnings.push(`security setting ${k}: ${cur[k]} → ${v}`);
      }
      for (const r of ipAdd) if (r.action === 'allow') plan.warnings.push(`adds an allow rule (exempts ${r.cidr} from brute-force protection and blocks)`);
      plan.system = {
        settings: Object.entries(doc.system.settings).filter(([k, v]) => cur[k] !== v).map(([key, to]) => ({ key, from: cur[key], to })),
        limits: { all: Object.keys(doc.system.limits.all).length, api: Object.keys(doc.system.limits.api).length },
        quotas: doc.system.quotas.length,
        viewerRules: doc.system.viewerRules.length,
        ipRulesAdded: ipAdd.map((r) => `${r.action} ${r.cidr}`),
        ipRulesSkipped: doc.system.ipRules.length - ipAdd.length,
      };
      plan.system._ipAdd = ipAdd;
    }
    for (const u of doc.users) {
      const d = decisions.users.get(u.username);
      if (!d) { plan.users.push({ username: u.username, action: 'skip' }); continue; }
      const existing = this.#userByName(d.as);
      const parts = [u.credentials ? 'credentials' : null, u.config ? 'config' : null].filter(Boolean);
      const entry = { username: u.username, as: d.as, parts };
      if (existing && existing.role !== 'user') {
        entry.action = 'refused';
        plan.errors.push(`"${d.as}" is the owner account and cannot be imported over — import it under another name`);
      } else if (existing && !d.overwrite) {
        entry.action = 'conflict';
        plan.errors.push(`"${d.as}" already exists — choose overwrite, another name, or skip`);
      } else if (!existing && !u.credentials) {
        entry.action = 'refused';
        plan.errors.push(`"${d.as}" does not exist here and the export has no credentials for it — it cannot be created`);
      } else {
        entry.action = existing ? 'overwrite' : 'create';
        if (existing && u.credentials) entry.note = 'ends its sessions and revokes its API keys; its shares stay';
      }
      plan.users.push(entry);
    }
    const out = (applied) => {
      const { _ipAdd, ...system } = plan.system ?? {};
      return { ok: true, applied, plan: { system: plan.system ? system : null, users: plan.users, errors: plan.errors, warnings: plan.warnings } };
    };
    if (dryRun) return out(false);
    if (plan.errors.length) return fail(409, 'import_conflicts', `The import was not applied: ${plan.errors.length} problem${plan.errors.length === 1 ? '' : 's'} (run the preview).`, { plan: out(false).plan });

    const ts = now();
    const replaceScope = (userId, limits, quotas, rules) => {
      this.sql.exec('DELETE FROM limits WHERE user_id = ?', userId);
      for (const ch of ['all', 'api']) {
        for (const [k, v] of Object.entries(limits[ch])) this.sql.exec('INSERT INTO limits (user_id, channel, key, value) VALUES (?, ?, ?, ?)', userId, ch, k, JSON.stringify(v));
      }
      for (const o of this.sql.exec('SELECT id FROM quotas WHERE user_id = ?', userId).toArray()) this.sql.exec('DELETE FROM usage WHERE quota_id = ?', o.id);
      this.sql.exec('DELETE FROM quotas WHERE user_id = ?', userId);
      for (const q of quotas) this.sql.exec('INSERT INTO quotas (id, user_id, channel, kind, n, unit, max) VALUES (?, ?, ?, ?, ?, ?, ?)', newId(), userId, q.channel, q.kind, q.n, q.unit, q.max);
      this.sql.exec('DELETE FROM viewer_rules WHERE user_id = ?', userId);
      for (const r of rules) this.sql.exec('INSERT INTO viewer_rules (user_id, match, value, renderer) VALUES (?, ?, ?, ?)', userId, r.match, r.value, r.renderer);
    };
    this.ctx.storage.transactionSync(() => {
      if (plan.system) {
        const s = doc.system;
        for (const [k, v] of Object.entries(s.settings)) this.sql.exec('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', k, JSON.stringify(v));
        replaceScope('', s.limits, s.quotas, s.viewerRules);
        for (const r of plan.system._ipAdd) this.sql.exec('INSERT INTO ip_rules (id, cidr, action, expires, note, created) VALUES (?, ?, ?, ?, ?, ?)', newId(), r.cidr, r.action, r.expires, r.note, ts);
        // The same entries the admin API writes, so an import is as visible as
        // the equivalent manual changes.
        this.#log(actorId, null, 'import.system', `settings=${plan.system.settings.length} ipRules+${plan.system._ipAdd.length}`);
        this.#logChunks(actorId, null, 'settings.updated', 'import: ', plan.system.settings.map((c) => `${c.key}=${JSON.stringify(c.to)}`));
        for (const ch of ['all', 'api']) this.#logChunks(actorId, null, 'limits.updated', `import global ${ch}: `, Object.entries(s.limits[ch]).map(([k, v]) => `${k}=${JSON.stringify(v)}`).concat(Object.keys(s.limits[ch]).length ? [] : ['none']));
        this.#logChunks(actorId, null, 'quotas.updated', 'import global: ', s.quotas.length ? s.quotas.map((q) => `${q.max}/${q.n}${q.unit} ${q.kind} ${q.channel}`) : ['none']);
        this.#log(actorId, null, 'viewer_rules.updated', `import global: ${s.viewerRules.length} rules`);
        for (const r of plan.system._ipAdd) this.#log(actorId, null, 'iprule.added', `import: ${r.action} ${r.cidr}${r.note ? ` (${r.note})` : ''}`);
      }
      for (const [i, u] of doc.users.entries()) {
        const e = plan.users[i];
        if (e.action !== 'create' && e.action !== 'overwrite') continue;
        let id;
        if (e.action === 'create') {
          id = newId();
          const c = u.credentials;
          this.sql.exec("INSERT INTO users (id, username, role, pw_salt, pw_t, pw_verifier, disabled, created, updated) VALUES (?, ?, 'user', ?, ?, ?, ?, ?, ?)",
            id, e.as, c.salt, c.t, c.verifier, c.disabled ? 1 : 0, ts, ts);
        } else {
          id = this.#userByName(e.as).id;
          if (u.credentials) {
            const c = u.credentials;
            // New credentials end every existing session, revoke the account's
            // API keys (they are not tied to the password) and clear lockouts.
            this.sql.exec('UPDATE users SET pw_salt = ?, pw_t = ?, pw_verifier = ?, disabled = ?, sess_ver = sess_ver + 1, updated = ? WHERE id = ?',
              c.salt, c.t, c.verifier, c.disabled ? 1 : 0, ts, id);
            this.sql.exec('DELETE FROM failures WHERE user_id = ?', id);
            this.sql.exec('DELETE FROM pwchange_failures WHERE user_id = ?', id);
            this.sql.exec('DELETE FROM api_keys WHERE user_id = ?', id);
          }
        }
        if (u.config) {
          replaceScope(id, u.config.limits, u.config.quotas, u.config.viewerRules);
          const L = u.config.limits;
          for (const ch of ['all', 'api']) this.#logChunks(actorId, id, 'limits.updated', `import ${ch}: `, Object.keys(L[ch]).length ? Object.entries(L[ch]).map(([k, v]) => `${k}=${JSON.stringify(v)}`) : ['none']);
        }
        this.#log(actorId, id, 'user.imported', `${e.action}${e.as !== u.username ? ` from=${u.username}` : ''} parts=${e.parts.join('+')}`);
      }
    });
    return out(true);
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
    // Anonymous trackers expire after being idle, with their usage counters.
    const idleBefore = ts - this.#settings()['public.trackerIdleSec'];
    this.sql.exec("DELETE FROM usage WHERE user_id IN (SELECT 'pub:t:' || id_hash FROM trackers WHERE last_seen < ?)", idleBefore);
    this.sql.exec('DELETE FROM trackers WHERE last_seen < ?', idleBefore);
    this.sql.exec('DELETE FROM ip_rules WHERE expires IS NOT NULL AND expires < ?', ts);
    this.sql.exec("UPDATE shares SET status = 'expired' WHERE status = 'active' AND expires > 0 AND expires < ?", ts);
    this.sql.exec("DELETE FROM shares WHERE status != 'active' AND locked = 0 AND expires < ?", ts - SHARE_PRUNE_SEC);
    await this.ctx.storage.setAlarm(Date.now() + 3600 * 1000);
  }
}

export const SETTING_KEYS = Object.keys(SETTINGS);
