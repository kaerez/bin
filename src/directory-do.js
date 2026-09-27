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
import { b64urlFromBytes, bytesFromB64url, randomBytes, utf8, timingSafeEqualHex, sha256Hex } from '../public/js/bytes.js';
import { verifyRegistration, verifyAssertion, assertionId } from './lib/webauthn.js';
import { ARGON2 } from '../public/js/format.js';
import {
  SETTINGS, checkSetting, settingsWithDefaults, crossCheckSettings, logValue, LIMITS, checkLimit, resolveLimits, restrictForApi, MAX_API_KEYS, API_SCOPES, DEFAULT_KEY_SCOPES, PASSWORD_POLICY_KEYS,
  UNLIMITED, checkQuota, quotaBucket, checkViewerRule, DEFAULT_VIEWER_RULES, MAX_PASSKEYS,
} from './lib/settings.js';
import { normalizeRule, parseIp, parseRule, ruleContains } from './lib/ip.js';
import { EXPORT_FORMAT, MAX_EXPORT_USERS, USER_PARTS, OWNER_PARTS } from './lib/portable.js';
import { refusedTypes, checkDeclaredTypes, describeType, MAX_FOLDER_DEPTH } from '../public/js/filepolicy.js';
import { HARD_MAX_SHARE_BYTES } from '../public/js/files.js';
import { normalizeUrlRules, upgradeUrlRules, DEFAULT_URL_RULES } from '../public/js/sharetypes.js';
import { publicStatement } from '../public/js/a11ystatement.js';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, role TEXT NOT NULL,
  pw_salt TEXT NOT NULL, pw_t INTEGER NOT NULL, pw_verifier TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0,
  sess_ver INTEGER NOT NULL DEFAULT 1, created INTEGER NOT NULL, updated INTEGER NOT NULL,
  webauthn_handle TEXT, mfa INTEGER NOT NULL DEFAULT 0, role_id TEXT);
CREATE TABLE IF NOT EXISTS roles (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE, own_quotas INTEGER NOT NULL DEFAULT 0,
  created INTEGER NOT NULL, updated INTEGER NOT NULL);
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
  name TEXT NOT NULL, created INTEGER NOT NULL, last_used INTEGER, expires INTEGER,
  scopes TEXT NOT NULL DEFAULT 'notes,files,policy');
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
  locked INTEGER NOT NULL DEFAULT 0, locked_by TEXT, locked_at INTEGER, opens_total INTEGER NOT NULL DEFAULT 0, lh TEXT);
CREATE INDEX IF NOT EXISTS shares_user ON shares(user_id, created);
CREATE TABLE IF NOT EXISTS ip_rules (id TEXT PRIMARY KEY, cidr TEXT NOT NULL, action TEXT NOT NULL, expires INTEGER,
  note TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS trackers (id_hash TEXT PRIMARY KEY, created INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  uses INTEGER NOT NULL DEFAULT 0, ip_hash TEXT NOT NULL, blocked INTEGER NOT NULL DEFAULT 0, reason TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS trackers_ip ON trackers(ip_hash, created);
CREATE INDEX IF NOT EXISTS trackers_seen ON trackers(last_seen);
CREATE TABLE IF NOT EXISTS opens (id INTEGER PRIMARY KEY AUTOINCREMENT, share_id TEXT NOT NULL, user_id TEXT NOT NULL, ts INTEGER NOT NULL,
  ip TEXT NOT NULL DEFAULT '', country TEXT NOT NULL DEFAULT '', region TEXT NOT NULL DEFAULT '', city TEXT NOT NULL DEFAULT '',
  browser TEXT NOT NULL DEFAULT '', browser_ver TEXT NOT NULL DEFAULT '', os TEXT NOT NULL DEFAULT '', langs TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS opens_share ON opens(share_id, id);
CREATE INDEX IF NOT EXISTS opens_user ON opens(user_id, ts);
CREATE INDEX IF NOT EXISTS opens_ts ON opens(ts);
CREATE INDEX IF NOT EXISTS activity_ts ON activity(ts);
CREATE TABLE IF NOT EXISTS passkeys (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, public_key TEXT NOT NULL,
  alg INTEGER NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0, transports TEXT NOT NULL DEFAULT '',
  backup_eligible INTEGER NOT NULL DEFAULT 0, backed_up INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL, last_used INTEGER);
CREATE INDEX IF NOT EXISTS passkeys_user ON passkeys(user_id);
CREATE TABLE IF NOT EXISTS recovery_codes (hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, created INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS recovery_user ON recovery_codes(user_id);
CREATE TABLE IF NOT EXISTS webauthn_challenges (id TEXT PRIMARY KEY, user_id TEXT, purpose TEXT NOT NULL, challenge TEXT NOT NULL,
  exp INTEGER NOT NULL, tries INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS webauthn_spent (challenge TEXT PRIMARY KEY, exp INTEGER NOT NULL);
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
  // 4: read receipts (every open of a share)
  (m) => {
    m.sql.exec(`CREATE TABLE IF NOT EXISTS opens (id INTEGER PRIMARY KEY AUTOINCREMENT, share_id TEXT NOT NULL, user_id TEXT NOT NULL, ts INTEGER NOT NULL,
      ip TEXT NOT NULL DEFAULT '', country TEXT NOT NULL DEFAULT '', region TEXT NOT NULL DEFAULT '', city TEXT NOT NULL DEFAULT '',
      browser TEXT NOT NULL DEFAULT '', browser_ver TEXT NOT NULL DEFAULT '', os TEXT NOT NULL DEFAULT '', langs TEXT NOT NULL DEFAULT '')`);
    m.sql.exec('CREATE INDEX IF NOT EXISTS opens_share ON opens(share_id, id)');
    m.sql.exec('CREATE INDEX IF NOT EXISTS opens_user ON opens(user_id, ts)');
  },
  // 5: per-key API scopes (existing keys keep the creation scopes) — see API_SCOPES
  (m) => m.addColumn('api_keys', 'scopes', "TEXT NOT NULL DEFAULT 'notes,files,policy'"),
  // 6: passkeys, recovery codes, WebAuthn challenges; users.webauthn_handle, users.mfa
  (m) => {
    m.addColumn('users', 'webauthn_handle', 'TEXT');
    m.addColumn('users', 'mfa', 'INTEGER NOT NULL DEFAULT 0');
    m.sql.exec(`CREATE TABLE IF NOT EXISTS passkeys (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, public_key TEXT NOT NULL,
      alg INTEGER NOT NULL, sign_count INTEGER NOT NULL DEFAULT 0, transports TEXT NOT NULL DEFAULT '',
      backup_eligible INTEGER NOT NULL DEFAULT 0, backed_up INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL, last_used INTEGER)`);
    m.sql.exec('CREATE INDEX IF NOT EXISTS passkeys_user ON passkeys(user_id)');
    m.sql.exec('CREATE TABLE IF NOT EXISTS recovery_codes (hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, created INTEGER NOT NULL)');
    m.sql.exec('CREATE INDEX IF NOT EXISTS recovery_user ON recovery_codes(user_id)');
    m.sql.exec(`CREATE TABLE IF NOT EXISTS webauthn_challenges (id TEXT PRIMARY KEY, user_id TEXT, purpose TEXT NOT NULL, challenge TEXT NOT NULL,
      exp INTEGER NOT NULL, tries INTEGER NOT NULL DEFAULT 0)`);
  },
  // 7: usernameless login challenges are no longer stored (HMAC-signed); only
  // spent ones are remembered until they expire
  (m) => {
    m.sql.exec('CREATE TABLE IF NOT EXISTS webauthn_spent (challenge TEXT PRIMARY KEY, exp INTEGER NOT NULL)');
    m.sql.exec("DELETE FROM webauthn_challenges WHERE purpose = 'login'");
  },
  // 8: read-receipt counter (every open, stored or throttled) and time indexes
  // for log and receipt pruning
  (m) => {
    m.addColumn('shares', 'opens_total', 'INTEGER NOT NULL DEFAULT 0');
    m.sql.exec('CREATE INDEX IF NOT EXISTS opens_ts ON opens(ts)');
    m.sql.exec('CREATE INDEX IF NOT EXISTS activity_ts ON activity(ts)');
  },
  // 9: each share's link-proof hash, kept after its content is gone, so a late
  // fetch with the right link is told apart from a guess (shares from before
  // this have none and are never counted, as before)
  (m) => {
    m.addColumn('shares', 'lh', 'TEXT');
  },
  // 10: roles. Each account has one (users.role_id; none = the Default role,
  // i.e. the global rows); a role's limits, quotas and viewer rules live under
  // the scope "r:<id>". Per-user overrides are dropped (the public account
  // keeps its own); how many is recorded and logged once the migration is done.
  (m) => {
    m.sql.exec(`CREATE TABLE IF NOT EXISTS roles (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE, own_quotas INTEGER NOT NULL DEFAULT 0,
      created INTEGER NOT NULL, updated INTEGER NOT NULL)`);
    m.addColumn('users', 'role_id', 'TEXT');
    const own = "user_id != '' AND user_id != 'public-user-0000' AND user_id NOT LIKE 'r:%'";
    const counts = [
      m.sql.exec(`SELECT COUNT(*) AS c FROM limits WHERE ${own}`).one().c,
      m.sql.exec(`SELECT COUNT(*) AS c FROM quotas WHERE ${own}`).one().c,
      m.sql.exec(`SELECT COUNT(*) AS c FROM viewer_rules WHERE ${own}`).one().c,
      m.sql.exec(`SELECT COUNT(DISTINCT user_id) AS c FROM (SELECT user_id FROM limits WHERE ${own} UNION SELECT user_id FROM quotas WHERE ${own} UNION SELECT user_id FROM viewer_rules WHERE ${own})`).one().c,
    ];
    m.sql.exec(`DELETE FROM usage WHERE quota_id IN (SELECT id FROM quotas WHERE ${own})`);
    m.sql.exec(`DELETE FROM limits WHERE ${own}`);
    m.sql.exec(`DELETE FROM quotas WHERE ${own}`);
    m.sql.exec(`DELETE FROM viewer_rules WHERE ${own}`);
    if (counts.some((c) => c > 0)) {
      m.sql.exec("INSERT INTO meta (k, v) VALUES ('roles_migration', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
        `accounts=${counts[3]} limits=${counts[0]} quotas=${counts[1]} viewer_rules=${counts[2]}`);
    }
    materializeDefaultRole(m.sql);
  },
  // 11: link rules say which form a scheme takes: scheme:name:// or
  // scheme:name: ("scheme:tel" → "scheme:tel:", "scheme:https" →
  // "scheme:https://", other schemes → both forms, so nothing changes)
  (m) => {
    for (const r of m.sql.exec("SELECT user_id, channel, value FROM limits WHERE key = 'urlRules'").toArray()) {
      let list;
      try { list = normalizeUrlRules(upgradeUrlRules(JSON.parse(r.value))); } catch { list = [...DEFAULT_URL_RULES]; }
      m.sql.exec("UPDATE limits SET value = ? WHERE user_id = ? AND channel = ? AND key = 'urlRules'", JSON.stringify(list), r.user_id, r.channel);
    }
  },
  // 12: the server-wide share-size cap, viewer switch and largest previewable
  // file are role options now: drop the old settings; the Default role gets a
  // value for every option (the download window and upload deadline start
  // from the current settings, which stay the owner's own).
  (m) => {
    for (const k of ['files.maxShareBytes', 'viewer.enabled', 'viewer.maxBytes']) m.sql.exec('DELETE FROM settings WHERE key = ?', k);
    materializeDefaultRole(m.sql);
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
 * The Default role holds an explicit value for every role option (the global
 * rows): whatever is missing gets its built-in default, and the per-role
 * values of server-wide settings (user session timeouts, the largest
 * previewable file) start from the current settings. Idempotent.
 */
function materializeDefaultRole(sql) {
  const rows = {};
  for (const r of sql.exec("SELECT key, value FROM limits WHERE user_id = '' AND channel = 'all'").toArray()) rows[r.key] = r.value;
  const st = {};
  for (const r of sql.exec('SELECT key, value FROM settings').toArray()) { try { st[r.key] = JSON.parse(r.value); } catch { /* default applies */ } }
  const settings = settingsWithDefaults(st);
  const start = { sessionIdleSec: settings['session.idleSec'], sessionAbsSec: settings['session.absSec'],
    fileGrantSec: settings['files.grantSec'], filePendingSec: settings['files.pendingSec'] };
  // The file-type mode and list go together: set both or neither.
  if (!('fileTypeMode' in rows) || !('fileTypeRules' in rows)) { delete rows.fileTypeMode; delete rows.fileTypeRules; }
  for (const [k, spec] of Object.entries(LIMITS)) {
    if (k in rows) continue;
    const v = k in start ? start[k] : spec.def;
    sql.exec("INSERT INTO limits (user_id, channel, key, value) VALUES ('', 'all', ?, ?) ON CONFLICT(user_id, channel, key) DO UPDATE SET value = excluded.value", k, JSON.stringify(v));
  }
}

/** The storage scope of a role's limits, quotas and viewer rules. */
const roleScope = (id) => `r:${id}`;
const ROLE_ID_RE = /^[A-Za-z0-9_-]{16}$/;
const RESERVED_ROLE_NAMES = ['owner', 'default', 'public'];
const TURNSTILE_KEY_RE = /^[A-Za-z0-9_-]{10,100}$/; // as src/lib/turnstile.js
/** A key's scopes in canonical order, or null unless a non-empty list of known scopes. */
const keyScopes = (list) => (Array.isArray(list) && list.length && list.every((x) => API_SCOPES.includes(x)) ? API_SCOPES.filter((x) => list.includes(x)) : null);
/**
 * The built-in public (anonymous) account: owns shares created without an
 * account. It has no password, cannot sign in, cannot be deleted, renamed,
 * disabled, impersonated or exported, and never holds API keys. Its name is
 * outside USERNAME_RE, so no real account can take it.
 */
export const PUBLIC_ID = 'public-user-0000';
/**
 * Most users the admin share list filters by at once. The ids are bound as one
 * JSON array (`json_each(?)`), not one parameter each, so the list stays well
 * clear of SQLite's bound-parameter limit (about 100 in a Durable Object).
 */
export const MAX_SHARE_FILTER_USERS = 500; // ~19 bytes per id in the URL: stays well under the 16 KB URL limit
/**
 * Limits that mean nothing for the public account: it has no API keys, no
 * dashboard to see read receipts in, no password or passkeys, and its log
 * entries are the server's. They cannot be set for it (inheriting is fine).
 */
export const PUBLIC_NA_LIMITS = Object.freeze(['apiEnabled', 'apiMaxKeys', 'receiptIp', 'receiptLocation', 'receiptBrowser', 'receiptOs',
  'receiptLanguages', 'logMaxAgeSec', 'logMaxEntries', 'pwMinLength', 'pwUpper', 'pwLower', 'pwDigit', 'pwSymbol', 'passkeys', 'passkeysMax',
  'sessionIdleSec', 'sessionAbsSec']);
const PUBLIC_NAME = '(public)';
// Anonymous tracker ids are stateless until first used to create a share:
// 12 random bytes ‖ issued-at (u32 BE seconds) ‖ HMAC tag (8 bytes) → 32 chars.
const TRACKER_RE = /^[A-Za-z0-9_-]{32}$/;
// Hard ceiling on stored trackers (each costs one row in this singleton).
const MAX_TRACKERS = 200000;
const HEX64_RE = /^[0-9a-f]{64}$/;
const B64_16_RE = /^[A-Za-z0-9_-]{22}$/;
const SHARE_PRUNE_SEC = 30 * 86400;
const MAX_OPENS_PER_SHARE = 1000;
// Read receipts are throttled so that a link holder cannot flood this object
// or push the genuine receipts out: one per share and address per window, at
// most OPENS_PER_MINUTE per share, and the first OPENS_KEEP_FIRST are kept
// for good (the rest is a rolling window). Every open that reaches this
// object counts in shares.opens_total (the Worker drops only floods: more than
// 5 a minute from one address for one share).
const OPENS_DEDUPE_SEC = 60;
const OPENS_PER_MINUTE = 30;
const OPENS_KEEP_FIRST = 100;
// Passkeys (see the passkeys section and src/lib/webauthn.js).

const RECOVERY_CODES = 20;
const CHALLENGE_SEC = 300;
const MAX_CHALLENGES = 5000;
// Pending (stored) challenges per account and purpose: a new one retires the oldest.
const MAX_CHALLENGES_PER_USER = 3;
const SECOND_FACTOR_TRIES = 5;
// A passkey imported onto an account whose WebAuthn user handle differs from
// the one it was registered under (e.g. the owner's passkeys from another
// server) keeps its own handle here, in meta, so that a usernameless sign-in
// can still check the handle the authenticator returns. No schema change.
const handleAlias = (credentialId) => `passkey.handle:${credentialId}`;
// Recovery codes: 16 Crockford base32 characters (80 random bits), shown as
// XXXX-XXXX-XXXX-XXXX; stored as SHA-256 only. Typing is forgiving: case,
// dashes and spaces are ignored and O/I/L read as 0/1/1.
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
function newRecoveryCode() {
  const b = randomBytes(10);
  let bits = 0;
  let acc = 0;
  let out = '';
  for (const x of b) {
    acc = (acc << 8) | x;
    bits += 8;
    while (bits >= 5) { bits -= 5; out += CROCKFORD[(acc >> bits) & 31]; }
  }
  return out.match(/.{4}/g).join('-');
}
export function normalizeRecoveryCode(code) {
  if (typeof code !== 'string' || code.length > 64) return null;
  const v = code.toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
  return /^[0-9A-HJKMNP-TV-Z]{16}$/.test(v) ? v : null;
}
// Read-receipt details and the limit that lets a sender see each one.
const RECEIPT_FIELDS = [
  { limit: 'receiptIp', cols: ['ip'] },
  { limit: 'receiptLocation', cols: ['country', 'region', 'city'] },
  { limit: 'receiptBrowser', cols: ['browser', 'browser_ver'] },
  { limit: 'receiptOs', cols: ['os'] },
  { limit: 'receiptLanguages', cols: ['langs'] },
];

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
      const dropped = this.#meta('roles_migration');
      if (dropped) {
        this.#log(null, null, 'roles.migrated', `per-user settings removed (roles replace them): ${dropped}`);
        this.sql.exec("DELETE FROM meta WHERE k = 'roles_migration'");
      }
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
    return u && { id: u.id, username: u.username, role: u.role, disabled: !!u.disabled, created: u.created, updated: u.updated,
      roleId: u.role === 'owner' ? 'owner' : u.role === 'user' && this.#role(u.role_id) ? u.role_id : u.role === 'user' ? 'default' : null };
  }
  /**
   * `actor` is a user id, or { id, imp: true } when the owner acted while
   * impersonating `subject` (the user's own log shows it as theirs; the audit
   * shows the truth), or { id, adm: true } when the owner acted directly from
   * the admin panel on the subject's data (never shown in the user's own log).
   */
  #log(actor, subject, action, detail = '') {
    // Enforce the size limit now and then, not only in the hourly alarm.
    this.logWrites = ((this.logWrites ?? 0) + 1) % 500;
    if (this.logWrites === 0) this.#pruneLogs();
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
  #role(id) {
    return typeof id === 'string' && id ? this.sql.exec('SELECT * FROM roles WHERE id = ?', id).toArray()[0] || null : null;
  }
  /**
   * Where an account's limits, quotas and viewer rules live: its role's
   * scope ("r:<id>"), the Default role's (the global rows, ''), or — for the
   * public account — its own.
   */
  #scopeOf(u) {
    if (u.role === 'public') return u.id;
    if (u.role === 'user' && this.#role(u.role_id)) return roleScope(u.role_id);
    return '';
  }
  #effective(u) {
    // The owner's role is locked: everything allowed, no limits.
    if (u.role === 'owner') return { all: { ...UNLIMITED }, api: { ...UNLIMITED } };
    const scope = this.#scopeOf(u);
    const all = resolveLimits(this.#limitRows('', 'all'), scope ? this.#limitRows(scope, 'all') : {});
    const api = restrictForApi(all, this.#limitRows('', 'api'), scope ? this.#limitRows(scope, 'api') : {});
    return { all, api };
  }
  /**
   * Server-wide caps as they apply to `u`. The owner is exempt from the global
   * settings that restrict what an account may do (the share-size cap and the
   * viewer switch and size), keeping only the protocol's hard ceilings.
   */
  #caps(u, L, s) {
    const owner = u.role === 'owner';
    return {
      // Per role now (migration 12 folded the old server-wide cap and switch in).
      maxShareBytes: owner ? HARD_MAX_SHARE_BYTES : Math.min(HARD_MAX_SHARE_BYTES, L.maxShareBytes ?? HARD_MAX_SHARE_BYTES),
      viewerEnabled: owner ? true : !!L.viewer,
      viewerMaxBytes: owner ? LIMITS.viewerMaxBytes.max : (L.viewerMaxBytes ?? LIMITS.viewerMaxBytes.max),
      grantSec: L.fileGrantSec ?? s['files.grantSec'],
      pendingSec: L.filePendingSec ?? s['files.pendingSec'],
    };
  }

  #viewerRules(u, limits) {
    const scope = u.role !== 'owner' && limits.viewerCustomRules ? this.#scopeOf(u) : '';
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
        // Recovery must get the owner in even if their passkeys are lost too.
        this.#dropPasskeys(owner.id);
        this.#log(owner.id, owner.id, 'owner.recovered', `username=${username} (passkeys removed)`);
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
      return this.#unknownLoginFailure(username, ts, s, lockoutOff, 'Wrong username or password.');
    }
    const locked = this.#lockedUntil(u, ts, lockoutOff);
    if (locked) return fail(423, 'account_locked', 'This account is temporarily locked after too many failed logins.', { until: locked });
    if (typeof verifier !== 'string' || !timingSafeEqualHex(verifier, u.pw_verifier)) {
      this.#passwordFailure(u, ts, s, lockoutOff);
      return fail(401, 'invalid_login', 'Wrong username or password.');
    }
    if (u.disabled) return fail(403, 'account_disabled', 'This account is disabled.');
    if (this.#needsSecondFactor(u)) {
      // No session yet: the browser answers this challenge with a passkey (or
      // a recovery code) — see secondFactor().
      this.#log(u.id, u.id, 'login.password_ok', 'awaiting passkey');
      return { ok: true, secondFactor: { ...this.#newChallenge('second', u.id), allow: this.#allowList(u.id), recoveryLeft: this.#recoveryLeft(u.id) } };
    }
    this.#log(u.id, u.id, 'login');
    return this.#sessionFor(u, s);
  }

  /**
   * A failed sign-in for a username that does not exist. It is counted and
   * locked exactly like a real account (under a keyed hash of the name), so
   * "423 locked" versus "401" does not reveal which usernames exist.
   */
  async #unknownLoginFailure(username, ts, s, lockoutOff, message) {
    const key = await crypto.subtle.importKey('raw', utf8(`secbin-lockout/v1:${this.#meta('secret')}`), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, utf8(String(username).toLowerCase())));
    const phantom = { id: `n:${b64urlFromBytes(mac.subarray(0, 18))}`, role: 'user' };
    const locked = this.#lockedUntil(phantom, ts, lockoutOff);
    if (locked) return fail(423, 'account_locked', 'This account is temporarily locked after too many failed logins.', { until: locked });
    this.#passwordFailure(phantom, ts, s, lockoutOff);
    return fail(401, 'invalid_login', message);
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
    if (lockedUntil && !u.id.startsWith('n:')) this.#log(null, u.id, 'account.locked', `until=${lockedUntil}`);
  }

  /** Session timeouts: the server-wide ones, or the account's role's (never for the owner). */
  #sessionSettings(s = this.#settings(), u = null) {
    let idleSec = s['session.idleSec'];
    let absSec = s['session.absSec'];
    if (u && u.role === 'user') {
      const L = this.#effective(u).all;
      absSec = L.sessionAbsSec ?? absSec;
      idleSec = Math.min(L.sessionIdleSec ?? idleSec, absSec);
    }
    return { idleSec, absSec };
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
    // Impersonating, the owner's own (server-wide) timeouts apply.
    return { user: this.#publicUser(u), actor: this.#publicUser(actor), settings: this.#sessionSettings(undefined, actor ? null : u) };
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
    const caps = this.#caps(u, eff.all, s);
    return {
      user: this.#publicUser(u),
      impersonating,
      limits: eff.all,
      apiLimits: eff.api,
      caps: {
        maxShareBytes: caps.maxShareBytes,
        grantSec: caps.grantSec,
      },
      viewer: {
        enabled: caps.viewerEnabled,
        maxBytes: caps.viewerMaxBytes,
        rules: caps.viewerEnabled ? this.#viewerRules(u, eff.all) : [],
      },
      apiKeys: { enabled: eff.all.apiEnabled, max: eff.all.apiMaxKeys ?? MAX_API_KEYS, count: keyCount },
      // For the browser to enforce on a password change (the server never sees passwords).
      passwordPolicy: Object.fromEntries(PASSWORD_POLICY_KEYS.map((k) => [k, eff.all[k]])),
      passkeys: { mode: eff.all.passkeys, count: this.#passkeyCount(u.id), required: this.#needsSecondFactor(u), recoveryLeft: this.#recoveryLeft(u.id) },
      quotas: u.role === 'owner' ? [] : this.#quotaStatus(u.id),
    };
  }

  /**
   * The quotas counted for an account: its role's own list when the role has
   * one, else the Default role's (the global list). The public account has
   * the global list plus its own.
   */
  #applicableQuotas(uid) {
    const u = this.#user(uid);
    if (!u) return [];
    if (u.role === 'public') return this.sql.exec("SELECT * FROM quotas WHERE user_id = '' OR user_id = ?", uid).toArray();
    const scope = this.#scopeOf(u);
    const own = scope && this.#role(u.role_id).own_quotas;
    return this.sql.exec('SELECT * FROM quotas WHERE user_id = ?', own ? scope : '').toArray();
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
  async changePassword(uid, { current, reauth, origin, rpId, salt, t, verifier, actorId = uid, lockoutOff = false }) {
    const u = this.#user(uid);
    if (!u) return fail(404, 'not_found', 'User not found.');
    const wrong = await this.#confirmChange(u, actorId, { current, reauth, origin, rpId }, lockoutOff);
    if (wrong) return wrong;
    const bad = this.#checkCredential(salt, t, verifier);
    if (bad) return fail(400, 'invalid_credential', bad);
    this.sql.exec('UPDATE users SET pw_salt = ?, pw_t = ?, pw_verifier = ?, sess_ver = sess_ver + 1, updated = ? WHERE id = ?', salt, t, verifier, now(), uid);
    this.#log(actorId, uid, 'password.changed');
    // Passkeys and recovery codes are not tied to the password: tell the user
    // they still work (Account asks them to review them).
    return { ok: true, ver: u.sess_ver + 1, passkeys: this.#passkeyCount(uid), recoveryLeft: this.#recoveryLeft(uid) };
  }

  /** Change one's own username (needs the password or a passkey, unless impersonated). */
  async changeUsername(uid, { username, current, reauth, origin, rpId, actorId = uid, lockoutOff = false }) {
    const u = this.#user(uid);
    if (!u || u.role === 'public') return fail(404, 'not_found', 'User not found.');
    if (typeof username !== 'string' || !USERNAME_RE.test(username)) return fail(400, 'invalid_username', 'Username must be 3–64 characters: letters, digits, . _ @ -');
    const wrong = await this.#confirmChange(u, actorId, { current, reauth, origin, rpId }, lockoutOff);
    if (wrong) return wrong;
    const clash = this.#userByName(username);
    if (clash && clash.id !== uid) return fail(409, 'username_taken', 'That username is taken.');
    if (u.username === username) return { ok: true, username };
    this.sql.exec('UPDATE users SET username = ?, updated = ? WHERE id = ?', username, now(), uid);
    this.#log(actorId, uid, 'username.changed', `from=${u.username} to=${username}`);
    return { ok: true, username };
  }

  /**
   * Step-up check of a signed-in account's current password (password change,
   * admin export/import). Wrong answers count toward the same threshold as a
   * login lockout; reaching it ends every session of the account.
   */
  async verifyCurrent(uid, current, { lockoutOff = false, reauth, origin, rpId } = {}) {
    const u = this.#user(uid);
    if (!u) return fail(404, 'not_found', 'User not found.');
    return (await this.#stepUp(u, { current, reauth, origin, rpId }, lockoutOff)) ?? { ok: true };
  }

  /**
   * "Confirm it's you" for a change to one's own account: the current
   * password (`current`, a verifier) or a fresh passkey assertion (`reauth`:
   * {challengeId, credential} for a "reauth" challenge of this account).
   * Returns null when confirmed, else the failure to return.
   */
  async #stepUp(u, { current, reauth, origin, rpId } = {}, lockoutOff = false) {
    if (current === undefined && reauth && typeof reauth === 'object') {
      const c = this.#takeChallenge(reauth.challengeId, 'reauth');
      let ok = false;
      if (c && c.user_id === u.id && this.#passkeyMode(u) !== 'off') {
        const id = assertionId(reauth.credential);
        const p = id && this.sql.exec('SELECT * FROM passkeys WHERE id = ? AND user_id = ?', id, u.id).toArray()[0];
        ok = !!p && (await this.#checkAssertion(p, reauth.credential, c.challenge, origin, rpId)).ok;
      }
      if (ok) {
        this.sql.exec('DELETE FROM pwchange_failures WHERE user_id = ?', u.id);
        return null;
      }
      return this.#stepUpFailure(u, lockoutOff, 'reauth_failed', 'The passkey could not be verified.');
    }
    return this.#checkCurrent(u, current, lockoutOff);
  }

  #checkCurrent(u, current, lockoutOff) {
    if (typeof current !== 'string' || !timingSafeEqualHex(current, u.pw_verifier)) {
      return this.#stepUpFailure(u, lockoutOff, 'wrong_password', 'The current password is incorrect.');
    }
    this.sql.exec('DELETE FROM pwchange_failures WHERE user_id = ?', u.id);
    return null;
  }

  /** A failed step-up: after lockout.max within the window, every session of the account ends. */
  #stepUpFailure(u, lockoutOff, code, message) {
    const ts = now();
    if (!lockoutOff) {
      const st = this.#settings();
      const f = this.sql.exec('SELECT * FROM pwchange_failures WHERE user_id = ?', u.id).toArray()[0];
      const fresh = !f || ts - f.start > st['lockout.windowSec'];
      const count = fresh ? 1 : f.count + 1;
      if (count >= st['lockout.max']) {
        this.sql.exec('DELETE FROM pwchange_failures WHERE user_id = ?', u.id);
        this.sql.exec('UPDATE users SET sess_ver = sess_ver + 1, updated = ? WHERE id = ?', ts, u.id);
        this.#log(null, u.id, 'sessions.revoked', 'too many failed confirmations');
        return fail(401, 'session_revoked', 'Too many failed confirmations: you have been signed out everywhere. Log in again.');
      }
      this.sql.exec('INSERT INTO pwchange_failures (user_id, count, start) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET count = excluded.count, start = excluded.start',
        u.id, count, fresh ? ts : f.start);
    }
    return fail(403, code, message);
  }

  /**
   * The confirmation for a change to `u`'s own account, made by `actor`: the
   * user themselves (a user id: the password or a passkey, see #stepUp) or
   * the owner impersonating them ({ id, imp: true }). The owner acting on
   * another account needs no confirmation (the owner's session is the
   * authority), but must still be the enabled owner and not `u`.
   * Returns null when confirmed, else the failure to return.
   */
  async #confirmChange(u, actor, step, lockoutOff) {
    if (actor && typeof actor === 'object') {
      const o = actor.imp ? this.#user(actor.id) : null;
      return o && o.role === 'owner' && !o.disabled && o.id !== u.id ? null : fail(403, 'forbidden', 'Not allowed.');
    }
    return this.#stepUp(u, step, lockoutOff);
  }

  /** A challenge to confirm a change to one's own account with a passkey. */
  async reauthOptions(uid) {
    const u = this.#user(uid);
    if (!u || u.role === 'public') return fail(404, 'not_found', 'User not found.');
    if (this.#passkeyMode(u) === 'off' || !this.#passkeyCount(uid)) return fail(409, 'no_passkeys', 'This account has no passkey to confirm with: use the password.');
    return { ok: true, ...this.#newChallenge('reauth', uid), allow: this.#allowList(uid) };
  }

  async activity(uid, { before = null, limit = 50 } = {}) {
    const lim = Math.max(1, Math.min(200, limit | 0));
    // Impersonation is invisible to the user: their own view never names the
    // actor, so actions the owner took while impersonating appear as the
    // user's own, and the start and end of an impersonation are not shown
    // (the owner-only admin audit keeps the start, the end and the real
    // actor). Direct admin-panel actions on the user's shares (adm) are not
    // shown either.
    const where = "subject_id = ? AND adm = 0 AND action NOT IN ('impersonate.start', 'impersonate.end')";
    const rows = before
      ? this.sql.exec(`SELECT id, ts, action, detail FROM activity WHERE ${where} AND id < ? ORDER BY id DESC LIMIT ?`, uid, before, lim).toArray()
      : this.sql.exec(`SELECT id, ts, action, detail FROM activity WHERE ${where} ORDER BY id DESC LIMIT ?`, uid, lim).toArray();
    return rows;
  }

  // ── API keys ─────────────────────────────────────────────────────────────
  async listKeys(uid) {
    return this.sql.exec('SELECT id, name, created, last_used, expires, scopes FROM api_keys WHERE user_id = ? ORDER BY created DESC', uid).toArray()
      .map((k) => ({ ...k, scopes: String(k.scopes || '').split(',').filter((x) => API_SCOPES.includes(x)) }));
  }

  /**
   * Create an API key. On one's own account (`actorId` = `uid`) it needs the
   * password or a passkey; the owner creates keys for other users freely,
   * from the admin panel (`actorId` = the owner's id) or while impersonating
   * them (`actorId` = { id, imp: true }).
   */
  async createKey(uid, { name, hash, expires, scopes, actorId = uid, current, reauth, origin, rpId, lockoutOff = false }) {
    const u = this.#user(uid);
    if (!u) return fail(404, 'not_found', 'User not found.');
    if (u.role === 'public') return fail(403, 'api_disabled', 'The public account never has API keys.');
    if (actorId === uid || typeof actorId === 'object') {
      const wrong = await this.#confirmChange(u, actorId, { current, reauth, origin, rpId }, lockoutOff);
      if (wrong) return wrong;
    }
    const eff = this.#effective(u).all;
    if (!eff.apiEnabled) return fail(403, 'api_disabled', 'API keys are not enabled for this account.');
    const count = this.sql.exec('SELECT COUNT(*) AS c FROM api_keys WHERE user_id = ?', uid).one().c;
    const maxKeys = eff.apiMaxKeys ?? MAX_API_KEYS;
    if (count >= maxKeys) return fail(409, 'too_many_keys', `This account may hold at most ${maxKeys} API keys.`);
    const label = cleanLabel(name);
    if (label === null || label === '') return fail(400, 'invalid_name', 'Give the key a name (up to 100 characters).');
    if (typeof hash !== 'string' || !HEX64_RE.test(hash)) return fail(400, 'invalid_key', 'invalid key');
    if (expires !== null && expires !== undefined && (!Number.isSafeInteger(expires) || expires <= now())) return fail(400, 'invalid_expiry', 'Expiry must be in the future.');
    let sc = DEFAULT_KEY_SCOPES;
    if (scopes !== undefined) {
      sc = keyScopes(scopes);
      if (!sc) return fail(400, 'invalid_scopes', `Choose one or more scopes: ${API_SCOPES.join(', ')}.`);
    }
    const id = newId();
    this.sql.exec('INSERT INTO api_keys (key_hash, id, user_id, name, created, expires, scopes) VALUES (?, ?, ?, ?, ?, ?, ?)', hash, id, uid, label, now(), expires ?? null, sc.join(','));
    this.#log(actorId, uid, 'apikey.created', `name=${label} scopes=${sc.join(',')}`);
    return { ok: true, id };
  }

  /** Rename a key or change its scopes (same confirmation rule as createKey). */
  async updateKey(uid, id, { name, scopes, actorId = uid, current, reauth, origin, rpId, lockoutOff = false }) {
    const u = this.#user(uid);
    if (!u) return fail(404, 'not_found', 'User not found.');
    const k = this.sql.exec('SELECT name, scopes FROM api_keys WHERE user_id = ? AND id = ?', uid, String(id)).toArray()[0];
    if (!k) return fail(404, 'not_found', 'Key not found.');
    const label = name === undefined ? k.name : cleanLabel(name);
    if (label === null || label === '') return fail(400, 'invalid_name', 'Give the key a name (up to 100 characters).');
    const sc = scopes === undefined ? String(k.scopes || '').split(',').filter((x) => API_SCOPES.includes(x)) : keyScopes(scopes);
    if (!sc) return fail(400, 'invalid_scopes', `Choose one or more scopes: ${API_SCOPES.join(', ')}.`);
    if (actorId === uid || typeof actorId === 'object') {
      const wrong = await this.#confirmChange(u, actorId, { current, reauth, origin, rpId }, lockoutOff);
      if (wrong) return wrong;
    }
    this.sql.exec('UPDATE api_keys SET name = ?, scopes = ? WHERE user_id = ? AND id = ?', label, sc.join(','), uid, String(id));
    this.#log(actorId, uid, 'apikey.updated', `name=${label} scopes=${sc.join(',')}`);
    return { ok: true };
  }

  async revokeKey(uid, id, actorId = uid, { current, reauth, origin, rpId, lockoutOff = false } = {}) {
    const r = this.sql.exec('SELECT name FROM api_keys WHERE user_id = ? AND id = ?', uid, id).toArray()[0];
    if (!r) return fail(404, 'not_found', 'Key not found.');
    if (actorId === uid || typeof actorId === 'object') {
      const wrong = await this.#confirmChange(this.#user(uid), actorId, { current, reauth, origin, rpId }, lockoutOff);
      if (wrong) return wrong;
    }
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
    return { user: this.#publicUser(u), keyId: k.id, scopes: String(k.scopes || '').split(',').filter((x) => API_SCOPES.includes(x)) };
  }

  // ── passkeys (WebAuthn) and recovery codes ───────────────────────────────
  // The Worker passes the request's origin and RP ID (its hostname); this
  // object holds the one-time challenges and does every check (see
  // src/lib/webauthn.js). Awaits happen only between self-contained steps:
  // a challenge is taken (deleted or counted) before verification, and the
  // writes after it re-check what they depend on.

  #passkeyMode(u) { return this.#effective(u).all.passkeys; }
  #passkeyMax(u) { return Math.min(MAX_PASSKEYS, this.#effective(u).all.passkeysMax ?? MAX_PASSKEYS); }
  #passkeyCount(uid) { return this.sql.exec('SELECT COUNT(*) AS c FROM passkeys WHERE user_id = ?', uid).one().c; }
  #recoveryLeft(uid) { return this.sql.exec('SELECT COUNT(*) AS c FROM recovery_codes WHERE user_id = ?', uid).one().c; }
  /** Does a password login of `u` also need a passkey (or recovery code)? */
  #needsSecondFactor(u) {
    const mode = this.#passkeyMode(u);
    if (mode === 'off' || !this.#passkeyCount(u.id)) return false;
    return mode === 'second' || !!u.mfa;
  }
  #webauthnHandle(u) {
    if (u.webauthn_handle) return u.webauthn_handle;
    const h = b64urlFromBytes(randomBytes(16));
    this.sql.exec('UPDATE users SET webauthn_handle = ? WHERE id = ?', h, u.id);
    return h;
  }
  /**
   * A stored challenge for an account: "register" (signed in) or "second"
   * (right password). Only those callers can create one, and each account
   * keeps at most MAX_CHALLENGES_PER_USER per purpose, so nobody can flood the
   * table or push out someone else's pending sign-in. Usernameless "login"
   * challenges are never stored (see #loginChallenge).
   */
  #newChallenge(purpose, uid) {
    const ts = now();
    this.sql.exec('DELETE FROM webauthn_challenges WHERE exp <= ?', ts);
    this.sql.exec(`DELETE FROM webauthn_challenges WHERE id IN (SELECT id FROM webauthn_challenges WHERE user_id = ? AND purpose = ?
      ORDER BY exp DESC, rowid DESC LIMIT -1 OFFSET ?)`, uid, purpose, MAX_CHALLENGES_PER_USER - 1);
    // A backstop only: reaching it needs thousands of accounts mid-sign-in.
    if (this.sql.exec('SELECT COUNT(*) AS c FROM webauthn_challenges').one().c >= MAX_CHALLENGES) {
      this.sql.exec('DELETE FROM webauthn_challenges WHERE id IN (SELECT id FROM webauthn_challenges ORDER BY exp, rowid LIMIT ?)', MAX_CHALLENGES / 10);
    }
    const id = newId();
    const challenge = b64urlFromBytes(randomBytes(32));
    this.sql.exec('INSERT INTO webauthn_challenges (id, user_id, purpose, challenge, exp) VALUES (?, ?, ?, ?, ?)', id, uid, purpose, challenge, ts + CHALLENGE_SEC);
    return { challengeId: id, challenge, timeoutMs: CHALLENGE_SEC * 1000 };
  }
  async #loginKey() {
    if (!this.loginKey) {
      this.loginKey = await crypto.subtle.importKey('raw', utf8(`secbin-webauthn-login/v1:${this.#meta('secret')}`), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    }
    return this.loginKey;
  }
  /**
   * A usernameless sign-in challenge that is not stored: 16 random bytes, the
   * expiry and an HMAC tag, all in the challenge itself (it is also its id).
   * Anyone may ask for one, so asking writes nothing; the challenge is marked
   * spent only when it is used with a registered passkey.
   */
  async #loginChallenge() {
    const body = new Uint8Array(20);
    body.set(randomBytes(16));
    new DataView(body.buffer).setUint32(16, now() + CHALLENGE_SEC);
    const tag = new Uint8Array(await crypto.subtle.sign('HMAC', await this.#loginKey(), body)).subarray(0, 16);
    const out = new Uint8Array(36);
    out.set(body);
    out.set(tag, 20);
    const challenge = b64urlFromBytes(out);
    return { challengeId: challenge, challenge, timeoutMs: CHALLENGE_SEC * 1000 };
  }
  /** → its expiry when `token` is a genuine, unexpired login challenge, else 0. */
  async #checkLoginChallenge(token) {
    if (typeof token !== 'string' || token.length !== 48) return 0;
    let b;
    try { b = bytesFromB64url(token); } catch { return 0; }
    if (b.length !== 36) return 0;
    const tag = new Uint8Array(await crypto.subtle.sign('HMAC', await this.#loginKey(), b.subarray(0, 20))).subarray(0, 16);
    let diff = 0;
    for (let i = 0; i < 16; i++) diff |= tag[i] ^ b[20 + i];
    const exp = new DataView(b.buffer, b.byteOffset).getUint32(16);
    return diff === 0 && exp > now() ? exp : 0;
  }
  /** One-time use: the challenge is deleted as it is read. */
  #takeChallenge(id, purpose) {
    if (typeof id !== 'string' || id.length > 40) return null;
    const c = this.sql.exec('DELETE FROM webauthn_challenges WHERE id = ? AND purpose = ? RETURNING *', id, purpose).toArray()[0];
    return c && c.exp > now() ? c : null;
  }
  #allowList(uid) {
    return this.sql.exec('SELECT id, transports FROM passkeys WHERE user_id = ? ORDER BY created', uid).toArray()
      .map((p) => ({ id: p.id, transports: p.transports ? p.transports.split(',') : [] }));
  }
  #sessionFor(u, s = this.#settings()) {
    this.sql.exec('DELETE FROM failures WHERE user_id = ?', u.id);
    return { ok: true, user: { id: u.id, username: u.username, role: u.role, ver: u.sess_ver }, settings: this.#sessionSettings(s, u) };
  }
  async #codeHash(code) {
    const norm = normalizeRecoveryCode(code);
    return norm ? sha256Hex(utf8(`secbin-recovery/v1:${norm}`)) : null;
  }
  /** A new set of codes and their hashes (hashing awaits, so do it before any decision). */
  async #prepareCodes() {
    const codes = [];
    const hashes = [];
    for (let i = 0; i < RECOVERY_CODES; i++) {
      const c = newRecoveryCode();
      codes.push(c);
      hashes.push(await this.#codeHash(c));
    }
    return { codes, hashes };
  }
  /** Replace an account's codes with a prepared set (synchronous). */
  #storeCodes(uid, { hashes }) {
    const ts = now();
    this.ctx.storage.transactionSync(() => {
      this.sql.exec('DELETE FROM recovery_codes WHERE user_id = ?', uid);
      for (const h of hashes) this.sql.exec('INSERT INTO recovery_codes (hash, user_id, created) VALUES (?, ?, ?)', h, uid, ts);
    });
  }
  /** The WebAuthn user handle a passkey was registered under (its own, if imported with another). */
  #passkeyHandle(p, u) { return this.#meta(handleAlias(p.id)) ?? u.webauthn_handle ?? null; }
  #dropPasskeys(uid) {
    this.sql.exec('DELETE FROM meta WHERE k IN (SELECT ? || id FROM passkeys WHERE user_id = ?)', handleAlias(''), uid);
    this.sql.exec('DELETE FROM passkeys WHERE user_id = ?', uid);
    this.sql.exec('DELETE FROM recovery_codes WHERE user_id = ?', uid);
    this.sql.exec('UPDATE users SET mfa = 0 WHERE id = ?', uid);
  }

  /** The signed-in user's passkeys, mode and recovery-code count. */
  async passkeyStatus(uid) {
    const u = this.#user(uid);
    if (!u) return fail(404, 'not_found', 'User not found.');
    const mode = this.#passkeyMode(u);
    return {
      ok: true,
      mode,
      mfa: mode === 'second' || !!u.mfa,
      required: this.#needsSecondFactor(u),
      max: this.#passkeyMax(u),
      recoveryLeft: this.#recoveryLeft(uid),
      passkeys: this.sql.exec('SELECT id, name, created, last_used, backed_up FROM passkeys WHERE user_id = ? ORDER BY created', uid).toArray()
        .map((p) => ({ id: p.id, name: p.name, created: p.created, lastUsed: p.last_used, synced: !!p.backed_up })),
    };
  }

  /** Start registering a passkey (the current password is checked on completion). */
  async passkeyRegisterOptions(uid) {
    const u = this.#user(uid);
    if (!u || u.role === 'public') return fail(404, 'not_found', 'User not found.');
    if (this.#passkeyMode(u) === 'off') return fail(403, 'passkeys_disabled', 'Passkeys are not enabled for your account.');
    const max = this.#passkeyMax(u);
    if (this.#passkeyCount(uid) >= max) return fail(409, 'too_many_passkeys', `This account can have up to ${max} passkeys. Remove one first.`);
    return { ok: true, ...this.#newChallenge('register', uid), user: { handle: this.#webauthnHandle(u), name: u.username }, exclude: this.#allowList(uid) };
  }

  async addPasskey(uid, { challengeId, credential, name, current, reauth, origin, rpId, actorId = uid, lockoutOff = false }) {
    const u = this.#user(uid);
    if (!u) return fail(404, 'not_found', 'User not found.');
    const c = this.#takeChallenge(challengeId, 'register');
    if (!c || c.user_id !== uid) return fail(400, 'challenge_expired', 'That passkey request expired. Try again.');
    if (this.#passkeyMode(u) === 'off') return fail(403, 'passkeys_disabled', 'Passkeys are not enabled for your account.');
    const label = cleanLabel(name);
    if (label === null || label === '') return fail(400, 'invalid_name', 'Give the passkey a name (up to 100 characters).');
    const wrong = await this.#confirmChange(u, actorId, { current, reauth, origin, rpId }, lockoutOff);
    if (wrong) return wrong;
    const r = await verifyRegistration(credential, { challenge: c.challenge, origin, rpId });
    if (!r.ok) return fail(400, 'invalid_passkey', `The passkey could not be verified (${r.reason}).`);
    // Every await is behind us from here: the checks, the insert and the
    // decision to issue codes happen in one uninterrupted step.
    const prepared = await this.#prepareCodes();
    if (this.sql.exec('SELECT 1 FROM passkeys WHERE id = ?', r.credentialId).toArray().length) {
      return fail(409, 'passkey_exists', 'That passkey is already registered.');
    }
    if (this.#passkeyCount(uid) >= this.#passkeyMax(u)) return fail(409, 'too_many_passkeys', `This account can have up to ${this.#passkeyMax(u)} passkeys.`);
    const first = this.#passkeyCount(uid) === 0;
    this.sql.exec('DELETE FROM meta WHERE k = ?', handleAlias(r.credentialId)); // registered here: the account's own handle
    this.sql.exec('INSERT INTO passkeys (id, user_id, name, public_key, alg, sign_count, transports, backup_eligible, backed_up, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      r.credentialId, uid, label, r.publicKey, r.alg, r.signCount, r.transports.join(','), r.backupEligible ? 1 : 0, r.backedUp ? 1 : 0, now());
    this.#log(actorId, uid, 'passkey.added', `name=${label}`);
    // The first passkey comes with a fresh set of recovery codes, shown once.
    let codes = null;
    if (first || this.#recoveryLeft(uid) === 0) {
      this.#storeCodes(uid, prepared);
      codes = prepared.codes;
      this.#log(actorId, uid, 'recovery.issued', `count=${codes.length}`);
    }
    return { ok: true, id: r.credentialId, codes };
  }

  async removePasskey(uid, id, { current, reauth, origin, rpId, actorId = uid, lockoutOff = false }) {
    const u = this.#user(uid);
    if (!u) return fail(404, 'not_found', 'User not found.');
    const wrong = await this.#confirmChange(u, actorId, { current, reauth, origin, rpId }, lockoutOff);
    if (wrong) return wrong;
    const p = this.sql.exec('SELECT name FROM passkeys WHERE id = ? AND user_id = ?', String(id), uid).toArray()[0];
    if (!p) return fail(404, 'not_found', 'Passkey not found.');
    this.sql.exec('DELETE FROM passkeys WHERE id = ? AND user_id = ?', String(id), uid);
    this.sql.exec('DELETE FROM meta WHERE k = ?', handleAlias(String(id)));
    this.#log(actorId, uid, 'passkey.removed', `name=${p.name}`);
    // Without passkeys, recovery codes and the second-factor choice mean nothing.
    if (!this.#passkeyCount(uid)) {
      this.#dropPasskeys(uid);
      this.#log(actorId, uid, 'recovery.revoked', 'last passkey removed');
    }
    return { ok: true };
  }

  async regenerateRecoveryCodes(uid, { current, reauth, origin, rpId, actorId = uid, lockoutOff = false }) {
    const prepared = await this.#prepareCodes();
    const u = this.#user(uid);
    if (!u) return fail(404, 'not_found', 'User not found.');
    const wrong = await this.#confirmChange(u, actorId, { current, reauth, origin, rpId }, lockoutOff);
    // No await after the step-up: the checks and the store run in one step.
    if (wrong) return wrong;
    if (!this.#passkeyCount(uid)) return fail(409, 'no_passkeys', 'Add a passkey first: recovery codes stand in for a passkey.');
    this.#storeCodes(uid, prepared);
    this.#log(actorId, uid, 'recovery.issued', `count=${prepared.codes.length} (old codes revoked)`);
    return { ok: true, codes: prepared.codes };
  }

  /** The user's choice (mode "any"): should a password login also need a passkey? */
  async setSecondFactor(uid, { on, current, reauth, origin, rpId, actorId = uid, lockoutOff = false }) {
    const u = this.#user(uid);
    if (!u) return fail(404, 'not_found', 'User not found.');
    if (typeof on !== 'boolean') return fail(400, 'invalid', 'on must be true or false');
    const mode = this.#passkeyMode(u);
    if (mode === 'off') return fail(403, 'passkeys_disabled', 'Passkeys are not enabled for your account.');
    if (mode === 'second' && !on) return fail(403, 'second_factor_required', 'The administrator requires a passkey after the password.');
    const wrong = await this.#confirmChange(u, actorId, { current, reauth, origin, rpId }, lockoutOff);
    if (wrong) return wrong;
    if (on && !this.#passkeyCount(uid)) return fail(409, 'no_passkeys', 'Add a passkey first.');
    this.sql.exec('UPDATE users SET mfa = ? WHERE id = ?', on ? 1 : 0, uid);
    this.#log(actorId, uid, on ? 'mfa.enabled' : 'mfa.disabled');
    return { ok: true };
  }

  /** Usernameless sign-in: a challenge any of the site's passkeys can answer. */
  async passkeyLoginOptions() {
    return { ok: true, ...(await this.#loginChallenge()) };
  }

  async #checkAssertion(p, credential, challenge, origin, rpId) {
    const r = await verifyAssertion(credential, { challenge, origin, rpId, publicKey: p.public_key, signCount: p.sign_count });
    if (!r.ok) return r;
    // Written only if no concurrent assertion moved the counter past this one;
    // when counters are in use, a counter that did not move forward may mean
    // two devices hold the same key (the server cannot know for sure).
    const moved = this.sql.exec('UPDATE passkeys SET sign_count = ?, backed_up = ?, last_used = ? WHERE id = ? AND (sign_count < ? OR ? = 0) RETURNING id',
      r.signCount, r.backedUp ? 1 : 0, now(), p.id, r.signCount, r.signCount).toArray().length;
    if (!moved) return { ok: false, reason: 'signature counter did not move forward' };
    return r;
  }

  /** Sign in with a passkey alone (mode "any" only). */
  async passkeyLogin({ challengeId, credential, origin, rpId }) {
    const exp = await this.#checkLoginChallenge(challengeId);
    if (!exp) return fail(400, 'challenge_expired', 'That sign-in request expired. Try again.');
    const id = assertionId(credential);
    const p = id && this.sql.exec('SELECT * FROM passkeys WHERE id = ?', id).toArray()[0];
    const u = p && this.#user(p.user_id);
    if (!u || (u.role !== 'owner' && u.role !== 'user')) return fail(401, 'invalid_passkey', 'The passkey could not be verified.');
    // Spend the challenge before verifying (single use, even if this attempt fails).
    const ts = now();
    this.sql.exec('DELETE FROM webauthn_spent WHERE exp <= ?', ts);
    const fresh = this.sql.exec('INSERT INTO webauthn_spent (challenge, exp) VALUES (?, ?) ON CONFLICT DO NOTHING RETURNING challenge', challengeId, exp).toArray().length;
    if (!fresh) return fail(400, 'challenge_expired', 'That sign-in request was already used. Try again.');
    const r = await this.#checkAssertion(p, credential, challengeId, origin, rpId);
    if (!r.ok) return fail(401, 'invalid_passkey', 'The passkey could not be verified.');
    const handle = this.#passkeyHandle(p, u);
    if (r.userHandle && handle && r.userHandle !== handle) return fail(401, 'invalid_passkey', 'The passkey could not be verified.');
    const mode = this.#passkeyMode(u);
    if (mode === 'off') return fail(403, 'passkeys_disabled', 'Passkeys are not enabled for this account.');
    if (mode === 'second') return fail(403, 'password_first', 'This account signs in with its password first, then the passkey.');
    if (u.disabled) return fail(403, 'account_disabled', 'This account is disabled.');
    this.#log(u.id, u.id, 'login', `passkey=${p.name}`);
    return this.#sessionFor(u);
  }

  /** Sign in with a recovery code alone (in every passkey mode). */
  async recoveryLogin({ username, code, lockoutOff = false }) {
    const u = this.#loginUser(username);
    const ts = now();
    const s = this.#settings();
    const hash = await this.#codeHash(code);
    if (!u) return this.#unknownLoginFailure(username, ts, s, lockoutOff, 'Wrong username or recovery code.');
    const locked = this.#lockedUntil(u, ts, lockoutOff);
    if (locked) return fail(423, 'account_locked', 'This account is temporarily locked after too many failed logins.', { until: locked });
    // A recovery code is the way back in when everything else is lost: it
    // signs in on its own whatever the passkey mode or the user's "passkey
    // after password" choice. Only the guards against guessing still apply
    // (Turnstile, per-IP blocking, the account lockout), and a disabled
    // account stays disabled.
    const valid = hash && this.sql.exec('SELECT 1 FROM recovery_codes WHERE user_id = ? AND hash = ?', u.id, hash).toArray().length;
    if (!valid) {
      this.#passwordFailure(u, ts, s, lockoutOff);
      return fail(401, 'invalid_login', 'Wrong username or recovery code.');
    }
    if (u.disabled) return fail(403, 'account_disabled', 'This account is disabled.');
    this.sql.exec('DELETE FROM recovery_codes WHERE user_id = ? AND hash = ?', u.id, hash);
    this.#log(u.id, u.id, 'login', `recovery code (${this.#recoveryLeft(u.id)} left)`);
    return { ...this.#sessionFor(u, s), recoveryLeft: this.#recoveryLeft(u.id) };
  }

  /**
   * The second step of a password login: a passkey assertion or a recovery
   * code for the challenge issued by login(). A few tries per challenge; each
   * failure counts toward the account lockout.
   */
  async secondFactor({ challengeId, credential, code, origin, rpId, lockoutOff = false }) {
    const ts = now();
    const c = typeof challengeId === 'string' && challengeId.length <= 40
      && this.sql.exec("SELECT * FROM webauthn_challenges WHERE id = ? AND purpose = 'second'", challengeId).toArray()[0];
    if (!c || c.exp <= ts) return fail(400, 'challenge_expired', 'The sign-in expired. Enter your password again.');
    const u = this.#user(c.user_id);
    if (!u) return fail(400, 'challenge_expired', 'The sign-in expired. Enter your password again.');
    const locked = this.#lockedUntil(u, ts, lockoutOff);
    if (locked) return fail(423, 'account_locked', 'This account is temporarily locked after too many failed logins.', { until: locked });
    this.sql.exec('UPDATE webauthn_challenges SET tries = tries + 1 WHERE id = ?', c.id);
    if (c.tries + 1 > SECOND_FACTOR_TRIES) {
      this.sql.exec('DELETE FROM webauthn_challenges WHERE id = ?', c.id);
      return fail(400, 'challenge_expired', 'Too many tries. Enter your password again.');
    }
    const s = this.#settings();
    let how = null;
    if (typeof code === 'string' && code) {
      const hash = await this.#codeHash(code);
      if (hash && this.sql.exec('DELETE FROM recovery_codes WHERE user_id = ? AND hash = ? RETURNING hash', u.id, hash).toArray().length) {
        how = `recovery code (${this.#recoveryLeft(u.id)} left)`;
      }
    } else {
      const id = assertionId(credential);
      const p = id && this.sql.exec('SELECT * FROM passkeys WHERE id = ? AND user_id = ?', id, u.id).toArray()[0];
      if (p && (await this.#checkAssertion(p, credential, c.challenge, origin, rpId)).ok) how = `passkey=${p.name}`;
    }
    if (!how) {
      this.#passwordFailure(u, ts, s, lockoutOff);
      return fail(401, 'invalid_second_factor', typeof code === 'string' && code ? 'That recovery code is not valid (each works once).' : 'The passkey could not be verified.');
    }
    // Spend the challenge; a concurrent success already did → refuse this one.
    if (!this.sql.exec('DELETE FROM webauthn_challenges WHERE id = ? RETURNING id', c.id).toArray().length) {
      return fail(400, 'challenge_expired', 'The sign-in expired. Enter your password again.');
    }
    if (u.disabled) return fail(403, 'account_disabled', 'This account is disabled.');
    this.#log(u.id, u.id, 'login', `password + ${how}`);
    // recoveryLeft only when a code was spent (the browser then points to Account).
    return typeof code === 'string' && code ? { ...this.#sessionFor(u, s), recoveryLeft: this.#recoveryLeft(u.id) } : this.#sessionFor(u, s);
  }

  /**
   * Admin: remove every passkey (and recovery code) of an account. The owner
   * does this for another user as freely as setting their password; on the
   * owner's own account it needs the same confirmation as on Account.
   */
  async adminResetPasskeys(id, actorId, { current, reauth, origin, rpId, lockoutOff = false } = {}) {
    const u = this.#user(id);
    if (!u || u.role === 'public') return fail(404, 'not_found', 'User not found.');
    if (id === actorId) {
      const wrong = await this.#stepUp(u, { current, reauth, origin, rpId }, lockoutOff);
      if (wrong) return wrong;
    }
    const n = this.#passkeyCount(id);
    this.#dropPasskeys(id);
    this.#log(actorId, id, 'passkeys.reset_by_admin', `removed=${n}`);
    return { ok: true, removed: n };
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
      const cap = this.#caps(u, L, s).maxShareBytes;
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
    if (u.role === 'owner') return { ok: true, refund: [], pendingSec: s['files.pendingSec'] };

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
    return { ok: true, refund: hits, pendingSec: this.#caps(u, eff.all, s).pendingSec };
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
      caps: { maxShareBytes: this.#caps(u, L, s).maxShareBytes, grantSec: this.#caps(u, L, s).grantSec },
      viewer: { enabled: !!L.viewer, maxBytes: this.#caps(u, L, s).viewerMaxBytes, rules: L.viewer ? this.#viewerRules(u, L) : [] },
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

  /**
   * What a sender's client must check before creating (for the CLI, which has
   * only an API key): the URL rules for link shares. Only the account's own
   * effective values, for the channel it uses.
   */
  async sharePolicy(uid, channel = 'all') {
    const u = this.#user(uid);
    if (!u || u.disabled) return fail(403, 'forbidden', 'Account unavailable.');
    const eff = this.#effective(u);
    const L = channel === 'api' ? eff.api : eff.all;
    return { ok: true, url: L.url, urlRules: L.urlRules };
  }

  /**
   * Limits check for raising views/expiry on an existing share (no quota use),
   * for the channel the change comes through (an API key gets the API limits).
   */
  async authorizeIncrease(uid, { views, expireAt }, channel = 'all') {
    const u = this.#user(uid);
    if (!u || u.disabled) return fail(403, 'forbidden', 'Account unavailable.');
    const eff = this.#effective(u);
    const L = channel === 'api' ? eff.api : eff.all;
    const via = channel === 'api' ? ' via the API' : '';
    if (views !== undefined) {
      if (views === null && !L.allowUnlimitedViews) return fail(403, 'unlimited_views_disabled', `Unlimited views are not allowed for this account${via}.`);
      if (views !== null && L.maxViews !== null && views > L.maxViews) return fail(403, 'too_many_views', `At most ${L.maxViews} views are allowed${via}.`, { max: L.maxViews });
    }
    if (expireAt !== undefined && L.maxExpireSec !== null && expireAt > now() + L.maxExpireSec) {
      return fail(403, 'expiry_too_long', `Expiry may be at most ${L.maxExpireSec} seconds from now${via}.`, { max: L.maxExpireSec });
    }
    return { ok: true };
  }

  // ── shares index ("My shares") ───────────────────────────────────────────
  async recordShare({ id, uid, kind, label, created, expires, views, lh = null }, actorId = uid) {
    const l = cleanLabel(label) ?? '';
    // Upsert that never touches the lock columns: re-recording an id must not
    // silently unlock it.
    this.sql.exec(`INSERT INTO shares (id, user_id, kind, label, created, expires, views_total, status, lh) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?)
      ON CONFLICT(id) DO UPDATE SET user_id = excluded.user_id, kind = excluded.kind, label = excluded.label, created = excluded.created,
        expires = excluded.expires, views_total = excluded.views_total, status = 'active', lh = excluded.lh`,
      id, uid, kind, l, created, expires, views ?? null, typeof lh === 'string' && lh.length <= 64 ? lh : null);
    this.#log(actorId, uid, `share.created`, `id=${id} kind=${kind}`);
  }

  async listShares(uid, { q = '', status = '', limit = 50, offset = 0 } = {}) {
    const lim = Math.max(1, Math.min(100, limit | 0));
    const off = Math.max(0, offset | 0);
    const like = `%${String(q).replace(/[%_\\]/g, (c) => '\\' + c)}%`;
    const where = `WHERE user_id = ? AND label LIKE ? ESCAPE '\\' ${status ? 'AND status = ?' : ''}`;
    const args = status ? [uid, like, String(status)] : [uid, like];
    const rows = this.sql.exec(
      `SELECT id, kind, label, created, expires, views_total, status, locked,
        MAX(shares.opens_total, (SELECT COUNT(*) FROM opens o WHERE o.share_id = shares.id)) AS opens FROM shares ${where} ORDER BY created DESC LIMIT ? OFFSET ?`,
      ...args, lim, off).toArray();
    // The total counts what the filters match, so pagination is correct.
    const total = this.sql.exec(`SELECT COUNT(*) AS c FROM shares ${where}`, ...args).one().c;
    return { rows, total };
  }

  async getShare(uid, id) {
    return this.sql.exec(`SELECT id, user_id, kind, label, created, expires, views_total, status, locked,
      MAX(shares.opens_total, (SELECT COUNT(*) FROM opens o WHERE o.share_id = shares.id)) AS opens FROM shares WHERE user_id = ? AND id = ?`, uid, id).toArray()[0] || null;
  }

  /** Any user's share, for the admin (no owner scoping). */
  async adminShare(id) {
    return this.sql.exec(`SELECT s.id, s.user_id, u.username, s.kind, s.label, s.created, s.expires, s.views_total, s.status,
      s.locked, s.locked_at, lu.username AS locked_by
      FROM shares s LEFT JOIN users u ON u.id = s.user_id LEFT JOIN users lu ON lu.id = s.locked_by WHERE s.id = ?`, id).toArray()[0] || null;
  }

  // ── read receipts ────────────────────────────────────────────────────────
  /**
   * Record one open of a share (only shares in the index — account shares).
   * `info` holds what the request revealed about the opener; it is kept as
   * long as the activity log (log.* settings / per-user limits) and at most
   * MAX_OPENS_PER_SHARE per share (the oldest go first).
   */
  async recordOpen(shareId, info = {}) {
    const r = this.sql.exec('SELECT user_id FROM shares WHERE id = ?', shareId).toArray()[0];
    if (!r) return;
    const ts = now();
    // eslint-disable-next-line no-control-regex
    const t = (v, n) => String(v ?? '').replace(/[\u0000-\u001f\u007f]/g, '').slice(0, n);
    const ip = t(info.ip, 64);
    this.sql.exec('UPDATE shares SET opens_total = opens_total + 1 WHERE id = ?', shareId);
    // Throttle (see OPENS_*): the same address again within the window, or a
    // burst beyond the per-minute cap, is counted but not stored again.
    if (this.sql.exec('SELECT 1 FROM opens WHERE share_id = ? AND ip = ? AND ts > ? LIMIT 1', shareId, ip, ts - OPENS_DEDUPE_SEC).toArray().length) return;
    if (this.sql.exec('SELECT COUNT(*) AS c FROM opens WHERE share_id = ? AND ts > ?', shareId, ts - 60).one().c >= OPENS_PER_MINUTE) return;
    this.sql.exec(`INSERT INTO opens (share_id, user_id, ts, ip, country, region, city, browser, browser_ver, os, langs)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, shareId, r.user_id, ts, ip, t(info.country, 8), t(info.region, 64),
    t(info.city, 64), t(info.browser, 32), t(info.version, 8), t(info.os, 32), t(info.langs, 200));
    const c = this.sql.exec('SELECT COUNT(*) AS c FROM opens WHERE share_id = ?', shareId).one().c;
    if (c > MAX_OPENS_PER_SHARE) {
      // Keep the first receipts (who opened it first) and the most recent ones.
      this.sql.exec(`DELETE FROM opens WHERE id IN (SELECT id FROM opens WHERE share_id = ? ORDER BY id ASC LIMIT ? OFFSET ?)`,
        shareId, c - MAX_OPENS_PER_SHARE, OPENS_KEEP_FIRST);
    }
  }

  /**
   * The opens of a share. The sender (`uid` = the share's owner) sees the time
   * of every open and only the details the admin lets that account see
   * (receipt* limits); the admin (`admin: true`) always sees everything.
   */
  async shareOpens(uid, shareId, { admin = false, limit = 200 } = {}) {
    const s = this.sql.exec('SELECT user_id FROM shares WHERE id = ?', shareId).toArray()[0];
    if (!s || (!admin && s.user_id !== uid)) return fail(404, 'not_found', 'Share not found.');
    const lim = Math.max(1, Math.min(MAX_OPENS_PER_SHARE, limit | 0));
    const rows = this.sql.exec('SELECT ts, ip, country, region, city, browser, browser_ver, os, langs FROM opens WHERE share_id = ? ORDER BY id DESC LIMIT ?', shareId, lim).toArray();
    // Every open counts, including those not stored individually (throttled, or before receipts existed).
    const stored = this.sql.exec('SELECT COUNT(*) AS c FROM opens WHERE share_id = ?', shareId).one().c;
    const counted = this.sql.exec('SELECT opens_total FROM shares WHERE id = ?', shareId).toArray()[0]?.opens_total ?? 0;
    const total = Math.max(stored, counted);
    let fields = RECEIPT_FIELDS;
    if (!admin) {
      const owner = this.#user(s.user_id);
      const L = owner ? this.#effective(owner).all : {};
      fields = RECEIPT_FIELDS.filter((f) => L[f.limit] === true);
    }
    const keys = new Set(fields.flatMap((f) => f.cols));
    return {
      ok: true,
      total,
      fields: fields.map((f) => f.limit),
      rows: rows.map((r) => Object.fromEntries(Object.entries(r).filter(([k]) => k === 'ts' || keys.has(k)))),
    };
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

  /**
   * True when `id` was a real share (it is still in the share index: active,
   * or ended within the last SHARE_PRUNE_SEC). Fetches of such ids that find
   * nothing — expired, used up, revoked, deleted — are not "invalid".
   */
  /**
   * A fetch of a share whose content is gone (expired, used up, revoked or
   * deleted): 'ok' when the id was a share and the request's link-proof hash
   * `lh` (if it sent one) matches it, 'wrong_link' when it does not, and
   * 'unknown' when the id was never a share. Shares recorded before link
   * hashes were kept answer 'ok'.
   */
  async goneShare(id, lh = null) {
    const r = this.sql.exec('SELECT lh FROM shares WHERE id = ?', id).toArray()[0];
    if (!r) return 'unknown';
    if (typeof lh !== 'string' || typeof r.lh !== 'string') return 'ok';
    return r.lh.length === lh.length && timingSafeEqualHex(r.lh, lh) ? 'ok' : 'wrong_link';
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
  async updateShare(uid, id, { label, expires, views, status }, actorId = uid, { admin = null, keyId = null } = {}) {
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
    // A change made with an API key names the key (its id, never the secret).
    if (keyId && !admin) parts.push(`apikey=${String(keyId).slice(0, 16)}`);
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
    const ids = (Array.isArray(users) ? users : []).filter((u) => typeof u === 'string').slice(0, MAX_SHARE_FILTER_USERS);
    // One JSON array parameter for any number of users (one `?` each would exceed the limit).
    if (ids.length) { where.push('s.user_id IN (SELECT value FROM json_each(?))'); args.push(JSON.stringify(ids)); }
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
    const rows = this.sql.exec(`SELECT s.id, s.user_id, u.username, s.kind, s.label, s.created, s.expires, s.views_total, s.status, MAX(s.opens_total, (SELECT COUNT(*) FROM opens o WHERE o.share_id = s.id)) AS opens,
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
      this.sql.exec('DELETE FROM meta WHERE k IN (SELECT ? || id FROM passkeys WHERE user_id = ?)', handleAlias(''), id);
      for (const t of ['limits', 'quotas', 'usage', 'api_keys', 'failures', 'viewer_rules', 'shares', 'opens', 'passkeys', 'recovery_codes', 'webauthn_challenges']) this.sql.exec(`DELETE FROM ${t} WHERE user_id = ?`, id);
      this.sql.exec('DELETE FROM users WHERE id = ?', id);
      this.#log(actorId, id, 'user.deleted', `username=${u.username}`);
    });
    return { ok: true, shares };
  }

  async setPassword(id, { salt, t, verifier }, actorId) {
    const u = this.#user(id);
    if (!u) return fail(404, 'not_found', 'User not found.');
    if (u.role === 'public') return fail(403, 'forbidden', 'The public account has no password.');
    // The owner changes their own password from Account (which asks for the
    // current one); an admin-side reset would skip that step-up.
    if (u.role === 'owner') return fail(403, 'use_account_page', 'Change the owner password from Account, with the current password.');
    const bad = this.#checkCredential(salt, t, verifier);
    if (bad) return fail(400, 'invalid_credential', bad);
    this.sql.exec('UPDATE users SET pw_salt = ?, pw_t = ?, pw_verifier = ?, sess_ver = sess_ver + 1, updated = ? WHERE id = ?', salt, t, verifier, now(), id);
    this.sql.exec('DELETE FROM failures WHERE user_id = ?', id);
    // Passkeys and recovery codes are not tied to the password and stay
    // (remove them separately if the account may have been taken over).
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
      // Only the public account has settings of its own; users have their role's.
      limits: u.role === 'public' ? { all: this.#limitRows(id, 'all'), api: this.#limitRows(id, 'api') } : { all: {}, api: {} },
      effective: this.#effective(u),
      quotas: u.role === 'public' ? this.sql.exec('SELECT id, channel, kind, n, unit, max FROM quotas WHERE user_id = ?', id).toArray() : [],
      viewerRules: u.role === 'public' ? this.sql.exec('SELECT match, value, renderer FROM viewer_rules WHERE user_id = ? ORDER BY id', id).toArray() : [],
      role: u.role === 'user' ? (this.#role(u.role_id) ? { id: u.role_id, name: this.#role(u.role_id).name } : { id: 'default', name: 'Default' }) : null,
      keys: await this.listKeys(id),
      passkeys: { count: this.#passkeyCount(id), recoveryLeft: this.#recoveryLeft(id), mfa: this.#needsSecondFactor(u) },
    };
  }

  // ── Turnstile keys set in the admin panel ────────────────────────────────
  /** For the Worker only (never returned by an API): the keys, or null. */
  async turnstileKeys() {
    const sitekey = this.#meta('turnstile.sitekey');
    const secret = this.#meta('turnstile.secret');
    return sitekey && secret ? { sitekey, secret } : null;
  }

  /** What the admin panel shows: the site key (public) and whether a secret is set. */
  async turnstileStatus() {
    return { sitekey: this.#meta('turnstile.sitekey'), secretSet: !!this.#meta('turnstile.secret') };
  }

  /**
   * Set or clear the admin-panel Turnstile keys. A security setting, so it
   * needs the owner's password or a passkey. An empty `secret` keeps the one
   * already stored (the site key can change alone); the secret is never
   * returned or logged.
   */
  async setTurnstileKeys(actorId, { sitekey, secret, clear = false, current, reauth, origin, rpId, lockoutOff = false }) {
    const actor = this.#user(actorId);
    if (!actor || actor.role !== 'owner') return fail(403, 'forbidden', 'Only the owner can change this.');
    const wrong = await this.#stepUp(actor, { current, reauth, origin, rpId }, lockoutOff);
    if (wrong) return wrong;
    if (clear === true) {
      this.sql.exec("DELETE FROM meta WHERE k IN ('turnstile.sitekey', 'turnstile.secret')");
      this.#log(actorId, null, 'turnstile.cleared');
      return { ok: true, sitekey: null, secretSet: false };
    }
    const key = typeof sitekey === 'string' ? sitekey.trim() : '';
    const sec = typeof secret === 'string' ? secret.trim() : '';
    const keptSecret = this.#meta('turnstile.secret');
    if (!TURNSTILE_KEY_RE.test(key)) return fail(400, 'invalid_sitekey', 'Enter the site key from the Cloudflare dashboard (10–100 letters, digits, - or _).');
    if (sec && !TURNSTILE_KEY_RE.test(sec)) return fail(400, 'invalid_secret', 'Enter the secret key from the Cloudflare dashboard (10–100 letters, digits, - or _).');
    if (!sec && !keptSecret) return fail(400, 'invalid_secret', 'Enter the secret key too.');
    this.#setMeta('turnstile.sitekey', key);
    if (sec) this.#setMeta('turnstile.secret', sec);
    this.#log(actorId, null, 'turnstile.updated', `sitekey=${key}${sec ? ' (secret replaced)' : ''}`);
    return { ok: true, sitekey: key, secretSet: true };
  }

  // ── admin: limits / quotas / viewer rules / settings ─────────────────────
  /**
   * An admin scope: '' (the Default role), "role:<id>" (a custom role) or the
   * public account's id. Users have no settings of their own: their role's
   * apply. → { key, label } or a failure.
   */
  #adminScope(scope) {
    if (scope === '' || scope === 'global' || scope === 'role:default') return { key: '', label: 'Default role' };
    if (scope === PUBLIC_ID) return { key: PUBLIC_ID, label: 'public account' };
    if (typeof scope === 'string' && scope.startsWith('role:')) {
      const r = this.#role(scope.slice(5));
      return r ? { key: roleScope(r.id), label: `role ${r.name}` } : fail(404, 'not_found', 'Role not found.');
    }
    if (this.#user(scope)) return fail(400, 'use_a_role', 'Accounts have no settings of their own: give the user a role (Admin → Roles).');
    return fail(404, 'not_found', 'Not found.');
  }

  async setLimits(scopeIn, channel, patch, actorId) {
    const sc = this.#adminScope(scopeIn);
    if (sc.ok === false) return sc;
    const scopeUserId = sc.key;
    if (channel !== 'all' && channel !== 'api') return fail(400, 'invalid', 'channel must be all or api');
    if (!patch || typeof patch !== 'object') return fail(400, 'invalid', 'patch must be an object');
    const ops = [];
    try {
      for (const [k, v] of Object.entries(patch)) {
        if (!Object.prototype.hasOwnProperty.call(LIMITS, k)) throw new Error(`unknown limit "${k}"`);
        if (scopeUserId === PUBLIC_ID && v !== 'inherit' && PUBLIC_NA_LIMITS.includes(k)) throw new Error(`"${k}" does not apply to the public account`);
        if (scopeUserId === '' && channel === 'all' && v === 'inherit') throw new Error(`the Default role has a value for every option ("${k}" cannot inherit)`);
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
    this.#log(actorId, scopeUserId === PUBLIC_ID ? PUBLIC_ID : null, 'limits.updated', `${sc.label} ${channel}: ${ops.map(([k, v]) => `${k}=${v === undefined ? 'inherit' : JSON.stringify(v)}`).join(', ')}`);
    return { ok: true };
  }

  async setQuotas(scopeIn, list, actorId) {
    const sc = this.#adminScope(scopeIn);
    if (sc.ok === false) return sc;
    const scopeUserId = sc.key;
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
      // Saving a role's list means the role uses it (instead of Default's).
      if (scopeUserId.startsWith('r:')) this.sql.exec('UPDATE roles SET own_quotas = 1, updated = ? WHERE id = ?', now(), scopeUserId.slice(2));
    });
    this.#log(actorId, scopeUserId === PUBLIC_ID ? PUBLIC_ID : null, 'quotas.updated', `${sc.label}: ${clean.map((q) => `${q.max}/${q.n}${q.unit} ${q.kind} ${q.channel}`).join('; ') || 'none'}`);
    return { ok: true };
  }

  async setViewerRules(scopeIn, list, actorId) {
    const sc = this.#adminScope(scopeIn);
    if (sc.ok === false) return sc;
    const scopeUserId = sc.key;
    if (!Array.isArray(list) || list.length > 200) return fail(400, 'invalid', 'rules must be a list (max 200)');
    let clean;
    try { clean = list.map(checkViewerRule); } catch (e) { return fail(400, 'invalid_rule', e.message); }
    this.ctx.storage.transactionSync(() => {
      this.sql.exec('DELETE FROM viewer_rules WHERE user_id = ?', scopeUserId);
      for (const r of clean) this.sql.exec('INSERT INTO viewer_rules (user_id, match, value, renderer) VALUES (?, ?, ?, ?)', scopeUserId, r.match, r.value, r.renderer);
    });
    this.#log(actorId, scopeUserId === PUBLIC_ID ? PUBLIC_ID : null, 'viewer_rules.updated', `${sc.label}: ${clean.length} rules`);
    return { ok: true };
  }

  // ── roles ────────────────────────────────────────────────────────────────
  // Two built-in roles are not stored: "owner" (locked: everything allowed,
  // no limits; the owner's only, never assignable) and "default" (the global
  // rows: Defaults & quotas). Custom roles are rows in `roles`; each user has
  // exactly one role (users.role_id; empty = Default).

  #roleName(name) {
    const n = cleanLabel(name);
    if (!n || n.length > 64) return fail(400, 'invalid_name', 'Give the role a name (1–64 characters).');
    if (RESERVED_ROLE_NAMES.includes(n.toLowerCase())) return fail(409, 'name_taken', `"${n}" is a built-in role.`);
    return { ok: true, name: n };
  }

  async listRoles() {
    const counts = Object.fromEntries(this.sql.exec("SELECT role_id, COUNT(*) AS c FROM users WHERE role = 'user' AND role_id IN (SELECT id FROM roles) GROUP BY role_id").toArray().map((r) => [r.role_id, r.c]));
    const custom = this.sql.exec('SELECT * FROM roles ORDER BY name COLLATE NOCASE').toArray();
    const assigned = Object.values(counts).reduce((a, b) => a + b, 0);
    const users = this.sql.exec("SELECT COUNT(*) AS c FROM users WHERE role = 'user'").one().c;
    return {
      roles: [
        // Owner: everything allowed, no limits; only the owner's own session
        // timeouts and file-share windows can be changed. Public: the public
        // (anonymous) account's; cannot be renamed, deleted or assigned.
        { id: 'owner', name: 'Owner', builtin: true, locked: true, users: this.#owner() ? 1 : 0 },
        { id: 'default', name: 'Default', builtin: true, users: users - assigned },
        { id: 'public', name: 'Public', builtin: true, fixed: true, users: 0 },
        ...custom.map((r) => ({ id: r.id, name: r.name, builtin: false, ownQuotas: !!r.own_quotas, users: counts[r.id] || 0, created: r.created, updated: r.updated })),
      ],
    };
  }

  /** One custom role, with what it sets, what it inherits from Default, and its lists. */
  async roleDetail(id) {
    const r = this.#role(id);
    if (!r) return fail(404, 'not_found', 'Role not found.');
    const sc = roleScope(r.id);
    const all = this.#limitRows(sc, 'all');
    const globalAll = this.#limitRows('', 'all');
    const effAll = resolveLimits(globalAll, all);
    return {
      ok: true,
      role: { id: r.id, name: r.name, ownQuotas: !!r.own_quotas },
      limits: { all, api: this.#limitRows(sc, 'api') },
      effective: { all: effAll, api: restrictForApi(effAll, this.#limitRows('', 'api'), this.#limitRows(sc, 'api')) },
      inherited: resolveLimits(globalAll, {}),
      quotas: this.sql.exec('SELECT id, channel, kind, n, unit, max FROM quotas WHERE user_id = ?', sc).toArray(),
      viewerRules: this.sql.exec('SELECT match, value, renderer FROM viewer_rules WHERE user_id = ? ORDER BY id', sc).toArray(),
      users: this.sql.exec("SELECT id, username FROM users WHERE role = 'user' AND role_id = ? ORDER BY username", r.id).toArray(),
    };
  }

  async createRole(name, actorId) {
    const n = this.#roleName(name);
    if (!n.ok) return n;
    if (this.sql.exec('SELECT 1 FROM roles WHERE name = ?', n.name).toArray().length) return fail(409, 'name_taken', 'A role with that name exists.');
    const id = newId();
    const ts = now();
    this.sql.exec('INSERT INTO roles (id, name, own_quotas, created, updated) VALUES (?, ?, 0, ?, ?)', id, n.name, ts, ts);
    this.#log(actorId, null, 'role.created', `name=${n.name}`);
    return { ok: true, id };
  }

  /** Rename a role, or choose whether it has its own quota list (instead of Default's). */
  async updateRole(id, { name, ownQuotas }, actorId) {
    const r = this.#role(id);
    if (!r) return fail(404, 'not_found', 'Role not found.');
    let label = r.name;
    if (name !== undefined) {
      const n = this.#roleName(name);
      if (!n.ok) return n;
      const clash = this.sql.exec('SELECT id FROM roles WHERE name = ?', n.name).toArray()[0];
      if (clash && clash.id !== id) return fail(409, 'name_taken', 'A role with that name exists.');
      label = n.name;
    }
    if (ownQuotas !== undefined && typeof ownQuotas !== 'boolean') return fail(400, 'invalid', 'ownQuotas must be true or false');
    const own = ownQuotas === undefined ? r.own_quotas : ownQuotas ? 1 : 0;
    this.sql.exec('UPDATE roles SET name = ?, own_quotas = ?, updated = ? WHERE id = ?', label, own, now(), id);
    this.#log(actorId, null, 'role.updated', `name=${label}${label !== r.name ? ` (was ${r.name})` : ''} ownQuotas=${!!own}`);
    return { ok: true };
  }

  /**
   * A new role with everything `fromId` sets ("default": the Default role's
   * values, copied as explicit settings so later changes to Default do not
   * change the copy).
   */
  async duplicateRole(fromId, name, actorId) {
    const src = fromId === 'default' ? { key: '', name: 'Default', own_quotas: 1 } : (() => { const r = this.#role(fromId); return r && { key: roleScope(r.id), name: r.name, own_quotas: r.own_quotas }; })();
    if (!src) return fail(404, 'not_found', 'Role not found.');
    const n = this.#roleName(name);
    if (!n.ok) return n;
    if (this.sql.exec('SELECT 1 FROM roles WHERE name = ?', n.name).toArray().length) return fail(409, 'name_taken', 'A role with that name exists.');
    const id = newId();
    const to = roleScope(id);
    const ts = now();
    this.ctx.storage.transactionSync(() => {
      this.sql.exec('INSERT INTO roles (id, name, own_quotas, created, updated) VALUES (?, ?, ?, ?, ?)', id, n.name, src.own_quotas ? 1 : 0, ts, ts);
      for (const l of this.sql.exec('SELECT channel, key, value FROM limits WHERE user_id = ?', src.key).toArray()) {
        this.sql.exec('INSERT INTO limits (user_id, channel, key, value) VALUES (?, ?, ?, ?)', to, l.channel, l.key, l.value);
      }
      for (const q of this.sql.exec('SELECT channel, kind, n, unit, max FROM quotas WHERE user_id = ?', src.key).toArray()) {
        this.sql.exec('INSERT INTO quotas (id, user_id, channel, kind, n, unit, max) VALUES (?, ?, ?, ?, ?, ?, ?)', newId(), to, q.channel, q.kind, q.n, q.unit, q.max);
      }
      for (const v of this.sql.exec('SELECT match, value, renderer FROM viewer_rules WHERE user_id = ? ORDER BY id', src.key).toArray()) {
        this.sql.exec('INSERT INTO viewer_rules (user_id, match, value, renderer) VALUES (?, ?, ?, ?)', to, v.match, v.value, v.renderer);
      }
    });
    this.#log(actorId, null, 'role.created', `name=${n.name} (copy of ${src.name})`);
    return { ok: true, id };
  }

  /** Delete a custom role; its users move to the Default role. */
  async deleteRole(id, actorId) {
    const r = this.#role(id);
    if (!r) return fail(404, 'not_found', 'Role not found.');
    const sc = roleScope(r.id);
    let moved = 0;
    this.ctx.storage.transactionSync(() => {
      moved = this.sql.exec("SELECT COUNT(*) AS c FROM users WHERE role = 'user' AND role_id = ?", id).one().c;
      this.sql.exec('UPDATE users SET role_id = NULL, updated = ? WHERE role_id = ?', now(), id);
      this.sql.exec('DELETE FROM usage WHERE quota_id IN (SELECT id FROM quotas WHERE user_id = ?)', sc);
      for (const t of ['limits', 'quotas', 'viewer_rules']) this.sql.exec(`DELETE FROM ${t} WHERE user_id = ?`, sc);
      this.sql.exec('DELETE FROM roles WHERE id = ?', id);
    });
    this.#log(actorId, null, 'role.deleted', `name=${r.name} users moved to Default=${moved}`);
    return { ok: true, moved };
  }

  /** Give a user a role ("default" or a custom role id). The owner's role cannot change. */
  async setUserRole(uid, roleId, actorId) {
    const u = this.#user(uid);
    if (!u) return fail(404, 'not_found', 'User not found.');
    if (u.role === 'owner') return fail(403, 'owner_role', 'The owner always has the Owner role.');
    if (u.role !== 'user') return fail(403, 'forbidden', 'The public account always has the Public role.');
    if (roleId === 'owner') return fail(403, 'owner_role', 'The Owner role belongs to the owner only.');
    if (roleId === 'public') return fail(403, 'public_role', 'The Public role belongs to the public (anonymous) account only.');
    let next = null;
    let label = 'Default';
    if (roleId !== 'default' && roleId !== null && roleId !== '') {
      const r = typeof roleId === 'string' && ROLE_ID_RE.test(roleId) ? this.#role(roleId) : null;
      if (!r) return fail(404, 'not_found', 'Role not found.');
      next = r.id;
      label = r.name;
    }
    this.sql.exec('UPDATE users SET role_id = ?, updated = ? WHERE id = ?', next, now(), uid);
    this.#log(actorId, uid, 'role.assigned', `role=${label}`);
    return { ok: true, roleId: next ?? 'default' };
  }

  async adminGlobal() {
    const globalAll = this.#limitRows('', 'all');
    return {
      settings: this.#settings(),
      limits: { all: globalAll, api: this.#limitRows('', 'api') },
      // What applies when nothing is set: the built-in defaults, and what a
      // user inherits from the global rows.
      defaults: {
        settings: Object.fromEntries(Object.entries(SETTINGS).map(([k, v]) => [k, v.def])),
        limits: Object.fromEntries(Object.entries(LIMITS).map(([k, v]) => [k, v.def])),
        inherited: resolveLimits(globalAll, {}),
      },
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
    const cur = this.#settings();
    const merged = { ...cur, ...Object.fromEntries(ops) };
    const bad = crossCheckSettings(merged);
    if (bad) return fail(400, 'invalid_setting', bad);
    this.ctx.storage.transactionSync(() => {
      for (const [k, v] of ops) this.sql.exec('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', k, JSON.stringify(v));
    });
    // Every change is logged (long text by its length), in entries that fit.
    const changed = ops.filter(([k, v]) => cur[k] !== v);
    this.#logChunks(actorId, null, 'settings.updated', '', changed.length ? changed.map(([k, v]) => `${k}=${logValue(v)}`) : ['no changes']);
    return { ok: true, settings: this.#settings() };
  }

  /** Public, non-secret viewer policy (the recipient page intersects with it). */
  async publicConfig() {
    const s = this.#settings();
    return { accessibility: publicStatement(s) };
  }

  /**
   * What opening a file share needs from its sender's role, now: the download
   * window, and the viewer policy the recipient's page intersects with the
   * share's own (so turning the viewer off in a role stops it for existing
   * links at once).
   */
  async shareOpenPolicy(id) {
    const s = this.#settings();
    const row = this.sql.exec('SELECT user_id FROM shares WHERE id = ?', id).toArray()[0];
    const u = row && this.#user(row.user_id);
    if (!u) return { grantSec: s['files.grantSec'], viewer: { enabled: false, maxBytes: 0, rules: [] } };
    const L = this.#effective(u).all;
    const c = this.#caps(u, L, s);
    return { grantSec: c.grantSec, viewer: { enabled: c.viewerEnabled, maxBytes: c.viewerMaxBytes, rules: c.viewerEnabled ? this.#viewerRules(u, L) : [] } };
  }

  // ── admin: IP rules ──────────────────────────────────────────────────────
  async ipRules() {
    const ts = now();
    return this.sql.exec('SELECT id, cidr, action, expires, note, created FROM ip_rules WHERE expires IS NULL OR expires > ? ORDER BY created DESC', ts).toArray();
  }

  async addIpRule({ cidr, action, expires, note, callerIp = null }, actorId) {
    const c = normalizeRule(cidr);
    if (!c) return fail(400, 'invalid_cidr', 'Enter an IPv4/IPv6 address, a CIDR block (10.0.0.0/8) or a range (10.0.0.5-10.0.0.20).');
    if (action !== 'allow' && action !== 'block') return fail(400, 'invalid_action', 'action must be allow or block');
    // Never lock out the owner adding the rule (as imports already check): a
    // block covering their own address needs an allow rule for them first.
    const me = parseIp(callerIp ?? '');
    if (action === 'block' && me && ruleContains(parseRule(c), me)) {
      const allowed = (await this.ipRules()).some((r) => r.action === 'allow' && (r.expires === null || r.expires > now()) && ruleContains(parseRule(r.cidr), me));
      if (!allowed) return fail(409, 'blocks_yourself', `This rule would block your own address (${callerIp}). Add an allow rule for yourself first.`);
    }
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
   * Build the plaintext export document (the browser encrypts it before it is
   * stored). `system`: true (every part) or { settings, roles, ipRules,
   * turnstile, public } booleans. `users`: 'all' or a list of user ids (both
   * with the parts in `parts`), or a list of { id, parts } (parts chosen per
   * user): credentials, role, apiKeys (hashes: the keys keep working),
   * passkeys (public keys and the "Password and passkey" choice) and
   * recoveryCodes (hashes). `owner`: the owner's row, the parts among
   * passkeys and recoveryCodes; the owner's password, role and API keys are
   * never exported.
   */
  async exportData({ system = false, users = [], parts = [], owner: ownerParts = [], origin }, actorId) {
    const doc = { format: EXPORT_FORMAT, created: now(), users: [] };
    if (typeof origin === 'string') doc.origin = origin.slice(0, 200);
    const part = (k) => system === true || (system && typeof system === 'object' && system[k] === true);
    const sysParts = ['settings', 'roles', 'ipRules', 'turnstile', 'public'].filter(part);
    if (sysParts.length) {
      doc.system = {};
      if (part('settings')) doc.system.settings = this.#settings();
      if (part('ipRules')) doc.system.ipRules = (await this.ipRules()).map((r) => ({ cidr: r.cidr, action: r.action, expires: r.expires ?? null, note: r.note || '' }));
      if (part('turnstile')) doc.system.turnstile = await this.turnstileKeys();
      if (part('public')) {
        doc.system.public = {
          limits: { all: this.#limitRows(PUBLIC_ID, 'all'), api: this.#limitRows(PUBLIC_ID, 'api') },
          quotas: this.#quotaRows(PUBLIC_ID),
          viewerRules: this.sql.exec('SELECT match, value, renderer FROM viewer_rules WHERE user_id = ? ORDER BY id', PUBLIC_ID).toArray(),
        };
      }
    }
    if (part('roles')) {
      Object.assign(doc.system, {
        limits: { all: this.#limitRows('', 'all'), api: this.#limitRows('', 'api') },
        quotas: this.#quotaRows(''),
        viewerRules: this.sql.exec("SELECT match, value, renderer FROM viewer_rules WHERE user_id = '' ORDER BY id").toArray(),
        roles: this.sql.exec('SELECT * FROM roles ORDER BY name COLLATE NOCASE').toArray().map((r) => {
          const sc = roleScope(r.id);
          return {
            name: r.name,
            ownQuotas: !!r.own_quotas,
            limits: { all: this.#limitRows(sc, 'all'), api: this.#limitRows(sc, 'api') },
            quotas: this.#quotaRows(sc),
            viewerRules: this.sql.exec('SELECT match, value, renderer FROM viewer_rules WHERE user_id = ? ORDER BY id', sc).toArray(),
          };
        }),
      });
    }
    // Which accounts, each with its parts (only plain users: never the owner or the public account).
    const onlyParts = (list) => USER_PARTS.filter((k) => Array.isArray(list) && list.includes(k));
    const picks = [];
    const seen = new Set();
    const wanted = users === 'all'
      ? this.sql.exec("SELECT * FROM users WHERE role = 'user' ORDER BY username LIMIT ?", MAX_EXPORT_USERS + 1).toArray().map((u) => ({ u, parts: onlyParts(parts) }))
      : (Array.isArray(users) ? users : []).slice(0, MAX_EXPORT_USERS + 1)
        .map((x) => (typeof x === 'string' ? { u: this.#user(x), parts: onlyParts(parts) } : { u: this.#user(x?.id), parts: onlyParts(x?.parts) }));
    for (const w of wanted) {
      if (!w.u || w.u.role !== 'user' || !w.parts.length || seen.has(w.u.id)) continue;
      seen.add(w.u.id);
      picks.push(w);
    }
    // Never produce a file that the import would refuse.
    if (picks.length > MAX_EXPORT_USERS) return fail(413, 'too_many_users', `An export holds at most ${MAX_EXPORT_USERS} users — export them in parts.`);
    for (const { u, parts: P } of picks) {
      const e = { username: u.username };
      if (P.includes('credentials')) e.credentials = { salt: u.pw_salt, t: u.pw_t, verifier: u.pw_verifier, disabled: !!u.disabled };
      // A user's role, by name (the role itself travels in `system`).
      if (P.includes('role')) e.role = this.#role(u.role_id)?.name ?? 'Default';
      if (P.includes('apiKeys')) {
        e.apiKeys = this.sql.exec('SELECT key_hash, name, created, expires, last_used, scopes FROM api_keys WHERE user_id = ? ORDER BY created', u.id).toArray()
          .map((k) => ({ hash: k.key_hash, name: k.name, created: k.created, expires: k.expires ?? null, lastUsed: k.last_used ?? null, scopes: String(k.scopes || '').split(',').filter((x) => API_SCOPES.includes(x)) }));
      }
      if (P.includes('passkeys')) e.passkeys = { mfa: !!u.mfa, keys: this.#exportPasskeys(u) };
      if (P.includes('recoveryCodes')) e.recoveryCodes = this.#exportRecoveryCodes(u);
      doc.users.push(e);
    }
    // The owner's row: its passkeys and/or recovery codes (hashes), when chosen.
    const OP = OWNER_PARTS.filter((k) => Array.isArray(ownerParts) && ownerParts.includes(k));
    const owner = OP.length ? this.#owner() : null;
    const ownerLog = [];
    if (owner) {
      doc.owner = {};
      if (OP.includes('passkeys')) {
        doc.owner.passkeys = { keys: this.#exportPasskeys(owner) };
        ownerLog.push(`passkeys(${doc.owner.passkeys.keys.length})`);
      }
      if (OP.includes('recoveryCodes')) {
        doc.owner.recoveryCodes = this.#exportRecoveryCodes(owner);
        ownerLog.push(`recoveryCodes(${doc.owner.recoveryCodes.length})`);
      }
    }
    const used = USER_PARTS.filter((k) => picks.some((x) => x.parts.includes(k)));
    this.#log(actorId, null, 'export.created', `system=${sysParts.join('+') || 'none'} users=${doc.users.length} parts=${used.join('+') || 'none'}${owner ? ` owner=${ownerLog.join('+')}` : ''}`);
    // Which accounts left the system (and with what), in chunks that fit the audit detail field.
    const groups = new Map();
    for (const x of picks) {
      const k = x.parts.join('+');
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(x.u.username);
    }
    for (const [k, names] of groups) this.#logChunks(actorId, null, 'export.users', `${k}: `, names);
    return { ok: true, doc };
  }

  /** An account's unused recovery codes as exported: their hashes only. */
  #exportRecoveryCodes(u) {
    return this.sql.exec('SELECT hash FROM recovery_codes WHERE user_id = ? ORDER BY created, hash', u.id).toArray().map((c) => c.hash);
  }

  /** An account's passkeys as exported: public keys, each with the user handle it was registered under. */
  #exportPasskeys(u) {
    return this.sql.exec('SELECT * FROM passkeys WHERE user_id = ? ORDER BY created, id', u.id).toArray().map((k) => ({
      id: k.id, handle: this.#passkeyHandle(k, u), name: k.name, publicKey: k.public_key, alg: k.alg, signCount: k.sign_count,
      transports: k.transports ? k.transports.split(',') : [], backupEligible: !!k.backup_eligible, backedUp: !!k.backed_up, created: k.created, lastUsed: k.last_used ?? null,
    }));
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
   * decisions (portable.js): the system parts, the owner's passkeys and, per
   * user, the action and the parts chosen. The plan says per account what
   * changes and what is skipped (and why). Applying is all-or-nothing: one
   * storage transaction, and any planning error refuses the whole import.
   * `host` is this server's hostname (passkeys work only where they were
   * registered).
   */
  async importData(doc, decisions, { dryRun = true, callerIp = null, host = '' } = {}, actorId) {
    const plan = { system: null, owner: null, users: [], errors: [], warnings: [] };
    const S = decisions.systemParts ?? new Set();
    const sys = doc.system ?? { parts: [] };
    const ts = now();
    let ipAdd = [];
    if (S.size) {
      plan.system = { parts: [...S] };
      if (S.has('settings')) {
        const cur = this.#settings();
        const bad = crossCheckSettings({ ...cur, ...sys.settings });
        if (bad) plan.errors.push(`system: ${bad}`);
        // Security-relevant changes are called out in the preview.
        for (const [k, v] of Object.entries(sys.settings)) {
          if (/^(guard|lockout|public)\./.test(k) && cur[k] !== v) plan.warnings.push(`security setting ${k}: ${cur[k]} → ${v}`);
        }
        plan.system.settings = Object.entries(sys.settings).filter(([k, v]) => cur[k] !== v).map(([key, to]) => ({ key, from: cur[key], to }));
      }
      if (S.has('roles')) {
        plan.system.roles = sys.roles.map((r) => ({ name: r.name, action: this.sql.exec('SELECT 1 FROM roles WHERE name = ?', r.name).toArray().length ? 'replace' : 'create' }));
        plan.system.limits = { all: Object.keys(sys.limits.all).length, api: Object.keys(sys.limits.api).length };
        plan.system.quotas = sys.quotas.length;
        plan.system.viewerRules = sys.viewerRules.length;
      }
      if (S.has('ipRules')) {
        const existingRules = new Set((await this.ipRules()).map((r) => `${r.action} ${r.cidr}`));
        ipAdd = sys.ipRules.filter((r) => (r.expires === null || r.expires > ts) && !existingRules.has(`${r.action} ${r.cidr}`));
        // Never lock out the owner who is importing: a new block rule covering
        // the caller (with no allow rule for it) refuses the import.
        const me = parseIp(callerIp ?? '');
        if (me) {
          const after = [...(await this.ipRules()), ...ipAdd].map((r) => ({ action: r.action, c: parseRule(r.cidr) }));
          const allowed = after.some((r) => r.action === 'allow' && ruleContains(r.c, me));
          const blocking = ipAdd.find((r) => r.action === 'block' && ruleContains(parseRule(r.cidr), me));
          if (blocking && !allowed) plan.errors.push(`system: the IP rule "block ${blocking.cidr}" would block your own address — remove it from the file or add an allow rule for yourself first`);
        }
        for (const r of ipAdd) if (r.action === 'allow') plan.warnings.push(`adds an allow rule (exempts ${r.cidr} from brute-force protection and blocks)`);
        plan.system.ipRulesAdded = ipAdd.map((r) => `${r.action} ${r.cidr}`);
        plan.system.ipRulesSkipped = sys.ipRules.length - ipAdd.length;
      }
      if (S.has('turnstile')) {
        plan.system.turnstile = sys.turnstile ? `site key ${sys.turnstile.sitekey} (and its secret)` : 'none (the panel keys are removed)';
        plan.warnings.push('the Turnstile keys set in the admin panel are replaced (the deployment\'s own keys, if any, still win); the widget must allow this hostname');
      }
      if (S.has('public')) plan.system.public = { limits: Object.keys(sys.public.limits.all).length, quotas: sys.public.quotas.length, viewerRules: sys.public.viewerRules.length };
    }
    // ── accounts ──
    // The confirmed rule: an import never removes or overwrites an existing
    // account's credentials. An existing account (the owner included) only
    // gets its role set (if chosen; never the owner's) and the imported
    // passkeys added (if chosen). New accounts come from the chosen parts.
    const fileHost = (() => { try { return doc.origin ? new URL(doc.origin).hostname : ''; } catch { return ''; } })();
    const hashOwner = (hash) => this.sql.exec('SELECT user_id FROM api_keys WHERE key_hash = ?', hash).toArray()[0]?.user_id;
    const passkeyOwner = (id) => this.sql.exec('SELECT user_id FROM passkeys WHERE id = ?', id).toArray()[0]?.user_id;
    const codeTaken = (hash) => this.sql.exec('SELECT 1 FROM recovery_codes WHERE hash = ?', hash).toArray().length > 0;
    const seenHashes = new Set();
    const seenPasskeys = new Set();
    const seenCodes = new Set();
    const planned = new Map(); // account id → passkeys this import adds to it
    const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
    const names = (ks) => ks.map((k) => `"${k.name}"`).join(', ');
    const roleHere = (name) => this.sql.exec('SELECT * FROM roles WHERE name = ?', name).toArray()[0] || null;
    const roleInFile = (name) => (S.has('roles') ? sys.roles.find((r) => r.name.toLowerCase() === name.toLowerCase()) : null) || null;
    const isDefault = (name) => name.toLowerCase() === 'default';
    // An account's limits after the import, from its role's name (the roles part may bring or replace it).
    const limitsFor = (name) => {
      let own = {};
      if (name && !isDefault(name)) {
        const f = roleInFile(name);
        const r = f ? null : roleHere(name);
        own = f ? f.limits.all : r ? this.#limitRows(roleScope(r.id), 'all') : {};
      }
      return resolveLimits(S.has('roles') ? sys.limits.all : this.#limitRows('', 'all'), own);
    };
    // The file's passkeys an account takes: never one registered here already
    // (a credential id belongs to one account) and only as many as fit.
    const takePasskeys = (list, uid, max, skipped) => {
      let room = max - (uid ? this.#passkeyCount(uid) : 0) - (planned.get(uid) ?? 0);
      const add = [];
      for (const k of list) {
        const holder = passkeyOwner(k.id);
        if (holder && holder === uid) skipped.push(`passkey "${k.name}": already registered to this account`);
        else if (holder) skipped.push(`passkey "${k.name}": already registered to another account here (a passkey belongs to one account)`);
        else if (seenPasskeys.has(k.id)) skipped.push(`passkey "${k.name}": already taken by another account in this import`);
        else if (room <= 0) skipped.push(`passkey "${k.name}": does not fit (this account can have up to ${max} passkeys)`);
        else { add.push(k); room--; seenPasskeys.add(k.id); }
      }
      if (uid) planned.set(uid, (planned.get(uid) ?? 0) + add.length);
      return add;
    };
    const passkeyWarnings = (who, add, lim) => {
      if (!add.length) return;
      if (fileHost && host && fileHost !== host) plan.warnings.push(`"${who}": passkeys were registered for ${fileHost} and will not work on ${host} (recovery codes do)`);
      if (lim && lim.passkeys === 'off') plan.warnings.push(`"${who}": passkeys are turned off for its role — the imported passkeys are kept but work only once the role allows passkeys`);
    };
    const jobs = []; // what applying does, per account
    for (const u of doc.users) {
      const d = decisions.users.get(u.username);
      if (!d) { plan.users.push({ username: u.username, action: 'skip' }); continue; }
      const P = d.parts;
      const existing = this.#userByName(d.as);
      const entry = { username: u.username, as: d.as, action: d.action, changes: [], skipped: [] };
      plan.users.push(entry);
      if (existing && existing.role !== 'user' && existing.role !== 'owner') {
        entry.action = 'refused';
        plan.errors.push(`"${d.as}" is a built-in account and cannot be imported into`);
        continue;
      }
      if (existing && d.action === 'create') {
        entry.action = 'conflict';
        plan.errors.push(`"${d.as}" already exists here — choose "update existing" (sets its role and adds passkeys only), import it under another name, or skip it`);
        continue;
      }
      if (!existing && d.action === 'update') {
        entry.action = 'refused';
        plan.errors.push(`"${d.as}" does not exist here, so it cannot be updated — choose "create" or skip it`);
        continue;
      }
      if (!existing && !P.has('credentials')) {
        entry.action = 'refused';
        plan.errors.push(`"${d.as}" does not exist here and no credentials are imported for it — it cannot be created`);
        continue;
      }
      const roleOk = (name) => {
        if (isDefault(name) || roleHere(name) || roleInFile(name)) return true;
        plan.errors.push(`"${u.username}": the role "${name}" does not exist here — import the roles too, or create the role first`);
        return false;
      };
      const job = { u, entry, id: existing?.id ?? null, create: !existing, role: null, apiKeys: [], passkeys: [], codes: [], mfa: false };
      jobs.push(job);
      if (!existing) {
        // A new account, from the chosen parts.
        entry.changes.push(u.credentials.disabled ? 'credentials (disabled account)' : 'credentials');
        if (P.has('role') && roleOk(u.role)) { job.role = u.role; entry.role = u.role; entry.changes.push(`role ${u.role}`); }
        if (P.has('apiKeys')) {
          for (const k of u.apiKeys) {
            if (seenHashes.has(k.hash) || hashOwner(k.hash)) plan.errors.push(`"${u.username}": the API key "${k.name}" already belongs to another account here`);
            seenHashes.add(k.hash);
          }
          job.apiKeys = u.apiKeys;
          entry.changes.push(plural(u.apiKeys.length, 'API key'));
          if (u.apiKeys.length) plan.warnings.push(`"${u.username}": ${plural(u.apiKeys.length, 'API key')} will work here as on the old server — revoke on either side separately`);
        }
        if (P.has('passkeys')) {
          const lim = limitsFor(job.role);
          job.passkeys = takePasskeys(u.passkeys.keys, null, Math.min(MAX_PASSKEYS, lim.passkeysMax ?? MAX_PASSKEYS), entry.skipped);
          job.mfa = u.passkeys.mfa && job.passkeys.length > 0;
          entry.changes.push(`${plural(job.passkeys.length, 'passkey')}${job.passkeys.length ? ` (${names(job.passkeys)})` : ''}${job.mfa ? ', "Password and passkey" on' : ''}`);
          passkeyWarnings(d.as, job.passkeys, lim);
        }
        if (P.has('recoveryCodes')) {
          const taken = u.recoveryCodes.filter((h) => seenCodes.has(h) || codeTaken(h));
          job.codes = u.recoveryCodes.filter((h) => !taken.includes(h));
          for (const h of job.codes) seenCodes.add(h);
          entry.changes.push(plural(job.codes.length, 'recovery code'));
          if (taken.length) entry.skipped.push(`${plural(taken.length, 'recovery code')}: already belong${taken.length === 1 ? 's' : ''} to another account here`);
        }
        continue;
      }
      // An existing account: only its role and added passkeys.
      const owner = existing.role === 'owner';
      if (owner) entry.owner = true;
      const kept = 'an existing account keeps its own';
      if (P.has('credentials')) entry.skipped.push(`password and disabled flag: ${kept}`);
      if (P.has('apiKeys')) entry.skipped.push(`API keys: ${kept}`);
      if (P.has('recoveryCodes')) entry.skipped.push(`recovery codes: ${kept}`);
      const current = owner ? 'Owner' : this.#role(existing.role_id)?.name ?? 'Default';
      if (P.has('role')) {
        if (owner) entry.skipped.push('role: the owner always has the Owner role');
        else if (roleOk(u.role)) {
          job.role = u.role;
          entry.role = u.role;
          entry.changes.push(current.toLowerCase() === u.role.toLowerCase() ? `role ${u.role} (unchanged)` : `role ${current} → ${u.role}`);
        }
      }
      if (P.has('passkeys')) {
        const lim = owner ? null : limitsFor(job.role ?? current);
        job.passkeys = takePasskeys(u.passkeys.keys, existing.id, owner ? MAX_PASSKEYS : Math.min(MAX_PASSKEYS, lim.passkeysMax ?? MAX_PASSKEYS), entry.skipped);
        if (job.passkeys.length) entry.changes.push(`adds ${plural(job.passkeys.length, 'passkey')} (${names(job.passkeys)}); its passkeys stay`);
        entry.skipped.push(`"Password and passkey" choice: ${kept}`);
        passkeyWarnings(d.as, job.passkeys, lim);
      }
    }
    // The file's owner row, applied to this server's owner: an existing
    // account, so its passkeys are added and its recovery codes never taken.
    const OP = decisions.ownerParts ?? new Set();
    if (OP.size) {
      const o = this.#owner();
      if (!o) plan.errors.push('this server has no owner yet');
      else {
        const entry = { as: o.username, changes: [], skipped: [] };
        const job = { u: null, entry, id: o.id, create: false, owner: true, role: null, apiKeys: [], passkeys: [], codes: [], mfa: false };
        if (OP.has('passkeys')) {
          job.passkeys = takePasskeys(doc.owner.passkeys.keys, o.id, MAX_PASSKEYS, entry.skipped);
          entry.changes.push(job.passkeys.length ? `adds ${plural(job.passkeys.length, 'passkey')} (${names(job.passkeys)}); your passkeys, password and recovery codes stay` : 'no passkeys to add');
          passkeyWarnings(o.username, job.passkeys, null);
        }
        if (OP.has('recoveryCodes')) entry.skipped.push('recovery codes: an existing account keeps its own');
        plan.owner = entry;
        jobs.push(job);
      }
    }
    const out = (applied) => ({ ok: true, applied, plan: { system: plan.system, owner: plan.owner ?? null, users: plan.users, errors: plan.errors, warnings: plan.warnings } });
    if (dryRun) return out(false);
    if (plan.errors.length) return fail(409, 'import_conflicts', `The import was not applied: ${plan.errors.length} problem${plan.errors.length === 1 ? '' : 's'} (run the preview).`, { plan: out(false).plan });

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
      if (S.has('settings')) {
        for (const [k, v] of Object.entries(sys.settings)) this.sql.exec('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', k, JSON.stringify(v));
        this.#logChunks(actorId, null, 'settings.updated', 'import: ', plan.system.settings.map((c) => `${c.key}=${logValue(c.to)}`));
      }
      if (S.has('roles')) {
        replaceScope('', sys.limits, sys.quotas, sys.viewerRules);
        materializeDefaultRole(this.sql); // the Default role keeps a value for every option
        for (const ch of ['all', 'api']) this.#logChunks(actorId, null, 'limits.updated', `import Default role ${ch}: `, Object.entries(sys.limits[ch]).map(([k, v]) => `${k}=${JSON.stringify(v)}`).concat(Object.keys(sys.limits[ch]).length ? [] : ['none']));
        this.#logChunks(actorId, null, 'quotas.updated', 'import Default role: ', sys.quotas.length ? sys.quotas.map((q) => `${q.max}/${q.n}${q.unit} ${q.kind} ${q.channel}`) : ['none']);
        this.#log(actorId, null, 'viewer_rules.updated', `import Default role: ${sys.viewerRules.length} rules`);
        for (const r of sys.roles) {
          let row = this.sql.exec('SELECT * FROM roles WHERE name = ?', r.name).toArray()[0];
          const created = !row;
          if (!row) {
            this.sql.exec('INSERT INTO roles (id, name, own_quotas, created, updated) VALUES (?, ?, ?, ?, ?)', newId(), r.name, r.ownQuotas ? 1 : 0, ts, ts);
            row = this.sql.exec('SELECT * FROM roles WHERE name = ?', r.name).toArray()[0];
          } else {
            this.sql.exec('UPDATE roles SET own_quotas = ?, updated = ? WHERE id = ?', r.ownQuotas ? 1 : 0, ts, row.id);
          }
          replaceScope(roleScope(row.id), r.limits, r.quotas, r.viewerRules);
          this.#log(actorId, null, created ? 'role.created' : 'role.updated', `import: name=${r.name}`);
        }
      }
      if (S.has('ipRules')) {
        for (const r of ipAdd) {
          this.sql.exec('INSERT INTO ip_rules (id, cidr, action, expires, note, created) VALUES (?, ?, ?, ?, ?, ?)', newId(), r.cidr, r.action, r.expires, r.note, ts);
          this.#log(actorId, null, 'iprule.added', `import: ${r.action} ${r.cidr}${r.note ? ` (${r.note})` : ''}`);
        }
      }
      if (S.has('turnstile')) {
        this.sql.exec("DELETE FROM meta WHERE k IN ('turnstile.sitekey', 'turnstile.secret')");
        if (sys.turnstile) {
          this.#setMeta('turnstile.sitekey', sys.turnstile.sitekey);
          this.#setMeta('turnstile.secret', sys.turnstile.secret);
        }
        this.#log(actorId, null, sys.turnstile ? 'turnstile.updated' : 'turnstile.cleared', sys.turnstile ? `import: sitekey=${sys.turnstile.sitekey}` : 'import');
      }
      if (S.has('public')) {
        replaceScope(PUBLIC_ID, sys.public.limits, sys.public.quotas, sys.public.viewerRules);
        this.#log(actorId, PUBLIC_ID, 'limits.updated', `import public account: ${Object.keys(sys.public.limits.all).length} limits, ${sys.public.quotas.length} quotas`);
      }
      if (S.size) this.#log(actorId, null, 'import.system', `parts=${[...S].join('+')}`);
      for (const job of jobs) {
        const { u, entry } = job;
        let id = job.id;
        if (job.create) {
          id = newId();
          const c = u.credentials;
          this.sql.exec("INSERT INTO users (id, username, role, pw_salt, pw_t, pw_verifier, disabled, created, updated) VALUES (?, ?, 'user', ?, ?, ?, ?, ?, ?)",
            id, entry.as, c.salt, c.t, c.verifier, c.disabled ? 1 : 0, ts, ts);
        }
        const did = [];
        if (job.role !== null) {
          const r = isDefault(job.role) ? null : roleHere(job.role);
          this.sql.exec('UPDATE users SET role_id = ?, updated = ? WHERE id = ?', r ? r.id : null, ts, id);
          this.#log(actorId, id, 'role.assigned', `import: role=${r ? r.name : 'Default'}`);
          did.push(`role=${r ? r.name : 'Default'}`);
        }
        if (job.apiKeys.length) {
          for (const k of job.apiKeys) {
            this.sql.exec('INSERT INTO api_keys (key_hash, id, user_id, name, created, last_used, expires, scopes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
              k.hash, newId(), id, k.name, k.created, k.lastUsed, k.expires, k.scopes.join(','));
          }
          this.#log(actorId, id, 'apikey.imported', `count=${job.apiKeys.length}`);
          did.push(`apiKeys=${job.apiKeys.length}`);
        }
        if (job.passkeys.length) {
          for (const k of job.passkeys) this.#importPasskey(id, k);
          if (job.mfa) this.sql.exec('UPDATE users SET mfa = 1 WHERE id = ?', id);
          this.#logChunks(actorId, id, 'passkeys.imported', `import${job.owner && !u ? ' (owner passkeys)' : ''}: added ${job.passkeys.length}: `, job.passkeys.map((k) => k.name));
          did.push(`passkeys+${job.passkeys.length}`);
        }
        if (job.codes.length) {
          for (const h of job.codes) this.sql.exec('INSERT INTO recovery_codes (hash, user_id, created) VALUES (?, ?, ?)', h, id, ts);
          this.#log(actorId, id, 'recovery.imported', `count=${job.codes.length}`);
          did.push(`recoveryCodes=${job.codes.length}`);
        }
        const from = u && entry.as !== u.username ? ` from=${u.username}` : '';
        const what = u ? `${job.create ? 'create' : 'update'}${from}` : 'owner';
        this.#log(actorId, id, 'user.imported', `${what}: ${did.join(' ') || 'no changes'}${!job.create && entry.skipped.length ? `; skipped ${entry.skipped.length}` : ''}`);
      }
    });
    return out(true);
  }

  /** Store an imported passkey for `uid`, keeping the user handle it was registered under. */
  #importPasskey(uid, k) {
    this.sql.exec('INSERT INTO passkeys (id, user_id, name, public_key, alg, sign_count, transports, backup_eligible, backed_up, created, last_used) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      k.id, uid, k.name, k.publicKey, k.alg, k.signCount, k.transports.join(','), k.backupEligible ? 1 : 0, k.backedUp ? 1 : 0, k.created, k.lastUsed);
    this.sql.exec('DELETE FROM meta WHERE k = ?', handleAlias(k.id));
    if (!k.handle) return;
    const cur = this.#user(uid).webauthn_handle;
    if (!cur) this.sql.exec('UPDATE users SET webauthn_handle = ? WHERE id = ?', k.handle, uid);
    else if (cur !== k.handle) this.#setMeta(handleAlias(k.id), k.handle);
  }

  /**
   * Activity-log retention: the global age and size (log.* settings), each
   * account's own limits (logMaxAgeSec / logMaxEntries, for entries about that
   * account) and the owner's own (log.ownerMaxAgeSec / log.ownerMaxEntries,
   * for entries about the owner and entries the owner made). Global settings
   * and role limits never apply to the owner's entries; server-wide
   * configuration changes are never pruned automatically at all. The owner
   * can clear any of them by hand.
   */
  #pruneLogs() {
    const s = this.#settings();
    const ts = now();
    const owner = this.#owner();
    const oid = owner ? owner.id : '';
    // Not removed by the global or per-account limits: entries about the
    // owner, entries the owner made (admin actions, impersonation) and
    // server-wide entries with no subject (settings, the Default role, roles,
    // IP rules and blocks, exports and imports, Turnstile).
    const PRUNABLE = 'subject_id IS NOT NULL AND subject_id != ? AND (actor_id IS NULL OR actor_id != ?)';
    this.sql.exec(`DELETE FROM activity WHERE ts < ? AND ${PRUNABLE}`, ts - s['log.maxAgeSec'], oid, oid);
    // Read receipts live as long as the log does.
    this.sql.exec('DELETE FROM opens WHERE ts < ? AND user_id IS NOT ?', ts - s['log.maxAgeSec'], oid);
    // The owner's own limits (null: kept until cleared). They cover entries
    // about the owner and those the owner made, never a configuration change:
    // one with no subject, or the owner configuring the public account (its
    // limits, quotas, viewer rules and browser ids).
    if (owner) {
      const PUBLIC_CONFIG = "subject_id = ? AND actor_id IS ? AND (action IN ('limits.updated', 'quotas.updated', 'viewer_rules.updated') OR action LIKE 'tracker.%')";
      const OWNED = `subject_id IS NOT NULL AND (subject_id = ? OR actor_id IS ?) AND NOT (${PUBLIC_CONFIG})`;
      const args = [oid, oid, PUBLIC_ID, oid];
      if (s['log.ownerMaxAgeSec'] !== null) {
        this.sql.exec(`DELETE FROM activity WHERE ts < ? AND ${OWNED}`, ts - s['log.ownerMaxAgeSec'], ...args);
        this.sql.exec('DELETE FROM opens WHERE user_id = ? AND ts < ?', oid, ts - s['log.ownerMaxAgeSec']);
      }
      if (s['log.ownerMaxEntries'] !== null) {
        const n = this.sql.exec(`SELECT COUNT(*) AS c FROM activity WHERE ${OWNED}`, ...args).one().c;
        if (n > s['log.ownerMaxEntries']) {
          this.sql.exec(`DELETE FROM activity WHERE id IN (SELECT id FROM activity WHERE ${OWNED} ORDER BY id ASC LIMIT ?)`, ...args, n - s['log.ownerMaxEntries']);
        }
      }
    }
    // Per-account limits: visit only the accounts they apply to (every account
    // when a global value is set, otherwise those with their own value).
    // (A row holding null means "no per-account limit".)
    const LOG_SET = "channel = 'all' AND key IN ('logMaxAgeSec', 'logMaxEntries') AND value != 'null'";
    const global = this.sql.exec(`SELECT 1 FROM limits WHERE user_id = '' AND ${LOG_SET} LIMIT 1`).toArray().length;
    const users = global
      ? this.sql.exec("SELECT * FROM users WHERE role IN ('user', 'public')").toArray()
      : this.sql.exec(`SELECT * FROM users WHERE role IN ('user', 'public') AND (id IN (SELECT user_id FROM limits WHERE ${LOG_SET})
          OR role_id IN (SELECT substr(user_id, 3) FROM limits WHERE user_id LIKE 'r:%' AND ${LOG_SET}))`).toArray();
    for (const u of users) {
      const L = this.#effective(u).all;
      if (L.logMaxAgeSec !== null) {
        this.sql.exec('DELETE FROM activity WHERE subject_id = ? AND ts < ? AND (actor_id IS NULL OR actor_id != ?)', u.id, ts - L.logMaxAgeSec, oid);
        this.sql.exec('DELETE FROM opens WHERE user_id = ? AND ts < ?', u.id, ts - L.logMaxAgeSec);
      }
      if (L.logMaxEntries !== null) {
        this.sql.exec(`DELETE FROM activity WHERE subject_id = ? AND (actor_id IS NULL OR actor_id != ?)
          AND id NOT IN (SELECT id FROM activity WHERE subject_id = ? ORDER BY id DESC LIMIT ?)`, u.id, oid, u.id, L.logMaxEntries);
      }
    }
    const count = this.sql.exec(`SELECT COUNT(*) AS c FROM activity WHERE ${PRUNABLE}`, oid, oid).one().c;
    if (count > s['log.maxEntries']) {
      this.sql.exec(`DELETE FROM activity WHERE id IN (SELECT id FROM activity WHERE ${PRUNABLE} ORDER BY id ASC LIMIT ?)`, oid, oid, count - s['log.maxEntries']);
    }
  }

  /**
   * Admin: delete log entries — all of them, or those about one account —
   * optionally only those older than `before` (unix seconds). Leaves no
   * record of the clearing (as configured). Returns the number deleted.
   */
  async clearLogs({ scope, userId, before }) {
    const where = [];
    const args = [];
    if (scope === 'user') {
      if (typeof userId !== 'string' || !this.#user(userId)) return fail(404, 'not_found', 'User not found.');
      where.push('subject_id = ?');
      args.push(userId);
    } else if (scope !== 'all') {
      return fail(400, 'invalid', 'scope must be "all" or "user"');
    }
    if (before !== undefined && before !== null) {
      if (!Number.isSafeInteger(before) || before <= 0) return fail(400, 'invalid', 'before must be a unix time in seconds');
      where.push('ts < ?');
      args.push(before);
    }
    const q = where.length ? ` WHERE ${where.join(' AND ')}` : '';
    const n = this.sql.exec(`SELECT COUNT(*) AS c FROM activity${q}`, ...args).one().c;
    this.sql.exec(`DELETE FROM activity${q}`, ...args);
    // Read receipts go with the log (same scope: the share's sender).
    const oq = q.replace('subject_id = ?', 'user_id = ?');
    const opens = this.sql.exec(`SELECT COUNT(*) AS c FROM opens${oq}`, ...args).one().c;
    this.sql.exec(`DELETE FROM opens${oq}`, ...args);
    // The open counters go too, unless only older entries were cleared (a
    // counter cannot be split by date).
    if (before === undefined || before === null) {
      if (scope === 'user') this.sql.exec('UPDATE shares SET opens_total = 0 WHERE user_id = ?', userId);
      else this.sql.exec('UPDATE shares SET opens_total = 0');
    }
    return { ok: true, deleted: n, receipts: opens };
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
    this.#pruneLogs();
    this.sql.exec('DELETE FROM revoked_sessions WHERE exp < ?', ts);
    this.sql.exec('DELETE FROM webauthn_challenges WHERE exp <= ?', ts);
    this.sql.exec('DELETE FROM webauthn_spent WHERE exp <= ?', ts);
    this.sql.exec('DELETE FROM usage WHERE ts < ?', ts - 400 * 86400);
    // Lockout counters for usernames that do not exist, once they no longer matter.
    this.sql.exec("DELETE FROM failures WHERE user_id LIKE 'n:%' AND locked_until < ? AND start < ?", ts, ts - this.#settings()['lockout.windowSec']);
    // Anonymous trackers expire after being idle, with their usage counters.
    const idleBefore = ts - this.#settings()['public.trackerIdleSec'];
    this.sql.exec("DELETE FROM usage WHERE user_id IN (SELECT 'pub:t:' || id_hash FROM trackers WHERE last_seen < ?)", idleBefore);
    this.sql.exec('DELETE FROM trackers WHERE last_seen < ?', idleBefore);
    this.sql.exec('DELETE FROM ip_rules WHERE expires IS NOT NULL AND expires < ?', ts);
    this.sql.exec("UPDATE shares SET status = 'expired' WHERE status = 'active' AND expires > 0 AND expires < ?", ts);
    this.sql.exec("DELETE FROM shares WHERE status != 'active' AND locked = 0 AND expires < ?", ts - SHARE_PRUNE_SEC);
    // Receipts go with their share: once the share row is gone nobody can see them.
    this.sql.exec('DELETE FROM opens WHERE share_id NOT IN (SELECT id FROM shares)');
    await this.ctx.storage.setAlarm(Date.now() + 3600 * 1000);
  }
}

export const SETTING_KEYS = Object.keys(SETTINGS);
