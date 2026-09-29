// migration17.test.js — audit C2: migration 17 carries each role's regular
// maxExpireSec into its new reverseMaxExpireSec, also when a Directory
// several releases old runs steps 10–15 (which fill in the Default role with
// today's defaults: no limit) before 17 in the same upgrade. In Directories
// of their own; synthetic data only.
import { env, runInDurableObject } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import { SCHEMA_VERSION } from '../src/directory-do.js';

// The Directory's schema before migrations existed (aec1571^).
const V0 = `
CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, role TEXT NOT NULL,
  pw_salt TEXT NOT NULL, pw_t INTEGER NOT NULL, pw_verifier TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0,
  sess_ver INTEGER NOT NULL DEFAULT 1, created INTEGER NOT NULL, updated INTEGER NOT NULL);
CREATE TABLE limits (user_id TEXT NOT NULL, channel TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (user_id, channel, key));
CREATE TABLE quotas (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, channel TEXT NOT NULL, kind TEXT NOT NULL, n INTEGER NOT NULL, unit TEXT NOT NULL, max INTEGER NOT NULL);
CREATE TABLE usage (quota_id TEXT NOT NULL, user_id TEXT NOT NULL, bucket INTEGER NOT NULL, count INTEGER NOT NULL, ts INTEGER NOT NULL, PRIMARY KEY (quota_id, user_id, bucket));
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE viewer_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, match TEXT NOT NULL, value TEXT NOT NULL, renderer TEXT NOT NULL);
CREATE TABLE api_keys (key_hash TEXT PRIMARY KEY, id TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL, name TEXT NOT NULL, created INTEGER NOT NULL, last_used INTEGER, expires INTEGER);
CREATE TABLE revoked_sessions (sid TEXT PRIMARY KEY, exp INTEGER NOT NULL);
CREATE TABLE failures (user_id TEXT PRIMARY KEY, count INTEGER NOT NULL, start INTEGER NOT NULL, locked_until INTEGER NOT NULL DEFAULT 0);
CREATE TABLE activity (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, actor_id TEXT, subject_id TEXT, action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', imp INTEGER NOT NULL DEFAULT 0);
CREATE INDEX activity_subject ON activity(subject_id, id);
CREATE TABLE shares (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, kind TEXT NOT NULL, label TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL, expires INTEGER NOT NULL, views_total INTEGER, status TEXT NOT NULL);
CREATE INDEX shares_user ON shares(user_id, created);
CREATE TABLE ip_rules (id TEXT PRIMARY KEY, cidr TEXT NOT NULL, action TEXT NOT NULL, expires INTEGER, note TEXT NOT NULL DEFAULT '', created INTEGER NOT NULL);
CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
`;

const stub = (name) => env.DIRECTORY.get(env.DIRECTORY.idFromName(name));
/** A new instance of the Directory (as after a deploy): its constructor runs the migrations. */
const restart = (name) => runInDurableObject(stub(name), (i, s) => { try { s.abort('restart'); } catch { /* the instance ends here */ } }).catch(() => {});
const reverseBounds = (name) => runInDurableObject(stub(name), (i, s) => s.storage.sql
  .exec("SELECT user_id, channel, value FROM limits WHERE key = 'reverseMaxExpireSec' ORDER BY user_id, channel").toArray());
const version = (name) => runInDurableObject(stub(name), (i, s) => s.storage.sql.exec("SELECT v FROM meta WHERE k = 'schema_version'").one().v);

describe('migration 17 on a multi-version upgrade (audit C2)', () => {
  it('the schema is at 20 (17, then 18: the Receive kinds in the Default role, 19: sign-in records sealed, records.test.js, 20: failed sign-ins logged, audit-w3a.test.js); the runs below go through all of them', () => {
    expect(SCHEMA_VERSION).toBe(20);
  });

  it('from the oldest schema (0 → 17 in one run): the Default role keeps its bound for reverse shares, per channel', async () => {
    const name = 'm17-from-v0';
    await runInDurableObject(stub(name), (i, s) => {
      const sql = s.storage.sql;
      for (const t of sql.exec("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%'").toArray()) sql.exec(`DROP TABLE IF EXISTS ${t.name}`);
      for (const stmt of V0.split(';').map((x) => x.trim()).filter(Boolean)) sql.exec(stmt);
      const ts = 1700000000;
      sql.exec("INSERT INTO users VALUES ('owner0000000000A', 'owner', 'owner', 'AAAAAAAAAAAAAAAAAAAAAA', 3, 'x', 0, 1, ?, ?)", ts, ts);
      sql.exec("INSERT INTO users VALUES ('user00000000000B', 'alice', 'user', 'AAAAAAAAAAAAAAAAAAAAAA', 3, 'y', 0, 1, ?, ?)", ts, ts);
      sql.exec("INSERT INTO limits VALUES ('', 'all', 'maxExpireSec', '86400')");
      sql.exec("INSERT INTO limits VALUES ('', 'api', 'maxExpireSec', '3600')");
      sql.exec("INSERT INTO meta VALUES ('secret', 'c3ludGhldGljLXNlY3JldC1mb3ItdGhlLXRlc3Qtb25seQ')");
    });
    await restart(name);
    expect(await version(name)).toBe(String(SCHEMA_VERSION));
    expect(await reverseBounds(name)).toEqual([{ user_id: '', channel: 'all', value: '86400' }, { user_id: '', channel: 'api', value: '3600' }]);
    // Once migrated, nothing runs again: a value the owner sets afterwards stays.
    await runInDurableObject(stub(name), (i, s) => { s.storage.sql.exec("UPDATE limits SET value = 'null' WHERE user_id = '' AND channel = 'all' AND key = 'reverseMaxExpireSec'"); });
    await restart(name);
    expect((await reverseBounds(name))[0]).toEqual({ user_id: '', channel: 'all', value: 'null' });
  });

  it('from schema 13 (14 → 17 in one run): the Default role and a custom role keep theirs; a role without one gets none', async () => {
    const name = 'm17-from-v13';
    await runInDurableObject(stub(name), (i, s) => {
      const sql = s.storage.sql;
      // As release 13 left it: no option of 14–17 in the Default role, schema version 13.
      sql.exec("DELETE FROM limits WHERE key IN ('reverseEnabled', 'reverseMaxActive', 'reverseMaxBytes', 'shareCaptcha', 'shareCaptchaDefault', 'reverseCaptcha', 'reverseCaptchaDefault', "
        + "'reverseMaxExpireSec', 'reverseNoExpiry', 'reverseMaxViews', 'reverseAllowUnlimitedViews', 'reversePassword', 'reversePasswordDefault', 'reverseEdit')");
      sql.exec("INSERT OR REPLACE INTO limits (user_id, channel, key, value) VALUES ('', 'all', 'maxExpireSec', '86400')");
      sql.exec("INSERT INTO roles (id, name, own_quotas, created, updated) VALUES ('roleAAAAAAAAAAAA', 'short', 0, 1, 1), ('roleBBBBBBBBBBBB', 'plain', 0, 1, 1)");
      sql.exec("INSERT INTO limits (user_id, channel, key, value) VALUES ('r:roleAAAAAAAAAAAA', 'all', 'maxExpireSec', '7200'), ('r:roleAAAAAAAAAAAA', 'api', 'maxExpireSec', '600')");
      sql.exec("UPDATE meta SET v = '13' WHERE k = 'schema_version'");
    });
    await restart(name);
    expect(await version(name)).toBe(String(SCHEMA_VERSION));
    expect(await reverseBounds(name)).toEqual([
      { user_id: '', channel: 'all', value: '86400' },
      { user_id: 'r:roleAAAAAAAAAAAA', channel: 'all', value: '7200' },
      { user_id: 'r:roleAAAAAAAAAAAA', channel: 'api', value: '600' },
    ]);
  });

  it('from schema 16 (17 alone, the usual path): unchanged', async () => {
    const name = 'm17-from-v16';
    await runInDurableObject(stub(name), (i, s) => {
      const sql = s.storage.sql;
      sql.exec("DELETE FROM limits WHERE key = 'reverseMaxExpireSec'");
      sql.exec("INSERT OR REPLACE INTO limits (user_id, channel, key, value) VALUES ('', 'all', 'maxExpireSec', '86400')");
      sql.exec("UPDATE meta SET v = '16' WHERE k = 'schema_version'");
    });
    await restart(name);
    expect(await reverseBounds(name)).toEqual([{ user_id: '', channel: 'all', value: '86400' }]);
  });
});
