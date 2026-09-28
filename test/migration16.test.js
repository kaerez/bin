// migration16.test.js — audit B X1: the Directory's migrations from the state
// the release before left (main at 8889932: schema version 15, the CAPTCHA
// migration its last) through migration 16, the Drive key model v2, in a
// storage of its own: every existing account gets a user salt, every Drive
// that may hold something of the release before waits for its upgrade, and
// every Drive opens (its KEKs come from the server). Synthetic data only.
import { runInDurableObject } from 'cloudflare:test';
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, fetchJson } from './helpers.js';
import { enableDrive } from './drive-helpers.js';
import { dirStub, driveOf } from './reverse-helpers.js';
import { SCHEMA_VERSION } from '../src/directory-do.js';
import { b64urlFromBytes, randomBytes } from '../public/js/bytes.js';

let oc;
beforeAll(async () => { oc = await owner(); });

describe('migration 16 from the Directory the release before left', () => {
  it('is the last migration, after #65\'s CAPTCHA (15)', () => {
    expect(SCHEMA_VERSION).toBe(16);
  });

  it('every account gets a salt; the Drives that may hold anything of the release before wait; every Drive opens', async () => {
    const withDrive = await makeUser('m16-drive');
    await enableDrive(withDrive.id);
    const plain = await makeUser('m16-nodrive');
    const ownerId = (await (await fetchJson('/api/private/me', { cookie: oc })).json()).user.id;
    // A Drive of the release before: one folder its DK sealed (the usage row, as that release kept it).
    await runInDurableObject(driveOf(withDrive.id), (i, s) => {
      s.storage.sql.exec("INSERT INTO nodes (id, parent, kind, name, state, created, updated) VALUES (?, 'root', 'dir', ?, 'ready', 1, 1)", b64urlFromBytes(randomBytes(16)), JSON.stringify({ iv: 'A'.repeat(16), ct: 'B'.repeat(40) }));
    });
    await dirStub().setDriveUsed(withDrive.id, 100);
    // The Directory as main left it: none of migration 16's tables or keys, schema version 15.
    await runInDurableObject(dirStub(), (i, s) => {
      const sql = s.storage.sql;
      for (const t of ['meks', 'user_salts', 'mek_candidates', 'drive_migration']) sql.exec(`DROP TABLE IF EXISTS ${t}`);
      sql.exec("DELETE FROM meta WHERE k LIKE 'mek.%'");
      sql.exec("UPDATE meta SET v = '15' WHERE k = 'schema_version'");
    });
    // A new instance of the Directory (as after a deploy): its constructor runs the migrations.
    await runInDurableObject(dirStub(), (i, s) => { try { s.abort('restart'); } catch { /* the instance ends here */ } }).catch(() => {});
    const after = await runInDurableObject(dirStub(), (i, s) => {
      const sql = s.storage.sql;
      return {
        version: sql.exec("SELECT v FROM meta WHERE k = 'schema_version'").one().v,
        salts: sql.exec('SELECT user_id FROM user_salts').toArray().map((r) => r.user_id),
        pending: sql.exec("SELECT user_id FROM drive_migration WHERE state = 'pending'").toArray().map((r) => r.user_id),
      };
    });
    expect(after.version).toBe(String(SCHEMA_VERSION));
    expect(after.salts).toEqual(expect.arrayContaining([ownerId, withDrive.id, plain.id]));
    expect(after.pending).toEqual(expect.arrayContaining([ownerId, withDrive.id]));
    expect(after.pending).not.toContain(plain.id); // no Drive usage, no escrow wrap: nothing to upgrade
    // Every Drive opens: the keyring is made on first need, the KEKs come from the server.
    const keys = await fetchJson('/api/private/drive/keys', { method: 'POST', cookie: withDrive.cookie, body: {} });
    expect(keys.status, await keys.clone().text()).toBe(200);
    expect((await keys.json()).keys.length).toBeGreaterThan(0);
    const st = await (await fetchJson('/api/private/drive', { cookie: withDrive.cookie })).json();
    expect(st.migration).toMatchObject({ pending: true, v1Items: 1 });
    expect((await fetchJson('/api/private/drive/keys', { method: 'POST', cookie: oc, body: {} })).status).toBe(200);
  });
});
