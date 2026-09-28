// drive-keys-reaudit.test.js — regression tests for the re-audit of the Drive
// key model v2 (after audits A and B), in a storage of their own. Each test
// fails without its fix. Synthetic data only.
//   N1  a previous root MEK from a key kit is put back only when it opens
//       something here, and "Go back" leads only to a root this server worked
//       with or one that opens items here;
//   N2  removing the previous root says (and logs) how many items stay
//       unreadable, from the root change's own check, even after its job was
//       cleared; with no check yet it waits for the re-seal;
//   N5  a Drive holding something of the release before with no upgrade row
//       waits for its upgrade (and can finish it);
//   M4  the owner's own old wraps stay while a Drive waits, after regenerated
//       recovery codes or a removed passkey too.
import { runInDurableObject } from 'cloudflare:test';
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, fetchJson, intent, proofFor } from './helpers.js';
import { enableDrive, mkdir, driveKeys } from './drive-helpers.js';
import { driveOf, dirStub } from './reverse-helpers.js';
import { b64urlFromBytes, randomBytes } from '../public/js/bytes.js';

const STEP = { current: proofFor('owner-password') };
const K = '/api/private/admin/keys';
let oc;
let ownerId;
beforeAll(async () => {
  oc = await owner();
  ownerId = (await (await fetchJson('/api/private/me', { cookie: oc })).json()).user.id;
});
const post = (path, body = {}, cookie = oc) => fetchJson(path, { method: 'POST', cookie, headers: intent, body });
const del = (path, body = {}) => fetchJson(path, { method: 'DELETE', cookie: oc, headers: intent, body });
const status = async () => (await fetchJson(K, { cookie: oc })).json();
const adminAudit = async () => (await (await fetchJson('/api/private/admin/audit?limit=500', { cookie: oc })).json()).rows;
const dirMeta = (k) => runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec('SELECT v FROM meta WHERE k = ?', k).toArray()[0]?.v ?? null);
async function runJob() {
  let job = null;
  for (let n = 0; n < 400; n++) {
    ({ job } = await (await post(`${K}/jobs/step`)).json());
    if (!job || job.finished) break;
  }
  return job;
}
async function changeRoot() {
  const c = await (await post(`${K}/candidate`, { purpose: 'root', ...STEP })).json();
  const r = await post(`${K}/root`, { candidate: c.id, ...STEP });
  expect(r.status, await r.clone().text()).toBe(200);
  return c.fp;
}
/** An item whose name opens under no key (a damaged seal): the root change's check fails on it. */
const damage = (uid, id) => runInDurableObject(driveOf(uid), (i, s) => s.storage.sql.exec('UPDATE nodes SET name = ? WHERE id = ?', JSON.stringify({ iv: 'A'.repeat(16), ct: 'B'.repeat(43) }), id));
const removeNode = (u, id) => fetchJson(`/api/private/drive/nodes/${id}`, { method: 'DELETE', cookie: u.cookie, headers: intent });

describe('the previous root MEK (re-audit N1, N2)', () => {
  it('N1: a key kit\'s previous root that opens nothing here is reported unused and not written', async () => {
    const u = await makeUser('n1-user');
    await enableDrive(u.id);
    await mkdir(u.cookie);
    const kit = (await (await post(`${K}/kit`, STEP)).json()).material;
    const foreign = b64urlFromBytes(randomBytes(32)); // a key of the file's author: opens nothing here
    for (const dryRun of [true, false]) {
      const r = await (await post(`${K}/restore`, { root: kit.root, rootOld: { key: foreign }, dryRun, ...STEP })).json();
      expect(r.rootOld, `dryRun ${dryRun}`).toMatch(/^unused/);
      expect(r.changed).toBe(false);
    }
    const st = await status();
    expect(st.root.changing).toBe(false);
    expect(await dirMeta('mek.rootOld')).toBeNull();
    const k = await driveKeys(u.cookie, { fresh: true });
    expect(k.raw.keys.some((x) => typeof x.kekOld === 'string')).toBe(false);
    // Root changes are not blocked by it.
    const fp = await changeRoot();
    expect((await runJob()).result).toMatchObject({ ok: true });
    expect((await status()).root.fp).toBe(fp);
  });

  it('N1: a previous root that opens items here is put back; "Go back" then checks it opens them before switching', async () => {
    const u = await makeUser('n1-proven');
    await enableDrive(u.id);
    await mkdir(u.cookie);
    const before = (await status()).root.fp;
    // A root change whose re-seal has not run yet: every item is still under the previous root.
    await changeRoot();
    const kit = (await (await post(`${K}/kit`, STEP)).json()).material;
    expect(kit.rootOld).toBeTruthy();
    // The Directory loses the previous root (and the job record): only the kit has it.
    await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec("DELETE FROM meta WHERE k IN ('mek.rootOld', 'mek.job')"));
    const r = await (await post(`${K}/restore`, { root: kit.root, rootOld: kit.rootOld, dryRun: false, ...STEP })).json();
    expect(r.rootOld).toBe('restored');
    const st = await status();
    expect(st.root).toMatchObject({ changing: true, oldFp: before, oldOrigin: 'restored', check: null });
    // Going back: it still opens the items, so the roots swap.
    const undo = await post(`${K}/root/undo`, STEP);
    expect(undo.status, await undo.clone().text()).toBe(200);
    expect((await runJob()).result).toMatchObject({ ok: true });
    expect((await status()).root).toMatchObject({ fp: before, changing: false });
  });

  it('N1: "Go back" to a previous root that opens nothing here is refused (409 unproven_root); the root stays', async () => {
    const u = await makeUser('n1b-user');
    await enableDrive(u.id);
    await mkdir(u.cookie);
    const st0 = await status();
    // A previous root that did not come from this server's root change (as a restore before the fix left it).
    const foreign = b64urlFromBytes(randomBytes(32));
    await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec("INSERT OR REPLACE INTO meta (k, v) VALUES ('mek.rootOld', ?)", JSON.stringify({ key: foreign, fp: 'foreignfpAAA', created: 1, origin: 'restored' })));
    expect((await status()).root).toMatchObject({ changing: true, oldOrigin: 'restored' });
    const undo = await post(`${K}/root/undo`, STEP);
    expect([undo.status, (await undo.json()).error]).toEqual([409, 'unproven_root']);
    const shown = (await (await post(`${K}/root/show`, STEP)).json()).key;
    expect(shown).not.toBe(foreign);
    expect((await status()).root.fp).toBe(st0.root.fp);
    // The re-seal finishes the change (nothing is under that key) and it goes.
    expect((await post(`${K}/jobs`, { kind: 'root', ...STEP })).status).toBe(200);
    expect((await runJob()).result).toMatchObject({ ok: true });
    expect(await dirMeta('mek.rootOld')).toBeNull();
  });

  it('N2: after the failed root job was cleared, removing the previous root says and logs how many items stay unreadable', async () => {
    const u = await makeUser('n2-user');
    await enableDrive(u.id);
    const f = await mkdir(u.cookie);
    await damage(u.id, f.id);
    await changeRoot();
    const job = await runJob();
    expect(job).toMatchObject({ finished: true, failed: 1, result: { ok: false } });
    expect((await status()).root.check).toMatchObject({ failed: 1, ids: [f.id] });
    // A finished root job can be cleared; the count stays with the root change.
    expect((await del(`${K}/jobs`, STEP)).status).toBe(200);
    const st = await status();
    expect(st.job).toBeNull();
    expect(st.root.check).toMatchObject({ failed: 1 });
    const drop = await (await post(`${K}/root/drop-old`, { confirm: st.root.oldFp, ...STEP })).json();
    expect(drop).toMatchObject({ ok: true, lost: 1, ids: [f.id] });
    const row = (await adminAudit()).find((x) => x.action === 'keys.root_old_dropped' && x.detail.includes(st.root.oldFp));
    expect(row.detail).toMatch(new RegExp(`items left unreadable: 1 \\(${f.id}\\)$`));
    expect(await dirMeta('mek.rootCheck')).toBeNull();
    expect((await removeNode(u, f.id)).status).toBe(200);
  });

  it('N2: with no check of the two roots yet, removing the previous root waits for the re-seal (409 not_checked)', async () => {
    const u = await makeUser('n2b-user');
    await enableDrive(u.id);
    const f = await mkdir(u.cookie);
    await changeRoot();
    const kit = (await (await post(`${K}/kit`, STEP)).json()).material;
    await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec("DELETE FROM meta WHERE k IN ('mek.rootOld', 'mek.job')"));
    expect((await (await post(`${K}/restore`, { root: kit.root, rootOld: kit.rootOld, dryRun: false, ...STEP })).json()).rootOld).toBe('restored');
    const st = await status();
    const drop = await post(`${K}/root/drop-old`, { confirm: st.root.oldFp, ...STEP });
    expect([drop.status, (await drop.json()).error]).toEqual([409, 'not_checked']);
    expect((await status()).root.changing).toBe(true);
    // The re-seal checks every item and finishes the change.
    expect((await post(`${K}/jobs`, { kind: 'root', ...STEP })).status).toBe(200);
    expect((await runJob()).result).toMatchObject({ ok: true });
    expect((await status()).root.changing).toBe(false);
    expect((await removeNode(u, f.id)).status).toBe(200);
  });
});

describe('the upgrade (re-audit N5 and the M4 leftover)', () => {
  it('N5: a Drive holding an item of the release before with no upgrade row waits for its upgrade', async () => {
    const u = await makeUser('n5-user');
    await enableDrive(u.id);
    await runInDurableObject(driveOf(u.id), (i, s) => {
      s.storage.sql.exec("INSERT INTO nodes (id, parent, kind, name, state, created, updated) VALUES (?, 'root', 'dir', ?, 'ready', 1, 1)", b64urlFromBytes(randomBytes(16)), JSON.stringify({ iv: 'A'.repeat(16), ct: 'B'.repeat(40) }));
    });
    await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec('DELETE FROM drive_migration WHERE user_id = ?', u.id));
    const m = await (await fetchJson('/api/private/drive/migrate', { cookie: u.cookie })).json();
    expect(m).toMatchObject({ state: 'pending', v1Items: 1 });
    const row = await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec('SELECT state, v1_items FROM drive_migration WHERE user_id = ?', u.id).toArray()[0]);
    expect(row).toMatchObject({ state: 'pending', v1_items: 1 });
    // An upload of re-sealed items is taken (not "already upgraded"): the upgrade can finish.
    const put = await fetchJson('/api/private/drive/migrate', { method: 'PUT', cookie: u.cookie, headers: intent, body: { items: [] } });
    expect([put.status, (await put.json()).error]).toEqual([400, 'invalid']);
    // A finished upgrade is not set back.
    await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec("UPDATE drive_migration SET state = 'done' WHERE user_id = ?", u.id));
    await fetchJson('/api/private/drive/migrate', { cookie: u.cookie });
    expect(await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec('SELECT state FROM drive_migration WHERE user_id = ?', u.id).one().state)).toBe('done');
    await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec('DELETE FROM drive_migration WHERE user_id = ?', u.id));
    await runInDurableObject(driveOf(u.id), (i, s) => s.storage.sql.exec('DELETE FROM nodes WHERE mek IS NULL AND id != ?', 'root'));
  });

  it('M4: the owner\'s own old wraps stay while a Drive waits, after the owner removes their passkeys and codes too; then they go', async () => {
    const waiting = await makeUser('m4-waiting');
    await enableDrive(waiting.id);
    await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec("INSERT OR REPLACE INTO drive_migration (user_id, state, v1_items, v1_links, updated) VALUES (?, 'pending', 1, 0, 1)", waiting.id));
    await fetchJson('/api/private/drive/keys', { method: 'POST', cookie: oc, body: {} }); // the owner's Drive exists
    const wraps = () => runInDurableObject(driveOf(ownerId), (i, s) => s.storage.sql.exec('SELECT kind FROM wraps ORDER BY kind').toArray().map((r) => r.kind));
    await runInDurableObject(driveOf(ownerId), (i, s) => {
      s.storage.sql.exec("INSERT INTO wraps (kind, ref, data) VALUES ('passkey', 'goneOwnerPasskey', 'x')");
      s.storage.sql.exec("INSERT INTO wraps (kind, ref, data) VALUES ('recovery', 'goneOwnerCodeRef', 'x')");
    });
    // The owner's "remove all passkeys" on their own account (the same pruning as regenerated codes or a removed passkey).
    const regen = await post(`/api/private/admin/users/${ownerId}/passkeys`, STEP);
    expect(regen.status, await regen.clone().text()).toBe(200);
    expect(await wraps()).toEqual(['passkey', 'recovery']);
    // Nothing waits any more: the next change prunes them as before.
    await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec("UPDATE drive_migration SET state = 'done' WHERE user_id = ?", waiting.id));
    const again = await post(`/api/private/admin/users/${ownerId}/passkeys`, STEP);
    expect(again.status, await again.clone().text()).toBe(200);
    expect(await wraps()).toEqual([]);
  });
});
