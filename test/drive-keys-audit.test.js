// drive-keys-audit.test.js — regression tests for the Drive key model v2
// security audit, part A (F1–F8): the keyring jobs and routes, in a storage
// of their own. Each test fails without its fix. Synthetic data only.
//   F1  a Drive whose only content is a reverse link is part of every job and
//       of every usage count (sub-MEK delete, root change, useRoot);
//   F2  a root change that cannot finish: the kit carries both roots, restore
//       and cancel work, the re-seal runs again, go back, or drop the old root;
//   F3  during a root change nothing new is accepted under the old root, and
//       a final check over every Drive runs before the old root goes;
//   F4  a re-seal (and an import's restore) never reverts a rename made meanwhile;
//   F5  a restored salt must open the Drive; a Drive with link keys gets no new salt;
//   F6  a sub-MEK this server never had is added only when it opens something;
//   F7  cancelling a job, and the restore / import previews, need the step-up;
//   F8  a candidate is for its purpose only; unused candidates are purged.
import { runInDurableObject } from 'cloudflare:test';
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, fetchJson, intent, proofFor, USER_PW } from './helpers.js';
import { enableDrive, mkdir, uploadRealFile, node, driveKeys, sealed, openStored } from './drive-helpers.js';
import { receiver, newReverse, openLinkPriv, driveOf, dirStub } from './reverse-helpers.js';
import { newSalt, sealName } from '../public/js/drivekeys.js';
import { b64urlFromBytes, randomBytes, utf8, fromUtf8 } from '../public/js/bytes.js';

const STEP = { current: proofFor('owner-password') };
const K = '/api/private/admin/keys';
let oc;
beforeAll(async () => { oc = await owner(); });

const post = (path, body = {}, cookie = oc) => fetchJson(path, { method: 'POST', cookie, headers: intent, body });
const del = (path, body = {}) => fetchJson(path, { method: 'DELETE', cookie: oc, headers: intent, body });
const status = async () => (await fetchJson(K, { cookie: oc })).json();
const errorOf = async (r) => (await r.json()).error;
const adminAudit = async () => (await (await fetchJson('/api/private/admin/audit?limit=500', { cookie: oc })).json()).rows;
const candidate = async (purpose) => (await (await post(`${K}/candidate`, { purpose, ...STEP })).json());
async function addSub({ rotate = true } = {}) {
  const c = await candidate('sub');
  const r = await post(`${K}/subs`, { candidate: c.id, rotate, ...STEP });
  expect(r.status, await r.clone().text()).toBe(200);
  return (await r.json()).id;
}
async function changeRoot() {
  const c = await candidate('root');
  const r = await post(`${K}/root`, { candidate: c.id, ...STEP });
  expect(r.status, await r.clone().text()).toBe(200);
  return c.fp;
}
async function runJob(until = (j) => j.finished) {
  let job = null;
  for (let n = 0; n < 400; n++) {
    ({ job } = await (await post(`${K}/jobs/step`)).json());
    if (!job || until(job)) break;
  }
  return job;
}
const linkRow = (uid, id) => runInDurableObject(driveOf(uid), (i, s) => s.storage.sql.exec('SELECT id, mek, priv FROM reverse WHERE id = ?', id).one());
/** A link's key opens with the session's KEK of the sub-MEK it names (the field layer removed by the server's listing). */
async function linkOpens(u, id) {
  const x = (await (await fetchJson('/api/private/drive/reverse', { cookie: u.cookie })).json()).reverse.find((r) => r.id === id);
  await openLinkPriv(u.cookie, id, x.priv, x.mek);
  return x.mek;
}

describe('F1: a Drive whose only content is a reverse link', () => {
  it('is counted: its sub-MEK cannot be deleted until a re-seal moved the link; the re-seal moves it', async () => {
    const u = await receiver('f1-sub');
    const r = await newReverse(u.cookie);
    expect(r.res.status).toBe(201);
    const s0 = await status();
    const old = s0.current;
    // No item, no usage row: still in the keyring's view.
    expect(await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec('SELECT COUNT(*) AS c FROM drive_usage WHERE user_id = ?', u.id).one().c)).toBe(0);
    expect((await (await fetchJson(`${K}/usage`, { cookie: oc })).json()).counts[old]).toBeGreaterThanOrEqual(1);
    const now = await addSub();
    const refused = await del(`${K}/subs/${old}`, STEP);
    expect([refused.status, await errorOf(refused)]).toEqual([409, 'in_use']);
    expect((await post(`${K}/jobs`, { from: old, remove: true, ...STEP })).status).toBe(200);
    const job = await runJob();
    expect(job.result).toMatchObject({ ok: true, removed: true });
    expect((await linkRow(u.id, r.id)).mek).toBe(now);
    expect(await linkOpens(u, r.id)).toBe(now);
  });

  it('is visited by a root change: its link key is re-sealed under the new root before the old one goes', async () => {
    const u = await receiver('f1-root');
    const r = await newReverse(u.cookie);
    const before = (await linkRow(u.id, r.id)).priv;
    await changeRoot();
    const job = await runJob();
    expect(job).toMatchObject({ kind: 'root', finished: true, failed: 0, result: { ok: true } });
    expect((await status()).root.changing).toBe(false);
    expect((await linkRow(u.id, r.id)).priv).not.toBe(before);
    await linkOpens(u, r.id); // opens under the KEK the new root gives
  });

  it('counts for useRoot: an instance with only link keys is not "empty"', async () => {
    const r = await post(`${K}/restore`, { root: { key: b64urlFromBytes(randomBytes(32)) }, useRoot: true, ...STEP });
    expect([r.status, await errorOf(r)]).toEqual([409, 'in_use']);
  });
});

describe('F2 / F3: a root change', () => {
  it('F3: a rename sealed under the previous root is refused (stale_keys); sealed under the new one it is kept, and the change finishes', async () => {
    const u = await makeUser('f3-rename');
    await enableDrive(u.id);
    const f = await mkdir(u.cookie);
    const oldKeys = await driveKeys(u.cookie, { fresh: true }); // a page loaded before the change
    await changeRoot();
    const n = (await (await node(u.cookie, f.id)).json()).node;
    const seal = async (kek) => sealName(kek, { userId: u.id, mekId: n.mek, salt: n.ks }, 'name', utf8('renamed'));
    const stale = await fetchJson(`/api/private/drive/nodes/${f.id}`, { method: 'PATCH', cookie: u.cookie, body: { name: await seal(oldKeys.keks.get(n.mek)), ks: n.ks, mek: n.mek } });
    expect([stale.status, await errorOf(stale)]).toEqual([409, 'stale_keys']);
    const fresh = await driveKeys(u.cookie, { fresh: true });
    const ok = await fetchJson(`/api/private/drive/nodes/${f.id}`, { method: 'PATCH', cookie: u.cookie, body: { name: await seal(fresh.keks.get(n.mek)), ks: n.ks, mek: n.mek } });
    expect(ok.status).toBe(200);
    // The item now mixes a name under the new root with nothing else yet re-sealed: the job takes each field under either root.
    const job = await runJob();
    expect(job.result).toMatchObject({ ok: true });
    const after = (await (await node(u.cookie, f.id)).json()).node;
    expect(fromUtf8((await openStored(u.cookie, after)).name)).toBe('renamed');
  });

  it('F3: the final check over every Drive catches anything still under the old root, and the old root stays', async () => {
    const u = await makeUser('f3-verify');
    await enableDrive(u.id);
    const f = await mkdir(u.cookie);
    const oldKek = (await driveKeys(u.cookie, { fresh: true })).keks;
    await changeRoot();
    const mid = await runJob((j) => j.verifying);
    expect(mid).toMatchObject({ verifying: true, finished: false });
    // Something wrote a name under the old root after the item was re-sealed (what the rename check now refuses).
    const n = (await (await node(u.cookie, f.id)).json()).node;
    const bad = JSON.stringify(await sealName(oldKek.get(n.mek), { userId: u.id, mekId: n.mek, salt: n.ks }, 'name', utf8('under the old root')));
    await runInDurableObject(driveOf(u.id), (i, s) => s.storage.sql.exec('UPDATE nodes SET name = ? WHERE id = ?', bad, f.id));
    const job = await runJob();
    expect(job).toMatchObject({ kind: 'root', finished: true, result: { ok: false } });
    expect(job.failedIds).toContain(f.id);
    const st = await status();
    expect(st.root.changing).toBe(true); // the old root is kept for it
    // F2: a stuck root change does not block the key kit (it holds both roots), a restore preview or clearing the finished job.
    const kit = await (await post(`${K}/kit`, STEP)).json();
    expect(kit.material.rootOld.fp).toBe(st.root.oldFp);
    expect((await post(`${K}/restore`, { root: kit.material.root, rootOld: kit.material.rootOld, ...STEP })).status).toBe(200);
    // F2: the re-seal runs again (and moves the item, which opens under the old root).
    expect((await post(`${K}/jobs`, { kind: 'root', ...STEP })).status).toBe(200);
    const again = await runJob();
    expect(again.result).toMatchObject({ ok: true });
    expect((await status()).root.changing).toBe(false);
    expect(fromUtf8((await openStored(u.cookie, (await (await node(u.cookie, f.id)).json()).node)).name)).toBe('under the old root');
  });

  it('F2: an item under neither root: retry fails again; the owner goes back to the previous root, or drops it with its fingerprint typed', async () => {
    const u = await makeUser('f2-stuck');
    await enableDrive(u.id);
    const f = await mkdir(u.cookie);
    const good = await mkdir(u.cookie);
    await runInDurableObject(driveOf(u.id), (i, s) => s.storage.sql.exec('UPDATE nodes SET name = ? WHERE id = ?', JSON.stringify({ iv: 'A'.repeat(16), ct: 'B'.repeat(43) }), f.id));
    const first = (await status()).root.fp;
    await changeRoot();
    let job = await runJob();
    expect(job).toMatchObject({ finished: true, result: { ok: false } });
    expect(job.failedIds).toContain(f.id);
    expect((await post(`${K}/jobs`, { kind: 'root' })).status).toBe(400); // the step-up
    expect((await post(`${K}/jobs`, { kind: 'root', ...STEP })).status).toBe(200);
    job = await runJob();
    expect(job.result).toMatchObject({ ok: false });
    // A new root change still waits for this one.
    const c = await candidate('root');
    expect(await errorOf(await post(`${K}/root`, { candidate: c.id, ...STEP }))).toBe('root_changing');
    // Go back: the previous root is current again, everything is re-sealed under it (the damaged item still fails).
    const undo = await post(`${K}/root/undo`, STEP);
    expect(undo.status, await undo.clone().text()).toBe(200);
    expect((await status()).root.fp).toBe(first);
    job = await runJob();
    expect(job.result).toMatchObject({ ok: false });
    expect((await openStored(u.cookie, (await (await node(u.cookie, good.id)).json()).node)).name.length).toBeGreaterThan(0);
    // Drop the root that was new: only with its fingerprint typed; the loss is recorded.
    const st = await status();
    expect(await errorOf(await post(`${K}/root/drop-old`, { confirm: 'nope', ...STEP }))).toBe('confirm');
    expect((await post(`${K}/root/drop-old`, { confirm: st.root.oldFp })).status).toBe(400); // the step-up
    const drop = await post(`${K}/root/drop-old`, { confirm: st.root.oldFp, ...STEP });
    expect(drop.status, await drop.clone().text()).toBe(200);
    expect((await status()).root).toMatchObject({ fp: first, changing: false, oldFp: null });
    expect((await adminAudit()).some((r) => r.action === 'keys.root_old_dropped' && r.detail.includes(st.root.oldFp))).toBe(true);
    // The session no longer gets an old-root KEK.
    expect((await driveKeys(u.cookie, { fresh: true })).raw.changing).toBe(false);
    // Tidy: the damaged item goes (the following tests' root changes then finish).
    expect((await fetchJson(`/api/private/drive/nodes/${f.id}`, { method: 'DELETE', cookie: u.cookie, headers: intent })).status).toBe(200);
  });

  it('F7: cancelling a re-seal needs the step-up; a root change is not cancelled while it runs', async () => {
    const u = await makeUser('f7-cancel');
    await enableDrive(u.id);
    await mkdir(u.cookie);
    const old = (await status()).current;
    await addSub();
    expect((await post(`${K}/jobs`, { from: old, ...STEP })).status).toBe(200);
    const noStep = await del(`${K}/jobs`);
    expect([noStep.status, await errorOf(noStep)]).toEqual([400, 'reauth_required']);
    expect((await status()).job).toMatchObject({ kind: 'reseal', finished: false });
    expect((await del(`${K}/jobs`, STEP)).status).toBe(200);
    expect((await status()).job).toBeNull();
  });
});

describe('F4: a re-seal never reverts a rename made meanwhile', () => {
  it('applySealed (a job, a kit restore) and restoreItem (an import) compare the stored name, metadata and DEK too', async () => {
    const u = await makeUser('f4-cas');
    await enableDrive(u.id);
    const f = await mkdir(u.cookie);
    const page = await driveOf(u.id).sealedPage(u.id, {});
    const it0 = page.items.find((x) => x.id === f.id);
    expect(it0.from.name).toBeTypeOf('string');
    // The rename lands between the job's read and its write.
    const k = await driveKeys(u.cookie, { fresh: true });
    const renamed = await sealName(k.keks.get(it0.mek), { userId: u.id, mekId: it0.mek, salt: it0.ks }, 'name', utf8('kept'));
    expect((await fetchJson(`/api/private/drive/nodes/${f.id}`, { method: 'PATCH', cookie: u.cookie, body: { name: renamed, ks: it0.ks, mek: it0.mek } })).status).toBe(200);
    // The job's write, from what it read: same mek and salt, the old name.
    const s = await sealed(u.cookie, 'dir', { keys: k, name: utf8('reverted') });
    const w = await driveOf(u.id).applySealed(u.id, { items: [{ id: f.id, ks: s.ks, mek: s.mek, mfp: 'x', name: JSON.stringify(s.name), meta: null, dek: null, fromMek: it0.mek, fromKs: it0.ks, from: it0.from }] });
    expect(w).toMatchObject({ done: 0, skipped: 1 });
    expect(fromUtf8((await openStored(u.cookie, (await (await node(u.cookie, f.id)).json()).node)).name)).toBe('kept');
    // Without `from` nothing is written at all.
    expect(await driveOf(u.id).applySealed(u.id, { items: [{ id: f.id, ks: s.ks, mek: s.mek, mfp: 'x', name: JSON.stringify(s.name), fromMek: it0.mek, fromKs: it0.ks }] })).toMatchObject({ done: 0, skipped: 1 });
    // restoreItem (a keys import) the same way.
    const file = await uploadRealFile(u.cookie, 'root', utf8('synthetic'));
    const item = (await driveOf(u.id).itemKeys(u.id, file.id)).item;
    const renamed2 = await sealName(k.keks.get(item.mek), { userId: u.id, mekId: item.mek, salt: item.ks }, 'name', utf8('kept too'));
    expect((await fetchJson(`/api/private/drive/nodes/${file.id}`, { method: 'PATCH', cookie: u.cookie, body: { name: renamed2, ks: item.ks, mek: item.mek } })).status).toBe(200);
    const r = await driveOf(u.id).restoreItem(u.id, { id: file.id, ks: s.ks, mek: s.mek, mfp: 'x', name: JSON.stringify(s.name), meta: null, dek: null, fromMek: item.mek, fromKs: item.ks, from: item.from });
    expect(r).toMatchObject({ ok: false, error: 'changed' });
    expect(fromUtf8((await openStored(u.cookie, (await (await node(u.cookie, file.id)).json()).node)).name)).toBe('kept too');
  });
});

describe('F5 / F6: what a restore or an import may add', () => {
  it('F5: a salt is restored only when it opens the Drive; a Drive that holds a link key gets no new random salt', async () => {
    const u = await makeUser('f5-salt');
    await enableDrive(u.id);
    await mkdir(u.cookie);
    const right = (await (await post(`${K}/kit`, STEP)).json()).material.salts[u.id].salt;
    await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec('DELETE FROM user_salts WHERE user_id = ?', u.id));
    const wrong = await (await post(`${K}/restore`, { salts: { [u.id]: newSalt() }, dryRun: false, ...STEP })).json();
    expect(wrong.salts).toMatchObject({ restored: 0, wrong: 1 });
    expect(await errorOf(await fetchJson('/api/private/drive/keys', { method: 'POST', cookie: u.cookie, body: {} }))).toBe('salt_missing');
    const ok = await (await post(`${K}/restore`, { salts: { [u.id]: right }, dryRun: false, ...STEP })).json();
    expect(ok.salts).toMatchObject({ restored: 1, wrong: 0 });
    expect((await fetchJson('/api/private/drive/keys', { method: 'POST', cookie: u.cookie, body: {} })).status).toBe(200);
    // Only a link key: the salt is not replaced by a new one (the link would be lost); the import checks the salt against it.
    const v = await receiver('f5-link');
    const link = await newReverse(v.cookie);
    const salt = (await (await post(`${K}/kit`, STEP)).json()).material.salts[v.id].salt;
    await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec('DELETE FROM user_salts WHERE user_id = ?', v.id));
    expect(await errorOf(await fetchJson('/api/private/drive/keys', { method: 'POST', cookie: v.cookie, body: {} }))).toBe('salt_missing');
    expect((await (await post(`${K}/restore`, { salts: { [v.id]: newSalt() }, ...STEP })).json()).salts).toMatchObject({ restored: 0, wrong: 1 });
    expect((await (await post(`${K}/restore`, { salts: { [v.id]: salt }, dryRun: false, ...STEP })).json()).salts).toMatchObject({ restored: 1 });
    await linkOpens(v, link.id);
    // An empty Drive still gets one (nothing to lose).
    const w = await makeUser('f5-empty');
    await enableDrive(w.id);
    await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec('DELETE FROM user_salts WHERE user_id = ?', w.id));
    expect((await fetchJson('/api/private/drive/keys', { method: 'POST', cookie: w.cookie, body: {} })).status).toBe(200);
  });

  it('F5: the personal kit restore checks a salt against a link key too', async () => {
    const v = await receiver('f5-kit');
    const link = await newReverse(v.cookie);
    const kit = (await (await post('/api/private/drive/kit', { current: proofFor(USER_PW) }, v.cookie)).json()).kit;
    await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec('DELETE FROM user_salts WHERE user_id = ?', v.id));
    const restore = (salt) => post('/api/private/drive/kit/restore', { salt, current: proofFor(USER_PW) }, v.cookie);
    expect((await (await restore(newSalt())).json()).salt).toBe('wrong');
    expect((await (await restore(kit.userSalt)).json()).salt).toBe('restored');
    await linkOpens(v, link.id);
  });

  it('F6: a sub-MEK id this server never had is added only when it opens something sealed under it here', async () => {
    const unknown = `m${b64urlFromBytes(randomBytes(8))}`;
    const r = await (await post(`${K}/restore`, { subs: [{ id: unknown, key: b64urlFromBytes(randomBytes(32)), from: 1, until: 2 }], dryRun: false, ...STEP })).json();
    expect(r.subs).toEqual([{ id: unknown, result: expect.stringMatching(/^unused/) }]);
    expect((await status()).subs.some((s) => s.id === unknown)).toBe(false);
    // A lost sub-MEK (items still name it): a wrong key is refused, the right one comes back.
    const u = await makeUser('f6-lost');
    await enableDrive(u.id);
    const f = await mkdir(u.cookie);
    const m = (await (await post(`${K}/kit`, STEP)).json()).material;
    const cur = m.subs.find((s) => s.id === m.current);
    // Keep the timeline valid: another sub-MEK is current before this one is lost.
    await addSub();
    await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec('DELETE FROM meks WHERE id = ?', cur.id));
    const wrong = await (await post(`${K}/restore`, { subs: [{ ...cur, key: b64urlFromBytes(randomBytes(32)) }], dryRun: false, ...STEP })).json();
    expect(wrong.subs[0].result).toMatch(/^wrong/);
    const right = await (await post(`${K}/restore`, { subs: [cur], dryRun: false, ...STEP })).json();
    expect(right.subs[0].result).toMatch(/^added/);
    expect((await openStored(u.cookie, (await (await node(u.cookie, f.id)).json()).node)).name.length).toBeGreaterThan(0);
  });

  it('F7: the restore and import previews need the step-up', async () => {
    const r = await post(`${K}/restore`, { salts: {} });
    expect([r.status, await errorOf(r)]).toEqual([400, 'reauth_required']);
    const i = await post(`${K}/import`, { document: { format: 'secbin-keys-export/1', users: [] } });
    expect([i.status, await errorOf(i)]).toEqual([400, 'reauth_required']);
  });
});

describe('F8: key candidates', () => {
  it('a candidate is used only for its purpose; expired ones are purged on the next keyring call', async () => {
    const root = await candidate('root');
    const asSub = await post(`${K}/subs`, { candidate: root.id, ...STEP });
    expect([asSub.status, await errorOf(asSub)]).toEqual([409, 'candidate_purpose']);
    const sub = await candidate('sub');
    const asRoot = await post(`${K}/root`, { candidate: sub.id, ...STEP });
    expect([asRoot.status, await errorOf(asRoot)]).toEqual([409, 'candidate_purpose']);
    expect(await errorOf(await post(`${K}/candidate`, { purpose: 'other', ...STEP }))).toBe('invalid');
    // Expired: gone at the next status read, without a new candidate being made.
    await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec('UPDATE mek_candidates SET exp = 1'));
    expect(await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec('SELECT COUNT(*) AS c FROM mek_candidates').one().c)).toBeGreaterThan(0);
    await status();
    expect(await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec('SELECT COUNT(*) AS c FROM mek_candidates').one().c)).toBe(0);
  });
});
