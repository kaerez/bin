// drive-upgrade-audit.test.js — regression tests for the Drive key model v2
// security audit, part B: the upgrade of Drives made before it (docs/
// DRIVE.md §3.3), in workerd with the real server and browser code, in a
// storage of its own. Each test fails without its fix. Synthetic data only.
//   M1  a root change waits while a Drive has something of the release before
//       left; a link key an earlier root change wrapped at rest still upgrades;
//   M2  a link the old key does not open (damaged, or paused by a start over)
//       is retired (the step-up) so that the upgrade finishes;
//   M4  AUTHN owner recovery keeps the owner's old wraps while a Drive waits;
//       a passkey the owner removes, or codes the owner replaces, lose theirs
//       at once all the same (the maintainer's rule), and a waiting Drive
//       still upgrades through the escrow;
//   L1  a finished upgrade stays finished (a late PUT is refused);
//   L2  a disabled account's Drive is upgraded too; deleting the last waiting
//       account cleans the escrow of the release before up;
//   L3  the old Drive key leaves the tab once nothing waits;
//   L5  the owner's archive of the release before is not counted, and can be deleted;
//   L6  the wrap hygiene while a Drive waits: recovery codes regenerated, an
//       admin "remove all passkeys", a self password change.
import { env, SELF, runInDurableObject } from 'cloudflare:test';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { ORIGIN, AUTHN, owner, setOwnerCookie, login, makeUser, fetchJson, intent, proofFor, salt16, USER_PW, freshIp } from './helpers.js';
import { enableDrive, driveKeys, openStored, node } from './drive-helpers.js';
import { openLinkPriv, driveOf, dirStub } from './reverse-helpers.js';
import * as main from './fixtures/drivekeys-main.js';
import { upgradeOwnDrive, upgradeUserDrive, retireLinks } from '../public/js/driveupgrade.js';
import { saveLegacyKey, loadLegacyKey } from '../public/js/drivev1.js';
import { bindSession } from '../public/js/api.js';
import { sealAtRest, keyBytes } from '../public/js/drivekeys.js';
import { createReverseKey, linkHash } from '../public/js/reversekeys.js';
import { driveChunkKey } from '../src/drive-do.js';
import { b64urlFromBytes, randomBytes, utf8 } from '../public/js/bytes.js';
import { importFileKey, encryptChunk } from '../public/js/files.js';
import worker from '../src/index.js';

const CODE = 'ABCD-EFGH-JKMN-PQRS';
let OWNER_PW = 'owner-password';
const ownerStep = () => ({ current: proofFor(OWNER_PW) });
const K = '/api/private/admin/keys';
let oc;
let ownerId;
let escrow;
let ownerDk;
let ownerDrive;
const realFetch = globalThis.fetch;
let as = null;
const store = new Map();
const now = () => Math.floor(Date.now() / 1000);
const nid = () => b64urlFromBytes(randomBytes(16));
const rid = () => `r${b64urlFromBytes(randomBytes(16)).slice(0, 22)}`;
async function actAs(cookie) { as = cookie; bindSession(await (await fetchJson('/api/private/me', { cookie })).json()); }

/**
 * `uid`'s Drive as the release before made it: `items` folders, a file of real
 * ciphertext, a link DK sealed, optionally a link whose key another DK sealed
 * (`damaged`: it opens under nothing here; with `paused`, as a start over left
 * it, with an archive holding a received file), the wraps (a recovery code
 * and, with `passkey`, a passkey's; the escrow wrap for a user), the key check
 * value; the Directory's escrow records and the "pending" row.
 */
async function legacyDrive(uid, dk, { isOwner = false, items = 1, file = true, link = true, damaged = false, paused = false, passkey = null, recoveryRef = null } = {}) {
  const k = await main.deriveSubkeys(dk);
  const t = now();
  const out = { dk, folders: [], file: null, link: null, bad: null, archived: null };
  const rows = [];
  for (let i = 0; i < items; i++) {
    const id = nid();
    out.folders.push(id);
    rows.push({ id, kind: 'dir', name: JSON.stringify(await main.sealField(k.names, 'name', id, `Folder ${i}`)), meta: null, size: 0, chunks: 0, fk: null });
  }
  if (file) {
    const id = nid();
    const plain = utf8(`synthetic content of ${uid}`);
    const fk = randomBytes(32);
    rows.push({ id, kind: 'file', name: JSON.stringify(await main.sealField(k.names, 'name', id, 'report.txt')),
      meta: JSON.stringify(await main.sealField(k.names, 'meta', id, JSON.stringify({ type: 'text/plain', mtime: 1, size: plain.length }))), size: plain.length, chunks: 1,
      fk: JSON.stringify(await main.sealField(k.files, 'fk', id, fk)) });
    await env.FILES.put(driveChunkKey(uid, id, 0), await encryptChunk(await importFileKey(b64urlFromBytes(fk)), 0, 1, plain));
    out.file = { id, fk, plain };
  }
  const links = [];
  if (link) {
    const { pub, privateKey } = await createReverseKey();
    out.link = { id: rid(), pub };
    links.push({ id: out.link.id, priv: JSON.stringify(await main.sealReversePriv(dk, out.link.id, privateKey)), lh: await linkHash(pub), agen: null });
  }
  if (damaged || paused) {
    const { pub, privateKey } = await createReverseKey();
    out.bad = rid();
    links.push({ id: out.bad, priv: JSON.stringify(await main.sealReversePriv(main.createDriveKey(), out.bad, privateKey)), lh: await linkHash(pub), agen: paused ? 1 : null });
  }
  const wraps = [await main.wrapRecovery(dk, CODE, recoveryRef ?? undefined)];
  if (passkey) wraps.push(await main.wrapPrf(dk, randomBytes(32), passkey));
  if (!isOwner) wraps.push(await main.wrapEscrow(dk, escrow.publicJwk));
  const kcv = await main.keyCheckValue(dk);
  const escrowPriv = isOwner ? await main.sealEscrowPriv(dk, escrow.privateKey) : null;
  if (paused) {
    const id = nid();
    const bytes = utf8('kept in the archive');
    await env.FILES.put(driveChunkKey(uid, id, 0), bytes);
    out.archived = { id, size: bytes.length };
  }
  await runInDurableObject(driveOf(uid), (inst, state) => {
    const sql = state.storage.sql;
    for (const r of rows) sql.exec("INSERT INTO nodes (id, parent, kind, name, meta, size, chunks, fk, state, created, updated) VALUES (?, 'root', ?, ?, ?, ?, ?, ?, 'ready', ?, ?)", r.id, r.kind, r.name, r.meta, r.size, r.chunks, r.fk, t, t);
    for (const l of links) sql.exec("INSERT INTO reverse (id, folder, priv, lh, opts, created, expires, status, agen) VALUES (?, 'root', ?, ?, '{}', ?, ?, ?, ?)", l.id, l.priv, l.lh, t, t + 86400, l.agen ? 'paused' : 'active', l.agen);
    if (out.archived) {
      sql.exec("INSERT INTO archive_nodes (gen, id, parent, kind, name, size, chunks, state, created, updated, rs) VALUES (1, ?, 'root', 'file', '{}', ?, 1, 'ready', ?, ?, ?)", out.archived.id, out.archived.size, t, t, out.bad);
      sql.exec("INSERT INTO archive_meta (gen, k, v) VALUES (1, 'at', ?)", String(t));
    }
    for (const w of wraps) sql.exec('INSERT INTO wraps (kind, ref, data) VALUES (?, ?, ?)', w.kind, w.ref, w.data);
    const meta = (k2, v) => sql.exec('INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v', k2, v);
    meta('kcv', kcv);
    meta('driveSalt', salt16());
    if (escrowPriv) meta('escrowPriv', escrowPriv);
  });
  const kid = await main.escrowKeyId(escrow.publicJwk);
  await runInDurableObject(dirStub(), (inst, state) => {
    const sql = state.storage.sql;
    const meta = (k2, v) => sql.exec('INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v', k2, v);
    meta('drive.escrowPub', JSON.stringify(escrow.publicJwk));
    if (!isOwner) meta(`drive.escrowKid:${uid}`, kid);
    sql.exec("INSERT INTO drive_migration (user_id, state, updated) VALUES (?, 'pending', ?) ON CONFLICT(user_id) DO UPDATE SET state = 'pending'", uid, t);
    for (const l of links) sql.exec("INSERT INTO shares (id, user_id, kind, label, created, expires, views_total, status) VALUES (?, ?, 'reverse', '', ?, ?, NULL, 'active')", l.id, uid, t, t + 86400);
  });
  await dirStub().setDriveUsed(uid, 1);
  return out;
}
const migrationRow = (uid) => runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec('SELECT state FROM drive_migration WHERE user_id = ?', uid).toArray()[0]?.state ?? null);
const dirMeta = (k) => runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec('SELECT v FROM meta WHERE k = ?', k).toArray()[0]?.v ?? null);
const reverseRow = (uid, id) => runInDurableObject(driveOf(uid), (i, s) => s.storage.sql.exec('SELECT * FROM reverse WHERE id = ?', id).toArray()[0] ?? null);
const wrapsOf = (uid) => runInDurableObject(driveOf(uid), (i, s) => s.storage.sql.exec('SELECT kind FROM wraps ORDER BY kind').toArray().map((w) => w.kind));
const shareStatus = (id) => runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec('SELECT status FROM shares WHERE id = ?', id).toArray()[0]?.status ?? null);
const audit = async (uid) => (await (await fetchJson(`/api/private/admin/audit?user=${uid}&limit=500`, { cookie: oc })).json()).rows;
const post = (path, body = {}, cookie = oc) => fetchJson(path, { method: 'POST', cookie, headers: intent, body });
const kekOf = async (cookie) => { const k = await driveKeys(cookie, { fresh: true }); return { current: k.current, kek: k.keks.get(k.current) }; };

beforeAll(async () => {
  oc = await owner();
  ownerId = (await (await fetchJson('/api/private/me', { cookie: oc })).json()).user.id;
  globalThis.sessionStorage = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };
  globalThis.fetch = (path, init = {}) => {
    if (typeof path !== 'string' || !path.startsWith('/')) return realFetch(path, init);
    const { method = 'GET', headers = {}, body } = init;
    return SELF.fetch(`${ORIGIN}${path}`, { method, headers: { ...headers, ...(as ? { cookie: as } : {}) }, body, redirect: 'manual' });
  };
  ownerDk = main.createDriveKey();
  escrow = await main.createEscrowKeyPair();
  // The owner's own Drive of the release before: a folder, a link paused by a start over (its key under the
  // archived DK), the archive with a file it received; a recovery code's wrap and a passkey's (their
  // credentials exist), for AUTHN recovery below.
  const ref = await main.recoveryRef(CODE);
  await runInDurableObject(dirStub(), (i, s) => {
    s.storage.sql.exec('INSERT INTO recovery_codes (user_id, hash, created) VALUES (?, ?, ?)', ownerId, ref, now());
    s.storage.sql.exec("INSERT INTO passkeys (id, user_id, name, public_key, alg, created) VALUES ('ownerpasskeyAAAA', ?, 'key', 'x', -7, ?)", ownerId, now());
  });
  ownerDrive = await legacyDrive(ownerId, ownerDk, { isOwner: true, items: 1, file: false, link: false, paused: true, passkey: 'ownerpasskeyAAAA', recoveryRef: ref });
});
afterAll(() => { globalThis.fetch = realFetch; delete globalThis.sessionStorage; });

describe('the upgrade, after the audit (in order: the escrow material stays until the last Drive is done)', () => {
  let m1;
  let dm1;
  let forever;
  it('M1: a root change waits while a Drive has something of the release before; a link key an earlier root change wrapped at rest still upgrades', async () => {
    m1 = await makeUser('m1-user');
    await enableDrive(m1.id, { reverseEnabled: true });
    dm1 = await legacyDrive(m1.id, main.createDriveKey(), { items: 2 });
    const before = (await (await fetchJson(K, { cookie: oc })).json()).root.fp;
    const c = await (await post(`${K}/candidate`, { purpose: 'root', ...ownerStep() })).json();
    const r = await post(`${K}/root`, { candidate: c.id, ...ownerStep() });
    expect(r.status).toBe(409);
    const body = await r.json();
    expect(body.error).toBe('migration_pending');
    expect(body.drives.map((d) => d.id)).toEqual(expect.arrayContaining([m1.id, ownerId]));
    expect((await (await fetchJson(K, { cookie: oc })).json()).root).toMatchObject({ fp: before, changing: false });
    // What a root change before the fix left: the v1 link key wrapped by the field layer.
    const fk = await dirStub().fieldKeys(m1.id, ['linkKey']);
    await runInDurableObject(driveOf(m1.id), async (i, s) => {
      const row = s.storage.sql.exec('SELECT priv FROM reverse WHERE id = ?', dm1.link.id).one();
      s.storage.sql.exec('UPDATE reverse SET priv = ? WHERE id = ?', await sealAtRest(keyBytes(fk.cur.linkKey), { userId: m1.id, field: 'linkKey', ref: dm1.link.id }, row.priv), dm1.link.id);
    });
    const page = await (await fetchJson('/api/private/drive/migrate/items', { cookie: m1.cookie })).json();
    expect(page.links[0].priv.startsWith('{')).toBe(true); // handed out as the release before sealed it
    await actAs(m1.cookie);
    saveLegacyKey(dm1.dk, m1.id);
    const { current, kek } = await kekOf(m1.cookie);
    const up = await upgradeOwnDrive({ user: { id: m1.id, role: 'user' }, current, kek });
    expect(up).toMatchObject({ upgraded: 4, damaged: 0, unopened: [], done: true });
    expect(await migrationRow(m1.id)).toBe('done');
    const x = (await (await fetchJson('/api/private/drive/reverse', { cookie: m1.cookie })).json()).reverse.find((y) => y.id === dm1.link.id);
    await openLinkPriv(m1.cookie, dm1.link.id, x.priv, x.mek);
  });

  it('L1: a finished upgrade stays finished: a late or repeated upload is refused, the state stays "done"', async () => {
    const k = await driveKeys(m1.cookie, { fresh: true });
    const late = await fetchJson('/api/private/drive/migrate', { method: 'PUT', cookie: m1.cookie, headers: intent, body: { items: [{ id: dm1.folders[0], ks: 'A'.repeat(43), mek: k.current, name: { iv: 'A'.repeat(16), ct: 'B'.repeat(40) } }] } });
    expect([late.status, (await late.json()).error]).toEqual([409, 'already_upgraded']);
    const byOwner = await fetchJson(`/api/private/admin/drive/migrate/${m1.id}`, { method: 'PUT', cookie: oc, headers: intent, body: { items: [{ id: dm1.folders[0] }] } });
    expect([byOwner.status, (await byOwner.json()).error]).toEqual([409, 'already_upgraded']);
    expect(await migrationRow(m1.id)).toBe('done');
    // And a "pending" write never undoes "done" (a slower browser's bookkeeping).
    await dirStub().migrationSet(m1.id, { state: 'pending', v1Items: 3, v1Links: 0 });
    expect(await migrationRow(m1.id)).toBe('done');
    expect((await (await fetchJson('/api/private/drive', { cookie: m1.cookie })).json()).migration).toBeNull();
  });

  it('M2: a link the old key does not open holds the upgrade until its user retires it (the step-up); what it received is listed as failed', async () => {
    const u = await makeUser('m2-user');
    await enableDrive(u.id, { reverseEnabled: true });
    const d = await legacyDrive(u.id, main.createDriveKey(), { items: 1, damaged: true });
    // A file it received and that was not taken in yet.
    const recv = nid();
    await runInDurableObject(driveOf(u.id), (i, s) => s.storage.sql.exec("INSERT INTO nodes (id, parent, kind, name, meta, size, chunks, fk, state, created, updated, rs) VALUES (?, 'root', 'file', '\"x\"', '\"x\"', 1, 1, '\"x\"', 'ready', ?, ?, ?)", recv, now(), now(), d.bad));
    await actAs(u.cookie);
    saveLegacyKey(d.dk, u.id);
    const { current, kek } = await kekOf(u.cookie);
    const up = await upgradeOwnDrive({ user: { id: u.id, role: 'user' }, current, kek });
    expect(up).toMatchObject({ upgraded: 3, unopened: [d.bad], done: false });
    expect(await migrationRow(u.id)).toBe('pending');
    expect(loadLegacyKey(u.id)).not.toBeNull(); // kept until the upgrade is done
    await expect(retireLinks({ ids: [d.bad], step: {} })).rejects.toMatchObject({ code: 'reauth_required' });
    const x = await retireLinks({ ids: [d.bad], step: { current: proofFor(USER_PW) } });
    expect(x).toMatchObject({ retired: 1, failed: 1, done: true });
    expect(await migrationRow(u.id)).toBe('done');
    expect(await reverseRow(u.id, d.bad)).toMatchObject({ status: 'revoked', priv: '', mek: null });
    expect((await reverseRow(u.id, d.bad)).retired).toBeGreaterThan(0);
    expect(await shareStatus(d.bad)).toBe('revoked');
    expect(await runInDurableObject(driveOf(u.id), (i, s) => s.storage.sql.exec('SELECT rwhy FROM nodes WHERE id = ?', recv).one().rwhy)).toBe('unreadable');
    const act = (await (await fetchJson('/api/private/me/activity', { cookie: u.cookie })).json()).rows;
    expect(act.some((r) => r.action === 'drive.links_retired')).toBe(true);
    // The link that opened is upgraded and works; only v1 links can be retired.
    const again = await post('/api/private/drive/migrate/retire', { ids: [d.link.id], current: proofFor(USER_PW) }, u.cookie);
    expect(await again.json()).toMatchObject({ retired: [] });
  });

  it('M2 through the escrow: the owner retires a user\'s link that does not open (admin audit)', async () => {
    const u = await makeUser('m2-escrow');
    await enableDrive(u.id, { reverseEnabled: true });
    const d = await legacyDrive(u.id, main.createDriveKey(), { items: 1, damaged: true });
    await actAs(oc);
    saveLegacyKey(ownerDk, ownerId);
    const up = await upgradeUserDrive({ ownerId, userId: u.id, step: ownerStep() });
    expect(up).toMatchObject({ unopened: [d.bad], done: false });
    const x = await retireLinks({ ids: [d.bad], step: ownerStep(), target: u.id });
    expect(x).toMatchObject({ retired: 1, done: true });
    expect(await migrationRow(u.id)).toBe('done');
    const rows = await audit(u.id);
    expect(rows.find((r) => r.action === 'drive.links_retired')).toMatchObject({ adm: 1, actor_id: ownerId });
  });

  it('L2: a disabled account\'s Drive is upgraded through the escrow too', async () => {
    const u = await makeUser('l2-disabled');
    await enableDrive(u.id);
    const d = await legacyDrive(u.id, main.createDriveKey(), { items: 1, link: false });
    expect((await fetchJson(`/api/private/admin/users/${u.id}`, { method: 'PATCH', cookie: oc, body: { disabled: true } })).status).toBe(200);
    await actAs(oc);
    saveLegacyKey(ownerDk, ownerId);
    expect(await upgradeUserDrive({ ownerId, userId: u.id, step: ownerStep() })).toMatchObject({ upgraded: 2, done: true });
    expect(await migrationRow(u.id)).toBe('done');
    const list = await (await fetchJson('/api/private/admin/drive/migration', { cookie: oc })).json();
    expect(list.drives.find((x) => x.id === u.id)).toMatchObject({ state: 'done', disabled: true });
    void d;
  });

  it('L3: the user\'s tab drops the old Drive key once its Drive was upgraded elsewhere', async () => {
    const u = await makeUser('l3-user');
    await enableDrive(u.id);
    const d = await legacyDrive(u.id, main.createDriveKey(), { items: 1, link: false });
    store.clear();
    saveLegacyKey(d.dk, u.id); // the user's sign-in opened it in this tab
    const userTab = new Map(store);
    await actAs(oc);
    saveLegacyKey(ownerDk, ownerId);
    await upgradeUserDrive({ ownerId, userId: u.id, step: ownerStep() });
    store.clear();
    for (const [k, v] of userTab) store.set(k, v);
    await actAs(u.cookie);
    const { openDrive } = await import('../public/js/driveclient.js');
    const c = await openDrive({ user: { id: u.id, role: 'user', impersonating: false } });
    expect(c.migration).toBeNull();
    expect(loadLegacyKey(u.id)).toBeNull();
  });

  it('L5: the owner\'s archive of the release before is not counted, and is deleted with the step-up and the username typed', async () => {
    const usedOf = async () => (await driveOf(ownerId).usage(ownerId)).used;
    const used = await usedOf();
    const info = await (await fetchJson('/api/private/admin/drive/archive', { cookie: oc })).json();
    expect(info).toMatchObject({ items: 1, bytes: ownerDrive.archived.size, received: 1, links: [ownerDrive.bad] });
    const del = (body) => fetchJson('/api/private/admin/drive/archive', { method: 'DELETE', cookie: oc, headers: intent, body });
    expect((await del({ confirm: 'owner' })).status).toBe(400); // the step-up
    expect((await (await del({ confirm: 'someone', ...ownerStep() })).json()).error).toBe('confirm');
    const r = await del({ confirm: 'owner', ...ownerStep() });
    expect(r.status, await r.clone().text()).toBe(200);
    expect(await r.json()).toMatchObject({ items: 1, links: 1 });
    expect(await usedOf()).toBe(used); // the archive never counted towards the capacity
    expect(await env.FILES.get(driveChunkKey(ownerId, ownerDrive.archived.id, 0))).toBeNull();
    expect(await runInDurableObject(driveOf(ownerId), (i, s) => s.storage.sql.exec('SELECT COUNT(*) AS c FROM archive_nodes').one().c)).toBe(0);
    expect(await reverseRow(ownerId, ownerDrive.bad)).toMatchObject({ status: 'revoked', priv: '', agen: null });
    expect(await shareStatus(ownerDrive.bad)).toBe('revoked');
    expect((await audit(ownerId)).some((x) => x.action === 'drive.archive_deleted')).toBe(true);
  });

  it('M2 (the start over) and L3 (the owner): the owner\'s own upgrade finishes now; the owner keeps the old key while a Drive waits', async () => {
    forever = await makeUser('never-signs-in');
    await enableDrive(forever.id);
    await legacyDrive(forever.id, main.createDriveKey(), { items: 1, link: false });
    await actAs(oc);
    saveLegacyKey(ownerDk, ownerId);
    const { current, kek } = await kekOf(oc);
    const up = await upgradeOwnDrive({ user: { id: ownerId, role: 'owner' }, current, kek });
    expect(up).toMatchObject({ unopened: [], done: true, cleanup: false });
    expect(await migrationRow(ownerId)).toBe('done');
    expect(loadLegacyKey(ownerId)).not.toBeNull(); // it opens the escrow of the Drive that waits
    expect(await dirMeta('drive.escrowPub')).not.toBeNull();
  });

  it('M4: AUTHN owner recovery keeps the owner\'s old wraps while a Drive waits', async () => {
    expect(await wrapsOf(ownerId)).toEqual(['passkey', 'recovery']);
    const NEW = 'a-brand-new-recovery-token-0123456789';
    const rec = await worker.fetch(new Request(`${ORIGIN}/api/auth/setup`, {
      method: 'POST', headers: { 'content-type': 'application/json', 'cf-connecting-ip': freshIp() },
      body: JSON.stringify({ token: NEW, username: 'owner', salt: salt16(), t: 3, proof: proofFor('recovered-owner-pass') }),
    }), { ...env, AUTHN: NEW }, { waitUntil() {} });
    expect(rec.status).toBe(200);
    expect((await rec.json()).recovered).toBe(true);
    OWNER_PW = 'recovered-owner-pass';
    oc = await login('owner', OWNER_PW);
    setOwnerCookie(oc);
    // The owner's passkey and codes are gone; their wraps stay (the paper code still opens the old key).
    expect(await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec('SELECT COUNT(*) AS c FROM recovery_codes WHERE user_id = ?', ownerId).one().c)).toBe(0);
    expect(await wrapsOf(ownerId)).toEqual(['passkey', 'recovery']);
    expect(AUTHN).toBeTruthy();
  });

  // The maintainer's rule after the re-audit: a credential the owner removes loses its old wrap at once, even
  // while Drives wait; only the wraps an AUTHN owner recovery kept stay. The waiting Drives still upgrade.
  it('owner wrap pruning: a passkey the owner removes, and codes the owner replaces, lose their wraps while a Drive waits; the recovery\'s held wraps stay; a waiting Drive still upgrades through the escrow', async () => {
    const later = await makeUser('waits-for-escrow');
    await enableDrive(later.id, {}, ownerStep()); // the owner's password changed above (the step-up of a role option)
    const laterDrive = await legacyDrive(later.id, main.createDriveKey(), { items: 1, link: false });
    const wrapRefs = () => runInDurableObject(driveOf(ownerId), (i, s) => s.storage.sql.exec('SELECT kind, ref FROM wraps ORDER BY kind, ref').toArray().map((w) => `${w.kind}:${w.ref}`));
    const held = await wrapRefs(); // kept by the AUTHN recovery above (their credentials are gone)
    expect(held.map((x) => x.split(':')[0])).toEqual(['passkey', 'recovery']);
    // Two new passkeys and a code, each with an old wrap (as the release before would have made them).
    const code2 = await main.recoveryRef('WXYZ-2345-6789-ABCD');
    await runInDurableObject(dirStub(), (i, s) => {
      for (const id of ['ownerpasskeyBBBB', 'ownerpasskeyCCCC']) s.storage.sql.exec("INSERT INTO passkeys (id, user_id, name, public_key, alg, created) VALUES (?, ?, 'key', 'x', -7, ?)", id, ownerId, now());
      s.storage.sql.exec('INSERT INTO recovery_codes (user_id, hash, created) VALUES (?, ?, ?)', ownerId, code2, now());
    });
    const extra = [await main.wrapPrf(ownerDk, randomBytes(32), 'ownerpasskeyBBBB'), await main.wrapPrf(ownerDk, randomBytes(32), 'ownerpasskeyCCCC'), await main.wrapRecovery(ownerDk, 'WXYZ-2345-6789-ABCD', code2)];
    await runInDurableObject(driveOf(ownerId), (i, s) => { for (const w of extra) s.storage.sql.exec('INSERT INTO wraps (kind, ref, data) VALUES (?, ?, ?)', w.kind, w.ref, w.data); });
    expect(await migrationRow(later.id)).toBe('pending');
    // Account says so before the removal.
    expect((await (await fetchJson('/api/private/me/passkeys', { cookie: oc })).json()).drivesWaiting).toBeGreaterThan(0);
    // The owner removes a passkey: its wrap goes at once; the others stay.
    const rm = await post('/api/private/me/passkeys/ownerpasskeyBBBB/remove', ownerStep());
    expect(rm.status, await rm.clone().text()).toBe(200);
    expect(await wrapRefs()).toEqual([...held, 'passkey:ownerpasskeyCCCC', `recovery:${code2}`].sort());
    // The owner replaces the recovery codes: the old code's wrap goes at once.
    const regen = await post('/api/private/me/recovery-codes', ownerStep());
    expect(regen.status, await regen.clone().text()).toBe(200);
    expect(await wrapRefs()).toEqual([...held, 'passkey:ownerpasskeyCCCC'].sort());
    // The waiting Drive still upgrades: the owner's old key (open in this tab) opens the escrow.
    await actAs(oc);
    expect(loadLegacyKey(ownerId)).not.toBeNull();
    const up = await upgradeUserDrive({ ownerId, userId: later.id, step: ownerStep() });
    expect(up).toMatchObject({ unopened: [], done: true });
    expect(await migrationRow(later.id)).toBe('done');
    const n = (await (await node(later.cookie, laterDrive.folders[0])).json()).node;
    expect(n).toBeTruthy();
    expect(await wrapRefs()).toEqual([...held, 'passkey:ownerpasskeyCCCC'].sort()); // a Drive still waits (never-signs-in)
  });

  it('L2: deleting the last waiting account cleans up the escrow of the release before; then the owner\'s tab drops its old key', async () => {
    const del = await fetchJson(`/api/private/admin/users/${forever.id}`, { method: 'DELETE', cookie: oc, headers: intent });
    expect(del.status, await del.clone().text()).toBe(200);
    expect(await dirMeta('drive.escrowPub')).toBeNull();
    expect(await runInDurableObject(driveOf(ownerId), (i, s) => s.storage.sql.exec("SELECT COUNT(*) AS c FROM meta WHERE k = 'escrowPriv'").one().c)).toBe(0);
    expect(await wrapsOf(ownerId)).toEqual([]);
    const list = await (await fetchJson('/api/private/admin/drive/migration', { cookie: oc })).json();
    expect(list).toMatchObject({ left: 0, legacyEscrow: false });
    await actAs(oc);
    const { openDrive } = await import('../public/js/driveclient.js');
    await openDrive({ user: { id: ownerId, role: 'owner', impersonating: false } });
    expect(loadLegacyKey(ownerId)).toBeNull();
  });

  it('M1: with nothing of the release before left, the root change runs', async () => {
    const c = await (await post(`${K}/candidate`, { purpose: 'root', ...ownerStep() })).json();
    const r = await post(`${K}/root`, { candidate: c.id, ...ownerStep() });
    expect(r.status, await r.clone().text()).toBe(200);
    let job = null;
    for (let n = 0; n < 400; n++) { ({ job } = await (await post(`${K}/jobs/step`)).json()); if (!job || job.finished) break; }
    expect(job.result).toMatchObject({ ok: true });
    const n = (await (await node(m1.cookie, dm1.file.id)).json()).node;
    expect([...(await openStored(m1.cookie, n)).dek]).toEqual([...dm1.file.fk]);
  });
});

describe('L6: the wrap hygiene while a Drive waits', () => {
  it('regenerated recovery codes and an admin "remove all passkeys" drop the wraps of the credentials that went; a self password change marks the password wrap stale', async () => {
    const u = await makeUser('l6-user');
    await enableDrive(u.id, {}, ownerStep());
    escrow ??= await main.createEscrowKeyPair();
    const ref = await main.recoveryRef(CODE);
    await runInDurableObject(dirStub(), (i, s) => {
      s.storage.sql.exec('INSERT INTO recovery_codes (user_id, hash, created) VALUES (?, ?, ?)', u.id, ref, now());
      s.storage.sql.exec("INSERT INTO passkeys (id, user_id, name, public_key, alg, created) VALUES ('userpasskeyAAAAA', ?, 'key', 'x', -7, ?)", u.id, now());
    });
    await legacyDrive(u.id, main.createDriveKey(), { items: 1, link: false, file: false, passkey: 'userpasskeyAAAAA', recoveryRef: ref });
    expect(await wrapsOf(u.id)).toEqual(['escrow', 'passkey', 'recovery']);
    // New codes: the old code's wrap goes (the passkey's stays).
    const regen = await post('/api/private/me/recovery-codes', { current: proofFor(USER_PW) }, u.cookie);
    expect(regen.status, await regen.clone().text()).toBe(200);
    expect(await wrapsOf(u.id)).toEqual(['escrow', 'passkey']);
    // The owner removes all their passkeys (and codes): the passkey's wrap goes.
    const rm = await post(`/api/private/admin/users/${u.id}/passkeys`, {});
    expect(rm.status, await rm.clone().text()).toBe(200);
    expect(await wrapsOf(u.id)).toEqual(['escrow']);
    // A password wrap, then the user's own password change: kept, marked stale (it opens only with the old password).
    await runInDurableObject(driveOf(u.id), (i, s) => s.storage.sql.exec("INSERT INTO wraps (kind, ref, data) VALUES ('pw', 'pw', 'x')"));
    const pw = await fetchJson('/api/private/me/password', { method: 'POST', cookie: u.cookie, body: { current: proofFor(USER_PW), salt: salt16(), t: 3, proof: proofFor('l6-new-password-1') } });
    expect(pw.status, await pw.clone().text()).toBe(200);
    expect(await wrapsOf(u.id)).toEqual(['escrow', 'pw']);
    expect(await runInDurableObject(driveOf(u.id), (i, s) => s.storage.sql.exec("SELECT v FROM meta WHERE k = 'pwStale'").toArray()[0]?.v)).toBe('1');
  });
});
