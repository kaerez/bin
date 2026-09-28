// drive-upgrade.test.js — the one-time upgrade of Drives made before the key
// model v2 (docs/DRIVE.md §3.3), in workerd with the real server and the real
// browser code (public/js/driveupgrade.js and drivev1.js, over a fetch that
// goes to the Worker), in a storage of its own. The Drives are made as the
// release before made them, with that release's own code
// (test/fixtures/drivekeys-main.js): the old Drive key (DK), its wraps (a
// recovery code, the owner's escrow), names, metadata and file keys sealed
// under DK, and a reverse link whose key DK sealed, with real ciphertext.
// Checked: the owner upgrades a user's Drive through the escrow of that
// release, and the users (the owner included) their own at sign-in; every
// item opens under v2 with the same content; the old wraps go only after the
// server verified every item (the owner's escrow keys and records only once
// every Drive is upgraded); the upgrade resumes and repeats safely, refuses
// what does not open, and cannot skip the verification; the wrap hygiene of
// the release before holds while a Drive waits. Synthetic data only.
import { env, SELF, runInDurableObject } from 'cloudflare:test';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { ORIGIN, owner, makeUser, fetchJson, intent, cookieOf, proofFor, salt16, freshIp, liveCookie } from './helpers.js';
import { enableDrive, driveKeys, openStored, node, sealed } from './drive-helpers.js';
import { openLinkPriv, driveOf, dirStub } from './reverse-helpers.js';
import * as main from './fixtures/drivekeys-main.js';
import { upgradeOwnDrive, upgradeUserDrive, legacyUnlockAtSignIn, UpgradeBlocked } from '../public/js/driveupgrade.js';
import { saveLegacyKey, loadLegacyKey, clearLegacyKey } from '../public/js/drivev1.js';
import { bindSession } from '../public/js/api.js';
import { createReverseKey, linkHash, fragmentOf } from '../public/js/reversekeys.js';
import { driveChunkKey } from '../src/drive-do.js';
import { b64urlFromBytes, randomBytes, utf8, fromUtf8 } from '../public/js/bytes.js';
import { importFileKey, encryptChunk, decryptChunk } from '../public/js/files.js';

const CODE = 'ABCD-EFGH-JKMN-PQRS';
/** The owner's step-up (the escrow route hands out a user's old key wrap and KEK). */
const STEP = { current: proofFor('owner-password') };
let oc;
let ownerId;
let escrow; // the owner's escrow key pair of the release before
let ownerDk;

// The browser code's fetch and sessionStorage, here: same-origin requests go to the Worker with `as`'s cookie.
const realFetch = globalThis.fetch;
let as = null;
const store = new Map();
beforeAll(async () => {
  oc = await owner();
  ownerId = (await (await fetchJson('/api/private/me', { cookie: oc })).json()).user.id;
  globalThis.sessionStorage = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };
  globalThis.fetch = (path, init = {}) => {
    if (typeof path !== 'string' || !path.startsWith('/')) return realFetch(path, init);
    const { method = 'GET', headers = {}, body } = init;
    return SELF.fetch(`${ORIGIN}${path}`, { method, headers: { ...headers, ...(as ? { cookie: as } : {}) }, body, redirect: 'manual' });
  };
  // The owner's Drive of the release before: its DK, the escrow key pair sealed under it, a folder.
  ownerDk = main.createDriveKey();
  escrow = await main.createEscrowKeyPair();
  await legacyDrive(ownerId, ownerDk, { owner: true, items: 1 });
});
afterAll(() => { globalThis.fetch = realFetch; delete globalThis.sessionStorage; });
/**
 * The browser code acts as `cookie`'s session from here, as a page loaded for
 * it would (api.js records the session, and its CSRF token, from
 * /api/private/me at load; nav.js bindSession).
 */
async function actAs(cookie) {
  as = liveCookie(cookie);
  bindSession(await (await fetchJson('/api/private/me', { cookie })).json());
}

const now = () => Math.floor(Date.now() / 1000);
const nid = () => b64urlFromBytes(randomBytes(16));

/**
 * Make `uid`'s Drive as the release before did: `items` folders (and one
 * file of real ciphertext when `file`), a reverse link, the wraps (a
 * recovery code; the escrow wrap for a user) and the key check value; the
 * Directory's escrow records and the upgrade's "pending" row (migration 16).
 * → { dk, folders, file: { id, fk, plain }, link: { id, pub } }.
 */
async function legacyDrive(uid, dk, { owner: isOwner = false, items = 2, file = true, link = true, recovery = true } = {}) {
  const k = await main.deriveSubkeys(dk);
  const t = now();
  const rows = [];
  const folders = [];
  for (let i = 0; i < items; i++) {
    const id = nid();
    folders.push(id);
    rows.push({ id, parent: 'root', kind: 'dir', name: JSON.stringify(await main.sealField(k.names, 'name', id, `Folder ${i}`)), meta: null, size: 0, chunks: 0, fk: null });
  }
  let f = null;
  if (file) {
    const id = nid();
    const plain = utf8(`synthetic content of ${uid}`);
    const fk = randomBytes(32);
    const meta = { type: 'text/plain', mtime: 1700000000000, size: plain.length };
    rows.push({ id, parent: folders[0] ?? 'root', kind: 'file', name: JSON.stringify(await main.sealField(k.names, 'name', id, 'report.txt')),
      meta: JSON.stringify(await main.sealField(k.names, 'meta', id, JSON.stringify(meta))), size: plain.length, chunks: 1, fk: JSON.stringify(await main.sealField(k.files, 'fk', id, fk)) });
    await env.FILES.put(driveChunkKey(uid, id, 0), await encryptChunk(await importFileKey(b64urlFromBytes(fk)), 0, 1, plain));
    f = { id, fk, plain };
  }
  let l = null;
  if (link) {
    const id = `r${b64urlFromBytes(randomBytes(16)).slice(0, 22)}`;
    const { pub, privateKey } = await createReverseKey();
    l = { id, pub, priv: JSON.stringify(await main.sealReversePriv(dk, id, privateKey)), lh: await linkHash(pub) };
  }
  const wraps = [];
  if (recovery) wraps.push(await main.wrapRecovery(dk, CODE));
  if (!isOwner) wraps.push(await main.wrapEscrow(dk, escrow.publicJwk));
  const kcv = await main.keyCheckValue(dk);
  const escrowPriv = isOwner ? await main.sealEscrowPriv(dk, escrow.privateKey) : null;
  await runInDurableObject(driveOf(uid), (inst, state) => {
    const sql = state.storage.sql;
    for (const r of rows) {
      sql.exec("INSERT INTO nodes (id, parent, kind, name, meta, size, chunks, fk, state, created, updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ready', ?, ?)",
        r.id, r.parent, r.kind, r.name, r.meta, r.size, r.chunks, r.fk, t, t);
    }
    if (l) sql.exec("INSERT INTO reverse (id, folder, priv, lh, opts, created, expires, status) VALUES (?, ?, ?, ?, '{}', ?, ?, 'active')", l.id, folders[0] ?? 'root', l.priv, l.lh, t, t + 86400);
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
    // The link's row in the share index, as its creation recorded it.
    if (l) sql.exec("INSERT INTO shares (id, user_id, kind, label, created, expires, views_total, status) VALUES (?, ?, 'reverse', '', ?, ?, NULL, 'active')", l.id, uid, t, t + 86400);
  });
  await dirStub().setDriveUsed(uid, 1);
  return { dk, folders, file: f, link: l };
}

const legacyOf = (uid) => runInDurableObject(driveOf(uid), (inst, state) => ({
  wraps: state.storage.sql.exec('SELECT kind FROM wraps ORDER BY kind').toArray().map((w) => w.kind),
  meta: Object.fromEntries(state.storage.sql.exec("SELECT k, v FROM meta WHERE k IN ('kcv', 'driveSalt', 'escrowPriv')").toArray().map((r) => [r.k, r.v])),
  v1: state.storage.sql.exec("SELECT COUNT(*) AS c FROM nodes WHERE id != 'root' AND mek IS NULL AND rs IS NULL").one().c,
}));
const dirMeta = (k) => runInDurableObject(dirStub(), (inst, state) => state.storage.sql.exec('SELECT v FROM meta WHERE k = ?', k).toArray()[0]?.v ?? null);
const migrationRow = (uid) => runInDurableObject(dirStub(), (inst, state) => state.storage.sql.exec('SELECT state FROM drive_migration WHERE user_id = ?', uid).toArray()[0]?.state ?? null);
const adminAudit = async (uid) => (await (await fetchJson(`/api/private/admin/audit?user=${uid}&limit=500`, { cookie: oc })).json()).rows;

/** Every item and the link of a legacy Drive open under v2 with what they held. */
async function checkUpgraded(cookie, uid, d) {
  for (const id of d.folders) {
    const n = (await (await node(cookie, id)).json()).node;
    expect(n.v1).toBeUndefined();
    expect(n.mek).toMatch(/^m/);
    expect(fromUtf8((await openStored(cookie, n)).name)).toMatch(/^Folder \d$/);
  }
  if (d.file) {
    const n = (await (await node(cookie, d.file.id)).json()).node;
    const o = await openStored(cookie, n);
    expect(fromUtf8(o.name)).toBe('report.txt');
    expect([...o.dek]).toEqual([...d.file.fk]); // the old file key is the DEK: the content is untouched
    const ct = new Uint8Array(await (await SELF.fetch(`${ORIGIN}/api/private/drive/files/${d.file.id}/chunk/0`, { headers: { cookie } })).arrayBuffer());
    expect([...await decryptChunk(await importFileKey(b64urlFromBytes(o.dek)), 0, 1, ct)]).toEqual([...d.file.plain]);
  }
  if (d.link) {
    const x = (await (await fetchJson('/api/private/drive/reverse', { cookie })).json()).reverse.find((r) => r.id === d.link.id);
    expect(x.mek).toMatch(/^m/);
    expect(fragmentOf((await openLinkPriv(cookie, d.link.id, x.priv, x.mek)).pub)).toBe(fragmentOf(d.link.pub));
  }
  void uid;
}

describe('the upgrade of Drives made before the key model v2', () => {
  let u;
  let d;
  it('a Drive waiting for its upgrade: listed as such, its old items shown as waiting, nothing changed yet', async () => {
    u = await makeUser('up-user');
    await enableDrive(u.id, { reverseEnabled: true });
    d = await legacyDrive(u.id, main.createDriveKey());
    const s = await (await fetchJson('/api/private/drive', { cookie: u.cookie })).json();
    expect(s.migration).toMatchObject({ pending: true, v1Items: 3, v1Links: 1, legacy: true });
    const n = (await (await node(u.cookie, d.file.id)).json()).node;
    expect(n).toMatchObject({ v1: true, fk: expect.any(Object) });
    expect(n.mek).toBeUndefined();
    const list = await (await fetchJson('/api/private/admin/drive/migration', { cookie: oc })).json();
    expect(list.legacyEscrow).toBe(true);
    expect(list.drives.find((x) => x.id === u.id)).toMatchObject({ state: 'pending', v1Items: 3, v1Links: 1, legacy: true });
    // What opens the old DK for the user's own upgrade: their own wraps (never the escrow wrap) and the salt.
    const m = await (await fetchJson('/api/private/drive/migrate', { cookie: u.cookie })).json();
    expect(m.wraps.map((w) => w.kind)).toEqual(['recovery']);
    expect(m).toMatchObject({ legacy: true, v1Items: 3, v1Links: 1, kcv: await main.keyCheckValue(d.dk) });
    expect(m.escrowPriv).toBeUndefined();
    // Finishing now removes nothing.
    const early = await fetchJson(`/api/private/admin/drive/migrate/${u.id}/finish`, { method: 'POST', cookie: oc, headers: intent, body: {} });
    expect([early.status, (await early.json()).error]).toEqual([409, 'not_upgraded']);
    expect((await legacyOf(u.id)).wraps).toEqual(['escrow', 'recovery']);
  });

  it('the owner upgrades it through the escrow of that release (admin audit); every item opens under v2; then the old wraps go', async () => {
    await actAs(oc);
    clearLegacyKey();
    await expect(upgradeUserDrive({ ownerId, userId: u.id, step: STEP })).rejects.toBeInstanceOf(UpgradeBlocked); // the owner's old DK is not in the tab
    saveLegacyKey(ownerDk, ownerId);
    // Audit B I3: the escrow route needs the step-up, like Show.
    const noStep = await fetchJson(`/api/private/admin/drive/migrate/${u.id}/escrow`, { method: 'POST', cookie: oc, headers: intent, body: {} });
    expect([noStep.status, (await noStep.json()).error]).toEqual([400, 'reauth_required']);
    expect((await adminAudit(u.id)).some((x) => x.action === 'drive.escrow_used')).toBe(false);
    const r = await upgradeUserDrive({ ownerId, userId: u.id, step: STEP });
    expect(r).toMatchObject({ upgraded: 4, damaged: 0 });
    expect(r.verified).toBeGreaterThanOrEqual(4);
    await checkUpgraded(u.cookie, u.id, d);
    const L = await legacyOf(u.id);
    expect(L).toMatchObject({ wraps: [], v1: 0 });
    expect(L.meta).toEqual({});
    expect(await migrationRow(u.id)).toBe('done');
    const rows = await adminAudit(u.id);
    expect(rows.find((x) => x.action === 'drive.escrow_used')).toMatchObject({ adm: 1, actor_id: ownerId });
    expect(rows.find((x) => x.action === 'drive.migrated' && x.actor_id === ownerId)).toMatchObject({ adm: 1 });
    // The user's own activity: a system event, no admin detail.
    const act = (await (await fetchJson('/api/private/me/activity', { cookie: u.cookie })).json()).rows;
    expect(act.find((x) => x.action === 'drive.migrated')).toMatchObject({ detail: '' });
    // The owner's escrow keys and records stay while the owner's own Drive waits.
    expect(await dirMeta('drive.escrowPub')).not.toBeNull();
    expect((await legacyOf(ownerId)).meta.escrowPriv).toBeTruthy();
    // A repeat changes nothing.
    const again = await upgradeUserDrive({ ownerId, userId: u.id, step: STEP });
    expect(again.upgraded).toBe(0);
    await checkUpgraded(u.cookie, u.id, d);
    // The Drive page's summary no longer shows an upgrade.
    expect((await (await fetchJson('/api/private/drive', { cookie: u.cookie })).json()).migration).toBeNull();
  });

  it('a user upgrades their own Drive with what they sign in with (here a recovery code); the owner acting as them cannot', async () => {
    const v = await makeUser('up-self');
    await enableDrive(v.id, { reverseEnabled: true });
    const dv = await legacyDrive(v.id, main.createDriveKey());
    const ic = cookieOf(await fetchJson(`/api/private/admin/users/${v.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent }));
    const imp = await fetchJson('/api/private/drive/migrate', { method: 'PUT', cookie: ic, headers: intent, body: { items: [] } });
    expect([imp.status, (await imp.json()).error]).toEqual([403, 'impersonating']);
    await actAs(v.cookie);
    const user = { id: v.id, role: 'user' };
    expect(await legacyUnlockAtSignIn({ user, code: 'ZZZZ-YYYY-XXXX-WWWW' })).toBe(false); // not this Drive's code
    expect(await legacyUnlockAtSignIn({ user, code: CODE.toLowerCase() })).toBe(true);
    expect(loadLegacyKey(v.id)).toEqual(dv.dk);
    const k = await driveKeys(v.cookie, { fresh: true });
    const r = await upgradeOwnDrive({ user, current: k.current, kek: k.keks.get(k.current) });
    expect(r).toMatchObject({ upgraded: 4, damaged: 0 });
    expect(loadLegacyKey(v.id)).toBeNull(); // a user's old key is not kept
    await checkUpgraded(v.cookie, v.id, dv);
    expect(await legacyOf(v.id)).toMatchObject({ wraps: [], v1: 0 });
    expect(await migrationRow(v.id)).toBe('done');
  });

  it('an old Drive key planted in the tab is refused before anything is sealed or marked damaged, and removed (its check value is not the server’s)', async () => {
    const p = await makeUser('up-planted');
    await enableDrive(p.id);
    const dp = await legacyDrive(p.id, main.createDriveKey(), { items: 2, link: false });
    await actAs(p.cookie);
    const user = { id: p.id, role: 'user' };
    saveLegacyKey(randomBytes(32), p.id); // any script on the origin could write this slot
    const k = await driveKeys(p.cookie, { fresh: true });
    const e = await upgradeOwnDrive({ user, current: k.current, kek: k.keks.get(k.current) }).catch((x) => x);
    expect(e).toBeInstanceOf(UpgradeBlocked);
    expect(e.reason).toBe('wrong');
    expect(loadLegacyKey(p.id)).toBeNull();
    expect((await legacyOf(p.id)).v1).toBe(3); // nothing re-sealed, nothing marked damaged
    // The genuine key (the sign-in opens it) then upgrades it with nothing lost.
    expect(await legacyUnlockAtSignIn({ user, code: CODE })).toBe(true);
    expect(await upgradeOwnDrive({ user, current: k.current, kek: k.keks.get(k.current) })).toMatchObject({ upgraded: 3, damaged: 0 });
    await checkUpgraded(p.cookie, p.id, dp);
  });

  it('resumable and idempotent; refuses what does not open; the verification cannot be skipped; nothing goes before every item opens', async () => {
    const w = await makeUser('up-manual');
    await enableDrive(w.id);
    const dw = await legacyDrive(w.id, main.createDriveKey(), { items: 3, link: false });
    const put = (body) => fetchJson('/api/private/drive/migrate', { method: 'PUT', cookie: w.cookie, headers: intent, body });
    const finish = () => fetchJson('/api/private/drive/migrate/finish', { method: 'POST', cookie: w.cookie, headers: intent, body: { after: 'n.zzzzzzzzzzzzzzzzzzzzzz' } });
    const page = await (await fetchJson('/api/private/drive/migrate/items', { cookie: w.cookie })).json();
    expect(page.items).toHaveLength(4);
    const k = await driveKeys(w.cookie, { fresh: true });
    const seal = async (it) => {
      const s = await sealed(w.cookie, it.kind, { keys: k, name: utf8('re-sealed'), dek: it.kind === 'file' ? dw.file.fk : undefined });
      return { id: it.id, ks: s.ks, mek: s.mek, name: s.name, ...(it.kind === 'file' ? { meta: s.meta, dek: s.dek } : {}) };
    };
    const [a, b, c, e] = await Promise.all(page.items.map(seal));
    // A seal that does not open under the current KEK, or a stale sub-MEK: refused, nothing stored.
    const bad = await put({ items: [{ ...a, name: { iv: 'A'.repeat(16), ct: 'B'.repeat(40) } }] });
    expect([bad.status, (await bad.json()).error]).toEqual([400, 'bad_seal']);
    const stale = await put({ items: [{ ...a, mek: `m${'Q'.repeat(11)}` }] });
    expect([stale.status, (await stale.json()).error]).toEqual([409, 'mek_not_current']);
    expect((await legacyOf(w.id)).v1).toBe(4);
    // Half now, the same half again (nothing changes), and nothing goes while items wait.
    expect(await (await put({ items: [a, b] })).json()).toMatchObject({ done: 2, skipped: 0, v1Items: 2 });
    expect(await (await put({ items: [a, b] })).json()).toMatchObject({ done: 0, skipped: 2, v1Items: 2 });
    const early = await finish();
    expect([early.status, (await early.json()).error]).toEqual([409, 'not_upgraded']);
    expect((await legacyOf(w.id)).wraps).toEqual(['escrow', 'recovery']);
    expect(await (await put({ items: [c, e] })).json()).toMatchObject({ done: 2, v1Items: 0 });
    // An upgraded item damaged in storage: the verification fails and nothing goes (and it starts over).
    const good = await runInDurableObject(driveOf(w.id), (i, s) => s.storage.sql.exec('SELECT name FROM nodes WHERE id = ?', a.id).one().name);
    await runInDurableObject(driveOf(w.id), (i, s) => s.storage.sql.exec('UPDATE nodes SET name = ? WHERE id = ?', JSON.stringify({ iv: 'A'.repeat(16), ct: 'C'.repeat(40) }), a.id));
    const failed = await finish();
    expect([failed.status, (await failed.json()).error]).toEqual([409, 'verify_failed']);
    expect((await legacyOf(w.id)).wraps).toEqual(['escrow', 'recovery']);
    await runInDurableObject(driveOf(w.id), (i, s) => s.storage.sql.exec('UPDATE nodes SET name = ? WHERE id = ?', good, a.id));
    // The client's cursor is ignored: the server verifies from where it stopped (here: from the start).
    const done = await (await finish()).json();
    expect(done).toMatchObject({ ok: true, done: true, verified: 4 });
    expect(await legacyOf(w.id)).toMatchObject({ wraps: [], v1: 0 });
    const n = (await (await node(w.cookie, dw.file.id)).json()).node;
    expect([...(await openStored(w.cookie, n)).dek]).toEqual([...dw.file.fk]);
  });

  it('while a Drive waits: an admin reset removes the old password wrap when another own wrap remains (else marks it stale); a spent recovery code’s wrap goes, handed once to that sign-in', async () => {
    const x = await makeUser('up-hygiene');
    await enableDrive(x.id);
    await legacyDrive(x.id, main.createDriveKey(), { items: 1, file: false, link: false });
    const ref = (await main.wrapRecovery(main.createDriveKey(), CODE)).ref;
    await runInDurableObject(dirStub(), (inst, state) => {
      state.storage.sql.exec('INSERT INTO recovery_codes (user_id, hash, created) VALUES (?, ?, ?)', x.id, ref, now());
    });
    const pwWrap = () => runInDurableObject(driveOf(x.id), (i, s) => s.storage.sql.exec("INSERT OR REPLACE INTO wraps (kind, ref, data) VALUES ('pw', 'pw', ?)", `1.${b64urlFromBytes(randomBytes(12))}.${b64urlFromBytes(randomBytes(48))}`));
    const reset = () => fetchJson(`/api/private/admin/users/${x.id}/password`, { method: 'POST', cookie: oc, body: { salt: salt16(), t: 3, proof: proofFor(`reset-pass-${now()}`) } });
    await pwWrap();
    expect((await legacyOf(x.id)).wraps).toEqual(['escrow', 'pw', 'recovery']);
    expect((await reset()).status).toBe(200);
    expect((await legacyOf(x.id)).wraps).toEqual(['escrow', 'recovery']); // the old password no longer opens it; the code still does
    const r = await fetchJson('/api/auth/recovery', { method: 'POST', body: { username: 'up-hygiene', code: CODE }, ip: freshIp() });
    expect(r.status).toBe(200);
    expect((await r.json()).driveSpent.map((w) => w.kind)).toEqual(['recovery']);
    expect((await legacyOf(x.id)).wraps).toEqual(['escrow']);
    // No other own wrap left: a reset keeps the pw wrap, marked stale.
    await pwWrap();
    expect((await reset()).status).toBe(200);
    expect((await legacyOf(x.id)).wraps).toEqual(['escrow', 'pw']);
    expect(await runInDurableObject(driveOf(x.id), (i, s) => s.storage.sql.exec("SELECT v FROM meta WHERE k = 'pwStale'").toArray()[0]?.v)).toBe('1');
  });

  it('the owner’s own Drive last: upgraded in the owner’s browser; once every Drive is upgraded, the escrow keys and records go', async () => {
    // Every other Drive waiting is done first (the one made for the hygiene test, through the escrow).
    await actAs(oc);
    saveLegacyKey(ownerDk, ownerId);
    const list = await (await fetchJson('/api/private/admin/drive/migration', { cookie: oc })).json();
    for (const x of list.drives.filter((y) => y.state !== 'done' && y.id !== ownerId)) await upgradeUserDrive({ ownerId, userId: x.id, step: STEP });
    expect((await legacyOf(ownerId)).meta.escrowPriv).toBeTruthy();
    const k = await driveKeys(oc, { fresh: true });
    const r = await upgradeOwnDrive({ user: { id: ownerId, role: 'owner' }, current: k.current, kek: k.keks.get(k.current) });
    expect(r).toMatchObject({ upgraded: 3, damaged: 0 });
    expect(await migrationRow(ownerId)).toBe('done');
    const L = await legacyOf(ownerId);
    expect(L).toMatchObject({ wraps: [], v1: 0 });
    expect(L.meta).toEqual({});
    expect(await dirMeta('drive.escrowPub')).toBeNull();
    expect(await dirMeta(`drive.escrowKid:${u.id}`)).toBeNull();
    const rows = (await (await fetchJson('/api/private/admin/audit?limit=500', { cookie: oc })).json()).rows;
    expect(rows.some((x) => x.action === 'drive.migration_done')).toBe(true);
    const done = await (await fetchJson('/api/private/admin/drive/migration', { cookie: oc })).json();
    expect(done).toMatchObject({ left: 0, legacyEscrow: false });
  });

  it('a damaged old item is kept under a placeholder name (its content was already unreadable)', async () => {
    const y = await makeUser('up-damaged');
    await enableDrive(y.id);
    const dy = await legacyDrive(y.id, main.createDriveKey(), { items: 1, link: false });
    await runInDurableObject(driveOf(y.id), (i, s) => s.storage.sql.exec('UPDATE nodes SET name = ? WHERE id = ?', JSON.stringify({ iv: 'A'.repeat(16), ct: 'D'.repeat(40) }), dy.folders[0]));
    await actAs(y.cookie);
    saveLegacyKey(dy.dk, y.id);
    const k = await driveKeys(y.cookie, { fresh: true });
    const r = await upgradeOwnDrive({ user: { id: y.id, role: 'user' }, current: k.current, kek: k.keks.get(k.current) });
    expect(r).toMatchObject({ upgraded: 2, damaged: 1 });
    const n = (await (await node(y.cookie, dy.folders[0])).json()).node;
    expect(fromUtf8((await openStored(y.cookie, n)).name)).toBe(`damaged-${dy.folders[0]}`);
    // The file (not damaged) keeps its name and content.
    const f = (await (await node(y.cookie, dy.file.id)).json()).node;
    expect(fromUtf8((await openStored(y.cookie, f)).name)).toBe('report.txt');
  });
});
