// drive-audit5-owner.test.js — regressions for the round-5 audit around AUTHN
// owner recovery, starting over and a user's escrowReset (workerd, a storage of
// its own). Each block was a proof of concept that passed against be7654a:
//   - R5-L2: two start overs at once: one archive, one epoch, the keys and the
//     key check value of one request; the other gets 409;
//   - R5-I1: a repeated escrowReset for an epoch already applied writes no
//     audit row, and the route is rate limited;
//   - R5-L4: an owner Drive with content but no wrap takes no "first set-up":
//     409 drive_keyless; the ways out are a kit restore (the same DK, with the
//     step-up) and starting over (with the step-up).
// Synthetic data only.
import { env, runInDurableObject } from 'cloudflare:test';
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, setOwnerCookie, login, makeUser, fetchJson, intent, salt16, proofFor, USER_PW } from './helpers.js';
import { enableDrive, uploadFile } from './drive-helpers.js';
import worker from '../src/index.js';
import { b64urlFromBytes, randomBytes } from '../public/js/bytes.js';
import {
  createDriveKey, createEscrowKeyPair, sealEscrowPriv, createSigningKeyPair, sealSigningKey, endorseEscrowKey, wrapEscrow, escrowKeyId,
  sealEscrowPin, keyCheckValue, recoveryRef,
} from '../public/js/drivekeys.js';
import { driveChunkKey } from '../src/drive-do.js';

const ORIGIN = 'https://secbin.test';
let OWNER_PW = 'owner-password';
let oc;
const o = {};
const keys = (cookie, body) => fetchJson('/api/private/drive/keys', { method: 'PUT', cookie, headers: intent, body });
const startOver = (cookie, body) => fetchJson('/api/private/drive/start-over', { method: 'POST', cookie, headers: intent, body });
const W = (n = 60) => `1.${b64urlFromBytes(randomBytes(12))}.${b64urlFromBytes(randomBytes(n))}`;
const pwWrap = () => ({ kind: 'pw', ref: 'pw', data: W() });
const driveOf = (uid) => env.DRIVE.get(env.DRIVE.idFromName(`drive:${uid}`));
const dirOf = () => env.DIRECTORY.get(env.DIRECTORY.idFromName('directory'));
const sql = (stub, q, ...a) => runInDurableObject(stub, (inst, state) => state.storage.sql.exec(q, ...a).toArray());
const errorOf = async (r) => { try { return (await r.clone().json()).error; } catch { return null; } };
const st = async (cookie) => (await fetchJson('/api/private/drive', { cookie })).json();
const callWith = (overrides, path, init = {}) => worker.fetch(new Request(`${ORIGIN}${path}`, init), { ...env, ...overrides }, { waitUntil() {} });
async function authnRecovery(newPassword) {
  const NEW = `recovery-token-${b64urlFromBytes(randomBytes(16))}`;
  const r = await callWith({ AUTHN: NEW }, '/api/auth/setup', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token: NEW, username: 'owner', salt: salt16(), t: 3, proof: proofFor(newPassword) }),
  });
  expect(r.status).toBe(200);
  OWNER_PW = newPassword;
  oc = await login('owner', newPassword);
  setOwnerCookie(oc);
}
/** New owner keys for a start over (under a new DK). */
async function startOverBody(confirm = 'owner') {
  const dk = createDriveKey();
  const e = await createEscrowKeyPair();
  const s = await createSigningKeyPair();
  return {
    dk, e, s,
    body: {
      confirm, driveSalt: salt16(), set: [pwWrap()], kcv: await keyCheckValue(dk),
      escrowPub: e.publicJwk, escrowPriv: await sealEscrowPriv(dk, e.privateKey), escrowSignPub: s.publicJwk,
      escrowSignPriv: await sealSigningKey(dk, s.privateKey), escrowSig: await endorseEscrowKey(s.privateKey, e.publicJwk), current: proofFor(OWNER_PW),
    },
  };
}
const rewrapRows = async (uid) => (await sql(dirOf(), "SELECT COUNT(*) AS c FROM activity WHERE action = 'drive.escrow_rewrapped' AND subject_id = ?", uid))[0].c;

beforeAll(async () => {
  oc = await owner();
  o.id = (await (await fetchJson('/api/private/me', { cookie: oc })).json()).user.id;
  o.dk = createDriveKey();
  o.e = await createEscrowKeyPair();
  o.s = await createSigningKeyPair();
  const r = await keys(oc, {
    driveSalt: salt16(), set: [pwWrap()], kcv: await keyCheckValue(o.dk),
    escrowPub: o.e.publicJwk, escrowPriv: await sealEscrowPriv(o.dk, o.e.privateKey),
    escrowSignPub: o.s.publicJwk, escrowSignPriv: await sealSigningKey(o.dk, o.s.privateKey), escrowSig: await endorseEscrowKey(o.s.privateKey, o.e.publicJwk),
  });
  expect(r.status).toBe(200);
  o.file = await uploadFile(oc, 'root', 1000);
  o.kid = await escrowKeyId(o.e.publicJwk);
});

describe('starting over, the reset and races', () => {
  const u = {};
  it('R5-L2: two start overs at once after AUTHN recovery: one archive, one epoch, the keys of one request', async () => {
    u.acc = await makeUser('r5o-user');
    await enableDrive(u.acc.id);
    u.dk = createDriveKey();
    expect((await keys(u.acc.cookie, { driveSalt: salt16(), set: [pwWrap(), await wrapEscrow(u.dk, o.e.publicJwk)], escrowPin: await sealEscrowPin(u.dk, { escrow: o.kid, sign: null }), kcv: await keyCheckValue(u.dk) })).status).toBe(200);
    const userBefore = JSON.stringify(await sql(driveOf(u.acc.id), 'SELECT kind, ref, data FROM wraps ORDER BY kind'));
    expect((await startOver(oc, (await startOverBody()).body)).status).toBe(409); // a usable wrap is left
    await authnRecovery('recovered-owner-pw-5');
    const nodesBefore = JSON.stringify(await sql(driveOf(o.id), "SELECT * FROM nodes WHERE id != 'root' ORDER BY id"));
    const wrapsBefore = JSON.stringify(await sql(driveOf(o.id), 'SELECT kind, ref, data FROM wraps ORDER BY kind, ref'));
    const A = await startOverBody();
    const B = await startOverBody();
    const [ra, rb] = await Promise.all([startOver(oc, A.body), startOver(oc, B.body)]);
    expect([ra.status, rb.status].sort()).toEqual([200, 409]);
    expect(await errorOf(ra.status === 409 ? ra : rb)).toBe('drive_unlockable');
    const won = ra.status === 200 ? A : B;
    const archiveGens = await sql(driveOf(o.id), "SELECT gen FROM archive_meta WHERE k = 'at'");
    expect(archiveGens.map((g) => g.gen)).toEqual([1]);
    const meta = Object.fromEntries((await sql(driveOf(o.id), 'SELECT k, v FROM meta')).map((m) => [m.k, m.v]));
    const dm = Object.fromEntries((await sql(dirOf(), "SELECT k, v FROM meta WHERE k LIKE 'drive.%'")).map((m) => [m.k, m.v]));
    // Every piece from the same request: the Drive's sealed keys, the KCV, the pw wrap, the Directory's public keys.
    expect(meta.escrowPriv).toBe(won.body.escrowPriv);
    expect(meta.escrowSignPriv).toBe(won.body.escrowSignPriv);
    expect(meta.kcv).toBe(won.body.kcv);
    expect((await sql(driveOf(o.id), "SELECT data FROM wraps WHERE kind = 'pw'"))[0].data).toBe(won.body.set[0].data);
    expect(await escrowKeyId(JSON.parse(dm['drive.escrowPub']))).toBe(await escrowKeyId(won.e.publicJwk));
    expect(JSON.parse(dm['drive.escrowSignPub'])).toEqual(won.s.publicJwk);
    expect(JSON.parse(dm['drive.ownerReset']).epoch).toBe(1);
    // The archive holds the owner's Drive exactly as it was; no user's Drive changed.
    const cols = 'id, parent, kind, name, meta, size, chunks, fk, state, done, upload_hash, created, updated';
    expect(JSON.stringify(await sql(driveOf(o.id), `SELECT ${cols} FROM archive_nodes WHERE gen = 1 ORDER BY id`))).toBe(nodesBefore);
    expect(JSON.stringify(await sql(driveOf(o.id), 'SELECT kind, ref, data FROM archive_wraps WHERE gen = 1 ORDER BY kind, ref'))).toBe(wrapsBefore);
    expect(await env.FILES.get(driveChunkKey(o.id, o.file.id, 0))).not.toBeNull();
    expect(JSON.stringify(await sql(driveOf(u.acc.id), 'SELECT kind, ref, data FROM wraps ORDER BY kind'))).toBe(userBefore);
    o.after = { won, epoch: 1 };
  });

  it('R5-I1: an escrowReset for an epoch already applied writes no audit row; the route is rate limited', async () => {
    const rec = await st(u.acc.cookie);
    const kcv = await keyCheckValue(u.dk);
    const move = () => ({ set: [], escrowReset: rec.ownerReset.epoch, kcv });
    const first = await keys(u.acc.cookie, { ...move(), set: [await wrapEscrow(u.dk, rec.escrowPub)] });
    expect(first.status).toBe(200);
    expect(await rewrapRows(u.acc.id)).toBe(2); // the user's activity and the admin audit
    // Again with a session alone: the wrap is for the same key now, a replacement (the step-up).
    const bare = await keys(u.acc.cookie, { ...move(), set: [await wrapEscrow(u.dk, rec.escrowPub)] });
    expect(await errorOf(bare)).toBe('reauth_required');
    // Even with the step-up: accepted as a change of the wrap, but no second record.
    const stepped = await keys(u.acc.cookie, { ...move(), set: [await wrapEscrow(u.dk, rec.escrowPub)], current: proofFor(USER_PW) });
    expect(stepped.status).toBe(200);
    expect(await rewrapRows(u.acc.id)).toBe(2);
    // Rate limited: a few per window, then 429 (and still no row).
    const statuses = [];
    for (let i = 0; i < 6; i++) statuses.push((await keys(u.acc.cookie, { ...move(), set: [await wrapEscrow(u.dk, rec.escrowPub)], current: proofFor(USER_PW) })).status);
    expect(statuses.at(-1)).toBe(429);
    expect(statuses.filter((s) => s === 429).length).toBeGreaterThanOrEqual(3);
    expect(await rewrapRows(u.acc.id)).toBe(2);
    // The Directory records each user and epoch once.
    expect(await dirOf().driveEscrowRewrapped(u.acc.id, 'abcd-efgh', 1)).toEqual({ ok: true, logged: false });
    expect(await rewrapRows(u.acc.id)).toBe(2);
  });

  it('the archive: GET cross-site 403; delete needs the typed username and the step-up; finish on a non-empty archive 409', async () => {
    const cross = await fetchJson('/api/private/drive/archive/1', { cookie: oc, headers: { 'sec-fetch-site': 'cross-site' } });
    const noConfirm = await fetchJson('/api/private/drive/archive/1', { method: 'DELETE', cookie: oc, headers: intent, body: { current: proofFor(OWNER_PW) } });
    const noStep = await fetchJson('/api/private/drive/archive/1', { method: 'DELETE', cookie: oc, headers: intent, body: { confirm: 'owner' } });
    const fin = await fetchJson('/api/private/drive/archive/1/finish', { method: 'POST', cookie: oc, headers: intent, body: { current: proofFor(OWNER_PW) } });
    expect(cross.status).toBe(403);
    expect(noConfirm.status).toBe(400);
    expect(await errorOf(noStep)).toBe('reauth_required');
    expect(fin.status).toBe(409);
  });

  it('R5-L4: an owner Drive with content and no wrap (after AUTHN recovery) takes no first set-up; start over (with the step-up) still works', async () => {
    // The owner's Drive: a recovery-code wrap only (codes need a passkey; a synthetic code in the Directory).
    const ref = await recoveryRef('WXYZ-2345-6789-ABCD');
    await sql(dirOf(), 'INSERT INTO recovery_codes (hash, user_id, created) VALUES (?, ?, 1)', ref, o.id);
    const kcv = await keyCheckValue(o.after.won.dk);
    expect((await keys(oc, { set: [{ kind: 'recovery', ref, data: W() }], kcv })).status).toBe(200);
    expect((await keys(oc, { remove: [{ kind: 'pw', ref: 'pw' }], current: proofFor(OWNER_PW) })).status).toBe(200);
    await uploadFile(oc, 'root', 500);
    await authnRecovery('recovered-owner-pw-6');
    expect((await st(oc)).wraps).toEqual([]);
    const kcvBefore = (await sql(driveOf(o.id), "SELECT v FROM meta WHERE k = 'kcv'"))[0]?.v;
    // A new key as a "first set-up": refused with a clear code, with or without the step-up.
    const other = createDriveKey();
    for (const body of [
      { driveSalt: salt16(), set: [pwWrap()] },
      { driveSalt: salt16(), set: [pwWrap()], kcv: await keyCheckValue(other) },
      { driveSalt: salt16(), set: [pwWrap()], kcv: await keyCheckValue(other), current: proofFor(OWNER_PW) },
    ]) {
      const r = await keys(oc, body);
      expect(r.status, JSON.stringify(Object.keys(body))).toBe(409);
      expect(await errorOf(r)).toBe('drive_keyless');
    }
    expect((await st(oc)).wraps).toEqual([]);
    expect((await sql(driveOf(o.id), "SELECT v FROM meta WHERE k = 'kcv'"))[0]?.v).toBe(kcvBefore);
    // The same DK back (a kit restore) needs the step-up.
    expect(await errorOf(await keys(oc, { driveSalt: salt16(), set: [pwWrap()], kcv }))).toBe('reauth_required');
    // Starting over is not blocked: with the step-up it works.
    const so = await startOver(oc, (await startOverBody()).body);
    expect(so.status).toBe(200);
    expect((await so.json()).ownerReset.epoch).toBe(2);
  });

  it('R5-L4: the way back with a kit: the same DK, with the step-up', async () => {
    // Again a Drive with content and only a recovery-code wrap, then AUTHN recovery.
    const now = await st(oc);
    expect(now.wraps.map((w) => w.kind)).toEqual(['pw']);
    // The start over's DK stands for the kit's: its key check value is the one stored.
    const kcvNow = (await sql(driveOf(o.id), "SELECT v FROM meta WHERE k = 'kcv'"))[0].v;
    const ref = await recoveryRef('KLMN-2345-6789-ABCD');
    await sql(dirOf(), 'INSERT INTO recovery_codes (hash, user_id, created) VALUES (?, ?, 1)', ref, o.id);
    expect((await keys(oc, { set: [{ kind: 'recovery', ref, data: W() }], kcv: kcvNow })).status).toBe(200);
    expect((await keys(oc, { remove: [{ kind: 'pw', ref: 'pw' }], current: proofFor(OWNER_PW) })).status).toBe(200);
    await uploadFile(oc, 'root', 100);
    await authnRecovery('recovered-owner-pw-7');
    expect((await st(oc)).wraps).toEqual([]);
    const restore = await keys(oc, { driveSalt: salt16(), set: [pwWrap()], kcv: kcvNow, current: proofFor(OWNER_PW) });
    expect(restore.status).toBe(200);
    expect((await st(oc)).wraps.map((w) => w.kind)).toEqual(['pw']);
    // Now the Drive opens again: starting over is refused.
    expect(await errorOf(await startOver(oc, (await startOverBody()).body))).toBe('drive_unlockable');
  });

  it('R5-L2: more rounds of three start overs at once: each round one archive, one epoch, one set of keys', async () => {
    for (let round = 0; round < 3; round++) {
      await authnRecovery(`recovered-owner-pw-r${round}`);
      const gensBefore = (await sql(driveOf(o.id), "SELECT gen FROM archive_meta WHERE k = 'at'")).length;
      const epochBefore = (await st(oc)).ownerReset.epoch;
      const bodies = [await startOverBody(), await startOverBody(), await startOverBody()];
      const res = await Promise.all(bodies.map((b) => startOver(oc, b.body)));
      expect(res.map((r) => r.status).sort()).toEqual([200, 409, 409]);
      const won = bodies[res.findIndex((r) => r.status === 200)];
      expect((await sql(driveOf(o.id), "SELECT gen FROM archive_meta WHERE k = 'at'")).length).toBe(gensBefore + 1);
      const now = await st(oc);
      expect(now.ownerReset.epoch).toBe(epochBefore + 1);
      expect(await escrowKeyId(now.escrowPub)).toBe(await escrowKeyId(won.e.publicJwk));
      expect(now.escrowPriv).toBe(won.body.escrowPriv);
      expect((await sql(driveOf(o.id), "SELECT v FROM meta WHERE k = 'kcv'"))[0].v).toBe(won.body.kcv);
      expect(now.wraps).toEqual([won.body.set[0]]);
    }
  });
});

