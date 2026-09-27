// drive-escrow.test.js — the owner's escrow and a Drive's keys (docs/DRIVE.md
// §3, §6), in a storage of its own (the owner has no escrow key at first):
//   - a user's Drive is set up only once the owner's escrow key exists, and
//     always with an escrow wrap for the current key and a wrap of their own;
//   - the escrow wrap cannot be removed; it is always for the current key;
//   - the escrow key is rotated only with the owner's step-up and the owner's
//     signing key's signature; the old private key stays sealed (under the
//     owner's DK) only while some user's escrow wrap still needs it;
//   - regression: no server-held key exists for any Drive — the server stores
//     only wraps and sealed keys, never DK or a key that opens one.
import { env, runInDurableObject } from 'cloudflare:test';
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, fetchJson, intent, salt16, proofFor, USER_PW } from './helpers.js';
import { enableDrive, drive } from './drive-helpers.js';
import { b64urlFromBytes, randomBytes } from '../public/js/bytes.js';
import {
  createDriveKey, createEscrowKeyPair, sealEscrowPriv, openEscrowKeyPair, createSigningKeyPair, sealSigningKey,
  endorseEscrowKey, wrapEscrow, unlockWithEscrow, escrowKeyId, sealEscrowPin,
} from '../public/js/drivekeys.js';

const OWNER_PW = 'owner-password';
let oc;
beforeAll(async () => { oc = await owner(); });

const keys = (cookie, body) => fetchJson('/api/private/drive/keys', { method: 'PUT', cookie, headers: intent, body });
const W = (n = 60) => `1.${b64urlFromBytes(randomBytes(12))}.${b64urlFromBytes(randomBytes(n))}`;
const pwWrap = () => ({ kind: 'pw', ref: 'pw', data: W() });
const driveOf = (uid) => env.DRIVE.get(env.DRIVE.idFromName(`drive:${uid}`));
const dirStub = () => env.DIRECTORY.get(env.DIRECTORY.idFromName('directory'));
const ownerId = async () => (await (await fetchJson('/api/private/me', { cookie: oc })).json()).user.id;
const errorOf = async (r) => (await r.json()).error;

/** Every row of every table of a Durable Object's SQLite storage, as one JSON text. */
const dumpDo = (stub) => runInDurableObject(stub, (inst, state) => {
  const out = {};
  for (const { name } of state.storage.sql.exec("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%'").toArray()) {
    out[name] = state.storage.sql.exec(`SELECT * FROM "${name}"`).toArray();
  }
  return JSON.stringify(out);
});
const driveMeta = (uid) => runInDurableObject(driveOf(uid), (inst, state) => state.storage.sql.exec('SELECT k FROM meta').toArray().map((r) => r.k));
const driveWrapKinds = (uid) => runInDurableObject(driveOf(uid), (inst, state) => state.storage.sql.exec('SELECT kind FROM wraps').toArray().map((r) => r.kind));

describe('the owner’s escrow key and every Drive’s escrow wrap', () => {
  const o = {}; // the owner's DK and keys
  const a = {}; // user A: DK and account

  it('before the owner’s escrow key exists, a user’s Drive is not set up (409 escrow_not_ready) and nothing is stored', async () => {
    a.u = await makeUser('esc-a');
    await enableDrive(a.u.id);
    expect((await drive(a.u.cookie)).escrowPub).toBeNull();
    const r = await keys(a.u.cookie, { driveSalt: salt16(), set: [pwWrap()] });
    expect(r.status).toBe(409);
    expect(await errorOf(r)).toBe('escrow_not_ready');
    const st = await drive(a.u.cookie);
    expect(st.wraps).toEqual([]);
    expect(st.driveSalt).toBeNull();
  });

  it('the owner creates the escrow key and the signing key once, with no step-up', async () => {
    o.dk = createDriveKey();
    o.e1 = await createEscrowKeyPair();
    o.s = await createSigningKeyPair();
    o.sealed1 = await sealEscrowPriv(o.dk, o.e1.privateKey);
    const r = await keys(oc, {
      driveSalt: salt16(), set: [pwWrap()],
      escrowPub: o.e1.publicJwk, escrowPriv: o.sealed1,
      escrowSignPub: o.s.publicJwk, escrowSignPriv: await sealSigningKey(o.dk, o.s.privateKey), escrowSig: await endorseEscrowKey(o.s.privateKey, o.e1.publicJwk),
    });
    expect(r.status).toBe(200);
    o.kid1 = await escrowKeyId(o.e1.publicJwk);
    const st = await drive(a.u.cookie);
    expect(st.escrowPub).toEqual(o.e1.publicJwk);
    expect(st.escrowSignPub).toEqual(o.s.publicJwk);
  });

  it('a new Drive needs an escrow wrap for the current key and a wrap of the user’s own', async () => {
    a.dk = createDriveKey();
    const esc = await wrapEscrow(a.dk, o.e1.publicJwk);
    for (const body of [
      { driveSalt: salt16(), set: [pwWrap()] }, // no escrow wrap
      { set: [esc] }, // no own wrap
      { driveSalt: salt16(), set: [pwWrap(), await wrapEscrow(a.dk, (await createEscrowKeyPair()).publicJwk)] }, // another key's
    ]) {
      const r = await keys(a.u.cookie, body);
      expect(r.status, JSON.stringify(body.set.map((w) => w.kind))).toBe(400);
    }
    expect((await drive(a.u.cookie)).wraps).toEqual([]);
    const ok = await keys(a.u.cookie, { driveSalt: salt16(), set: [pwWrap(), esc], escrowPin: await sealEscrowPin(a.dk, { escrow: o.kid1, sign: null }) });
    expect(ok.status).toBe(200);
    expect((await drive(a.u.cookie)).wraps.map((w) => w.kind).sort()).toEqual(['escrow', 'pw']);
    // The owner's escrow private key opens it (and nothing the server has does).
    const w = (await drive(a.u.cookie)).wraps.find((x) => x.kind === 'escrow');
    const { privateKey } = await openEscrowKeyPair(o.dk, (await drive(oc)).escrowPriv);
    expect(b64urlFromBytes(await unlockWithEscrow(privateKey, w))).toBe(b64urlFromBytes(a.dk));
  });

  it('the user cannot remove the escrow wrap, even with the step-up, nor remove their last own wrap', async () => {
    const r = await keys(a.u.cookie, { remove: [{ kind: 'escrow', ref: 'escrow' }], current: proofFor(USER_PW) });
    expect(r.status).toBe(403);
    expect(await errorOf(r)).toBe('escrow_required');
    const last = await keys(a.u.cookie, { remove: [{ kind: 'pw', ref: 'pw' }], current: proofFor(USER_PW) });
    expect(last.status).toBe(409);
    expect(await errorOf(last)).toBe('last_own_wrap');
    expect((await drive(a.u.cookie)).wraps.map((w) => w.kind).sort()).toEqual(['escrow', 'pw']);
  });

  it('rotation: only with the owner’s step-up and the signing key’s signature', async () => {
    o.e2 = await createEscrowKeyPair();
    const body = { escrowPub: o.e2.publicJwk, escrowPriv: await sealEscrowPriv(o.dk, o.e2.privateKey), escrowSig: await endorseEscrowKey(o.s.privateKey, o.e2.publicJwk) };
    const bare = await keys(oc, body);
    expect(bare.status).toBe(400);
    expect(await errorOf(bare)).toBe('reauth_required');
    expect((await keys(oc, { ...body, current: proofFor('wrong-password-1') })).status).toBe(403);
    // A signature over another key, or by another signing key: refused.
    const other = await createSigningKeyPair();
    for (const sig of [await endorseEscrowKey(o.s.privateKey, o.e1.publicJwk), await endorseEscrowKey(other.privateKey, o.e2.publicJwk)]) {
      expect((await keys(oc, { ...body, escrowSig: sig, current: proofFor(OWNER_PW) })).status).toBe(400);
    }
    expect((await drive(a.u.cookie)).escrowPub).toEqual(o.e1.publicJwk);
    // A user's session never changes the owner's keys.
    expect((await keys(a.u.cookie, { ...body, current: proofFor(USER_PW) })).status).toBe(403);
    const ok = await keys(oc, { ...body, current: proofFor(OWNER_PW) });
    expect(ok.status).toBe(200);
    expect((await drive(a.u.cookie)).escrowPub).toEqual(o.e2.publicJwk);
  });

  it('the old private key stays sealed for the owner while a user’s escrow wrap needs it, and goes once they re-wrap', async () => {
    const st = await drive(oc);
    expect(Object.keys(st.escrowPrivOld)).toEqual([o.kid1]);
    expect(st.escrowPrivOld[o.kid1]).toBe(o.sealed1);
    // Sealed under the owner's DK: the owner opens it, and it opens A's wrap.
    const old = await openEscrowKeyPair(o.dk, st.escrowPrivOld[o.kid1]);
    const w = (await drive(a.u.cookie)).wraps.find((x) => x.kind === 'escrow');
    expect(b64urlFromBytes(await unlockWithEscrow(old.privateKey, w))).toBe(b64urlFromBytes(a.dk));
    // Users never see the owner's keys, old or current.
    const mine = await drive(a.u.cookie);
    for (const k of ['escrowPriv', 'escrowSignPriv', 'escrowPrivOld']) expect(mine[k], k).toBeUndefined();
    // A wrap for the old key is no longer accepted; one for the new key is.
    expect((await keys(a.u.cookie, { set: [await wrapEscrow(a.dk, o.e1.publicJwk)] })).status).toBe(400);
    expect((await keys(a.u.cookie, { set: [await wrapEscrow(a.dk, o.e2.publicJwk)] })).status).toBe(200);
    expect((await drive(oc)).escrowPrivOld).toEqual({});
  });

  it('regression: no server-held key exists for any Drive', async () => {
    const oid = await ownerId();
    const b = await makeUser('esc-b');
    await enableDrive(b.id); // enabled, never set up
    // escrowVer, kit and archiveGen (the owner's only): the escrow key's version,
    // the latest recovery kit's, the last archive's number — public numbers, kids and times.
    const allowedMeta = ['uid', 'driveSalt', 'pendingSec', 'escrowPin', 'pwStale', 'escrowPriv', 'escrowSignPriv', 'escrowPrivOld', 'escrowVer', 'kit', 'archiveGen'];
    for (const uid of [oid, a.u.id, b.id]) {
      for (const k of await driveMeta(uid)) expect(allowedMeta, `${uid}: meta ${k}`).toContain(k);
      for (const k of await driveWrapKinds(uid)) expect(['pw', 'recovery', 'passkey', 'escrow'], `${uid}: wrap ${k}`).toContain(k);
    }
    const ver = await runInDurableObject(driveOf(oid), (inst, state) => state.storage.sql.exec("SELECT v FROM meta WHERE k = 'escrowVer'").toArray()[0]?.v);
    expect(Object.keys(JSON.parse(ver)).sort()).toEqual(['created', 'kid', 'version']);
    for (const uid of [a.u.id, b.id]) for (const k of await driveMeta(uid)) expect(['escrowVer', 'kit', 'archiveGen']).not.toContain(k);
    // Only the owner's Drive holds (sealed) escrow keys.
    for (const k of await driveMeta(a.u.id)) expect(['escrowPriv', 'escrowSignPriv', 'escrowPrivOld']).not.toContain(k);
    // No other kind of wrap, and no hand-over key, is accepted or handed out.
    const hand = await keys(a.u.cookie, { set: [{ kind: 'handoff', ref: 'handoff', data: W() }] });
    expect(hand.status).toBe(400);
    expect((await keys(a.u.cookie, { handoffKey: b64urlFromBytes(randomBytes(32)) })).status).toBe(400);
    for (const c of [oc, a.u.cookie, b.cookie]) expect(Object.keys(await drive(c))).not.toContain('handoffKey');
    // DK is nowhere in the server's storage: not in any Drive, not in the Directory.
    const texts = [await dumpDo(dirStub()), ...(await Promise.all([oid, a.u.id, b.id].map((uid) => dumpDo(driveOf(uid)))))];
    for (const dk of [o.dk, a.dk]) {
      const needle = b64urlFromBytes(dk);
      for (const t of texts) expect(t.includes(needle)).toBe(false);
    }
    // The Directory keeps only public escrow data for the Drive.
    const dirMeta = await runInDurableObject(dirStub(), (inst, state) => state.storage.sql.exec("SELECT k FROM meta WHERE k LIKE 'drive.%'").toArray().map((r) => r.k));
    for (const k of dirMeta) expect(k, k).toMatch(/^drive\.(escrowPub|escrowSignPub|escrowSig|escrowKid:.+|ownerReset)$/);
    // And the Worker has no secret for the Drive.
    expect(Object.keys(env).filter((k) => /drive|handoff|escrow/i.test(k) && k !== 'DRIVE')).toEqual([]);
  });
});
