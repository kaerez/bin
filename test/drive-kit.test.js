// drive-kit.test.js — the server side of the owner recovery kit and of the
// owner starting over without one (docs/DRIVE.md §3), in a storage of its own:
//   - AUTHN owner recovery drops the owner's passkey / recovery-code wraps and
//     marks the owner's Drive pwStale, and changes no escrow key;
//   - the kit routes are the owner's only (403 for a user, 403 while
//     impersonating); a download is recorded (version, kid, time) only after
//     the step-up; a check is recorded with its verdict and changes nothing;
//     the live check hands out one escrow wrap per kid in use (audited);
//   - sealed escrow keys are put back only for the server's own public keys
//     and kids in use, always with the step-up, and nothing else changes;
//   - the escrow key's version: 1 at the first creation, one more per
//     rotation, never moved by anything else;
//   - starting over: only when no wrap the owner can open is left, with the
//     typed username and the step-up; the old Drive is archived intact (items,
//     R2 objects, wraps); the owner reset is recorded; no user's Drive changes;
//     the archive comes back (parents first, with the step-up) or is deleted
//     (typed username, step-up); a user's browser moving to the reset's key is
//     recorded in their activity and the admin audit.
import { env, runInDurableObject } from 'cloudflare:test';
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, setOwnerCookie, login, makeUser, fetchJson, intent, salt16, proofFor, USER_PW } from './helpers.js';
import { enableDrive, drive, enc, mkdir, uploadFile, del, KCV } from './drive-helpers.js';
import worker from '../src/index.js';
import { b64urlFromBytes, randomBytes } from '../public/js/bytes.js';
import {
  createDriveKey, createEscrowKeyPair, sealEscrowPriv, createSigningKeyPair, sealSigningKey, endorseEscrowKey, wrapEscrow, escrowKeyId, sealEscrowPin,
} from '../public/js/drivekeys.js';
import { driveChunkKey } from '../src/drive-do.js';

const ORIGIN = 'https://secbin.test';
let OWNER_PW = 'owner-password';
let oc;
beforeAll(async () => { oc = await owner(); });

const keys = (cookie, body) => fetchJson('/api/private/drive/keys', { method: 'PUT', cookie, headers: intent, body });
const kit = (cookie, body) => fetchJson('/api/private/drive/kit', { method: 'POST', cookie, headers: intent, body });
const kitKeys = (cookie, body) => fetchJson('/api/private/drive/kit/keys', { method: 'PUT', cookie, headers: intent, body });
const startOver = (cookie, body) => fetchJson('/api/private/drive/start-over', { method: 'POST', cookie, headers: intent, body });
const W = (n = 60) => `1.${b64urlFromBytes(randomBytes(12))}.${b64urlFromBytes(randomBytes(n))}`;
const driveOf = (uid) => env.DRIVE.get(env.DRIVE.idFromName(`drive:${uid}`));
const errorOf = async (r) => (await r.json()).error;
const me = async (cookie) => (await (await fetchJson('/api/private/me', { cookie })).json()).user;
const audit = async (uid) => (await (await fetchJson(`/api/private/admin/audit?user=${uid}&limit=500`, { cookie: oc })).json()).rows;
const activity = async (cookie) => (await (await fetchJson('/api/private/me/activity', { cookie })).json()).rows;
const rows = (uid, sql) => runInDurableObject(driveOf(uid), (inst, state) => state.storage.sql.exec(sql).toArray());
/** Call the Worker with a modified env (a new AUTHN value, for a recovery). */
const callWith = (overrides, path, init = {}) => worker.fetch(new Request(`${ORIGIN}${path}`, init), { ...env, ...overrides }, { waitUntil() {} });
async function authnRecovery(newPassword) {
  const NEW = `recovery-token-${b64urlFromBytes(randomBytes(16))}`;
  const r = await callWith({ AUTHN: NEW }, '/api/auth/setup', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token: NEW, username: 'owner', salt: salt16(), t: 3, proof: proofFor(newPassword) }),
  });
  expect(r.status).toBe(200);
  expect((await r.json()).recovered).toBe(true);
  OWNER_PW = newPassword;
  oc = await login('owner', newPassword);
  setOwnerCookie(oc);
}
const publicKeys = async () => { const st = await drive(oc); return { escrowPub: st.escrowPub, escrowSignPub: st.escrowSignPub, version: st.escrowVersion }; };

describe('the owner recovery kit (server)', () => {
  const o = {};
  const a = {};

  it('the first escrow key is version 1; a user\'s Drive is set up on it', async () => {
    o.id = (await me(oc)).id;
    o.dk = createDriveKey();
    o.e1 = await createEscrowKeyPair();
    o.s = await createSigningKeyPair();
    o.sealed1 = await sealEscrowPriv(o.dk, o.e1.privateKey);
    const r = await keys(oc, {
      driveSalt: salt16(), set: [{ kind: 'pw', ref: 'pw', data: W() }], kcv: KCV, escrowPub: o.e1.publicJwk, escrowPriv: o.sealed1,
      escrowSignPub: o.s.publicJwk, escrowSignPriv: await sealSigningKey(o.dk, o.s.privateKey), escrowSig: await endorseEscrowKey(o.s.privateKey, o.e1.publicJwk),
    });
    expect(r.status).toBe(200);
    o.kid1 = await escrowKeyId(o.e1.publicJwk);
    const st = await drive(oc);
    expect(st.escrowVersion).toMatchObject({ version: 1, kid: o.kid1 });
    expect(st.escrowVersion.created).toBeGreaterThan(0);
    expect(st.kit).toBeNull();
    a.u = await makeUser('kit-a');
    await enableDrive(a.u.id);
    a.dk = createDriveKey();
    expect((await keys(a.u.cookie, { driveSalt: salt16(), set: [{ kind: 'pw', ref: 'pw', data: W() }, await wrapEscrow(a.dk, o.e1.publicJwk)], escrowPin: await sealEscrowPin(a.dk, { escrow: o.kid1, sign: null }), kcv: KCV })).status).toBe(200);
    // A user's re-wrap to the same key (a replacement: the step-up) changes no escrow key and no version.
    const before = await publicKeys();
    expect((await keys(a.u.cookie, { set: [await wrapEscrow(a.dk, o.e1.publicJwk)], kcv: KCV, current: proofFor(USER_PW) })).status).toBe(200);
    expect(await publicKeys()).toEqual(before);
    // The user sees no owner-only kit data.
    const ust = await drive(a.u.cookie);
    for (const k of ['kit', 'escrowVersion', 'archives', 'escrowKids']) expect(ust[k], k).toBeUndefined();
  });

  it('the kit routes are the owner\'s only: 403 for a user and while impersonating', async () => {
    for (const [method, path] of [['POST', '/api/private/drive/kit'], ['GET', '/api/private/drive/kit/probe'], ['PUT', '/api/private/drive/kit/keys'], ['POST', '/api/private/drive/start-over'], ['GET', '/api/private/drive/archive/1'], ['DELETE', '/api/private/drive/archive/1']]) {
      const r = await fetchJson(path, { method, cookie: a.u.cookie, headers: intent, body: method === 'GET' ? undefined : { event: 'exported', current: proofFor(USER_PW) } });
      expect(r.status, `${method} ${path}`).toBe(403);
      expect(await errorOf(r)).toBe('owner_only');
    }
    const ic = await (async () => {
      const r = await fetchJson(`/api/private/admin/users/${a.u.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent });
      expect(r.status).toBe(200);
      return r.headers.get('set-cookie').split(';')[0];
    })();
    const r = await kit(ic, { event: 'exported', current: proofFor(OWNER_PW) });
    expect(r.status).toBe(403);
    expect(await errorOf(r)).toBe('impersonating');
    expect((await fetchJson('/api/private/admin/unimpersonate', { method: 'POST', cookie: ic, headers: intent })).status).toBe(200);
  });

  it('a download is recorded only after the step-up, with the version, kid and time, in the admin audit only', async () => {
    const bare = await kit(oc, { event: 'exported' });
    expect(bare.status).toBe(400);
    expect(await errorOf(bare)).toBe('reauth_required');
    expect((await kit(oc, { event: 'exported', current: proofFor('wrong-password-9') })).status).toBe(403);
    expect((await drive(oc)).kit).toBeNull();
    const ok = await kit(oc, { event: 'exported', current: proofFor(OWNER_PW) });
    expect(ok.status).toBe(200);
    const st = await drive(oc);
    expect(st.kit).toMatchObject({ version: 1, kid: o.kid1 });
    expect(st.kit.at).toBeGreaterThan(0);
    // Always available: a second download is recorded again.
    expect((await kit(oc, { event: 'exported', current: proofFor(OWNER_PW) })).status).toBe(200);
    const exported = (await audit(o.id)).filter((x) => x.action === 'drive.kit_exported');
    expect(exported.length).toBe(2);
    expect(exported[0].detail).toContain('version=1');
    expect((await activity(oc)).some((x) => x.action.startsWith('drive.kit_'))).toBe(false);
    expect((await kit(oc, { event: 'nonsense' })).status).toBe(400);
  });

  it('a check is recorded with its verdict and changes no Drive state; the live check hands out one escrow wrap per kid in use (audited)', async () => {
    const before = JSON.stringify(await rows(o.id, 'SELECT k, v FROM meta ORDER BY k'));
    const bad = await kit(oc, { event: 'verified', verdict: 'fine' });
    expect(bad.status).toBe(400);
    expect((await kit(oc, { event: 'verified', verdict: 'incomplete', issues: ['current', 'version'], version: 1 })).status).toBe(200);
    expect(JSON.stringify(await rows(o.id, 'SELECT k, v FROM meta ORDER BY k'))).toBe(before);
    const v = (await audit(o.id)).find((x) => x.action === 'drive.kit_verified');
    expect(v.detail).toContain('verdict=incomplete');
    expect(v.detail).toContain('issues=current,version');
    const pr = await fetchJson('/api/private/drive/kit/probe', { cookie: oc });
    expect(pr.status).toBe(200);
    const { probes } = await pr.json();
    expect(probes).toHaveLength(1);
    expect(probes[0].kid).toBe(o.kid1);
    expect(probes[0].wrap.kind).toBe('escrow');
    expect((await audit(a.u.id)).some((x) => x.action === 'drive.escrow_used' && x.detail.includes('owner recovery kit check'))).toBe(true);
    const cross = await fetchJson('/api/private/drive/kit/probe', { cookie: oc, headers: { 'sec-fetch-site': 'cross-site' } });
    expect(cross.status).toBe(403);
  });

  it('a rotation is version 2; restoring the public key alone moves no version', async () => {
    o.e2 = await createEscrowKeyPair();
    o.sealed2 = await sealEscrowPriv(o.dk, o.e2.privateKey);
    expect((await keys(oc, { escrowPub: o.e2.publicJwk, escrowPriv: o.sealed2, escrowSig: await endorseEscrowKey(o.s.privateKey, o.e2.publicJwk), current: proofFor(OWNER_PW) })).status).toBe(200);
    o.kid2 = await escrowKeyId(o.e2.publicJwk);
    let st = await drive(oc);
    expect(st.escrowVersion).toMatchObject({ version: 2, kid: o.kid2 });
    expect(st.kit.kid).toBe(o.kid1); // the latest kit is for the older key now
    // The same public key put back (a "restore"): not a rotation.
    expect((await keys(oc, { escrowPub: o.e2.publicJwk, escrowSig: await endorseEscrowKey(o.s.privateKey, o.e2.publicJwk), current: proofFor(OWNER_PW) })).status).toBe(200);
    st = await drive(oc);
    expect(st.escrowVersion.version).toBe(2);
    expect(Object.keys(st.escrowPrivOld)).toEqual([o.kid1]);
  });

  it('AUTHN owner recovery drops the owner\'s passkey and recovery-code wraps, marks pwStale, and changes no escrow key', async () => {
    // A stand-in recovery-code wrap (its code is gone after the recovery).
    await runInDurableObject(driveOf(o.id), (inst, state) => state.storage.sql.exec("INSERT INTO wraps (kind, ref, data) VALUES ('recovery', ?, ?)", 'a'.repeat(64), W()));
    const before = await publicKeys();
    expect((await drive(oc)).pwStale).toBe(false);
    await authnRecovery('recovered-owner-pw-1');
    const st = await drive(oc);
    expect(st.pwStale).toBe(true);
    expect(st.wraps.map((w) => w.kind)).toEqual(['pw']); // the old pw wrap stays (stale), the code's is gone
    expect(await publicKeys()).toEqual(before);
    expect(st.escrowPriv).toBe(o.sealed2);
  });

  it('sealed escrow keys come back only for the server\'s own public keys and kids in use, always with the step-up', async () => {
    await runInDurableObject(driveOf(o.id), (inst, state) => {
      state.storage.sql.exec("DELETE FROM meta WHERE k IN ('escrowPriv', 'escrowSignPriv')");
    });
    const before = await publicKeys();
    const other = await createEscrowKeyPair();
    const otherSign = await createSigningKeyPair();
    const step = { current: proofFor(OWNER_PW) };
    for (const body of [
      { escrowPriv: { pub: other.publicJwk, data: W() } }, // not the server's escrow key
      { escrowSignPriv: { pub: otherSign.publicJwk, data: W() } }, // not the server's signing key
      { escrowPrivOld: { [await escrowKeyId(other.publicJwk)]: { pub: other.publicJwk, data: W() } } }, // not a kid in use
      { escrowPrivOld: { [o.kid2]: { pub: o.e2.publicJwk, data: W() } } }, // the current key is not an earlier one
      { escrowPrivOld: { [o.kid1]: { pub: o.e2.publicJwk, data: W() } } }, // a kid that is not its key's
    ]) {
      const r = await kitKeys(oc, { ...body, ...step });
      expect(r.status, JSON.stringify(Object.keys(body))).toBe(400);
      expect(await errorOf(r)).toBe('key_mismatch');
    }
    const good = { escrowPriv: { pub: o.e2.publicJwk, data: o.sealed2 }, escrowSignPriv: { pub: o.s.publicJwk, data: await sealSigningKey(o.dk, o.s.privateKey) } };
    const bare = await kitKeys(oc, good);
    expect(bare.status).toBe(400);
    expect(await errorOf(bare)).toBe('reauth_required');
    expect((await kitKeys(oc, { ...good, current: proofFor('wrong-password-9') })).status).toBe(403);
    expect((await kitKeys(oc, { ...good, ...step })).status).toBe(200);
    const st = await drive(oc);
    expect(st.escrowPriv).toBe(o.sealed2);
    expect(typeof st.escrowSignPriv).toBe('string');
    expect(await publicKeys()).toEqual(before); // nothing public changed: no key, no version
    expect((await audit(o.id)).some((x) => x.action === 'drive.kit_keys_restored')).toBe(true);
    // A kit use checks the password.
    expect((await kit(oc, { event: 'used', version: 1 })).status).toBe(400);
    expect((await kit(oc, { event: 'used', version: 1, ...step })).status).toBe(200);
  });

  it('starting over: refused while a wrap the owner can open is left; needs the typed username and the step-up', async () => {
    // The owner writes a fresh pw wrap (stale: no step-up), so the Drive can be opened again.
    const fresh = W();
    expect((await keys(oc, { driveSalt: salt16(), set: [{ kind: 'pw', ref: 'pw', data: fresh }], kcv: KCV })).status).toBe(200);
    o.body = async () => {
      o.dk2 = createDriveKey();
      const e = await createEscrowKeyPair();
      const s = await createSigningKeyPair();
      o.e3 = e;
      o.s3 = s;
      return {
        confirm: 'owner', driveSalt: salt16(), set: [{ kind: 'pw', ref: 'pw', data: W() }], escrowPub: e.publicJwk, escrowPriv: await sealEscrowPriv(o.dk2, e.privateKey),
        escrowSignPub: s.publicJwk, escrowSignPriv: await sealSigningKey(o.dk2, s.privateKey), escrowSig: await endorseEscrowKey(s.privateKey, e.publicJwk), kcv: KCV,
      };
    };
    const usable = await startOver(oc, { ...(await o.body()), current: proofFor(OWNER_PW) });
    expect(usable.status).toBe(409);
    expect(await errorOf(usable)).toBe('drive_unlockable');
    // The Drive's content, before the owner loses the way in again.
    o.folder = (await mkdir(oc)).id;
    o.file = await uploadFile(oc, o.folder, 5000);
    o.oldWraps = (await drive(oc)).wraps;
    await authnRecovery('recovered-owner-pw-2');
    const b = await o.body();
    const noConfirm = await startOver(oc, { ...b, confirm: 'someone', current: proofFor(OWNER_PW) });
    expect(noConfirm.status).toBe(400);
    expect(await errorOf(noConfirm)).toBe('confirm_required');
    const noStep = await startOver(oc, b);
    expect(noStep.status).toBe(400);
    expect(await errorOf(noStep)).toBe('reauth_required');
    expect((await startOver(oc, { ...b, current: proofFor('wrong-password-9') })).status).toBe(403);
    // Unsigned by its own new signing key: refused.
    expect((await startOver(oc, { ...b, escrowSig: await endorseEscrowKey(o.s.privateKey, b.escrowPub), current: proofFor(OWNER_PW) })).status).toBe(400);
    expect((await drive(oc)).escrowPub).toEqual(o.e2.publicJwk);
  });

  it('starting over archives the old Drive intact, records the reset, and changes no user\'s Drive', async () => {
    const userBefore = JSON.stringify(await rows(a.u.id, 'SELECT * FROM wraps ORDER BY kind, ref')) + JSON.stringify(await rows(a.u.id, 'SELECT k, v FROM meta ORDER BY k'));
    const oldNodes = (await rows(o.id, "SELECT id, name, fk FROM nodes WHERE id != 'root' ORDER BY id"));
    const oldWraps = (await drive(oc)).wraps;
    const b = await o.body();
    const r = await startOver(oc, { ...b, current: proofFor(OWNER_PW) });
    expect(r.status).toBe(200);
    const out = await r.json();
    expect(out.archive).toBe(1);
    expect(out.escrowVersion).toMatchObject({ version: 3, kid: await escrowKeyId(o.e3.publicJwk) });
    expect(out.ownerReset).toMatchObject({ epoch: 1, kid: await escrowKeyId(o.e3.publicJwk), signPub: o.s3.publicJwk });
    const st = await drive(oc);
    expect(st.escrowPub).toEqual(o.e3.publicJwk);
    expect(st.escrowSignPub).toEqual(o.s3.publicJwk);
    expect(st.wraps.map((w) => w.kind)).toEqual(['pw']);
    expect(st.pwStale).toBe(false);
    expect(st.kit).toBeNull();
    expect(st.escrowPrivOld).toEqual({});
    expect(st.ownerReset).toMatchObject({ epoch: 1 });
    expect(st.archives).toEqual([expect.objectContaining({ gen: 1, items: oldNodes.length, bytes: 5000 })]);
    // The archive: the same items, the same wraps, the same R2 objects.
    expect(await rows(o.id, 'SELECT id, name, fk FROM archive_nodes WHERE gen = 1 ORDER BY id')).toEqual(oldNodes);
    expect((await rows(o.id, 'SELECT kind, ref, data FROM archive_wraps WHERE gen = 1 ORDER BY kind, ref')).map((w) => ({ ...w }))).toEqual(oldWraps.map((w) => ({ kind: w.kind, ref: w.ref, data: w.data })));
    const obj = await env.FILES.get(driveChunkKey(o.id, o.file.id, 0));
    expect(obj).not.toBeNull();
    expect(new Uint8Array(await obj.arrayBuffer())).toEqual(o.file.chunks[0]);
    expect((await rows(o.id, "SELECT v FROM archive_meta WHERE gen = 1 AND k = 'escrowPriv'"))[0].v).toBe(o.sealed2);
    // The Drive is empty; the archive counts towards its storage.
    expect((await (await fetchJson('/api/private/drive/nodes/root', { cookie: oc })).json()).children).toEqual([]);
    expect(st.used).toBeGreaterThanOrEqual(5000);
    // An archived item is not reachable as an item of the Drive.
    expect((await fetchJson(`/api/private/drive/nodes/${o.file.id}`, { cookie: oc })).status).toBe(404);
    expect((await del(oc, o.folder)).status).toBe(404);
    // No user's Drive changed.
    expect(JSON.stringify(await rows(a.u.id, 'SELECT * FROM wraps ORDER BY kind, ref')) + JSON.stringify(await rows(a.u.id, 'SELECT k, v FROM meta ORDER BY k'))).toBe(userBefore);
    expect((await audit(o.id)).some((x) => x.action === 'drive.owner_reset' && x.detail.includes('archive 1'))).toBe(true);
    // The user sees the reset record (public), not the owner's keys.
    expect((await drive(a.u.cookie)).ownerReset).toMatchObject({ epoch: 1, kid: await escrowKeyId(o.e3.publicJwk) });
  });

  it('a user\'s move to the reset\'s key is recorded in their activity (system event) and the admin audit', async () => {
    const bad = await keys(a.u.cookie, { set: [await wrapEscrow(a.dk, o.e3.publicJwk)], escrowReset: 2 });
    expect(bad.status).toBe(400);
    const r = await keys(a.u.cookie, { set: [await wrapEscrow(a.dk, o.e3.publicJwk)], escrowPin: await sealEscrowPin(a.dk, { escrow: await escrowKeyId(o.e3.publicJwk), sign: null, epoch: 1 }), escrowReset: 1, kcv: KCV });
    expect(r.status).toBe(200);
    const mine = (await activity(a.u.cookie)).find((x) => x.action === 'drive.escrow_rewrapped');
    expect(mine).toBeTruthy();
    expect(mine.detail).toContain((await escrowKeyId(o.e3.publicJwk)).slice(0, 4));
    expect((await audit(a.u.id)).some((x) => x.action === 'drive.escrow_rewrapped' && x.detail.includes('user=kit-a'))).toBe(true);
    // The owner cannot claim a user's reset re-wrap.
    expect((await keys(oc, { escrowReset: 1, set: [{ kind: 'pw', ref: 'pw', data: W() }] })).status).toBe(400);
  });

  it('the archive comes back only folders first, with the step-up; its escrow keys join the owner\'s for kids in use', async () => {
    const view = await (await fetchJson('/api/private/drive/archive/1', { cookie: oc })).json();
    expect(view.escrowPriv).toBe(o.sealed2);
    expect(view.nodes.map((n) => n.id).sort()).toEqual([o.folder, o.file.id].sort());
    const put = (body) => fetchJson('/api/private/drive/archive/1/nodes', { method: 'PUT', cookie: oc, headers: intent, body });
    const step = { current: proofFor(OWNER_PW) };
    const file = { id: o.file.id, name: enc(), meta: enc(), fk: enc(32) };
    const folder = { id: o.folder, name: enc() };
    expect((await put({ nodes: [folder] })).status).toBe(400); // no step-up
    const early = await put({ nodes: [file], ...step });
    expect(early.status).toBe(409);
    expect(await errorOf(early)).toBe('parent_first');
    // A user is still on kid1 (never moved): that key may come back; kid2 (no user's) may not.
    const fin = (body) => fetchJson('/api/private/drive/archive/1/finish', { method: 'POST', cookie: oc, headers: intent, body });
    expect((await fin({ ...step })).status).toBe(409); // items still archived
    const r = await put({ nodes: [folder, file], ...step });
    expect(r.status).toBe(200);
    expect(await r.json()).toMatchObject({ restored: 2, left: 0 });
    const b = await makeUser('kit-b');
    await enableDrive(b.id);
    await runInDurableObject(env.DIRECTORY.get(env.DIRECTORY.idFromName('directory')), (inst, state) => state.storage.sql.exec('INSERT INTO meta (k, v) VALUES (?, ?)', `drive.escrowKid:${b.id}`, o.kid1));
    const notInUse = await fin({ escrowPrivOld: { [o.kid2]: { pub: o.e2.publicJwk, data: W() } }, ...step });
    expect(notInUse.status).toBe(400);
    const resealed = W();
    const done = await fin({ escrowPrivOld: { [o.kid1]: { pub: o.e1.publicJwk, data: resealed } }, ...step });
    expect(done.status).toBe(200);
    const st = await drive(oc);
    expect(st.archives).toEqual([]);
    expect(st.escrowPrivOld[o.kid1]).toBe(resealed);
    expect((await (await fetchJson('/api/private/drive/nodes/root', { cookie: oc })).json()).children.map((c) => c.id)).toEqual([o.folder]);
    expect(await env.FILES.get(driveChunkKey(o.id, o.file.id, 0))).not.toBeNull();
    expect((await audit(o.id)).some((x) => x.action === 'drive.archive_restored')).toBe(true);
    expect(await rows(o.id, 'SELECT gen FROM archive_wraps')).toEqual([]);
  });

  it('an archive is deleted only with the typed username and the step-up, R2 objects included', async () => {
    // A second start over (after losing the way in again) archives the Drive as generation 2.
    await authnRecovery('recovered-owner-pw-3');
    const r = await startOver(oc, { ...(await o.body()), current: proofFor(OWNER_PW) });
    expect(r.status).toBe(200);
    expect((await r.json()).archive).toBe(2);
    expect((await drive(oc)).ownerReset.epoch).toBe(2);
    const delA = (body) => fetchJson('/api/private/drive/archive/2', { method: 'DELETE', cookie: oc, headers: intent, body });
    expect(await errorOf(await delA({ confirm: 'nope', current: proofFor(OWNER_PW) }))).toBe('confirm_required');
    expect(await errorOf(await delA({ confirm: 'owner' }))).toBe('reauth_required');
    expect((await delA({ confirm: 'owner', current: proofFor('wrong-password-9') })).status).toBe(403);
    expect(await env.FILES.get(driveChunkKey(o.id, o.file.id, 0))).not.toBeNull();
    const ok = await delA({ confirm: 'owner', current: proofFor(OWNER_PW) });
    expect(ok.status).toBe(200);
    expect(await env.FILES.get(driveChunkKey(o.id, o.file.id, 0))).toBeNull();
    expect((await drive(oc)).archives).toEqual([]);
    expect(await rows(o.id, 'SELECT id FROM archive_nodes')).toEqual([]);
    expect((await audit(o.id)).some((x) => x.action === 'drive.archive_deleted')).toBe(true);
  });
});

describe('the owner sets up a new user’s Drive (Admin → Users)', () => {
  const adminKeys = (cookie, id, body) => fetchJson(`/api/private/admin/drive/keys/${id}`, { method: 'PUT', cookie, headers: intent, body });
  const escrowNow = async () => (await drive(oc)).escrowPub;
  const firstBody = async (dk, pub, extra = {}) => ({
    first: true, driveSalt: salt16(), set: [{ kind: 'pw', ref: 'pw', data: W() }, await wrapEscrow(dk, pub)],
    escrowPin: await sealEscrowPin(dk, { escrow: await escrowKeyId(pub), sign: null }), kcv: KCV, ...extra,
  });

  it('only for a user with no wrap yet: one pw and one escrow wrap for the current key, with the kcv; logged', async () => {
    const c = await makeUser('kit-created');
    await enableDrive(c.id);
    const dk = createDriveKey();
    const pub = await escrowNow();
    for (const body of [
      { ...(await firstBody(dk, pub)), set: [{ kind: 'pw', ref: 'pw', data: W() }] }, // no escrow wrap
      { ...(await firstBody(dk, pub)), set: [{ kind: 'pw', ref: 'pw', data: W() }, await wrapEscrow(dk, pub), { kind: 'passkey', ref: 'cred1', data: W() }] }, // an extra kind
      { ...(await firstBody(dk, pub)), set: [{ kind: 'pw', ref: 'pw', data: W() }, await wrapEscrow(dk, (await createEscrowKeyPair()).publicJwk)] }, // another key's
      { ...(await firstBody(dk, pub)), kcv: undefined }, // no check value
      { ...(await firstBody(dk, pub)), escrowPin: undefined },
    ]) {
      const r = await adminKeys(oc, c.id, body);
      expect(r.status, JSON.stringify(body.set.map((w) => w.kind))).toBe(400);
    }
    expect((await adminKeys(c.cookie, c.id, await firstBody(dk, pub))).status).toBe(403); // a user
    const r = await adminKeys(oc, c.id, await firstBody(dk, pub));
    expect(r.status).toBe(200);
    expect((await drive(c.cookie)).wraps.map((w) => w.kind).sort()).toEqual(['escrow', 'pw']);
    const again = await adminKeys(oc, c.id, await firstBody(dk, pub));
    expect(again.status).toBe(409);
    expect(await errorOf(again)).toBe('drive_exists');
    expect((await audit(c.id)).some((x) => x.action === 'drive.created_by_owner' && x.adm === 1)).toBe(true);
    const mine = (await activity(c.cookie)).filter((x) => x.action === 'drive.created_by_owner');
    expect(mine).toEqual([expect.objectContaining({ detail: '' })]); // a system event, no admin detail
    // The pw wrap after a reset: only as a wrap of the same DK.
    const bad = await adminKeys(oc, c.id, { driveSalt: salt16(), set: [{ kind: 'pw', ref: 'pw', data: W() }], kcv: KCV.replace(/^./, KCV[0] === 'A' ? 'B' : 'A') });
    expect(await errorOf(bad)).toBe('kcv_mismatch');
  });

  it('the create response says whether the role has the Drive; for a role without one the server still refuses (409 drive_disabled) and stores nothing', async () => {
    const created = async (username) => {
      const r = await fetchJson('/api/private/admin/users', { method: 'POST', cookie: oc, body: { username, salt: salt16(), t: 3, proof: proofFor(USER_PW) } });
      expect(r.status).toBe(201);
      return (await r.json()).user;
    };
    // The Default role has no Drive: the owner's browser makes no set-up request for it.
    const u = await created('kit-create-nodrive');
    expect(u.drive).toEqual(expect.objectContaining({ enabled: false, used: 0 }));
    // Were it sent anyway (a race with a role change), the guard stays: 409, no wrap, no pin, no audit entry.
    const dk = createDriveKey();
    const r = await adminKeys(oc, u.id, await firstBody(dk, await escrowNow()));
    expect(r.status).toBe(409);
    expect(await errorOf(r)).toBe('drive_disabled');
    expect(await rows(u.id, 'SELECT kind FROM wraps')).toEqual([]);
    expect((await audit(u.id)).some((x) => x.action === 'drive.created_by_owner')).toBe(false);
    // With the Drive on its role, the same request sets it up.
    await enableDrive(u.id);
    expect((await adminKeys(oc, u.id, await firstBody(dk, await escrowNow()))).status).toBe(200);
  });

  it('refused while impersonating, and for a role without a Drive; an imported account has no Drive until it signs in', async () => {
    const d = await makeUser('kit-nodrive');
    const dk = createDriveKey();
    const nd = await adminKeys(oc, d.id, await firstBody(dk, await escrowNow()));
    expect(nd.status).toBe(409);
    expect(await errorOf(nd)).toBe('drive_disabled');
    await enableDrive(d.id);
    const ir = await fetchJson(`/api/private/admin/users/${d.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent });
    const ic = ir.headers.get('set-cookie').split(';')[0];
    expect((await adminKeys(ic, d.id, await firstBody(dk, await escrowNow()))).status).toBe(403);
    expect((await fetchJson('/api/private/admin/unimpersonate', { method: 'POST', cookie: ic, headers: intent })).status).toBe(200);
    // Import: the account comes with a verifier only, never a Drive.
    const ex = await fetchJson('/api/private/admin/export', { method: 'POST', cookie: oc, body: { current: proofFor(OWNER_PW), users: [d.id], parts: ['credentials'] } });
    expect(ex.status).toBe(200);
    const doc = (await ex.json()).document;
    const imp = await fetchJson('/api/private/admin/import', { method: 'POST', cookie: oc, body: { current: proofFor(OWNER_PW), document: doc, decisions: { system: false, users: { 'kit-nodrive': { as: 'kit-imported' } } }, dryRun: false } });
    expect(imp.status).toBe(200);
    const id = (await (await fetchJson('/api/private/admin/users', { cookie: oc })).json()).users.find((u) => u.username === 'kit-imported').id;
    expect(await rows(id, 'SELECT kind FROM wraps')).toEqual([]);
  });
});
