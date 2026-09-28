// drive-audit5.test.js — regressions for the round-5 audit of the Drive (server
// side), in a storage of its own. Each block was a proof of concept that passed
// against be7654a and now asserts the fix (SECURITY.md, "Drive keys"):
//   - R5-L1: an existing passkey, recovery-code or escrow wrap is replaced
//     only with the step-up and the Drive's key check value;
//   - R5-L2: two first set-ups at once (the user's own, or the owner's for a
//     new user) leave one DK: one wins, the other gets 409;
//   - R5-L3: the key check value is required at every first set-up and is
//     never taken from a later change; a Drive without one takes no pw wrap;
//   - R5-I2: the owner's kit check (`kit/probe`) is rate limited per session;
//   - R5-I3: the admin escrow route returns only the escrow wrap;
//   - R5-I6: the owner's own Drive takes no escrow wrap;
//   - access control on the new routes stays as it was.
// Synthetic data only (made-up users, random keys).
import { env, runInDurableObject } from 'cloudflare:test';
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, login, fetchJson, intent, salt16, proofFor, USER_PW, cookieOf } from './helpers.js';
import { enableDrive, drive, enc } from './drive-helpers.js';
import { b64urlFromBytes, randomBytes } from '../public/js/bytes.js';
import {
  createDriveKey, createEscrowKeyPair, sealEscrowPriv, openEscrowKeyPair, createSigningKeyPair, sealSigningKey,
  endorseEscrowKey, wrapEscrow, unlockWithEscrow, escrowKeyId, sealEscrowPin, keyCheckValue, recoveryRef,
} from '../public/js/drivekeys.js';
import { KIT_PROBE_MAX } from '../src/routes/drive.js';

let oc;
const o = {};
const keys = (cookie, body, headers = intent) => fetchJson('/api/private/drive/keys', { method: 'PUT', cookie, headers, body });
const adminKeys = (id, body) => fetchJson(`/api/private/admin/drive/keys/${id}`, { method: 'PUT', cookie: oc, headers: intent, body });
const W = (n = 60) => `1.${b64urlFromBytes(randomBytes(12))}.${b64urlFromBytes(randomBytes(n))}`;
const pwWrap = () => ({ kind: 'pw', ref: 'pw', data: W() });
const driveOf = (uid) => env.DRIVE.get(env.DRIVE.idFromName(`drive:${uid}`));
const dirStub = () => env.DIRECTORY.get(env.DIRECTORY.idFromName('directory'));
const meta = (uid, k) => runInDurableObject(driveOf(uid), (inst, state) => state.storage.sql.exec('SELECT v FROM meta WHERE k = ?', k).toArray()[0]?.v ?? null);
const wrapsOf = (uid) => runInDurableObject(driveOf(uid), (inst, state) => state.storage.sql.exec('SELECT kind, ref, data FROM wraps ORDER BY kind, ref').toArray());
const errorOf = async (r) => { try { return (await r.clone().json()).error; } catch { return null; } };
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
async function impersonate(uid) {
  const r = await fetchJson(`/api/private/admin/users/${uid}/impersonate`, { method: 'POST', cookie: oc, headers: intent });
  expect(r.status).toBe(200);
  return cookieOf(r);
}
const unimpersonate = (ic) => fetchJson('/api/private/admin/unimpersonate', { method: 'POST', cookie: ic, headers: intent });

/** A genuine first set-up body for `dk`: a pw wrap (stand-in), a real escrow wrap, the pin and the KCV. */
const firstBody = async (dk, extra = []) => ({
  driveSalt: salt16(), set: [pwWrap(), await wrapEscrow(dk, o.e.publicJwk), ...extra],
  escrowPin: await sealEscrowPin(dk, { escrow: o.kid, sign: o.skid }), kcv: await keyCheckValue(dk),
});

/** A user with the Drive on and a genuine first set-up. */
async function userWithDrive(name, extra = []) {
  const u = await makeUser(name);
  await enableDrive(u.id);
  const dk = createDriveKey();
  const r = await keys(u.cookie, await firstBody(dk, extra));
  expect(r.status, await r.clone().text()).toBe(200);
  return { ...u, username: name, dk };
}

/** A synthetic recovery code of the account (codes need a passkey first: put in the Directory directly). */
async function recoveryCodeFor(uid, code) {
  const ref = await recoveryRef(code);
  await runInDurableObject(dirStub(), (inst, state) => state.storage.sql.exec('INSERT INTO recovery_codes (hash, user_id, created) VALUES (?, ?, 1)', ref, uid));
  return ref;
}

beforeAll(async () => {
  oc = await owner();
  o.id = (await (await fetchJson('/api/private/me', { cookie: oc })).json()).user.id;
  o.dk = createDriveKey();
  o.e = await createEscrowKeyPair();
  o.s = await createSigningKeyPair();
  o.kid = await escrowKeyId(o.e.publicJwk);
  o.skid = null;
  const ownerFirst = {
    driveSalt: salt16(), set: [pwWrap()], kcv: await keyCheckValue(o.dk),
    escrowPub: o.e.publicJwk, escrowPriv: await sealEscrowPriv(o.dk, o.e.privateKey),
    escrowSignPub: o.s.publicJwk, escrowSignPriv: await sealSigningKey(o.dk, o.s.privateKey), escrowSig: await endorseEscrowKey(o.s.privateKey, o.e.publicJwk),
  };
  o.noKcv = await keys(oc, { ...ownerFirst, kcv: undefined }); // R5-L3: the owner's own first set-up needs it too
  o.noKcvState = await drive(oc);
  const r = await keys(oc, ownerFirst);
  expect(r.status, await r.clone().text()).toBe(200);
});

describe('R5-L1: an existing wrap is replaced only with the step-up and the key check value', () => {
  it('a recovery wrap and the escrow wrap: junk, or a wrap of another DK, is refused with the session alone', async () => {
    const u = await makeUser('r5-over');
    await enableDrive(u.id);
    const ref = await recoveryCodeFor(u.id, 'ABCD-EFGH-JKMN-PQRS');
    const dk = createDriveKey();
    const recWrap = { kind: 'recovery', ref, data: W() };
    expect((await keys(u.cookie, await firstBody(dk, [recWrap]))).status).toBe(200);
    const kcv = await keyCheckValue(dk);
    const before = await wrapsOf(u.id);
    // Removing the recovery wrap needs the step-up (unchanged).
    const rm = await keys(u.cookie, { remove: [{ kind: 'recovery', ref }] });
    expect(await errorOf(rm)).toBe('reauth_required');
    // Overwriting it: no KCV → refused; with the KCV but no step-up → refused.
    const junk = `1.${b64urlFromBytes(randomBytes(12))}.${b64urlFromBytes(randomBytes(48))}`;
    const ov = await keys(u.cookie, { set: [{ kind: 'recovery', ref, data: junk }] });
    expect(ov.status).toBe(400);
    expect(await errorOf(await keys(u.cookie, { set: [{ kind: 'recovery', ref, data: junk }], kcv }))).toBe('reauth_required');
    // The escrow wrap for the current kid, with junk or a wrap of ANOTHER Drive key to the owner's genuine key.
    const escJunk = `1.${b64urlFromBytes(randomBytes(65))}.${o.kid}.${b64urlFromBytes(randomBytes(12))}.${b64urlFromBytes(randomBytes(48))}`;
    const oe = await keys(u.cookie, { set: [{ kind: 'escrow', ref: 'escrow', data: escJunk }] });
    expect(oe.status).toBe(400);
    expect(await errorOf(await keys(u.cookie, { set: [{ kind: 'escrow', ref: 'escrow', data: escJunk }], kcv }))).toBe('reauth_required');
    const other = createDriveKey();
    const oe2 = await keys(u.cookie, { set: [await wrapEscrow(other, o.e.publicJwk)] });
    expect(oe2.status).toBe(400);
    // …and a KCV of another DK is refused even with the step-up.
    expect(await errorOf(await keys(u.cookie, { set: [await wrapEscrow(other, o.e.publicJwk)], kcv: await keyCheckValue(other), current: proofFor(USER_PW) }))).toBe('kcv_mismatch');
    // Nothing changed: the owner's escrow still opens this Drive's DK.
    expect(await wrapsOf(u.id)).toEqual(before);
    const ownerPriv = (await openEscrowKeyPair(o.dk, await meta(o.id, 'escrowPriv'))).privateKey;
    const opened = await unlockWithEscrow(ownerPriv, (await wrapsOf(u.id)).find((x) => x.kind === 'escrow'));
    expect(same(opened, dk)).toBe(true);
    // With the step-up and the Drive's KCV the user may replace a wrap of their own.
    const fresh = { kind: 'recovery', ref, data: W() };
    expect((await keys(u.cookie, { set: [fresh], kcv, current: proofFor(USER_PW) })).status).toBe(200);
    expect((await wrapsOf(u.id)).find((x) => x.kind === 'recovery').data).toBe(fresh.data);
    // The same data again is no change and needs nothing more than the KCV.
    expect((await keys(u.cookie, { set: [fresh], kcv })).status).toBe(200);
  });

  it('a brand-new wrap of the same DK also needs the KCV; an escrow wrap only for the current kid', async () => {
    const u = await userWithDrive('r5-new-wrap');
    const ref = await recoveryCodeFor(u.id, 'WXYZ-WXYZ-WXYZ-WXYZ');
    const add = { set: [{ kind: 'recovery', ref, data: W() }] };
    expect(await errorOf(await keys(u.cookie, add))).toBe('kcv_required');
    expect(await errorOf(await keys(u.cookie, { ...add, kcv: await keyCheckValue(createDriveKey()) }))).toBe('kcv_mismatch');
    expect((await keys(u.cookie, { ...add, kcv: await keyCheckValue(u.dk) })).status).toBe(200); // added: no step-up
    // A pin change alone needs the KCV too.
    expect(await errorOf(await keys(u.cookie, { escrowPin: enc(40) }))).toBe('kcv_required');
    // An escrow wrap for any other kid than the current one is refused.
    const e2 = await createEscrowKeyPair();
    expect((await keys(u.cookie, { set: [await wrapEscrow(u.dk, e2.publicJwk)], kcv: await keyCheckValue(u.dk), current: proofFor(USER_PW) })).status).toBe(400);
  });

  it('while impersonating, the escrow wrap is never replaced', async () => {
    const u = await userWithDrive('r5-imp-esc');
    const ic = await impersonate(u.id);
    const r = await keys(ic, { set: [await wrapEscrow(u.dk, o.e.publicJwk)], kcv: await keyCheckValue(u.dk) });
    expect(r.status).toBe(403);
    expect(await errorOf(r)).toBe('impersonating');
    await unimpersonate(ic);
  });
});

describe('R5-L2: first set-ups are atomic', () => {
  it('two first set-ups of the same user at once: one wins, the other gets 409; wraps and KCV of one DK', async () => {
    for (let i = 0; i < 8; i++) {
      const u = await makeUser(`r5-race-${i}`);
      await enableDrive(u.id);
      const d1 = createDriveKey();
      const d2 = createDriveKey();
      // As the browser sends it (`first: true`), and once in four without the flag.
      const flag = i % 4 ? { first: true } : {};
      const [b1, b2] = [{ ...flag, ...(await firstBody(d1)) }, { ...flag, ...(await firstBody(d2)) }];
      const [r1, r2] = await Promise.all([keys(u.cookie, b1), keys(u.cookie, b2)]);
      const lost = r1.status === 200 ? r2 : r1;
      expect([r1.status, r2.status]).toContain(200);
      if (flag.first) {
        expect(lost.status).toBe(409);
        expect(await errorOf(lost)).toBe('drive_exists');
      } else {
        // Without the flag, a loser that sees the winner's wraps is a replacement: the step-up.
        expect([[409, 'drive_exists'], [400, 'reauth_required']]).toContainEqual([lost.status, await errorOf(lost)]);
      }
      const won = r1.status === 200 ? { b: b1, dk: d1 } : { b: b2, dk: d2 };
      const w = await wrapsOf(u.id);
      expect(w.find((x) => x.kind === 'pw').data).toBe(won.b.set[0].data);
      expect(w.find((x) => x.kind === 'escrow').data).toBe(won.b.set[1].data);
      expect(await meta(u.id, 'kcv')).toBe(won.b.kcv);
      expect(await meta(u.id, 'escrowPin')).toBe(JSON.stringify(won.b.escrowPin));
      // The winner's DK can get a new pw wrap.
      const again = await keys(u.cookie, { driveSalt: salt16(), set: [pwWrap()], kcv: await keyCheckValue(won.dk), current: proofFor(USER_PW) });
      expect(again.status).toBe(200);
    }
  });

  it('the owner sets up a new user’s Drive while the user’s own first sign-in does: one wins, never a split', async () => {
    for (let i = 0; i < 8; i++) {
      const v = await makeUser(`r5-race-o-${i}`);
      await enableDrive(v.id);
      const dv = createDriveKey();
      const dOwner = createDriveKey();
      const bv = { first: true, ...(await firstBody(dv)) };
      const bo = { first: true, ...(await firstBody(dOwner)) };
      // Both orders: the owner's request first, then the user's first.
      const calls = [() => keys(v.cookie, bv), () => adminKeys(v.id, bo)];
      const [rv, ro] = i % 2 ? await Promise.all(calls.map((f) => f())) : (await Promise.all([calls[1](), calls[0]()])).reverse();
      expect([rv.status, ro.status].sort()).toEqual([200, 409]);
      const won = rv.status === 200 ? bv : bo;
      const w = await wrapsOf(v.id);
      expect(w.find((x) => x.kind === 'pw').data).toBe(won.set[0].data);
      expect(await meta(v.id, 'kcv')).toBe(won.kcv);
      expect(await errorOf(rv.status === 409 ? rv : ro)).toBe('drive_exists');
    }
    // And one after the other: the owner's first set-up over the user's Drive is refused.
    const u = await userWithDrive('r5-race-after');
    const late = await adminKeys(u.id, { first: true, ...(await firstBody(createDriveKey())) });
    expect(late.status).toBe(409);
    expect(await errorOf(late)).toBe('drive_exists');
  });

  it('the Drive object refuses a first set-up of a Drive with content, a KCV or sealed keys (no wrap)', async () => {
    const u = await makeUser('r5-do-keyless');
    await enableDrive(u.id);
    await driveOf(u.id).summary(u.id); // binds the object to the user
    await runInDurableObject(driveOf(u.id), (inst, state) => state.storage.sql.exec("INSERT INTO meta (k, v) VALUES ('kcv', ?)", b64urlFromBytes(randomBytes(32))));
    const r = await driveOf(u.id).setKeys(u.id, { set: [pwWrap()], kcv: b64urlFromBytes(randomBytes(32)), onlyIfEmpty: true });
    expect(r).toMatchObject({ ok: false, status: 409, error: 'drive_keyless' });
    const viaOwner = await adminKeys(u.id, { first: true, ...(await firstBody(createDriveKey())) });
    expect(await errorOf(viaOwner)).toBe('drive_keyless');
    for (const flag of [{}, { first: true }]) {
      const viaUser = await keys(u.cookie, { ...flag, ...(await firstBody(createDriveKey())) });
      expect(viaUser.status).toBe(409);
      expect(await errorOf(viaUser)).toBe('drive_keyless');
    }
    // A "first set-up" of a Drive that has wraps is refused as such.
    const has = await userWithDrive('r5-first-flag');
    const again = await keys(has.cookie, { first: true, ...(await firstBody(createDriveKey())) });
    expect(again.status).toBe(409);
    expect(await errorOf(again)).toBe('drive_exists');
    expect(await wrapsOf(u.id)).toEqual([]);
  });
});

describe('R5-L3: the key check value, with every first set-up and never taken later', () => {
  it('a first set-up without it is refused; a later change never sets one; a Drive without one takes no pw wrap', async () => {
    const u = await makeUser('r5-kcv');
    await enableDrive(u.id);
    const dk = createDriveKey();
    const noKcv = { ...(await firstBody(dk)), kcv: undefined };
    const r0 = await keys(u.cookie, noKcv);
    expect(r0.status).toBe(400);
    expect(await errorOf(r0)).toBe('kcv_required');
    expect(await wrapsOf(u.id)).toEqual([]);
    // A Drive that has wraps but no KCV (none can be made through the API any more: put in directly).
    await driveOf(u.id).setKeys(u.id, { driveSalt: salt16(), set: [pwWrap(), await wrapEscrow(dk, o.e.publicJwk)], escrowPin: JSON.stringify(enc(40)) });
    expect(await meta(u.id, 'kcv')).toBeNull();
    // A change with an arbitrary KCV is refused, and stores nothing.
    const bogus = b64urlFromBytes(randomBytes(32));
    const pin = await keys(u.cookie, { escrowPin: enc(40), kcv: bogus });
    expect(pin.status).toBe(409);
    expect(await errorOf(pin)).toBe('kcv_missing');
    expect(await meta(u.id, 'kcv')).toBeNull();
    // No pw wrap, not the user's own, not the owner's after a reset.
    const own = await keys(u.cookie, { driveSalt: salt16(), set: [pwWrap()], kcv: await keyCheckValue(dk), current: proofFor(USER_PW) });
    expect(await errorOf(own)).toBe('kcv_missing');
    const admin = await adminKeys(u.id, { driveSalt: salt16(), set: [pwWrap()], kcv: await keyCheckValue(dk) });
    expect(admin.status).toBe(409);
    expect(await errorOf(admin)).toBe('kcv_missing');
  });

  it('the owner’s own first set-up needs it too (refused, nothing stored)', async () => {
    expect(o.noKcv.status).toBe(400);
    expect(await errorOf(o.noKcv)).toBe('kcv_required');
    expect(o.noKcvState.wraps).toEqual([]);
    expect(o.noKcvState.escrowPub).toBeNull();
  });

  it('the owner-created Drive needs it (as before)', async () => {
    const v = await makeUser('r5-kcv-owner-made');
    await enableDrive(v.id);
    const r = await adminKeys(v.id, { first: true, ...(await firstBody(createDriveKey())), kcv: undefined });
    expect(r.status).toBe(400);
    expect(await errorOf(r)).toBe('kcv_required');
  });

  it('the admin re-key after a reset, fed a substituted escrow wrap: the substitution is refused, and so is a pw wrap of another DK', async () => {
    const u = await userWithDrive('r5-kcv-chain');
    const other = createDriveKey();
    expect((await keys(u.cookie, { set: [await wrapEscrow(other, o.e.publicJwk)] })).status).toBe(400); // R5-L1
    const esc = await (await fetchJson(`/api/private/admin/drive/escrow/${u.id}`, { method: 'POST', cookie: oc, headers: intent, body: { reason: 'password reset' } })).json();
    const opened = await unlockWithEscrow(o.e.privateKey, esc.wrap);
    expect(same(opened, u.dk)).toBe(true);
    const bad = await adminKeys(u.id, { driveSalt: salt16(), set: [pwWrap()], kcv: await keyCheckValue(other) });
    expect(bad.status).toBe(409);
    expect(await errorOf(bad)).toBe('kcv_mismatch');
    expect((await adminKeys(u.id, { driveSalt: salt16(), set: [pwWrap()], kcv: await keyCheckValue(opened) })).status).toBe(200);
  });
});

describe('R5-I3: the admin escrow route returns only the escrow wrap', () => {
  it('the escrow wrap and a count, never the user’s own wraps', async () => {
    const u = await userWithDrive('r5-escrow-only');
    const r = await fetchJson(`/api/private/admin/drive/escrow/${u.id}`, { method: 'POST', cookie: oc, headers: intent, body: { reason: 'password reset' } });
    expect(r.status).toBe(200);
    const body = await r.json();
    expect(Object.keys(body).sort()).toEqual(['wrap', 'wraps']);
    expect(body.wraps).toBe(2);
    expect(body.wrap.kind).toBe('escrow');
    const pw = (await wrapsOf(u.id)).find((x) => x.kind === 'pw').data;
    expect(JSON.stringify(body)).not.toContain(pw);
  });
});

describe('R5-I6: the owner’s own Drive has no escrow wrap', () => {
  it('refused, and never counted as a kid in use', async () => {
    const before = await (await fetchJson('/api/private/drive', { cookie: oc })).json();
    const fake = `1.${b64urlFromBytes(randomBytes(65))}.${b64urlFromBytes(randomBytes(16))}.${b64urlFromBytes(randomBytes(12))}.${b64urlFromBytes(randomBytes(48))}`;
    for (const data of [fake, (await wrapEscrow(o.dk, o.e.publicJwk)).data]) {
      const r = await keys(oc, { set: [{ kind: 'escrow', ref: 'escrow', data }], kcv: await keyCheckValue(o.dk), current: proofFor('owner-password') });
      expect(r.status).toBe(400);
      expect(await errorOf(r)).toBe('escrow_own');
    }
    expect((await wrapsOf(o.id)).some((w) => w.kind === 'escrow')).toBe(false);
    const after = await (await fetchJson('/api/private/drive', { cookie: oc })).json();
    expect(after.escrowKids).toEqual(before.escrowKids);
    // Even a kid recorded for the owner (none can be now) is not "in use".
    await runInDurableObject(dirStub(), (inst, state) => state.storage.sql.exec("INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v", `drive.escrowKid:${o.id}`, 'Q'.repeat(22)));
    expect((await (await fetchJson('/api/private/drive', { cookie: oc })).json()).escrowKids).not.toContain('Q'.repeat(22));
  });
});

describe('R5-I2: the kit check is rate limited per owner session', () => {
  it(`at most ${KIT_PROBE_MAX} calls per window; another session has its own budget`, async () => {
    await userWithDrive('r5-probe');
    const statuses = [];
    for (let i = 0; i < KIT_PROBE_MAX + 5; i++) statuses.push((await fetchJson('/api/private/drive/kit/probe', { method: 'POST', cookie: oc, headers: intent, body: {} })).status);
    expect(statuses.slice(0, KIT_PROBE_MAX).every((s) => s === 200)).toBe(true);
    expect(statuses.slice(KIT_PROBE_MAX).every((s) => s === 429)).toBe(true);
    const last = await fetchJson('/api/private/drive/kit/probe', { method: 'POST', cookie: oc, headers: intent, body: {} });
    expect(await errorOf(last)).toBe('rate_limited');
    // A refused call writes no admin-audit row.
    const rows = async () => (await (await fetchJson('/api/private/admin/audit?limit=500', { cookie: oc })).json()).rows.filter((r) => r.action === 'drive.escrow_used' && /kit check/.test(r.detail)).length;
    const n = await rows();
    await fetchJson('/api/private/drive/kit/probe', { method: 'POST', cookie: oc, headers: intent, body: {} });
    expect(await rows()).toBe(n);
    const other = await login('owner', 'owner-password');
    expect((await fetchJson('/api/private/drive/kit/probe', { method: 'POST', cookie: other, headers: intent, body: {} })).status).toBe(200);
  });
});

describe('R5 access control on the new routes (unchanged)', () => {
  it('user 403, impersonating 403, cross-site 403, missing intent refused, step-up 400', async () => {
    const u = await userWithDrive('r5-ac');
    const routes = [
      ['POST', '/api/private/drive/kit', { event: 'exported' }],
      ['POST', '/api/private/drive/kit', { event: 'used' }],
      ['POST', '/api/private/drive/kit', { event: 'verified', verdict: 'complete' }],
      ['POST', '/api/private/drive/kit/probe', {}],
      ['PUT', '/api/private/drive/kit/keys', { escrowPriv: { pub: o.e.publicJwk, data: W() } }],
      ['POST', '/api/private/drive/start-over', { confirm: 'owner' }],
      ['GET', '/api/private/drive/archive/1', undefined],
      ['DELETE', '/api/private/drive/archive/1', { confirm: 'owner' }],
      ['PUT', '/api/private/drive/archive/1/nodes', { nodes: [] }],
      ['POST', '/api/private/drive/archive/1/finish', {}],
    ];
    const ic = await impersonate(u.id);
    for (const [method, path, body] of routes) {
      expect((await fetchJson(path, { method, cookie: u.cookie, headers: intent, body })).status, `${method} ${path}`).toBe(403);
      expect((await fetchJson(path, { method, cookie: ic, headers: intent, body })).status, `${method} ${path}`).toBe(403);
    }
    for (const [method, path, body] of [['PUT', `/api/private/admin/drive/keys/${u.id}`, { first: true }], ['POST', `/api/private/admin/drive/escrow/${u.id}`, { reason: 'test reason' }]]) {
      expect((await fetchJson(path, { method, cookie: u.cookie, headers: intent, body })).status).toBe(403);
      expect((await fetchJson(path, { method, cookie: ic, headers: intent, body })).status).toBe(403);
    }
    await unimpersonate(ic);
    const e3 = await createEscrowKeyPair();
    for (const [method, path, body] of [
      ['POST', '/api/private/drive/kit', { event: 'exported' }],
      ['POST', '/api/private/drive/kit', { event: 'used' }],
      ['PUT', '/api/private/drive/keys', { escrowPub: e3.publicJwk, escrowPriv: W(), escrowSig: await endorseEscrowKey(o.s.privateKey, e3.publicJwk) }],
    ]) {
      const r = await fetchJson(path, { method, cookie: oc, headers: intent, body });
      expect(r.status).toBe(400);
      expect(await errorOf(r)).toBe('reauth_required');
    }
    for (const [method, path, body] of [['POST', '/api/private/drive/kit', { event: 'verified', verdict: 'complete' }], ['PUT', '/api/private/drive/kit/keys', {}], ['POST', '/api/private/drive/start-over', {}], ['DELETE', '/api/private/drive/archive/1', {}], ['PUT', `/api/private/admin/drive/keys/${u.id}`, {}]]) {
      expect([400, 403]).toContain((await fetchJson(path, { method, cookie: oc, body })).status);
      expect((await fetchJson(path, { method, cookie: oc, headers: { ...intent, 'sec-fetch-site': 'cross-site' }, body })).status).toBe(403);
    }
    expect((await fetchJson('/api/private/drive/kit/probe', { method: 'POST', cookie: oc, headers: { ...intent, 'sec-fetch-site': 'same-site' }, body: {} })).status).toBe(403);
  });

  it('reset metadata cannot be written by a non-owner; escrowReset needs a real reset; start-over is owner-only', async () => {
    const u = await userWithDrive('r5-forge');
    const e2 = await createEscrowKeyPair();
    const s2 = await createSigningKeyPair();
    const a = await keys(u.cookie, { set: [await wrapEscrow(u.dk, o.e.publicJwk)], escrowReset: 1, kcv: await keyCheckValue(u.dk) });
    const b = await keys(u.cookie, { escrowPub: e2.publicJwk, escrowSignPub: s2.publicJwk, escrowSig: await endorseEscrowKey(s2.privateKey, e2.publicJwk) });
    const c = await fetchJson('/api/private/drive/start-over', { method: 'POST', cookie: u.cookie, headers: intent, body: { confirm: u.username } });
    expect(a.status).toBe(400);
    expect(b.status).toBe(403);
    expect(c.status).toBe(403);
    expect((await drive(u.cookie)).ownerReset).toBeNull();
  });

  it('the Directory records an owner reset only over the epoch the start over read (compare-and-set)', async () => {
    const e = await createEscrowKeyPair();
    const s = await createSigningKeyPair();
    const args = { kid: await escrowKeyId(e.publicJwk), signPub: JSON.stringify(s.publicJwk), escrowPub: JSON.stringify(e.publicJwk), sig: await endorseEscrowKey(s.privateKey, e.publicJwk) };
    const pubBefore = (await drive(oc)).escrowPub;
    const r = await dirStub().recordOwnerReset(o.id, { ...args, expectEpoch: 7 });
    expect(r).toMatchObject({ ok: false, status: 409, error: 'reset_conflict' });
    expect((await drive(oc)).escrowPub).toEqual(pubBefore); // nothing written
    expect((await drive(oc)).ownerReset).toBeNull();
  });

  it('a first escrow key needs no step-up only while none exists (compare-and-set in the Drive and the Directory)', async () => {
    const e = await createEscrowKeyPair();
    const r = await dirStub().setEscrowPub(o.id, JSON.stringify(e.publicJwk), { onlyIfNone: true });
    expect(r).toMatchObject({ ok: false, status: 409, error: 'escrow_exists' });
    const d = await driveOf(o.id).setKeys(o.id, { escrowPriv: W(), noEscrowYet: true });
    expect(d).toMatchObject({ ok: false, status: 409, error: 'escrow_exists' });
    expect((await drive(oc)).escrowPub).toEqual(o.e.publicJwk);
  });
});

