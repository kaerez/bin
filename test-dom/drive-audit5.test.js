// drive-audit5.test.js — regressions for the round-5 audit of the Drive
// (client side): the real client (public/js/driveclient.js) against the
// in-memory server (drive-fake-server.js), with a wrapper around its fetch
// that plays "anyone who can change server responses". Each block was a proof
// of concept that passed against be7654a:
//   - R5-M2: a missing pin, a missing escrow wrap or a wrap for another key
//     than the pinned one is never a first use: the tamper notice, no re-wrap;
//   - the automatic re-wrap after an owner reset (the accepted exception) is
//     automatic every time: two genuine resets in a row both move the Drive by
//     itself (no time limit; the 30-day limit of R5-M1 was removed by the
//     maintainer), each epoch once;
//   - the accepted exception otherwise as specified (each variant: notice);
//   - R5-L2 (client): a first set-up that loses the race to another tab (or
//     to the owner) opens the Drive that won instead of failing.
// Synthetic data only.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { unlockDrive } from '../public/js/driveclient.js';
import { ApiError } from '../public/js/api.js';
import {
  createEscrowKeyPair, createSigningKeyPair, endorseEscrowKey, escrowKeyId, signingKeyId, openEscrowPin,
  escrowWrapKeyId, clearSessionKey, releaseSessionKeys, createDriveKey, wrapPassword, wrapEscrow, sealEscrowPin, keyCheckValue,
} from '../public/js/drivekeys.js';
import { fakeServer } from './drive-fake-server.js';

const T = 180000;
const PW = 'user password 1';
let S;
const use = (srv) => { S = srv; globalThis.fetch = S.fetch; return srv; };
beforeEach(() => { clearSessionKey(); releaseSessionKeys(); clearSessionKey(); });
afterEach(() => { vi.restoreAllMocks(); });

/** The owner's genuine keys: an escrow pair signed by a signing key. */
async function ownerKeys() {
  const s = await createSigningKeyPair();
  const e = await createEscrowKeyPair();
  return { s, e, sig: await endorseEscrowKey(s.privateKey, e.publicJwk) };
}

/** A user whose Drive is set up on the owner's genuine keys (pinned), epoch `epoch`. */
async function userOn(k, { epoch = 0 } = {}) {
  const SU = use(fakeServer());
  Object.assign(SU, { escrowPub: k.e.publicJwk, escrowSignPub: k.s.publicJwk, escrowSig: k.sig });
  if (epoch) SU.ownerReset = { epoch, kid: await escrowKeyId(k.e.publicJwk), signPub: k.s.publicJwk, at: 1 };
  const c = await unlockDrive({ password: PW });
  return { SU, dk: c.dk };
}

/** Wrap the server's fetch so that GET /api/private/drive answers are rewritten by `edit(data)`. */
function tamper(SU, edit) {
  const orig = SU.fetch;
  globalThis.fetch = vi.fn(async (url, init = {}) => {
    const r = await orig(url, init);
    const u = new URL(url, 'https://bin.example');
    if (u.pathname === '/api/private/drive' && (init.method || 'GET') === 'GET') {
      const d = await r.json();
      edit(d);
      return { ...r, json: async () => d };
    }
    return r;
  });
}

/** The PUT /api/private/drive/keys bodies the client sent (what a response-changing server receives). */
const sentKeys = (SU, from = 0) => SU.requests.slice(from).filter((q) => q.method === 'PUT' && q.path === '/api/private/drive/keys').map((q) => q.body);
const sentEscrowWraps = (SU, from = 0) => sentKeys(SU, from).flatMap((b) => (b.set || []).filter((w) => w.kind === 'escrow'));

describe('R5-M2: a stripped or mismatched pin is tampering, never a first use', () => {
  const cases = [
    ['no pin and no escrow wrap, an unsigned attacker key', (d, a) => { d.escrowPin = null; d.wraps = d.wraps.filter((w) => w.kind !== 'escrow'); Object.assign(d, { escrowPub: a.e.publicJwk, escrowSignPub: null, escrowSig: null, ownerReset: null }); }],
    ['no pin, the wrap’s kid rewritten to the attacker’s, attacker-signed keys', (d, a) => {
      d.escrowPin = null;
      d.wraps = d.wraps.map((w) => (w.kind === 'escrow' ? { ...w, data: w.data.split('.').map((x, i) => (i === 2 ? a.kid : x)).join('.') } : w));
      Object.assign(d, { escrowPub: a.e.publicJwk, escrowSignPub: a.s.publicJwk, escrowSig: a.sig, ownerReset: null });
    }],
    ['a pin, but no escrow wrap', (d, a) => { d.wraps = d.wraps.filter((w) => w.kind !== 'escrow'); Object.assign(d, { escrowPub: a.e.publicJwk, escrowSignPub: null, escrowSig: null }); }],
    ['a pin, and a wrap whose kid is not the pinned one', (d, a) => {
      d.wraps = d.wraps.map((w) => (w.kind === 'escrow' ? { ...w, data: w.data.split('.').map((x, i) => (i === 2 ? a.kid : x)).join('.') } : w));
      Object.assign(d, { escrowPub: a.e.publicJwk, escrowSignPub: a.s.publicJwk, escrowSig: a.sig });
    }],
    ['no pin, the owner’s genuine key unchanged', (d) => { d.escrowPin = null; }],
  ];
  for (const [label, edit] of cases) {
    it(label, async () => {
      const k = await ownerKeys();
      const { SU } = await userOn(k);
      expect(SU.escrowPin).not.toBeNull(); // every Drive has a pin from its set-up
      const a = { s: await createSigningKeyPair(), e: await createEscrowKeyPair() };
      a.kid = await escrowKeyId(a.e.publicJwk);
      a.sig = await endorseEscrowKey(a.s.privateKey, a.e.publicJwk);
      const pin0 = SU.escrowPin;
      tamper(SU, (d) => edit(d, a));
      const from = SU.requests.length;
      clearSessionKey();
      const c = await unlockDrive({ password: PW });
      expect(c.notice).toMatchObject({ kind: 'escrow_changed', tampered: true });
      expect(sentEscrowWraps(SU, from)).toHaveLength(0); // nothing re-wrapped
      expect(sentKeys(SU, from).some((b) => b.escrowPin !== undefined)).toBe(false); // nothing re-pinned
      expect(SU.escrowPin).toBe(pin0);
    }, T);
  }

  it('the genuine first set-up in this browser still wraps and pins (no wraps yet)', async () => {
    const k = await ownerKeys();
    const { SU, dk } = await userOn(k);
    const pin = await openEscrowPin(dk, SU.escrowPin);
    expect(pin).toEqual({ escrow: await escrowKeyId(k.e.publicJwk), sign: await signingKeyId(k.s.publicJwk) });
    expect(escrowWrapKeyId(SU.wraps.get('escrow|escrow'))).toBe(pin.escrow);
    clearSessionKey();
    expect((await unlockDrive({ password: PW })).notice).toBeNull();
  }, T);

  it('"Trust the new key" after a stripped pin: the pin is written with the KCV, the wrap for the same key is not replaced', async () => {
    const k = await ownerKeys();
    const { SU, dk } = await userOn(k);
    const wrap0 = SU.wraps.get('escrow|escrow');
    SU.escrowPin = null; // stripped on the server
    clearSessionKey();
    const c = await unlockDrive({ password: PW });
    expect(c.notice).toMatchObject({ kind: 'escrow_changed', tampered: true });
    const from = SU.requests.length;
    expect(await c.acceptEscrowKey()).toBe(true);
    const [body] = sentKeys(SU, from);
    expect(body.set).toEqual([]);
    expect(body.kcv).toBe(await keyCheckValue(dk));
    expect(SU.wraps.get('escrow|escrow')).toEqual(wrap0);
    expect(await openEscrowPin(dk, SU.escrowPin)).toMatchObject({ escrow: await escrowKeyId(k.e.publicJwk) });
    clearSessionKey();
    expect((await unlockDrive({ password: PW })).notice).toBeNull();
  }, T);
});

describe('the automatic reset re-wrap: every genuine reset, each epoch once', () => {
  /** A reset the server reports: epoch `epoch`, new keys signed by a new signing key. */
  async function reset(SU, epoch) {
    const s = await createSigningKeyPair();
    const e = await createEscrowKeyPair();
    const sig = await endorseEscrowKey(s.privateKey, e.publicJwk);
    Object.assign(SU, { escrowPub: e.publicJwk, escrowSignPub: s.publicJwk, escrowSig: sig });
    SU.ownerReset = { epoch, kid: await escrowKeyId(e.publicJwk), signPub: s.publicJwk, at: 3 };
    return { s, e };
  }
  const T0 = 1_800_000_000_000;
  const ROTATED = { kind: 'escrow_rotated', text: 'Your administrator rotated a security key; nothing for you to do.' };

  it('two consecutive genuine resets (a day apart) both move the Drive by itself, with the short notice; each epoch applies once', async () => {
    const k = await ownerKeys();
    const now = vi.spyOn(Date, 'now').mockReturnValue(T0);
    const { SU, dk } = await userOn(k);
    for (const [epoch, at] of [[1, T0], [2, T0 + 86400 * 1000]]) {
      now.mockReturnValue(at);
      const r = await reset(SU, epoch);
      const from = SU.requests.length;
      clearSessionKey();
      const c = await unlockDrive({ password: PW });
      expect(c.notice, `epoch ${epoch}`).toEqual(ROTATED);
      const sent = sentKeys(SU, from).filter((b) => b.escrowReset !== undefined);
      expect(sent.map((b) => b.escrowReset)).toEqual([epoch]);
      expect(sentEscrowWraps(SU, from)).toHaveLength(1);
      expect(escrowWrapKeyId(SU.wraps.get('escrow|escrow'))).toBe(await escrowKeyId(r.e.publicJwk));
      expect(await openEscrowPin(dk, SU.escrowPin)).toEqual({ escrow: await escrowKeyId(r.e.publicJwk), sign: await signingKeyId(r.s.publicJwk), epoch });
      // The same reset reported again: already pinned, nothing re-wrapped.
      const again = SU.requests.length;
      clearSessionKey();
      expect((await unlockDrive({ password: PW })).notice).toBeNull();
      expect(sentEscrowWraps(SU, again)).toHaveLength(0);
    }
    expect(SU.activity.filter((x) => x.action === 'drive.escrow_rewrapped')).toHaveLength(2);
  }, T);

  it('a signed rotation after an automatic move: moved by itself, the reset’s signing key and epoch stay pinned', async () => {
    const k = await ownerKeys();
    const { SU, dk } = await userOn(k);
    const r1 = await reset(SU, 1);
    clearSessionKey();
    await unlockDrive({ password: PW });
    // The (reset's) signing key signs a new escrow key: moved by itself, as always.
    const e2 = await createEscrowKeyPair();
    Object.assign(SU, { escrowPub: e2.publicJwk, escrowSig: await endorseEscrowKey(r1.s.privateKey, e2.publicJwk) });
    clearSessionKey();
    expect((await unlockDrive({ password: PW })).notice).toBeNull();
    expect(await openEscrowPin(dk, SU.escrowPin)).toEqual({ escrow: await escrowKeyId(e2.publicJwk), sign: await signingKeyId(r1.s.publicJwk), epoch: 1 });
  }, T);
});

describe('the accepted exception, as specified (each gets the notice, no re-wrap)', () => {
  const variants = [
    ['an epoch skip (pinned 1, reset 3)', 1, { epoch: 3 }],
    ['a replay of the same epoch (pinned 1, reset 1)', 1, { epoch: 1 }],
    ['an epoch the server moves back (pinned 2, reset 1)', 2, { epoch: 1 }],
    ['an unsigned key without a reset', 0, { epoch: 0 }],
    ['a reset whose signPub is not the server’s signing key', 0, { epoch: 1, resetSignOther: true }],
    ['a reset whose signing key did not sign the escrow key', 0, { epoch: 1, sigByOther: true }],
  ];
  for (const [label, pinnedEpoch, v] of variants) {
    it(label, async () => {
      const k = await ownerKeys();
      const { SU, dk } = await userOn(k, { epoch: pinnedEpoch });
      expect((await openEscrowPin(dk, SU.escrowPin)).epoch ?? 0).toBe(pinnedEpoch);
      const wrap0 = SU.wraps.get('escrow|escrow');
      const e2 = await createEscrowKeyPair();
      const s2 = await createSigningKeyPair();
      const other = await createSigningKeyPair();
      const sigKey = v.sigByOther ? other : s2;
      Object.assign(SU, { escrowPub: e2.publicJwk, escrowSignPub: s2.publicJwk, escrowSig: await endorseEscrowKey(sigKey.privateKey, e2.publicJwk) });
      SU.ownerReset = v.epoch ? { epoch: v.epoch, kid: await escrowKeyId(e2.publicJwk), signPub: (v.resetSignOther ? other : s2).publicJwk, at: 2 } : null;
      const from = SU.requests.length;
      clearSessionKey();
      const c = await unlockDrive({ password: PW });
      expect(c.notice).toMatchObject({ kind: 'escrow_changed' });
      expect(SU.wraps.get('escrow|escrow')).toEqual(wrap0);
      expect(sentEscrowWraps(SU, from)).toHaveLength(0);
    }, T);
  }
});

describe('R5-L2 (client): a first set-up that loses the race', () => {
  it('opens the Drive the other tab (or the owner) set up with the same password, instead of failing', async () => {
    const k = await ownerKeys();
    const SU = use(fakeServer());
    Object.assign(SU, { escrowPub: k.e.publicJwk, escrowSignPub: k.s.publicJwk, escrowSig: k.sig });
    const winner = createDriveKey();
    const orig = SU.fetch;
    let raced = false;
    globalThis.fetch = vi.fn(async (url, init = {}) => {
      const u = new URL(url, 'https://bin.example');
      if (!raced && u.pathname === '/api/private/drive/keys' && init.method === 'PUT') {
        raced = true;
        // The other tab's set-up lands first (same password, another DK)…
        const { driveSalt, wrap } = await wrapPassword(winner, PW);
        const esc = await wrapEscrow(winner, k.e.publicJwk);
        SU.driveSalt = driveSalt;
        SU.wraps.set('pw|pw', wrap);
        SU.wraps.set('escrow|escrow', esc);
        SU.escrowPin = await sealEscrowPin(winner, { escrow: await escrowKeyId(k.e.publicJwk), sign: await signingKeyId(k.s.publicJwk) });
        SU.kcv = await keyCheckValue(winner);
        // …and this one gets 409 drive_exists, as the Drive object answers.
        const e = new ApiError('This Drive already has keys: they are never replaced.', 409, 'drive_exists');
        return { ok: false, status: 409, type: 'basic', json: async () => ({ error: e.code, message: e.message }) };
      }
      return orig(url, init);
    });
    const c = await unlockDrive({ password: PW });
    expect(c.dk).toEqual(winner);
    expect(c.notice).toBeNull();
  }, T);
});
