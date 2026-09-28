// drivev1.test.js — the Drive keys of the release before the key model v2,
// opened once more for the upgrade (public/js/drivev1.js, docs/DRIVE.md
// §3.3), on Node's Web Crypto and the real Argon2id: every wrap the old
// release made (made here with that release's own code, the test fixture
// test/fixtures/drivekeys-main.js) opens with what it was made for and with
// nothing else; old sealed fields and link keys open for their node and field
// only; the old key check value matches; the tab's copy of the old DK.
import { describe, it, expect, beforeEach } from 'vitest';
import { createHash } from 'node:crypto';
import * as main from '../test/fixtures/drivekeys-main.js';
import {
  deriveSubkeysV1, openFieldV1, keyCheckValueV1, unlockWithPassword, unlockWithRecovery, unlockWithPrf, DRIVE_PRF_SALT,
  escrowKeyId, escrowWrapKeyId, openEscrowKey, unlockWithEscrow, openReversePrivV1, saveLegacyKey, loadLegacyKey, clearLegacyKey, openKitV1,
} from '../public/js/drivev1.js';
import * as kitV1 from '../test/fixtures/drivekit-main.js';
import { clearSessionKey } from '../public/js/drivekeys.js';
import { DecryptError } from '../public/js/crypto.js';
import { fromUtf8, randomBytes, b64urlFromBytes } from '../public/js/bytes.js';

const eq = (a, b) => expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
const CODE = 'ABCD-EFGH-JKMN-PQRS';

describe('the old sealed fields', () => {
  it('open with the old DK for their field and node only; the key check value is the release’s', async () => {
    const dk = main.createDriveKey();
    const k = await main.deriveSubkeys(dk);
    const name = await main.sealField(k.names, 'name', 'node1', 'report.pdf');
    const fk = randomBytes(32);
    const sealedFk = await main.sealField(k.files, 'fk', 'node1', fk);
    const v1 = await deriveSubkeysV1(dk);
    expect(fromUtf8(await openFieldV1(v1.names, 'name', 'node1', name))).toBe('report.pdf');
    expect(fromUtf8(await openFieldV1(v1.names, 'name', 'node1', JSON.stringify(name)))).toBe('report.pdf');
    eq(await openFieldV1(v1.files, 'fk', 'node1', sealedFk), fk);
    await expect(openFieldV1(v1.names, 'name', 'node2', name)).rejects.toThrow(DecryptError);
    await expect(openFieldV1(v1.names, 'meta', 'node1', name)).rejects.toThrow(DecryptError);
    await expect(openFieldV1(v1.files, 'name', 'node1', name)).rejects.toThrow(DecryptError);
    await expect(openFieldV1((await deriveSubkeysV1(main.createDriveKey())).names, 'name', 'node1', name)).rejects.toThrow(DecryptError);
    await expect(openFieldV1(v1.names, 'name', 'node1', '{not json')).rejects.toThrow(DecryptError);
    expect(await keyCheckValueV1(dk)).toBe(await main.keyCheckValue(dk));
    expect(await keyCheckValueV1(main.createDriveKey())).not.toBe(await main.keyCheckValue(dk));
    await expect(deriveSubkeysV1(new Uint8Array(16))).rejects.toThrow(TypeError);
  });

  it('an old reverse-link key opens for its link only', async () => {
    const dk = main.createDriveKey();
    const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const sealed = await main.sealReversePriv(dk, 'rAAAAAAAAAAAAAAAAAAAAAA', kp.privateKey);
    eq(await openReversePrivV1(dk, 'rAAAAAAAAAAAAAAAAAAAAAA', sealed), new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey)));
    await expect(openReversePrivV1(dk, 'rBBBBBBBBBBBBBBBBBBBBBB', sealed)).rejects.toThrow(DecryptError);
  });
});

describe('the old wraps', () => {
  it('the password wrap (Argon2id, 64 MiB, t=3): the right password and salt only', async () => {
    const dk = main.createDriveKey();
    const { driveSalt, wrap } = await main.wrapPassword(dk, 'correct horse battery');
    eq(await unlockWithPassword('correct horse battery', driveSalt, [wrap]), dk);
    const { driveSalt: s2, wrap: w2 } = await main.wrapPassword(dk, 'café');
    eq(await unlockWithPassword('café', s2, [w2]), dk); // NFC: typed decomposed
    expect(await unlockWithPassword('wrong password', driveSalt, [wrap])).toBeNull();
    expect(await unlockWithPassword('correct horse battery', s2, [wrap])).toBeNull();
    expect(await unlockWithPassword('correct horse battery', driveSalt, [{ ...wrap, ref: 'other' }])).toBeNull();
    expect(await unlockWithPassword('correct horse battery', driveSalt, [{ ...wrap, kind: 'recovery' }])).toBeNull();
    expect(await unlockWithPassword('correct horse battery', 'not-b64!', [wrap])).toBeNull();
    expect(await unlockWithPassword('', driveSalt, [wrap])).toBeNull();
    expect(await unlockWithPassword('x', driveSalt, [])).toBeNull();
  }, 60000);

  it('recovery-code wraps: the code as typed opens its own wrap; a wrong code or a moved wrap does not', async () => {
    const dk = main.createDriveKey();
    const w = await main.wrapRecovery(dk, CODE);
    expect(w.ref).toBe(createHash('sha256').update('secbin-recovery/v1:ABCDEFGHJKMNPQRS').digest('hex'));
    eq(await unlockWithRecovery(' abcd efgh-jkmn pqrs ', [w]), dk);
    expect(await unlockWithRecovery('ABCD-EFGH-JKMN-PQRT', [w])).toBeNull();
    expect(await unlockWithRecovery('garbage', [w])).toBeNull();
    expect(await unlockWithRecovery(CODE, [{ ...w, ref: 'moved' }])).toBeNull();
    const other = 'ZZZZ-YYYY-XXXX-WWWW';
    const wraps = [await main.wrapRecovery(dk, other), w];
    eq(await unlockWithRecovery(other, wraps), dk);
    eq(await unlockWithRecovery(CODE, wraps), dk);
  });

  it('passkey (PRF) wraps: the salt is SHA-256("secbin-drive/v1 prf"); another output or credential does not open', async () => {
    eq(DRIVE_PRF_SALT, createHash('sha256').update('secbin-drive/v1 prf').digest());
    eq(DRIVE_PRF_SALT, main.DRIVE_PRF_SALT);
    const dk = main.createDriveKey();
    const prf = randomBytes(32);
    const w = await main.wrapPrf(dk, prf, 'cred-1');
    eq(await unlockWithPrf(prf.buffer.slice(0), 'cred-1', [w]), dk);
    expect(await unlockWithPrf(randomBytes(32), 'cred-1', [w])).toBeNull();
    expect(await unlockWithPrf(prf, 'cred-2', [w])).toBeNull();
    expect(await unlockWithPrf(prf, 'cred-2', [{ ...w, ref: 'cred-2' }])).toBeNull();
    expect(await unlockWithPrf(new Uint8Array(8), 'cred-1', [w])).toBeNull();
  });

  it('the owner’s escrow: the sealed escrow key opens with the owner’s old DK; a user’s escrow wrap with that key only', async () => {
    const ownerDk = main.createDriveKey();
    const owner = await main.createEscrowKeyPair();
    const sealedPriv = await main.sealEscrowPriv(ownerDk, owner.privateKey);
    const key = await openEscrowKey(ownerDk, sealedPriv);
    expect(key.kid).toBe(await main.escrowKeyId(owner.publicJwk));
    expect(await escrowKeyId(owner.publicJwk)).toBe(key.kid);
    await expect(openEscrowKey(main.createDriveKey(), sealedPriv)).rejects.toThrow(DecryptError);
    await expect(openEscrowKey(ownerDk, 'nope')).rejects.toThrow(DecryptError);
    const userDk = main.createDriveKey();
    const w = await main.wrapEscrow(userDk, owner.publicJwk);
    expect(escrowWrapKeyId(w)).toBe(key.kid);
    eq(await unlockWithEscrow(key.privateKey, w), userDk);
    const stranger = await main.createEscrowKeyPair();
    expect(await unlockWithEscrow(stranger.privateKey, w)).toBeNull();
    const parts = w.data.split('.');
    expect(await unlockWithEscrow(key.privateKey, { ...w, data: [parts[0], parts[1], 'AAAAAAAAAAAAAAAAAAAAAA', parts[3], parts[4]].join('.') })).toBeNull();
    expect(await unlockWithEscrow(key.privateKey, { ...w, kind: 'pw' })).toBeNull();
    expect(await unlockWithEscrow(key.privateKey, { kind: 'escrow', ref: 'escrow', data: 'junk' })).toBeNull();
  });
});

describe('the tab’s copy of the old DK', () => {
  const store = new Map();
  beforeEach(() => {
    store.clear();
    globalThis.sessionStorage = {
      getItem: (k) => (store.has(k) ? store.get(k) : null),
      setItem: (k, v) => store.set(k, String(v)),
      removeItem: (k) => store.delete(k),
    };
  });

  it('for its account only; cleared with every other Drive key of the tab', () => {
    const dk = main.createDriveKey();
    expect(loadLegacyKey('u1')).toBeNull();
    expect(saveLegacyKey(dk, 'u1')).toBe(true);
    expect(store.get('secbin_dk')).toBe(b64urlFromBytes(dk));
    eq(loadLegacyKey('u1'), dk);
    expect(loadLegacyKey('u2')).toBeNull();
    expect(saveLegacyKey(new Uint8Array(5), 'u1')).toBe(false);
    clearLegacyKey();
    expect(loadLegacyKey('u1')).toBeNull();
    saveLegacyKey(dk, 'u1');
    clearSessionKey();
    expect(store.size).toBe(0);
  });
});

// Audit B M4: a recovery kit of the release before still opens the old DK for the upgrade (a Drive
// whose wraps no longer open: after an AUTHN recovery, a lost password). Made with that release's own
// code (test/fixtures/drivekit-main.js).
describe('the recovery kits of the release before (open only)', () => {
  const ORIGIN = 'https://bin.example';
  it('an owner kit (and a user kit) opens for its account, on its server, with its passphrase; the DK it holds comes back', async () => {
    const dk = main.createDriveKey();
    const owner = await kitV1.sealDriveKit('owner', { v: 1, ownerId: 'ownerAAAAAAAAAAA', made: 1, dk: b64urlFromBytes(dk), escrow: null, sign: null, old: [] }, { accountId: 'ownerAAAAAAAAAAA', origin: ORIGIN, passphrase: 'kit pass' });
    eq(await openKitV1(owner, { accountId: 'ownerAAAAAAAAAAA', origin: ORIGIN, passphrase: 'kit pass' }), dk);
    await expect(openKitV1(owner, { accountId: 'ownerAAAAAAAAAAA', origin: ORIGIN, passphrase: 'wrong' })).rejects.toMatchObject({ name: 'DriveKitV1Error', check: 'auth' });
    await expect(openKitV1(owner, { accountId: 'ownerAAAAAAAAAAA', origin: 'https://elsewhere.example', passphrase: 'kit pass' })).rejects.toMatchObject({ check: 'auth' });
    await expect(openKitV1(owner, { accountId: 'someoneElseAAAAA', origin: ORIGIN, passphrase: 'kit pass' })).rejects.toMatchObject({ check: 'owner' });
    const user = await kitV1.sealDriveKit('user', { v: 1, userId: 'userAAAAAAAAAAAA', dk: b64urlFromBytes(dk) }, { accountId: 'userAAAAAAAAAAAA', origin: ORIGIN, passphrase: '' });
    eq(await openKitV1(user, { accountId: 'userAAAAAAAAAAAA', origin: ORIGIN, passphrase: '' }), dk);
    // Not a kit of that release (a v2 kit, or anything else): refused by its form.
    await expect(openKitV1(JSON.stringify({ format: 'secbin-user-kit/2' }), { accountId: 'userAAAAAAAAAAAA', origin: ORIGIN })).rejects.toMatchObject({ check: 'format' });
    // A changed file fails authentication.
    const env = JSON.parse(owner);
    env.ct = `${env.ct.slice(0, -2)}${env.ct.endsWith('AA') ? 'BB' : 'AA'}`;
    await expect(openKitV1(JSON.stringify(env), { accountId: 'ownerAAAAAAAAAAA', origin: ORIGIN, passphrase: 'kit pass' })).rejects.toMatchObject({ check: 'auth' });
  }, 60000);
});
