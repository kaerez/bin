// drivekeys.test.js — the Drive's keys (docs/DRIVE.md §3) on Node's Web Crypto
// and the real Argon2id: sub-keys, sealed fields bound to their field and node
// (a value cannot be moved), every wrap kind round trip and failure (wrong
// password / code / PRF / escrow key, wrap moved to another ref), the owner's
// sealed escrow key, the tab's session copy, and manifest v3 validation.
import { describe, it, expect, beforeEach } from 'vitest';
import { createHash } from 'node:crypto';
import {
  createDriveKey, deriveSubkeys, sealField, openField, wrapPassword, unlockWithPassword, wrapRecovery, unlockWithRecovery,
  normalizeRecoveryCode, recoveryRef, DRIVE_PRF_SALT, wrapPrf, unlockWithPrf, createEscrowKeyPair, sealEscrowPriv,
  openEscrowPriv, wrapEscrow, unlockWithEscrow, escrowKeyId, escrowWrapKeyId, saveSessionKey, loadSessionKey, clearSessionKey,
} from '../public/js/drivekeys.js';
import { validateRefsManifest, buildRefsManifest, refChunks } from '../public/js/refsmanifest.js';
import { DecryptError } from '../public/js/crypto.js';
import { fromUtf8, b64urlFromBytes, randomBytes } from '../public/js/bytes.js';
import { CHUNK, ManifestError } from '../public/js/files.js';

const eq = (a, b) => expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
const CODE = 'ABCD-EFGH-JKMN-PQRS';

describe('Drive key and sub-keys', () => {
  it('DK is 32 random bytes; sub-keys are AES-GCM keys, not extractable', async () => {
    const a = createDriveKey();
    const b = createDriveKey();
    expect(a).toBeInstanceOf(Uint8Array);
    expect(a.length).toBe(32);
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
    const k = await deriveSubkeys(a);
    expect(k.names.algorithm.name).toBe('AES-GCM');
    expect(k.files.algorithm.name).toBe('AES-GCM');
    expect(k.names.extractable).toBe(false);
    await expect(deriveSubkeys(new Uint8Array(16))).rejects.toThrow(TypeError);
  });

  it('the same DK gives the same sub-keys; names and files keys differ', async () => {
    const dk = createDriveKey();
    const k1 = await deriveSubkeys(dk);
    const k2 = await deriveSubkeys(dk.slice());
    const s = await sealField(k1.names, 'name', 'n1', 'report.pdf');
    expect(fromUtf8(await openField(k2.names, 'name', 'n1', s))).toBe('report.pdf');
    await expect(openField(k1.files, 'name', 'n1', s)).rejects.toThrow(DecryptError);
  });
});

describe('sealed fields — AAD binds field and node', () => {
  it('round trips strings and bytes; fresh IV every time', async () => {
    const { names } = await deriveSubkeys(createDriveKey());
    const a = await sealField(names, 'name', 'node', 'ünï cödé.txt');
    const b = await sealField(names, 'name', 'node', 'ünï cödé.txt');
    expect(a.iv).not.toBe(b.iv);
    expect(Object.keys(a).sort()).toEqual(['ct', 'iv']);
    expect(fromUtf8(await openField(names, 'name', 'node', a))).toBe('ünï cödé.txt');
    const bytes = randomBytes(40);
    eq(await openField(names, 'fk', 'node', await sealField(names, 'fk', 'node', bytes)), bytes);
    // The server may return the sealed value as JSON text.
    expect(fromUtf8(await openField(names, 'name', 'node', JSON.stringify(a)))).toBe('ünï cödé.txt');
  });

  it('a value cannot be moved to another node or another field', async () => {
    const { names } = await deriveSubkeys(createDriveKey());
    const s = await sealField(names, 'name', 'nodeA', 'secret');
    await expect(openField(names, 'name', 'nodeB', s)).rejects.toThrow(DecryptError);
    await expect(openField(names, 'meta', 'nodeA', s)).rejects.toThrow(DecryptError);
  });

  it('tampering and malformed input fail closed', async () => {
    const { names } = await deriveSubkeys(createDriveKey());
    const s = await sealField(names, 'name', 'n', 'x');
    const ct = Buffer.from(s.ct, 'base64url');
    ct[0] ^= 1;
    await expect(openField(names, 'name', 'n', { iv: s.iv, ct: b64urlFromBytes(ct) })).rejects.toThrow(DecryptError);
    await expect(openField(names, 'name', 'n', { iv: 'short', ct: s.ct })).rejects.toThrow(DecryptError);
    await expect(openField(names, 'name', 'n', null)).rejects.toThrow(DecryptError);
    await expect(openField(names, 'name', 'n', '{not json')).rejects.toThrow(DecryptError);
  });
});

describe('pw wrap (Argon2id, 64 MiB, t=3)', () => {
  it('round trips; wrong password, wrong salt and a moved wrap fail', async () => {
    const dk = createDriveKey();
    const { driveSalt, wrap } = await wrapPassword(dk, 'correct horse battery');
    expect(wrap).toMatchObject({ kind: 'pw', ref: 'pw' });
    expect(wrap.data).toMatch(/^1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    expect(Buffer.from(driveSalt, 'base64url').length).toBe(16);
    eq(await unlockWithPassword('correct horse battery', driveSalt, [wrap]), dk);
    // NFC: the same password typed decomposed unlocks too.
    const { driveSalt: s2, wrap: w2 } = await wrapPassword(dk, 'café');
    eq(await unlockWithPassword('café', s2, [w2]), dk);
    expect(await unlockWithPassword('wrong password', driveSalt, [wrap])).toBeNull();
    expect(await unlockWithPassword('correct horse battery', s2, [wrap])).toBeNull();
    expect(await unlockWithPassword('correct horse battery', driveSalt, [{ ...wrap, ref: 'other' }])).toBeNull();
    expect(await unlockWithPassword('correct horse battery', driveSalt, [{ ...wrap, kind: 'recovery' }])).toBeNull();
    expect(await unlockWithPassword('correct horse battery', 'not-b64!', [wrap])).toBeNull();
    expect(await unlockWithPassword('', driveSalt, [wrap])).toBeNull();
    expect(await unlockWithPassword('x', driveSalt, [])).toBeNull();
  }, 60000);
});

describe('recovery wraps', () => {
  it('normalises codes as the server does (src/directory-do.js normalizeRecoveryCode)', async () => {
    const cases = [[CODE, 'ABCDEFGHJKMNPQRS'], ['abcd efgh jkmn pqrs', 'ABCDEFGHJKMNPQRS'], ['oOiI-lLAB-CDEF-GHJK', '001111ABCDEFGHJK'],
      ['short', null], ['', null], ['ABCD-EFGH-JKMN-PQRU', null], ['x'.repeat(80), null], [42, null]];
    for (const [c, want] of cases) expect(normalizeRecoveryCode(c)).toBe(want);
    const hex = createHash('sha256').update('secbin-recovery/v1:ABCDEFGHJKMNPQRS').digest('hex');
    expect(await recoveryRef('abcd-efgh-jkmn-pqrs')).toBe(hex);
    expect(await recoveryRef('nope')).toBeNull();
  });

  it('round trips with the code as typed; a wrong code or a moved wrap fails', async () => {
    const dk = createDriveKey();
    const w = await wrapRecovery(dk, CODE);
    expect(w.kind).toBe('recovery');
    expect(w.ref).toBe(await recoveryRef(CODE));
    eq(await unlockWithRecovery(' abcd efgh-jkmn pqrs ', [w]), dk);
    expect(await unlockWithRecovery('ABCD-EFGH-JKMN-PQRT', [w])).toBeNull();
    expect(await unlockWithRecovery('garbage', [w])).toBeNull();
    expect(await unlockWithRecovery(CODE, [{ ...w, ref: 'moved' }])).toBeNull();
    // Among many codes' wraps, each code opens its own.
    const other = 'ZZZZ-YYYY-XXXX-WWWW';
    const wraps = [await wrapRecovery(dk, other), w];
    eq(await unlockWithRecovery(other, wraps), dk);
    eq(await unlockWithRecovery(CODE, wraps), dk);
    await expect(wrapRecovery(dk, 'bad')).rejects.toThrow(TypeError);
  });
});

describe('passkey (PRF) wraps', () => {
  it('the PRF salt is SHA-256("secbin-drive/v1 prf")', () => {
    eq(DRIVE_PRF_SALT, createHash('sha256').update('secbin-drive/v1 prf').digest());
  });

  it('round trips; another PRF output or credential fails', async () => {
    const dk = createDriveKey();
    const prf = randomBytes(32);
    const w = await wrapPrf(dk, prf, 'cred-1');
    expect(w).toMatchObject({ kind: 'passkey', ref: 'cred-1' });
    eq(await unlockWithPrf(prf.buffer.slice(0), 'cred-1', [w]), dk);
    expect(await unlockWithPrf(randomBytes(32), 'cred-1', [w])).toBeNull();
    expect(await unlockWithPrf(prf, 'cred-2', [w])).toBeNull();
    expect(await unlockWithPrf(prf, 'cred-2', [{ ...w, ref: 'cred-2' }])).toBeNull(); // AAD binds the credential
    expect(await unlockWithPrf(new Uint8Array(8), 'cred-1', [w])).toBeNull();
    await expect(wrapPrf(dk, prf, '')).rejects.toThrow(TypeError);
  });
});

describe('owner escrow', () => {
  it('a user DK wrapped to the owner opens with the owner key only', async () => {
    const owner = await createEscrowKeyPair();
    expect(Object.keys(owner.publicJwk).sort()).toEqual(['crv', 'kty', 'x', 'y']);
    const userDk = createDriveKey();
    const w = await wrapEscrow(userDk, owner.publicJwk);
    expect(w).toMatchObject({ kind: 'escrow', ref: 'escrow' });
    expect(escrowWrapKeyId(w)).toBe(await escrowKeyId(owner.publicJwk));
    eq(await unlockWithEscrow(owner.privateKey, w), userDk);
    const stranger = await createEscrowKeyPair();
    expect(await unlockWithEscrow(stranger.privateKey, w)).toBeNull();
    expect(await escrowKeyId(stranger.publicJwk)).not.toBe(escrowWrapKeyId(w));
    // Tampering with the ephemeral key or the kid breaks it.
    const parts = w.data.split('.');
    expect(await unlockWithEscrow(owner.privateKey, { ...w, data: [parts[0], parts[1], 'AAAAAAAAAAAAAAAAAAAAAA', parts[3], parts[4]].join('.') })).toBeNull();
    const eph = await createEscrowKeyPair();
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', await crypto.subtle.importKey('jwk', eph.publicJwk, { name: 'ECDH', namedCurve: 'P-256' }, true, [])));
    expect(await unlockWithEscrow(owner.privateKey, { ...w, data: [parts[0], b64urlFromBytes(raw), parts[2], parts[3], parts[4]].join('.') })).toBeNull();
    expect(await unlockWithEscrow(owner.privateKey, { ...w, kind: 'pw' })).toBeNull();
    expect(await unlockWithEscrow(owner.privateKey, { kind: 'escrow', ref: 'escrow', data: 'junk' })).toBeNull();
  });

  it('the escrow private key sealed under the owner DK opens with that DK only', async () => {
    const ownerDk = createDriveKey();
    const owner = await createEscrowKeyPair();
    const sealed = await sealEscrowPriv(ownerDk, owner.privateKey);
    expect(sealed).toMatch(/^1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    const priv = await openEscrowPriv(ownerDk, sealed);
    expect(priv.extractable).toBe(false);
    const userDk = createDriveKey();
    eq(await unlockWithEscrow(priv, await wrapEscrow(userDk, owner.publicJwk)), userDk);
    await expect(openEscrowPriv(createDriveKey(), sealed)).rejects.toThrow(DecryptError);
    await expect(openEscrowPriv(ownerDk, 'nope')).rejects.toThrow(DecryptError);
  });
});

describe('the tab copy (sessionStorage)', () => {
  const store = new Map();
  beforeEach(() => {
    store.clear();
    globalThis.sessionStorage = {
      getItem: (k) => (store.has(k) ? store.get(k) : null),
      setItem: (k, v) => store.set(k, String(v)),
      removeItem: (k) => store.delete(k),
    };
  });

  it('saves, loads (for the same user only) and clears', () => {
    const dk = createDriveKey();
    expect(loadSessionKey()).toBeNull();
    expect(saveSessionKey(dk, 'u1')).toBe(true);
    expect(store.get('secbin_dk')).toBe(b64urlFromBytes(dk));
    eq(loadSessionKey('u1'), dk);
    eq(loadSessionKey(), dk);
    expect(loadSessionKey('u2')).toBeNull();
    clearSessionKey();
    expect(loadSessionKey('u1')).toBeNull();
    expect(store.size).toBe(0);
  });

  it('never throws, and rejects malformed values', () => {
    store.set('secbin_dk', 'AAAA');
    expect(loadSessionKey()).toBeNull();
    expect(saveSessionKey(new Uint8Array(5))).toBe(false);
    globalThis.sessionStorage = { getItem() { throw new Error('denied'); }, setItem() { throw new Error('denied'); }, removeItem() { throw new Error('denied'); } };
    expect(loadSessionKey()).toBeNull();
    expect(saveSessionKey(createDriveKey())).toBe(false);
    expect(() => clearSessionKey()).not.toThrow();
    delete globalThis.sessionStorage;
    expect(loadSessionKey()).toBeNull();
  });
});

describe('manifest v3', () => {
  const fk = b64urlFromBytes(randomBytes(32));
  const file = (path, ref, size = 5) => ({ path, size, type: 'text/plain', mtime: 1, ref, fk });
  const base = () => ({ v: 3, kind: 'refs', entries: [file('a.txt', 0), file('d/b.txt', 1, 7)], dirs: ['d', 'e'], view: null });

  it('validates and normalises (files, then folders; total)', () => {
    const m = validateRefsManifest(base());
    expect(m.total).toBe(12);
    expect(m.entries.map((e) => e.path)).toEqual(['a.txt', 'd/b.txt', 'd', 'e']);
    expect(m.entries[2]).toEqual({ path: 'd', dir: true });
    const noView = base();
    delete noView.view;
    expect(validateRefsManifest(noView).view).toBeNull();
    const built = buildRefsManifest({ files: [{ path: 'x', size: 1, type: 'text/plain', mtime: 0, fk }], dirs: [], view: { rules: [], maxBytes: 5 } });
    expect(built).toMatchObject({ v: 3, kind: 'refs', entries: [{ path: 'x', ref: 0 }], view: { maxBytes: 5 } });
  });

  it('fails closed on anything malformed', () => {
    const bad = [
      (m) => { m.v = 2; },
      (m) => { m.kind = 'stream'; },
      (m) => { m.extra = 1; },
      (m) => { m.entries[0].path = '../x'; },
      (m) => { m.entries[0].ref = 1; }, // duplicate ref
      (m) => { m.entries[0].ref = 9; },
      (m) => { m.entries[0].fk = 'short'; },
      (m) => { m.entries[0].size = -1; },
      (m) => { m.entries[0].type = 'text/plain; charset=utf-8'; },
      (m) => { m.entries[0].extra = true; },
      (m) => { m.entries[1].path = 'a.txt'; },
      (m) => { m.dirs.push('a.txt'); },
      (m) => { m.dirs.push('a.txt/sub'); },
      (m) => { m.view = { rules: [{ match: 'mime', value: 'x/y', renderer: 'html' }], maxBytes: 1 }; },
      (m) => { m.entries = []; m.dirs = []; },
    ];
    for (const change of bad) {
      const m = base();
      change(m);
      expect(() => validateRefsManifest(m)).toThrow(ManifestError);
    }
  });

  it('chunk counts: none for an empty file, one per 8 MiB started', () => {
    expect(refChunks(0)).toBe(0);
    expect(refChunks(1)).toBe(1);
    expect(refChunks(CHUNK)).toBe(1);
    expect(refChunks(CHUNK + 1)).toBe(2);
  });
});

