// drivekeys.test.js — the Drive key model v2 (docs/DRIVE.md §3) on Node's
// Web Crypto: fixed vectors for every derivation (KEK, user key, field key,
// fingerprint, check values) and for every sealed format (a DEK, a name, a
// sub-MEK, a link key, a field-layer value), what each seal is bound to (the
// user, the sub-MEK, the per-item salt, the field; the item id is not part of
// it), the sub-MEK timeline, keys entered by hand, what the tab keeps (never a KEK),
// and manifest v3 validation.
import { describe, it, expect, beforeEach } from 'vitest';
import {
  deriveKek, deriveUserKey, deriveFieldKey, keyFingerprint, keyCheckValue, saltCheckValue, sameCheck, sealDek, openDek, sealName, openName,
  sealSubMek, openSubMek, sealLinkKey, openLinkKey, sealAtRest, openAtRest, isAtRest, effectiveAt, mekStatus, checkTimeline, parseManualKey,
  clearImpersonationKeys, clearSessionKey, purgeStaleSlots, readSlot, writeSlot,
  holdSessionKeys, releaseSessionKeys, newSalt, newKey, newMekId, MEK_ID_RE, KEY_RE,
} from '../public/js/drivekeys.js';
import { validateRefsManifest, buildRefsManifest, refChunks } from '../public/js/refsmanifest.js';
import { DecryptError } from '../public/js/crypto.js';
import { fromUtf8, utf8, b64urlFromBytes, randomBytes } from '../public/js/bytes.js';
import { CHUNK, ManifestError } from '../public/js/files.js';

const eq = (a, b) => expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true);
const bytes = (start, n = 32) => Uint8Array.from({ length: n }, (_, i) => (start + i) & 0xff);
// The fixed inputs of the vectors (synthetic).
const ROOT = bytes(0x00);
const SUB = bytes(0x20);
const SALT = b64urlFromBytes(bytes(0x40));
const UID = 'AAAAAAAAAAAAAAAA';
const MEK = 'mAAAAAAAAAAA';
const LINK = 'rAAAAAAAAAAAAAAAAAAAAAA';
const AT = { userId: UID, mekId: MEK, salt: SALT };

describe('fixed vectors (docs/DRIVE.md §3: any change here breaks every stored Drive)', () => {
  it('derivations', async () => {
    const kek = await deriveKek(ROOT, SUB, SALT, UID);
    expect(b64urlFromBytes(kek)).toBe('y3g9XzCBKsUXxc4dQqYTDACYVr1c-97XPgBVc54U8FI');
    const uk = await deriveUserKey(ROOT, SALT, UID);
    expect(b64urlFromBytes(uk)).toBe('3K1ElciYFwiwXUQD5uBlCXbNKWLdejRhqpC_9m4KfjA');
    expect(b64urlFromBytes(await deriveFieldKey(uk, 'linkKey'))).toBe('YXljE3BneUEtY4fBVr3ZlOH5Tu1kH495Up_feUvYB3Q');
    expect(await keyFingerprint(ROOT)).toBe('a6-46-7hpHY');
    expect(await keyFingerprint(SUB)).toBe('3A63ePi43VA');
    expect(await keyCheckValue(kek, 'kek')).toBe('bw7OksE4Mi2BsNXqnU7VIzqm2_9Pg8dMt2p6kkgqMPo');
    expect(await keyCheckValue(ROOT, 'mek')).toBe('WeAH1pJfYRgigtnsMYZq_01ygnfVvGjh71iRt_wku3U');
    expect(await saltCheckValue(SALT, UID)).toBe('70CkVH5oSgZ1Xb3Vy71EzYh0vfDRGV_BdPme1J3K_aE');
    // A check value is not the key, and differs per kind.
    expect(await keyCheckValue(kek, 'mek')).not.toBe(await keyCheckValue(kek, 'kek'));
  });

  it('sealed formats open as stored', async () => {
    const kek = await deriveKek(ROOT, SUB, SALT, UID);
    eq(await openDek(kek, AT, { iv: 'dGibffGqOsts-4As', ct: '-Pq6K0lBBQFtJ16J8AkppHZrIwLhpDr2LcAmIGvk15SfEwZa_baTcRp-XYemjdKY' }), bytes(0x60));
    expect(fromUtf8(await openName(kek, AT, 'name', { iv: 'RQxxGrMwxWUrg_6g', ct: 'UcJl0rBRoothooVgZTfJED9X92RaQ6EpEr8' }))).toBe('report.pdf');
    eq(await openSubMek(ROOT, MEK, 'm1.7F3bi8DFMr4Necyw.PkCDIGwbo6u-7VgUvPAkeJOCR04-7w17BimmwZflZbjbS4sdFNwD6ApelkGMY5u4'), SUB);
    eq(await openLinkKey(kek, { userId: UID, mekId: MEK, linkId: LINK }, { iv: 'cw3NTg1qILhHm54Q', ct: 'Rj_4ZP9WgKNH1eIULm2iBqMJZ56Ur0ke82EcJL-Dg0phvFC9zTaROH1gQ6Ia2nfrKGH21d6Qawo' }), bytes(0x80, 40));
    const fk = await deriveFieldKey(await deriveUserKey(ROOT, SALT, UID), 'linkKey');
    expect(await openAtRest(fk, { userId: UID, field: 'linkKey', ref: LINK }, 'a1.jHyq4ZIAK1BlODgB.PAw9Vt_zGFIGW-LsEe2FS8uxIIAY')).toBe('hello');
  });
});

describe('what each seal is bound to', () => {
  it('a DEK: the KEK, the user, the sub-MEK and the per-DEK salt — not the item id', async () => {
    const kek = newKey();
    const dek = newKey();
    const at = { userId: UID, mekId: MEK, salt: newSalt() };
    const s = await sealDek(kek, at, dek);
    expect(Object.keys(s).sort()).toEqual(['ct', 'iv']);
    const s2 = await sealDek(kek, at, dek);
    expect(s2.iv).not.toBe(s.iv); // a fresh IV every time
    eq(await openDek(kek, at, s), dek);
    eq(await openDek(kek, at, JSON.stringify(s)), dek); // as the server stores it
    for (const other of [{ ...at, userId: 'BBBBBBBBBBBBBBBB' }, { ...at, mekId: 'mBBBBBBBBBBB' }, { ...at, salt: newSalt() }]) {
      await expect(openDek(kek, other, s)).rejects.toThrow(DecryptError);
    }
    await expect(openDek(newKey(), at, s)).rejects.toThrow(DecryptError);
    // A DEK and a name under the same keys and salt use different sub-keys.
    await expect(openName(kek, at, 'name', s)).rejects.toThrow(DecryptError);
  });

  it('names and metadata: their field too; tampering and malformed input fail closed', async () => {
    const kek = newKey();
    const at = { userId: UID, mekId: MEK, salt: newSalt() };
    const s = await sealName(kek, at, 'name', utf8('ünï cödé.txt'));
    expect(fromUtf8(await openName(kek, at, 'name', s))).toBe('ünï cödé.txt');
    await expect(openName(kek, at, 'meta', s)).rejects.toThrow(DecryptError);
    const ct = Buffer.from(s.ct, 'base64url');
    ct[0] ^= 1;
    await expect(openName(kek, at, 'name', { iv: s.iv, ct: b64urlFromBytes(ct) })).rejects.toThrow(DecryptError);
    for (const bad of [{ iv: 'short', ct: s.ct }, null, '{not json', 42]) await expect(openName(kek, at, 'name', bad)).rejects.toThrow(DecryptError);
  });

  it('sub-MEKs under the root, bound to their id; link keys to their link; field-layer values to user, field and ref', async () => {
    const root = newKey();
    const sub = newKey();
    const id = newMekId();
    expect(id).toMatch(MEK_ID_RE);
    const sealed = await sealSubMek(root, id, sub);
    expect(sealed).toMatch(/^m1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+$/);
    eq(await openSubMek(root, id, sealed), sub);
    await expect(openSubMek(root, newMekId(), sealed)).rejects.toThrow();
    await expect(openSubMek(newKey(), id, sealed)).rejects.toThrow();
    const kek = newKey();
    const lk = await sealLinkKey(kek, { userId: UID, mekId: MEK, linkId: LINK }, bytes(1, 50));
    await expect(openLinkKey(kek, { userId: UID, mekId: MEK, linkId: `r${'B'.repeat(22)}` }, lk)).rejects.toThrow();
    const fk = newKey();
    const v = await sealAtRest(fk, { userId: UID, field: 'received', ref: 'name:x' }, '{"iv":"x"}');
    expect(isAtRest(v)).toBe(true);
    expect(isAtRest('{"iv":"x","ct":"y"}')).toBe(false);
    expect(await openAtRest(fk, { userId: UID, field: 'received', ref: 'name:x' }, v)).toBe('{"iv":"x"}');
    for (const other of [{ userId: 'BBBBBBBBBBBBBBBB', field: 'received', ref: 'name:x' }, { userId: UID, field: 'linkKey', ref: 'name:x' }, { userId: UID, field: 'received', ref: 'meta:x' }]) {
      await expect(openAtRest(fk, other, v)).rejects.toThrow();
    }
  });

  it('check values compare in constant time and never match an empty or different value', async () => {
    const a = await keyCheckValue(newKey());
    expect(sameCheck(a, a)).toBe(true);
    expect(sameCheck(a, await keyCheckValue(newKey()))).toBe(false);
    expect(sameCheck('', '')).toBe(false);
    expect(sameCheck(a, null)).toBe(false);
    expect(sameCheck(a, a.slice(1))).toBe(false);
    expect(newSalt()).toMatch(KEY_RE);
  });
});

describe('the sub-MEK timeline', () => {
  const m = (id, from, until, created = 0) => ({ id, from, until, created });
  it('the latest start wins; one open-ended key; no gap; statuses', () => {
    const list = [m('mA', 0, 100), m('mB', 100, 200), m('mC', 200, null)];
    expect(effectiveAt(list, 50).id).toBe('mA');
    expect(effectiveAt(list, 100).id).toBe('mB');
    expect(effectiveAt(list, 5000).id).toBe('mC');
    expect(effectiveAt(list, -1)).toBeNull();
    expect(checkTimeline(list, 150)).toBeNull();
    expect(mekStatus(list, list[0], 150)).toBe('retired');
    expect(mekStatus(list, list[1], 150)).toBe('current');
    expect(mekStatus(list, list[2], 150)).toBe('scheduled');
    // Overlaps: the later start wins, the other is "overlapped".
    const over = [m('mA', 0, 300), m('mB', 100, null)];
    expect(effectiveAt(over, 150).id).toBe('mB');
    expect(mekStatus(over, over[0], 150)).toBe('overlapped');
    expect(checkTimeline(over, 150)).toBeNull();
    // What is refused.
    expect(checkTimeline([], 0)).toMatch(/at least one/);
    expect(checkTimeline([m('mA', 0, 100)], 50)).toMatch(/open-ended/);
    expect(checkTimeline([m('mA', 0, null), m('mB', 10, null)], 50)).toMatch(/open-ended/);
    expect(checkTimeline([m('mA', 0, 100), m('mB', 200, null)], 50)).toMatch(/gap/);
    expect(checkTimeline([m('mA', 100, null)], 50)).toMatch(/in effect now/);
    expect(checkTimeline([m('mA', 100, 50), m('mB', 0, null)], 150)).toMatch(/end before/);
  });
});

describe('keys entered by hand', () => {
  it('32 bytes as hex, base64 or base64url (spaces ignored); anything else, or one repeated byte, is refused', () => {
    const k = randomBytes(32);
    eq(parseManualKey(Buffer.from(k).toString('hex')), k);
    eq(parseManualKey(Buffer.from(k).toString('base64')), k);
    eq(parseManualKey(b64urlFromBytes(k)), k);
    eq(parseManualKey(` ${Buffer.from(k).toString('hex').replace(/(.{8})/g, '$1 ')} `), k);
    for (const bad of ['', 'x', Buffer.from(randomBytes(31)).toString('hex'), Buffer.from(randomBytes(33)).toString('base64'), '0'.repeat(64), 'A'.repeat(43), null]) {
      expect(() => parseManualKey(bad), String(bad)).toThrow(TypeError);
    }
  });
});

describe('what the tab keeps (sessionStorage): never a KEK', () => {
  const store = new Map();
  beforeEach(() => {
    store.clear();
    globalThis.sessionStorage = {
      getItem: (k) => (store.has(k) ? store.get(k) : null),
      setItem: (k, v) => store.set(k, String(v)),
      removeItem: (k) => store.delete(k),
    };
  });

  it('the module has no way to store or load a KEK', async () => {
    const m = await import('../public/js/drivekeys.js');
    for (const name of ['saveSessionKeys', 'loadSessionKeys', 'saveImpersonationKeys', 'loadImpersonationKeys']) expect(m[name], name).toBeUndefined();
  });

  it('the slots of a release before go (the KEK slots, the old impersonation DK); only the old DK of a Drive waiting for its upgrade stays until sign-out', () => {
    for (const k of ['secbin_kek', 'secbin_kek_imp', 'secbin_dk_imp', 'secbin_dk_imp_uid', 'secbin_dk', 'secbin_dk_uid']) store.set(k, 'planted');
    purgeStaleSlots();
    expect([...store.keys()].sort()).toEqual(['secbin_dk', 'secbin_dk_uid']);
    store.set('secbin_kek_imp', 'planted');
    clearImpersonationKeys();
    expect(store.has('secbin_kek_imp')).toBe(false);
    clearSessionKey();
    expect(store.size).toBe(0);
  });

  it('never throws, and holds the old DK in memory while third-party script is on the page', () => {
    writeSlot('secbin_dk', 'D'.repeat(43));
    holdSessionKeys();
    expect(store.has('secbin_dk')).toBe(false);
    expect(readSlot('secbin_dk')).toBe('D'.repeat(43));
    releaseSessionKeys();
    expect(store.get('secbin_dk')).toBe('D'.repeat(43));
    globalThis.sessionStorage = { getItem() { throw new Error('denied'); }, setItem() { throw new Error('denied'); }, removeItem() { throw new Error('denied'); } };
    expect(readSlot('secbin_dk')).toBeNull();
    expect(writeSlot('secbin_dk', 'x')).toBe(false);
    expect(() => clearSessionKey()).not.toThrow();
    expect(() => purgeStaleSlots()).not.toThrow();
    delete globalThis.sessionStorage;
    expect(readSlot('secbin_dk')).toBeNull();
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

