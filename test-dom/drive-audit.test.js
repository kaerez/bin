// drive-audit.test.js — the browser side of the Drive fixes from security
// audit round 2 and of the owner's impersonated Drive (docs/DRIVE.md §3, §8.1),
// with the real client against the in-memory server (drive-fake-server.js):
//   H-1  the owner's browser checks the server's escrow public key against
//        its own private key; a user's browser pins the escrow key and never
//        re-wraps to another one without the user's say;
//   L-6  a file without readable metadata, or whose size disagrees, is
//        unreadable, never an empty file;
//   DK   the Account page keeps the tab's keys out of sessionStorage;
//   impersonation: the owner opens, reads, uploads and shares in a user's
//        Drive through the escrow, with the user's key in its own slot, and
//        creates a new Drive for the user (finished at the user's sign-in).
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { openDrive, unlockDrive, unlockAtSignIn, DriveLocked } from '../public/js/driveclient.js';
import {
  loadSessionKey, clearSessionKey, saveSessionKey, createDriveKey, createEscrowKeyPair, sealEscrowPriv, wrapEscrow,
  wrapPassword, unlockWithPassword, escrowKeyId, openEscrowPin, sealEscrowPin, loadImpersonationKey, clearImpersonationKey,
  holdSessionKeys, releaseSessionKeys, unlockWithEscrow,
} from '../public/js/drivekeys.js';
import { startDrive } from '../public/dashboard/js/drive-app.js';
import * as drive from '../public/js/driveclient.js';
import { fakeServer, seedTree } from './drive-fake-server.js';

const PASSWORD = 'drive password 1';
const enc = (s) => new TextEncoder().encode(s);
let S;
const install = (opts) => { S = fakeServer(opts); globalThis.fetch = S.fetch; return S; };
const keyCalls = () => S.requests.filter((r) => r.path === '/api/private/drive/keys');
beforeEach(() => { clearSessionKey(); releaseSessionKeys(); clearSessionKey(); });
afterEach(() => { vi.restoreAllMocks(); });

function fakeFile(name, bytes, type = 'text/plain') {
  return { name, size: bytes.length, type, lastModified: 1700000000000, slice: (a, b) => ({ arrayBuffer: async () => bytes.slice(a, b).buffer }) };
}

describe('H-1: the owner’s browser checks the escrow public key', () => {
  async function ownerDrive() {
    install({ role: 'owner' });
    S.proof = 'PROOF';
    const d = await unlockDrive({ password: PASSWORD }); // the first set-up creates the pair
    return d;
  }

  it('alerts when the server’s escrow public key is not its own, and never re-creates the pair silently', async () => {
    const d = await ownerDrive();
    const mine = S.escrowPub;
    const attacker = (await createEscrowKeyPair()).publicJwk;
    S.escrowPub = attacker; // swapped on the server
    const before = keyCalls().length;
    const c = await openDrive({ user: S.user });
    expect(c.notice).toMatchObject({ kind: 'escrow_mismatch' });
    expect(keyCalls().length).toBe(before); // nothing written: no new pair, no re-seal
    // Restoring needs the owner's confirmation and puts back the key derived from the private key.
    await c.restoreEscrowKey({ current: 'PROOF' });
    expect(S.escrowPub).toEqual(mine);
    expect(keyCalls().at(-1).body.current).toBe('PROOF');
    expect((await openDrive({ user: S.user })).notice).toBeNull();
    void d;
  }, 60000);

  it('an escrow private key that does not open, or a missing one, is shown too (a new pair needs the confirmation)', async () => {
    await ownerDrive();
    const other = await createEscrowKeyPair();
    S.escrowPriv = await sealEscrowPriv(createDriveKey(), other.privateKey); // sealed under another DK
    const c = await openDrive({ user: S.user });
    expect(c.notice).toMatchObject({ kind: 'escrow_unreadable' });
    await expect(c.newEscrowKey({})).rejects.toMatchObject({ code: 'reauth_required' });
    await c.newEscrowKey({ current: 'PROOF' });
    expect((await openDrive({ user: S.user })).notice).toBeNull();
    S.escrowPriv = null;
    expect((await openDrive({ user: S.user })).notice).toMatchObject({ kind: 'escrow_missing' });
  }, 60000);
});

describe('H-1: a user’s browser pins the escrow key', () => {
  it('pins the first key (trust on first use); a new key is never wrapped to until the user accepts it', async () => {
    install();
    const first = await createEscrowKeyPair();
    S.escrowPub = first.publicJwk;
    const d = await unlockDrive({ password: PASSWORD });
    expect(await openEscrowPin(d.dk, S.escrowPin)).toBe(await escrowKeyId(first.publicJwk));
    const wrapBefore = S.wraps.get('escrow|escrow');
    // The server now hands out another key.
    const second = await createEscrowKeyPair();
    S.escrowPub = second.publicJwk;
    const c = await openDrive({ user: S.user });
    expect(c.notice).toMatchObject({ kind: 'escrow_changed', kid: await escrowKeyId(second.publicJwk) });
    expect(S.wraps.get('escrow|escrow')).toEqual(wrapBefore); // not re-wrapped
    expect(await unlockWithEscrow(first.privateKey, S.wraps.get('escrow|escrow'))).toEqual(d.dk);
    // The user accepts: re-wrapped to the new key, which is now pinned.
    await c.acceptEscrowKey();
    expect(await unlockWithEscrow(second.privateKey, S.wraps.get('escrow|escrow'))).toEqual(d.dk);
    expect(await openEscrowPin(d.dk, S.escrowPin)).toBe(await escrowKeyId(second.publicJwk));
    expect((await openDrive({ user: S.user })).notice).toBeNull();
  }, 60000);

  it('a pin that does not open (altered, or another Drive’s) counts as a changed key; no pin and a wrap for another key too', async () => {
    install();
    const k = await createEscrowKeyPair();
    S.escrowPub = k.publicJwk;
    const d = await unlockDrive({ password: PASSWORD });
    S.escrowPin = await sealEscrowPin(createDriveKey(), await escrowKeyId(k.publicJwk));
    expect((await openDrive({ user: S.user })).notice).toMatchObject({ kind: 'escrow_changed' });
    // No pin, and the escrow wrap is for an older key: not silently re-wrapped either.
    S.escrowPin = null;
    const old = await createEscrowKeyPair();
    S.wraps.set('escrow|escrow', await wrapEscrow(d.dk, old.publicJwk));
    const n = keyCalls().length;
    expect((await openDrive({ user: S.user })).notice).toMatchObject({ kind: 'escrow_changed' });
    expect(keyCalls().length).toBe(n);
  }, 60000);

  it('the Drive page shows the notice and its "Trust the new key" button', async () => {
    install();
    S.escrowPub = (await createEscrowKeyPair()).publicJwk;
    await unlockDrive({ password: PASSWORD });
    S.escrowPub = (await createEscrowKeyPair()).publicJwk;
    const mount = document.createElement('div');
    document.body.replaceChildren(mount);
    const r = await startDrive(mount, { drive, profile: { limits: {}, user: { username: 'u' } }, user: S.user, revoke: async () => {} });
    expect(r.state).toBe('open');
    const box = mount.querySelector('#drive-escrow-notice');
    expect(box.getAttribute('role')).toBe('status');
    mount.querySelector('#drive-escrow-accept').click();
    for (let i = 0; i < 200 && mount.querySelector('#drive-escrow-notice'); i++) await new Promise((res) => setTimeout(res, 10));
    expect(mount.querySelector('#drive-escrow-notice')).toBeNull();
  }, 60000);
});

describe('L-6: a file needs its sealed metadata', () => {
  it('missing metadata or a size that disagrees makes it unreadable, never an empty file', async () => {
    install();
    const dk = createDriveKey();
    saveSessionKey(dk, 'u1');
    S.wraps.set('pw|pw', (await wrapPassword(dk, PASSWORD)).wrap);
    const ids = await seedTree(S, dk, { 'a.txt': enc('hello a'), 'b.txt': enc('hello b'), 'c.txt': enc('hello c') });
    const a = S.nodes.get(ids.get('a.txt'));
    a.meta = null; a.size = 0; a.chunks = 0; // the server drops the metadata and claims an empty file
    const b = S.nodes.get(ids.get('b.txt'));
    b.size = 3; // a size that disagrees with the sealed one
    const c = await openDrive({ user: S.user });
    const { children } = await c.list();
    const by = Object.fromEntries(children.map((x) => [x.id, x]));
    expect(by[a.id]).toMatchObject({ unreadable: true, name: null });
    expect(by[b.id]).toMatchObject({ unreadable: true, name: null });
    expect(by[ids.get('c.txt')].name).toBe('c.txt');
    await expect(c.download(a.id)).rejects.toThrow(/cannot be read/);
    await expect(c.download(b.id)).rejects.toThrow(/cannot be read/);
    // Files whose metadata alone is gone do not make the tab drop its key (their names still open).
    S.nodes.get(ids.get('c.txt')).meta = null;
    await c.list();
    expect(loadSessionKey('u1')).toEqual(dk);
  }, 30000);
});

describe('names: no bidi or invisible characters (audit round 3, L-5)', () => {
  it('checkPath, the client’s checkName and the page’s checkName refuse them; ordinary names pass', async () => {
    const { checkPath } = await import('../public/js/files.js');
    const { checkName } = await import('../public/js/driveclient.js');
    const page = await import('../public/dashboard/js/drive-app.js');
    for (const bad of ['invoice\u202efdp.exe', 'a\u200bb.txt', 'x\u2028y', 'nel\u0085.txt', 'rtl\u2067x', 'b\ufeffom', 'lrm\u200e.txt']) {
      expect(() => checkPath(bad), JSON.stringify(bad)).toThrow();
      expect(() => checkPath(`dir/${bad}`)).toThrow();
      expect(() => checkName(bad)).toThrow(/invisible/);
      expect(page.checkName(bad).error).toMatch(/invisible/);
    }
    for (const ok of ['report.pdf', 'café résumé.txt', 'עברית.txt', '日本語.md']) {
      expect(checkPath(ok)).toBe(ok);
      expect(checkName(ok)).toBe(ok);
      expect(page.checkName(ok)).toEqual({ name: ok });
    }
  });
});

describe('DK exposure: pages with third-party script', () => {
  it('holdSessionKeys moves the tab’s keys out of sessionStorage (still usable); release puts them back', () => {
    const dk = createDriveKey();
    saveSessionKey(dk, 'u1');
    holdSessionKeys();
    expect(sessionStorage.getItem('secbin_dk')).toBeNull();
    expect(sessionStorage.getItem('secbin_dk_uid')).toBeNull();
    expect(loadSessionKey('u1')).toEqual(dk);
    const next = createDriveKey();
    saveSessionKey(next, 'u1'); // e.g. unlocked with the password on Account: memory only
    expect(sessionStorage.getItem('secbin_dk')).toBeNull();
    releaseSessionKeys();
    expect(loadSessionKey('u1')).toEqual(next);
    expect(sessionStorage.getItem('secbin_dk_uid')).toBe('u1');
  });
});

describe('impersonation: the owner in a user’s Drive', () => {
  async function ownerAndUser() {
    install();
    const ownerDk = createDriveKey();
    const kp = await createEscrowKeyPair();
    S.escrowPub = kp.publicJwk;
    S.ownerEscrowPriv = await sealEscrowPriv(ownerDk, kp.privateKey);
    return { ownerDk, kp };
  }

  it('opens the user’s Drive through the escrow, keeps the user’s key in its own slot, reads, uploads and shares', async () => {
    const { ownerDk, kp } = await ownerAndUser();
    const userDk = createDriveKey();
    S.wraps.set('pw|pw', (await wrapPassword(userDk, 'the user password')).wrap);
    S.wraps.set('escrow|escrow', await wrapEscrow(userDk, kp.publicJwk));
    const ids = await seedTree(S, userDk, { 'report.txt': enc('the quarterly report') });
    S.impersonatedBy = 'owner';
    const u = { ...S.user, impersonating: true };
    // Without the owner's own key in the tab: a notice, no escrow call.
    await expect(openDrive({ user: u })).rejects.toMatchObject({ name: 'DriveLocked', reason: 'owner_locked' });
    expect(S.requests.some((r) => r.path === '/api/private/drive/escrow')).toBe(false);
    saveSessionKey(ownerDk, 'owner1');
    const c = await openDrive({ user: u });
    expect(S.escrowUses).toBe(1);
    expect(loadSessionKey('owner1')).toEqual(ownerDk); // the owner's slot is untouched
    expect(loadImpersonationKey('u1')).toEqual(userDk);
    const { children } = await c.list();
    expect(children.map((x) => x.name)).toEqual(['report.txt']);
    const got = await (await c.download(ids.get('report.txt'))).blob();
    expect(new TextDecoder().decode(new Uint8Array(await got.arrayBuffer()))).toBe('the quarterly report');
    const id = await c.upload('root', fakeFile('from-owner.txt', enc('uploaded by the owner')));
    expect(S.nodes.get(id).state).toBe('ready');
    const sh = await c.share([id], { expire: '1h' });
    expect(sh.id).toMatch(/^fSHARE/);
    // Opening again in this tab needs no second escrow use; the user's own keys were never touched.
    await openDrive({ user: u });
    expect(S.escrowUses).toBe(1);
    expect(keyCalls()).toHaveLength(0);
    clearImpersonationKey();
    expect(loadImpersonationKey('u1')).toBeNull();
    expect(loadSessionKey('owner1')).toEqual(ownerDk);
  }, 60000);

  it('says what is missing: no escrow key yet, no escrow wrap, a server escrow key that is not the owner’s', async () => {
    const { ownerDk } = await ownerAndUser();
    saveSessionKey(ownerDk, 'owner1');
    S.impersonatedBy = 'owner';
    const u = { ...S.user, impersonating: true };
    S.wraps.set('pw|pw', (await wrapPassword(createDriveKey(), 'x')).wrap);
    await expect(openDrive({ user: u })).rejects.toMatchObject({ reason: 'no_wrap' });
    const priv = S.ownerEscrowPriv;
    S.ownerEscrowPriv = null;
    await expect(openDrive({ user: u })).rejects.toMatchObject({ reason: 'no_escrow' });
    S.ownerEscrowPriv = priv;
    S.escrowPub = (await createEscrowKeyPair()).publicJwk;
    await expect(openDrive({ user: u })).rejects.toMatchObject({ reason: 'escrow_mismatch' });
    // The Drive page shows the notice (an alert for the mismatch), not the unlock prompt.
    const mount = document.createElement('div');
    document.body.replaceChildren(mount);
    const r = await startDrive(mount, { drive, profile: { limits: {}, user: { username: 'alice' } }, user: u, revoke: async () => {} });
    expect(r).toMatchObject({ state: 'impersonating', reason: 'escrow_mismatch' });
    expect(mount.querySelector('#drive-impersonating [role="alert"]')).not.toBeNull();
    expect(mount.querySelector('#drive-unlock')).toBeNull();
    expect(DriveLocked).toBeTypeOf('function');
  }, 60000);

  it('creates a new Drive for the user (escrow + hand-over), which the user’s sign-in finishes with a password wrap', async () => {
    const { ownerDk, kp } = await ownerAndUser();
    saveSessionKey(ownerDk, 'owner1');
    S.impersonatedBy = 'owner';
    const u = { ...S.user, impersonating: true };
    const c = await openDrive({ user: u });
    expect([...S.wraps.keys()].sort()).toEqual(['escrow|escrow', 'handoff|handoff']);
    expect(S.handoffKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const id = await c.mkdir('root', 'For you');
    // The page shows the Drive with the impersonation note.
    const mount = document.createElement('div');
    document.body.replaceChildren(mount);
    const r = await startDrive(mount, { drive, profile: { limits: {}, user: { username: 'alice' } }, user: u, revoke: async () => {} });
    expect(r.state).toBe('open');
    expect(mount.querySelector('#drive-imp-note').textContent).toMatch(/cannot be removed or replaced while you act as alice/);
    // The impersonation ends; the user signs in with their password.
    clearSessionKey();
    S.impersonatedBy = null;
    expect(await unlockAtSignIn({ user: S.user, password: 'the user password' })).toBe(true);
    const dk = loadSessionKey('u1');
    expect(await unlockWithPassword('the user password', S.driveSalt, [...S.wraps.values()])).toEqual(dk);
    expect(await unlockWithEscrow(kp.privateKey, S.wraps.get('escrow|escrow'))).toEqual(dk);
    expect(S.wraps.has('handoff|handoff')).toBe(false);
    expect(S.handoffKey).toBeNull();
    const mine = await openDrive({ user: S.user });
    expect((await mine.list()).children.map((x) => x.name)).toEqual(['For you']);
    expect(await openEscrowPin(dk, S.escrowPin)).toBe(await escrowKeyId(kp.publicJwk));
    void id;
  }, 60000);
});
