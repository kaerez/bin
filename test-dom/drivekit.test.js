// drivekit.test.js — the owner recovery kit, starting over without one, and
// the users' automatic move to a reset's escrow key (docs/DRIVE.md §3), with
// the real client (public/js/driveclient.js) and pages (drive-app.js,
// drivekit-ui.js) against the in-memory server (drive-fake-server.js).
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as drive from '../public/js/driveclient.js';
import {
  openDrive, unlockDrive, unlockAtSignIn, buildOwnerKit, restoreOwnerKit, verifyOwnerKit, startOverOwnerDrive, escrowPasswordReset,
  ownerKitStatus, kidFingerprint, DriveLocked, updatePasswordWrap, ownerSetsUpUserDrive,
} from '../public/js/driveclient.js';
import {
  createDriveKey, createEscrowKeyPair, createSigningKeyPair, endorseEscrowKey, wrapEscrow, escrowKeyId, signingKeyId, sealEscrowPin, openEscrowPin,
  openEscrowKeyPair, sameEscrowKey, loadSessionKey, saveSessionKey, clearSessionKey, releaseSessionKeys, escrowWrapKeyId, unlockWithEscrow,
  wrapRecovery, wrapPrf, unlockWithPassword, unlockWithRecovery, unlockWithPrf, keyCheckValue,
} from '../public/js/drivekeys.js';
import { sealDriveKit, parseDriveKit, KIT_FORMATS } from '../public/js/drivekit.js';
import { stretch } from '../public/js/pwauth.js';
import { b64urlFromBytes } from '../public/js/bytes.js';
import { startDrive } from '../public/dashboard/js/drive-app.js';
import { kitCard, resetThrottle } from '../public/dashboard/js/drivekit-ui.js';
import { fakeServer, seedTree } from './drive-fake-server.js';

const PW = 'owner password 1';
const NEWPW = 'owner password after recovery';
const NEWPW2 = 'owner password after the second recovery';
const SALT = 'AAAAAAAAAAAAAAAAAAAAAA';
const KITPASS = 'a long kit passphrase';
const enc = (s) => new TextEncoder().encode(s);
const T = 180000;
let S; // the server in use (for debugging)
const use = (srv) => { S = srv; globalThis.fetch = S.fetch; return srv; };
const until = async (fn, ms = 60000) => {
  const t0 = Date.now();
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 20));
  }
};
const nonGet = (srv, from = 0) => srv.requests.slice(from).filter((r) => r.method !== 'GET');
const publicKeys = (srv) => JSON.stringify({ p: srv.escrowPub, s: srv.escrowSignPub, v: srv.escrowVer });
const PROOF = {};
beforeEach(async () => {
  clearSessionKey(); releaseSessionKeys(); clearSessionKey(); resetThrottle();
  document.body.replaceChildren();
  PROOF.old ??= await stretch(PW, SALT, 3);
  PROOF.new ??= await stretch(NEWPW, SALT, 3);
  PROOF.new2 ??= await stretch(NEWPW2, SALT, 3);
});
afterEach(() => { vi.restoreAllMocks(); });

/** The owner (escrow key v1, a file in their Drive) and one user's escrow wrap. */
async function ownerSetup() {
  const SO = use(fakeServer({ role: 'owner' }));
  SO.proof = PROOF.old;
  const d = await unlockDrive({ password: PW });
  await seedTree(SO, d.dk, { 'mine.txt': enc('the owner’s file\n') });
  const a = { dk: createDriveKey() };
  a.wrap = await wrapEscrow(a.dk, SO.escrowPub);
  SO.escrowKids = [await escrowKeyId(SO.escrowPub)];
  return { SO, d, a, user: SO.user };
}
const kitOf = async (user, passphrase = KITPASS) => (await buildOwnerKit({ user, passphrase, step: { current: PROOF.old } })).text;
const restore = (user, text, passphrase = KITPASS, password = NEWPW, proof = PROOF.new) => restoreOwnerKit({ user, text, passphrase, password, step: { current: proof } });
async function opensUser(SO, wrap) {
  SO.userWraps = [wrap];
  return escrowPasswordReset({ ownerId: SO.user.id, userId: 'uX', newPassword: 'new user password' });
}
async function listNames(user) {
  return (await (await openDrive({ user })).list()).children.map((c) => c.name);
}
/** Put a File in an <input type="file"> as a user would (happy-dom: files and value). */
function pick(input, file) {
  let files = file ? [file] : [];
  Object.defineProperty(input, 'files', { configurable: true, get: () => files });
  Object.defineProperty(input, 'value', { configurable: true, get: () => (files.length ? `C:\\fakepath\\${files[0].name}` : ''), set: (v) => { if (v === '') files = []; } });
  input.dispatchEvent(new Event('change', { bubbles: true }));
}
function captureDownloads() {
  const blobs = [];
  URL.createObjectURL = (b) => { blobs.push(b); return 'blob:x'; };
  URL.revokeObjectURL = () => {};
  return blobs;
}
const profileOf = (user) => ({ user: { ...user }, limits: {}, caps: { driveEnabled: true } });

describe('the owner recovery kit: download, AUTHN recovery, restore', () => {
  it('full cycle: kit, rotation, AUTHN recovery, restore from the OLD kit; users on the new and the old key open; then the new password alone unlocks', async () => {
    const { SO, d, a, user } = await ownerSetup();
    const oldKit = await kitOf(user);
    expect(JSON.parse(oldKit).format).toBe('secbin-owner-kit/1');
    expect(SO.kit).toMatchObject({ version: 1 });
    await d.rotateEscrowKey({ current: PROOF.old });
    expect(SO.escrowVer.version).toBe(2);
    const b = { dk: createDriveKey() };
    b.wrap = await wrapEscrow(b.dk, SO.escrowPub);
    SO.escrowKids = [escrowWrapKeyId(a.wrap), escrowWrapKeyId(b.wrap)];
    const keysBefore = publicKeys(SO);
    // AUTHN recovery: new password, no passkeys or codes; the pw wrap is stale.
    SO.authnRecovery(PROOF.new);
    clearSessionKey();
    expect(await unlockAtSignIn({ user, password: NEWPW })).toBe(false);
    await expect(openDrive({ user })).rejects.toMatchObject({ reason: 'locked', ownerRecovery: true });
    const r = await restore(user, oldKit);
    expect(r.restored).toMatchObject({ escrow: false, signing: false, earlier: 0 });
    expect(loadSessionKey(user.id)).toEqual(d.dk);
    expect(SO.pwStale).toBe(false);
    expect(SO.audit.some((x) => x.action === 'drive.kit_used')).toBe(true);
    // A user on the NEW key and one still on the OLD key: both open through the escrow.
    expect(await opensUser(SO, b.wrap)).toBe('ok');
    expect(await opensUser(SO, a.wrap)).toBe('ok');
    // The new password alone unlocks now, with no kit.
    clearSessionKey();
    expect(await unlockAtSignIn({ user, password: NEWPW })).toBe(true);
    expect(loadSessionKey(user.id)).toEqual(d.dk);
    expect(await listNames(user)).toEqual(['mine.txt']);
    expect(publicKeys(SO)).toBe(keysBefore); // nothing but a rotation changes the escrow keys
  }, T);

  it('the owner’s escrowPriv deleted on the server: put back from the snapshot, then a user’s Drive opens', async () => {
    const { SO, d, a, user } = await ownerSetup();
    const text = await kitOf(user);
    SO.escrowPriv = null;
    SO.authnRecovery(PROOF.new);
    clearSessionKey();
    const r = await restore(user, text);
    expect(r.restored.escrow).toBe(true);
    const pair = await openEscrowKeyPair(d.dk, SO.escrowPriv);
    expect(sameEscrowKey(pair.publicJwk, SO.escrowPub)).toBe(true);
    expect(SO.requests.some((x) => x.path === '/api/private/drive/kit/keys' && x.body.current === PROOF.new)).toBe(true);
    expect(await opensUser(SO, a.wrap)).toBe('ok');
  }, T);

  it('a snapshot key that is not the server’s is refused, and nothing is written', async () => {
    const { SO, user } = await ownerSetup();
    const text = await kitOf(user);
    SO.escrowPub = (await createEscrowKeyPair()).publicJwk; // swapped on the server
    SO.escrowPriv = null;
    SO.authnRecovery(PROOF.new);
    clearSessionKey();
    const n = SO.requests.length;
    await expect(restore(user, text)).rejects.toMatchObject({ name: 'DriveKitError', check: 'dk' });
    expect(nonGet(SO, n)).toEqual([]);
    expect(loadSessionKey(user.id)).toBeNull();
    // The server refuses a mismatched key by itself too.
    const res = await fetch('/api/private/drive/kit/keys', { method: 'PUT', body: JSON.stringify({ escrowPriv: { pub: (await createEscrowKeyPair()).publicJwk, data: '1.a.b' }, current: PROOF.new }) });
    expect(res.status).toBe(400);
  }, T);

  it('a wrong passphrase, another owner’s kit and a user kit are refused', async () => {
    const { SO, d, user } = await ownerSetup();
    const text = await kitOf(user);
    SO.authnRecovery(PROOF.new);
    await expect(restore(user, text, 'not the passphrase')).rejects.toMatchObject({ check: 'auth' });
    const other = await sealDriveKit('owner', { v: 1, dk: b64urlFromBytes(d.dk) }, { accountId: 'owner2', origin: location.origin, passphrase: KITPASS });
    await expect(restore(user, other)).rejects.toMatchObject({ check: 'owner' });
    const userKit = await sealDriveKit('user', { v: 1, dk: b64urlFromBytes(d.dk) }, { accountId: user.id, origin: location.origin, passphrase: KITPASS });
    expect(parseDriveKit(userKit).kind).toBe('user');
    expect(JSON.parse(userKit).format).toBe(KIT_FORMATS.user);
    await expect(restore(user, userKit)).rejects.toMatchObject({ check: 'kind' });
    // Another server (origin): the tag does not verify.
    const elsewhere = await sealDriveKit('owner', { v: 1, dk: b64urlFromBytes(d.dk) }, { accountId: user.id, origin: 'https://other.example', passphrase: KITPASS });
    await expect(restore(user, elsewhere)).rejects.toMatchObject({ check: 'auth' });
    expect(loadSessionKey(user.id)).toEqual(d.dk); // untouched
  }, T);

  it('a user gets 403 on the kit and restore routes, and the client refuses them', async () => {
    const SU = use(fakeServer());
    for (const [method, path] of [['POST', '/api/private/drive/kit'], ['GET', '/api/private/drive/kit/probe'], ['PUT', '/api/private/drive/kit/keys'], ['POST', '/api/private/drive/start-over']]) {
      const r = await fetch(path, { method, ...(method === 'GET' ? {} : { body: JSON.stringify({ event: 'exported' }) }) });
      expect(r.status, path).toBe(403);
    }
    await expect(buildOwnerKit({ user: SU.user, step: { current: 'x' } })).rejects.toMatchObject({ code: 'owner_only' });
    await expect(restoreOwnerKit({ user: SU.user, text: '{}', password: 'x', step: {} })).rejects.toMatchObject({ code: 'owner_only' });
    await expect(verifyOwnerKit({ user: SU.user, text: '{}' })).rejects.toMatchObject({ code: 'owner_only' });
  });

  it('a download without the step-up is refused (and not recorded); with it, it can be downloaded again and again', async () => {
    const { SO, user } = await ownerSetup();
    await expect(buildOwnerKit({ user, passphrase: KITPASS, step: {} })).rejects.toMatchObject({ code: 'reauth_required' });
    await expect(buildOwnerKit({ user, passphrase: KITPASS, step: { current: 'wrong' } })).rejects.toMatchObject({ code: 'wrong_password' });
    expect(SO.kit).toBeNull();
    const one = await kitOf(user);
    const two = await kitOf(user);
    expect(one).not.toBe(two); // a new file each time (new salt, IV)
    expect(SO.audit.filter((x) => x.action === 'drive.kit_exported')).toHaveLength(2);
  }, T);

  it('an empty passphrase works (through Argon2id), and the page warns about it', async () => {
    const { user } = await ownerSetup();
    const text = await kitOf(user, '');
    expect(Object.keys(JSON.parse(text)).sort()).toEqual(['ct', 'format', 'iv', 'm', 'ownerId', 'salt', 't']);
    expect((await verifyOwnerKit({ user, text, passphrase: '' })).verdict).toBe('complete');
    await expect(verifyOwnerKit({ user, text, passphrase: 'x' })).resolves.toMatchObject({ verdict: 'failed' });
    const card = document.body.appendChild(kitCard({ profile: profileOf(user), drive, place: 'export' }));
    const warn = card.querySelector('#kit-pass-warn');
    expect(warn.hidden).toBe(false);
    expect(warn.textContent).toMatch(/No passphrase.*opens every user’s Drive.*offline/);
    const pass = card.querySelector('#kit-pass');
    pass.value = 'short';
    pass.dispatchEvent(new Event('input'));
    expect(warn.hidden).toBe(false);
    expect(warn.textContent).toMatch(/short passphrase/);
    pass.value = 'a much longer passphrase';
    pass.dispatchEvent(new Event('input'));
    expect(warn.hidden).toBe(true);
  }, T);
});

describe('no flow but an explicit rotation (or the first creation) changes the escrow keys', () => {
  it('owner sign-ins (also with the escrow key missing), AUTHN recovery, kit restore, restoreEscrowKey without a signing key, a user’s re-wrap', async () => {
    const { SO, user } = await ownerSetup();
    const text = await kitOf(user);
    const before = publicKeys(SO);
    const kid = await escrowKeyId(SO.escrowPub);
    const from = SO.requests.length; // after the first creation
    for (let i = 0; i < 2; i++) { clearSessionKey(); expect(await unlockAtSignIn({ user, password: PW })).toBe(true); }
    const priv = SO.escrowPriv;
    SO.escrowPriv = null;
    clearSessionKey();
    expect(await unlockAtSignIn({ user, password: PW })).toBe(true);
    const c = await openDrive({ user });
    expect(c.notice).toMatchObject({ kind: 'escrow_missing' });
    SO.escrowPriv = priv;
    // A restore never makes a signing key.
    const sp = SO.escrowSignPriv;
    SO.escrowSignPriv = null;
    const c2 = await openDrive({ user });
    await expect(c2.restoreEscrowKey({ current: PROOF.old })).rejects.toThrow(/signing key/);
    SO.escrowSignPriv = sp;
    SO.authnRecovery(PROOF.new);
    clearSessionKey();
    await restore(user, text);
    clearSessionKey();
    expect(await unlockAtSignIn({ user, password: NEWPW })).toBe(true);
    expect(publicKeys(SO)).toBe(before);
    expect(await escrowKeyId(SO.escrowPub)).toBe(kid);
    expect(SO.requests.slice(from).filter((r) => r.path === '/api/private/drive/keys' && r.body && (r.body.escrowPub || r.body.escrowSignPub || r.body.escrowPriv))).toEqual([]);
    // A user's re-wrap (to a new key the pinned signing key signed) changes nothing on the server's keys.
    const SU = use(fakeServer());
    const s1 = await createSigningKeyPair();
    const k1 = await createEscrowKeyPair();
    Object.assign(SU, { escrowPub: k1.publicJwk, escrowSignPub: s1.publicJwk, escrowSig: await endorseEscrowKey(s1.privateKey, k1.publicJwk) });
    await unlockDrive({ password: 'user password 1' });
    const k2 = await createEscrowKeyPair();
    Object.assign(SU, { escrowPub: k2.publicJwk, escrowSig: await endorseEscrowKey(s1.privateKey, k2.publicJwk) });
    const userBefore = publicKeys(SU);
    await openDrive({ user: SU.user });
    expect(escrowWrapKeyId(SU.wraps.get('escrow|escrow'))).toBe(await escrowKeyId(k2.publicJwk));
    expect(publicKeys(SU)).toBe(userBefore);
  }, T);
});

describe('the kit status and the fresh-kit notice (the Drive page)', () => {
  it('shows the version, fingerprint and dates; the notice after a rotation survives a reload and clears only after a fresh download', async () => {
    const { SO, d, user } = await ownerSetup();
    saveSessionKey(d.dk, user.id);
    const blobs = captureDownloads();
    const page = async () => {
      document.body.replaceChildren();
      const mount = document.body.appendChild(document.createElement('main'));
      const r = await startDrive(mount, { drive, profile: profileOf(user), user });
      expect(r.state).toBe('open');
      return mount;
    };
    let m = await page();
    const st = await ownerKitStatus({ user });
    expect(m.querySelector('[data-kit="escrow"]').textContent).toMatch(new RegExp(`version 1 · fingerprint ${kidFingerprint(st.kid)} · created `));
    expect(m.querySelector('[data-kit="latest"]').textContent).toBe('Latest kit downloaded: never');
    expect(m.querySelector('#kit-status-notice').dataset.state).toBe('none');
    // Download from the Drive page.
    m.querySelector('#kit-pass').value = m.querySelector('#kit-pass2').value = KITPASS;
    m.querySelector('#kit-confirm').value = PW;
    m.querySelector('#kit-download').click();
    await until(() => blobs.length === 1 && !m.querySelector('#kit-status-notice'));
    expect(JSON.parse(await blobs[0].text()).format).toBe('secbin-owner-kit/1');
    expect(m.querySelector('[data-kit="latest"]').textContent).toMatch(/^Latest kit downloaded: version 1 · /);
    m = await page();
    expect(m.querySelector('#kit-status-notice')).toBeNull();
    // A rotation: the notice appears, announced.
    m.querySelector('#drive-rotate-pw').value = PW;
    m.querySelector('#drive-rotate-btn').closest('form').dispatchEvent(new Event('submit', { cancelable: true }));
    await until(() => m.querySelector('#kit-status-notice'));
    const n = m.querySelector('#kit-status-notice');
    expect(n.getAttribute('role')).toBe('alert');
    expect(n.textContent).toContain('The escrow key was replaced. Download a fresh owner recovery kit: it holds all current and past escrow keys.');
    expect(n.textContent).toContain('Older kits still work through the Drive key');
    expect(n.querySelector('button').textContent).toBe('Download kit');
    // Survives a reload (a static notice now).
    m = await page();
    expect(m.querySelector('#kit-status-notice').getAttribute('role')).toBe('note');
    expect(m.querySelector('[data-kit="escrow"]').textContent).toMatch(/version 2/);
    // The Download kit button opens the form; a fresh download clears it.
    m.querySelector('#kit-notice-download').click();
    expect(m.querySelector('#kit-forms').open).toBe(true);
    m.querySelector('#kit-pass').value = m.querySelector('#kit-pass2').value = KITPASS;
    m.querySelector('#kit-confirm').value = PW;
    m.querySelector('#kit-download').click();
    await until(() => blobs.length === 2 && !m.querySelector('#kit-status-notice'));
    m = await page();
    expect(m.querySelector('#kit-status-notice')).toBeNull();
    expect(SO.kit.version).toBe(2);
  }, T);
});

describe('Verify kit (read-only)', () => {
  it('an older kit is "older version, still works"; a fresh one is a complete backup; no server writes but the audit', async () => {
    const { SO, d, a, user } = await ownerSetup();
    SO.probes = [{ kid: escrowWrapKeyId(a.wrap), wrap: a.wrap }];
    const old = await kitOf(user);
    await d.rotateEscrowKey({ current: PROOF.old });
    const b = { dk: createDriveKey() };
    b.wrap = await wrapEscrow(b.dk, SO.escrowPub);
    SO.escrowKids = [escrowWrapKeyId(a.wrap), escrowWrapKeyId(b.wrap)];
    SO.probes.push({ kid: escrowWrapKeyId(b.wrap), wrap: b.wrap });
    const snapshot = () => JSON.stringify([[...SO.wraps], SO.escrowPriv, SO.escrowPrivOld, SO.escrowSignPriv, SO.escrowPub, SO.kit, [...SO.nodes.keys()]]);
    const before = snapshot();
    const n = SO.requests.length;
    const r = await verifyOwnerKit({ user, text: old, passphrase: KITPASS });
    expect(r.verdict).toBe('incomplete');
    const by = Object.fromEntries(r.checks.map((c) => [c.id, c]));
    expect(by.format.status).toBe('pass');
    expect(by.auth.status).toBe('pass');
    expect(by.dk.status).toBe('pass');
    expect(by.current.status).toBe('warn');
    expect(by.past.status).toBe('pass');
    expect(by.signing.status).toBe('pass');
    expect(by.version).toMatchObject({ status: 'warn' });
    expect(by.version.detail).toMatch(/^Older version 1 \(the current one is 2\): still works through the Drive key, but download a fresh kit for a complete snapshot\./);
    expect(by.proof.status).toBe('warn'); // the new key's user opens only through the Drive key
    expect(r.fixes.join(' ')).toMatch(/Download a fresh kit/);
    // No writes but the audit record; no Drive state changed.
    expect(nonGet(SO, n).map((x) => `${x.method} ${x.path} ${x.body.event}`)).toEqual(['POST /api/private/drive/kit verified']);
    expect(snapshot()).toBe(before);
    expect(SO.audit.at(-1)).toMatchObject({ action: 'drive.kit_verified' });
    expect(SO.audit.at(-1).detail).toMatch(/verdict=incomplete/);
    // A fresh kit: a complete backup.
    const fresh = await kitOf(user);
    const f = await verifyOwnerKit({ user, text: fresh, passphrase: KITPASS });
    expect(f.verdict).toBe('complete');
    expect(f.checks.every((c) => c.status === 'pass')).toBe(true);
    expect(f.fixes).toEqual([]);
  }, T);

  it('a tampered file fails authentication, another owner’s kit the owner check, a wrong passphrase says so', async () => {
    const { d, user } = await ownerSetup();
    const text = await kitOf(user);
    const env = JSON.parse(text);
    const ct = env.ct.split('');
    ct[10] = ct[10] === 'A' ? 'B' : 'A';
    const tampered = JSON.stringify({ ...env, ct: ct.join('') });
    const t = await verifyOwnerKit({ user, text: tampered, passphrase: KITPASS });
    expect(t.verdict).toBe('failed');
    expect(t.checks.find((c) => c.id === 'auth')).toMatchObject({ status: 'fail' });
    const other = await sealDriveKit('owner', { v: 1, dk: b64urlFromBytes(d.dk) }, { accountId: 'owner2', origin: location.origin, passphrase: KITPASS });
    const o = await verifyOwnerKit({ user, text: other, passphrase: KITPASS });
    expect(o.checks[0]).toMatchObject({ id: 'format', status: 'fail', detail: 'This kit belongs to another owner account.' });
    const w = await verifyOwnerKit({ user, text, passphrase: 'wrong passphrase' });
    expect(w.checks.find((c) => c.id === 'auth').detail).toMatch(/^Wrong passphrase/);
  }, T);

  it('a snapshot missing a past key still in use is incomplete', async () => {
    const { SO, d, a, user } = await ownerSetup();
    await d.rotateEscrowKey({ current: PROOF.old });
    const kept = SO.escrowPrivOld;
    SO.escrowPrivOld = {}; // not in the Drive when this kit was made
    const text = await kitOf(user);
    SO.escrowPrivOld = kept;
    SO.escrowKids = [escrowWrapKeyId(a.wrap)];
    const r = await verifyOwnerKit({ user, text, passphrase: KITPASS });
    expect(r.verdict).toBe('incomplete');
    const past = r.checks.find((c) => c.id === 'past');
    expect(past.status).toBe('warn');
    expect(past.detail).toContain(kidFingerprint(escrowWrapKeyId(a.wrap)));
  }, T);

  it('reads only the file the owner selects: no file, no check (and a hint); the inputs are cleared after', async () => {
    const { SO, user } = await ownerSetup();
    const blobs = captureDownloads();
    const card = document.body.appendChild(kitCard({ profile: profileOf(user), drive, place: 'export' }));
    card.querySelector('#kit-pass').value = card.querySelector('#kit-pass2').value = KITPASS;
    card.querySelector('#kit-confirm').value = PW;
    card.querySelector('#kit-download').click();
    await until(() => blobs.length === 1);
    const btn = card.querySelector('#kit-verify');
    const input = card.querySelector('#kit-verify-file');
    expect(input.getAttribute('accept')).toBe('.json,application/json');
    expect(card.querySelector('label.field input#kit-verify-file').closest('label').textContent).toContain('Kit file to verify');
    expect(btn.disabled).toBe(true);
    expect(card.querySelector(`#${btn.getAttribute('aria-describedby')}`).textContent).toMatch(/Choose the kit file you saved/);
    // Nothing kept by the page to fall back on.
    const saved = await blobs[0].text();
    for (const store of [sessionStorage, localStorage]) for (let i = 0; i < store.length; i++) expect(store.getItem(store.key(i))).not.toContain(JSON.parse(saved).ct);
    const n = SO.requests.length;
    btn.disabled = false; // even if forced, no file means no check
    btn.click();
    await new Promise((r) => setTimeout(r, 50));
    expect(SO.requests.length).toBe(n);
    expect(card.querySelector('#kit-verify-out').children.length).toBe(0);
    const file = new File([saved], 'secbin-owner-kit.json', { type: 'application/json' });
    const read = vi.spyOn(file, 'text');
    pick(input, file);
    expect(btn.disabled).toBe(false);
    card.querySelector('#kit-verify-pass').value = KITPASS;
    btn.click();
    await until(() => card.querySelector('#kit-verify-verdict'));
    expect(read).toHaveBeenCalledTimes(1);
    expect(card.querySelector('#kit-verify-verdict').textContent).toBe('Complete backup');
    expect([...card.querySelectorAll('.kit-checks li')].map((li) => li.dataset.status).every((s) => s === 'pass' || s === 'skip')).toBe(true);
    expect(input.value).toBe('');
    expect(card.querySelector('#kit-verify-pass').value).toBe('');
    expect(btn.disabled).toBe(true);
  }, T);

  it('failed openings are throttled in the page', async () => {
    const { user } = await ownerSetup();
    const text = await kitOf(user);
    const card = document.body.appendChild(kitCard({ profile: profileOf(user), drive, place: 'export' }));
    for (let i = 0; i < 3; i++) {
      pick(card.querySelector('#kit-verify-file'), new File([text], 'k.json'));
      card.querySelector('#kit-verify-pass').value = 'wrong';
      card.querySelector('#kit-verify').click();
      await until(() => card.querySelector('#kit-verify-verdict'));
    }
    pick(card.querySelector('#kit-verify-file'), new File([text], 'k.json'));
    card.querySelector('#kit-verify').click();
    await until(() => /Too many failed attempts/.test(card.querySelector('#kit-verify-msg').textContent));
    expect(card.querySelector('#kit-verify').disabled).toBe(true);
  }, T);
});

describe('the same kit from the export screen and the Drive page', () => {
  for (const place of ['export', 'drive']) {
    it(`a kit from the ${place === 'export' ? 'export screen' : 'Drive page'}: restores everything after AUTHN recovery, and the archive after a start over`, async () => {
      const { SO, d, a, user } = await ownerSetup();
      saveSessionKey(d.dk, user.id);
      const blobs = captureDownloads();
      let root;
      if (place === 'export') {
        root = document.body.appendChild(kitCard({ profile: profileOf(user), drive, place: 'export' }));
      } else {
        root = document.body.appendChild(document.createElement('main'));
        await startDrive(root, { drive, profile: profileOf(user), user });
      }
      root.querySelector('#kit-pass').value = root.querySelector('#kit-pass2').value = KITPASS;
      root.querySelector('#kit-confirm').value = PW;
      root.querySelector('#kit-download').click();
      await until(() => blobs.length === 1);
      const text = await blobs[0].text();
      expect(JSON.parse(text).format).toBe('secbin-owner-kit/1');
      // AUTHN recovery, then the restore from the Drive page's unlock screen (the file picked).
      SO.authnRecovery(PROOF.new);
      clearSessionKey();
      document.body.replaceChildren();
      const mount = document.body.appendChild(document.createElement('main'));
      const started = await startDrive(mount, { drive, profile: profileOf(user), user });
      expect(started.state).toBe('locked');
      expect(mount.querySelector('#drive-owner-recovery')).not.toBeNull();
      pick(mount.querySelector('#kit-restore-file'), new File([text], 'kit.json'));
      mount.querySelector('#kit-restore-pass').value = KITPASS;
      mount.querySelector('#kit-restore-pw').value = NEWPW;
      mount.querySelector('#kit-restore').click();
      await started.unlocked;
      expect(mount.querySelector('#drive-app')).not.toBeNull();
      expect(loadSessionKey(user.id)).toEqual(d.dk);
      expect(await opensUser(SO, a.wrap)).toBe('ok');
      // Lost again, and started over: the old Drive is archived; the kit brings it back.
      SO.authnRecovery(PROOF.new2);
      clearSessionKey();
      const so = await startOverOwnerDrive({ user, confirm: 'owner', password: NEWPW2, step: { current: PROOF.new2 } });
      expect(await listNames(user)).toEqual([]);
      expect(SO.archives).toHaveLength(1);
      await seedTree(SO, so.client.dk, { 'mine.txt': enc('a new file of the same name\n') });
      expect(await opensUser(SO, a.wrap)).toBe('failed'); // the old key is in the archive only
      const r = await restore(user, text, KITPASS, NEWPW2, PROOF.new2);
      expect(r.restored).toMatchObject({ archive: 1, items: 1, earlier: 1 });
      expect((await listNames(user)).sort()).toEqual(['mine.txt', 'mine (2).txt'].sort());
      expect(SO.archives).toEqual([]);
      expect(await opensUser(SO, a.wrap)).toBe('ok'); // the user still on the old key opens again
      expect(loadSessionKey(user.id)).toEqual(so.client.dk); // the Drive keeps its (new) key
    }, T);
  }
});

describe('starting over without a kit', () => {
  it('is refused while a wrap the owner can open is left, without the typed username or the step-up', async () => {
    const { SO, user } = await ownerSetup();
    const n = SO.requests.length;
    await expect(startOverOwnerDrive({ user, confirm: 'owner', password: PW, step: { current: PROOF.old } })).rejects.toMatchObject({ reason: 'unlockable' });
    expect(SO.requests.slice(n).some((r) => r.path === '/api/private/drive/start-over')).toBe(false);
    SO.authnRecovery(PROOF.new);
    await expect(startOverOwnerDrive({ user, confirm: 'someone', password: NEWPW, step: { current: PROOF.new } })).rejects.toMatchObject({ code: 'confirm_required' });
    await expect(startOverOwnerDrive({ user, confirm: 'owner', password: NEWPW, step: {} })).rejects.toMatchObject({ code: 'reauth_required' });
    await expect(startOverOwnerDrive({ user, confirm: 'owner', password: NEWPW, step: { current: 'wrong' } })).rejects.toMatchObject({ code: 'wrong_password' });
    expect(SO.archives).toEqual([]);
  }, T);

  it('keeps the old Drive as an archive, moves each user to the new key automatically once (with the notice once), after which the owner opens it', async () => {
    const { SO, user } = await ownerSetup();
    // A user whose Drive pinned the owner's first key and signing key.
    const SU = use(fakeServer());
    Object.assign(SU, { escrowPub: SO.escrowPub, escrowSignPub: SO.escrowSignPub, escrowSig: SO.escrowSig });
    const u = await unlockDrive({ password: 'user password 1' });
    await seedTree(SU, u.dk, { 'theirs.txt': enc('the user’s file\n') });
    const userWrap = SU.wraps.get('escrow|escrow');
    const oldKid = escrowWrapKeyId(userWrap);
    const userDk = u.dk;
    use(SO);
    SO.escrowKids = [oldKid];
    const archivedIds = [...SO.nodes.keys()].filter((k) => k !== 'root');
    const chunks = [...SO.chunks.keys()];
    SO.authnRecovery(PROOF.new);
    clearSessionKey();
    const r = await startOverOwnerDrive({ user, confirm: 'owner', password: NEWPW, step: { current: PROOF.new } });
    expect(SO.escrowVer.version).toBe(2); // a rotation
    expect(SO.ownerReset).toMatchObject({ epoch: 1, kid: await escrowKeyId(SO.escrowPub) });
    expect(SO.audit.some((x) => x.action === 'drive.owner_reset')).toBe(true);
    expect([...SO.archives[0].nodes.keys()]).toEqual(archivedIds);
    expect([...SO.chunks.keys()]).toEqual(chunks); // chunks untouched
    expect(r.client.kit.state).toBe('none'); // the fresh-kit notice
    const ownerDk = r.client.dk;
    expect(await opensUser(SO, userWrap)).toBe('failed'); // not until the user's browser moves
    // The user's next unlock: moved by itself, once, with the notice once.
    use(SU);
    Object.assign(SU, { escrowPub: SO.escrowPub, escrowSignPub: SO.escrowSignPub, escrowSig: SO.escrowSig, ownerReset: SO.ownerReset });
    clearSessionKey();
    const c = await unlockDrive({ password: 'user password 1' });
    expect(c.notice).toMatchObject({ kind: 'escrow_rotated', text: 'Your administrator rotated a security key; nothing for you to do.' });
    expect(escrowWrapKeyId(SU.wraps.get('escrow|escrow'))).toBe(await escrowKeyId(SO.escrowPub));
    expect(await openEscrowPin(userDk, SU.escrowPin)).toEqual({ escrow: await escrowKeyId(SO.escrowPub), sign: await signingKeyId(SO.escrowSignPub), epoch: 1 });
    expect(SU.activity).toEqual([expect.objectContaining({ action: 'drive.escrow_rewrapped' })]);
    expect(SU.audit).toEqual([expect.objectContaining({ action: 'drive.escrow_rewrapped' })]);
    expect((await c.list()).children.map((x) => x.name)).toEqual(['theirs.txt']); // intact, usable by the user
    const again = await openDrive({ user: SU.user });
    expect(again.notice).toBeNull(); // once
    expect(SU.activity).toHaveLength(1); // never applied twice
    // The owner opens it through the escrow now.
    use(SO);
    saveSessionKey(ownerDk, user.id);
    const moved = SU.wraps.get('escrow|escrow');
    expect(await unlockWithEscrow((await openEscrowKeyPair(ownerDk, SO.escrowPriv)).privateKey, moved)).toEqual(userDk);
    expect(await opensUser(SO, moved)).toBe('ok');
  }, T);

  it('any other unsigned change keeps the notice: no reset, a skipped epoch, a key the reset’s signing key did not sign, the same reset twice', async () => {
    const SU = use(fakeServer());
    const s1 = await createSigningKeyPair();
    const k1 = await createEscrowKeyPair();
    Object.assign(SU, { escrowPub: k1.publicJwk, escrowSignPub: s1.publicJwk, escrowSig: await endorseEscrowKey(s1.privateKey, k1.publicJwk) });
    const u = await unlockDrive({ password: 'user password 1' });
    const wrap0 = SU.wraps.get('escrow|escrow');
    const rotateTo = async ({ epoch, signedBy, resetSign }) => {
      const k = await createEscrowKeyPair();
      const s = signedBy ?? await createSigningKeyPair();
      Object.assign(SU, { escrowPub: k.publicJwk, escrowSignPub: s.publicJwk, escrowSig: await endorseEscrowKey(s.privateKey, k.publicJwk) });
      SU.ownerReset = epoch ? { epoch, kid: await escrowKeyId(k.publicJwk), signPub: (resetSign ?? s).publicJwk, at: 1 } : null;
    };
    const expectNotice = async () => {
      clearSessionKey();
      const c = await unlockDrive({ password: 'user password 1' });
      expect(c.notice).toMatchObject({ kind: 'escrow_changed' });
      expect(SU.wraps.get('escrow|escrow')).toEqual(wrap0);
    };
    await rotateTo({ epoch: 0 }); // unsigned, no reset
    await expectNotice();
    await rotateTo({ epoch: 2 }); // skips a step (pinned: none)
    await expectNotice();
    await rotateTo({ epoch: 1, resetSign: await createSigningKeyPair() }); // not signed by the reset's signing key
    await expectNotice();
    // A real reset: applied.
    await rotateTo({ epoch: 1 });
    clearSessionKey();
    expect((await unlockDrive({ password: 'user password 1' })).notice).toMatchObject({ kind: 'escrow_rotated' });
    const moved = SU.wraps.get('escrow|escrow');
    // The same epoch again with another unsigned key: the notice, no re-wrap.
    await rotateTo({ epoch: 1 });
    clearSessionKey();
    const c = await unlockDrive({ password: 'user password 1' });
    expect(c.notice).toMatchObject({ kind: 'escrow_changed' });
    expect(SU.wraps.get('escrow|escrow')).toEqual(moved);
    expect(SU.activity).toHaveLength(1);
    void u;
  }, T);

  it('the Drive page: the unlock screen offers the kit and starting over (typed username); the archive can be deleted (typed username, step-up)', async () => {
    const { SO, user } = await ownerSetup();
    SO.authnRecovery(PROOF.new);
    clearSessionKey();
    const mount = document.body.appendChild(document.createElement('main'));
    const started = await startDrive(mount, { drive, profile: profileOf(user), user });
    const box = mount.querySelector('#drive-owner-recovery');
    expect(box.querySelector('#kit-restore-file')).not.toBeNull();
    expect(box.textContent).toMatch(/kept as an archive, sealed under the old Drive key/);
    expect(box.textContent).toMatch(/comes back if a recovery kit for it is ever found/);
    mount.querySelector('#drive-reset-user').value = 'not me';
    mount.querySelector('#drive-reset-pw').value = NEWPW;
    mount.querySelector('#drive-reset-form').dispatchEvent(new Event('submit', { cancelable: true }));
    await until(() => !mount.querySelector('#drive-reset-msg').hidden);
    expect(mount.querySelector('#drive-reset-msg').textContent).toMatch(/Type your username/);
    expect(SO.archives).toEqual([]);
    mount.querySelector('#drive-reset-user').value = 'owner';
    mount.querySelector('#drive-reset-pw').value = NEWPW;
    mount.querySelector('#drive-reset-form').dispatchEvent(new Event('submit', { cancelable: true }));
    await started.unlocked;
    expect(SO.archives).toHaveLength(1);
    expect(mount.querySelector('#kit-status-notice').getAttribute('role')).toBe('alert');
    const del = mount.querySelector('#drive-archive-delete-1');
    expect(mount.querySelector('#drive-archive').textContent).toMatch(/could no longer bring them back/);
    mount.querySelector('#drive-archive-user-1').value = 'owner';
    del.closest('form').dispatchEvent(new Event('submit', { cancelable: true }));
    await until(() => !mount.querySelector('#drive-archive-msg-1').hidden);
    expect(SO.archives).toHaveLength(1); // no password: refused
    mount.querySelector('#drive-archive-user-1').value = 'owner';
    mount.querySelector('#drive-archive-pw-1').value = NEWPW;
    del.closest('form').dispatchEvent(new Event('submit', { cancelable: true }));
    await until(() => !SO.archives.length);
    expect(SO.audit.some((x) => x.action === 'drive.archive_deleted')).toBe(true);
    void DriveLocked; void sealEscrowPin;
  }, T);
});

function fakeFile(name, bytes, type = 'text/plain') {
  return { name, size: bytes.length, type, lastModified: 1700000000000, slice: (a, b) => ({ arrayBuffer: async () => bytes.slice(a, b).buffer }) };
}
const CODE = 'ABCD-EFGH-JKMN-PQRS';
const PRF = new Uint8Array(32).fill(7);
/** A user's Drive (server SU) set up by the user, with a recovery-code and a passkey wrap and a file, on the owner's escrow key. */
async function userWithDrive(SO) {
  const SU = use(fakeServer());
  Object.assign(SU, { escrowPub: SO.escrowPub, escrowSignPub: SO.escrowSignPub, escrowSig: SO.escrowSig });
  const c = await unlockDrive({ password: 'user password 1' });
  const dk = c.dk.slice();
  const rec = await wrapRecovery(dk, CODE);
  SU.wraps.set(`recovery|${rec.ref}`, rec);
  const pk = await wrapPrf(dk, PRF, 'cred-1');
  SU.wraps.set('passkey|cred-1', pk);
  await seedTree(SU, dk, { 'theirs.txt': enc('the user’s file\n') });
  return { SU, dk };
}
/** What the real server does with the owner's PUT /api/private/admin/drive/keys/<id> (the fake records it). */
function applyAdminKeys(SO, SU) {
  const { body } = SO.adminKeys.at(-1);
  SU.driveSalt = body.driveSalt;
  for (const w of body.set) SU.wraps.set(`${w.kind}|${w.ref}`, w);
  SU.pwStale = false;
}
const readFile = async (c, name) => {
  const n = (await c.list()).children.find((x) => x.name === name);
  return new TextDecoder().decode(new Uint8Array(await (await (await c.download(n.id)).blob()).arrayBuffer()));
};

describe('a password change or an admin reset keeps the same Drive key', () => {
  it('the user’s own change, from a tab without the key: the old password (or the passkey’s PRF) opens it, the new pw wrap is of the same DK', async () => {
    const { SO } = await ownerSetup();
    const ownerEscrow = (await openEscrowKeyPair(loadSessionKey(SO.user.id), SO.escrowPriv)).privateKey;
    const { SU, dk } = await userWithDrive(SO);
    for (const [how, opts] of [['old password', { oldPassword: 'user password 1' }], ['passkey PRF', { oldPassword: '', prfOutput: PRF, credentialId: 'cred-1' }]]) {
      const next = `user password after ${how}`;
      SU.pwStale = true; // what the server marks on the change
      clearSessionKey(); // the tab lacks DK
      expect(await updatePasswordWrap({ userId: SU.user.id, newPassword: next, ...opts }), how).toBe('ok');
      const wraps = [...SU.wraps.values()];
      expect(await unlockWithPassword(next, SU.driveSalt, wraps)).toEqual(dk);
      expect(await unlockWithRecovery(CODE, wraps)).toEqual(dk);
      expect(await unlockWithPrf(PRF, 'cred-1', wraps)).toEqual(dk);
      expect(await unlockWithEscrow(ownerEscrow, SU.wraps.get('escrow|escrow'))).toEqual(dk);
      expect(SU.kcv).toBe(await keyCheckValue(dk));
      expect(await readFile(await openDrive({ user: SU.user }), 'theirs.txt')).toBe('the user’s file\n');
      // Continue from the password just set.
      opts.oldPassword = opts.oldPassword ? next : '';
    }
    // A pw wrap of another key is refused (even when no step-up is needed).
    SU.pwStale = true;
    const other = createDriveKey();
    const r = await fetch('/api/private/drive/keys', { method: 'PUT', body: JSON.stringify({ driveSalt: SALT, set: [(await (await import('../public/js/drivekeys.js')).wrapPassword(other, 'x')).wrap], kcv: await keyCheckValue(other) }) });
    expect(r.status).toBe(409);
  }, T);

  it('an admin reset with the owner’s Drive unlocked: the same DK, the new password opens the same files; without it, the DK is untouched and a later reset fixes the pw wrap', async () => {
    const { SO, d } = await ownerSetup();
    const { SU, dk } = await userWithDrive(SO);
    use(SO);
    SO.userWraps = [...SU.wraps.values()];
    saveSessionKey(d.dk, SO.user.id);
    expect(await escrowPasswordReset({ ownerId: SO.user.id, userId: SU.user.id, newPassword: 'reset by the owner 1' })).toBe('ok');
    expect(SO.adminKeys.at(-1).body.kcv).toBe(await keyCheckValue(dk));
    applyAdminKeys(SO, SU);
    use(SU);
    clearSessionKey();
    expect(await unlockAtSignIn({ user: SU.user, password: 'reset by the owner 1' })).toBe(true);
    expect(loadSessionKey(SU.user.id)).toEqual(dk);
    expect(await readFile(await openDrive({ user: SU.user }), 'theirs.txt')).toBe('the user’s file\n');
    // A reset without the owner's Drive: the server drops the old pw wrap (another wrap remains); the DK is untouched.
    use(SO);
    clearSessionKey();
    expect(await escrowPasswordReset({ ownerId: SO.user.id, userId: SU.user.id, newPassword: 'reset by the owner 2' })).toBe('locked');
    SU.wraps.delete('pw|pw');
    SU.pwStale = true;
    use(SU);
    expect(await unlockWithRecovery(CODE, [...SU.wraps.values()])).toEqual(dk);
    // Later, with the owner's Drive unlocked, a reset fixes the pw wrap.
    use(SO);
    SO.userWraps = [...SU.wraps.values()];
    saveSessionKey(d.dk, SO.user.id);
    expect(await escrowPasswordReset({ ownerId: SO.user.id, userId: SU.user.id, newPassword: 'reset by the owner 3' })).toBe('ok');
    applyAdminKeys(SO, SU);
    expect(await unlockWithPassword('reset by the owner 3', SU.driveSalt, [...SU.wraps.values()])).toEqual(dk);
    expect(await unlockWithEscrow((await openEscrowKeyPair(d.dk, SO.escrowPriv)).privateKey, SU.wraps.get('escrow|escrow'))).toEqual(dk);
  }, T);
});

describe('the owner sets up a new user’s Drive', () => {
  it('created with the pw and escrow wraps; the owner puts a file in it before the first sign-in; the user opens it with the starting password and sees it', async () => {
    const { SO, d } = await ownerSetup();
    saveSessionKey(d.dk, SO.user.id);
    expect(await ownerSetsUpUserDrive({ ownerId: SO.user.id, userId: 'u1', password: 'starting password 1' })).toBe('created');
    const made = SO.userDrives.u1;
    expect(made.wraps.map((w) => w.kind).sort()).toEqual(['escrow', 'pw']);
    expect(escrowWrapKeyId(made.wraps.find((w) => w.kind === 'escrow'))).toBe(await escrowKeyId(SO.escrowPub));
    expect(loadSessionKey('u1')).toBeNull(); // nothing of the user's key kept here
    // The user's Drive on the server, as the owner created it.
    const SU = use(fakeServer());
    Object.assign(SU, { escrowPub: SO.escrowPub, escrowSignPub: SO.escrowSignPub, escrowSig: SO.escrowSig, driveSalt: made.driveSalt, escrowPin: made.escrowPin, kcv: made.kcv });
    for (const w of made.wraps) SU.wraps.set(`${w.kind}|${w.ref}`, w);
    // The owner, acting as the user before they ever signed in: opens it through the escrow and adds a file.
    Object.assign(SU, { impersonatedBy: 'owner', ownerEscrowPriv: SO.escrowPriv, escrowPrivOld: {} });
    const imp = await openDrive({ user: { id: 'u1', role: 'user', impersonating: true } });
    await imp.upload('root', fakeFile('welcome.txt', enc('from the owner\n')));
    SU.impersonatedBy = null;
    clearSessionKey();
    expect(await unlockAtSignIn({ user: SU.user, password: 'starting password 1' })).toBe(true);
    const c = await openDrive({ user: SU.user });
    expect(c.notice).toBeNull(); // the pin the owner sealed is the key's
    expect(await readFile(c, 'welcome.txt')).toBe('from the owner\n');
    // The owner opens it through the escrow.
    expect(await unlockWithEscrow((await openEscrowKeyPair(d.dk, SO.escrowPriv)).privateKey, SU.wraps.get('escrow|escrow'))).toEqual(c.dk);
  }, T);

  it('deferred to the first sign-in when the owner’s Drive is locked or there is no escrow key', async () => {
    const { SO, d } = await ownerSetup();
    clearSessionKey();
    expect(await ownerSetsUpUserDrive({ ownerId: SO.user.id, userId: 'u2', password: 'p' })).toBe('locked');
    saveSessionKey(d.dk, SO.user.id);
    const priv = SO.escrowPriv;
    SO.escrowPriv = null;
    expect(await ownerSetsUpUserDrive({ ownerId: SO.user.id, userId: 'u2', password: 'p' })).toBe('no_escrow');
    SO.escrowPriv = priv;
    SO.escrowSig = await endorseEscrowKey((await createSigningKeyPair()).privateKey, SO.escrowPub); // not the signing key's
    expect(await ownerSetsUpUserDrive({ ownerId: SO.user.id, userId: 'u2', password: 'p' })).toBe('mismatch');
    expect(SO.userDrives.u2).toBeUndefined();
  }, T);
});
