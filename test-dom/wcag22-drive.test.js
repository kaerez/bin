// wcag22-drive.test.js (DOM) — the WCAG 2.2 fixes to the Drive states from the
// owner recovery kit and starting over (docs/WCAG22.md), with the real client
// (public/js/driveclient.js) and pages (drive-app.js, drivekit-ui.js) against
// the in-memory server (drive-fake-server.js):
//   4.1.3  each kit form's message sits in a status line that is in the page
//          before the message; the Drive page's status line stays in place
//          across the unlock screen and the Drive, and says the automatic
//          move to a reset's escrow key (the notice itself is content);
//   1.3.1 / 4.1.2  the kit card is a section named by its heading; the
//          passphrase warning describes the passphrase field while it shows;
//   3.3.1  starting over marks the field at fault invalid, described by the error;
//   2.4.3  focus after a start over, a restore and an archive deletion goes to a
//          heading, never to the page.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as drive from '../public/js/driveclient.js';
import { unlockDrive, buildOwnerKit } from '../public/js/driveclient.js';
import { createEscrowKeyPair, createSigningKeyPair, endorseEscrowKey, escrowKeyId, clearSessionKey, releaseSessionKeys } from '../public/js/drivekeys.js';
import { stretch } from '../public/js/pwauth.js';
import { startDrive } from '../public/dashboard/js/drive-app.js';
import { kitCard, resetThrottle } from '../public/dashboard/js/drivekit-ui.js';
import { fakeServer, seedTree } from './drive-fake-server.js';

const PW = 'owner password 1';
const NEWPW = 'owner password after recovery';
const SALT = 'AAAAAAAAAAAAAAAAAAAAAA';
const enc = (s) => new TextEncoder().encode(s);
const T = 180000;
const use = (srv) => { globalThis.fetch = srv.fetch; return srv; };
const until = async (fn, ms = 60000) => {
  const t0 = Date.now();
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 20));
  }
};
const PROOF = {};
beforeEach(async () => {
  clearSessionKey(); releaseSessionKeys(); clearSessionKey(); resetThrottle();
  document.body.replaceChildren();
  PROOF.old ??= await stretch(PW, SALT, 3);
  PROOF.new ??= await stretch(NEWPW, SALT, 3);
});
afterEach(() => { vi.restoreAllMocks(); });

const profileOf = (user) => ({ user: { ...user }, limits: {}, caps: { driveEnabled: true } });
/** The owner (escrow key v1, a file in their Drive). */
async function ownerSetup() {
  const SO = use(fakeServer({ role: 'owner' }));
  SO.proof = PROOF.old;
  const d = await unlockDrive({ password: PW });
  await seedTree(SO, d.dk, { 'mine.txt': enc('the owner’s file\n') });
  return { SO, d, user: SO.user };
}
/** The Drive page's mount, with its status line as the static page has it. */
function driveMount() {
  const mount = document.body.appendChild(document.createElement('div'));
  mount.id = 'drive-root';
  mount.appendChild(Object.assign(document.createElement('p'), { className: 'msg', textContent: 'Opening your Drive…' })).setAttribute('role', 'status');
  return mount;
}
const submit = (form) => form.dispatchEvent(new Event('submit', { cancelable: true }));

describe('the kit card', () => {
  it('is a section named by its heading; every form\'s message is inside a status line that is there before the message', async () => {
    const { user } = await ownerSetup();
    const card = document.body.appendChild(kitCard({ profile: profileOf(user), drive, place: 'export' }));
    expect(card.tagName).toBe('SECTION');
    expect(document.getElementById(card.getAttribute('aria-labelledby')).textContent).toBe('Owner recovery kit');
    for (const id of ['kit-download-msg', 'kit-verify-msg', 'kit-restore-msg']) {
      const msg = card.querySelector(`#${id}`);
      expect(msg.hidden).toBe(true);
      expect(msg.hasAttribute('role')).toBe(false);
      expect(msg.parentElement.getAttribute('role')).toBe('status');
      expect(msg.parentElement.hidden).toBe(false);
    }
    // The download's message appears inside the same, already present, status line.
    const live = card.querySelector('#kit-download-msg').parentElement;
    card.querySelector('#kit-pass').value = 'one';
    card.querySelector('#kit-pass2').value = 'two';
    card.querySelector('#kit-download').click();
    await until(() => !card.querySelector('#kit-download-msg').hidden);
    expect(card.querySelector('#kit-download-msg').textContent).toBe('The two passphrases differ.');
    expect(card.querySelector('#kit-download-msg').parentElement).toBe(live);
  }, T);

  it('the passphrase warning describes the passphrase field while it shows, and only then', async () => {
    const { user } = await ownerSetup();
    const card = document.body.appendChild(kitCard({ profile: profileOf(user), drive, place: 'export' }));
    const pass = card.querySelector('#kit-pass');
    const warn = card.querySelector('#kit-pass-warn');
    expect(warn.hidden).toBe(false);
    expect(pass.getAttribute('aria-describedby')).toBe('kit-pass-warn');
    pass.value = 'a much longer passphrase';
    pass.dispatchEvent(new Event('input'));
    expect(warn.hidden).toBe(true);
    expect(pass.hasAttribute('aria-describedby')).toBe(false);
    pass.value = 'short';
    pass.dispatchEvent(new Event('input'));
    expect(pass.getAttribute('aria-describedby')).toBe('kit-pass-warn');
  }, T);
});

describe('the Drive page: unlock screen, start over, the archive', () => {
  it('the status line stays in place and says the screen; start over marks the field at fault; focus goes to the folder heading, then after deleting the archive too', async () => {
    const { SO, user } = await ownerSetup();
    SO.authnRecovery(PROOF.new);
    clearSessionKey();
    const mount = driveMount();
    const status = mount.firstChild;
    const started = await startDrive(mount, { drive, profile: profileOf(user), user });
    expect(started.state).toBe('locked');
    expect(mount.firstChild).toBe(status); // the same node, never removed
    expect(status.getAttribute('role')).toBe('status');
    expect(status.textContent).toBe('Unlock your Drive');
    expect(status.className).toBe('sr-only');
    const who = mount.querySelector('#drive-reset-user');
    const pw = mount.querySelector('#drive-reset-pw');
    who.value = 'not me';
    pw.value = NEWPW;
    submit(mount.querySelector('#drive-reset-form'));
    await until(() => !mount.querySelector('#drive-reset-msg').hidden);
    expect(who.getAttribute('aria-invalid')).toBe('true');
    expect(who.getAttribute('aria-describedby')).toBe('drive-reset-msg');
    expect(document.activeElement).toBe(who);
    who.value = 'owner';
    pw.value = '';
    submit(mount.querySelector('#drive-reset-form'));
    await until(() => /account password/.test(mount.querySelector('#drive-reset-msg').textContent));
    expect(who.hasAttribute('aria-invalid')).toBe(false);
    expect(pw.getAttribute('aria-invalid')).toBe('true');
    expect(pw.getAttribute('aria-describedby')).toBe('drive-reset-msg');
    expect(document.activeElement).toBe(pw);
    pw.value = NEWPW;
    mount.querySelector('#drive-reset-btn').focus();
    submit(mount.querySelector('#drive-reset-form'));
    // As in Chromium: the button is disabled while it runs, so focus falls to the page.
    expect(mount.querySelector('#drive-reset-btn').disabled).toBe(true);
    document.activeElement.blur();
    const app = await started.unlocked;
    await app.ready;
    expect(mount.firstChild).toBe(status);
    expect(mount.querySelector('#kit-status-notice').getAttribute('role')).toBe('alert');
    expect(document.activeElement.id).toBe('drive-pane-title');
    // The archive: a section named by its heading; its delete button is described by what it holds.
    const box = mount.querySelector('#drive-archive');
    expect(box.tagName).toBe('SECTION');
    expect(document.getElementById(box.getAttribute('aria-labelledby')).textContent).toBe('Your Drive from before you started over');
    const del = mount.querySelector('#drive-archive-delete-1');
    expect(document.getElementById(del.getAttribute('aria-describedby')).textContent).toMatch(/^Archived .*1 item/);
    const aw = mount.querySelector('#drive-archive-user-1');
    aw.value = 'nobody';
    submit(del.closest('form'));
    await until(() => !mount.querySelector('#drive-archive-msg-1').hidden);
    expect(aw.getAttribute('aria-invalid')).toBe('true');
    expect(aw.getAttribute('aria-describedby')).toBe('drive-archive-msg-1');
    aw.value = 'owner';
    mount.querySelector('#drive-archive-pw-1').value = NEWPW;
    del.focus();
    submit(del.closest('form'));
    await until(() => !mount.querySelector('#drive-archive'));
    expect(document.activeElement.id).toBe('drive-pane-title');
  }, T);

  it('a restore from the kit on the Drive page mounts it again with focus on the folder heading', async () => {
    const { user } = await ownerSetup();
    const text = (await buildOwnerKit({ user, passphrase: '', step: { current: PROOF.old } })).text;
    const mount = driveMount();
    const started = await startDrive(mount, { drive, profile: profileOf(user), user });
    await started.app.ready;
    const status = mount.firstChild;
    const file = mount.querySelector('#kit-restore-file');
    let files = [{ name: 'kit.json', text: async () => text }];
    Object.defineProperty(file, 'files', { configurable: true, get: () => files });
    Object.defineProperty(file, 'value', { configurable: true, get: () => (files.length ? 'C:\\fakepath\\kit.json' : ''), set: (v) => { if (v === '') files = []; } });
    file.dispatchEvent(new Event('change', { bubbles: true }));
    mount.querySelector('#kit-restore-pw').value = PW;
    const go = mount.querySelector('#kit-restore');
    go.focus();
    go.click();
    go.blur(); // as in Chromium, where the disabled button loses focus
    await until(() => document.activeElement && document.activeElement.id === 'drive-pane-title', 120000);
    expect(mount.firstChild).toBe(status);
    expect(mount.querySelectorAll('#drive-app')).toHaveLength(1);
  }, T);

  it('a user\'s Drive moved to a reset\'s escrow key by itself: said by the page\'s status line; the notice is content', async () => {
    const SU = use(fakeServer());
    const s1 = await createSigningKeyPair();
    const k1 = await createEscrowKeyPair();
    Object.assign(SU, { escrowPub: k1.publicJwk, escrowSignPub: s1.publicJwk, escrowSig: await endorseEscrowKey(s1.privateKey, k1.publicJwk) });
    await unlockDrive({ password: 'user password 1' });
    const k2 = await createEscrowKeyPair();
    const s2 = await createSigningKeyPair();
    Object.assign(SU, { escrowPub: k2.publicJwk, escrowSignPub: s2.publicJwk, escrowSig: await endorseEscrowKey(s2.privateKey, k2.publicJwk) });
    SU.ownerReset = { epoch: 1, kid: await escrowKeyId(k2.publicJwk), signPub: s2.publicJwk, at: 1 };
    clearSessionKey();
    const mount = driveMount();
    const status = mount.firstChild;
    const started = await startDrive(mount, { drive, profile: profileOf(SU.user), user: SU.user });
    expect(started.state).toBe('locked');
    mount.querySelector('#drive-unlock-pw').value = 'user password 1';
    mount.querySelector('#drive-unlock-btn').focus();
    mount.querySelector('#drive-unlock-btn').click();
    document.activeElement.blur(); // as in Chromium, where the busy button loses focus
    const app = await started.unlocked;
    await app.ready;
    const notice = mount.querySelector('#drive-escrow-rotated');
    expect(notice.hasAttribute('role')).toBe(false);
    expect(mount.firstChild).toBe(status);
    expect(status.textContent).toBe('Your administrator rotated a security key; nothing for you to do.');
    expect(document.activeElement.id).toBe('drive-pane-title');
  }, T);
});
