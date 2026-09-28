// drive-kits.test.js — the pages of the Drive key model v2 (docs/DRIVE.md §3,
// §3.1) with the real modules against the in-memory server
// (drive-fake-server.js): the personal kit card on Account (download with the
// step-up, verify a selected file with a date — read-only, only check values
// sent; no restore, for a user or the owner; a note instead while the owner
// acts as the user), Admin
// → Security → Keys (the keyring with its plain-language help, Show with the
// step-up and hidden again, a generated sub-MEK used or thrown away, entering
// one by hand, rotation, a re-seal with its progress, the key kit download
// and verify, a restore from a user's personal kit), and the Drive keys card of Import / export (the parts, the
// user picker with search, select all / deselect all and id lists, the
// masked view, the sealed file, an import previewed then applied).
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { fakeServer, seedTree } from './drive-fake-server.js';
import * as drive from '../public/js/driveclient.js';
import { clearSessionKey } from '../public/js/drivekeys.js';
import { parseDriveKit, openDriveKit, sealDriveKit } from '../public/js/drivekit.js';
import { openExport, sealExport } from '../public/js/exportcrypt.js';
import { resetThrottle } from '../public/dashboard/js/kit-ui.js';
import { b64urlFromBytes } from '../public/js/bytes.js';

// "Confirm it's you" (confirm.js): the typed password becomes a { current } proof; an empty field is refused.
vi.mock('../public/dashboard/js/confirm.js', () => ({
  confirmStep: async (input) => {
    const v = input.value;
    input.value = '';
    if (!v) throw new Error('Enter your current password.');
    return { current: `proof:${v}` };
  },
  canUsePasskey: async () => false,
  confirmLabel: (t) => t,
}));

const until = async (fn, ms = 20000) => {
  const t0 = Date.now();
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 10));
  }
};
const $ = (s) => document.querySelector(s);
const button = (root, text) => [...root.querySelectorAll('button')].find((b) => b.textContent.trim() === text);
const pick = (input, files) => { Object.defineProperty(input, 'files', { configurable: true, get: () => files }); input.dispatchEvent(new Event('change')); };
/** What saveText / download saves: the Blob and the file name. */
function captureSaves() {
  const saved = [];
  let last = null;
  vi.spyOn(URL, 'createObjectURL').mockImplementation((b) => { last = b; return 'blob:x'; });
  vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function click() { saved.push({ blob: last, name: this.download }); });
  return saved;
}
function mount(el) {
  const main = document.createElement('main');
  main.id = 'main';
  main.appendChild(el);
  document.body.replaceChildren(main);
  return el;
}

let S;
beforeEach(() => { document.body.replaceChildren(); clearSessionKey(); resetThrottle(); });
afterEach(() => { vi.restoreAllMocks(); });

describe('Account → Drive personal kit', () => {
  const PROFILE = () => ({ user: S.user, caps: { driveEnabled: true } });
  const confirm = async (input) => {
    const v = input.value;
    input.value = '';
    if (!v) throw new Error('Enter your current password.');
    return { current: v };
  };

  it('download (the step-up), verify the selected file with a date — the kit file itself is never sent', async () => {
    S = fakeServer();
    S.proof = 'account-pw';
    globalThis.fetch = S.fetch;
    await seedTree(S, { 'a.txt': new TextEncoder().encode('a') });
    const { personalKitCard } = await import('../public/dashboard/js/userkit.js');
    const card = mount(personalKitCard({ profile: PROFILE(), drive, confirm }));
    expect(card.querySelector('.subtitle').textContent).toMatch(/store it offline/);
    const saves = captureSaves();
    // Without the password: refused, nothing downloaded.
    $('#ukit-download').click();
    await until(() => /password/.test($('#ukit-download-msg').textContent) && !$('#ukit-download').disabled);
    expect(saves).toHaveLength(0);
    // An empty passphrase is allowed, with the warning.
    expect($('#ukit-pass-warn').textContent).toMatch(/No passphrase/);
    $('#ukit-pass').value = 'kit passphrase 123';
    $('#ukit-pass').dispatchEvent(new Event('input'));
    $('#ukit-pass2').value = 'kit passphrase 123';
    $('#ukit-confirm').value = 'account-pw';
    $('#ukit-download').click();
    await until(() => saves.length === 1, 60000);
    expect(saves[0].name).toMatch(/^secbin-personal-kit-alice-/);
    const text = await saves[0].blob.text();
    const payload = await openDriveKit(parseDriveKit(text), { kind: 'user', accountId: S.user.id, origin: location.origin, passphrase: 'kit passphrase 123' });
    expect(payload).toMatchObject({ id: S.user.id, username: 'alice', userSalt: S.salt });
    expect($('#ukit-download-msg').textContent).toMatch(/1 key/);
    // Verify: the selected file, read-only; only check values go to the server.
    expect($('#ukit-verify').disabled).toBe(true);
    pick($('#ukit-verify-file'), [new File([text], 'kit.json', { type: 'application/json' })]);
    expect($('#ukit-verify').disabled).toBe(false);
    $('#ukit-verify-pass').value = 'kit passphrase 123';
    expect($('#ukit-verify-date').type).toBe('date');
    const n0 = S.requests.length;
    $('#ukit-verify').click();
    await until(() => $('#ukit-verify-verdict'), 60000);
    expect($('#ukit-verify-verdict').dataset.verdict).toBe('complete');
    expect(document.activeElement).toBe($('#ukit-verify-verdict'));
    const sent = S.requests.slice(n0);
    expect(sent.map((r) => r.path)).toEqual(['/api/private/drive/kit/verify']);
    expect(JSON.stringify(sent[0].body)).not.toContain(S.salt);
    expect(JSON.stringify(sent[0].body)).not.toContain(payload.keks[0].kek);
    expect($('#ukit-verify-pass').value).toBe(''); // cleared after use
    // Nothing on this card restores (only the owner does, from Admin → Security → Keys).
    expect(S.requests.some((r) => /\/kit\/(restore|items)/.test(r.path))).toBe(false);
  }, 120000);

  // Only the owner restores from a personal kit (Admin → Security → Keys): the Account page is the same for everyone.
  for (const role of ['user', 'owner']) {
    it(`no Restore section, for ${role === 'owner' ? 'the owner’s own Account page' : 'a user'}: only Download and Verify, and the text does not offer one`, async () => {
      S = fakeServer({ role });
      globalThis.fetch = S.fetch;
      await S.ready;
      const { personalKitCard } = await import('../public/dashboard/js/userkit.js');
      const card = mount(personalKitCard({ profile: { user: S.user, caps: { driveEnabled: true } }, drive, confirm }));
      expect([...card.querySelectorAll('legend')].map((l) => l.textContent)).toEqual(['Download', 'Verify']);
      for (const id of ['#ukit-restore-set', '#ukit-restore', '#ukit-restore-file', '#ukit-restore-pass', '#ukit-restore-confirm', '#ukit-restore-msg']) expect(card.querySelector(id), id).toBeNull();
      expect([...card.querySelectorAll('button')].map((b) => b.textContent)).toEqual(['Download personal kit', 'Verify kit']);
      expect(card.textContent).not.toMatch(/restor|puts? back/i);
      expect($('#ukit-download')).not.toBeNull();
      expect($('#ukit-verify-file')).not.toBeNull();
    });
  }

  it('while the owner acts as the user: a note, no kit', async () => {
    S = fakeServer();
    globalThis.fetch = S.fetch;
    const { personalKitCard } = await import('../public/dashboard/js/userkit.js');
    const card = mount(personalKitCard({ profile: { ...PROFILE(), impersonatedBy: 'owner' }, drive, confirm }));
    expect(card.textContent).toMatch(/the user’s own.*key kit/);
    expect(card.querySelector('#ukit-download')).toBeNull();
  });
});

describe('Admin → Security → Keys', () => {
  const profile = () => ({ user: S.user });
  async function open() {
    S = fakeServer({ role: 'owner' });
    globalThis.fetch = S.fetch;
    await S.ready;
    const { keysSection } = await import('../public/dashboard/js/admin-keys.js');
    const el = mount(keysSection({ profile: profile() }));
    await until(() => $('#keys-subs-table tbody tr'));
    return el;
  }

  it('shows the keyring with plain-language help on every action; Show needs the step-up and hides again', async () => {
    const el = await open();
    expect(el.querySelector('#keys-ring .subtitle').textContent).toMatch(/server can open every Drive/);
    expect($('#keys-root-help').textContent).toMatch(/re-seals every item/);
    expect($('#keys-add-help').textContent).toMatch(/current one from the date/);
    expect($('#keys-rotate-help').textContent).toMatch(/new data uses a new sub-MEK/);
    const rows = [...document.querySelectorAll('#keys-subs-table tbody tr')];
    expect(rows).toHaveLength(1);
    expect(rows[0].dataset.status).toBe('current');
    for (const b of rows[0].querySelectorAll('button')) expect(b.title.length).toBeGreaterThan(20); // each action says what it does
    expect($('#keys-kit-notice').textContent).toMatch(/No key kit has been downloaded yet/);
    // Show: refused without the password, then shown and hidden again.
    button($('#keys-root'), 'Show').click();
    await until(() => !$('#keys-msg').hidden);
    expect($('#keys-shown').textContent).toBe('');
    $('#keys-confirm').value = 'pw';
    button($('#keys-root'), 'Show').click();
    await until(() => $('#keys-shown .key-value'));
    expect($('#keys-shown .key-value').textContent).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect($('#keys-shown').textContent).toMatch(/hidden again in 60 seconds/);
    button($('#keys-shown'), 'Hide').click();
    expect($('#keys-shown .key-value')).toBeNull();
    expect(S.requests.find((r) => r.path === '/api/private/admin/keys/root/show' && r.body.current).body.current).toBe('proof:pw');
  });

  it('a generated sub-MEK is used only on “Use this key” (another can be generated); a manual key with its help; rotation', async () => {
    await open();
    $('#keys-confirm').value = 'pw';
    button(document, 'Rotate now…').click();
    await until(() => $('.key-chooser'));
    expect($('#sub-manual-help').textContent).toMatch(/openssl rand -base64 32.*RandomNumberGenerator.*not Get-Random/);
    button($('.key-chooser'), 'Generate securely').click();
    await until(() => button($('.key-chooser'), 'Use this key'));
    const first = $('.key-chooser .key-value').textContent;
    $('#keys-confirm').value = 'pw';
    button($('.key-chooser'), 'Generate another').click();
    await until(() => $('.key-chooser .key-value') && $('.key-chooser .key-value').textContent !== first);
    expect(S.subs).toHaveLength(1); // nothing stored yet
    const second = $('.key-chooser .key-value').textContent;
    $('#keys-confirm').value = 'pw';
    button($('.key-chooser'), 'Use this key').click();
    await until(() => S.subs.length === 2);
    await until(() => document.querySelectorAll('#keys-subs-table tbody tr').length === 2);
    expect(S.current().id).toBe(S.subs[1].id);
    expect(S.audit.at(-1).action).toBe('keys.rotated');
    void second;
    // A key typed by hand: checked in the page first.
    $('#keys-confirm').value = 'pw';
    button(document, 'Add a sub-MEK…').click();
    await until(() => $('.key-chooser'));
    $('#sub-manual').value = 'too short';
    button($('.key-chooser'), 'Use the key I entered').click();
    expect($('.key-chooser .msg').textContent).toMatch(/32 bytes/);
    $('#sub-manual').value = Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) => b.toString(16).padStart(2, '0')).join('');
    button($('.key-chooser'), 'Use the key I entered').click();
    await until(() => S.subs.length === 3);
    expect($('#sub-manual')).toBeNull(); // the chooser is gone, with the key typed into it
  }, 60000);

  it('re-seal: every item under an older sub-MEK moves to the current one, with progress; then it can be deleted', async () => {
    await open();
    await seedTree(S, { 'a.txt': new TextEncoder().encode('a'), Folder: {} });
    const old = S.current().id;
    await S.addSub({ from: Math.floor(Date.now() / 1000) - 1 });
    const { keysSection } = await import('../public/dashboard/js/admin-keys.js');
    mount(keysSection({ profile: profile() }));
    await until(() => document.querySelectorAll('#keys-subs-table tbody tr').length === 2);
    const row = () => $(`#keys-subs-table tr[data-id="${old}"]`);
    await until(() => row().children[5].textContent === '2');
    $('#keys-confirm').value = 'pw';
    button(row(), 'Re-seal').click();
    await until(() => [...S.nodes.values()].filter((n) => n.mek === old).length === 0);
    await until(() => row() && row().children[5].textContent === '0');
    // The files still open, under the new sub-MEK.
    const c = await drive.openDrive({ user: S.user });
    expect((await c.list('root')).children.map((x) => x.name).sort()).toEqual(['Folder', 'a.txt']);
    $('#keys-confirm').value = 'pw';
    button(row(), 'Delete').click(); // arm
    button(row(), `Re-seal 0 item(s), then delete?`).click();
    await until(() => !S.subs.some((x) => x.id === old));
  }, 60000);

  it('no stray "null" text: a user’s file keys with no more pages, and the upgrade card with one Drive waiting', async () => {
    S = fakeServer({ role: 'owner' });
    globalThis.fetch = S.fetch;
    await S.ready;
    S.migrationDrives = [{ id: 'uBBBBBBBBBBBBBBB', username: 'bea', state: 'pending', v1Items: 2, v1Links: 0 }];
    const { keysSection } = await import('../public/dashboard/js/admin-keys.js');
    mount(keysSection({ profile: profile() }));
    await until(() => $('#keys-subs-table tbody tr') && $('#keys-upgrade') && !$('#keys-upgrade').hidden);
    await until(() => $('#keys-user option'));
    $('#keys-user-confirm').value = 'pw';
    $('#keys-user-deks').click();
    await until(() => /No files/.test($('#keys-user-out').textContent));
    const stray = [];
    const walk = (n) => { for (const c of n.childNodes) { if (c.nodeType === 3 && ['null', 'undefined'].includes(c.textContent.trim())) stray.push(n.id || n.nodeName); else if (c.nodeType === 1) walk(c); } };
    walk(document.body);
    expect(stray).toEqual([]);
  });

  // Re-audit v2r N4: a user's KEKs shown here go when the session locks or changes, as the Drive's do.
  it('a user’s keys and a shown key are dropped when the session ends or changes; seeing them again takes the step-up', async () => {
    const { SESSION_CHANGED_EVENT } = await import('../public/js/api.js');
    for (const ev of ['secbin:session-ended', SESSION_CHANGED_EVENT]) {
      document.body.replaceChildren();
      await open();
      await until(() => $('#keys-user option'));
      $('#keys-user-confirm').value = 'pw';
      $('#keys-user-view').click();
      await until(() => /KEK for/.test($('#keys-user-out').textContent));
      button($('#keys-user-out'), 'Show').click();
      await until(() => $('#keys-user-out .key-reveal'));
      expect($('#keys-user-out .key-value').textContent.length).toBeGreaterThan(20);
      // A key of the keyring shown too.
      $('#keys-confirm').value = 'pw';
      button($('#keys-root'), 'Show').click();
      await until(() => $('#keys-shown .key-reveal'));
      window.dispatchEvent(new Event(ev));
      expect($('#keys-user-out').textContent).toMatch(/cleared when your session ended or changed/);
      expect(document.querySelector('.key-reveal'), ev).toBeNull();
      expect(document.querySelector('.key-value'), ev).toBeNull();
      // Again: a new request, with the step-up.
      const n0 = S.requests.length;
      $('#keys-user-view').click();
      await until(() => !$('#keys-user-msg').hidden);
      expect($('#keys-user-msg').textContent).toMatch(/password/);
      expect(S.requests.slice(n0).some((r) => /\/admin\/keys\/users\//.test(r.path))).toBe(false);
    }
  }, 60000);

  // Audit A F2: a root change that could not finish shows its failed items and the three ways on.
  it('a stuck root change: the items listed; run it again, go back to the previous root, or drop it with its fingerprint typed (each with the step-up)', async () => {
    S = fakeServer({ role: 'owner' });
    globalThis.fetch = S.fetch;
    await S.ready;
    S.rootOld = new Uint8Array(32).fill(9);
    S.stuckIds = ['AAAAAAAAAAAAAAAAAAAAAA'];
    S.rootCheck = { failed: 1, ids: S.stuckIds };
    S.job = { kind: 'root', from: null, drives: 1, drive: 1, phase: 'verifyrest', done: 3, failed: 1, failedIds: S.stuckIds, pass: 1, verifying: true, finished: true, result: { ok: false, message: '1 item(s) do not open under the new root MEK.' } };
    const { keysSection } = await import('../public/dashboard/js/admin-keys.js');
    mount(keysSection({ profile: profile() }));
    await until(() => $('#keys-root-stuck'));
    expect($('#keys-root-stuck').textContent).toMatch(/1 item\(s\) do not open under the new root MEK \(AAAAAAAAAAAAAAAAAAAAAA\)/);
    expect($('#keys-root-drop').textContent).toBe('Remove the previous root (1 item stays unreadable)');
    // Run it again: the step-up first.
    $('#keys-root-retry').click();
    await until(() => !$('#keys-msg').hidden);
    expect($('#keys-msg').textContent).toMatch(/password/);
    $('#keys-confirm').value = 'pw';
    $('#keys-root-retry').click();
    await until(() => S.rootJobs === 1);
    await until(() => $('#keys-root-stuck') && !$('#keys-root-retry').disabled);
    // Drop the previous root: its fingerprint typed.
    const fp = $('#keys-root-stuck label').textContent.match(/\(([^)]+)\)/)[1];
    $('#keys-root-drop-confirm').value = 'wrong';
    $('#keys-confirm').value = 'pw';
    $('#keys-root-drop').click();
    await until(() => /confirm/.test($('#keys-msg').textContent));
    expect(S.rootOld).not.toBeNull();
    $('#keys-root-drop-confirm').value = fp;
    $('#keys-confirm').value = 'pw';
    const t = document.createElement('div');
    t.id = 'toast';
    document.body.append(t);
    $('#keys-root-drop').click();
    await until(() => S.rootOld === null);
    await until(() => !$('#keys-root-stuck'));
    expect(S.audit.find((a) => a.action === 'keys.root_old_dropped').detail).toBe('items left unreadable: 1');
    await until(() => /1 item stays unreadable/.test(t.textContent));
  }, 60000);

  // Re-audit v2r N2: the count comes from the root change's check, kept with it; without one, no drop.
  it('a stuck root change with its job cleared still says how many items stay unreadable; with no check yet, "Remove" waits for the re-seal', async () => {
    S = fakeServer({ role: 'owner' });
    globalThis.fetch = S.fetch;
    await S.ready;
    S.rootOld = new Uint8Array(32).fill(7);
    S.rootCheck = { failed: 2, ids: ['CCCCCCCCCCCCCCCCCCCCCC', 'DDDDDDDDDDDDDDDDDDDDDD'] };
    S.job = null; // the finished job was cleared
    const { keysSection } = await import('../public/dashboard/js/admin-keys.js');
    mount(keysSection({ profile: profile() }));
    await until(() => $('#keys-root-stuck'));
    expect($('#keys-root-stuck-count').textContent).toMatch(/^2 item\(s\) do not open under the new root MEK \(CCCCCCCCCCCCCCCCCCCCCC, DDDDDDDDDDDDDDDDDDDDDD\)/);
    expect($('#keys-root-drop').textContent).toBe('Remove the previous root (2 items stay unreadable)');
    expect($('#keys-root-drop').disabled).toBe(false);
    document.body.replaceChildren();
    // A previous root put back from a key kit, not checked yet: the count is unknown, the drop waits.
    S.rootCheck = null;
    S.rootOldOrigin = 'restored';
    mount(keysSection({ profile: profile() }));
    await until(() => $('#keys-root-stuck'));
    expect($('#keys-root-stuck-count').textContent).toMatch(/no re-seal has checked the items under these two roots yet/);
    expect($('#keys-root-drop').disabled).toBe(true);
    expect($('#keys-root-undo').title).toMatch(/put back from a key kit/);
    // "Go back" to it is refused while it opens nothing here (the server checks).
    $('#keys-confirm').value = 'pw';
    $('#keys-root-undo').click();
    $('#keys-root-undo').click();
    await until(() => !$('#keys-msg').hidden);
    expect(S.rootOld).not.toBeNull();
  }, 60000);

  it('a stuck root change: "Go back to the previous root" swaps the roots and re-seals everything under it', async () => {
    S = fakeServer({ role: 'owner' });
    globalThis.fetch = S.fetch;
    await S.ready;
    const before = S.root;
    S.rootOld = new Uint8Array(32).fill(5);
    S.rootCheck = { failed: 1, ids: ['BBBBBBBBBBBBBBBBBBBBBB'] };
    S.job = { kind: 'root', from: null, drives: 1, drive: 1, phase: 'verify', done: 0, failed: 1, failedIds: ['BBBBBBBBBBBBBBBBBBBBBB'], pass: 1, verifying: true, finished: true, result: { ok: false, message: 'x' } };
    const { keysSection } = await import('../public/dashboard/js/admin-keys.js');
    mount(keysSection({ profile: profile() }));
    await until(() => $('#keys-root-undo'));
    $('#keys-confirm').value = 'pw';
    $('#keys-root-undo').click(); // armed
    $('#keys-root-undo').click(); // confirmed
    await until(() => S.rootOld === null);
    expect([...S.root]).toEqual(new Array(32).fill(5));
    expect(S.root).not.toBe(before);
    await until(() => !$('#keys-root-stuck'));
  }, 60000);

  // Audit B L5: the owner's archive of the release before, deleted with the step-up and the username typed.
  it('the upgrade card shows the owner\'s archive of the previous release, and deletes it', async () => {
    S = fakeServer({ role: 'owner' });
    globalThis.fetch = S.fetch;
    await S.ready;
    S.archive = { items: 3, bytes: 2048, received: 1, links: ['rAAAAAAAAAAAAAAAAAAAAAA'] };
    const { keysSection } = await import('../public/dashboard/js/admin-keys.js');
    mount(keysSection({ profile: profile() }));
    await until(() => $('#keys-archive'));
    expect($('#keys-archive').textContent).toMatch(/3 items \(2\.0 KB, of which 1 received/);
    $('#keys-archive-confirm').value = 'nobody';
    $('#keys-archive-pw').value = 'pw';
    $('#keys-archive-delete').click();
    await until(() => !$('#keys-archive-msg').hidden);
    expect(S.archive).not.toBeNull();
    $('#keys-archive-confirm').value = S.user.username;
    $('#keys-archive-pw').value = 'pw';
    $('#keys-archive-delete').click();
    await until(() => S.archive === null && $('#keys-upgrade').hidden); // nothing left to show: the card goes
    expect(S.audit.some((a) => a.action === 'drive.archive_deleted')).toBe(true);
  }, 60000);

  it('the key kit: download (the step-up, passphrase warning), then verify the saved file with a date', async () => {
    await open();
    const saves = captureSaves();
    expect($('#kkit-pass-warn').textContent).toMatch(/No passphrase/);
    $('#kkit-download').click();
    await until(() => /password/.test($('#kkit-download-msg').textContent) && !$('#kkit-download').disabled);
    $('#kkit-confirm').value = 'pw';
    $('#kkit-download').click();
    await until(() => saves.length === 1, 60000);
    expect(saves[0].name).toMatch(/^secbin-key-kit-/);
    const text = await saves[0].blob.text();
    expect(parseDriveKit(text).kind).toBe('key');
    await until(() => $('#keys-kit-last') && /Latest key kit/.test($('#keys-kit-last').textContent));
    pick($('#kkit-verify-file'), [new File([text], 'k.json')]);
    const n0 = S.requests.length;
    $('#kkit-verify').click();
    await until(() => $('#kkit-verify-verdict'), 60000);
    const verify = S.requests.slice(n0).find((r) => r.path === '/api/private/admin/keys/verify');
    expect(verify).toBeTruthy();
    expect(JSON.stringify(verify.body)).not.toContain(S.salt);
  }, 120000);

  it('restore a user’s personal kit: the user chosen, that user’s kit only, the step-up (a password once for every call), only check-free kit content sent', async () => {
    S = fakeServer({ role: 'owner' });
    S.otherUsers = [{ id: 'bobbobbobbobbob1', username: 'bob', role: 'user' }];
    globalThis.fetch = S.fetch;
    await S.ready;
    // The owner's own personal kit (made on their Account page), and bob's.
    const own = await drive.buildPersonalKit({ user: S.user, passphrase: 'kit pass', step: { current: 'proof:x' } });
    const payload = await openDriveKit(parseDriveKit(own.text), { kind: 'user', accountId: S.user.id, origin: location.origin, passphrase: 'kit pass' });
    const bobs = await sealDriveKit('user', { ...payload, id: 'bobbobbobbobbob1', username: 'bob' }, { accountId: 'bobbobbobbobbob1', origin: location.origin, passphrase: 'kit pass' });
    const { keysSection } = await import('../public/dashboard/js/admin-keys.js');
    mount(keysSection({ profile: profile() }));
    await until(() => $('#ukr-user option'));
    expect($('#keys-user-kit-title').textContent).toBe('Restore a user’s personal kit');
    expect([...$('#ukr-user').options].map((o) => o.textContent)).toEqual(['owner (you)', 'bob']);
    expect($('#ukr-restore').disabled).toBe(true); // no file yet
    const sent = () => S.requests.filter((r) => /\/kit-restore$/.test(r.path));
    // Another user's kit for the chosen user: refused in this browser, nothing sent.
    $('#ukr-user').value = S.user.id;
    $('#ukr-user').dispatchEvent(new Event('change'));
    pick($('#ukr-file'), [new File([bobs], 'kit.json')]);
    expect($('#ukr-restore').disabled).toBe(false);
    $('#ukr-pass').value = 'kit pass';
    $('#ukr-confirm').value = 'pw';
    $('#ukr-restore').click();
    await until(() => /another account/.test($('#ukr-msg').textContent), 60000);
    expect(sent()).toHaveLength(0);
    resetThrottle();
    // Without the password: refused before anything is sent.
    pick($('#ukr-file'), [new File([own.text], 'kit.json')]);
    $('#ukr-pass').value = 'kit pass';
    $('#ukr-restore').click();
    await until(() => /password/.test($('#ukr-msg').textContent) && !$('#ukr-restore').disabled);
    expect(sent()).toHaveLength(0);
    // The right kit, with the step-up: only what the server lost comes back (here nothing).
    $('#ukr-pass').value = 'kit pass';
    $('#ukr-confirm').value = 'pw';
    $('#ukr-restore').click();
    await until(() => /Restore done/.test($('#ukr-msg').textContent), 60000);
    expect($('#ukr-msg').textContent).toBe('Restore done for owner: the user salt was already there; nothing else was missing.');
    expect(sent()).toHaveLength(1);
    expect(sent()[0].path).toBe(`/api/private/admin/keys/users/${S.user.id}/kit-restore`);
    expect(sent()[0].body).toMatchObject({ current: 'proof:pw', kit: { id: S.user.id, salt: S.salt, keks: [{ mekId: payload.keks[0].mekId, kek: payload.keks[0].kek }] } });
    expect(JSON.stringify(sent()[0].body)).not.toContain(parseDriveKit(own.text).ct); // the file itself is not uploaded
    expect($('#ukr-pass').value).toBe(''); // the passphrase is cleared after use
    expect(S.audit.at(-1).action).toBe('drive.kit_restored');
    // A Drive that takes two calls: the password is asked once, the second call resumes where the first stopped.
    S.kitLost = [S.current().id];
    S.kitRestorePages = 2;
    S.kitRestoreBodies = [];
    pick($('#ukr-file'), [new File([own.text], 'kit.json')]);
    $('#ukr-pass').value = 'kit pass';
    $('#ukr-confirm').value = 'pw';
    const n0 = sent().length;
    $('#ukr-restore').click();
    await until(() => /Restore done/.test($('#ukr-msg').textContent) && sent().length === n0 + 2, 60000);
    const [a, b] = sent().slice(n0);
    expect(a.body.resume).toBeUndefined();
    expect(b.body).toMatchObject({ current: 'proof:pw', resume: { mek: S.current().id, after: `n.${'A'.repeat(22)}` } });
    expect($('#ukr-msg').textContent).toMatch(/4 items sealed again under the current key/);
    // No stray "null" / "undefined" text in the card.
    const stray = [];
    const walk = (n) => { for (const c of n.childNodes) { if (c.nodeType === 3 && ['null', 'undefined'].includes(c.textContent.trim())) stray.push(n.id || n.nodeName); else if (c.nodeType === 1) walk(c); } };
    walk($('#keys-user-kit'));
    expect(stray).toEqual([]);
  }, 120000);

  it('the restore card’s message sits in a status line that is in the page before it (WCAG 4.1.3); every field has a label', async () => {
    await open();
    await until(() => $('#ukr-user option'));
    const m = $('#ukr-msg');
    expect(m.hasAttribute('role')).toBe(false);
    expect(m.parentElement.getAttribute('role')).toBe('status');
    expect(m.parentElement.hidden).toBe(false);
    for (const id of ['ukr-user', 'ukr-file', 'ukr-pass', 'ukr-confirm']) expect($(`#${id}`).closest('label.field').querySelector('.field-label').textContent.length, id).toBeGreaterThan(3);
  });
});

describe('WCAG 2.2 (docs/WCAG22.md): the kit forms', () => {
  it('each form\'s message sits in a status line that is in the page before it (4.1.3); the passphrase warning describes the field while it shows (1.3.1)', async () => {
    S = fakeServer();
    globalThis.fetch = S.fetch;
    await S.ready;
    const { personalKitCard } = await import('../public/dashboard/js/userkit.js');
    mount(personalKitCard({ profile: { user: { ...S.user, username: 'alice' } }, drive, confirm: async () => ({ current: 'proof:pw' }) }));
    for (const id of ['ukit-download-msg', 'ukit-verify-msg']) {
      const m = document.getElementById(id);
      expect(m.hasAttribute('role'), id).toBe(false);
      expect(m.parentElement.getAttribute('role'), id).toBe('status');
      expect(m.parentElement.hidden, id).toBe(false);
    }
    const pass = $('#ukit-pass');
    expect(pass.getAttribute('aria-describedby')).toBe('ukit-pass-warn'); // empty: the warning shows
    pass.value = 'a long enough kit passphrase';
    pass.dispatchEvent(new Event('input'));
    expect($('#ukit-pass-warn').hidden).toBe(true);
    expect(pass.hasAttribute('aria-describedby')).toBe(false);
    // A message said after the page loaded goes into the same, already present, status line.
    const live = $('#ukit-download-msg').parentElement;
    $('#ukit-pass2').value = 'something else';
    $('#ukit-download').click();
    await until(() => !$('#ukit-download-msg').hidden);
    expect($('#ukit-download-msg').textContent).toMatch(/passphrases differ/);
    expect($('#ukit-download-msg').parentElement).toBe(live);
  });
});

describe('Admin → Import / export → Drive keys', () => {
  it('chooses parts and users (search, select all, id lists), shows the file masked, seals it; an import is previewed, then applied with the step-up', async () => {
    S = fakeServer({ role: 'owner' });
    S.otherUsers = [{ id: 'bobbobbobbobbob1', username: 'bob', role: 'user' }, { id: 'carolcarolcarol1', username: 'carol', role: 'user' }];
    globalThis.fetch = S.fetch;
    await S.ready;
    const { keysPortCard } = await import('../public/dashboard/js/admin-keysport.js');
    const card = mount(await keysPortCard({ user: S.user }));
    expect(card.querySelector('.subtitle').textContent).toMatch(/never part of the export above/);
    // The picker: search narrows, "Select all" takes those shown.
    $('#kx-search').value = 'bo';
    $('#kx-search').dispatchEvent(new Event('input'));
    button(card, 'Select all').click();
    const checked = () => [...document.querySelectorAll('#kx-users li')].filter((li) => li.querySelector('input').checked).map((li) => li.dataset.id);
    expect(checked()).toEqual(['bobbobbobbobbob1']);
    $('#kx-search').value = '';
    $('#kx-search').dispatchEvent(new Event('input'));
    button(card, 'Deselect all').click();
    expect(checked()).toEqual([]);
    // An uploaded id list chooses those that are here.
    pick($('#kx-ids-file'), [new File(['carolcarolcarol1\nnot-a-user-id-000\n'], 'ids.txt')]);
    await until(() => checked().length === 1);
    expect(checked()).toEqual(['carolcarolcarol1']);
    const saves = captureSaves();
    button(card, 'Download the chosen ids (a list of user ids, no keys)').click();
    expect(await saves[0].blob.text()).toBe('carolcarolcarol1\n');
    // Build: the step-up, then the masked view.
    $('#kx-root').checked = true;
    $('#kx-keks').checked = true;
    $('#kx-subs').value = 'all';
    $('#kx-build').click();
    await until(() => /password/.test($('#kx-msg').textContent) && !$('#kx-build').disabled);
    expect(S.exportBodies).toBeUndefined();
    $('#kx-confirm').value = 'pw';
    $('#kx-build').click();
    await until(() => $('#kx-view ul'));
    expect(S.exportBodies[0]).toMatchObject({ root: true, subs: 'all', users: [{ id: 'carolcarolcarol1', keks: true, deks: false }], current: 'proof:pw' });
    expect($('#kx-view').textContent).toMatch(/Root MEK/);
    expect($('#kx-view').textContent).not.toMatch(/[A-Za-z0-9_-]{43}/); // masked
    button($('#kx-view'), 'Show').click();
    expect($('#kx-view .key-value').textContent).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // Sealed under the passphrase (empty: allowed, with the warning).
    expect($('#kx-nopass').hidden).toBe(false);
    $('#kx-pass').value = 'export pass';
    $('#kx-pass').dispatchEvent(new Event('input'));
    $('#kx-pass2').value = 'export pass';
    $('#kx-save').click();
    await until(() => saves.length === 2, 60000);
    const text = await saves[1].blob.text();
    const doc = await openExport(text, 'export pass');
    expect(doc).toMatchObject({ format: 'secbin-keys-export/1', root: { key: expect.any(String) } });
    expect(text).not.toContain(doc.root.key);
    // Import: decrypt here, preview (the step-up too: audit A F7), then import (the step-up again).
    pick($('#ki-file'), [new File([text], 'keys.json')]);
    $('#ki-pass').value = 'export pass';
    $('#ki-open').click();
    await until(() => $('#ki-preview'), 60000);
    expect($('#ki-take-root').checked).toBe(true);
    $('#ki-preview').click();
    await until(() => /password/.test($('#ki-plan-msg').textContent) && !$('#ki-preview').disabled);
    expect(S.importBodies).toBeUndefined(); // nothing sent without it
    $('#ki-confirm').value = 'pw';
    $('#ki-preview').click();
    await until(() => $('#ki-plan li'));
    expect(S.importBodies[0]).toMatchObject({ dryRun: true, take: { root: true }, current: 'proof:pw' });
    expect($('#ki-plan').textContent).toMatch(/Preview/);
    $('#ki-confirm').value = 'pw';
    $('#ki-apply').click();
    await until(() => S.importBodies.length === 2);
    expect(S.importBodies[1]).toMatchObject({ dryRun: false, current: 'proof:pw' });
  }, 120000);

  it('the labels say what the id list and the build hold', async () => {
    S = fakeServer({ role: 'owner' });
    globalThis.fetch = S.fetch;
    await S.ready;
    const { keysPortCard } = await import('../public/dashboard/js/admin-keysport.js');
    const card = mount(await keysPortCard({ user: S.user }));
    expect(button(card, 'Download the chosen ids')).toBeUndefined();
    expect(button(card, 'Download the chosen ids (a list of user ids, no keys)')).toBeTruthy();
    expect(card.textContent).toMatch(/a plain text file of the chosen user ids, one per line, with no keys: choose it here again later/);
    expect($('#kx-build').getAttribute('aria-describedby')).toBe('kx-build-hint');
    const hint = $('#kx-build-hint').textContent;
    expect(hint).toMatch(/the chosen users’ salts, KEKs and DEKs \(as ticked\)/);
    expect(hint).toMatch(/“Encrypt and download” then encrypts it with the export passphrase/);
  });

  it('verify: a saved export, read-only after the step-up (check values and the DEKs only); a tampered copy shows what does not match', async () => {
    S = fakeServer({ role: 'owner' });
    S.otherUsers = [{ id: 'bobbobbobbobbob1', username: 'bob', role: 'user' }];
    globalThis.fetch = S.fetch;
    await S.ready;
    await seedTree(S, { 'a.txt': new TextEncoder().encode('verify me, synthetic') });
    const { keysPortCard } = await import('../public/dashboard/js/admin-keysport.js');
    mount(await keysPortCard({ user: S.user }));
    // An export of everything for the owner's own account.
    pick($('#kx-ids-file'), [new File([`${S.user.id}\n`], 'ids.txt')]);
    await until(() => document.querySelector(`#kx-users li[data-id="${S.user.id}"] input`).checked);
    for (const id of ['#kx-root', '#kx-salts', '#kx-keks']) $(id).checked = true;
    $('#kx-subs').value = 'all';
    $('#kx-deks').value = 'all';
    $('#kx-confirm').value = 'pw';
    $('#kx-build').click();
    await until(() => $('#kx-view ul'));
    const saves = captureSaves();
    $('#kx-pass').value = 'vp';
    $('#kx-pass2').value = 'vp';
    $('#kx-save').click();
    await until(() => saves.length === 1, 60000);
    const text = await saves[0].blob.text();
    const doc = await openExport(text, 'vp');
    expect(doc.users[0].deks).toHaveLength(1);
    // The Verify form: the file, its passphrase, the date, the step-up.
    const set = $('#kv-set');
    expect(set.querySelector('legend').textContent).toBe('Verify a Drive keys export');
    expect([...set.querySelectorAll('.field-label')].map((x) => x.textContent)).toEqual(['Drive keys export file to verify', 'Its passphrase', 'The sub-MEK in effect on', 'Your password (or leave it empty to confirm with a passkey)']);
    expect($('#kv-date').type).toBe('date');
    expect($('#kv-verify').disabled).toBe(true);
    const run = async (fileText, password) => {
      pick($('#kv-file'), [new File([fileText], 'keys.json')]);
      expect($('#kv-verify').disabled).toBe(false);
      $('#kv-pass').value = 'vp';
      $('#kv-confirm').value = password;
      $('#kv-verify').click();
    };
    // Without the step-up: refused, nothing sent.
    await run(text, '');
    await until(() => /password/.test($('#kv-msg').textContent));
    expect(S.xverifyBodies).toBeUndefined();
    expect($('#kv-out').childElementCount).toBe(0);
    await run(text, 'pw');
    await until(() => $('#kv-verdict'), 60000);
    expect($('#kv-verdict').dataset.verdict).toBe('complete');
    expect($('#kv-verdict').textContent).toBe('Everything in this file matches this server');
    expect(document.activeElement).toBe($('#kv-verdict'));
    expect($('#kv-summary').textContent).toMatch(/^Everything in this file matches this server\./);
    const status = (id) => $(`#kv-results [data-check="${id}"]`).dataset.status;
    expect(status('root')).toBe('pass');
    expect(S.subs.every((x) => status(`sub:${x.id}`) === 'pass')).toBe(true);
    expect(status(`user:${S.user.id}`)).toBe('pass');
    expect($(`#kv-results [data-check="user:${S.user.id}"]`).textContent).toMatch(/the user salt matches; KEKs: 1 of 1 match; DEKs: 1 of 1 open their file’s first chunk/);
    expect(status('date')).toBe('pass');
    // Only check values went, and the DEKs (tried on their files); the passphrase and password fields are cleared.
    const sent = S.xverifyBodies[0];
    expect(sent.current).toBe('proof:pw');
    const json = JSON.stringify(sent);
    for (const k of [doc.root.key, ...doc.subs.map((x) => x.key), doc.salts[S.user.id], ...doc.users[0].keks.map((x) => x.kek)]) expect(json).not.toContain(k);
    expect(sent.users[0].deks).toEqual(doc.users[0].deks);
    expect([$('#kv-pass').value, $('#kv-confirm').value]).toEqual(['', '']);
    expect(S.audit.at(-1)).toEqual({ action: 'keys.export_verified', detail: 'matches' });
    // A tampered copy: another root MEK, a wrong KEK, a broken DEK, a sub-MEK unknown here.
    const other = () => b64urlFromBytes(crypto.getRandomValues(new Uint8Array(32)));
    const tampered = await sealExport({
      ...doc, root: { ...doc.root, key: other() }, subs: [...doc.subs, { id: `m${'Z'.repeat(11)}`, key: other(), from: 0, until: 0 }],
      users: [{ ...doc.users[0], keks: doc.users[0].keks.map((x) => ({ ...x, kek: other() })), deks: doc.users[0].deks.map((x) => ({ ...x, dek: other() })) }],
    }, 'vp');
    await run(tampered, 'pw');
    await until(() => $('#kv-verdict')?.dataset.verdict === 'incomplete', 60000);
    expect($('#kv-verdict').textContent).toBe('Not everything in this file matches this server');
    expect(status('root')).toBe('fail');
    expect(status(`sub:m${'Z'.repeat(11)}`)).toBe('fail');
    expect(status(`user:${S.user.id}`)).toBe('fail');
    expect($(`#kv-results [data-check="user:${S.user.id}"]`).textContent).toMatch(/KEKs: 0 of 1 match; 1 differ .*DEKs: 0 of 1 open their file’s first chunk; 1 do not open it/);
    expect($('#kv-summary').textContent).toMatch(/^What does not match: Root MEK; Sub-MEK mZ{11}; owner \(owner1ownerowner\)\.$/);
    // The statuses are in words too, not only in colour.
    expect($(`#kv-results [data-check="root"] strong`).textContent).toBe('Fail: ');
    // The results go when the session ends.
    window.dispatchEvent(new Event('secbin:session-ended'));
    expect($('#kv-out').childElementCount).toBe(0);
  }, 180000);
});
