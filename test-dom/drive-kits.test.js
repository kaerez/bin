// drive-kits.test.js — the pages of the Drive key model v2 (docs/DRIVE.md §3,
// §3.1) with the real modules against the in-memory server
// (drive-fake-server.js): the personal kit card on Account (download with the
// step-up, verify a selected file with a date — read-only, only check values
// sent — and restore; a note instead while the owner acts as the user), Admin
// → Security → Keys (the keyring with its plain-language help, Show with the
// step-up and hidden again, a generated sub-MEK used or thrown away, entering
// one by hand, rotation, a re-seal with its progress, the key kit download
// and verify), and the Drive keys card of Import / export (the parts, the
// user picker with search, select all / deselect all and id lists, the
// masked view, the sealed file, an import previewed then applied).
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { fakeServer, seedTree } from './drive-fake-server.js';
import * as drive from '../public/js/driveclient.js';
import { clearSessionKey } from '../public/js/drivekeys.js';
import { parseDriveKit, openDriveKit } from '../public/js/drivekit.js';
import { openExport } from '../public/js/exportcrypt.js';
import { resetThrottle } from '../public/dashboard/js/kit-ui.js';

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

  it('download (the step-up), verify the selected file with a date, restore — the kit file itself is never sent', async () => {
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
    // Restore: the step-up, then only what the server lost (here nothing).
    pick($('#ukit-restore-file'), [new File([text], 'kit.json', { type: 'application/json' })]);
    $('#ukit-restore-pass').value = 'kit passphrase 123';
    $('#ukit-restore-confirm').value = 'account-pw';
    $('#ukit-restore').click();
    await until(() => /Restore done/.test($('#ukit-restore-msg').textContent), 60000);
    expect($('#ukit-restore-msg').textContent).toMatch(/already there/);
  }, 120000);

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
    button(card, 'Download the chosen ids').click();
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
    // Import: decrypt here, preview (no step-up), then import (the step-up).
    pick($('#ki-file'), [new File([text], 'keys.json')]);
    $('#ki-pass').value = 'export pass';
    $('#ki-open').click();
    await until(() => $('#ki-preview'), 60000);
    expect($('#ki-take-root').checked).toBe(true);
    $('#ki-preview').click();
    await until(() => $('#ki-plan li'));
    expect(S.importBodies[0]).toMatchObject({ dryRun: true, take: { root: true } });
    expect($('#ki-plan').textContent).toMatch(/Preview/);
    $('#ki-confirm').value = 'pw';
    $('#ki-apply').click();
    await until(() => S.importBodies.length === 2);
    expect(S.importBodies[1]).toMatchObject({ dryRun: false, current: 'proof:pw' });
  }, 120000);
});
