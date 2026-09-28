// drive.test.js — the Drive page (public/dashboard/js/drive-app.js) with the
// real Drive client (public/js/driveclient.js) against the in-memory §6 API
// behind a mocked fetch (drive-fake-server.js): disabled / set-up / locked /
// open states, the unlock (password, recovery code, passkey PRF), the tree +
// right pane, the dialogs (new folder, rename, move, delete, share, an item's
// shares with revoke), upload and download, plus the pure helpers and the
// nav's Drive switch.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { startDrive, checkName, shareOptions, toFraction, modifiedOf, pathOf, sortChildren, successNote } from '../public/dashboard/js/drive-app.js';
import * as drive from '../public/js/driveclient.js';
import { createDriveKey, saveSessionKey, loadSessionKey, clearSessionKey, wrapRecovery, recoveryRef, wrapPrf, DRIVE_PRF_SALT, createEscrowKeyPair } from '../public/js/drivekeys.js';
import { deriveAccess, openPaste } from '../public/js/crypto.js';
import { b64urlFromBytes, randomBytes } from '../public/js/bytes.js';
import { TAG } from '../public/js/files.js';
import { fakeServer, seedTree } from './drive-fake-server.js';

const until = async (fn, ms = 5000) => {
  const t0 = Date.now();
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 10));
  }
};
const names = () => [...document.querySelectorAll('#drive-rows tr')].map((tr) => tr.children[1].textContent.trim());
const title = () => document.getElementById('drive-pane-title').textContent;
const treeItem = (name) => [...document.querySelectorAll('#drive-tree-pane .tree-item')].find((li) => li.querySelector(':scope > .tree-label .tree-text').textContent === name);
const row = (name) => [...document.querySelectorAll('#drive-rows tr')].find((tr) => tr.children[1].textContent.trim() === name);
const dialog = () => document.querySelector('.drive-dialog [role="dialog"]');
const button = (root, text) => [...root.querySelectorAll('button')].find((b) => b.textContent.trim() === text);
const LIMITS = { maxViews: 100, allowUnlimitedViews: true, maxExpireSec: null, openerDelete: true, files: true };
const PROFILE = { limits: LIMITS, caps: { driveEnabled: true }, viewer: { enabled: true, rules: [], maxBytes: 1000 } };
const CODE = 'ABCD-EFGH-JKMN-PQRS';
const enc = (s) => new TextEncoder().encode(s);
const TREE = {
  Documents: { Reports: { 'q1.txt': enc('Q1 numbers\n'), Archive: {} }, 'notes.md': enc('# Notes\nhello\n') },
  Photos: { 'cat.png': new Uint8Array(2048) },
  Empty: {},
  'readme.txt': enc('Welcome to the Drive.\n'),
};

let S;
let dk;
let ids;

/** A server holding TREE under a Drive key with a recovery-code wrap; the tab has the key unless `locked`. */
async function server({ locked = false, capacity = 50 * 1024 * 1024 } = {}) {
  S = fakeServer({ capacity });
  globalThis.fetch = S.fetch;
  dk = createDriveKey();
  const w = await wrapRecovery(dk, CODE, await recoveryRef(CODE));
  S.wraps.set(`${w.kind}|${w.ref}`, w);
  ids = await seedTree(S, dk, TREE);
  if (!locked) saveSessionKey(dk, S.user.id);
  return S;
}

function mountPoint() {
  const mount = document.createElement('div');
  document.body.replaceChildren(document.createElement('main'), mount);
  document.body.firstChild.id = 'main';
  return mount;
}

const deps = (extra = {}) => ({ drive, profile: PROFILE, user: S.user, revoke: (id) => fetch(`/api/private/shares/${id}/revoke`, { method: 'POST' }), ...extra });

async function openApp(extra = {}) {
  await server();
  const mount = mountPoint();
  const r = await startDrive(mount, deps(extra));
  expect(r.state).toBe('open');
  await r.app.ready;
  return { ...r, mount };
}

beforeEach(() => { document.body.replaceChildren(); clearSessionKey(); });
afterEach(() => { vi.restoreAllMocks(); });

describe('pure helpers', () => {
  it('checkName', () => {
    expect(checkName('  a.txt ')).toEqual({ name: 'a.txt' });
    expect(checkName('')).toHaveProperty('error');
    expect(checkName('a/b').error).toMatch(/cannot contain/);
    expect(checkName('a\\b').error).toMatch(/cannot contain/);
    expect(checkName('a\u0001').error).toMatch(/control/);
    expect(checkName('..').error).toMatch(/reserved/);
    expect(checkName('x'.repeat(256)).error).toMatch(/255/);
    expect(checkName('x'.repeat(255))).toEqual({ name: 'x'.repeat(255) });
    expect(checkName('é'.repeat(128)).error).toMatch(/255 bytes/); // 256 bytes in UTF-8, as the client counts
    expect(checkName('é').name).toBe('é'); // NFC
  });

  it('shareOptions follows the composer rules and the role limits', () => {
    const L = { maxViews: 10, allowUnlimitedViews: false, maxExpireSec: 3600 };
    expect(shareOptions({ views: '3', unlimited: false, n: '30', unit: 'm' }, L)).toEqual({ views: 3, expire: '30m', expiryText: '30 minutes' });
    expect(shareOptions({ views: '11', unlimited: false, n: '1', unit: 'h' }, L).error).toMatch(/1 to 10/);
    expect(shareOptions({ views: '1', unlimited: true, n: '1', unit: 'h' }, L).error).toMatch(/Unlimited/);
    expect(shareOptions({ views: '1', unlimited: false, n: '2', unit: 'h' }, L).error).toMatch(/at most 60 minutes/);
    expect(shareOptions({ views: '1', unlimited: false, n: '0', unit: 'h' }, L).field).toBe('expire');
    expect(shareOptions({ views: '', unlimited: true, n: '1', unit: 'd' }, { allowUnlimitedViews: true })).toEqual({ views: null, expire: '1d', expiryText: '1 day' });
  });

  it('toFraction (the client\'s bytesDone, total), modifiedOf, sortChildren, pathOf, successNote', () => {
    expect(toFraction(1, 2)).toBe(0.5);
    expect(toFraction(7, 4)).toBe(1);
    expect(toFraction(3, 0)).toBe(0); // an empty file
    expect(toFraction(undefined)).toBe(0);
    expect(modifiedOf({ kind: 'file', mtime: 1700000000000 })).toBe(1700000000);
    expect(modifiedOf({ kind: 'dir', mtime: 0, updated: 1700000000 })).toBe(1700000000);
    expect(sortChildren([{ kind: 'file', name: 'a' }, { kind: 'dir', name: 'z' }, { kind: 'dir', name: 'b' }]).map((c) => c.name)).toEqual(['b', 'z', 'a']);
    expect(pathOf({ node: { id: 'x', name: 'X' }, path: [{ id: 'root', name: 'Drive' }, { id: 'x', name: 'X' }] })).toEqual([{ id: 'root', name: 'Drive' }, { id: 'x', name: 'X' }]);
    expect(pathOf({ node: { id: 'root', name: 'Drive' }, path: [{ id: 'root', name: 'Drive' }] })).toEqual([{ id: 'root', name: 'Drive' }]);
    expect(successNote({ views: 1, expiryText: '1 hour', what: 'the file' })).toMatch(/open the file once/);
  });
});

describe('startDrive states', () => {
  it('disabled: says Drive is not enabled', async () => {
    S = fakeServer({ enabled: false });
    globalThis.fetch = S.fetch;
    const mount = mountPoint();
    const r = await startDrive(mount, deps());
    expect(r.state).toBe('disabled');
    expect(mount.textContent).toMatch(/Drive is not enabled for your account/);
  });

  it('other errors are shown as an alert', async () => {
    S = fakeServer();
    globalThis.fetch = vi.fn(async () => ({ ok: false, status: 500, type: 'basic', json: async () => ({ error: 'boom', message: 'boom' }) }));
    const mount = mountPoint();
    const r = await startDrive(mount, deps());
    expect(r.state).toBe('error');
    expect(mount.querySelector('[role="alert"]').textContent).toMatch(/boom/);
  });

  it('set-up (no key yet): only the password is offered', async () => {
    S = fakeServer();
    S.escrowPub = (await createEscrowKeyPair()).publicJwk; // the owner's escrow key exists
    globalThis.fetch = S.fetch;
    const mount = mountPoint();
    const r = await startDrive(mount, deps());
    expect(r.state).toBe('locked');
    expect(mount.querySelector('#drive-unlock h2').textContent).toBe('Set up your Drive');
    expect(mount.querySelector('#drive-unlock-btn').textContent).toBe('Set up with password');
    expect(mount.querySelector('#drive-code-toggle').hidden).toBe(true);
    expect(mount.querySelector('#drive-unlock-passkey').hidden).toBe(true);
  });

  it('locked: the unlock prompt; a wrong password is refused, a recovery code unlocks', async () => {
    await server({ locked: true });
    const mount = mountPoint();
    const r = await startDrive(mount, deps());
    expect(r.state).toBe('locked');
    expect(mount.querySelector('#drive-unlock h2').textContent).toBe('Unlock your Drive');
    expect(mount.querySelector('#drive-unlock-passkey').hidden).toBe(true); // no passkey has a Drive wrap
    const pw = mount.querySelector('#drive-unlock-pw');
    expect(pw.type).toBe('password');
    expect(mount.querySelector('label[for="drive-unlock-pw"]')).not.toBeNull();
    pw.value = 'wrong';
    mount.querySelector('#drive-pw-form').dispatchEvent(new Event('submit', { cancelable: true }));
    await until(() => !mount.querySelector('#drive-unlock-msg').hidden, 30000);
    expect(mount.querySelector('#drive-unlock-msg').textContent).toMatch(/does not unlock your Drive/);
    expect(pw.getAttribute('aria-invalid')).toBe('true');
    mount.querySelector('#drive-code-toggle').click();
    expect(mount.querySelector('#drive-code-form').hidden).toBe(false);
    mount.querySelector('#drive-unlock-code').value = CODE.toLowerCase();
    mount.querySelector('#drive-code-form').dispatchEvent(new Event('submit', { cancelable: true }));
    const app = await r.unlocked;
    await app.ready;
    expect(mount.querySelector('#drive-app')).not.toBeNull();
    expect(pw.value).toBe('');
    expect(loadSessionKey(S.user.id)).toEqual(dk);
    expect(names()).toEqual(['Documents', 'Empty', 'Photos', 'readme.txt']);
  }, 60000);

  it('locked: a passkey with a Drive wrap unlocks through the shared PRF helper (passkeys.js)', async () => {
    await server({ locked: true });
    const rawId = randomBytes(16);
    const credId = b64urlFromBytes(rawId);
    const prf = randomBytes(32);
    const w = await wrapPrf(dk, prf, credId);
    S.wraps.set(`${w.kind}|${w.ref}`, w);
    let asked = null;
    vi.stubGlobal('PublicKeyCredential', function PublicKeyCredential() {});
    const creds = {
      create: async () => null,
      get: async (o) => {
        asked = o.publicKey;
        return {
          id: credId, rawId: rawId.slice().buffer, type: 'public-key',
          response: { clientDataJSON: new ArrayBuffer(1), authenticatorData: new ArrayBuffer(1), signature: new ArrayBuffer(1), userHandle: null },
          getClientExtensionResults: () => ({ prf: { results: { first: prf.slice().buffer } } }),
        };
      },
    };
    Object.defineProperty(navigator, 'credentials', { configurable: true, value: creds });
    try {
      const mount = mountPoint();
      const r = await startDrive(mount, deps());
      const pk = mount.querySelector('#drive-unlock-passkey');
      expect(pk.hidden).toBe(false);
      pk.click();
      const app = await r.unlocked;
      await app.ready;
      expect(Array.from(asked.extensions.prf.eval.first)).toEqual(Array.from(DRIVE_PRF_SALT));
      expect(asked.allowCredentials.map((c) => b64urlFromBytes(new Uint8Array(c.id)))).toEqual([credId]);
      expect(loadSessionKey(S.user.id)).toEqual(dk);
      // Neither the PRF output nor the key went to the server.
      const wire = JSON.stringify(S.requests.map((x) => x.body));
      expect(wire).not.toContain(b64urlFromBytes(prf));
      expect(wire).not.toContain(b64urlFromBytes(dk));
    } finally {
      delete navigator.credentials;
      vi.unstubAllGlobals();
    }
  });

  it('impersonating without the owner’s own Drive unlocked in the tab: a notice saying what to do (no prompt, nothing sent)', async () => {
    S = fakeServer();
    globalThis.fetch = S.fetch;
    const w = await wrapRecovery(createDriveKey(), CODE, await recoveryRef(CODE)); // the user's Drive exists
    S.wraps.set(`${w.kind}|${w.ref}`, w);
    S.impersonatedBy = 'owner';
    const mount = mountPoint();
    const r = await startDrive(mount, deps({ user: { ...S.user, impersonating: true } }));
    expect(r).toMatchObject({ state: 'impersonating', reason: 'owner_locked' });
    expect(mount.querySelector('#drive-impersonating').textContent).toMatch(/Unlock your own Drive first.*open Drive and unlock it/);
    expect(mount.querySelector('#drive-unlock')).toBeNull();
    expect(S.requests.some((x) => x.method !== 'GET')).toBe(false);
  });

  it('a tab key that does not open this Drive goes back to the unlock prompt', async () => {
    await server({ locked: true });
    saveSessionKey(createDriveKey(), S.user.id);
    const mount = mountPoint();
    const r = await startDrive(mount, deps());
    expect(r.state).toBe('open');
    await until(() => mount.querySelector('#drive-unlock'));
    expect(loadSessionKey(S.user.id)).toBeNull();
  });
});

/** Text nodes reading "null" or "undefined" under `root` (a nullish child passed to append/replaceChildren). */
function strayText(root) {
  const out = [];
  const walk = (n) => {
    for (const c of n.childNodes) {
      if (c.nodeType === 3 && ['null', 'undefined'].includes(c.textContent.trim())) out.push(`${c.textContent.trim()} in <${n.nodeName.toLowerCase()}${n.id ? `#${n.id}` : ''}>`);
      else if (c.nodeType === 1) walk(c);
    }
  };
  walk(root);
  return out;
}

describe('no stray "null" / "undefined" text on the unlock and set-up views', () => {
  const start = async (extra = {}) => {
    const mount = mountPoint();
    const r = await startDrive(mount, deps(extra));
    return { r, mount };
  };
  const ownerDeps = () => ({ profile: { ...PROFILE, user: { ...S.user } } });
  const wrapCode = async () => {
    const w = await wrapRecovery(createDriveKey(), CODE, await recoveryRef(CODE));
    S.wraps.set(`${w.kind}|${w.ref}`, w);
  };

  it('a user: set-up and unlock', async () => {
    S = fakeServer();
    S.escrowPub = (await createEscrowKeyPair()).publicJwk;
    globalThis.fetch = S.fetch;
    let { r, mount } = await start();
    expect(r.state).toBe('locked');
    expect(mount.querySelector('#drive-unlock h2').textContent).toBe('Set up your Drive');
    expect([...mount.childNodes].map((n) => n.id)).toEqual(['drive-unlock']);
    expect(strayText(document.body)).toEqual([]);

    await server({ locked: true });
    S.received = 2;
    ({ r, mount } = await start());
    expect(r.state).toBe('locked');
    expect(mount.querySelector('#drive-unlock h2').textContent).toBe('Unlock your Drive');
    expect([...mount.childNodes].map((n) => n.id)).toEqual(['drive-unlock']);
    expect(strayText(document.body)).toEqual([]);
  });

  it('the owner: set-up, unlock (with the kit restore) and nothing that opens the Drive (restore or start over)', async () => {
    S = fakeServer({ role: 'owner' });
    globalThis.fetch = S.fetch;
    let { r, mount } = await start(ownerDeps());
    expect(r.state).toBe('locked');
    expect(mount.querySelector('#drive-unlock h2').textContent).toBe('Set up your Drive');
    expect([...mount.childNodes].map((n) => n.id)).toEqual(['drive-unlock']);
    expect(strayText(document.body)).toEqual([]);

    await wrapCode();
    S.escrowPub = (await createEscrowKeyPair()).publicJwk;
    ({ r, mount } = await start(ownerDeps()));
    expect(r.state).toBe('locked');
    expect(mount.querySelector('#drive-unlock h2').textContent).toBe('Unlock your Drive');
    expect([...mount.childNodes].map((n) => n.id)).toEqual(['drive-unlock', 'drive-kit-unlock']);
    expect(strayText(document.body)).toEqual([]);

    S.wraps.clear();
    ({ r, mount } = await start(ownerDeps()));
    expect(r.state).toBe('locked');
    expect([...mount.childNodes].map((n) => n.id)).toEqual(['drive-unlock', 'drive-owner-recovery']);
    expect(strayText(document.body)).toEqual([]);
  });

  it('the owner acting as a user: the Drive notices in place of the unlock and set-up views', async () => {
    S = fakeServer();
    globalThis.fetch = S.fetch;
    S.impersonatedBy = 'owner';
    const acting = () => ({ user: { ...S.user, impersonating: true }, profile: { ...PROFILE, user: { ...S.user }, impersonatedBy: 'owner' } });
    let { r, mount } = await start(acting()); // the user has no Drive yet
    expect(r).toMatchObject({ state: 'impersonating', reason: 'no_drive' });
    expect(mount.querySelector('#drive-unlock')).toBeNull();
    expect(strayText(document.body)).toEqual([]);

    await wrapCode(); // the user's Drive exists; the owner's own is not unlocked in this tab
    ({ r, mount } = await start(acting()));
    expect(r).toMatchObject({ state: 'impersonating', reason: 'owner_locked' });
    expect(mount.querySelector('#drive-unlock')).toBeNull();
    expect(strayText(document.body)).toEqual([]);
  });

  it('the open Drive, for a user and for the owner', async () => {
    await openApp();
    expect(strayText(document.body)).toEqual([]);
    S = fakeServer({ role: 'owner' });
    globalThis.fetch = S.fetch;
    const mount = mountPoint();
    const r = await startDrive(mount, deps(ownerDeps()));
    expect(r.state).toBe('locked');
    mount.querySelector('#drive-unlock-pw').value = 'owner password';
    mount.querySelector('#drive-pw-form').dispatchEvent(new Event('submit', { cancelable: true }));
    const app = await r.unlocked;
    await app.ready;
    expect(mount.querySelector('#drive-app')).not.toBeNull();
    expect(strayText(document.body)).toEqual([]);
  }, 60000);
});

describe('the Drive', () => {
  it('root content on the right; tree collapsed by default; + expands; selecting shows a folder', async () => {
    await openApp();
    expect(names()).toEqual(['Documents', 'Empty', 'Photos', 'readme.txt']);
    expect(title()).toBe('My Drive');
    expect(treeItem('My Drive').getAttribute('aria-expanded')).toBe('true');
    for (const n of ['Documents', 'Empty', 'Photos']) expect(treeItem(n).getAttribute('aria-expanded')).toBe('false');
    treeItem('Documents').querySelector('.tree-twisty').click();
    await until(() => treeItem('Reports'));
    expect(treeItem('Documents').getAttribute('aria-expanded')).toBe('true');
    expect(title()).toBe('My Drive'); // + does not navigate
    treeItem('Reports').querySelector('.tree-label').click();
    await until(() => title() === 'Reports');
    expect(names()).toEqual(['Archive', 'q1.txt']);
    expect([...document.querySelectorAll('#drive-pane .crumbs .crumb')].map((c) => c.textContent)).toEqual(['My Drive', 'Documents', 'Reports']);
    // Opening from the right pane reveals and selects in the tree.
    row('Archive').querySelector('button.drive-open').click();
    await until(() => title() === 'Archive');
    expect(treeItem('Archive').getAttribute('aria-selected')).toBe('true');
    expect(document.getElementById('drive-empty').hidden).toBe(false);
  });

  it('capacity bar', async () => {
    await openApp();
    await until(() => /used/.test(document.getElementById('drive-cap-text').textContent));
    const m = document.getElementById('drive-cap-meter');
    expect(m.tagName).toBe('METER');
    expect(document.getElementById('drive-cap-text').textContent).toMatch(/of 50 MB used/);
  });

  it('toolbar follows the selection', async () => {
    await openApp();
    const B = (k) => document.getElementById(`drive-${k}`);
    expect(B('rename').disabled && B('move').disabled && B('del').disabled && B('share').disabled && B('download').disabled).toBe(true);
    row('readme.txt').querySelector('input[type="checkbox"]').click();
    expect(B('rename').disabled).toBe(false);
    expect(B('download').textContent).toBe('Download');
    row('Photos').querySelector('input[type="checkbox"]').click();
    expect(B('rename').disabled).toBe(true);
    expect(B('download').disabled).toBe(true);
    expect(B('move').disabled).toBe(false);
    expect(document.getElementById('drive-select-all').indeterminate).toBe(true);
    expect(document.getElementById('drive-selinfo').textContent).toBe('2 selected');
  });

  it('new folder and rename (dialogs, validation, focus back); names are sealed on the wire', async () => {
    await openApp();
    const mk = document.getElementById('drive-mkdir');
    mk.focus();
    mk.click();
    const d = dialog();
    expect(d.getAttribute('aria-modal')).toBe('true');
    expect(document.getElementById(d.getAttribute('aria-labelledby')).textContent).toBe('New folder');
    expect(document.getElementById('main').inert).toBe(true);
    const input = d.querySelector('input');
    expect(document.activeElement).toBe(input);
    input.value = 'Photos';
    button(d, 'Create').click();
    await until(() => !d.querySelector('.modal-msg').hidden);
    expect(d.querySelector('.modal-msg').textContent).toMatch(/already exists/);
    input.value = 'Fresh';
    button(d, 'Create').click();
    await until(() => row('Fresh'));
    expect(dialog()).toBeNull();
    expect(document.getElementById('main').inert).toBe(false);
    expect(document.activeElement).toBe(mk);
    await until(() => treeItem('Fresh'));
    row('Fresh').querySelector('input[type="checkbox"]').click();
    document.getElementById('drive-rename').click();
    dialog().querySelector('input').value = 'Fresher';
    dialog().querySelector('input').dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    await until(() => row('Fresher'));
    await until(() => treeItem('Fresher'));
    expect(treeItem('Fresh')).toBeUndefined();
    const wire = JSON.stringify(S.requests.map((r) => r.body));
    expect(wire).not.toContain('Fresh');
  });

  it('Escape closes a dialog', async () => {
    await openApp();
    document.getElementById('drive-mkdir').click();
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    expect(dialog()).toBeNull();
  });

  it('delete asks first, then removes', async () => {
    const { app } = await openApp();
    row('Empty').querySelector('input[type="checkbox"]').click();
    document.getElementById('drive-del').click();
    expect(dialog().textContent).toMatch(/Delete “Empty”\?/);
    expect(dialog().textContent).toMatch(/cannot be undone/);
    document.getElementById('drive-delete-confirm').click();
    await until(() => !row('Empty'));
    await until(() => !treeItem('Empty'));
    expect(app.selected.size).toBe(0);
    expect(S.nodes.has(ids.get('Empty'))).toBe(false);
  });

  it('move into another folder via the picker tree', async () => {
    await openApp();
    row('readme.txt').querySelector('input[type="checkbox"]').click();
    document.getElementById('drive-move').click();
    const d = dialog();
    const picker = d.querySelector('[role="tree"]');
    await until(() => picker.querySelectorAll('.tree-item').length >= 4);
    expect(button(d, 'Move here').disabled).toBe(true); // already in My Drive
    [...picker.querySelectorAll('.tree-text')].find((t) => t.textContent === 'Photos').closest('.tree-label').click();
    expect(d.querySelector('#drive-move-target').textContent).toBe('Move to: My Drive / Photos');
    button(d, 'Move here').click();
    await until(() => !row('readme.txt'));
    expect(S.nodes.get(ids.get('readme.txt')).parent).toBe(ids.get('Photos'));
    treeItem('Photos').querySelector('.tree-label').click();
    await until(() => title() === 'Photos' && row('readme.txt'));
  });

  it('share: options, validation and the link (manifest v3, viewer snapshot); the item\'s shares with revoke', async () => {
    await openApp();
    row('readme.txt').querySelector('input[type="checkbox"]').click();
    document.getElementById('drive-share').click();
    let d = dialog();
    expect(d.querySelector('#drive-share-deletable')).not.toBeNull(); // openerDelete allowed
    expect(d.querySelector('#drive-share-label').getAttribute('aria-describedby')).toMatch(/drive-share-label-hint/);
    d.querySelector('#drive-share-views').value = '0';
    button(d, 'Create link').click();
    expect(d.querySelector('.modal-msg').textContent).toMatch(/Views must be/);
    d.querySelector('#drive-share-views').value = '2';
    d.querySelector('#drive-share-label').value = 'for Bob';
    d.querySelector('#drive-share-view').checked = true;
    button(d, 'Create link').click();
    await until(() => d.querySelector('#drive-share-url'));
    const url = d.querySelector('#drive-share-url').textContent;
    expect(url).toMatch(/\/p\/fSHARE1#/);
    expect(d.querySelector('.modal-sub').textContent).toMatch(/up to 2 times/);
    const [body] = S.shareBodies;
    expect(body).toMatchObject({ nodes: [ids.get('readme.txt')], views: 2, expire: '24h', label: 'for Bob' });
    const access = await deriveAccess({ adata: body.paste.adata, fragment: url.split('#')[1] });
    const { acc, ...paste } = body.paste;
    void acc;
    const manifest = JSON.parse((await openPaste({ paste, access })).text);
    expect(manifest).toMatchObject({ v: 3, kind: 'refs', view: { rules: [], maxBytes: 1000 } });
    expect(manifest.entries.map((e) => e.path)).toEqual(['readme.txt']);
    button(d, 'Done').click();
    expect(dialog()).toBeNull();
    button(row('readme.txt'), 'Shares').click();
    d = dialog();
    await until(() => d.querySelector('#drive-shares-table'));
    const tr = d.querySelector('#drive-shares-table tbody tr');
    expect(tr.textContent).toMatch(/for Bob/);
    expect(tr.textContent).toMatch(/2 left of 2/);
    expect(tr.textContent).toMatch(/drive/);
    const rv = button(tr, 'Revoke');
    rv.click(); // arms
    expect(rv.textContent).toMatch(/irreversible/);
    rv.click();
    await until(() => /revoked/.test(d.querySelector('#drive-shares-table tbody tr').textContent));
    expect(S.revoked).toEqual(['fSHARE1']);
  });

  it('share: the administrator\'s file-type policy applies (limits reach the client)', async () => {
    await openApp({ profile: { ...PROFILE, limits: { ...LIMITS, fileTypeMode: 'block', fileTypeRules: ['ext:txt'] } } });
    row('readme.txt').querySelector('input[type="checkbox"]').click();
    document.getElementById('drive-share').click();
    const d = dialog();
    button(d, 'Create link').click();
    await until(() => !d.querySelector('.modal-msg').hidden);
    expect(d.querySelector('.modal-msg').textContent).toMatch(/does not allow/);
    expect(S.shareBodies).toHaveLength(0);
  });

  it('upload files into the open folder, with progress', async () => {
    await openApp();
    treeItem('Photos').querySelector('.tree-label').click();
    await until(() => title() === 'Photos');
    const input = document.getElementById('drive-file-input');
    Object.defineProperty(input, 'files', { configurable: true, value: [new File(['hello'], 'hi.txt', { type: 'text/plain' })] });
    input.dispatchEvent(new Event('change'));
    await until(() => row('hi.txt'));
    expect(document.querySelector('.drive-transfer .progress-label').textContent).toMatch(/Uploading hi\.txt: done/);
    const put = S.requests.find((r) => r.method === 'PUT' && r.path.includes('/chunk/'));
    expect(put.body.length).toBe(5 + TAG);
    const node = [...S.nodes.values()].find((n) => n.kind === 'file' && n.parent === ids.get('Photos') && n.size === 5);
    expect(node.state).toBe('ready');
  });

  it('an uploaded name already in the folder gets " (2)", " (3)"…', async () => {
    await openApp();
    const input = document.getElementById('drive-file-input');
    Object.defineProperty(input, 'files', { configurable: true, value: [new File(['a'], 'readme.txt'), new File(['b'], 'readme.txt'), new File(['c'], 'Photos')] });
    input.dispatchEvent(new Event('change'));
    await until(() => row('readme (3).txt'));
    expect(names()).toEqual(['Documents', 'Empty', 'Photos', 'Photos (2)', 'readme (2).txt', 'readme (3).txt', 'readme.txt']);
  });

  it('download a file (decrypted in the browser), with progress', async () => {
    await openApp();
    let saved = null;
    vi.spyOn(URL, 'createObjectURL').mockImplementation((b) => { saved = b; return 'blob:x'; });
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function click() { saved.name = this.download; });
    row('readme.txt').querySelector('input[type="checkbox"]').click();
    document.getElementById('drive-download').click();
    await until(() => /done/.test(document.querySelector('.drive-transfer .progress-label')?.textContent || ''));
    expect(saved.name).toBe('readme.txt');
    expect(new TextDecoder().decode(new Uint8Array(await saved.arrayBuffer()))).toBe('Welcome to the Drive.\n');
  });

  it('names are shown as text, never markup', async () => {
    await openApp();
    document.getElementById('drive-mkdir').click();
    dialog().querySelector('input').value = '<img src=x onerror=alert(1)>';
    button(dialog(), 'Create').click();
    await until(() => row('<img src=x onerror=alert(1)>'));
    expect(document.querySelector('#drive-app img')).toBeNull();
  });
});

describe('the client\'s progress and cancel for downloads', () => {
  it('download(id, { onProgress, signal }) reports (bytesDone, total) and stops on abort', async () => {
    await server();
    const c = await drive.openDrive({ user: S.user });
    const seen = [];
    const blob = await (await c.download(ids.get('readme.txt'), { onProgress: (d, t) => seen.push([d, t]) })).blob();
    expect(await blob.text()).toBe('Welcome to the Drive.\n');
    expect(seen).toEqual([[0, 22], [22, 22]]);
    const ctl = new AbortController();
    ctl.abort();
    await expect((await c.download(ids.get('readme.txt'), { signal: ctl.signal })).blob()).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('uploadTree: names that clash get " (2)"; existing folders are merged into, a file of a folder\'s name is not', async () => {
    await server();
    const c = await drive.openDrive({ user: S.user });
    const f = (n, t = 'x') => new File([t], n);
    await c.uploadTree('root', [
      { path: 'Documents/notes.md', file: f('notes.md') },
      { path: 'Documents/new.txt', file: f('new.txt') },
      { path: 'readme.txt/inner.txt', file: f('inner.txt') },
    ]);
    const top = await c.list('root');
    expect(top.children.map((x) => x.name)).toEqual(['Documents', 'Empty', 'Photos', 'readme (2).txt', 'readme.txt']);
    expect(top.children.find((x) => x.name === 'readme (2).txt').kind).toBe('dir');
    const docs = await c.list(ids.get('Documents'));
    expect(docs.children.map((x) => x.name)).toEqual(['Reports', 'new.txt', 'notes (2).md', 'notes.md']);
  });

  it('openDrive\'s DriveLocked names the passkeys that can unlock', async () => {
    await server({ locked: true });
    const w = await wrapPrf(dk, randomBytes(32), 'cred-9');
    S.wraps.set(`${w.kind}|${w.ref}`, w);
    await expect(drive.openDrive({ user: S.user })).rejects.toMatchObject({ name: 'DriveLocked', reason: 'locked', credentialIds: ['cred-9'] });
  });
});

describe('nav: Drive link', () => {
  it('driveAllowed reads caps.driveEnabled', async () => {
    vi.resetModules();
    vi.doMock('../public/js/api.js', () => ({ me: () => new Promise(() => {}), logout: async () => {}, admin: {}, ApiError: class extends Error {} }));
    const { driveAllowed } = await import('../public/dashboard/js/nav.js');
    expect(driveAllowed({ caps: { driveEnabled: true } })).toBe(true);
    expect(driveAllowed({ caps: { driveEnabled: 1 } })).toBe(false);
    expect(driveAllowed({ caps: {} })).toBe(false);
    expect(driveAllowed({})).toBe(false);
    vi.doUnmock('../public/js/api.js');
  });
});
