// receive-api.test.js — Receive links in the browser (docs/REVERSE.md §8):
// the Drive's "Receive…" waits for the open folder to list; the Edit form's
// folder choice (a tree of the Drive's folders, the role's folder depth, what
// it sends; the folder's lists follow the move); Pause / Resume in the
// Drive's lists; the receipts' wording for upload sessions. Synthetic data only.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { startDrive } from '../public/dashboard/js/drive-app.js';
import { reverseEditForm, reverseEditPatch, folderPathText } from '../public/dashboard/js/reverse-edit.js';
import { opensButton } from '../public/dashboard/js/receipts.js';
import * as drive from '../public/js/driveclient.js';
import { setReverseStretcher, createReverseKey, newReverseId } from '../public/js/reversekeys.js';
import { clearSessionKey, clearImpersonationKeys, sealLinkKey } from '../public/js/drivekeys.js';
import { hkdf32 } from '../public/js/crypto.js';
import { utf8 } from '../public/js/bytes.js';
import { revokeShare } from '../public/js/api.js';
import { fakeServer, seedTree } from './drive-fake-server.js';

setReverseStretcher(async (pw, salt) => hkdf32(pw, salt, utf8('dom-stretch')));

const until = async (fn, ms = 5000) => {
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
const dialog = () => document.querySelector('.drive-dialog [role="dialog"]');
const now = () => Math.floor(Date.now() / 1000);

beforeEach(() => { document.body.replaceChildren(); clearSessionKey(); clearImpersonationKeys(); });
afterEach(() => { vi.restoreAllMocks(); });

let S;
let ids;
async function server(tree = { Documents: { Taxes: {} }, Photos: {} }) {
  S = fakeServer({ capacity: 50 * 1024 * 1024 });
  globalThis.fetch = S.fetch;
  ids = await seedTree(S, tree);
  return S;
}
const BASE = { maxViews: 100, allowUnlimitedViews: true, maxExpireSec: null, files: true, reverseMaxBytes: 1024 ** 3 };
const profileWith = (limits) => ({ limits: { ...BASE, ...limits }, caps: { driveEnabled: true, reverseEnabled: true }, viewer: { enabled: false } });
function mountPoint() {
  const mount = document.createElement('div');
  document.body.replaceChildren(document.createElement('main'), mount);
  document.body.firstChild.id = 'main';
  return mount;
}
const confirm = async (input) => ({ current: `proof:${input.value}` });
const deps = (profile) => ({ drive, profile, user: S.user, confirm, canUsePasskey: async () => false, revoke: revokeShare });
/** A Receive link on `folder` (a path of the seeded tree, or root), as the server lists it. */
async function seedLink(folder = 'root', extra = {}) {
  const id = newReverseId();
  const { privateKey } = await createReverseKey();
  const mek = S.current().id;
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey));
  const priv = await sealLinkKey(await S.kekOf(mek), { userId: S.user.id, mekId: mek, linkId: id }, pkcs8);
  S.reverse.push({ id, folder: folder === 'root' ? 'root' : ids.get(folder), label: 'inbox', priv, mek, status: 'active', files: 0, bytes: 0, created: now() - 60, expires: now() + 86400, views: null, used: 0, ...extra });
  return id;
}
const treeItem = (root, name) => [...root.querySelectorAll('[role="treeitem"]')].find((li) => li.querySelector(':scope > .tree-label .tree-text')?.textContent === name);

describe('Drive: "Receive…" waits for the open folder', () => {
  it('stays disabled until the folder has listed, so the dialog always names it', async () => {
    await server();
    // Hold the first listing of the top folder back.
    let release;
    const held = new Promise((r) => { release = r; });
    const real = S.fetch;
    let first = true;
    globalThis.fetch = async (url, init) => {
      if (first && new URL(url, 'https://x').pathname === '/api/private/drive/nodes/root') { first = false; await held; }
      return real(url, init);
    };
    const r = await startDrive(mountPoint(), deps(profileWith({})));
    await until(() => $('#drive-receive'));
    const rec = $('#drive-receive');
    expect(rec.hidden).toBe(false);
    expect(rec.disabled).toBe(true);
    rec.click(); // a click on a disabled button does nothing; nor does a stray call
    expect(dialog()).toBeNull();
    release();
    await r.app.ready;
    await until(() => !rec.disabled);
    rec.click();
    await until(() => dialog());
    expect(dialog().querySelector('.modal-title').textContent).toBe('Receive into “My Drive”');
  });
});

describe('the Edit form: the folder it receives into', () => {
  const cur = { id: 'r1', folder: 'root', expires: now() + 86400, views: null, used: 0, maxFiles: null, maxBytes: null, maxFileBytes: null, types: null, captcha: false, password: false, note: false };
  const listing = {
    root: { path: [{ id: 'root', name: null }], children: [{ id: 'A'.repeat(22), kind: 'dir', name: 'Invoices' }, { id: 'F'.repeat(22), kind: 'file', name: 'x.txt' }] },
    [`${'A'.repeat(22)}`]: { path: [{ id: 'root', name: null }, { id: 'A'.repeat(22), name: 'Invoices' }], children: [{ id: 'B'.repeat(22), kind: 'dir', name: '2026' }] },
    [`${'B'.repeat(22)}`]: { path: [{ id: 'root', name: null }, { id: 'A'.repeat(22), name: 'Invoices' }, { id: 'B'.repeat(22), name: '2026' }], children: [] },
  };
  const folders = { list: vi.fn(async (id) => listing[id]) };

  it('no folder section without the Drive’s folders; with them, a labelled group, the tree on demand, a choice announced and undone', async () => {
    document.body.replaceChildren(reverseEditForm(cur, profileWith({})).el);
    expect(document.querySelector('.rev-edit-folder')).toBeNull();
    const f = reverseEditForm(cur, profileWith({}), { folders });
    document.body.replaceChildren(f.el);
    const box = document.querySelector('fieldset.rev-edit-folder');
    expect(box.querySelector('legend').textContent).toBe('Folder it receives into');
    const toggle = button(box, 'Choose another folder…');
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    expect(document.getElementById(toggle.getAttribute('aria-controls')).hidden).toBe(true);
    expect(folders.list).not.toHaveBeenCalled(); // nothing read until asked
    toggle.click();
    expect(toggle.getAttribute('aria-expanded')).toBe('true');
    const tree = await until(() => box.querySelector('[role="tree"]'));
    expect(tree.getAttribute('aria-label')).toBe('Folder to receive into');
    await until(() => box.querySelector('[id$="-folder-now"]').textContent === 'Uploads go to: My Drive.');
    // Only folders are offered.
    await until(() => treeItem(box, 'Invoices'));
    expect(treeItem(box, 'x.txt')).toBeUndefined();
    treeItem(box, 'Invoices').querySelector('.tree-label').click();
    const picked = box.querySelector('[id$="-folder-new"]');
    expect(picked.getAttribute('aria-live')).toBe('polite');
    expect(picked.textContent).toBe('New folder: My Drive / Invoices');
    expect(f.read().patch).toEqual({ folder: 'A'.repeat(22) });
    // Keep the current folder: the choice is undone, nothing to change.
    button(box, 'Keep the current folder').click();
    expect(f.read()).toMatchObject({ error: 'Nothing to change.' });
    expect(document.activeElement).toBe(toggle);
    // The current folder again: not a change either.
    treeItem(box, 'My Drive').querySelector('.tree-label').click();
    expect(picked.textContent).toMatch(/receives into now/);
    expect(f.read()).toMatchObject({ error: 'Nothing to change.' });
  });

  it('refuses a folder deeper than the role’s folder depth before anything is sent', async () => {
    const f = reverseEditForm(cur, profileWith({ maxFolderDepth: 1 }), { folders });
    document.body.replaceChildren(f.el);
    button(document.body, 'Choose another folder…').click();
    const inv = await until(() => treeItem(document.body, 'Invoices'));
    inv.querySelector('.tree-twisty').click();
    await until(() => treeItem(document.body, '2026'));
    treeItem(document.body, '2026').querySelector('.tree-label').click();
    const o = f.read();
    expect(o).toMatchObject({ field: 'folder' });
    expect(o.error).toMatch(/at most 1 level deep/);
    expect(f.field('folder')).toBe(button(document.body, 'Choose another folder…'));
    // One level is fine.
    treeItem(document.body, 'Invoices').querySelector('.tree-label').click();
    expect(f.read().patch).toEqual({ folder: 'A'.repeat(22) });
  });

  it('reverseEditPatch: a folder only when it differs, and within the depth', () => {
    const v = (x) => ({ unlimited: true, ...x });
    expect(reverseEditPatch(v({ folder: 'root', folderDepth: 0 }), cur, {}).error).toBe('Nothing to change.');
    expect(reverseEditPatch(v({ folder: 'X'.repeat(22), folderDepth: 3 }), cur, { maxFolderDepth: 2 }).field).toBe('folder');
    expect(reverseEditPatch(v({ folder: 'X'.repeat(22), folderDepth: 2 }), cur, { maxFolderDepth: 2 }).patch).toEqual({ folder: 'X'.repeat(22) });
    expect(reverseEditPatch(v({ folder: 'X'.repeat(22), folderDepth: 9 }), cur, {}).patch).toEqual({ folder: 'X'.repeat(22) });
    expect(folderPathText([{ id: 'root' }, { id: 'a', name: 'Tax' }, { id: 'b', name: '' }])).toBe('My Drive / Tax / (unnamed)');
  });
});

describe('Drive: moving a link from its Edit, and the folders’ Shares', () => {
  it('Edit → "Choose another folder…" sends the folder; the old folder’s Shares no longer list it, the new one’s do', async () => {
    await server();
    const id = await seedLink('Documents');
    const r = await startDrive(mountPoint(), deps(profileWith({})));
    await r.app.ready;
    document.body.appendChild(Object.assign(document.createElement('div'), { id: 'toast' }));
    const shares = async (name) => {
      const tr = [...document.querySelectorAll('#drive-rows tr')].find((x) => x.children[1].textContent.trim() === name);
      button(tr, 'Shares').click();
      await until(() => dialog()?.querySelector('#drive-shares-table, #drive-shares-empty'));
      return dialog();
    };
    const close = async () => { dialog().dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true })); await until(() => !dialog()); };
    let d = await shares('Documents');
    const row = d.querySelector('#drive-shares-table tbody tr');
    expect(row.dataset.kind).toBe('reverse');
    button(row, 'Edit').click();
    await until(() => dialog().querySelector('.rev-edit'));
    const box = dialog().querySelector('fieldset.rev-edit-folder');
    button(box, 'Choose another folder…').click();
    await until(() => box.querySelector('[id$="-folder-now"]').textContent === 'Uploads go to: My Drive / Documents.');
    await until(() => treeItem(box, 'Photos'));
    treeItem(box, 'Photos').querySelector('.tree-label').click();
    expect(box.querySelector('[id$="-folder-new"]').textContent).toBe('New folder: My Drive / Photos');
    button(dialog(), 'Save changes').click();
    await until(() => S.patches?.length);
    expect(S.patches.at(-1)).toEqual({ id, body: { folder: ids.get('Photos') } });
    await until(() => !dialog());
    expect($('#toast').textContent).toMatch(/receives into the folder you chose/);
    d = await shares('Documents');
    expect(d.querySelector('#drive-shares-empty')).not.toBeNull();
    await close();
    d = await shares('Photos');
    expect(d.querySelector('#drive-shares-table tbody tr').dataset.kind).toBe('reverse');
    await close();
  });
});

describe('Drive: Pause and Resume', () => {
  it('the Receive… list pauses a link (with the intent header) and resumes it; Edit stays for a link the user paused, not one the owner’s start over paused', async () => {
    await server();
    const id = await seedLink('root');
    const r = await startDrive(mountPoint(), deps(profileWith({})));
    await r.app.ready;
    $('#drive-receive').click();
    await until(() => $('#drive-rev-table'));
    const row = () => $('#drive-rev-table tbody tr');
    const pause = button(row(), 'Pause');
    expect(pause.getAttribute('aria-label')).toBe('Pause inbox');
    pause.click();
    await until(() => row()?.dataset.status === 'paused');
    expect(S.pauses).toEqual([{ id, on: true, intent: '1' }]);
    expect(button(row(), 'Resume')).toBeTruthy();
    expect(button(row(), 'Edit')).toBeTruthy();
    expect(button(row(), 'Revoke')).toBeTruthy();
    expect(row().querySelector('td[data-label="Status"]').textContent).toMatch(/^paused/);
    // Resume reopens it: the dialog asks for the account password first (a weakening change).
    button(row(), 'Resume').click();
    await until(() => dialog().querySelector('.modal-title').textContent === 'Resume “inbox”');
    const pw = dialog().querySelector('input[type="password"][id$="-confirm"]');
    expect(document.querySelector(`label[for="${pw.id}"]`).textContent).toMatch(/Your account password/);
    expect(document.activeElement).toBe(pw);
    expect(S.pauses).toHaveLength(1); // nothing sent yet
    pw.value = 'acct pw';
    button(dialog(), 'Resume').click();
    await until(() => S.pauses.length === 2);
    expect(S.pauses.at(-1)).toEqual({ id, on: false, intent: '1', body: { current: 'proof:acct pw' } });
    await until(() => !dialog());
    // A link the owner's start over paused in the release before (not the user): Revoke only.
    await seedLink('root', { status: 'paused', held: false, label: 'old' });
    $('#drive-receive').click();
    await until(() => $('#drive-rev-table')?.querySelectorAll('tbody tr').length === 2);
    const old = [...$('#drive-rev-table').querySelectorAll('tbody tr')].find((tr) => tr.children[0].textContent === 'old');
    expect(button(old, 'Revoke')).toBeTruthy();
    for (const t of ['Resume', 'Pause', 'Edit', 'Copy link']) expect(button(old, t), t).toBeUndefined();
  });
});

describe('Drive: Resume while the owner acts as the user', () => {
  it('asks for nothing and sends no confirmation', async () => {
    await server();
    const id = await seedLink('root', { status: 'paused', held: true });
    const r = await startDrive(mountPoint(), { ...deps(profileWith({})), user: { ...S.user, impersonating: true } });
    await r.app.ready;
    $('#drive-receive').click();
    await until(() => $('#drive-rev-table'));
    button($('#drive-rev-table tbody tr'), 'Resume').click();
    await until(() => dialog().querySelector('.modal-title').textContent === 'Resume “inbox”');
    expect(dialog().querySelector('input[type="password"][id$="-confirm"]').closest('.dfield').hidden).toBe(true);
    button(dialog(), 'Resume').click();
    await until(() => S.pauses?.length === 1);
    expect(S.pauses[0]).toEqual({ id, on: false, intent: '1', body: {} });
  });
});

describe('receipts of a Receive link', () => {
  it('count upload sessions, and say so', async () => {
    const tr = document.createElement('tr');
    const table = document.createElement('table');
    const tb = document.createElement('tbody');
    tb.appendChild(tr);
    table.appendChild(tb);
    document.body.replaceChildren(table);
    const b = opensButton({ opens: 2 }, async () => ({ total: 2, fields: [], rows: [{ ts: 1700000000 }, { ts: 1700000100 }] }), 8, tr, { receive: true });
    tr.appendChild(document.createElement('td')).appendChild(b);
    expect(b.textContent).toBe('2 upload sessions');
    b.click();
    await until(() => document.querySelector('.opens-row table'));
    const t = document.querySelector('.opens-row table');
    expect(t.getAttribute('aria-label')).toBe('Upload sessions of this link');
    expect(t.querySelector('th').textContent).toBe('Started at');
    expect(document.querySelector('.opens-row').textContent).toMatch(/Only the time of each upload session is shown/);
    expect(b.getAttribute('aria-expanded')).toBe('true');
    // A regular share keeps its words.
    const one = opensButton({ opens: 1 }, async () => ({ total: 0, fields: [], rows: [] }), 8, tr);
    expect(one.textContent).toBe('1 open');
  });
});
