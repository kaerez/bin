// drive.test.js — the Drive page logic (public/dashboard/js/drive-app.js)
// against the temporary in-memory client (public/js/driveclient.mock.js):
// disabled / locked / open states, the tree + right pane, the dialogs (new
// folder, rename, delete, share, an item's shares with revoke), plus the pure
// helpers and the nav's Drive switch.
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { startDrive, checkName, shareOptions, toFraction, modifiedOf, pathOf, sortChildren, successNote } from '../public/dashboard/js/drive-app.js';

const until = async (fn, ms = 3000) => {
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
const PROFILE = { limits: { maxViews: 100, allowUnlimitedViews: true, maxExpireSec: null, openerDelete: true, files: true }, caps: {} };

async function freshMock() {
  vi.resetModules();
  return import('../public/js/driveclient.mock.js');
}

async function openApp(extra = {}) {
  const drive = await freshMock();
  sessionStorage.setItem('secbin_mock_dk', '1');
  const mount = document.createElement('div');
  document.body.replaceChildren(document.createElement('main'), mount);
  document.body.firstChild.id = 'main';
  const revoked = [];
  const r = await startDrive(mount, { drive, profile: PROFILE, revoke: async (id) => { revoked.push(id); return drive.revokeShare(id); }, ...extra });
  await r.app.ready;
  return { ...r, drive, mount, revoked };
}

beforeEach(() => { document.body.replaceChildren(); try { sessionStorage.clear(); } catch { /* */ } });

describe('pure helpers', () => {
  it('checkName', () => {
    expect(checkName('  a.txt ')).toEqual({ name: 'a.txt' });
    expect(checkName('')).toHaveProperty('error');
    expect(checkName('a/b').error).toMatch(/cannot contain/);
    expect(checkName('a\\b').error).toMatch(/cannot contain/);
    expect(checkName('a\u0001').error).toMatch(/control/);
    expect(checkName('..').error).toMatch(/reserved/);
    expect(checkName('x'.repeat(256)).error).toMatch(/255/);
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

  it('toFraction, modifiedOf, sortChildren, pathOf, successNote', () => {
    expect(toFraction(0.5)).toBe(0.5);
    expect(toFraction(7)).toBe(1);
    expect(toFraction({ loaded: 1, total: 4 })).toBe(0.25);
    expect(toFraction({ done: 3, total: 0 })).toBe(0);
    expect(toFraction(undefined)).toBe(0);
    expect(modifiedOf({ kind: 'file', mtime: 1700000000000 })).toBe(1700000000);
    expect(modifiedOf({ kind: 'dir', updated: 1700000000 })).toBe(1700000000);
    expect(sortChildren([{ kind: 'file', name: 'a' }, { kind: 'dir', name: 'z' }, { kind: 'dir', name: 'b' }]).map((c) => c.name)).toEqual(['b', 'z', 'a']);
    expect(pathOf({ node: { id: 'x', name: 'X' }, path: [{ id: 'root', name: '' }] })).toEqual([{ id: 'root', name: '' }, { id: 'x', name: 'X' }]);
    expect(pathOf({ node: { id: 'root', name: '' }, path: [] })).toEqual([{ id: 'root', name: '' }]);
    expect(successNote({ views: 1, expiryText: '1 hour', what: 'the file' })).toMatch(/open the file once/);
  });
});

describe('startDrive states', () => {
  it('disabled: says Drive is not enabled', async () => {
    const drive = await freshMock();
    const mount = document.createElement('div');
    document.body.append(mount);
    const r = await startDrive(mount, { drive: { ...drive, openDrive: async () => { throw new drive.DriveDisabled(); } }, profile: PROFILE, revoke: async () => {} });
    expect(r.state).toBe('disabled');
    expect(mount.textContent).toMatch(/Drive is not enabled for your account/);
  });

  it('other errors are shown as an alert', async () => {
    const drive = await freshMock();
    const mount = document.createElement('div');
    const r = await startDrive(mount, { drive: { ...drive, openDrive: async () => { throw new Error('boom'); } }, profile: PROFILE, revoke: async () => {} });
    expect(r.state).toBe('error');
    expect(mount.querySelector('[role="alert"]').textContent).toMatch(/boom/);
  });

  it('locked: the unlock prompt; a wrong password is refused, a recovery code unlocks', async () => {
    const drive = await freshMock();
    const mount = document.createElement('div');
    document.body.append(mount);
    const r = await startDrive(mount, { drive, profile: PROFILE, revoke: async () => {} });
    expect(r.state).toBe('locked');
    const pw = mount.querySelector('#drive-unlock-pw');
    expect(pw.type).toBe('password');
    expect(mount.querySelector(`label[for="drive-unlock-pw"]`)).not.toBeNull();
    pw.value = 'wrong';
    mount.querySelector('#drive-pw-form').dispatchEvent(new Event('submit', { cancelable: true }));
    await until(() => !mount.querySelector('#drive-unlock-msg').hidden);
    expect(mount.querySelector('#drive-unlock-msg').textContent).toMatch(/did not unlock/);
    expect(pw.getAttribute('aria-invalid')).toBe('true');
    mount.querySelector('#drive-code-toggle').click();
    expect(mount.querySelector('#drive-code-form').hidden).toBe(false);
    mount.querySelector('#drive-unlock-code').value = 'AAAA-BBBB';
    mount.querySelector('#drive-code-form').dispatchEvent(new Event('submit', { cancelable: true }));
    const app = await r.unlocked;
    await app.ready;
    expect(mount.querySelector('#drive-app')).not.toBeNull();
    expect(pw.value).toBe('');
  });
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

  it('new folder and rename (dialogs, validation, focus back)', async () => {
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
  });

  it('Escape closes a dialog', async () => {
    await openApp();
    document.getElementById('drive-mkdir').click();
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    expect(dialog()).toBeNull();
  });

  it('delete asks first, then removes (and its shares end)', async () => {
    const { app } = await openApp();
    row('Empty').querySelector('input[type="checkbox"]').click();
    document.getElementById('drive-del').click();
    expect(dialog().textContent).toMatch(/Delete “Empty”\?/);
    expect(dialog().textContent).toMatch(/cannot be undone/);
    document.getElementById('drive-delete-confirm').click();
    await until(() => !row('Empty'));
    await until(() => !treeItem('Empty'));
    expect(app.selected.size).toBe(0);
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
    treeItem('Photos').querySelector('.tree-label').click();
    await until(() => title() === 'Photos' && row('readme.txt'));
  });

  it('share: options, validation and the link; the item\'s shares with revoke', async () => {
    const { revoked } = await openApp();
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
    button(d, 'Create link').click();
    await until(() => d.querySelector('#drive-share-url'));
    expect(d.querySelector('#drive-share-url').textContent).toMatch(/\/p\/fMOCK/);
    expect(d.querySelector('.modal-sub').textContent).toMatch(/up to 2 times/);
    button(d, 'Done').click();
    expect(dialog()).toBeNull();
    button(row('readme.txt'), 'Shares').click();
    d = dialog();
    await until(() => d.querySelector('#drive-shares-table'));
    const tr = d.querySelector('#drive-shares-table tbody tr');
    expect(tr.textContent).toMatch(/for Bob/);
    expect(tr.textContent).toMatch(/2 left of 2/);
    const rv = button(tr, 'Revoke');
    rv.click(); // arms
    expect(rv.textContent).toMatch(/irreversible/);
    rv.click();
    await until(() => /revoked/.test(d.querySelector('#drive-shares-table tbody tr').textContent));
    expect(revoked).toHaveLength(1);
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

describe('nav: Drive link', () => {
  it('driveAllowed reads caps.driveEnabled (and caps.drive)', async () => {
    vi.resetModules();
    vi.doMock('../public/js/api.js', () => ({ me: () => new Promise(() => {}), logout: async () => {}, admin: {}, ApiError: class extends Error {} }));
    const { driveAllowed } = await import('../public/dashboard/js/nav.js');
    expect(driveAllowed({ caps: { driveEnabled: true } })).toBe(true);
    expect(driveAllowed({ caps: { drive: { enabled: true } } })).toBe(true);
    expect(driveAllowed({ caps: { drive: true } })).toBe(true);
    expect(driveAllowed({ caps: {} })).toBe(false);
    expect(driveAllowed({})).toBe(false);
    vi.doUnmock('../public/js/api.js');
  });
});
