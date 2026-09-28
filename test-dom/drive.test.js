// drive.test.js — the Drive page (public/dashboard/js/drive-app.js) with the
// real Drive client (public/js/driveclient.js) against the in-memory §6 API
// behind a mocked fetch (drive-fake-server.js): disabled / unavailable / open
// states (the Drive opens with no prompt: the server hands the session its
// keys), the owner acting as the user, the upgrade notice of a Drive made
// before the key model v2, the tree + right pane, the dialogs (new folder,
// rename, move, delete, share, an item's shares with revoke), upload and
// download, plus the pure helpers and the nav's Drive switch.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { startDrive, checkName, shareOptions, toFraction, modifiedOf, pathOf, sortChildren, successNote } from '../public/dashboard/js/drive-app.js';
import * as drive from '../public/js/driveclient.js';
import { clearSessionKey } from '../public/js/drivekeys.js';
import { deriveAccess, openPaste } from '../public/js/crypto.js';
import { TAG } from '../public/js/files.js';
import { fakeServer, seedTree } from './drive-fake-server.js';
import { revokeShare } from '../public/js/api.js';

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
const enc = (s) => new TextEncoder().encode(s);
const TREE = {
  Documents: { Reports: { 'q1.txt': enc('Q1 numbers\n'), Archive: {} }, 'notes.md': enc('# Notes\nhello\n') },
  Photos: { 'cat.png': new Uint8Array(2048) },
  Empty: {},
  'readme.txt': enc('Welcome to the Drive.\n'),
};

let S;
let ids;

/** A server holding TREE, sealed under the user's current KEK. */
async function server({ capacity = 50 * 1024 * 1024 } = {}) {
  S = fakeServer({ capacity });
  globalThis.fetch = S.fetch;
  ids = await seedTree(S, TREE);
  return S;
}

function mountPoint() {
  const mount = document.createElement('div');
  document.body.replaceChildren(document.createElement('main'), mount);
  document.body.firstChild.id = 'main';
  return mount;
}

// `revoke` as the page passes it (drive.js): api.js, which sends the session's CSRF token.
const deps = (extra = {}) => ({ drive, profile: PROFILE, user: S.user, revoke: revokeShare, ...extra });

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
    // Security audit F1: a view-limited share says that downloads can outlast the last view (up to 10 more windows).
    expect(successNote({ views: 3, expiryText: '1 day', what: 'the files' })).toMatch(/After the last view, the recipient can still download while their download window is open, and can keep it open up to 10 more times, never past the expiry\./);
    expect(successNote({ views: 1, expiryText: '1 day', what: 'the file' })).toMatch(/up to 10 more times/);
    expect(successNote({ views: null, expiryText: '1 day', what: 'the file' })).not.toMatch(/last view/);
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

  it('a notice instead of the Drive (disabled, the keys cannot be had): the page’s status line announces its title (WCAG 4.1.3); the notice is content with a heading', async () => {
    const withStatusLine = () => {
      const mount = mountPoint();
      const live = document.createElement('p');
      live.className = 'msg';
      live.setAttribute('role', 'status');
      live.textContent = 'Opening your Drive…';
      mount.append(live); // as in /dashboard/drive/: in the page from the start
      return { mount, live };
    };
    // (The release before also had "not ready yet" and "no Drive while impersonating": the key model v2 has neither.)
    const cases = [
      ['disabled', () => { S = fakeServer({ enabled: false }); }, {}, '#drive-disabled', 'Drive is not enabled for your account'],
      ['unavailable', () => { S = fakeServer(); S.keysError = 'salt_missing'; }, {}, '#drive-unavailable', 'Your Drive cannot be opened right now'],
      ['unavailable', () => { S = fakeServer(); S.keysError = 'keys_missing'; S.impersonatedBy = 'owner'; }, { impersonating: true }, '#drive-unavailable', 'Your Drive cannot be opened right now'],
    ];
    for (const [state, make, user, sel, said] of cases) {
      make();
      globalThis.fetch = S.fetch;
      const { mount, live } = withStatusLine();
      const r = await startDrive(mount, deps({ user: { ...S.user, ...user } }));
      expect(r.state).toBe(state);
      // The same live region (never replaced), now visually hidden, says the notice's title.
      expect(mount.querySelector('[role="status"]')).toBe(live);
      expect(live.isConnected && live.className).toBe('sr-only');
      expect(live.textContent).toBe(said);
      const card = mount.querySelector(sel);
      expect(card.getAttribute('role')).toBeNull();
      expect(card.querySelector('h2').textContent).toBe(said);
      // Nothing is created: the one change is the request for the session's keys (a POST, refused here).
      expect(S.requests.filter((x) => x.method !== 'GET').map((x) => x.path).filter((x) => x !== '/api/private/drive/keys')).toEqual([]);
    }
    // What a user reads calls the owner "the administrator", as the other notices do.
    {
      S = fakeServer();
      S.keysError = 'keys_missing';
      globalThis.fetch = S.fetch;
      const mount = mountPoint();
      await startDrive(mount, deps());
      const text = mount.querySelector('#drive-unavailable').textContent;
      expect(text).toMatch(/The administrator restores them/);
      expect(text).not.toMatch(/\bowner\b/);
    }
  });

  it('a personal kit out of date (the keys changed after the last download): a calm notice with no key detail, a link to Account; none while the owner acts as the user', async () => {
    // Never downloaded, or downloaded with the keys as they are: no notice.
    let { mount } = await openApp();
    expect(mount.querySelector('#drive-kit-notice')).toBeNull();
    S.userKit = { at: 1, v: S.keyVersion.n, meks: [S.current().id] };
    mount = mountPoint();
    await (await startDrive(mount, deps())).app.ready;
    expect(mount.querySelector('#drive-kit-notice')).toBeNull();
    // The owner rotates (the key version goes up): the notice.
    await S.addSub({ from: Math.floor(Date.now() / 1000) - 10 });
    mount = mountPoint();
    await (await startDrive(mount, deps())).app.ready;
    const n = mount.querySelector('#drive-kit-notice');
    expect(n.getAttribute('role')).toBe('note');
    expect(n.textContent).toMatch(/^Your Drive’s keys were updated\. Download a new personal kit and keep it safe\./);
    expect(n.querySelector('a').getAttribute('href')).toBe('/dashboard/account/#drive-kit');
    for (const sub of S.subs) expect(n.textContent).not.toContain(sub.fp);
    expect(n.textContent).not.toMatch(/MEK|KEK|fingerprint|version \d/i);
    // The owner acting as the user: the kit is the user's own, no notice (and nothing it could do).
    S.impersonatedBy = 'owner';
    mount = mountPoint();
    await (await startDrive(mount, deps({ user: { ...S.user, impersonating: true } }))).app.ready;
    expect(mount.querySelector('#drive-kit-notice')).toBeNull();
    expect(mount.querySelector('#drive-imp-note')).not.toBeNull();
  });

  it('other errors are shown as an alert', async () => {
    S = fakeServer();
    globalThis.fetch = vi.fn(async () => ({ ok: false, status: 500, type: 'basic', json: async () => ({ error: 'boom', message: 'boom' }) }));
    const mount = mountPoint();
    const r = await startDrive(mount, deps());
    expect(r.state).toBe('error');
    expect(mount.querySelector('[role="alert"]').textContent).toMatch(/boom/);
  });

  it('opens with no prompt: no password, no set-up, no unlock screen', async () => {
    await server();
    const mount = mountPoint();
    const r = await startDrive(mount, deps());
    expect(r.state).toBe('open');
    await r.app.ready;
    expect(mount.querySelector('#drive-unlock')).toBeNull();
    expect(mount.querySelector('input[type="password"]')).toBeNull();
    expect(names()).toEqual(['Documents', 'Empty', 'Photos', 'readme.txt']);
    expect(sessionStorage.length).toBe(0); // the keys are in the page's memory only
    // Nothing but the session's keys is asked for (a POST: it may make the salt and is audited).
    expect(S.requests.filter((x) => x.method !== 'GET').map((x) => `${x.method} ${x.path}`)).toEqual(['POST /api/private/drive/keys']);
  });

  it('keys that cannot be had: what happened and who fixes it (the salt and the keyring: the administrator, from a kit)', async () => {
    await server();
    S.keysError = 'salt_missing';
    let mount = mountPoint();
    let r = await startDrive(mount, deps());
    expect(r).toEqual({ state: 'unavailable', reason: 'salt_missing' });
    expect(mount.querySelector('#drive-unavailable p.msg').textContent).toMatch(/user salt.*administrator puts it back from your personal kit/);
    // A user cannot restore it: no way to a restore of their own (the Account page has none).
    expect(mount.querySelector('#drive-unavailable a[href="/dashboard/account/#drive-kit"]')).toBeNull();
    expect(mount.querySelector('#drive-unavailable').textContent).not.toMatch(/Account → Drive personal kit → Restore/);
    S.keysError = 'keys_missing';
    mount = mountPoint();
    r = await startDrive(mount, deps({ user: { ...S.user, role: 'owner' } }));
    expect(r.reason).toBe('keys_missing');
    expect(mount.querySelector('#drive-unavailable').textContent).toMatch(/key kit/);
    expect(mount.querySelector('#drive-unavailable a[href="/dashboard/admin/#keys"]')).not.toBeNull();
  });

  it('the owner acting as the user: the user’s Drive opens as it is, with a note that the keys use is recorded', async () => {
    await server();
    S.impersonatedBy = 'owner';
    const mount = mountPoint();
    const r = await startDrive(mount, deps({ user: { ...S.user, impersonating: true }, profile: { ...PROFILE, user: { username: 'alice' } } }));
    expect(r.state).toBe('open');
    await r.app.ready;
    expect(mount.querySelector('#drive-imp-note').textContent).toMatch(/alice’s Drive.*admin audit/);
    expect(names()).toEqual(['Documents', 'Empty', 'Photos', 'readme.txt']);
    expect(S.audit.some((x) => x.action === 'drive.keys_used')).toBe(true);
  });

  it('a Drive waiting for its upgrade with no usable old key in the tab (none, or not this Drive’s): the password form, once', async () => {
    for (const reason of ['locked', 'wrong']) {
      await server();
      S.migration = { pending: true, v1Items: 1, v1Links: 0, legacy: true };
      const calls = [];
      const upgrade = {
        upgradeOwnDrive: async () => { calls.push('upgrade'); const e = new Error('no key'); e.name = 'UpgradeBlocked'; e.reason = reason; throw e; },
        legacyUnlock: async () => { calls.push('unlock'); },
      };
      const mount = mountPoint();
      const r = await startDrive(mount, deps({ upgrade }));
      await r.app.ready;
      await until(() => mount.querySelector('#drive-upgrade-form'));
      expect(mount.querySelector('#drive-upgrade-msg').hidden).toBe(true);
      expect(calls).toEqual(['upgrade']);
    }
  });

  // Audit B M2: links of the previous release the old key does not open are listed, and retired with the step-up.
  it('a Drive waiting whose old links do not open: they are listed; "Retire" (the step-up) retires them and the upgrade finishes', async () => {
    await server();
    S.migration = { pending: true, v1Items: 1, v1Links: 1, legacy: true };
    const calls = [];
    const upgrade = {
      upgradeOwnDrive: async () => { calls.push('upgrade'); return { upgraded: 1, damaged: 0, unopened: ['rAAAAAAAAAAAAAAAAAAAAAA'], done: false }; },
      retireLinks: async (o) => { calls.push(['retire', o.ids, o.step]); return { retired: 1, failed: 0, done: true }; },
    };
    const confirm = async (input) => { const v = input.value; input.value = ''; if (!v) throw new Error('Enter your current password.'); return { current: `proof:${v}` }; };
    const mount = mountPoint();
    const r = await startDrive(mount, deps({ upgrade, confirm, canUsePasskey: async () => false }));
    await r.app.ready;
    await until(() => mount.querySelector('#drive-retire-form'));
    expect(mount.querySelector('#drive-retire-form').textContent).toMatch(/rAAAAAAAAAAAAAAAAAAAAAA/);
    mount.querySelector('#drive-retire-btn').click();
    await until(() => !mount.querySelector('#drive-upgrade-msg').hidden);
    expect(mount.querySelector('#drive-upgrade-msg').textContent).toMatch(/password/);
    mount.querySelector('#drive-retire-pw').value = 'pw';
    mount.querySelector('#drive-retire-btn').click();
    await until(() => /Your Drive is upgraded/.test(mount.querySelector('#drive-upgrade').textContent));
    expect(calls).toEqual(['upgrade', ['retire', ['rAAAAAAAAAAAAAAAAAAAAAA'], { current: 'proof:pw' }]]);
    expect(mount.querySelector('#drive-upgrade').textContent).toMatch(/1 link whose key did not open was ended/);
  });

  // Audit B M4: a recovery kit of the previous release opens the old keys when nothing else does.
  it('a Drive waiting with no usable old key: a recovery kit of the previous release opens it (the file stays in the browser)', async () => {
    await server();
    S.migration = { pending: true, v1Items: 1, v1Links: 0, legacy: true };
    const calls = [];
    let first = true;
    const upgrade = {
      upgradeOwnDrive: async () => {
        calls.push('upgrade');
        if (first) { first = false; const e = new Error('no key'); e.name = 'UpgradeBlocked'; e.reason = 'locked'; throw e; }
        return { upgraded: 1, damaged: 0, unopened: [], done: true };
      },
      legacyUnlockWithKit: async (o) => { calls.push(['kit', o.text, o.passphrase]); },
    };
    const mount = mountPoint();
    const r = await startDrive(mount, deps({ upgrade }));
    await r.app.ready;
    await until(() => mount.querySelector('#drive-upgrade-kit-form'));
    const f = mount.querySelector('#drive-upgrade-kit');
    Object.defineProperty(f, 'files', { configurable: true, get: () => [new File(['{"format":"secbin-owner-kit/1"}'], 'kit.json')] });
    mount.querySelector('#drive-upgrade-kit-pass').value = 'kit pass';
    mount.querySelector('#drive-upgrade-kit-form').dispatchEvent(new Event('submit', { cancelable: true }));
    await until(() => /Your Drive is upgraded/.test(mount.querySelector('#drive-upgrade').textContent));
    expect(calls).toEqual(['upgrade', ['kit', '{"format":"secbin-owner-kit/1"}', 'kit pass'], 'upgrade']);
    expect(mount.querySelector('#drive-upgrade-kit-pass')).toBeNull();
  });

  it('a Drive made before the key model v2: the upgrade notice; the owner acting as the user is sent to Admin', async () => {
    await server();
    S.migration = { pending: true, v1Items: 2, v1Links: 0, legacy: true };
    const mount = mountPoint();
    const r = await startDrive(mount, deps({ user: { ...S.user, impersonating: true } }));
    await r.app.ready;
    expect(mount.querySelector('#drive-upgrade').textContent).toMatch(/2 items of this Drive still use.*Admin → Security → Keys/);
  });
});

/** `mount`'s children: the page's status line (kept in place, WCAG 4.1.3) by its role, the rest by id, text nodes as '#text'. */
const children = (mount) => [...mount.childNodes].map((n) => (n.nodeType !== 1 ? '#text' : n.id || n.getAttribute('role')));
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

describe('no stray "null" / "undefined" text in any state of the Drive page', () => {
  it('a user and the owner: the open Drive', async () => {
    await openApp();
    expect(strayText(document.body)).toEqual([]);
    await openApp({ user: { ...S.user, role: 'owner' }, profile: { ...PROFILE, user: { ...S.user } } });
    expect(strayText(document.body)).toEqual([]);
  });

  it('the keys cannot be had (the salt, the keyring), for a user and for the owner', async () => {
    for (const reason of ['salt_missing', 'keys_missing']) {
      for (const role of ['user', 'owner']) {
        await server();
        S.keysError = reason;
        const mount = mountPoint();
        const r = await startDrive(mount, deps({ user: { ...S.user, role } }));
        expect(r).toEqual({ state: 'unavailable', reason });
        // The page's status line (in place from the start) says the notice's title; the notice is content.
        expect(children(mount)).toEqual(['status', 'drive-unavailable']);
        expect(mount.firstChild.textContent).toBe('Your Drive cannot be opened right now');
        expect(strayText(document.body)).toEqual([]);
      }
    }
  });

  it('the owner acting as a user, a Drive waiting for its upgrade, and no Drive', async () => {
    await server();
    S.impersonatedBy = 'owner';
    let mount = mountPoint();
    let r = await startDrive(mount, deps({ user: { ...S.user, impersonating: true }, profile: { ...PROFILE, user: { username: 'alice' } } }));
    await r.app.ready;
    expect(strayText(document.body)).toEqual([]);
    await server();
    S.migration = { pending: true, v1Items: 2, v1Links: 0, legacy: true };
    mount = mountPoint();
    r = await startDrive(mount, deps());
    await r.app.ready;
    expect(mount.querySelector('#drive-upgrade')).not.toBeNull();
    expect(strayText(document.body)).toEqual([]);
    S = fakeServer({ enabled: false });
    globalThis.fetch = S.fetch;
    mount = mountPoint();
    r = await startDrive(mount, deps());
    expect(r.state).toBe('disabled');
    expect(strayText(document.body)).toEqual([]);
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

  it('each selection box sits in a <label> (the pointer target, WCAG 2.5.8); "Select all" is named by its text (2.5.3)', async () => {
    await openApp();
    for (const cb of document.querySelectorAll('#drive-table input[type="checkbox"]')) expect(cb.parentElement.matches('label.check-hit')).toBe(true);
    const all = document.getElementById('drive-select-all');
    expect(all.hasAttribute('aria-label')).toBe(false);
    expect(all.closest('label').textContent).toBe('Select all in this folder');
    // Clicking the label (not the box) toggles it.
    const box = row('readme.txt').querySelector('input[type="checkbox"]');
    box.closest('label').click();
    expect(box.checked).toBe(true);
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

describe('the role\'s file rules in the Drive (checked before anything is sent; the server\'s refusals shown as they come)', () => {
  const posts = (path) => S.requests.filter((r) => r.method === 'POST' && r.path === path);
  const withLimits = (extra) => ({ profile: { ...PROFILE, limits: { ...LIMITS, ...extra } } });
  const upload = (files) => {
    const input = document.getElementById('drive-file-input');
    Object.defineProperty(input, 'files', { configurable: true, value: files });
    input.dispatchEvent(new Event('change'));
  };
  const driveMsg = () => document.getElementById('drive-msg');

  it('an upload with a type the role refuses: the reason, and nothing of the batch sent; allowed types are declared', async () => {
    await openApp(withLimits({ fileTypeMode: 'block', fileTypeRules: ['ext:exe'] }));
    upload([new File(['a'], 'hi.txt', { type: 'text/plain' }), new File(['b'], 'tool.exe', { type: 'application/x-msdownload' })]);
    await until(() => !driveMsg().hidden);
    expect(driveMsg().textContent).toBe('Your administrator does not allow .exe (application/x-msdownload) files in the Drive (“tool.exe”).');
    expect(posts('/api/private/drive/files')).toHaveLength(0);
    upload([new File(['a'], 'hi.txt', { type: 'text/plain' })]);
    await until(() => row('hi.txt'));
    expect(posts('/api/private/drive/files').map((r) => r.body.types)).toEqual([[{ ext: 'txt', mime: 'text/plain' }]]);
    // Without a type policy, nothing is declared.
    await openApp();
    upload([new File(['a'], 'hi.txt', { type: 'text/plain' })]);
    await until(() => row('hi.txt'));
    expect(posts('/api/private/drive/files')[0].body).not.toHaveProperty('types');
  });

  it('a new folder past the depth limit: the reason in the dialog, nothing sent; one within it is made', async () => {
    const { app } = await openApp(withLimits({ maxFolderDepth: 1 }));
    await app.open(ids.get('Documents'));
    document.getElementById('drive-mkdir').click();
    let d = dialog();
    d.querySelector('input').value = 'Deeper';
    button(d, 'Create').click();
    await until(() => !d.querySelector('.modal-msg').hidden);
    expect(d.querySelector('.modal-msg').textContent).toBe('Folders may nest at most 1 level deep in your Drive for your account; the new folder would be at level 2.');
    expect(posts('/api/private/drive/folders')).toHaveLength(0);
    button(d, 'Cancel').click();
    await app.open('root');
    document.getElementById('drive-mkdir').click();
    d = dialog();
    d.querySelector('input').value = 'Level one';
    button(d, 'Create').click();
    await until(() => row('Level one'));
    expect(posts('/api/private/drive/folders')).toHaveLength(1);
  });

  it('an upload into a folder deeper than the limit (made before it): refused with the reason; what is there stays listed; the server\'s refusals as it words them', async () => {
    const { app } = await openApp(withLimits({ maxFolderDepth: 1 }));
    await app.open(ids.get('Documents/Reports'));
    expect(names()).toEqual(['Archive', 'q1.txt']);
    upload([new File(['a'], 'late.txt', { type: 'text/plain' })]);
    await until(() => !driveMsg().hidden);
    expect(driveMsg().textContent).toBe('Folders may nest at most 1 level deep in your Drive for your account; this folder is at level 2.');
    expect(posts('/api/private/drive/files')).toHaveLength(0);
    expect(names()).toEqual(['Archive', 'q1.txt']);
    // A refusal the server makes (here the bytes quota) is shown as it words it.
    S.refusals.push({ method: 'POST', path: /^\/api\/private\/drive\/files$/, status: 429, error: 'quota_exceeded', message: 'Quota reached: 1.0 GB uploaded to the Drive per 1d.', extra: { quota: { channel: 'all', kind: 'drive-bytes', n: 1, unit: 'd', max: 1024 ** 3 } } });
    await app.open(ids.get('Documents'));
    upload([new File(['a'], 'big.txt', { type: 'text/plain' })]);
    await until(() => /Quota reached/.test(driveMsg().textContent));
    expect(driveMsg().textContent).toBe('Quota reached: 1.0 GB uploaded to the Drive per 1d.');
    expect(row('big.txt')).toBeUndefined();
  });

  it('a move past the depth limit: the reason in the move dialog, nothing sent; a refusal only the server can make, as it words it', async () => {
    await openApp(withLimits({ maxFolderDepth: 1 }));
    row('Empty').querySelector('input[type="checkbox"]').click();
    document.getElementById('drive-move').click();
    const d = dialog();
    const picker = d.querySelector('[role="tree"]');
    await until(() => picker.querySelectorAll('.tree-item').length >= 3);
    [...picker.querySelectorAll('.tree-text')].find((t) => t.textContent === 'Photos').closest('.tree-label').click();
    button(d, 'Move here').click();
    await until(() => !d.querySelector('.modal-msg').hidden);
    expect(d.querySelector('.modal-msg').textContent).toBe('Folders may nest at most 1 level deep in your Drive for your account; the folder would be at level 2.');
    expect(S.requests.filter((r) => r.method === 'PATCH')).toHaveLength(0);
    button(d, 'Cancel').click();
    // What only the server can tell (the folders inside a folder being moved) comes back as it words it.
    S.refusals.push({ method: 'PATCH', path: /^\/api\/private\/drive\/nodes\//, status: 403, error: 'folder_too_deep', message: 'Folders may be nested at most 1 level deep in your Drive.', extra: { max: 1 } });
    row('Empty').querySelector('input[type="checkbox"]').click(); // unselected: now the file alone, which fits at level 1 here
    row('readme.txt').querySelector('input[type="checkbox"]').click();
    document.getElementById('drive-move').click();
    const d2 = dialog();
    const picker2 = d2.querySelector('[role="tree"]');
    await until(() => picker2.querySelectorAll('.tree-item').length >= 3);
    [...picker2.querySelectorAll('.tree-text')].find((t) => t.textContent === 'Photos').closest('.tree-label').click();
    button(d2, 'Move here').click();
    await until(() => !d2.querySelector('.modal-msg').hidden);
    expect(d2.querySelector('.modal-msg').textContent).toBe('Folders may be nested at most 1 level deep in your Drive.');
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
});

describe('nav: Drive link', () => {
  it('driveAllowed reads caps.driveEnabled', async () => {
    vi.resetModules();
    vi.doMock('../public/js/api.js', () => ({
      me: () => new Promise(() => {}), logout: async () => {}, admin: {}, ApiError: class extends Error {},
      bindSession: () => {}, forgetSession: () => {}, onSessionChanged: () => {}, isSessionChanged: () => false, SESSION_CHANGED: '',
    }));
    const { driveAllowed } = await import('../public/dashboard/js/nav.js');
    expect(driveAllowed({ caps: { driveEnabled: true } })).toBe(true);
    expect(driveAllowed({ caps: { driveEnabled: 1 } })).toBe(false);
    expect(driveAllowed({ caps: {} })).toBe(false);
    expect(driveAllowed({})).toBe(false);
    vi.doUnmock('../public/js/api.js');
  });
});
