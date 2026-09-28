// no-stray-text.test.js — the dashboard pages the DOM suite can render, with
// the API mocked, must not show a text node reading "null" or "undefined":
// append / replaceChildren / before / after / replaceWith turn a null,
// undefined (or false) argument into that text, where h() would skip it. The
// pages are the real public/dashboard/*/index.html markup and controllers
// (My shares, Account, every Admin tab, Admin → Import / export with a file
// open, and the Drive keys card's Verify with every kind of result); the
// Drive page's views are checked in drive.test.js.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect, vi, beforeEach } from 'vitest';

const root = process.cwd();
const read = (p) => readFileSync(join(root, p), 'utf8');

const fx = vi.hoisted(() => {
  const now = Math.floor(Date.now() / 1000);
  return {
    now,
    fileDoc: null,
    keys: false,
    kitStatus: { version: 3, versionAt: null, last: null, stale: false }, // the personal kit's state (Account)
    profile: {
      user: { id: 'o'.repeat(16), username: 'owner', role: 'owner' },
      impersonatedBy: null,
      limits: { text: true, files: true, maxViews: null, allowUnlimitedViews: true, maxExpireSec: null, maxFileBytes: null, maxFilesPerShare: null,
        reverseEdit: true, reverseNoExpiry: true, reverseMaxViews: null, reverseAllowUnlimitedViews: true, reversePassword: 'allow', reverseCaptcha: 'allow' },
      caps: { maxShareBytes: 1 << 20 },
      viewer: { enabled: false },
      apiKeys: { enabled: true, max: 5 },
      passkeys: { mode: 'any', count: 1, required: false, recoveryLeft: 20 },
      quotas: [],
    },
  };
});

vi.mock('../public/dashboard/js/nav.js', () => ({ ready: Promise.resolve(fx.profile) }));
vi.mock('../public/js/pwauth.js', () => ({
  stretch: vi.fn(), newCredential: vi.fn(), checkNewPassword: vi.fn(() => null), checkOwnerPassword: vi.fn(() => null),
  describePolicy: vi.fn(() => 'At least 12 characters.'), loginProof: vi.fn(async () => 'proof'),
}));
vi.mock('../public/js/exportcrypt.js', () => {
  class ExportCryptError extends Error {}
  return { ExportCryptError, sealExport: async () => '{}', openExport: async () => structuredClone(fx.fileDoc) };
});
vi.mock('../public/js/api.js', async () => {
  // The admin overview as the server builds it (src/directory-do.js adminGlobal), from the real defaults.
  const { SETTINGS, LIMITS, settingsWithDefaults, resolveLimits, restrictForApi } = await import('../src/lib/settings.js');
  const overview = {
    env: {}, settings: settingsWithDefaults({}), limits: { all: {}, api: {} },
    defaults: {
      settings: Object.fromEntries(Object.entries(SETTINGS).map(([k, v]) => [k, v.def])),
      limits: Object.fromEntries(Object.entries(LIMITS).map(([k, v]) => [k, v.def])),
      inherited: resolveLimits({}, {}),
    },
    quotas: [], viewerRules: [],
  };
  class ApiError extends Error {}
  const share = (id, extra) => ({ id, label: `label ${id}`, kind: 'text', created: fx.now - 60, expires: fx.now + 3600, views_total: 3, left: 2, status: 'active', ...extra });
  const users = [
    { id: 'o'.repeat(16), username: 'owner', role: 'owner', disabled: false, locked: false, created: fx.now },
    { id: 'b'.repeat(16), username: 'bob', role: 'user', disabled: false, locked: true, created: fx.now },
  ];
  return {
    ApiError,
    SESSION_CHANGED_EVENT: 'secbin:session-changed', // as api.js exports it (Admin → Keys listens for it)
    listShares: vi.fn(async () => ({ rows: [share('a'), share('b', { kind: 'files', status: 'revoked', views_total: null }),
      // A Receive link with no expiry (expires: null) and views.
      share('r', { kind: 'reverse', expires: null, views_total: 2, left: 1, used: 1, received: { files: 1, bytes: 5 }, captcha: true })] })),
    // The Drive's reverse shares (My shares' Edit reads a link's options here).
    drive: { kitStatus: vi.fn(async () => structuredClone(fx.kitStatus)), reverse: vi.fn(async () => ({ reverse: [{ id: 'r', folder: 'root', label: 'label r', created: fx.now - 60, expires: null, status: 'active', views: 2, used: 1, left: 1,
      maxFiles: null, maxBytes: null, maxFileBytes: null, types: null, captcha: true, password: false, note: false, files: 1, bytes: 5 }] })) },
    updateShare: vi.fn(async () => ({})),
    revokeShare: vi.fn(async () => ({})),
    listKeys: vi.fn(async () => ({ keys: [{ id: 'k1', name: 'laptop', created: fx.now, last_used: null, expires: null }] })),
    myActivity: vi.fn(async () => ({ rows: [{ id: 1, ts: fx.now, action: 'login', detail: 'ok' }] })),
    createKey: vi.fn(), revokeKey: vi.fn(), changePassword: vi.fn(), prelogin: vi.fn(async () => ({ salt: 'S'.repeat(22), t: 3 })),
    myPasskeys: vi.fn(async () => ({ ok: true, mode: 'any', mfa: false, required: false, max: 10, recoveryLeft: 20, passkeys: [{ id: 'p1', name: 'phone', created: fx.now, lastUsed: null, synced: true }] })),
    passkeyRegisterOptions: vi.fn(), addPasskey: vi.fn(), removePasskey: vi.fn(), regenerateRecoveryCodes: vi.fn(), setSecondFactor: vi.fn(),
    // The Drive keys card (Admin → Import / export): its sub-MEKs, and a Verify with every kind of result.
    keysApi: {
      // Only for that test (fx.keys): elsewhere the keyring is unavailable, as before.
      status: vi.fn(async () => { if (!fx.keys) throw new ApiError('unavailable'); return { subs: [{ id: 'mAAAAAAAAAAA', fp: 'abcdefghijk', status: 'current' }] }; }),
      verifyExport: vi.fn(async () => ({
        ok: true, now: fx.now, matches: false, root: { result: 'mismatch', fp: null },
        subs: { inFile: true, list: [{ id: 'mAAAAAAAAAAA', fp: null, from: 0, until: null, status: 'current', result: 'missing' }, { id: 'mBBBBBBBBBBB', fp: 'abcdefghijk', from: 0, until: 0, status: 'retired', result: 'mismatch' }], unknown: ['mZZZZZZZZZZZ'] },
        users: [
          { id: 'b'.repeat(16), username: 'bob', salt: 'none', keks: [{ mekId: 'mAAAAAAAAAAA', result: 'unchecked' }, { mekId: 'mZZZZZZZZZZZ', result: 'unknown' }], deks: { total: 3, opens: 0, fails: 1, missing: 1, empty: 1, unchecked: 0, failed: ['N'.repeat(22)], missingIds: [] } },
          { id: 'c'.repeat(16), username: null, salt: 'unknown', keks: [] },
        ],
      })),
    },
    admin: {
      overview: vi.fn(async () => structuredClone(overview)),
      users: vi.fn(async () => ({ users })),
      guard: vi.fn(async () => ({
        blocks: [{ key: '198.51.100.7', scope: 'login', since: fx.now, until: fx.now + 60 }],
        tracking: [{ key: '203.0.113.9', scope: 'invalid', count: 3, expires: fx.now + 60 }],
      })),
      ipRules: vi.fn(async () => ({ rules: [{ id: 'r1', cidr: '192.0.2.0/24', action: 'block', expires: null, note: '' }] })),
      audit: vi.fn(async () => ({ rows: [{ id: 9, ts: fx.now, actor: 'owner', subject: 'bob', imp: false, action: 'user.update', detail: 'limits' }] })),
      shares: vi.fn(async () => ({ rows: [{ ...share('c'), username: 'bob' }, { ...share('d', { kind: 'files', status: 'revoked', views_total: null }), username: null }] })),
      roles: vi.fn(async () => ({ roles: [
        { id: 'owner', name: 'Owner', builtin: true, locked: true, users: 1 },
        { id: 'default', name: 'Default', builtin: true, users: 1 },
        { id: 'public', name: 'Public', builtin: true, fixed: true, users: 0 },
      ] })),
      turnstile: vi.fn(async () => ({ sitekey: '', secretSet: false })),
      // The public account (src/routes/admin.js /public, directory-do.js userDetail).
      publicAccess: vi.fn(async () => ({ profile: {}, trackers: { rows: [{ id: 'AbCdEfGhIjKl', name: null, created: fx.now, last_seen: fx.now, uses: 2, blocked: false, reason: null }], total: 1, blocked: 0 } })),
      user: vi.fn(async (id) => {
        const all = resolveLimits({}, {});
        return {
          user: id === 'public-user-0000' ? { id, username: 'public', role: 'public' } : users[1],
          limits: { all: {}, api: {} }, effective: { all, api: restrictForApi(all, {}, {}) }, quotas: [], viewerRules: [], role: null, keys: { keys: [] },
          passkeys: { count: 0, recoveryLeft: 0, mfa: false },
        };
      }),
      exportData: vi.fn(async () => ({ document: { format: 'secbin-export/v1', created: 1, users: [] } })),
      importData: vi.fn(async () => ({ ok: true, applied: false, plan: { system: null, owner: null, users: [], errors: [], warnings: [] } })),
    },
  };
});

/** Mount a real page's <main> (and toast). */
function mountPage(path) {
  const html = read(path);
  document.body.innerHTML = `${html.match(/<main[\s\S]*<\/main>/)[0]}<div id="toast" role="status"></div>`;
}

const settle = async () => { for (let i = 0; i < 10; i++) await new Promise((r) => setTimeout(r, 0)); };

/** Text nodes reading "null" or "undefined" under `node`, with where they are. */
function strayText(node = document.body) {
  const out = [];
  const walk = (n) => {
    for (const c of n.childNodes) {
      if (c.nodeType === 3 && ['null', 'undefined'].includes(c.textContent.trim())) out.push(`${c.textContent.trim()} in <${n.nodeName.toLowerCase()}${n.id ? `#${n.id}` : ''}${n.className ? `.${String(n.className).split(' ').join('.')}` : ''}>`);
      else if (c.nodeType === 1) walk(c);
    }
  };
  walk(node);
  return out;
}

describe('no dashboard page shows a stray "null" or "undefined"', () => {
  beforeEach(() => { vi.resetModules(); });

  it('My shares', async () => {
    mountPage('public/dashboard/shares/index.html');
    await import('../public/dashboard/js/shares.js');
    await settle();
    expect(document.querySelectorAll('#shares-table tbody tr').length).toBeGreaterThan(0);
    expect(strayText()).toEqual([]);
    // A Receive link: "No expiry", its views, and its Edit row.
    const row = [...document.querySelectorAll('#shares-table tbody tr')].find((tr) => tr.querySelector('td[data-label="Type"]')?.textContent === 'receive');
    expect(row.querySelector('td[data-label="Expires"]').textContent).toBe('No expiry');
    expect(row.querySelector('td[data-label="Views"]').textContent).toBe('1 file received · 1 left of 2 views');
    [...row.querySelectorAll('button')].find((b) => b.textContent === 'Edit').click();
    await settle();
    expect(document.querySelector('.extend-row .rev-edit')).not.toBeNull();
    expect(strayText()).toEqual([]);
  });

  it('Account', async () => {
    mountPage('public/dashboard/account/index.html');
    await import('../public/dashboard/js/account.js');
    await settle();
    expect(document.querySelectorAll('#view-account table.table').length).toBeGreaterThan(0);
    expect(strayText()).toEqual([]);
  });

  it('Account with the Drive personal kit: never downloaded (no date), then out of date (the notices)', async () => {
    fx.profile.caps.driveEnabled = true;
    try {
      for (const st of [{ version: 3, versionAt: null, last: null, stale: false }, { version: 4, versionAt: fx.now, last: { at: fx.now - 60, version: 3 }, stale: true }]) {
        fx.kitStatus = st;
        vi.resetModules();
        mountPage('public/dashboard/account/index.html');
        await import('../public/dashboard/js/account.js');
        // The card's modules load on demand: wait for its state.
        for (let i = 0; i < 500 && !/^Version/.test(document.getElementById('ukit-version')?.textContent || ''); i++) await new Promise((r) => setTimeout(r, 10));
        await settle();
        expect(document.getElementById('ukit-version').textContent).toMatch(/^Version \d/);
        expect(document.getElementById('ukit-stale').hidden).toBe(!st.stale);
        expect(!!document.getElementById('acct-kit-notice')).toBe(st.stale);
        expect(strayText()).toEqual([]);
      }
    } finally {
      fx.profile.caps.driveEnabled = undefined;
    }
  });

  it('Account, while the owner acts as a user', async () => {
    const saved = fx.profile.user;
    fx.profile.user = { id: 'b'.repeat(16), username: 'bob', role: 'user' };
    fx.profile.impersonatedBy = 'owner';
    try {
      mountPage('public/dashboard/account/index.html');
      await import('../public/dashboard/js/account.js');
      await settle();
      expect(document.getElementById('acct-title').textContent).toMatch(/bob/);
      expect(strayText()).toEqual([]);
    } finally {
      fx.profile.user = saved;
      fx.profile.impersonatedBy = null;
    }
  });

  it('Admin: every tab', async () => {
    mountPage('public/dashboard/admin/index.html');
    await import('../public/dashboard/js/admin.js');
    await settle();
    const tabs = [...document.querySelectorAll('.tab[data-tab]')].map((t) => t.dataset.tab);
    expect(tabs.length).toBeGreaterThan(1);
    for (const tab of tabs) {
      document.querySelector(`.tab[data-tab="${tab}"]`).click();
      await settle();
      expect(strayText(), tab).toEqual([]);
    }
    // Roles: each built-in role's editor (Owner, Default, Public).
    document.querySelector('.tab[data-tab="roles"]').click();
    await settle();
    const edits = () => [...document.querySelectorAll('.admin-panel[data-panel="roles"] tbody button')].filter((b) => b.textContent === 'Edit');
    expect(edits()).toHaveLength(3);
    for (let i = 0; i < 3; i++) {
      edits()[i].click();
      await settle();
      expect([...document.querySelectorAll('.admin-panel[data-panel="roles"] h2')].map((x) => x.textContent)).toContain(`${['Owner', 'Default', 'Public'][i]} role`);
      expect(strayText(), `role ${i}`).toEqual([]);
    }
  });

  it('Admin → Import / export: export, and a file open for import (no system part in it)', async () => {
    const { renderPortable } = await import('../public/dashboard/js/admin-portable.js');
    document.body.innerHTML = '<div id="toast" role="status"></div>';
    const panel = document.body.appendChild(document.createElement('div'));
    await renderPortable(panel, fx.profile);
    expect(strayText()).toEqual([]);
    fx.fileDoc = { format: 'secbin-export/v1', created: 1, users: [{ username: 'bob', role: 'Default' }, { username: 'carol', role: 'Default' }] };
    const imp = panel.querySelectorAll('.card')[1];
    const file = imp.querySelector('[aria-label="Export file"]');
    Object.defineProperty(file, 'files', { value: [{ size: 10, text: async () => '{}' }] });
    [...imp.querySelectorAll('button')].find((b) => b.textContent === 'Decrypt').click();
    for (let i = 0; i < 50 && !imp.querySelector('table.part-table'); i++) await settle();
    expect(imp.querySelector('table.part-table')).not.toBeNull();
    expect(strayText()).toEqual([]);
  });

  it('Admin → Import / export → Drive keys: the Verify results, with missing names, fingerprints and origin', async () => {
    const { renderPortable } = await import('../public/dashboard/js/admin-portable.js');
    document.body.innerHTML = '<div id="toast" role="status"></div>';
    const panel = document.body.appendChild(document.createElement('div'));
    fx.keys = true;
    try { await renderPortable(panel, fx.profile); } finally { fx.keys = false; }
    expect(panel.querySelector('#kv-set')).not.toBeNull();
    expect(strayText()).toEqual([]);
    // A file whose parts are partly malformed, with no origin and a user without a name.
    fx.fileDoc = {
      format: 'secbin-keys-export/1', created: 1, root: { key: 'A'.repeat(43) },
      subs: [{ id: 'mZZZZZZZZZZZ', key: 'not a key' }], salts: { ['b'.repeat(16)]: 'B'.repeat(43), ['c'.repeat(16)]: null },
      users: [{ id: 'b'.repeat(16), keks: [{ mekId: 'mAAAAAAAAAAA', kek: 'C'.repeat(43) }], deks: [{ id: 'N'.repeat(22), dek: 'D'.repeat(43) }, { id: 'M'.repeat(22) }, {}] }, { id: 'c'.repeat(16) }],
    };
    const file = panel.querySelector('#kv-file');
    Object.defineProperty(file, 'files', { configurable: true, value: [{ size: 10, text: async () => '{}' }] });
    file.dispatchEvent(new Event('change'));
    panel.querySelector('#kv-confirm').value = 'pw';
    panel.querySelector('#kv-verify').click();
    for (let i = 0; i < 50 && !panel.querySelector('#kv-verdict'); i++) await settle();
    expect(panel.querySelector('#kv-verdict').dataset.verdict).toBe('incomplete');
    expect(panel.querySelectorAll('#kv-results li').length).toBeGreaterThan(5);
    expect(strayText()).toEqual([]);
  });
});
