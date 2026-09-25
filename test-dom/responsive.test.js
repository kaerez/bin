// responsive.test.js — the mobile/responsive contract and the plaintext-label
// hint, under happy-dom:
//   • unencryptedHint(): inert DOM, one shared wording, aria-describedby wiring;
//   • every data cell the dashboard builds carries its column name (data-label),
//     which the < 640px stacked-card layout prints via td::before;
//   • theme-init.js: an explicit choice wins, otherwise prefers-color-scheme;
//   • static checks on the pages/stylesheet (viewport-fit, dvh, ≥16px controls).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { unencryptedHint, UNENCRYPTED_HINT_TEXT } from '../public/js/common.js';

const root = process.cwd();
const read = (p) => readFileSync(join(root, p), 'utf8');

// ── module mocks for the dashboard controllers ───────────────────────────────
const fx = vi.hoisted(() => {
  const now = Math.floor(Date.now() / 1000);
  return {
    now,
    profile: {
      user: { username: 'owner', role: 'owner' },
      impersonatedBy: null,
      limits: { text: true, files: true, maxViews: null, allowUnlimitedViews: true, maxExpireSec: null, maxFileBytes: null, maxFilesPerShare: null },
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
  stretch: vi.fn(), newCredential: vi.fn(), checkNewPassword: vi.fn(() => null), describePolicy: vi.fn(() => 'At least 12 characters.'), loginProof: vi.fn(),
}));
vi.mock('../public/js/api.js', () => {
  class ApiError extends Error {}
  const share = (id, extra) => ({ id, label: `label ${id}`, kind: 'text', created: fx.now - 60, expires: fx.now + 3600, views_total: 3, left: 2, status: 'active', ...extra });
  return {
    ApiError,
    listShares: vi.fn(async () => ({ rows: [share('a'), share('b', { kind: 'files', status: 'revoked', views_total: null })] })),
    updateShare: vi.fn(async () => ({})),
    revokeShare: vi.fn(async () => ({})),
    listKeys: vi.fn(async () => ({ keys: [{ id: 'k1', name: 'laptop', created: fx.now, last_used: null, expires: null }] })),
    myActivity: vi.fn(async () => ({ rows: [{ id: 1, ts: fx.now, action: 'login', detail: 'ok' }] })),
    createKey: vi.fn(), revokeKey: vi.fn(), changePassword: vi.fn(), prelogin: vi.fn(),
    myPasskeys: vi.fn(async () => ({ ok: true, mode: 'any', mfa: false, required: false, max: 10, recoveryLeft: 20, passkeys: [{ id: 'p1', name: 'phone', created: fx.now, lastUsed: null, synced: true }] })),
    passkeyRegisterOptions: vi.fn(), addPasskey: vi.fn(), removePasskey: vi.fn(), regenerateRecoveryCodes: vi.fn(), setSecondFactor: vi.fn(),
    admin: {
      overview: vi.fn(async () => ({ env: {}, limits: { all: {}, api: {} }, quotas: [], settings: {}, viewerRules: [] })),
      users: vi.fn(async () => ({ users: [
        { id: 'u0', username: 'owner', role: 'owner', disabled: false, locked: false, created: fx.now },
        { id: 'u1', username: 'bob', role: 'user', disabled: false, locked: true, created: fx.now },
      ] })),
      guard: vi.fn(async () => ({
        blocks: [{ key: '198.51.100.7', scope: 'login', since: fx.now, until: fx.now + 60 }],
        tracking: [{ key: '203.0.113.9', scope: 'invalid', count: 3, expires: fx.now + 60 }],
      })),
      ipRules: vi.fn(async () => ({ rules: [{ id: 'r1', cidr: '192.0.2.0/24', action: 'block', expires: null, note: '' }] })),
      audit: vi.fn(async () => ({ rows: [{ id: 9, ts: fx.now, actor: 'owner', subject: 'bob', imp: false, action: 'user.update', detail: 'limits' }] })),
    },
  };
});

/** Mount a real page's <main> (and toast) so thead ↔ data-label is checked against the shipped markup. */
function mountPage(path) {
  const html = read(path);
  const main = html.match(/<main[\s\S]*<\/main>/)[0];
  document.body.innerHTML = `${main}<div id="toast" role="status"></div>`;
}

const settle = async () => { for (let i = 0; i < 10; i++) await new Promise((r) => setTimeout(r, 0)); };

/** Every body cell under a titled column carries that title as data-label; untitled (action) columns carry none. */
function expectLabelled(table) {
  const heads = [...table.querySelectorAll('thead th')].map((th) => th.textContent.trim());
  const rows = [...table.querySelectorAll('tbody tr')].filter((tr) => !tr.classList.contains('extend-row'));
  expect(rows.length, 'table has rows').toBeGreaterThan(0);
  for (const tr of rows) {
    const cells = [...tr.children];
    expect(cells.length).toBe(heads.length);
    cells.forEach((td, i) => {
      if (heads[i]) expect(td.dataset.label, `column ${heads[i]}`).toBe(heads[i]);
      else expect(td.hasAttribute('data-label'), 'action column has no data-label').toBe(false);
    });
  }
  return rows;
}

// ── unencryptedHint ──────────────────────────────────────────────────────────
describe('unencryptedHint — the reusable "label is not encrypted" hint', () => {
  it('builds an inert, clearly worded element', () => {
    const el = unencryptedHint('hint-1');
    expect(el.tagName).toBe('P');
    expect(el.id).toBe('hint-1');
    expect(el.classList.contains('hint-unencrypted')).toBe(true);
    expect(el.textContent).toBe(UNENCRYPTED_HINT_TEXT);
    expect(UNENCRYPTED_HINT_TEXT).toMatch(/not encrypted/i);
    expect(UNENCRYPTED_HINT_TEXT).toMatch(/server/i);
    expect(UNENCRYPTED_HINT_TEXT).toMatch(/admins/i);
    const icon = el.querySelector('svg');
    expect(icon).not.toBeNull();
    expect(icon.namespaceURI).toBe('http://www.w3.org/2000/svg');
    expect(icon.getAttribute('aria-hidden')).toBe('true');
    for (const n of [el, ...el.querySelectorAll('*')]) {
      expect(n.hasAttribute('style')).toBe(false);
      for (const a of n.getAttributeNames()) expect(a.startsWith('on')).toBe(false);
    }
  });

  it('wires aria-describedby on the input, appending and never duplicating', () => {
    const input = document.createElement('input');
    input.setAttribute('aria-describedby', 'other');
    unencryptedHint('hint-2', input);
    unencryptedHint('hint-2', input);
    expect(input.getAttribute('aria-describedby')).toBe('other hint-2');
    const bare = document.createElement('input');
    unencryptedHint('hint-3', bare);
    expect(bare.getAttribute('aria-describedby')).toBe('hint-3');
  });
});

// ── dashboard tables: data-label per cell ────────────────────────────────────
describe('dashboard tables carry data-label for the stacked mobile layout', () => {
  beforeEach(() => { vi.resetModules(); });

  it('My shares: every cell is labelled, and each label input is described by the hint', async () => {
    mountPage('public/dashboard/shares/index.html');
    await import('../public/dashboard/js/shares.js');
    await settle();
    const rows = expectLabelled(document.getElementById('shares-table'));
    expect(rows).toHaveLength(2);
    const ids = new Set();
    for (const tr of rows) {
      const input = tr.querySelector('input.label-in');
      const hintId = input.getAttribute('aria-describedby');
      expect(hintId).toBeTruthy();
      const hint = document.getElementById(hintId);
      expect(hint.classList.contains('hint-unencrypted')).toBe(true);
      expect(hint.closest('td')).toBe(input.closest('td')); // right under its own field
      ids.add(hintId);
    }
    expect(ids.size).toBe(rows.length); // unique ids
  });

  it('Account: passkey, API-key and activity rows are labelled', async () => {
    mountPage('public/dashboard/account/index.html');
    await import('../public/dashboard/js/account.js');
    await settle();
    const tables = document.querySelectorAll('#view-account table.table');
    expect(tables).toHaveLength(3);
    for (const t of tables) expectLabelled(t);
  });

  it('Admin: users, IP rules, blocks, tracking and audit rows are labelled', async () => {
    mountPage('public/dashboard/admin/index.html');
    await import('../public/dashboard/js/admin.js');
    await settle();
    const tables = () => [...document.querySelectorAll('.admin-panel:not([hidden]) table.table')];
    expect(tables()).toHaveLength(1); // users
    for (const t of tables()) expectLabelled(t);
    document.querySelector('.tab[data-tab="security"]').click();
    await settle();
    expect(tables()).toHaveLength(3); // rules, blocked, tracking
    for (const t of tables()) expectLabelled(t);
    document.querySelector('.tab[data-tab="audit"]').click();
    await settle();
    expect(tables()).toHaveLength(1);
    for (const t of tables()) expectLabelled(t);
  });
});

// ── theme-init.js ────────────────────────────────────────────────────────────
describe('theme-init.js — explicit choice wins, else prefers-color-scheme', () => {
  const src = read('public/js/theme-init.js');
  const run = ({ saved, prefersLight, storageThrows = false }) => {
    document.head.innerHTML = '<meta name="theme-color" content="#0d1117">';
    document.documentElement.className = 'dark';
    const store = storageThrows
      ? { getItem: () => { throw new Error('denied'); } }
      : { getItem: (k) => (k === 'secbin:theme' ? saved ?? null : null) };
    const mm = vi.fn((q) => ({ matches: q === '(prefers-color-scheme: light)' ? !!prefersLight : false, media: q }));
    // Run the real script with localStorage/matchMedia as its free variables.
    new Function('localStorage', 'matchMedia', src)(store, mm);
    return {
      dark: document.documentElement.classList.contains('dark'),
      meta: document.querySelector('meta[name="theme-color"]').content,
      mm,
    };
  };

  it('no stored choice + system light → light (and the light theme-color)', () => {
    const r = run({ prefersLight: true });
    expect(r.dark).toBe(false);
    expect(r.meta).toBe('#f2f1ec');
    expect(r.mm).toHaveBeenCalledWith('(prefers-color-scheme: light)');
  });

  it('no stored choice + system dark (or no preference) → dark', () => {
    const r = run({ prefersLight: false });
    expect(r.dark).toBe(true);
    expect(r.meta).toBe('#0d1117');
  });

  it('an explicit stored choice beats the system preference', () => {
    expect(run({ saved: 'dark', prefersLight: true }).dark).toBe(true);
    const light = run({ saved: 'light', prefersLight: false });
    expect(light.dark).toBe(false);
    expect(light.meta).toBe('#f2f1ec');
  });

  it('garbage in storage is ignored; storage that throws still follows the system', () => {
    expect(run({ saved: 'purple', prefersLight: true }).dark).toBe(false);
    expect(run({ storageThrows: true, prefersLight: true }).dark).toBe(false);
    expect(run({ storageThrows: true, prefersLight: false }).dark).toBe(true);
  });
});

// ── static page / stylesheet contract ────────────────────────────────────────
describe('pages and stylesheet — responsive contract', () => {
  const pages = ['public/index.html', 'public/dashboard/index.html', 'public/dashboard/shares/index.html', 'public/dashboard/account/index.html',
    'public/dashboard/admin/index.html', 'public/dashboard/login/index.html', 'public/dashboard/setup/index.html'];
  const css = read('public/css/styles.css');

  it('every page opts into safe-area insets (viewport-fit=cover) and keeps a theme-color meta', () => {
    for (const p of pages) {
      const html = read(p);
      expect(html, p).toMatch(/<meta name="viewport" content="[^"]*viewport-fit=cover[^"]*"/);
      expect(html, p).toMatch(/<meta name="theme-color"/);
    }
  });

  it('every vh length is paired with a dvh override on the same line', () => {
    const lines = css.split('\n').filter((l) => /\d+vh\b/.test(l) && !/^\s*\/?\*/.test(l));
    expect(lines.length).toBeGreaterThan(0);
    for (const l of lines) expect(l, l.trim()).toMatch(/\d+dvh\b/);
  });

  it('the touch/small-screen block forces ≥16px on every control, compact ones included', () => {
    const block = css.match(/@media \(hover: none\), \(pointer: coarse\), \(max-width: 768px\) \{\s*([^}]*font-size: 1rem;[^}]*)\}/)?.[1];
    expect(block, 'font-size block present').toBeTruthy();
    for (const sel of ['input', 'select', 'textarea', '.input.mime-in', '.input.opt-num', '.input.label-in', '.opt .input', '.editor']) {
      expect(block).toContain(sel);
    }
    // It must come after the compact sizes it overrides.
    expect(css.indexOf(block)).toBeGreaterThan(css.indexOf('.mime-in { width'));
  });

  it('stacked tables print the column name from data-label', () => {
    expect(css).toMatch(/@media \(max-width: 640px\)[\s\S]*td\[data-label\]::before \{ content: attr\(data-label\)/);
    expect(css).toMatch(/\.row-actions \{[^}]*flex-wrap: wrap/);
  });
});
