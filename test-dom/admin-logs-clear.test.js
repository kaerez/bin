// admin-logs-clear.test.js — Admin → Audit → Clear logs, on the real admin
// page and api.js against a fake fetch: the step-up is the real confirm.js —
// the typed password stretched into `current` (the field cleared), or, the
// field left empty, a passkey assertion for a fresh reauth challenge sent as
// `reauth`; with no passkey an empty field is refused and nothing is sent.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';

const OWNER = vi.hoisted(() => ({ user: { id: 'owner1ownerowner', username: 'owner', role: 'owner', impersonating: false }, impersonatedBy: null }));
const pk = vi.hoisted(() => ({ supported: true, keys: 1 }));
vi.mock('../public/dashboard/js/nav.js', () => ({ ready: Promise.resolve(OWNER) }));
vi.mock('../public/js/passkeys.js', () => ({
  passkeysSupported: () => pk.supported,
  usePasskey: async (publicKey) => ({ id: 'cred1', type: 'public-key', answered: publicKey.challenge }),
  usePasskeyPrf: async () => { throw new Error('not used here'); },
  createPasskey: async () => { throw new Error('not used here'); },
}));
vi.mock('../public/js/pwauth.js', async (orig) => ({ ...(await orig()), stretch: async (pw) => `stretched:${pw}` }));

const until = async (fn, ms = 10000) => {
  const t0 = Date.now();
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 20));
  }
};
const reply = (data, status = 200) => ({ ok: status < 400, status, type: 'basic', json: async () => data, clone() { return this; }, arrayBuffer: async () => new ArrayBuffer(0) });

const MINE = 'Your password (or leave it empty to confirm with a passkey)';
const sent = [];
let challenges = 0;
async function adminFetch(url, init = {}) {
  const p = new URL(url, 'https://bin.example').pathname;
  const body = init.body ? JSON.parse(init.body) : undefined;
  sent.push({ method: init.method || 'GET', path: p, body });
  if (p === '/api/private/admin/overview') return reply({ env: {}, limits: { all: {}, api: {} }, defaults: { inherited: {} }, quotas: [], settings: {}, viewerRules: [] });
  if (p === '/api/private/admin/audit') return reply({ rows: [{ id: 'a1', ts: 1700000000, actor: 'owner', subject: 'owner', action: 'login', detail: '' }] });
  if (p === '/api/private/admin/users') return reply({ users: [] });
  if (p === '/api/private/admin/roles') return reply({ roles: [] });
  // api.js takes the session's CSRF token from here before a change.
  if (p === '/api/private/me') return reply({ user: OWNER.user, csrf: 'T'.repeat(43) });
  if (p === '/api/auth/prelogin') return reply({ salt: 'S'.repeat(22), t: 3 });
  if (p === '/api/private/me/passkeys') return reply({ ok: true, mode: 'any', passkeys: Array.from({ length: pk.keys }, (_, i) => ({ id: `p${i}` })) });
  if (p === '/api/private/me/reauth') { challenges++; return reply({ challengeId: `ch${challenges}`, publicKey: { challenge: 'c' } }); }
  if (p === '/api/private/admin/logs/clear') return reply({ ok: true, deleted: 3 });
  return reply({ error: 'not_found' }, 404);
}

const card = () => [...document.querySelectorAll('.admin-panel[data-panel="audit"] .card')].find((c) => c.querySelector('h2')?.textContent === 'Clear logs');
const clears = () => sent.filter((x) => x.path === '/api/private/admin/logs/clear');
/** "Delete log entries", then "Delete for good?" (armConfirm). */
async function del() {
  const go = [...card().querySelectorAll('button')].find((b) => /Delete/.test(b.textContent));
  go.click();
  await until(() => go.textContent === 'Delete for good?');
  go.click();
}

beforeAll(async () => {
  globalThis.fetch = vi.fn(adminFetch);
  const html = readFileSync(join(process.cwd(), 'public/dashboard/admin/index.html'), 'utf8');
  document.body.innerHTML = `${html.match(/<main[\s\S]*<\/main>/)[0]}<div id="toast" role="status"></div>`;
  await import('../public/dashboard/js/admin.js');
  await until(() => document.querySelector('.tab[data-tab="audit"]')?.id === 'admin-tab-audit');
  document.querySelector('.tab[data-tab="audit"]').click();
  await until(() => card());
});
beforeEach(() => { Object.assign(pk, { supported: true, keys: 1 }); });

describe('Admin → Audit → Clear logs: the step-up', () => {
  it('the field says an empty field confirms with a passkey', () => {
    const mine = card().querySelector('input[type="password"]');
    expect(mine.getAttribute('aria-label')).toBe(MINE);
    expect(mine.autocomplete).toBe('current-password');
  });

  it('the typed password goes as a stretched `current` proof, and the field is cleared', async () => {
    const mine = card().querySelector(`input[aria-label="${MINE}"]`);
    mine.value = 'owner pw';
    const n = clears().length;
    await del();
    await until(() => clears().length === n + 1);
    expect(clears().at(-1).body).toMatchObject({ current: 'stretched:owner pw', scope: 'all' });
    expect(clears().at(-1).body.reauth).toBeUndefined();
    expect(mine.value).toBe('');
  });

  it('an empty field: a passkey for a fresh reauth challenge, sent as `reauth`', async () => {
    const n = clears().length;
    const c0 = challenges;
    await del();
    await until(() => clears().length === n + 1);
    expect(challenges).toBe(c0 + 1);
    expect(clears().at(-1).body.reauth).toEqual({ challengeId: `ch${c0 + 1}`, credential: { id: 'cred1', type: 'public-key', answered: 'c' } });
    expect(clears().at(-1).body.current).toBeUndefined();
  });

  it('an empty field with no passkey (none on the account, or none in this browser) is refused, nothing sent', async () => {
    for (const state of [{ keys: 0 }, { supported: false }]) {
      Object.assign(pk, { supported: true, keys: 1 }, state);
      const n = clears().length;
      const c0 = challenges;
      document.getElementById('admin-msg').textContent = '';
      await del();
      await until(() => /Enter your current password/.test(document.getElementById('admin-msg').textContent));
      expect(clears().length).toBe(n);
      expect(challenges).toBe(c0);
    }
  });
});
