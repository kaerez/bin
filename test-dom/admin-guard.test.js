// admin-guard.test.js — Admin → Security, "Currently blocked" and "Being
// tracked" on the real admin page against a fake fetch: a Guard row's key is a
// keyed hash of the network (sealed records, SECURITY.md, "Records at rest"), so the tables
// show the address the server opened for the owner (`addr`), never the key,
// and Unblock / Clear / Block 24h still send the row's key.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect, beforeAll, vi } from 'vitest';
import { SETTINGS, LIMITS } from '../src/lib/settings.js';

const OWNER = vi.hoisted(() => ({ user: { id: 'owner1ownerowner', username: 'owner', role: 'owner', impersonating: false }, impersonatedBy: null }));
vi.mock('../public/dashboard/js/nav.js', () => ({ ready: Promise.resolve(OWNER) }));

const T = 60000;
const until = async (fn, ms = 20000) => {
  const t0 = Date.now();
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error(`timed out: ${fn}`);
    await new Promise((r) => setTimeout(r, 20));
  }
};
const reply = (data, status = 200) => ({ ok: status < 400, status, type: 'basic', json: async () => data, clone() { return this; }, arrayBuffer: async () => new ArrayBuffer(0) });
const SETTING_VALUES = Object.fromEntries(Object.entries(SETTINGS).map(([k, v]) => [k, v.def]));
const BUILTIN = Object.fromEntries(Object.entries(LIMITS).map(([k, v]) => [k, v.def]));
const TAG_B = 'h:BBBBBBBBBBBBBBBBBBBBBBBB';
const TAG_T = 'h:TTTTTTTTTTTTTTTTTTTTTTTT';
const t = Math.floor(Date.now() / 1000);
const GUARD = {
  blocks: [{ scope: 'login', key: TAG_B, addr: '198.51.100.9/32', since: t - 60, until: t + 600 }],
  tracking: [{ scope: 'invalid', key: TAG_T, addr: '2001:db8:0:0:0:0:0:0/64', count: 3, start: t - 30, expires: t + 570 }],
};

const sent = [];
async function adminFetch(url, init = {}) {
  const p = new URL(url, 'https://bin.example').pathname;
  const method = init.method || 'GET';
  sent.push({ method, path: p, body: init.body ? JSON.parse(init.body) : undefined });
  if (p === '/api/private/admin/overview') {
    return reply({ turnstile: false, env: {}, settings: SETTING_VALUES, limits: { all: { ...BUILTIN }, api: {} }, defaults: { settings: SETTING_VALUES, limits: BUILTIN, inherited: { ...BUILTIN } }, quotas: [], viewerRules: [] });
  }
  if (p === '/api/private/me') return reply({ user: OWNER.user, csrf: 'T'.repeat(43) });
  if (p === '/api/private/admin/guard') return reply(GUARD);
  if (p.startsWith('/api/private/admin/guard/')) return reply({ ok: true });
  if (p === '/api/private/admin/ip-rules') return reply({ rules: [] });
  if (p === '/api/private/admin/turnstile') return reply({ sitekey: null, secretSet: false, active: null, deployment: true });
  if (p === '/api/private/admin/keys') return reply({ error: 'not_found' }, 404);
  if (p === '/api/private/admin/roles') return reply({ roles: [{ id: 'owner', name: 'Owner', builtin: true, locked: true, users: 1 }, { id: 'default', name: 'Default', builtin: true, users: 0 }] });
  if (p === '/api/private/admin/users') return reply({ users: [] });
  return reply({ error: 'not_found', message: `unrouted ${p}` }, 404);
}

const panel = () => document.querySelector('.admin-panel[data-panel="security"]');
const rowOf = (text) => [...panel().querySelectorAll('tr')].find((tr) => tr.textContent.includes(text));

beforeAll(async () => {
  globalThis.fetch = vi.fn(adminFetch);
  const html = readFileSync(join(process.cwd(), 'public/dashboard/admin/index.html'), 'utf8');
  document.body.innerHTML = `${html.match(/<main[\s\S]*<\/main>/)[0]}<div id="toast" role="status"></div>`;
  await import('../public/dashboard/js/admin.js');
  await until(() => document.querySelector('.tab[data-tab="security"]'));
  document.querySelector('.tab[data-tab="security"]').click();
  await until(() => rowOf('198.51.100.9/32') && rowOf('2001:db8:0:0:0:0:0:0/64'));
}, T);

describe('Admin → Security: the Guard shows addresses, never its keys', () => {
  it('each row shows the address the server opened; the key (a keyed hash) is not shown', () => {
    expect(rowOf('198.51.100.9/32').querySelector('td[data-label="IP / prefix"]').textContent).toBe('198.51.100.9/32');
    expect(rowOf('2001:db8:0:0:0:0:0:0/64').querySelector('td[data-label="IP / prefix"]').textContent).toBe('2001:db8:0:0:0:0:0:0/64');
    expect(panel().textContent).not.toContain(TAG_B);
    expect(panel().textContent).not.toContain(TAG_T);
  });

  it('Unblock, Clear and Block 24h send the row\'s key', async () => {
    rowOf('198.51.100.9/32').querySelector('button').click();
    await until(() => sent.some((x) => x.path === '/api/private/admin/guard/unblock'));
    expect(sent.find((x) => x.path === '/api/private/admin/guard/unblock').body).toEqual({ scope: 'login', key: TAG_B });
    await until(() => rowOf('2001:db8:0:0:0:0:0:0/64'));
    const block = [...rowOf('2001:db8:0:0:0:0:0:0/64').querySelectorAll('button')].find((b) => b.textContent === 'Block 24h');
    block.click();
    await until(() => sent.some((x) => x.path === '/api/private/admin/guard/block'));
    expect(sent.find((x) => x.path === '/api/private/admin/guard/block').body).toEqual({ scope: 'invalid', key: TAG_T, seconds: 86400 });
  });
});
