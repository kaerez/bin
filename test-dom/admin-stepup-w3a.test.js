// admin-stepup-w3a.test.js — the admin page asks for the owner's password (or
// a passkey) where the server now wants the step-up (security audit W3, A-1,
// A-2, A-4): lifting a Guard block, removing a block rule, a user's role that
// is looser, and a role's quota list. Each is sent without a confirmation
// first; on `400 reauth_required` the page shows the field (naming what the
// change weakens), puts a choice that did not apply back, and the next try
// sends the confirmation. The real admin page against a fake fetch; the
// confirmation itself (confirm.js) is a stand-in.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect, beforeAll, vi } from 'vitest';
import { SETTINGS, LIMITS } from '../src/lib/settings.js';

const OWNER = vi.hoisted(() => ({ user: { id: 'owner1ownerowner', username: 'owner', role: 'owner', impersonating: false }, impersonatedBy: null }));
vi.mock('../public/dashboard/js/nav.js', () => ({ ready: Promise.resolve(OWNER) }));
vi.mock('../public/dashboard/js/confirm.js', () => ({
  confirmLabel: (t) => t,
  canUsePasskey: async () => false,
  confirmStep: async (input) => { const pw = input.value; input.value = ''; if (!pw) throw new Error('Enter your current password.'); return { current: `proof:${pw}` }; },
}));

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
const t = Math.floor(Date.now() / 1000);
const TAG = 'h:BBBBBBBBBBBBBBBBBBBBBBBB';
const USER = { id: 'user1useruseruse', username: 'dana', role: 'user', roleId: 'default', disabled: false, locked: false, created: t };
const ROLE = { id: 'roleLooseAAAAAAA', name: 'Loose', builtin: false, users: 0 };

const sent = [];
/** The step-up is refused (400 reauth_required) for a change sent without one. */
const needs = (body, weakens) => (body && body.current === undefined ? reply({ error: 'reauth_required', message: `This change weakens a security control (${weakens.join(', ')}): confirm with your password or a passkey.`, weakens }, 400) : reply({ ok: true }));
async function adminFetch(url, init = {}) {
  const p = new URL(url, 'https://bin.example').pathname;
  const method = init.method || 'GET';
  const body = init.body ? JSON.parse(init.body) : undefined;
  sent.push({ method, path: p, body });
  if (p === '/api/private/admin/overview') {
    return reply({ turnstile: false, env: {}, settings: SETTING_VALUES, limits: { all: { ...BUILTIN }, api: {} }, defaults: { settings: SETTING_VALUES, limits: BUILTIN, inherited: { ...BUILTIN } }, quotas: [], viewerRules: [] });
  }
  if (p === '/api/private/me') return reply({ user: OWNER.user, csrf: 'T'.repeat(43) });
  if (p === '/api/private/admin/guard' && method === 'GET') return reply({ blocks: [{ scope: 'login', key: TAG, addr: '198.51.100.9/32', since: t - 60, until: t + 600 }], tracking: [] });
  if (p === '/api/private/admin/guard/unblock') return needs(body, ['guard.unblock']);
  if (p === '/api/private/admin/ip-rules') return reply({ rules: [{ id: 'ruleBlockAAAAAAA', cidr: '203.0.113.0/28', action: 'block', expires: null, note: '', created: t }] });
  if (p === '/api/private/admin/ip-rules/ruleBlockAAAAAAA') return needs(body, ['ipRule.block']);
  if (p === '/api/private/admin/turnstile') return reply({ sitekey: null, secretSet: false, active: null, deployment: true });
  if (p === '/api/private/admin/keys') return reply({ error: 'not_found' }, 404);
  if (p === '/api/private/admin/roles') return reply({ roles: [{ id: 'owner', name: 'Owner', builtin: true, locked: true, users: 1 }, { id: 'default', name: 'Default', builtin: true, users: 1 }, ROLE] });
  if (p === '/api/private/admin/users') return reply({ users: [USER] });
  if (p === `/api/private/admin/users/${USER.id}/role`) return needs(body, ['passkeys', 'quotas']);
  return reply({ error: 'not_found', message: `unrouted ${p}` }, 404);
}

const panel = (name) => document.querySelector(`.admin-panel[data-panel="${name}"]`);
const rowOf = (name, text) => [...panel(name).querySelectorAll('tr')].find((tr) => tr.textContent.includes(text));
const shownField = (card) => [...card.querySelectorAll('input[type="password"][id^="stepup-"]')].find((i) => !i.closest('[hidden]'));
const last = (path) => sent.filter((x) => x.path === path).at(-1);

beforeAll(async () => {
  globalThis.fetch = vi.fn(adminFetch);
  const html = readFileSync(join(process.cwd(), 'public/dashboard/admin/index.html'), 'utf8');
  document.body.innerHTML = `${html.match(/<main[\s\S]*<\/main>/)[0]}<div id="toast" role="status"></div>`;
  await import('../public/dashboard/js/admin.js');
  await until(() => document.querySelector('.tab[data-tab="security"]'));
}, T);

describe('Admin: the step-up where lifting a control or loosening a role needs it', () => {
  it('Unblock: refused without it, the field appears (naming what it weakens), the next click sends it', async () => {
    document.querySelector('.tab[data-tab="security"]').click();
    await until(() => rowOf('security', '198.51.100.9/32'));
    rowOf('security', '198.51.100.9/32').querySelector('button').click();
    await until(() => last('/api/private/admin/guard/unblock'));
    expect(last('/api/private/admin/guard/unblock').body).toEqual({ scope: 'login', key: TAG });
    const card = rowOf('security', '198.51.100.9/32').closest('.card');
    const field = await until(() => shownField(card));
    expect(card.textContent).toMatch(/guard\.unblock/);
    field.value = 'owner-pw';
    rowOf('security', '198.51.100.9/32').querySelector('button').click();
    await until(() => sent.filter((x) => x.path === '/api/private/admin/guard/unblock').length === 2);
    expect(last('/api/private/admin/guard/unblock').body).toEqual({ scope: 'login', key: TAG, current: 'proof:owner-pw' });
  });

  it('Remove a block rule: the same, in the DELETE\'s JSON body', async () => {
    await until(() => rowOf('security', '203.0.113.0/28'));
    const remove = () => [...rowOf('security', '203.0.113.0/28').querySelectorAll('button')].find((b) => b.textContent === 'Remove');
    remove().click();
    const path = '/api/private/admin/ip-rules/ruleBlockAAAAAAA';
    await until(() => last(path));
    expect(last(path)).toMatchObject({ method: 'DELETE', body: {} });
    const field = await until(() => shownField(rowOf('security', '203.0.113.0/28').closest('.card')));
    field.value = 'owner-pw';
    remove().click();
    await until(() => sent.filter((x) => x.path === path).length === 2);
    expect(last(path).body).toEqual({ current: 'proof:owner-pw' });
  });

  it('a looser role for a user: the choice goes back until confirmed, then applies', async () => {
    document.querySelector('.tab[data-tab="users"]').click();
    const pick = await until(() => panel('users').querySelector(`select[aria-label="Role of ${USER.username}"]`));
    const path = `/api/private/admin/users/${USER.id}/role`;
    pick.value = ROLE.id;
    pick.dispatchEvent(new Event('change'));
    await until(() => last(path));
    expect(last(path).body).toEqual({ roleId: ROLE.id });
    const field = await until(() => shownField(panel('users')));
    expect(pick.value).toBe('default'); // put back: nothing changed
    expect(panel('users').textContent).toMatch(/passkeys, quotas/);
    field.value = 'owner-pw';
    pick.value = ROLE.id;
    pick.dispatchEvent(new Event('change'));
    await until(() => sent.filter((x) => x.path === path).length === 2);
    expect(last(path).body).toEqual({ roleId: ROLE.id, current: 'proof:owner-pw' });
  });
});
