// admin-weakening.test.js — Admin → Settings, Roles and Security on the real
// admin page and api.js against a fake fetch: a save that weakens a security
// control is answered 400 reauth_required (with what it weakens); only then
// the page shows "Your password" (or a passkey, the field left empty), and the
// next save sends the confirmation from the real confirm.js. A save the server
// takes as it is (tightening) never shows the field or sends a confirmation.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { SETTINGS, LIMITS } from '../src/lib/settings.js';

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
// The Default role holds a value for every option (the per-role session and file-share values start from the settings).
const BUILTIN = { ...Object.fromEntries(Object.entries(LIMITS).map(([k, v]) => [k, v.def])),
  sessionIdleSec: SETTING_VALUES['session.idleSec'], sessionAbsSec: SETTING_VALUES['session.absSec'], fileGrantSec: SETTING_VALUES['files.grantSec'], filePendingSec: SETTING_VALUES['files.pendingSec'] };
const confirmed = (b) => b && (b.current !== undefined || b.reauth !== undefined);
const weak = (list) => reply({ error: 'reauth_required', message: `This change weakens a security control (${list.join(', ')}): confirm with your password or a passkey.`, weakens: list }, 400);

const sent = [];
let challenges = 0;
async function adminFetch(url, init = {}) {
  const p = new URL(url, 'https://bin.example').pathname;
  const method = init.method || 'GET';
  const body = init.body ? JSON.parse(init.body) : undefined;
  sent.push({ method, path: p, body });
  if (p === '/api/private/admin/overview') {
    return reply({ turnstile: false, env: {}, settings: SETTING_VALUES, limits: { all: { ...BUILTIN }, api: {} }, defaults: { settings: SETTING_VALUES, limits: BUILTIN, inherited: { ...BUILTIN } }, quotas: [], viewerRules: [] });
  }
  if (p === '/api/private/me') return reply({ user: OWNER.user, csrf: 'T'.repeat(43) });
  if (p === '/api/auth/prelogin') return reply({ salt: 'S'.repeat(22), t: 3 });
  if (p === '/api/private/me/passkeys') return reply({ ok: true, mode: 'any', passkeys: Array.from({ length: pk.keys }, (_, i) => ({ id: `p${i}` })) });
  if (p === '/api/private/me/reauth') { challenges++; return reply({ challengeId: `ch${challenges}`, publicKey: { challenge: 'c' } }); }
  // The server's rule, as far as these tests need it.
  if (p === '/api/private/admin/settings' && method === 'PATCH') {
    if (body.csrfTokens === false && !confirmed(body)) return weak(['csrfTokens']);
    if (body['lockout.max'] > SETTING_VALUES['lockout.max'] && !confirmed(body)) return weak(['lockout.max']);
    return reply({ ok: true, settings: { ...SETTING_VALUES, ...body } });
  }
  if (p === '/api/private/admin/limits' && method === 'PATCH') {
    if (body.patch.passkeys === 'off' && !confirmed(body)) return weak(['passkeys']);
    return reply({ ok: true });
  }
  if (p === '/api/private/admin/ip-rules' && method === 'POST') {
    if (body.action === 'allow' && !confirmed(body)) return weak(['ipRule.allow']);
    return reply({ ok: true, id: 'rule000000000001', cidr: body.cidr }, 201);
  }
  if (p === '/api/private/admin/ip-rules') return reply({ rules: [] });
  if (p === '/api/private/admin/guard') return reply({ blocks: [], tracking: [] });
  if (p === '/api/private/admin/turnstile') return reply({ sitekey: null, secretSet: false, active: null, deployment: true });
  if (p === '/api/private/admin/keys') return reply({ error: 'not_found' }, 404);
  if (p === '/api/private/admin/roles') return reply({ roles: [{ id: 'owner', name: 'Owner', builtin: true, locked: true, users: 1 }, { id: 'default', name: 'Default', builtin: true, users: 0 }] });
  if (p === '/api/private/admin/users') return reply({ users: [] });
  return reply({ error: 'not_found', message: `unrouted ${p}` }, 404);
}

const panel = (name) => document.querySelector(`.admin-panel[data-panel="${name}"]`);
const calls = (path) => sent.filter((x) => x.path === path && x.method !== 'GET');
/** The step-up slot inside `root`: its container, and the password field. */
const slotIn = (root) => {
  const input = root.querySelector('input[type="password"][id^="stepup-"]');
  return { input, box: input?.closest('div.stack'), why: input && document.getElementById(input.getAttribute('aria-describedby')) };
};
async function openTab(name) {
  document.querySelector(`.tab[data-tab="${name}"]`).click();
  await until(() => panel(name).querySelector('button'));
}

beforeAll(async () => {
  globalThis.fetch = vi.fn(adminFetch);
  const html = readFileSync(join(process.cwd(), 'public/dashboard/admin/index.html'), 'utf8');
  document.body.innerHTML = `${html.match(/<main[\s\S]*<\/main>/)[0]}<div id="toast" role="status"></div>`;
  await import('../public/dashboard/js/admin.js');
  await until(() => document.querySelector('.tab[data-tab="settings"]')?.id === 'admin-tab-settings');
}, T);
beforeEach(() => { sent.length = 0; Object.assign(pk, { supported: true, keys: 1 }); });

describe('Admin: the step-up only for a change that weakens a control', () => {
  it('Settings → CSRF tokens: off asks for the password once the server says so; the typed password goes as `current`', async () => {
    await openTab('settings');
    const card = await until(() => document.getElementById('set-csrf')?.closest('.card'));
    const s = slotIn(card);
    expect(s.box.hidden).toBe(true);
    document.getElementById('set-csrf').checked = false;
    document.getElementById('set-csrf-save').click();
    await until(() => !s.box.hidden);
    expect(calls('/api/private/admin/settings').map((x) => x.body)).toEqual([{ csrfTokens: false }]);
    expect(s.why.textContent).toMatch(/weakens a security control \(csrfTokens\).*Then save again\./);
    expect(s.input.closest('label').textContent).toMatch(/^Your password, or leave it empty to confirm with a passkey/);
    expect(document.activeElement).toBe(s.input);
    s.input.value = 'owner-pw';
    document.getElementById('set-csrf-save').click();
    await until(() => calls('/api/private/admin/settings').length === 2);
    await until(() => s.box.hidden);
    expect(calls('/api/private/admin/settings')[1].body).toEqual({ csrfTokens: false, current: 'stretched:owner-pw' });
    expect(s.input.value).toBe(''); // asked again for every change
    // Back on: the server takes it as it is; no field, no confirmation.
    document.getElementById('set-csrf').checked = true;
    document.getElementById('set-csrf-save').click();
    await until(() => calls('/api/private/admin/settings').length === 3);
    expect(calls('/api/private/admin/settings')[2].body).toEqual({ csrfTokens: true });
    expect(s.box.hidden).toBe(true);
  });

  it('Settings → Save settings: a tightening save sends no confirmation; a looser lockout confirms with a passkey (field left empty)', async () => {
    await openTab('settings');
    const p = panel('settings');
    const save = await until(() => [...p.querySelectorAll('button')].find((b) => b.textContent === 'Save settings'));
    const s = slotIn(p);
    save.click();
    await until(() => calls('/api/private/admin/settings').length === 1);
    expect(confirmed(calls('/api/private/admin/settings')[0].body)).toBe(false);
    expect(s.box.hidden).toBe(true);
    const max = p.querySelector('input[aria-label="Failed logins allowed"]');
    max.value = '50';
    max.dispatchEvent(new Event('input', { bubbles: true }));
    save.click();
    await until(() => !s.box.hidden);
    save.click();
    await until(() => calls('/api/private/admin/settings').length === 3);
    const last = calls('/api/private/admin/settings')[2].body;
    expect(last['lockout.max']).toBe(50);
    expect(last.reauth).toEqual({ challengeId: expect.stringMatching(/^ch\d+$/), credential: expect.objectContaining({ id: 'cred1' }) });
  });

  it('Roles → Default: passkeys off asks for the confirmation', async () => {
    await openTab('roles');
    const row = await until(() => [...panel('roles').querySelectorAll('tbody tr')].find((tr) => tr.firstChild.textContent === 'Default'));
    [...row.querySelectorAll('button')].find((b) => b.textContent === 'Edit').click();
    const detail = await until(() => document.getElementById('role-detail')?.querySelector('select[aria-label="Passkeys mode"]') && document.getElementById('role-detail'));
    const mode = detail.querySelector('select[aria-label="Passkeys mode"]');
    mode.value = 'enum:off';
    mode.dispatchEvent(new Event('change', { bubbles: true }));
    const card = mode.closest('.card');
    const s = slotIn(card);
    const save = [...card.querySelectorAll('button')].find((b) => /^Save\s+limits$/.test(b.textContent));
    save.click();
    await until(() => !s.box.hidden);
    s.input.value = 'owner-pw';
    save.click();
    await until(() => calls('/api/private/admin/limits').length === 2);
    expect(calls('/api/private/admin/limits')[1].body).toMatchObject({ scope: 'global', channel: 'all', patch: { passkeys: 'off' }, current: 'stretched:owner-pw' });
  }, T);

  it('Security → IP rules: an allow rule asks, a block rule does not', async () => {
    await openTab('security');
    const p = panel('security');
    const add = await until(() => [...p.querySelectorAll('button')].find((b) => b.textContent === 'Add rule'));
    p.querySelector('input[aria-label="IP address, CIDR block or range"]').value = '192.0.2.0/24'; // a block rule (the default action)
    expect(slotIn(add.closest('.card')).box.hidden).toBe(true);
    add.click();
    await until(() => calls('/api/private/admin/ip-rules').length === 1);
    expect(calls('/api/private/admin/ip-rules')[0].body).toMatchObject({ cidr: '192.0.2.0/24', action: 'block' });
    expect(confirmed(calls('/api/private/admin/ip-rules')[0].body)).toBe(false);
    await openTab('security');
    const p2 = panel('security');
    const add2 = await until(() => [...p2.querySelectorAll('button')].find((b) => b.textContent === 'Add rule'));
    const s2 = slotIn(add2.closest('.card'));
    p2.querySelector('input[aria-label="IP address, CIDR block or range"]').value = '0.0.0.0/0';
    p2.querySelector('select[aria-label="Action"]').value = 'allow';
    add2.click();
    await until(() => !s2.box.hidden);
    expect(s2.why.textContent).toMatch(/ipRule\.allow/);
    s2.input.value = 'owner-pw';
    add2.click();
    await until(() => calls('/api/private/admin/ip-rules').length === 3);
    expect(calls('/api/private/admin/ip-rules')[2].body).toMatchObject({ cidr: '0.0.0.0/0', action: 'allow', current: 'stretched:owner-pw' });
  }, T);
});
