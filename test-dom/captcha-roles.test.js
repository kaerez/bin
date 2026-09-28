// captcha-roles.test.js — Admin → Roles, the CAPTCHA options (the real admin
// page against stand-in admin routes): each option is a radio group (allow /
// require / off, and "same as Default" on a custom role) with its "Default for
// new shares" group shown only while the mode in effect is "allow"; the
// reverse-share one only while the role can use the Drive and reverse shares;
// the Default role holds values (no "same as Default"); the Public role has
// none; the Owner role says it is locked at "allow"; the editor says when
// Turnstile is not configured; Save sends the values.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect, beforeAll, vi } from 'vitest';
import { LIMITS, SETTINGS } from '../src/lib/settings.js';

const OWNER = vi.hoisted(() => ({ user: { id: 'owner1', username: 'owner', role: 'owner', impersonating: false }, impersonatedBy: null, limits: {} }));
vi.mock('../public/dashboard/js/nav.js', () => ({ ready: Promise.resolve(OWNER) }));

const T = 60000;
const until = async (fn, ms = 20000) => {
  const t0 = Date.now();
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 20));
  }
};
// Every role option's built-in value (the Default role holds one for each).
const BUILTIN = Object.fromEntries(Object.entries(LIMITS).map(([k, v]) => [k, v.def]));
const SETTING_VALUES = Object.fromEntries(Object.entries(SETTINGS).map(([k, v]) => [k, v.def]));
// As migration 12 does: the per-role values of server-wide settings start from the settings.
const START = { sessionIdleSec: SETTING_VALUES['session.idleSec'], sessionAbsSec: SETTING_VALUES['session.absSec'], fileGrantSec: SETTING_VALUES['files.grantSec'], filePendingSec: SETTING_VALUES['files.pendingSec'] };
const state = { turnstile: false, defaultRows: { ...BUILTIN, ...START }, customRows: {}, patches: [] };
const CUSTOM = 'CUSTOMROLE000001';
const reply = (data, status = 200) => ({ ok: status < 400, status, type: 'basic', json: async () => data });
function adminFetch(url, init = {}) {
  const method = init.method || 'GET';
  const p = new URL(url, 'https://bin.example').pathname;
  const body = typeof init.body === 'string' ? JSON.parse(init.body) : undefined;
  if (p === '/api/private/admin/overview') {
    return reply({ turnstile: state.turnstile, env: {}, settings: SETTING_VALUES, limits: { all: { ...state.defaultRows }, api: {} },
      defaults: { settings: SETTING_VALUES, limits: BUILTIN, inherited: { ...state.defaultRows } }, quotas: [], viewerRules: [] });
  }
  if (p === '/api/private/admin/roles') {
    return reply({ roles: [
      { id: 'owner', name: 'Owner', builtin: true, locked: true, users: 1 }, { id: 'default', name: 'Default', builtin: true, users: 0 },
      { id: 'public', name: 'Public', builtin: true, fixed: true, users: 0 }, { id: CUSTOM, name: 'Contractors', users: 0 }] });
  }
  if (p === `/api/private/admin/roles/${CUSTOM}`) {
    return reply({ role: { id: CUSTOM, name: 'Contractors', ownQuotas: false }, users: [], limits: { all: { ...state.customRows }, api: {} },
      effective: { all: { ...state.defaultRows, ...state.customRows }, api: {} }, inherited: { ...state.defaultRows }, quotas: [], viewerRules: [] });
  }
  // The page records its session (and its CSRF token) before its first change (public/js/api.js).
  if (p === '/api/private/me') return reply({ user: { id: 'owner-0000000000', username: 'owner', role: 'owner' }, impersonatedBy: null, csrf: 'C'.repeat(43) });
  if (p === '/api/private/admin/limits' && method === 'PATCH') { state.patches.push(body); return reply({ ok: true }); }
  if (p === '/api/private/admin/users/public-user-0000') {
    return reply({ user: { id: 'public-user-0000' }, limits: { all: {}, api: {} }, effective: { all: { ...state.defaultRows, shareCaptcha: 'off', reverseCaptcha: 'off' }, api: {} }, quotas: [], viewerRules: [] });
  }
  if (p === '/api/private/admin/public') return reply({ trackers: { rows: [], total: 0, blocked: 0 } });
  if (p === '/api/private/admin/users') return reply({ users: [] });
  return reply({ error: 'not_found', message: `unrouted ${p}` }, 404);
}

const detail = () => document.getElementById('role-detail');
const groups = () => [...detail().querySelectorAll('fieldset.captcha-role')];
const groupOf = (legend) => groups().find((f) => f.querySelector(':scope > legend').textContent === legend);
const radios = (fs) => [...fs.querySelectorAll(':scope > label.radio-opt input[type="radio"]')];
const labelOf = (r) => r.closest('label').textContent;
const checkedLabel = (list) => labelOf(list.find((r) => r.checked));
const defaultGroup = (fs) => fs.querySelector('fieldset.captcha-default');
const pick = (list, text) => { const r = list.find((x) => labelOf(x) === text); r.checked = true; r.dispatchEvent(new Event('change', { bubbles: true })); };
async function editRole(name) {
  document.querySelector('.tab[data-tab="roles"]').click();
  const row = await until(() => [...document.querySelectorAll('.admin-panel[data-panel="roles"] tbody tr')].find((tr) => tr.firstChild.textContent === name));
  [...row.querySelectorAll('button')].find((b) => b.textContent === 'Edit').click();
  await until(() => detail() && detail().querySelector('h2'));
}
const SHARES = 'CAPTCHA on shares (notes, file shares, Drive shares)';
const REVERSE = 'CAPTCHA on reverse shares (Receive files)';

beforeAll(async () => {
  globalThis.fetch = vi.fn(adminFetch);
  const html = readFileSync(join(process.cwd(), 'public/dashboard/admin/index.html'), 'utf8');
  document.body.innerHTML = `${html.match(/<main[\s\S]*<\/main>/)[0]}<div id="toast" role="status"></div>`;
  await import('../public/dashboard/js/admin.js');
}, T);

describe('Admin → Roles: the CAPTCHA options', () => {
  it('the Default role: radios with a value (no "same as Default"); the default for new shares only under "Allow"; the reverse one only with the Drive and reverse shares', async () => {
    await editRole('Default');
    const shares = await until(() => groupOf(SHARES));
    const r = radios(shares);
    expect(r.map(labelOf)).toEqual(['Allow CAPTCHA (user chooses per share)', 'Require CAPTCHA for all shares', 'Disable CAPTCHA']);
    expect(new Set(r.map((x) => x.name)).size).toBe(1); // one group: one tab stop, arrow keys move within it
    expect(checkedLabel(r)).toBe('Allow CAPTCHA (user chooses per share)');
    const def = defaultGroup(shares);
    expect(def.hidden).toBe(false);
    expect(def.querySelector('legend').textContent).toBe('Default for new shares:');
    expect(checkedLabel([...def.querySelectorAll('input')])).toBe('CAPTCHA off');
    pick(r, 'Require CAPTCHA for all shares');
    expect(def.hidden).toBe(true);
    pick(r, 'Disable CAPTCHA');
    expect(def.hidden).toBe(true);
    pick(r, 'Allow CAPTCHA (user chooses per share)');
    expect(def.hidden).toBe(false);
    pick([...def.querySelectorAll('input')], 'CAPTCHA on');
    // Turnstile is not configured: said next to the option (it is saved, not asked for).
    expect(shares.querySelector('p.warn').textContent).toMatch(/not active until Turnstile is configured/);
    expect(shares.getAttribute('aria-describedby')).toBe(shares.querySelector('p.warn').id);
    // The reverse-share option: hidden while the role has no Drive and no reverse shares.
    const rev = groupOf(REVERSE);
    expect(rev.closest('.limit-row').hidden).toBe(true);
    const sel = (label) => detail().querySelector(`select[aria-label="${label} mode"]`);
    sel('Drive allowed').value = 'true';
    sel('Drive allowed').dispatchEvent(new Event('change', { bubbles: true }));
    expect(rev.closest('.limit-row').hidden).toBe(true); // reverse shares still off
    sel('Receive files (reverse shares: anyone with the link uploads to a Drive folder)').value = 'true';
    sel('Receive files (reverse shares: anyone with the link uploads to a Drive folder)').dispatchEvent(new Event('change', { bubbles: true }));
    expect(rev.closest('.limit-row').hidden).toBe(false);
    const rr = radios(rev);
    expect(rr.map(labelOf)).toEqual(['Allow CAPTCHA (user chooses per share)', 'Require CAPTCHA for all reverse shares', 'Disable CAPTCHA']);
    expect(checkedLabel(rr)).toBe('Require CAPTCHA for all reverse shares');
    expect(defaultGroup(rev).hidden).toBe(true);
    expect(defaultGroup(rev).querySelector('legend').textContent).toBe('Default for new shares:');
    pick(rr, 'Allow CAPTCHA (user chooses per share)');
    expect(defaultGroup(rev).hidden).toBe(false);
    expect(checkedLabel([...defaultGroup(rev).querySelectorAll('input')])).toBe('CAPTCHA on');
    // Saved with the rest of the role's options.
    [...detail().querySelectorAll('button')].find((b) => /^Save\s+limits$/.test(b.textContent)).click();
    await until(() => state.patches.length);
    expect(document.getElementById('admin-msg').classList.contains('error')).toBe(false);
    expect(state.patches[0]).toMatchObject({ scope: 'global', channel: 'all' });
    expect(state.patches[0].patch).toMatchObject({ shareCaptcha: 'allow', shareCaptchaDefault: 'on', reverseCaptcha: 'allow', reverseCaptchaDefault: 'on', driveEnabled: true, reverseEnabled: true });
  }, T);

  it('a custom role: "same as Default" (with Default\'s value) until set; the default group follows what is in effect', async () => {
    state.patches = [];
    state.turnstile = true;
    await editRole('Contractors');
    const shares = await until(() => groupOf(SHARES));
    const r = radios(shares);
    expect(r.map(labelOf)).toEqual(['Same as Default (Allow CAPTCHA (user chooses per share))', 'Allow CAPTCHA (user chooses per share)', 'Require CAPTCHA for all shares', 'Disable CAPTCHA']);
    expect(checkedLabel(r)).toMatch(/^Same as Default/);
    const def = defaultGroup(shares);
    expect(def.hidden).toBe(false); // Default's value is "allow"
    expect(checkedLabel([...def.querySelectorAll('input')])).toBe('Same as Default (CAPTCHA off)');
    // Turnstile configured: no warning.
    expect(shares.querySelector('p.warn')).toBeNull();
    pick(r, 'Require CAPTCHA for all shares');
    expect(def.hidden).toBe(true);
    pick(r, 'Same as Default (Allow CAPTCHA (user chooses per share))');
    expect(def.hidden).toBe(false);
    pick(r, 'Disable CAPTCHA');
    [...detail().querySelectorAll('button')].find((b) => /^Save\s+limits$/.test(b.textContent)).click();
    await until(() => state.patches.length);
    expect(state.patches[0].scope).toBe(`role:${CUSTOM}`);
    expect(state.patches[0].patch).toMatchObject({ shareCaptcha: 'off', shareCaptchaDefault: 'inherit', reverseCaptcha: 'inherit', reverseCaptchaDefault: 'inherit' });
  }, T);

  it('a role that sets "off": that radio checked and no default group', async () => {
    state.customRows = { shareCaptcha: 'off' };
    await editRole('Contractors');
    const shares = await until(() => groupOf(SHARES));
    expect(checkedLabel(radios(shares))).toBe('Disable CAPTCHA');
    expect(defaultGroup(shares).hidden).toBe(true);
    state.customRows = {};
  }, T);

  it('the Public role has no CAPTCHA options; the Owner role says it is allowed, the choice per share', async () => {
    await editRole('Public');
    await until(() => detail().querySelector('h3'));
    expect(groups()).toHaveLength(0);
    await editRole('Owner');
    const note = await until(() => document.getElementById('owner-captcha'));
    expect(note.textContent).toMatch(/^CAPTCHA: allowed on shares and on reverse shares — you choose for each one/);
    expect(groups()).toHaveLength(0);
  }, T);
});
