// reverse-roles.test.js — Admin → Roles, the options of "Receive" links
// (reverse shares) that mirror regular shares' (the real admin page against
// stand-in admin routes): no expiry, the longest expiry, views, unlimited
// views, editing after creation, and the uploader password as a radio group
// with its default for new links; each with its default hint; custom roles
// inherit; the Public role has none; the Owner role says what applies.
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

const PW = 'Uploader password on Receive links';
const sel = (label, n = 0) => detail().querySelectorAll(`select[aria-label="${label} mode"]`)[n];
const rowNote = (label) => sel(label).closest('.limit-row').querySelector('span.mono.muted').textContent;
const set = (label, v) => { sel(label).value = v; sel(label).dispatchEvent(new Event('change', { bubbles: true })); };
const NO_EXPIRY = 'Receive: links with no expiry allowed (they take files until revoked)';
const MAX_VIEWS = 'Receive: most views per link (a view: one visit that starts sending files)';
const UNLIMITED = 'Receive: unlimited views allowed';
const MAX_EXPIRE = 'Receive: longest expiry of a link';
const EDIT = 'Receive: users may change a link after making it (expiry, views, limits, what it accepts, CAPTCHA, password, note)';

beforeAll(async () => {
  globalThis.fetch = vi.fn(adminFetch);
  const html = readFileSync(join(process.cwd(), 'public/dashboard/admin/index.html'), 'utf8');
  document.body.innerHTML = `${html.match(/<main[\s\S]*<\/main>/)[0]}<div id="toast" role="status"></div>`;
  await import('../public/dashboard/js/admin.js');
}, T);

describe('Admin → Roles: the Receive-link options', () => {
  it('the Default role: each option with its value and default hint; the password as a radio group (shown with the Drive and reverse shares); Save sends them', async () => {
    await editRole('Default');
    await until(() => sel(NO_EXPIRY));
    expect(sel(NO_EXPIRY).value).toBe('false');
    expect(rowNote(NO_EXPIRY)).toBe('default: no');
    expect(sel(MAX_VIEWS).value).toBe('null');
    expect(rowNote(MAX_VIEWS)).toBe('default: no limit');
    expect(sel(UNLIMITED).value).toBe('true');
    expect(rowNote(UNLIMITED)).toBe('default: yes');
    expect(sel(MAX_EXPIRE).value).toBe('null');
    expect(rowNote(MAX_EXPIRE)).toBe('default: no limit');
    expect(sel(EDIT).value).toBe('true');
    expect(rowNote(EDIT)).toBe('default: yes');
    // The Default role holds a value for every option: no "same as Default".
    expect([...sel(NO_EXPIRY).options].map((o) => o.value)).toEqual(['true', 'false']);
    const pw = groupOf(PW);
    expect(pw.closest('.limit-row').hidden).toBe(true);
    set('Drive allowed', 'true');
    set('Receive (reverse shares: anyone with the link uploads to a Drive folder)', 'true');
    expect(pw.closest('.limit-row').hidden).toBe(false);
    const r = radios(pw);
    expect(r.map(labelOf)).toEqual(['Allow a password (user chooses per link)', 'Require a password on every link', 'Disable passwords']);
    expect(checkedLabel(r)).toBe('Allow a password (user chooses per link)');
    const def = defaultGroup(pw);
    expect(def.hidden).toBe(false);
    expect(def.querySelector('legend').textContent).toBe('Default for new links:');
    expect(checkedLabel([...def.querySelectorAll('input')])).toBe('password off');
    expect(pw.querySelector('p.mono').textContent).toMatch(/it only lets them in/);
    expect(pw.closest('.limit-row').querySelector('span.mono.muted').textContent).toMatch(/^default: Allow a password \(user chooses per link\), password off/);
    pick(r, 'Require a password on every link');
    expect(def.hidden).toBe(true);
    set(NO_EXPIRY, 'true');
    set(MAX_VIEWS, 'value');
    detail().querySelector(`[aria-label="${MAX_VIEWS}"]`).value = '4';
    [...detail().querySelectorAll('button')].find((b) => /^Save\s+limits$/.test(b.textContent)).click();
    await until(() => state.patches.length);
    expect(state.patches[0].patch).toMatchObject({ reverseNoExpiry: true, reverseMaxViews: 4, reverseAllowUnlimitedViews: true, reverseMaxExpireSec: null,
      reversePassword: 'require', reversePasswordDefault: 'off', reverseEdit: true });
  }, T);

  it('a custom role inherits each one ("same as Default", with Default\'s value); the API limits include the expiry, views and editing', async () => {
    state.patches = [];
    await editRole('Contractors');
    await until(() => sel(NO_EXPIRY));
    expect(sel(NO_EXPIRY).value).toBe('inherit');
    expect(sel(NO_EXPIRY).selectedOptions[0].textContent).toBe('same as Default (no)');
    expect(radios(groupOf(PW)).map(labelOf)[0]).toBe('Same as Default (Allow a password (user chooses per link))');
    // The API channel's editor lists the options an API key can reach (not the password: API keys never create links).
    for (const label of [NO_EXPIRY, MAX_VIEWS, UNLIMITED, MAX_EXPIRE, EDIT]) expect(sel(label, 1), label).toBeTruthy();
    expect(detail().querySelectorAll('fieldset.captcha-role')).toHaveLength(3);
  }, T);

  it('the Public role has none of them; the Owner role says what applies', async () => {
    await editRole('Public');
    await until(() => detail().querySelector('h3'));
    for (const label of [NO_EXPIRY, MAX_VIEWS, UNLIMITED, MAX_EXPIRE, EDIT]) expect(sel(label), label).toBeUndefined();
    expect(groupOf(PW)).toBeUndefined();
    await editRole('Owner');
    const note = await until(() => document.getElementById('owner-reverse'));
    expect(note.textContent).toMatch(/or none; any number of views, or unlimited/);
  }, T);
});
