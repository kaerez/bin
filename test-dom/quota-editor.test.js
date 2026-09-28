// quota-editor.test.js — Admin → Roles → Quotas (the real admin page against
// stand-in admin routes): the kind select has one <optgroup> per group
// (Outgoing shares, Drive, Receive) with every kind labelled; the Public role's
// editor offers only the outgoing kinds the public account can use; a kind
// used only in the web app takes no "API only" channel; each control keeps its
// visible label; Save sends the kinds as chosen; a kind counted in bytes
// (Drive → "Bytes uploaded") takes its max in MiB or GiB, and sends bytes.
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
const BUILTIN = Object.fromEntries(Object.entries(LIMITS).map(([k, v]) => [k, v.def]));
const SETTING_VALUES = Object.fromEntries(Object.entries(SETTINGS).map(([k, v]) => [k, v.def]));
const q = (kind, channel = 'all') => ({ id: `q-${kind}-${channel}`, channel, kind, n: 1, unit: 'd', max: 3 });
const MiB = 1024 * 1024;
const GiB = 1024 * MiB;
const state = {
  defaultQuotas: [q('receive-upload'), q('note', 'api'), { ...q('drive-bytes'), max: 2 * GiB }],
  publicQuotas: [q('url')],
  saved: [],
};
const reply = (data, status = 200) => ({ ok: status < 400, status, type: 'basic', json: async () => data });
function adminFetch(url, init = {}) {
  const method = init.method || 'GET';
  const p = new URL(url, 'https://bin.example').pathname;
  const body = typeof init.body === 'string' ? JSON.parse(init.body) : undefined;
  if (p === '/api/private/admin/overview') {
    return reply({ turnstile: false, env: {}, settings: SETTING_VALUES, limits: { all: { ...BUILTIN }, api: {} },
      defaults: { settings: SETTING_VALUES, limits: BUILTIN, inherited: { ...BUILTIN } }, quotas: state.defaultQuotas, viewerRules: [] });
  }
  if (p === '/api/private/admin/roles') {
    return reply({ roles: [
      { id: 'owner', name: 'Owner', builtin: true, locked: true, users: 1 }, { id: 'default', name: 'Default', builtin: true, users: 0 },
      { id: 'public', name: 'Public', builtin: true, fixed: true, users: 0 }] });
  }
  if (p === '/api/private/me') return reply({ user: { id: 'owner-0000000000', username: 'owner', role: 'owner' }, impersonatedBy: null, csrf: 'C'.repeat(43) });
  if (p === '/api/private/admin/quotas' && method === 'PUT') { state.saved.push(body); return reply({ ok: true }); }
  if (p === '/api/private/admin/users/public-user-0000') {
    return reply({ user: { id: 'public-user-0000' }, limits: { all: {}, api: {} }, effective: { all: { ...BUILTIN }, api: {} }, quotas: state.publicQuotas, viewerRules: [] });
  }
  if (p === '/api/private/admin/public') return reply({ trackers: { rows: [], total: 0, blocked: 0 } });
  if (p === '/api/private/admin/users') return reply({ users: [] });
  return reply({ error: 'not_found', message: `unrouted ${p}` }, 404);
}

const detail = () => document.getElementById('role-detail');
async function editRole(name) {
  document.querySelector('.tab[data-tab="roles"]').click();
  const row = await until(() => [...document.querySelectorAll('.admin-panel[data-panel="roles"] tbody tr')].find((tr) => tr.firstChild.textContent === name));
  [...row.querySelectorAll('button')].find((b) => b.textContent === 'Edit').click();
  await until(() => detail() && detail().querySelector('h2') && detail().querySelector('.quota-row'));
}
const rowsOf = () => [...detail().querySelectorAll('.quota-row')];
const kindOf = (row) => row.querySelector('select[aria-label="Kind"]');
const channelOf = (row) => row.querySelector('select[aria-label="Via (channel)"]');
const groupsOf = (sel) => [...sel.children].map((g) => [g.tagName, g.label, [...g.children].map((o) => [o.value, o.textContent])]);
const button = (text) => [...detail().querySelectorAll('button')].find((b) => b.textContent === text);
const choose = (sel, value) => { sel.value = value; sel.dispatchEvent(new Event('change', { bubbles: true })); };

const OUTGOING = [['all', 'All outgoing shares'], ['text', 'Notes, links and credentials'], ['note', 'Notes'], ['url', 'Links'], ['secret', 'Credentials'],
  ['files', 'File and Drive shares'], ['file', 'File shares'], ['drive', 'Drive shares']];

beforeAll(async () => {
  globalThis.fetch = vi.fn(adminFetch);
  const html = readFileSync(join(process.cwd(), 'public/dashboard/admin/index.html'), 'utf8');
  document.body.innerHTML = `${html.match(/<main[\s\S]*<\/main>/)[0]}<div id="toast" role="status"></div>`;
  await import('../public/dashboard/js/admin.js');
}, T);

describe('Admin → Roles → Quotas: the kinds', () => {
  it('the kind select groups every kind (Outgoing shares, Drive, Receive); each control keeps its visible label', async () => {
    await editRole('Default');
    const [recv, api] = rowsOf();
    expect(groupsOf(kindOf(recv))).toEqual([
      ['OPTGROUP', 'Outgoing shares', OUTGOING],
      ['OPTGROUP', 'Drive', [['drive-upload', 'Files uploaded'], ['drive-bytes', 'Bytes uploaded']]],
      ['OPTGROUP', 'Receive', [['receive', 'All receive'], ['receive-link', 'New links'], ['receive-upload', 'Uploads received'],
        ['receive-file', 'Uploads with files'], ['receive-note', 'Notes received'], ['receive-url', 'Links received'], ['receive-secret', 'Credentials received']]],
    ]);
    expect(kindOf(recv).value).toBe('receive-upload');
    expect(kindOf(api).value).toBe('note');
    // Every control sits in a <label> whose text is its accessible name (WCAG 2.5.3, 3.3.2).
    for (const el of recv.querySelectorAll('select, input')) expect(el.closest('label').querySelector('.field-label').textContent).toBe(el.getAttribute('aria-label'));
    // The help says what the groups count.
    const help = [...detail().querySelectorAll('p.mono.muted')].map((p) => p.textContent).join(' ');
    expect(help).toMatch(/"All outgoing shares" counts every note, link, credential, file share and Drive share \(never Drive uploads or Receive\)/);
    expect(help).toMatch(/"Uploads received" counts each upload session that sends files through one of the user's links, or a note, link or credential/);
    expect(help).toMatch(/"Uploads with files", "Notes received", "Links received" and "Credentials received" count those sessions by what they send/);
  }, T);

  it('a kind used only in the web app takes no "API only" channel', async () => {
    const [recv, api] = rowsOf();
    const apiOpt = (row) => channelOf(row).querySelector('option[value="api"]');
    expect(apiOpt(recv).disabled).toBe(true);
    expect(channelOf(recv).value).toBe('all');
    expect(apiOpt(api).disabled).toBe(false);
    expect(channelOf(api).value).toBe('api');
    // Choosing a web-only kind moves an "API only" quota to GUI + API; an outgoing kind allows "API only" again.
    choose(kindOf(api), 'drive-upload');
    expect(channelOf(api).value).toBe('all');
    expect(apiOpt(api).disabled).toBe(true);
    choose(kindOf(api), 'file');
    expect(apiOpt(api).disabled).toBe(false);
    choose(channelOf(api), 'api');
    button('Save quotas').click();
    await until(() => state.saved.length);
    expect(state.saved[0]).toEqual({ scope: 'global', list: [
      { channel: 'all', kind: 'receive-upload', n: 1, unit: 'd', max: 3 },
      { channel: 'api', kind: 'file', n: 1, unit: 'd', max: 3 },
      { channel: 'all', kind: 'drive-bytes', n: 1, unit: 'd', max: 2 * GiB },
    ] });
  }, T);

  it('"Bytes uploaded" takes its max in MiB or GiB (shown in the unit that fits), and sends bytes; other kinds have no unit', async () => {
    const [recv, , bytes] = rowsOf();
    const unitOf = (row) => row.querySelector('select[aria-label="Max unit"]');
    const maxOf = (row) => row.querySelector('input[aria-label="Max"]');
    // A count kind: no unit shown.
    expect(unitOf(recv).closest('label').hidden).toBe(true);
    // The stored 2 GiB shows as 2 GiB, with a visible, labelled unit select.
    expect(kindOf(bytes).value).toBe('drive-bytes');
    expect(unitOf(bytes).closest('label').hidden).toBe(false);
    expect(unitOf(bytes).closest('label').querySelector('.field-label').textContent).toBe('Max unit');
    expect([...unitOf(bytes).options].map((o) => o.value)).toEqual(['MiB', 'GiB']);
    expect(unitOf(bytes).value).toBe('GiB');
    expect(maxOf(bytes).value).toBe('2');
    expect(channelOf(bytes).querySelector('option[value="api"]').disabled).toBe(true); // web only, as "Files uploaded"
    // 1.5 GiB and 300 MiB, as entered.
    maxOf(bytes).value = '1.5';
    button('Add quota').click();
    const added = rowsOf().at(-1);
    expect(unitOf(added).closest('label').hidden).toBe(true);
    choose(kindOf(added), 'drive-bytes');
    expect(unitOf(added).closest('label').hidden).toBe(false);
    expect(unitOf(added).value).toBe('MiB');
    maxOf(added).value = '300';
    button('Save quotas').click();
    await until(() => state.saved.length > 1);
    expect(state.saved[1].list.slice(2)).toEqual([
      { channel: 'all', kind: 'drive-bytes', n: 1, unit: 'd', max: 1.5 * GiB },
      { channel: 'all', kind: 'drive-bytes', n: 1, unit: 'd', max: 300 * MiB },
    ]);
    // Back to a count kind: the unit goes, and the max is a plain number again.
    choose(kindOf(added), 'drive-upload');
    expect(unitOf(added).closest('label').hidden).toBe(true);
    maxOf(added).value = '7';
    button('Save quotas').click();
    await until(() => state.saved.length > 2);
    expect(state.saved[2].list.at(-1)).toEqual({ channel: 'all', kind: 'drive-upload', n: 1, unit: 'd', max: 7 });
  }, T);

  it('the Public role offers only the outgoing kinds the public account can use', async () => {
    await editRole('Public');
    const [row] = rowsOf();
    expect(groupsOf(kindOf(row))).toEqual([['OPTGROUP', 'Outgoing shares', OUTGOING.filter(([k]) => k !== 'drive')]]);
    expect(kindOf(row).value).toBe('url');
    button('Add quota').click();
    const added = rowsOf().at(-1);
    expect(groupsOf(kindOf(added))).toEqual([['OPTGROUP', 'Outgoing shares', OUTGOING.filter(([k]) => k !== 'drive')]]);
    expect(kindOf(added).value).toBe('all');
    const help = [...detail().querySelectorAll('p.mono.muted')].map((p) => p.textContent).join(' ');
    expect(help).toMatch(/The public account has no Drive, so only outgoing shares it can make are counted/);
    expect(help).not.toMatch(/Uploads received/);
  }, T);
});
