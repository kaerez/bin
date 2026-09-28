// admin-tabs.test.js — Admin: a tab the person opens while the page is still
// loading (the overview request) stays open; the page's first tab is only the
// default (WCAG 3.2.5 Change on Request, 2.4.3 Focus Order).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect, beforeAll, vi } from 'vitest';

const OWNER = vi.hoisted(() => ({ user: { id: 'owner1', username: 'owner', role: 'owner', impersonating: false }, impersonatedBy: null }));
vi.mock('../public/dashboard/js/nav.js', () => ({ ready: Promise.resolve(OWNER) }));

const until = async (fn, ms = 10000) => {
  const t0 = Date.now();
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 20));
  }
};
const reply = (data, status = 200) => ({ ok: status < 400, status, type: 'basic', json: async () => data, arrayBuffer: async () => new ArrayBuffer(0) });

let releaseOverview;
const overviewGate = new Promise((r) => { releaseOverview = r; });
const seen = [];
async function adminFetch(url, init = {}) {
  const p = new URL(url, 'https://bin.example').pathname;
  seen.push(`${init.method || 'GET'} ${p}`);
  if (p === '/api/private/admin/overview') {
    await overviewGate;
    return reply({ env: {}, limits: { all: {}, api: {} }, defaults: { inherited: {} }, quotas: [], settings: {}, viewerRules: [] });
  }
  if (p === '/api/private/admin/audit') return reply({ rows: [{ id: 'a1', ts: 1700000000, actor: 'owner', subject: 'owner', action: 'login', detail: '' }] });
  if (p === '/api/private/admin/users') return reply({ users: [] });
  if (p === '/api/private/admin/roles') return reply({ roles: [] });
  return reply({ error: 'not_found' }, 404);
}

const tab = (name) => document.querySelector(`.tab[data-tab="${name}"]`);
const panel = (name) => document.querySelector(`.admin-panel[data-panel="${name}"]`);

beforeAll(async () => {
  globalThis.fetch = vi.fn(adminFetch);
  const html = readFileSync(join(process.cwd(), 'public/dashboard/admin/index.html'), 'utf8');
  document.body.innerHTML = `${html.match(/<main[\s\S]*<\/main>/)[0]}<div id="toast" role="status"></div>`;
  await import('../public/dashboard/js/admin.js');
});

describe('Admin tabs while the page loads', () => {
  it('a tab chosen before the overview arrives is not replaced by the default tab', async () => {
    await until(() => tab('audit').id === 'admin-tab-audit'); // the tabs are wired
    tab('audit').click();
    releaseOverview();
    await until(() => seen.includes('GET /api/private/admin/overview') && panel('audit').querySelector('tbody td'));
    await new Promise((r) => setTimeout(r, 100)); // the page's start-up has finished
    expect(tab('audit').getAttribute('aria-selected')).toBe('true');
    expect(panel('audit').hidden).toBe(false);
    expect(panel('users').hidden).toBe(true);
    expect(tab('users').getAttribute('aria-selected')).toBe('false');
    expect(seen).not.toContain('GET /api/private/admin/users');
  });
});
