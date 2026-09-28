// admin-new-user-drive.test.js — Admin → Users and a new user's Drive
// (docs/DRIVE.md §3, "Drives the owner sets up"), with the real admin page,
// API client and Drive client against the in-memory server
// (drive-fake-server.js) plus the few admin routes the page needs:
//   - a role without the Drive (the create response's `drive.enabled` false):
//     no Drive request for the user at all, and the create form says so;
//   - a role with the Drive: the owner's browser sets it up (one request);
//   - a race (the role loses the Drive between the create and the set-up): the
//     server's 409 drive_disabled is shown as the same case, with no error;
//   - a password reset for a user whose role has no Drive: no Drive request.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect, beforeAll, vi } from 'vitest';
import { unlockDrive } from '../public/js/driveclient.js';
import { saveSessionKey, loadSessionKey } from '../public/js/drivekeys.js';
import { stretch } from '../public/js/pwauth.js';
import { fakeServer } from './drive-fake-server.js';

const OWNER = vi.hoisted(() => ({ user: { id: 'owner1', username: 'owner', role: 'owner', impersonating: false }, impersonatedBy: null }));
vi.mock('../public/dashboard/js/nav.js', () => ({ ready: Promise.resolve(OWNER) }));
// A credential without Argon2id (the page only forwards it to the server).
vi.mock('../public/js/pwauth.js', async (orig) => ({ ...(await orig()), newCredential: async () => ({ salt: 'AAAAAAAAAAAAAAAAAAAAAA', t: 3, proof: 'proof' }) }));

const PW = 'owner password 1';
const SALT = 'AAAAAAAAAAAAAAAAAAAAAA';
const T = 120000;
const until = async (fn, ms = 30000) => {
  const t0 = Date.now();
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 20));
  }
};

let SO; // the owner's Drive server
const users = []; // the admin list
let nextDrive = { enabled: false }; // what the next create response says of the role's Drive
const reply = (data, status = 200) => ({ ok: status < 400, status, type: 'basic', json: async () => data, arrayBuffer: async () => new ArrayBuffer(0) });
/** The admin routes the Users panel uses; everything else goes to the Drive server (which records every request). */
function adminFetch(url, init = {}) {
  const method = init.method || 'GET';
  const p = new URL(url, 'https://bin.example').pathname;
  const body = typeof init.body === 'string' ? JSON.parse(init.body) : undefined;
  if (p === '/api/private/admin/overview') {
    SO.requests.push({ method, path: p });
    return reply({ env: {}, limits: { all: {}, api: {} }, defaults: { inherited: {} }, quotas: [], settings: {}, viewerRules: [] });
  }
  if (p === '/api/private/admin/roles') return reply({ roles: [{ id: 'owner', name: 'Owner', builtin: true, locked: true }, { id: 'default', name: 'Default', builtin: true }] });
  if (p === '/api/private/admin/users' && method === 'GET') return reply({ users: users.map((u) => ({ ...u, role: 'user', disabled: false, locked: false, created: 1, roleId: 'default' })) });
  if (p === '/api/private/admin/users' && method === 'POST') {
    SO.requests.push({ method, path: p, body });
    const u = { id: `u${String(users.length + 1).padStart(15, '0')}`, username: body.username, drive: { ...nextDrive, used: 0, capacity: null } };
    users.push(u);
    return reply({ ok: true, user: u }, 201);
  }
  const m = p.match(/^\/api\/private\/admin\/users\/([^/]+)(\/password)?$/);
  if (m && !m[2]) {
    const u = users.find((x) => x.id === m[1]);
    return reply({ user: { id: u.id, username: u.username }, effective: { all: { driveEnabled: u.drive.enabled }, api: {} }, role: null, keys: [], passkeys: { count: 0, recoveryLeft: 0, mfa: false } });
  }
  if (m && m[2] && method === 'POST') {
    SO.requests.push({ method, path: p, body });
    return reply({ ok: true });
  }
  return SO.fetch(url, init);
}
/** Requests about another user's Drive (the owner's escrow use or a set-up). */
const userDriveCalls = (from = 0) => SO.requests.slice(from).filter((r) => r.path.startsWith('/api/private/admin/drive/'));
const note = () => document.getElementById('user-create-drive');
const usersPanel = () => document.querySelector('.admin-panel[data-panel="users"]');

async function createUser(username) {
  const from = SO.requests.length;
  await until(() => usersPanel().querySelector('[aria-label="New username"]'));
  const q = (l) => usersPanel().querySelector(`[aria-label="${l}"]`);
  q('New username').value = username;
  q('New user password').value = 'starting password';
  q('Repeat password').value = 'starting password';
  const before = note()?.textContent;
  [...usersPanel().querySelectorAll('button')].find((b) => b.textContent === 'Create user').click();
  // The form is drawn again with the note about the new user's Drive.
  await until(() => note() && !note().hidden && note().textContent !== before && note().textContent.startsWith(`${username}:`));
  return from;
}

let consoleError;
beforeAll(async () => {
  SO = fakeServer({ role: 'owner' });
  globalThis.fetch = SO.fetch;
  SO.proof = await stretch(PW, SALT, 3);
  const d = await unlockDrive({ password: PW });
  saveSessionKey(d.dk, SO.user.id); // the owner's Drive is unlocked in this tab: a set-up would go ahead
  globalThis.fetch = vi.fn(adminFetch);
  const html = readFileSync(join(process.cwd(), 'public/dashboard/admin/index.html'), 'utf8');
  document.body.innerHTML = `${html.match(/<main[\s\S]*<\/main>/)[0]}<div id="toast" role="status"></div>`;
  consoleError = vi.spyOn(console, 'error');
  await import('../public/dashboard/js/admin.js');
}, T);

describe('Admin → Users: a new user’s Drive', () => {
  it('a role without the Drive: no Drive request for the user, and the create form says no Drive was created', async () => {
    expect(loadSessionKey(SO.user.id)).not.toBeNull();
    nextDrive = { enabled: false };
    const from = await createUser('nodrive');
    expect(SO.requests.slice(from).some((r) => r.method === 'POST' && r.path === '/api/private/admin/users')).toBe(true);
    expect(userDriveCalls(from)).toEqual([]);
    expect(SO.adminKeys).toEqual([]);
    expect(note().textContent).toBe('nodrive: Drive is not enabled for this role, so no Drive was created.');
    expect(note().getAttribute('role')).toBe('status');
    expect(consoleError).not.toHaveBeenCalled();
  }, T);

  it('a role with the Drive: the owner’s browser sets it up now (one first set-up)', async () => {
    nextDrive = { enabled: true };
    const from = await createUser('withdrive');
    const calls = userDriveCalls(from);
    expect(calls.map((r) => `${r.method} ${r.path}`)).toEqual([`PUT /api/private/admin/drive/keys/${users.at(-1).id}`]);
    expect(calls[0].body.first).toBe(true);
    expect(note().textContent).toBe('withdrive: their Drive is set up now; they open it with the password you set.');
    expect(consoleError).not.toHaveBeenCalled();
  }, T);

  it('a race (the role loses the Drive before the set-up): the server’s 409 is the same case, with no error', async () => {
    nextDrive = { enabled: true };
    const n = users.length + 1;
    SO.driveOff.add(`u${String(n).padStart(15, '0')}`); // the id the next create gets
    const errors = [];
    const onError = (e) => errors.push(e);
    window.addEventListener('unhandledrejection', onError);
    window.addEventListener('error', onError);
    try {
      const from = await createUser('raced');
      expect(userDriveCalls(from).map((r) => r.path)).toEqual([`/api/private/admin/drive/keys/${users.at(-1).id}`]);
      expect(note().textContent).toBe('raced: Drive is not enabled for this role, so no Drive was created.');
      expect(document.getElementById('toast').classList.contains('error')).toBe(false);
    } finally {
      window.removeEventListener('unhandledrejection', onError);
      window.removeEventListener('error', onError);
    }
    expect(errors).toEqual([]);
    expect(consoleError).not.toHaveBeenCalled();
  }, T);

  it('a password reset for a user whose role has no Drive: no unlock prompt and no Drive request', async () => {
    const u = users.find((x) => x.username === 'nodrive');
    const row = [...usersPanel().querySelectorAll('tbody tr')].find((tr) => tr.textContent.includes('nodrive'));
    [...row.querySelectorAll('button')].find((b) => b.textContent === 'Manage').click();
    await until(() => document.querySelector('#user-detail [aria-label="New password"]'));
    expect(document.getElementById('reset-unlock').hidden).toBe(true);
    const from = SO.requests.length;
    document.querySelector('#user-detail [aria-label="New password"]').value = 'reset password';
    document.querySelector('#user-detail [aria-label="Repeat new password"]').value = 'reset password';
    [...document.querySelectorAll('#user-detail button')].find((b) => b.textContent === 'Set password').click();
    await until(() => SO.requests.slice(from).some((r) => r.path === `/api/private/admin/users/${u.id}/password`));
    await new Promise((r) => setTimeout(r, 200));
    expect(userDriveCalls(from)).toEqual([]);
    expect(consoleError).not.toHaveBeenCalled();
  }, T);
});
