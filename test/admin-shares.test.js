// admin-shares.test.js — the owner's view of every user's shares: filters
// (users, kind, status, label, locked, created/expiry ranges) with correct
// totals, direct admin edits that never appear in the user's own activity,
// locks that freeze a share for its sender (edit, revoke and delete token),
// and the Directory schema migrations for instances created by older releases.
import { env, runInDurableObject } from 'cloudflare:test';
import { describe, it, expect, beforeAll, vi, afterEach } from 'vitest';
import { owner, makeUser, fetchJson, createNote, intent } from './helpers.js';
import { Directory, SCHEMA_VERSION } from '../src/directory-do.js';

let oc;
beforeAll(async () => { oc = await owner(); });
afterEach(() => vi.useRealTimers());

const adminList = async (qs = '') => (await fetchJson(`/api/private/admin/shares${qs}`, { cookie: oc })).json();
const adminPatch = (id, body) => fetchJson(`/api/private/admin/shares/${id}`, { method: 'PATCH', cookie: oc, body });
const lock = (id, locked) => fetchJson(`/api/private/admin/shares/${id}/lock`, { method: 'POST', cookie: oc, body: { locked } });

describe('admin share list', () => {
  it('shows every user\'s shares and filters by user, label, kind, lock and time ranges with correct totals', async () => {
    const a = await makeUser('share-owner-a');
    const b = await makeUser('share-owner-b');
    const t0 = Math.floor(Date.now() / 1000);
    const n1 = await createNote(a.cookie, { expire: '1h' }, { label: 'invoice one' });
    const n2 = await createNote(a.cookie, { expire: '7d' }, { label: 'invoice two' });
    const n3 = await createNote(b.cookie, { expire: '1h' }, { label: 'holiday' });

    const both = await adminList(`?users=${a.id},${b.id}`);
    expect(both.total).toBe(3);
    expect(both.rows.map((r) => r.username).sort()).toEqual(['share-owner-a', 'share-owner-a', 'share-owner-b']);

    const onlyA = await adminList(`?users=${a.id}`);
    expect(onlyA.total).toBe(2);
    const invoices = await adminList(`?users=${a.id},${b.id}&q=invoice`);
    expect(invoices.total).toBe(2);
    expect(invoices.rows.every((r) => r.label.startsWith('invoice'))).toBe(true);
    expect((await adminList(`?users=${a.id},${b.id}&kind=files`)).total).toBe(0);

    // Expiry range: only the 7-day note expires after t0 + 1 day.
    const later = await adminList(`?users=${a.id},${b.id}&expiresFrom=${t0 + 86400}`);
    expect(later.rows.map((r) => r.id)).toEqual([n2.id]);
    const soon = await adminList(`?users=${a.id},${b.id}&expiresTo=${t0 + 7200}`);
    expect(soon.rows.map((r) => r.id).sort()).toEqual([n1.id, n3.id].sort());
    // Creation range: everything was created at/after t0, nothing before.
    expect((await adminList(`?users=${a.id},${b.id}&createdFrom=${t0 - 5}`)).total).toBe(3);
    expect((await adminList(`?users=${a.id},${b.id}&createdTo=${t0 - 5}`)).total).toBe(0);

    await lock(n3.id, true);
    const locked = await adminList(`?users=${a.id},${b.id}&locked=true`);
    expect(locked.rows.map((r) => r.id)).toEqual([n3.id]);
    expect(locked.rows[0].locked_by).toBeTruthy();
    expect((await adminList(`?users=${a.id},${b.id}&locked=false`)).total).toBe(2);
    // Junk filter values are ignored, never an error.
    expect((await fetchJson(`/api/private/admin/shares?users=${a.id},../x&kind=evil&status=x&createdFrom=-1&limit=9999`, { cookie: oc })).status).toBe(200);
  });

  it('is owner-only', async () => {
    const u = await makeUser('not-an-admin');
    expect((await fetchJson('/api/private/admin/shares', { cookie: u.cookie })).status).toBe(403);
  });
});

describe('admin share edits', () => {
  it('change a user\'s share without appearing in the user\'s own activity (the audit shows them)', async () => {
    const u = await makeUser('edited-user');
    const n = await createNote(u.cookie, { bar: true, views: 2, expire: '1h' }, { label: 'before' });
    expect((await adminPatch(n.id, { label: 'after', views: 5 })).status).toBe(200);
    const mine = await (await fetchJson('/api/private/shares', { cookie: u.cookie })).json();
    const row = mine.rows.find((r) => r.id === n.id);
    expect(row.label).toBe('after');
    expect(row.views_total).toBe(5);

    const activity = await (await fetchJson('/api/private/me/activity', { cookie: u.cookie })).json();
    expect(activity.rows.some((r) => r.action === 'share.updated')).toBe(false);
    expect(activity.rows.some((r) => r.action === 'share.created')).toBe(true);
    const audit = await (await fetchJson(`/api/private/admin/audit?subject=${u.id}`, { cookie: oc })).json();
    const entry = (audit.rows || audit).find((r) => r.action === 'share.updated');
    expect(entry).toMatchObject({ adm: 1, subject: 'edited-user' });
  });

  it('admin edits are still increase-only and bounded by the protocol maxima', async () => {
    const u = await makeUser('bounded-user');
    const n = await createNote(u.cookie, { bar: true, views: 3, expire: '1h' });
    expect((await adminPatch(n.id, { views: 2 })).status).toBe(400);
    expect((await adminPatch(n.id, { views: 100001 })).status).toBe(400);
    expect((await adminPatch(n.id, { expires: Math.floor(Date.now() / 1000) + 366 * 86400 })).status).toBe(400);
  });
});

describe('share locks', () => {
  it('freeze a share for its sender — edits, revoke and the delete token — but not for the admin', async () => {
    const u = await makeUser('locked-user');
    const n = await createNote(u.cookie, { bar: true, views: 2, expire: '1h' }, { label: 'frozen' });
    expect((await lock(n.id, true)).status).toBe(200);

    const edit = await fetchJson(`/api/private/shares/${n.id}`, { method: 'PATCH', cookie: u.cookie, body: { label: 'nope' } });
    expect(edit.status).toBe(423);
    expect((await edit.json()).error).toBe('share_locked');
    expect((await fetchJson(`/api/private/shares/${n.id}/revoke`, { method: 'POST', cookie: u.cookie, headers: intent })).status).toBe(423);
    expect((await fetchJson(`/api/paste/${n.id}`, { method: 'DELETE', headers: { 'x-delete-token': n.deletetoken } })).status).toBe(423);
    // The user's list shows the lock.
    const mine = await (await fetchJson('/api/private/shares', { cookie: u.cookie })).json();
    expect(mine.rows.find((r) => r.id === n.id).locked).toBe(1);

    // The admin can still change it…
    expect((await adminPatch(n.id, { label: 'admin changed' })).status).toBe(200);
    // …and after unlocking, the sender's controls work again.
    expect((await lock(n.id, false)).status).toBe(200);
    expect((await fetchJson(`/api/private/shares/${n.id}`, { method: 'PATCH', cookie: u.cookie, body: { label: 'mine again' } })).status).toBe(200);
    expect((await fetchJson(`/api/private/shares/${n.id}/revoke`, { method: 'POST', cookie: u.cookie, headers: intent })).status).toBe(200);

    // Lock/unlock are admin actions, hidden from the user's log.
    const activity = await (await fetchJson('/api/private/me/activity', { cookie: u.cookie })).json();
    expect(activity.rows.some((r) => /share\.(un)?locked/.test(r.action))).toBe(false);
  });

  it('admin revoke works on a locked share', async () => {
    const u = await makeUser('revoked-by-admin');
    const n = await createNote(u.cookie, { bar: true, views: 1 });
    await lock(n.id, true);
    expect((await fetchJson(`/api/private/admin/shares/${n.id}/revoke`, { method: 'POST', cookie: oc, headers: intent })).status).toBe(200);
    const row = (await adminList(`?users=${u.id}`)).rows[0];
    expect(row.status).toBe('revoked');
  });

  it('a refused revoke destroys nothing, re-recording keeps the lock, and only the owner may act as admin', async () => {
    const u = await makeUser('lock-hardening');
    const n = await createNote(u.cookie, {});
    expect(n.res.status).toBe(201);
    await lock(n.id, true);
    expect((await fetchJson(`/api/private/shares/${n.id}/revoke`, { method: 'POST', cookie: u.cookie, headers: intent })).status).toBe(423);
    expect(await env.PASTES.get(n.id)).not.toBeNull(); // content untouched
    const dir = env.DIRECTORY.get(env.DIRECTORY.idFromName('directory'));
    await runInDurableObject(dir, async (instance) => {
      const row = await instance.adminShare(n.id);
      await instance.recordShare({ id: n.id, uid: row.user_id, kind: row.kind, label: row.label, created: row.created, expires: row.expires, views: row.views_total });
      expect(await instance.isShareLocked(n.id)).toBe(true);
      const forged = await instance.updateShare(null, n.id, { label: 'x' }, row.user_id, { admin: row.user_id });
      expect(forged.status).toBe(403);
    });
  });

  it('validates the lock body and unknown ids', async () => {
    const u = await makeUser('lock-validation');
    const n = await createNote(u.cookie, {});
    expect((await fetchJson(`/api/private/admin/shares/${n.id}/lock`, { method: 'POST', cookie: oc, body: { locked: 'yes' } })).status).toBe(400);
    expect((await fetchJson('/api/private/admin/shares/kAAAAAAAAAAAAAAAAAAAAAA/lock', { method: 'POST', cookie: oc, body: { locked: true } })).status).toBe(404);
  });
});

describe('Directory schema migrations', () => {
  it('upgrade a Directory created by an older release, idempotently', async () => {
    const stub = env.DIRECTORY.get(env.DIRECTORY.idFromName('migration-test'));
    await runInDurableObject(stub, async (_instance, state) => {
      const sql = state.storage.sql;
      const cols = (t) => sql.exec(`PRAGMA table_info(${t})`).toArray().map((c) => c.name);
      // Roll this instance back to the pre-migration shape.
      for (const c of ['locked', 'locked_by', 'locked_at']) sql.exec(`ALTER TABLE shares DROP COLUMN ${c}`);
      for (const c of ['imp', 'adm']) sql.exec(`ALTER TABLE activity DROP COLUMN ${c}`);
      sql.exec("DELETE FROM meta WHERE k = 'schema_version'");
      expect(cols('shares')).not.toContain('locked');

      // Constructing the Directory on the old storage migrates it…
      const d1 = new Directory(state, env);
      await state.blockConcurrencyWhile(async () => {});
      expect(cols('shares')).toEqual(expect.arrayContaining(['locked', 'locked_by', 'locked_at']));
      expect(cols('activity')).toEqual(expect.arrayContaining(['imp', 'adm']));
      expect(await d1.schemaVersion()).toBe(SCHEMA_VERSION);
      // …and doing it again is a no-op.
      const d2 = new Directory(state, env);
      await state.blockConcurrencyWhile(async () => {});
      expect(await d2.schemaVersion()).toBe(SCHEMA_VERSION);
    });
  });
});
