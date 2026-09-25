// logs.test.js — activity-log retention (global age/size, per-user limits,
// owner entries exempt) and the admin's "clear logs" (password step-up; all,
// one account, older than a date; leaves no record).
import { describe, it, expect, beforeAll } from 'vitest';
import { env, runInDurableObject } from 'cloudflare:test';
import { owner, makeUser, fetchJson, proofFor, createNote } from './helpers.js';

let oc;
beforeAll(async () => { oc = await owner(); });
const dirStub = () => env.DIRECTORY.get(env.DIRECTORY.idFromName('directory'));
const audit = async (user) => (await (await fetchJson(`/api/private/admin/audit${user ? `?user=${user}` : ''}`, { cookie: oc })).json()).rows;
const clear = (body) => fetchJson('/api/private/admin/logs/clear', { method: 'POST', cookie: oc, body: { current: proofFor('owner-password'), ...body } });

describe('activity log', () => {
  it('clear needs the password, then deletes one account\'s entries or everything older than a date', async () => {
    const a = await makeUser('log-a');
    const b = await makeUser('log-b');
    await createNote(a.cookie, {}, { label: 'x' });
    await createNote(b.cookie, {}, { label: 'y' });
    expect((await audit(a.id)).length).toBeGreaterThan(0);
    expect((await fetchJson('/api/private/admin/logs/clear', { method: 'POST', cookie: oc, body: { current: proofFor('wrong-password-9'), scope: 'all' } })).status).toBe(403);
    const r = await clear({ scope: 'user', user: a.id });
    expect(r.status).toBe(200);
    expect((await r.json()).deleted).toBeGreaterThan(0);
    expect(await audit(a.id)).toEqual([]); // and nothing says it happened
    expect((await audit(b.id)).length).toBeGreaterThan(0);
    expect((await (await clear({ scope: 'all', before: 1 })).json()).deleted).toBe(0); // nothing older than 1970
    expect((await clear({ scope: 'bogus' })).status).toBe(400);
  });

  it('prunes by age and size, per account, never the owner\'s entries', async () => {
    const u = await makeUser('log-c');
    expect((await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: u.id, channel: 'all', patch: { logMaxEntries: 10 } } })).status).toBe(200);
    for (let i = 0; i < 14; i++) await createNote(u.cookie);
    // Age everything, including the owner's own entries, far into the past.
    await runInDurableObject(dirStub(), async (_inst, state) => { state.storage.sql.exec('UPDATE activity SET ts = ts - ?', 400 * 86400); });
    await runInDurableObject(dirStub(), async (inst) => { await inst.alarm(); });
    const { users } = await (await fetchJson('/api/private/admin/users', { cookie: oc })).json();
    const ownerId = users.find((x) => x.role === 'owner').id;
    const rows = await audit();
    expect(rows.every((r) => r.subject_id === ownerId)).toBe(true); // 365-day default removed the rest
    expect(rows.length).toBeGreaterThan(0);
    // Per-account size: a fresh burst keeps only the newest 10.
    for (let i = 0; i < 14; i++) await createNote(u.cookie);
    await runInDurableObject(dirStub(), async (inst) => { await inst.alarm(); });
    expect((await audit(u.id)).length).toBe(10);
  });
});
