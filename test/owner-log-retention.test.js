// owner-log-retention.test.js — the owner's own activity-log retention
// (log.ownerMaxAgeSec / log.ownerMaxEntries, edited on the Owner role): kept
// forever by default; when set, old and excess entries about the owner and
// entries the owner made (admin actions, impersonation) are pruned, while
// server-wide configuration changes never are and other accounts' retention
// is unchanged. Also: validation, export/import and manual clearing.
import { describe, it, expect, beforeAll } from 'vitest';
import { env, runInDurableObject } from 'cloudflare:test';
import { owner, makeUser, fetchJson, proofFor, createNote, cookieOf, intent, freshIp } from './helpers.js';

const DAY = 86400;
const CURRENT = proofFor('owner-password');
const PUBLIC_ID = 'public-user-0000';
let oc;
let ownerId;
beforeAll(async () => {
  oc = await owner();
  const { users } = await (await fetchJson('/api/private/admin/users', { cookie: oc })).json();
  ownerId = users.find((x) => x.role === 'owner').id;
});
const dirStub = () => env.DIRECTORY.get(env.DIRECTORY.idFromName('directory'));
const settings = (patch) => fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: patch });
const overview = async () => (await (await fetchJson('/api/private/admin/overview', { cookie: oc })).json());
const audit = async (user) => (await (await fetchJson(`/api/private/admin/audit${user ? `?user=${user}` : ''}`, { cookie: oc })).json()).rows;
/** Every activity row, straight from storage (the audit API pages at 100). */
const allRows = () => runInDurableObject(dirStub(), async (_i, state) => state.storage.sql.exec('SELECT * FROM activity ORDER BY id').toArray());
const age = (sec) => runInDurableObject(dirStub(), async (_i, state) => { state.storage.sql.exec('UPDATE activity SET ts = ts - ?', sec); });
const prune = () => runInDurableObject(dirStub(), async (inst) => { await inst.alarm(); });
const insert = (n, actor, subject, action) => runInDurableObject(dirStub(), async (_i, state) => {
  const ts = Math.floor(Date.now() / 1000);
  for (let i = 0; i < n; i++) {
    state.storage.sql.exec('INSERT INTO activity (ts, actor_id, subject_id, action, detail, imp, adm) VALUES (?, ?, ?, ?, ?, 0, 0)', ts, actor, subject, action, `n=${i}`);
  }
});
/** What the owner's limits cover: about the owner or by the owner, not a configuration change. */
const PUBLIC_CONFIG = new Set(['limits.updated', 'quotas.updated', 'viewer_rules.updated']);
const owned = (r) => r.subject_id !== null && (r.subject_id === ownerId || r.actor_id === ownerId)
  && !(r.subject_id === PUBLIC_ID && r.actor_id === ownerId && (PUBLIC_CONFIG.has(r.action) || r.action.startsWith('tracker.')));

describe('owner log retention settings', () => {
  it('default to "keep forever", are validated and refuse out-of-range values', async () => {
    const o = await overview();
    expect(o.settings['log.ownerMaxAgeSec']).toBeNull();
    expect(o.settings['log.ownerMaxEntries']).toBeNull();
    expect(o.defaults.settings['log.ownerMaxAgeSec']).toBeNull();
    for (const bad of [{ 'log.ownerMaxAgeSec': 60 }, { 'log.ownerMaxAgeSec': 3651 * DAY }, { 'log.ownerMaxAgeSec': 'forever' }, { 'log.ownerMaxAgeSec': DAY + 0.5 },
      { 'log.ownerMaxEntries': 999 }, { 'log.ownerMaxEntries': 5000001 }, { 'log.ownerMaxEntries': false },
      // null is "keep forever" only for the owner's keys; the global ones always hold a value.
      { 'log.maxAgeSec': null }, { 'log.maxEntries': null }]) {
      const r = await settings(bad);
      expect(r.status, JSON.stringify(bad)).toBe(400);
      expect((await r.json()).error).toBe('invalid_setting');
    }
    expect((await settings({ 'log.ownerMaxAgeSec': 90 * DAY, 'log.ownerMaxEntries': 2000 })).status).toBe(200);
    expect((await overview()).settings['log.ownerMaxAgeSec']).toBe(90 * DAY);
    expect((await settings({ 'log.ownerMaxAgeSec': null, 'log.ownerMaxEntries': null })).status).toBe(200);
    const s = (await overview()).settings;
    expect([s['log.ownerMaxAgeSec'], s['log.ownerMaxEntries']]).toEqual([null, null]);
  });

  it('travel in the settings part of an export and are validated on import', async () => {
    const post = (path, body) => fetchJson(path, { method: 'POST', body, cookie: oc, ip: freshIp() });
    expect((await settings({ 'log.ownerMaxAgeSec': 200 * DAY, 'log.ownerMaxEntries': null })).status).toBe(200);
    const doc = (await (await post('/api/private/admin/export', { current: CURRENT, system: { settings: true } })).json()).document;
    expect(doc.system.settings['log.ownerMaxAgeSec']).toBe(200 * DAY);
    expect(doc.system.settings['log.ownerMaxEntries']).toBeNull();
    const imp = (document, dryRun) => post('/api/private/admin/import', { current: CURRENT, document, decisions: { system: { settings: true }, users: {} }, dryRun });
    for (const bad of [{ 'log.ownerMaxAgeSec': 5 }, { 'log.ownerMaxEntries': 'lots' }]) {
      const r = await imp({ ...doc, system: { settings: { ...doc.system.settings, ...bad } } }, true);
      expect(r.status).toBe(400);
    }
    expect((await settings({ 'log.ownerMaxAgeSec': null })).status).toBe(200);
    const r = await imp(doc, false);
    expect(r.status).toBe(200);
    expect((await overview()).settings['log.ownerMaxAgeSec']).toBe(200 * DAY);
    expect((await settings({ 'log.ownerMaxAgeSec': null })).status).toBe(200);
  });
});

describe('owner log pruning', () => {
  let u;
  it('by default keeps entries about the owner and the owner\'s own (impersonation included) forever', async () => {
    u = await makeUser('olr-alice');
    await createNote(u.cookie, {}, { label: 'own' }); // the user's own entry
    await createNote(oc, {}, { label: 'owner' }); // about the owner
    const imp = await fetchJson(`/api/private/admin/users/${u.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent });
    expect(imp.status).toBe(200);
    const ic = cookieOf(imp);
    expect((await createNote(ic, {}, { label: 'as-alice' })).res.status).toBe(201);
    expect((await fetchJson('/api/private/admin/unimpersonate', { method: 'POST', cookie: ic, headers: intent })).status).toBe(200);
    await age(4000 * DAY); // older than any limit could be
    await prune();
    const rows = await allRows();
    expect(rows.some((r) => r.action === 'share.created' && r.subject_id === ownerId)).toBe(true);
    expect(rows.some((r) => r.action === 'share.created' && r.subject_id === u.id && r.imp === 1 && r.actor_id === ownerId)).toBe(true);
    expect(rows.some((r) => r.action === 'impersonate.start' && r.subject_id === u.id)).toBe(true);
    expect(rows.some((r) => r.action === 'user.created' && r.subject_id === u.id)).toBe(true);
    // The user's own entries followed the global 365-day limit.
    expect(rows.some((r) => r.actor_id === u.id && r.subject_id === u.id)).toBe(false);
  });

  it('with an age limit set, prunes the owner\'s old entries but never configuration changes', async () => {
    // Configuration changes of every kind, all made by the owner.
    expect((await fetchJson('/api/private/admin/roles', { method: 'POST', cookie: oc, body: { name: 'olr-role' } })).status).toBe(201);
    expect((await fetchJson('/api/private/admin/ip-rules', { method: 'POST', cookie: oc, body: { cidr: '192.0.2.77', action: 'block', note: 'olr' } })).status).toBe(201);
    expect((await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: PUBLIC_ID, channel: 'all', patch: { maxViews: 5 } } })).status).toBe(200);
    expect((await fetchJson('/api/private/admin/export', { method: 'POST', cookie: oc, ip: freshIp(), body: { current: CURRENT, system: { settings: true } } })).status).toBe(200);
    expect((await settings({ 'log.ownerMaxAgeSec': 30 * DAY })).status).toBe(200);
    const configBefore = (await allRows()).filter((r) => !owned(r) && (r.subject_id === null || r.subject_id === PUBLIC_ID));
    expect(configBefore.map((r) => r.action)).toEqual(expect.arrayContaining(['settings.updated', 'role.created', 'iprule.added', 'limits.updated', 'export.created']));
    await age(400 * DAY);
    // Fresh activity after the ageing: kept.
    const v = await makeUser('olr-bob');
    await createNote(v.cookie, {}, { label: 'bob-own' });
    await createNote(oc, {}, { label: 'owner-fresh' });
    await prune();
    const rows = await allRows();
    const cutoff = Math.floor(Date.now() / 1000) - 30 * DAY;
    const mine = rows.filter(owned);
    expect(mine.length).toBeGreaterThan(0);
    expect(mine.every((r) => r.ts >= cutoff)).toBe(true); // nothing older than 30 days left
    expect(rows.some((r) => r.action === 'share.created' && r.subject_id === ownerId && r.ts < cutoff)).toBe(false);
    expect(rows.some((r) => r.imp === 1)).toBe(false); // the old impersonation records went
    expect(rows.some((r) => r.action === 'user.created' && r.subject_id === u.id)).toBe(false); // an old admin action
    expect(rows.some((r) => r.action === 'user.created' && r.subject_id === v.id)).toBe(true); // a fresh one
    expect(rows.some((r) => r.action === 'share.created' && r.subject_id === ownerId && r.ts >= cutoff)).toBe(true);
    // Every configuration change survived, however old.
    const ids = new Set(rows.map((r) => r.id));
    expect(configBefore.every((r) => ids.has(r.id))).toBe(true);
    // Another user's fresh entries are untouched.
    expect(rows.some((r) => r.actor_id === v.id && r.action === 'share.created')).toBe(true);
    expect((await settings({ 'log.ownerMaxAgeSec': null })).status).toBe(200);
  });

  it('with a size limit set, keeps only the newest owner entries; other accounts and configuration are untouched', async () => {
    const w = await makeUser('olr-carol');
    const x = await makeUser('olr-dave');
    // Dave's role keeps at most 10 entries about him (as before this feature).
    expect((await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: x.id, channel: 'all', patch: { logMaxEntries: 10 } } })).status).toBe(200);
    await insert(1200, ownerId, ownerId, 'test.owner');
    await insert(600, ownerId, w.id, 'test.admin'); // admin actions about Carol
    await insert(50, w.id, w.id, 'test.carol');
    await insert(14, x.id, x.id, 'test.dave');
    expect((await settings({ 'log.ownerMaxEntries': 1000 })).status).toBe(200);
    const before = await allRows();
    const config = before.filter((r) => !owned(r) && (r.subject_id === null || r.subject_id === PUBLIC_ID));
    expect(before.filter(owned).length).toBeGreaterThan(1800);
    await prune();
    const rows = await allRows();
    const mine = rows.filter(owned);
    expect(mine).toHaveLength(1000);
    // The newest were kept: everything owned newer than the oldest survivor is present.
    const oldestKept = mine[0].id;
    expect(before.filter((r) => owned(r) && r.id >= oldestKept)).toHaveLength(1000);
    expect(rows.filter((r) => r.action === 'test.admin')).toHaveLength(600); // the newest owned rows
    expect(rows.filter((r) => r.action === 'test.owner').length).toBeLessThan(1200);
    // Carol's own entries are not counted against the owner's limit.
    expect(rows.filter((r) => r.action === 'test.carol')).toHaveLength(50);
    // Dave's role limit still applies to his own entries.
    expect(rows.filter((r) => r.action === 'test.dave')).toHaveLength(10);
    const ids = new Set(rows.map((r) => r.id));
    expect(config.length).toBeGreaterThan(0);
    expect(config.every((r) => ids.has(r.id))).toBe(true);
    expect((await settings({ 'log.ownerMaxEntries': null })).status).toBe(200);
  });

  it('leaves clearing by hand as it was: the owner can still clear their own entries and configuration changes', async () => {
    const clear = (body) => fetchJson('/api/private/admin/logs/clear', { method: 'POST', cookie: oc, body: { current: CURRENT, ...body } });
    const r = await clear({ scope: 'user', user: ownerId });
    expect(r.status).toBe(200);
    expect((await r.json()).deleted).toBeGreaterThan(0);
    expect((await audit(ownerId))).toEqual([]);
    expect((await allRows()).some((row) => row.subject_id === null)).toBe(true);
    expect((await (await clear({ scope: 'all' })).json()).deleted).toBeGreaterThan(0);
    expect(await allRows()).toEqual([]);
  });
});
