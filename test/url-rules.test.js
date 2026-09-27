// url-rules.test.js — the admin's "links that may be shared" (urlRules limit):
// validated on save, global + per user, owner unrestricted, readable with an
// API key at GET /api/private/policy (the CLI checks links itself: the server
// cannot see them).
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, fetchJson, proofFor, USER_PW } from './helpers.js';

let oc;
beforeAll(async () => { oc = await owner(); });
const limits = (scope, patch) => fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope, channel: 'all', patch } });

describe('URL rules', () => {
  it('validates, inherits, overrides and is readable by the CLI', async () => {
    const u = await makeUser('url-rules');
    expect((await limits(u.id, { apiEnabled: true })).status).toBe(200);
    const key = (await (await fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body: { current: proofFor(USER_PW), name: 'cli' } })).json()).key;
    const policy = async () => (await fetchJson('/api/private/policy', { headers: { authorization: `Bearer ${key}` } })).json();
    expect((await policy()).urlRules).toEqual(['scheme:http://', 'scheme:https://']);
    for (const bad of [['scheme:javascript:'], ['scheme:data:'], ['re:(['], [], ['https'], 'scheme:https://', ['scheme:https'], ['scheme:tel'], ['scheme:https:']]) {
      expect((await limits('global', { urlRules: bad })).status).toBe(400);
    }
    expect((await limits('global', { urlRules: ['scheme:https://', 'scheme:tel:'] })).status).toBe(200);
    expect((await policy()).urlRules).toEqual(['scheme:https://', 'scheme:tel:']);
    expect((await limits(u.id, { urlRules: ['re:^https://([a-z0-9-]+\\.)*example\\.com/'] })).status).toBe(200);
    expect((await policy()).urlRules).toEqual(['re:^https://([a-z0-9-]+\\.)*example\\.com/']);
    const mine = await (await fetchJson('/api/private/policy', { cookie: oc })).json();
    expect(mine.urlRules).toEqual(['scheme:*']); // global settings never apply to the owner
    expect((await limits('global', { urlRules: ['scheme:http://', 'scheme:https://'] })).status).toBe(200);
  });

  it('an export from before the new syntax is upgraded on import', async () => {
    const CURRENT = proofFor('owner-password');
    const doc = (await (await fetchJson('/api/private/admin/export', { method: 'POST', cookie: oc, body: { current: CURRENT, system: true } })).json()).document;
    doc.system.limits.all.urlRules = ['scheme:https', 'scheme:tel', 'scheme:vscode'];
    const r = await fetchJson('/api/private/admin/import', { method: 'POST', cookie: oc, body: { current: CURRENT, document: doc, decisions: { system: true, users: {} }, dryRun: false } });
    expect(r.status).toBe(200);
    const ov = await (await fetchJson('/api/private/admin/overview', { cookie: oc })).json();
    expect(ov.limits.all.urlRules).toEqual(['scheme:https://', 'scheme:tel:', 'scheme:vscode://', 'scheme:vscode:']);
    await limits('global', { urlRules: ['scheme:http://', 'scheme:https://'] });
  });
});
