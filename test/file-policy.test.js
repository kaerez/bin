// file-policy.test.js — the admin's file policy (allowed/blocked file types,
// folder depth) enforced against the client's declaration at upload init:
// no declaration is asked for without a policy, a missing one is refused with
// the policy attached, refused types are named, the owner is exempt, and the
// API channel can only tighten the depth.
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, fetchJson } from './helpers.js';

let oc;
beforeAll(async () => { oc = await owner(); });

const limits = (scope, channel, patch) => fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope, channel, patch } });
const init = (cookie, extra = {}, headers = {}) => fetchJson('/api/private/file', {
  method: 'POST', cookie, headers, body: { views: 1, expire: '1h', padded: 65536, files: 1, maxFile: 10, ...extra },
});
const PDF = { ext: 'pdf', mime: 'application/pdf' };
const PNG = { ext: 'png', mime: 'image/png' };
const EXE = { ext: 'exe', mime: 'application/x-msdownload' };

describe('file policy', () => {
  it('asks for nothing when no policy applies', async () => {
    const u = await makeUser('policy-free');
    expect((await init(u.cookie)).status).toBe(201);
  });

  it('allow list: requires a declaration and refuses unlisted types, naming them', async () => {
    const u = await makeUser('policy-allow');
    expect((await limits(u.id, 'all', { fileTypeMode: 'allow', fileTypeRules: ['ext:pdf', 'mime:image/*'] })).status).toBe(200);
    const missing = await init(u.cookie);
    expect(missing.status).toBe(400);
    const m = await missing.json();
    expect(m.error).toBe('declaration_required');
    expect(m.policy).toEqual({ mode: 'allow', rules: ['ext:pdf', 'mime:image/*'], maxFolderDepth: null });
    expect((await init(u.cookie, { types: [PDF, PNG], depth: 0 })).status).toBe(201);
    const bad = await init(u.cookie, { types: [PDF, EXE] });
    expect(bad.status).toBe(403);
    const b = await bad.json();
    expect(b.error).toBe('file_type_not_allowed');
    expect(b.refused).toEqual([EXE]);
    expect(b.message).toContain('.exe (application/x-msdownload)');
  });

  it('block list: refuses matching types only', async () => {
    const u = await makeUser('policy-block');
    await limits(u.id, 'all', { fileTypeMode: 'block', fileTypeRules: ['ext:exe', 'mime:application/x-msdownload'] });
    expect((await init(u.cookie, { types: [PDF] })).status).toBe(201);
    expect((await init(u.cookie, { types: [{ ext: 'bin', mime: 'application/x-msdownload' }] })).status).toBe(403);
  });

  it('folder depth: requires a declaration and enforces the maximum (the API channel can only tighten it)', async () => {
    const u = await makeUser('policy-depth');
    await limits(u.id, 'all', { maxFolderDepth: 2, apiEnabled: true });
    expect((await (await init(u.cookie)).json()).error).toBe('declaration_required');
    expect((await init(u.cookie, { depth: 2 })).status).toBe(201);
    const deep = await init(u.cookie, { depth: 3 });
    expect(deep.status).toBe(403);
    expect((await deep.json()).error).toBe('folder_too_deep');
    // API channel: tightened to 1 for API keys; the web UI keeps 2.
    expect((await limits(u.id, 'api', { maxFolderDepth: 1 })).status).toBe(200);
    const key = (await (await fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body: { name: 'k' } })).json()).key;
    const viaApi = await init(undefined, { depth: 2 }, { authorization: `Bearer ${key}` });
    expect(viaApi.status).toBe(403);
    expect((await init(undefined, { depth: 1 }, { authorization: `Bearer ${key}` })).status).toBe(201);
    // …and the API channel cannot carry type policy (it applies to all channels alike).
    expect((await limits(u.id, 'api', { fileTypeMode: 'allow' })).status).toBe(400);
  });

  it('rejects malformed declarations and invalid policy values', async () => {
    const u = await makeUser('policy-validate');
    await limits(u.id, 'all', { fileTypeMode: 'allow', fileTypeRules: ['ext:pdf'] });
    for (const types of ['pdf', [{ ext: 'p d f', mime: 'application/pdf' }], [{ ext: 'pdf', mime: 'not a mime' }], Array(1001).fill(PDF)]) {
      expect((await init(u.cookie, { types })).status).toBe(400);
    }
    for (const patch of [{ fileTypeMode: 'everything' }, { fileTypeRules: ['exe'] }, { fileTypeRules: ['mime:*/*'] }, { fileTypeRules: 'ext:pdf' }, { maxFolderDepth: 65 }]) {
      expect([patch, (await limits(u.id, 'all', patch)).status]).toEqual([patch, 400]);
    }
  });

  it('shows the policy in the profile and exempts the owner', async () => {
    const u = await makeUser('policy-profile');
    await limits(u.id, 'all', { fileTypeMode: 'allow', fileTypeRules: ['ext:pdf'], maxFolderDepth: 1 });
    const me = await (await fetchJson('/api/private/me', { cookie: u.cookie })).json();
    expect(me.limits).toMatchObject({ fileTypeMode: 'allow', fileTypeRules: ['ext:pdf'], maxFolderDepth: 1 });
    await limits('global', 'all', { fileTypeMode: 'allow', fileTypeRules: ['ext:pdf'] });
    expect((await init(oc)).status).toBe(201); // the owner is unlimited
    await limits('global', 'all', { fileTypeMode: 'any', fileTypeRules: [] });
  });
});
