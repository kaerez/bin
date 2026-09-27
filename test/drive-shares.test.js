// drive-shares.test.js — Drive shares (docs/DRIVE.md §7) in workerd: a
// FileShare record referencing Drive files, authorized like a file share
// (limits, file policy declarations, quotas), opened like one (the open adds
// `refs`), chunks read by (ref, i); when a share ends only the share goes,
// and deleting a Drive item ends every share of it.
import { env, SELF, runDurableObjectAlarm } from 'cloudflare:test';
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import { ORIGIN, owner, makeUser, fetchJson, intent, proofHeaders, freshIp } from './helpers.js';
import { enableDrive, driveLimits, mkdir, createFile, uploadFile, del } from './drive-helpers.js';
import { encryptPaste, openPaste } from '../public/js/crypto.js';
import { b64urlFromBytes, randomBytes } from '../public/js/bytes.js';

let oc;
beforeAll(async () => { oc = await owner(); });
afterEach(() => vi.useRealTimers());

/** A v3 manifest for `files` [{id, path}] (the server never reads it: it is encrypted). */
async function sealManifest(files, { views = null, expire = '1h', deletable = false, password = '' } = {}) {
  const manifest = { v: 3, kind: 'refs', entries: files.map((f, ref) => ({ path: f.path, size: f.size ?? 0, type: 'application/octet-stream', mtime: 0, ref, fk: b64urlFromBytes(randomBytes(32)) })), dirs: [] };
  return encryptPaste({ text: JSON.stringify(manifest), fmt: 'files', bar: views !== null, views: views ?? undefined, expire, password, deletable });
}

async function share(cookie, nodes, { views = null, expire = '1h', deletable = false, label, extra = {}, sealAs = {} } = {}) {
  const { body, fragment } = await sealManifest(nodes.map((id, i) => ({ id, path: `f${i}` })), { views, expire, deletable, ...sealAs });
  const res = await fetchJson('/api/private/drive/shares', { method: 'POST', cookie, body: { nodes, views, expire, deletable, label, paste: body, ...extra } });
  return { res, fragment, ...(res.status === 201 ? await res.json() : {}) };
}

async function open(id, fragment, password = '', ip = freshIp()) {
  const head = await (await fetchJson(`/api/file/${id}`, { ip })).json();
  const { headers, access } = await proofHeaders(head.adata, fragment, password);
  const res = await fetchJson(`/api/file/${id}/open`, { method: 'POST', headers, ip });
  return { res, access, head };
}
const refChunk = (id, ref, i, grant) => SELF.fetch(`${ORIGIN}/api/file/${id}/chunk/${ref}/${i}`, { headers: { 'x-download-grant': grant } });
const bytesOf = async (r) => Array.from(new Uint8Array(await r.arrayBuffer()));
const myShares = async (cookie, q = '') => (await (await fetchJson(`/api/private/shares${q}`, { cookie })).json()).rows;

describe('Drive shares', () => {
  let u;
  beforeAll(async () => { u = await makeUser('dsh-main'); await enableDrive(u.id); });

  it('share files by reference: open adds refs, chunks by (ref, i), nothing copied', async () => {
    const folder = await mkdir(u.cookie);
    const a = await uploadFile(u.cookie, folder.id, 300);
    const b = await uploadFile(u.cookie, 'root', 50);
    // `nodes` lists files (the browser flattens folders): refs[i] is nodes[i].
    const dirShare = await share(u.cookie, [folder.id, a.id]);
    expect(dirShare.res.status).toBe(400);
    expect((await dirShare.res.json()).error).toBe('not_a_file');
    const s = await share(u.cookie, [a.id, b.id], { views: 3, label: 'drive share' });
    expect(s.res.status).toBe(201);
    expect(s.id[0]).toBe('f');
    expect(s.deletetoken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const o = await open(s.id, s.fragment);
    expect(o.res.status).toBe(200);
    const body = await o.res.json();
    expect(body.refs).toEqual([{ chunks: 1, size: 300 }, { chunks: 1, size: 50 }]);
    expect(body.paste.meta).toMatchObject({ views: 3, left: 2 });
    const manifest = JSON.parse((await openPaste({ paste: body.paste, access: o.access })).text);
    expect(manifest).toMatchObject({ v: 3, kind: 'refs' });
    const r0 = await refChunk(s.id, 0, 0, body.grant);
    expect(r0.status).toBe(200);
    expect(await bytesOf(r0)).toEqual(Array.from(a.chunks[0]));
    expect(await bytesOf(await refChunk(s.id, 1, 0, body.grant))).toEqual(Array.from(b.chunks[0]));
    expect((await refChunk(s.id, 2, 0, body.grant)).status).toBe(404);
    expect((await refChunk(s.id, 0, 1, body.grant)).status).toBe(404);
    expect((await refChunk(s.id, 0, 0, 'A'.repeat(43))).status).toBe(403);
    // The single-stream route has nothing for a Drive share.
    expect((await SELF.fetch(`${ORIGIN}/api/file/${s.id}/chunk/0`, { headers: { 'x-download-grant': body.grant } })).status).toBe(404);
    // Nothing was written under f/.
    expect((await env.FILES.list({ prefix: `f/${s.id}/` })).objects).toHaveLength(0);
    // My shares shows it as kind "drive"; the admin can filter on it.
    const row = (await myShares(u.cookie)).find((r) => r.id === s.id);
    expect(row).toMatchObject({ kind: 'drive', label: 'drive share', status: 'active', views_total: 3, left: 2 });
    const adm = await (await fetchJson(`/api/private/admin/shares?kind=drive&users=${u.id}`, { cookie: oc })).json();
    expect(adm.rows.map((r) => r.id)).toContain(s.id);
    expect(adm.rows.every((r) => r.kind === 'drive')).toBe(true);
  });

  it('several shares per item, listed per item; ending a share leaves the data', async () => {
    const f = await uploadFile(u.cookie, 'root', 100);
    const s1 = await share(u.cookie, [f.id], { expire: '1h' });
    const s2 = await share(u.cookie, [f.id], { views: 1 });
    const s3 = await share(u.cookie, [f.id]);
    for (const s of [s1, s2, s3]) expect(s.res.status).toBe(201);
    const rows = async () => (await (await fetchJson(`/api/private/drive/nodes/${f.id}/shares`, { cookie: u.cookie })).json()).shares;
    const list = async () => (await rows()).map((x) => x.id).sort();
    expect(await list()).toEqual([s1.id, s2.id, s3.id].sort());
    // Rows as in My shares (with `state` / `maxViews` aliases).
    expect((await rows()).find((x) => x.id === s2.id)).toMatchObject({ kind: 'drive', status: 'active', state: 'active', views_total: 1, maxViews: 1, left: 1, label: '', created: expect.any(Number), expires: expect.any(Number) });
    // s2: its only view spent (then purged when the grant runs out).
    const o = await open(s2.id, s2.fragment);
    expect(o.res.status).toBe(200);
    // s3: revoked from My shares.
    expect((await fetchJson(`/api/private/shares/${s3.id}/revoke`, { method: 'POST', cookie: u.cookie, headers: intent })).status).toBe(200);
    // s1: expires.
    vi.useFakeTimers({ now: Date.now() + 2 * 3600 * 1000, toFake: ['Date'] });
    for (const s of [s1, s2]) await runDurableObjectAlarm(env.FILESHARE.get(env.FILESHARE.idFromName(s.id)));
    vi.useRealTimers();
    expect((await fetchJson(`/api/file/${s1.id}`)).status).toBe(410);
    expect(await list()).toEqual([]);
    // The Drive file is untouched.
    expect(await env.FILES.get(`d/${u.id}/${f.id}/0`)).not.toBeNull();
    const own = await SELF.fetch(`${ORIGIN}/api/private/drive/files/${f.id}/chunk/0`, { headers: { cookie: u.cookie } });
    expect(await bytesOf(own)).toEqual(Array.from(f.chunks[0]));
  });

  it('deleting a Drive item ends every share of it (recipients get "gone")', async () => {
    const folder = await mkdir(u.cookie);
    const sub = await mkdir(u.cookie, folder.id);
    const f = await uploadFile(u.cookie, folder.id, 100);
    const g = await uploadFile(u.cookie, sub.id, 100);
    const other = await uploadFile(u.cookie, 'root', 10);
    const byFile = await share(u.cookie, [f.id]);
    const byFolder = await share(u.cookie, [g.id, f.id]); // the folder's files, flattened
    const unrelated = await share(u.cookie, [other.id]);
    const o = await open(byFile.id, byFile.fragment);
    const { grant } = await o.res.json();
    const r = await del(u.cookie, folder.id);
    expect(await r.json()).toMatchObject({ ok: true, sharesEnded: 2 });
    for (const s of [byFile, byFolder]) expect((await fetchJson(`/api/file/${s.id}`)).status).toBe(410);
    expect((await refChunk(byFile.id, 0, 0, grant)).status).toBe(410);
    const rows = await myShares(u.cookie);
    for (const s of [byFile, byFolder]) expect(rows.find((x) => x.id === s.id).status).toBe('revoked');
    expect(rows.find((x) => x.id === unrelated.id).status).toBe('active');
    expect((await open(unrelated.id, unrelated.fragment)).res.status).toBe(200);
  });

  it('checks what it is given: items exist, files are complete, the manifest matches', async () => {
    const f = await uploadFile(u.cookie, 'root', 10);
    const pend = await createFile(u.cookie, 'root', 10);
    expect((await share(u.cookie, [pend.id])).res.status).toBe(409);
    expect((await share(u.cookie, [b64urlFromBytes(randomBytes(16))])).res.status).toBe(404);
    expect((await share(u.cookie, [f.id, f.id])).res.status).toBe(400);
    expect((await share(u.cookie, ['root'])).res.status).toBe(400);
    expect((await share(u.cookie, [])).res.status).toBe(400);
    // The encrypted manifest must declare the same views / expiry / delete setting.
    const mm = await share(u.cookie, [f.id], { views: 2, sealAs: { views: 3 } });
    expect(mm.res.status).toBe(400);
    expect((await share(u.cookie, [f.id], { expire: '1h', sealAs: { expire: '2h' } })).res.status).toBe(400);
    expect((await share(u.cookie, [f.id], { expire: 'forever' })).res.status).toBe(400);
    // `acc` may also travel next to the paste.
    const { body, fragment } = await sealManifest([{ id: f.id, path: 'x' }]);
    const { acc, ...paste } = body;
    const sep = await fetchJson('/api/private/drive/shares', { method: 'POST', cookie: u.cookie, body: { nodes: [f.id], views: null, expire: '1h', paste, acc } });
    expect(sep.status).toBe(201);
    expect((await open((await sep.json()).id, fragment)).res.status).toBe(200);
    // …or in both places (as the browser sends it), then the same.
    expect((await fetchJson('/api/private/drive/shares', { method: 'POST', cookie: u.cookie, body: { nodes: [f.id], views: null, expire: '1h', paste: body, acc } })).status).toBe(201);
    const other = await sealManifest([{ id: f.id, path: 'y' }]);
    expect((await fetchJson('/api/private/drive/shares', { method: 'POST', cookie: u.cookie, body: { nodes: [f.id], views: null, expire: '1h', paste: body, acc: other.body.acc } })).status).toBe(400);
    // An empty file is shared with no chunks.
    const empty = await uploadFile(u.cookie, 'root', 0);
    const es = await share(u.cookie, [empty.id]);
    expect((await (await open(es.id, es.fragment)).res.json()).refs).toEqual([{ chunks: 0, size: 0 }]);
  });

  it('another user cannot share (or list shares of) my items', async () => {
    const f = await uploadFile(u.cookie, 'root', 10);
    const other = await makeUser('dsh-other');
    await enableDrive(other.id);
    expect((await share(other.cookie, [f.id])).res.status).toBe(404);
    expect((await fetchJson(`/api/private/drive/nodes/${f.id}/shares`, { cookie: other.cookie })).status).toBe(404);
  });
});

describe('Drive shares obey the role', () => {
  it('file sharing, views, expiry, files per share, recipient delete, file policy', async () => {
    const u = await makeUser('dsh-limits');
    await enableDrive(u.id, { maxViews: 5, allowUnlimitedViews: false, maxExpireSec: 3600, maxFilesPerShare: 2, openerDelete: false });
    const f1 = await uploadFile(u.cookie, 'root', 10);
    const f2 = await uploadFile(u.cookie, 'root', 10);
    const f3 = await uploadFile(u.cookie, 'root', 10);
    const code = async (s) => (await s.res.json()).error;
    expect(await code(await share(u.cookie, [f1.id], { views: null }))).toBe('unlimited_views_disabled');
    expect(await code(await share(u.cookie, [f1.id], { views: 6 }))).toBe('too_many_views');
    expect(await code(await share(u.cookie, [f1.id], { views: 1, expire: '2h' }))).toBe('expiry_too_long');
    expect(await code(await share(u.cookie, [f1.id, f2.id, f3.id], { views: 1 }))).toBe('too_many_files');
    expect(await code(await share(u.cookie, [f1.id], { views: 1, deletable: true }))).toBe('opener_delete_disabled');
    expect((await share(u.cookie, [f1.id, f2.id], { views: 5 })).res.status).toBe(201);
    // A file policy needs the declaration, as for file shares.
    await driveLimits(u.id, { fileTypeMode: 'block', fileTypeRules: ['ext:exe'] });
    const need = await share(u.cookie, [f1.id], { views: 1 });
    expect(await code(need)).toBe('declaration_required');
    expect(await code(await share(u.cookie, [f1.id], { views: 1, extra: { types: [{ ext: 'exe', mime: 'application/x-msdownload' }] } }))).toBe('file_type_not_allowed');
    expect((await share(u.cookie, [f1.id], { views: 1, extra: { types: [{ ext: 'txt', mime: 'text/plain' }] } })).res.status).toBe(201);
    await driveLimits(u.id, { files: false });
    expect(await code(await share(u.cookie, [f1.id], { views: 1 }))).toBe('files_disabled');
    // Stream-size caps do not apply: the files are already in the Drive.
    await driveLimits(u.id, { files: true, maxShareBytes: 1, maxFileBytes: 1, fileTypeMode: 'any', fileTypeRules: [] });
    expect((await share(u.cookie, [f1.id], { views: 1 })).res.status).toBe(201);
  });

  it('quotas count Drive shares as file shares', async () => {
    const u = await makeUser('dsh-quota');
    await enableDrive(u.id);
    const f = await uploadFile(u.cookie, 'root', 10);
    const q = await fetchJson('/api/private/admin/quotas', { method: 'PUT', cookie: oc, body: { scope: u.id, list: [{ channel: 'all', kind: 'files', n: 1, unit: 'd', max: 2 }] } });
    expect(q.status).toBe(200);
    expect((await share(u.cookie, [f.id])).res.status).toBe(201);
    expect((await share(u.cookie, [f.id])).res.status).toBe(201);
    const over = await share(u.cookie, [f.id]);
    expect(over.res.status).toBe(429);
    expect((await over.res.json()).error).toBe('quota_exceeded');
    const me = await (await fetchJson('/api/private/me', { cookie: u.cookie })).json();
    expect(me.quotas.find((x) => x.kind === 'files').used).toBe(2);
  });

  it('a recipient may "delete now" when allowed: only the share goes', async () => {
    const u = await makeUser('dsh-del');
    await enableDrive(u.id, { openerDelete: true });
    const f = await uploadFile(u.cookie, 'root', 10);
    const s = await share(u.cookie, [f.id], { deletable: true });
    expect(s.res.status).toBe(201);
    const o = await open(s.id, s.fragment);
    const head = o.head;
    const { headers } = await proofHeaders(head.adata, s.fragment);
    expect((await fetchJson(`/api/file/${s.id}/expire`, { method: 'POST', headers })).status).toBe(200);
    expect((await fetchJson(`/api/file/${s.id}`)).status).toBe(410);
    expect(await env.FILES.get(`d/${u.id}/${f.id}/0`)).not.toBeNull();
    // And the delete token works the same way.
    const t = await share(u.cookie, [f.id]);
    expect((await fetchJson(`/api/file/${t.id}`, { method: 'DELETE', headers: { 'x-delete-token': t.deletetoken } })).status).toBe(200);
    expect(await env.FILES.get(`d/${u.id}/${f.id}/0`)).not.toBeNull();
  });
});
