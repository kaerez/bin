// files.test.js — encrypted file shares end-to-end in workerd (FileShare DO +
// R2): authorized chunked upload with exact sizes, finalize with the encrypted
// manifest, proof-gated open with view counting, download grants, last-view
// grace + purge, R2 cleanup on alarm / revoke / delete, and caps.
import { env, SELF, runDurableObjectAlarm, runInDurableObject } from 'cloudflare:test';
import { MAX_ACTIVE_GRANTS, MAX_GRANTS_PER_CLIENT } from '../src/fileshare-do.js';
import { describe, it, expect, beforeAll, vi, afterEach } from 'vitest';
import { ORIGIN, owner, makeUser, fetchJson, proofHeaders, freshIp, intent } from './helpers.js';
import { encryptPaste, openPaste } from '../public/js/crypto.js';
import { layout, buildManifest, importFileKey, encryptChunk, decryptChunk, readStreamChunk, validateManifest, CHUNK } from '../public/js/files.js';
import { utf8 } from '../public/js/bytes.js';

let oc;
beforeAll(async () => { oc = await owner(); });
afterEach(() => vi.useRealTimers());

/** Upload `files` [{path, bytes, type}] as `cookie`; returns share info. */
async function upload(cookie, files, { views = null, expire = '1h', password = '', label, headers = {}, dirs = [], deletable, metaDeletable = deletable } = {}) {
  const l = layout(files.map((f) => ({ path: f.path, type: f.type || 'application/octet-stream', size: f.bytes.length, mtime: 0 })), dirs);
  const manifest = buildManifest({ entries: l.entries, total: l.total });
  const init = await fetchJson('/api/private/file', { method: 'POST', cookie, headers, body: { views, expire, padded: l.padded, files: files.length, maxFile: Math.max(0, ...files.map((f) => f.bytes.length)), ...(deletable ? { deletable: true } : {}) } });
  if (init.status !== 201) return { init };
  const { id, uploadtoken, deletetoken, chunks } = await init.json();
  const key = await importFileKey(manifest.fk);
  const sources = files.map((f, i) => ({ off: l.entries[i].off, size: f.bytes.length, read: async (a, b) => f.bytes.slice(a, b) }));
  for (let i = 0; i < chunks; i++) {
    const ct = await encryptChunk(key, i, chunks, await readStreamChunk(sources, i, l.total));
    const r = await SELF.fetch(`${ORIGIN}/api/private/file/${id}/chunk/${i}`, {
      method: 'PUT', headers: { ...(cookie ? { cookie } : {}), ...headers, 'content-type': 'application/octet-stream', 'x-upload-token': uploadtoken }, body: ct,
    });
    if (r.status !== 200) throw new Error(`chunk ${i}: ${r.status} ${await r.text()}`);
  }
  const { body, fragment } = await encryptPaste({ text: JSON.stringify(manifest), fmt: 'files', bar: views !== null, views: views ?? undefined, expire, password, deletable: metaDeletable });
  const fin = await fetchJson(`/api/private/file/${id}/finalize`, { method: 'POST', cookie, headers: { ...headers, 'x-upload-token': uploadtoken }, body: { paste: body, label } });
  return { id, deletetoken, uploadtoken, fragment, manifest, chunks, fin, init, l };
}

async function openShare(id, fragment, password = '', ip) {
  const head = await (await fetchJson(`/api/file/${id}`, { ip })).json();
  const { headers, access } = await proofHeaders(head.adata, fragment, password);
  const res = await fetchJson(`/api/file/${id}/open`, { method: 'POST', headers, ip });
  return { res, access, head };
}

const getChunk = (id, i, grant, ip) => SELF.fetch(`${ORIGIN}/api/file/${id}/chunk/${i}`, { headers: { 'x-download-grant': grant, ...(ip ? { 'cf-connecting-ip': ip } : {}) } });

describe('file share lifecycle', () => {
  it('uploads, opens with proofs, downloads and decrypts every file', async () => {
    const files = [
      { path: 'docs/readme.txt', bytes: utf8('hello files'), type: 'text/plain' },
      { path: 'docs/sub/data.bin', bytes: new Uint8Array(1000).map((_, i) => i & 0xff) },
    ];
    const s = await upload(oc, files, { views: 2, password: 'share-pass', label: 'my upload', dirs: ['empty'] });
    expect(s.fin.status).toBe(200);
    expect(s.id[0]).toBe('f');
    const head = await (await fetchJson(`/api/file/${s.id}`)).json();
    expect(head.wk).toBeUndefined();
    expect(head.meta).toMatchObject({ views: 2, left: 2 });
    const o = await openShare(s.id, s.fragment, 'share-pass');
    expect(o.res.status).toBe(200);
    const { paste, grant, chunks } = await o.res.json();
    const manifest = validateManifest(JSON.parse((await openPaste({ paste, access: o.access })).text));
    expect(manifest.entries.map((e) => e.path)).toEqual(['docs/readme.txt', 'docs/sub/data.bin', 'empty']);
    const key = await importFileKey(manifest.fk);
    const r = await getChunk(s.id, 0, grant);
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toBe('application/octet-stream');
    const plain = await decryptChunk(key, 0, chunks, new Uint8Array(await r.arrayBuffer()));
    const e0 = manifest.entries[0];
    expect(new TextDecoder().decode(plain.slice(e0.off, e0.off + e0.size))).toBe('hello files');
    const e1 = manifest.entries[1];
    expect(Array.from(plain.slice(e1.off, e1.off + e1.size))).toEqual(Array.from(files[1].bytes));
    // The server stored only ciphertext: names never appear in R2 or the DO record.
    const obj = await env.FILES.get(`f/${s.id}/0`);
    expect(new TextDecoder().decode(await obj.arrayBuffer())).not.toContain('readme');
  });

  it('wrong link / wrong password never spend a view; bad grants are refused', async () => {
    const s = await upload(oc, [{ path: 'a', bytes: utf8('x') }], { views: 1, password: 'right-pass' });
    const ip = freshIp();
    const bad = await openShare(s.id, s.fragment, 'wrong-pass', ip);
    expect((await bad.res.json()).error).toBe('bad_password');
    expect((await getChunk(s.id, 0, 'A'.repeat(43), ip)).status).toBe(403);
    const ok = await openShare(s.id, s.fragment, 'right-pass', ip);
    expect(ok.res.status).toBe(200);
  });

  it('after the last view: no new opens, the grant still works until it expires, then purge', async () => {
    const s = await upload(oc, [{ path: 'once.txt', bytes: utf8('last one') }], { views: 1 });
    const o = await openShare(s.id, s.fragment);
    const { grant } = await o.res.json();
    expect((await fetchJson(`/api/file/${s.id}`)).status).toBe(410);
    const { headers } = await proofHeaders(o.head.adata, s.fragment);
    expect((await fetchJson(`/api/file/${s.id}/open`, { method: 'POST', headers })).status).toBe(410);
    expect((await getChunk(s.id, 0, grant)).status).toBe(200);
    vi.useFakeTimers({ now: Date.now() + 2 * 3600 * 1000, toFake: ['Date'] });
    const stub = env.FILESHARE.get(env.FILESHARE.idFromName(s.id));
    await runDurableObjectAlarm(stub);
    vi.useRealTimers();
    expect((await getChunk(s.id, 0, grant)).status).toBe(410);
    expect(await env.FILES.get(`f/${s.id}/0`)).toBeNull();
  });

  it('delete token and owner revoke both purge R2', async () => {
    const s = await upload(oc, [{ path: 'x', bytes: utf8('x') }]);
    expect((await fetchJson(`/api/file/${s.id}`, { method: 'DELETE', headers: { 'x-delete-token': s.deletetoken } })).status).toBe(200);
    expect(await env.FILES.get(`f/${s.id}/0`)).toBeNull();
    const t = await upload(oc, [{ path: 'y', bytes: utf8('y') }]);
    expect((await fetchJson(`/api/private/shares/${t.id}/revoke`, { method: 'POST', cookie: oc, headers: intent })).status).toBe(200);
    expect(await env.FILES.get(`f/${t.id}/0`)).toBeNull();
    expect((await fetchJson(`/api/file/${t.id}`)).status).toBe(410);
  });

  it('an unfinalized upload is purged at its deadline', async () => {
    const init = await fetchJson('/api/private/file', { method: 'POST', cookie: oc, body: { views: null, expire: '1h', padded: 65536 } });
    const { id } = await init.json();
    vi.useFakeTimers({ now: Date.now() + 2 * 3600 * 1000, toFake: ['Date'] });
    await runDurableObjectAlarm(env.FILESHARE.get(env.FILESHARE.idFromName(id)));
    vi.useRealTimers();
    expect((await fetchJson(`/api/file/${id}`)).status).toBe(410);
  });
});

describe('upload validation and caps', () => {
  it('chunks must match their exact expected size and come from the uploader', async () => {
    const u = await makeUser('uploader-2');
    const init = await (await fetchJson('/api/private/file', { method: 'POST', cookie: oc, body: { views: null, expire: '1h', padded: 65536 } })).json();
    const put = (cookie, bytes, token = init.uploadtoken) => SELF.fetch(`${ORIGIN}/api/private/file/${init.id}/chunk/0`, {
      method: 'PUT', headers: { cookie, 'content-type': 'application/octet-stream', 'x-upload-token': token }, body: bytes });
    expect((await put(oc, new Uint8Array(100))).status).toBe(400); // wrong size
    expect((await put(u.cookie, new Uint8Array(65536 + 16))).status).toBe(403); // someone else
    expect((await put(oc, new Uint8Array(65536 + 16), 'B'.repeat(43))).status).toBe(403); // wrong token
    expect((await put(oc, new Uint8Array(CHUNK + 17))).status).toBe(413);
    // finalize before all chunks → 409
    const { body } = await encryptPaste({ text: '{}', fmt: 'files', expire: '1h' });
    expect((await fetchJson(`/api/private/file/${init.id}/finalize`, { method: 'POST', cookie: oc, headers: { 'x-upload-token': init.uploadtoken }, body: { paste: body } })).status).toBe(409);
  });

  it('the manifest must match what the upload was authorized for', async () => {
    const init = await (await fetchJson('/api/private/file', { method: 'POST', cookie: oc, body: { views: 3, expire: '1h', padded: 65536 } })).json();
    await SELF.fetch(`${ORIGIN}/api/private/file/${init.id}/chunk/0`, { method: 'PUT', headers: { cookie: oc, 'content-type': 'application/octet-stream', 'x-upload-token': init.uploadtoken }, body: new Uint8Array(65536 + 16) });
    const { body } = await encryptPaste({ text: '{}', fmt: 'files', expire: '1h' }); // unlimited, not 3 views
    expect((await fetchJson(`/api/private/file/${init.id}/finalize`, { method: 'POST', cookie: oc, headers: { 'x-upload-token': init.uploadtoken }, body: { paste: body } })).status).toBe(400);
  });

  it('enforces feature, share-size, file-count and per-file limits', async () => {
    const u = await makeUser('uploader-3');
    const lim = (patch) => fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: u.id, channel: 'all', patch } });
    const init = (body) => fetchJson('/api/private/file', { method: 'POST', cookie: u.cookie, body: { views: null, expire: '1h', padded: 65536, ...body } });
    await lim({ files: false });
    expect((await init({})).status).toBe(403);
    await lim({ files: true, maxShareBytes: 65536 });
    expect((await init({ padded: 131072 })).status).toBe(413);
    await lim({ maxShareBytes: 'inherit', maxFilesPerShare: 2, maxFileBytes: 1000 });
    expect((await init({ files: 3, maxFile: 10 })).status).toBe(403);
    expect((await init({ files: 2, maxFile: 1001 })).status).toBe(413);
    expect((await init({ files: 2, maxFile: 1000 })).status).toBe(201);
    expect((await init({ padded: 1000 })).status).toBe(400); // not a 64 KiB multiple
  });
});

describe('download grants', () => {
  it('one client holds at most MAX_GRANTS_PER_CLIENT live grants; reopening replaces its oldest', async () => {
    const s = await upload(oc, [{ path: 'b.txt', bytes: utf8('per client') }], { views: null });
    const ip = freshIp();
    const grants = [];
    for (let i = 0; i < MAX_GRANTS_PER_CLIENT + 1; i++) {
      const o = await openShare(s.id, s.fragment, '', ip);
      expect(o.res.status).toBe(200);
      grants.push((await o.res.json()).grant);
    }
    const stub = env.FILESHARE.get(env.FILESHARE.idFromName(s.id));
    await runInDurableObject(stub, async (_instance, state) => {
      expect(await state.storage.get('grants')).toHaveLength(MAX_GRANTS_PER_CLIENT);
    });
    expect((await getChunk(s.id, 0, grants[0], ip)).status).toBe(403); // the oldest was replaced
    expect((await getChunk(s.id, 0, grants.at(-1), ip)).status).toBe(200);
  });

  it('live outside the share record and are capped, so repeated opens cannot wedge a share', async () => {
    const s = await upload(oc, [{ path: 'a.txt', bytes: utf8('grant cap') }], { views: null });
    expect(s.fin.status).toBe(200);
    const first = await openShare(s.id, s.fragment);
    expect(first.res.status).toBe(200);
    const stub = env.FILESHARE.get(env.FILESHARE.idFromName(s.id));
    // Fill the grant table to the cap with live grants.
    await runInDurableObject(stub, async (_instance, state) => {
      const g = await state.storage.get('grants');
      expect(g).toHaveLength(1);
      expect((await state.storage.get('rec')).grants).toEqual([]); // kept empty for rollback safety
      const exp = Math.floor(Date.now() / 1000) + 3600;
      const fillers = Array.from({ length: MAX_ACTIVE_GRANTS - 1 }, (_, i) => ({ h: i.toString(16).padStart(64, '0'), exp }));
      await state.storage.put('grants', [...g, ...fillers]);
    });
    const busy = await openShare(s.id, s.fragment);
    expect(busy.res.status).toBe(429);
    expect(busy.res.headers.get('retry-after')).toBe('300');
    expect((await busy.res.json()).error).toBe('busy');
    // The first grant still works for downloads.
    const { grant } = await first.res.json();
    expect((await getChunk(s.id, 0, grant)).status).toBe(200);
    // Expired grants free their slots.
    await runInDurableObject(stub, async (_instance, state) => {
      await state.storage.put('grants', [{ h: '0'.repeat(64), exp: 1 }]);
    });
    expect((await openShare(s.id, s.fragment)).res.status).toBe(200);
  });
});

describe('recipient "delete now" on file shares', () => {
  const allow = (id) => fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: id, channel: 'all', patch: { openerDelete: true } } });
  const expire = async (id, fragment, password = '') => {
    const head = await (await fetchJson(`/api/file/${id}`)).json();
    const { headers } = await proofHeaders(head.adata, fragment, password);
    return fetchJson(`/api/file/${id}/expire`, { method: 'POST', headers });
  };

  it('refuses a manifest whose delete flag differs from the authorized upload', async () => {
    const u = await makeUser('files-deletable-mismatch');
    await allow(u.id);
    const a = await upload(u.cookie, [{ path: 'a.txt', bytes: utf8('x') }], { deletable: true, metaDeletable: false });
    expect(a.fin.status).toBe(400);
    const b = await upload(u.cookie, [{ path: 'a.txt', bytes: utf8('x') }], { metaDeletable: true });
    expect(b.fin.status).toBe(400);
  });

  it('deletes the share and its R2 chunks, with both proofs', async () => {
    const u = await makeUser('files-deletable');
    await allow(u.id);
    const s = await upload(u.cookie, [{ path: 'a.txt', bytes: utf8('delete me') }], { deletable: true, password: 'pw-files-1' });
    expect(s.fin.status).toBe(200);
    expect((await (await fetchJson(`/api/file/${s.id}`)).json()).meta.deletable).toBe(true);
    expect(await env.FILES.get(`f/${s.id}/0`)).not.toBeNull();
    expect((await expire(s.id, s.fragment, 'wrong-password')).status).toBe(403);
    expect(await env.FILES.get(`f/${s.id}/0`)).not.toBeNull();
    expect((await expire(s.id, s.fragment, 'pw-files-1')).status).toBe(200);
    expect(await env.FILES.get(`f/${s.id}/0`)).toBeNull();
    expect((await fetchJson(`/api/file/${s.id}`)).status).toBe(410);
    const mine = await (await fetchJson('/api/private/shares', { cookie: u.cookie })).json();
    expect(mine.rows.find((r) => r.id === s.id).status).toBe('deleted');
  });
});
