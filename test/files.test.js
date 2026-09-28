// files.test.js — encrypted file shares end-to-end in workerd (FileShare DO +
// R2): authorized chunked upload with exact sizes, finalize with the encrypted
// manifest, proof-gated open with view counting, download grants, last-view
// grace + purge, R2 cleanup on alarm / revoke / delete, and caps.
import { env, SELF, runDurableObjectAlarm, runInDurableObject } from 'cloudflare:test';
import { MAX_ACTIVE_GRANTS, MAX_GRANTS_PER_CLIENT, MAX_GRANT_EXTENSIONS } from '../src/fileshare-do.js';
import { describe, it, expect, beforeAll, vi, afterEach } from 'vitest';
import { ORIGIN, owner, makeUser, fetchJson, proofHeaders, freshIp, intent, csrfHeaders } from './helpers.js';
import { encryptPaste, openPaste } from '../public/js/crypto.js';
import { layout, buildManifest, importFileKey, encryptChunk, decryptChunk, readStreamChunk, validateManifest, CHUNK } from '../public/js/files.js';
import { utf8, randomBytes, b64urlFromBytes } from '../public/js/bytes.js';
import { invalidateGuardCaches } from '../src/lib/guard.js';

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
      method: 'PUT', headers: { ...(cookie ? { cookie, ...(await csrfHeaders(cookie)) } : {}), ...headers, 'content-type': 'application/octet-stream', 'x-upload-token': uploadtoken }, body: ct,
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
    const put = async (cookie, bytes, token = init.uploadtoken) => SELF.fetch(`${ORIGIN}/api/private/file/${init.id}/chunk/0`, {
      method: 'PUT', headers: { cookie, ...(await csrfHeaders(cookie)), 'content-type': 'application/octet-stream', 'x-upload-token': token }, body: bytes });
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
    await SELF.fetch(`${ORIGIN}/api/private/file/${init.id}/chunk/0`, { method: 'PUT', headers: { cookie: oc, ...(await csrfHeaders(oc)), 'content-type': 'application/octet-stream', 'x-upload-token': init.uploadtoken }, body: new Uint8Array(65536 + 16) });
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

describe('extending a download window (WCAG 2.2.1)', () => {
  const extend = (id, grant, ip) => fetchJson(`/api/file/${id}/extend`, { method: 'POST', headers: { 'x-download-grant': grant }, ip });

  it('moves the end by the window from now, spends no view, at most MAX_GRANT_EXTENSIONS times', async () => {
    const s = await upload(oc, [{ path: 'long.txt', bytes: utf8('take your time') }], { views: 2, expire: '1d' });
    const o = await openShare(s.id, s.fragment);
    const { grant, grantExpires } = await o.res.json();
    vi.useFakeTimers({ now: Date.now() + 50 * 60 * 1000, toFake: ['Date'] }); // 50 minutes later
    const r = await extend(s.id, grant);
    expect(r.status).toBe(200);
    const body = await r.json();
    expect(body.grantExpires).toBeGreaterThanOrEqual(grantExpires + 49 * 60);
    expect(body.extensionsLeft).toBe(MAX_GRANT_EXTENSIONS - 1);
    vi.useRealTimers();
    expect((await getChunk(s.id, 0, grant)).status).toBe(200);
    // No view was spent.
    expect((await (await fetchJson(`/api/file/${s.id}`)).json()).meta.left).toBe(1);
    for (let i = 1; i < MAX_GRANT_EXTENSIONS; i++) expect((await extend(s.id, grant)).status).toBe(200);
    const over = await extend(s.id, grant);
    expect(over.status).toBe(409);
    expect((await over.json()).error).toBe('extend_limit');
  });

  it('never past the share expiry; a bad or expired grant is refused', async () => {
    const s = await upload(oc, [{ path: 'short.txt', bytes: utf8('x') }], { views: null, expire: '1h' });
    const o = await openShare(s.id, s.fragment);
    const { grant, paste } = await o.res.json();
    const r = await (await extend(s.id, grant)).json();
    expect(r.grantExpires).toBeLessThanOrEqual(paste.meta.expires);
    expect((await extend(s.id, 'A'.repeat(43), freshIp())).status).toBe(403);
    expect((await extend(s.id, 'short', freshIp())).status).toBe(403);
    expect((await fetchJson(`/api/file/${s.id}/extend`, { headers: { 'x-download-grant': grant } })).status).toBe(405);
  });

  it('has the chunk route\'s guards: cross-site refused, the grant is the credential, a bad grant counts as invalid', async () => {
    const s = await upload(oc, [{ path: 'g.txt', bytes: utf8('guards') }], { views: null, expire: '1h' });
    const { grant } = await (await openShare(s.id, s.fragment)).res.json();
    for (const site of ['cross-site', 'same-site']) {
      const r = await fetchJson(`/api/file/${s.id}/extend`, { method: 'POST', headers: { 'x-download-grant': grant, 'sec-fetch-site': site } });
      expect(r.status).toBe(403);
      expect((await r.json()).error).toBe('cross_site');
    }
    // No grant, no extension (a session cookie is not a grant).
    expect((await fetchJson(`/api/file/${s.id}/extend`, { method: 'POST', cookie: oc })).status).toBe(403);
    // A note id is not a file share.
    expect((await fetchJson(`/api/paste/${s.id.slice(1)}x/extend`, { method: 'POST', headers: { 'x-download-grant': grant } })).status).toBeGreaterThanOrEqual(400);
    // Bad grants feed the Guard's "invalid" scope: the network ends up blocked, as for chunks.
    const ip = freshIp();
    let last;
    for (let i = 0; i < 80; i++) { // guard.invalid.max defaults to 60
      last = await fetchJson(`/api/file/${s.id}/extend`, { method: 'POST', headers: { 'x-download-grant': 'B'.repeat(43) }, ip });
      if (last.status === 429) break;
    }
    expect(last.status).toBe(429);
  }, 60000); // up to 60 requests to reach the block, as in the R4-L4 test below

  // Audit round 4, R4-L4: an unknown id answered 410 uncounted (a Directory
  // call and a new FileShare object each, never blocked); the chunk route
  // blocks the same pattern at guard.invalid.max.
  it('an id that was never a share counts as invalid, as on the chunk route; a known share that ended does not (R4-L4)', async () => {
    const unknown = () => `f${b64urlFromBytes(randomBytes(16))}`; // well-formed, never created
    const ip = freshIp();
    let last;
    let n = 0;
    for (; n < 80; n++) { // guard.invalid.max defaults to 60
      last = await extend(unknown(), 'C'.repeat(43), ip);
      if (last.status === 429) break;
      expect(last.status).toBe(410);
    }
    expect(last.status).toBe(429);
    expect(n).toBeLessThanOrEqual(60);
    // The same pattern on the chunk route, for comparison: blocked too.
    const ip2 = freshIp();
    let c;
    for (let i = 0; i < 80; i++) { c = await getChunk(unknown(), 0, 'C'.repeat(43), ip2); if (c.status === 429) break; }
    expect(c.status).toBe(429);
    // A share that existed and ended (its only view spent, then purged): a late
    // extend from the viewer's tab is a plain 410, never counted.
    const s = await upload(oc, [{ path: 'ended.txt', bytes: utf8('gone') }], { views: 1, expire: '1d' });
    const { grant } = await (await openShare(s.id, s.fragment)).res.json();
    vi.useFakeTimers({ now: Date.now() + 70 * 60 * 1000, toFake: ['Date'] }); // past the only window
    await runDurableObjectAlarm(env.FILESHARE.get(env.FILESHARE.idFromName(s.id)));
    expect(await env.FILES.get(`f/${s.id}/0`)).toBeNull();
    const ip3 = freshIp();
    for (let i = 0; i < 70; i++) expect((await extend(s.id, grant, ip3)).status).toBe(410);
  }, 120000);

  // Security audit F2: past the tenth extension, every further call was answered 409, uncounted,
  // each one a Directory call. The extend route has its own per-network limit (download-extend):
  // a loop ends in 429 rate_limited, refused before the Directory, and never sets the network's
  // invalid block (a 409 with a valid grant is not an invalid fetch). A recipient's ten extensions
  // and the one 409 the viewer sees keep working.
  it('a loop past the last extension ends in 429 (the extend route\'s own limit), never the invalid block; a recipient\'s ten extensions and one 409 work', async () => {
    const s = await upload(oc, [{ path: 'many.txt', bytes: utf8('many') }], { views: null, expire: '1d' });
    const ip = freshIp();
    const { grant } = await (await openShare(s.id, s.fragment, '', ip)).res.json();
    for (let i = 0; i < MAX_GRANT_EXTENSIONS; i++) expect((await extend(s.id, grant, ip)).status).toBe(200);
    const once = await extend(s.id, grant, ip);
    expect(once.status).toBe(409);
    expect((await once.json()).error).toBe('extend_limit');
    // The same network still opens and downloads.
    const again = await openShare(s.id, s.fragment, '', ip);
    expect(again.res.status).toBe(200);
    expect((await getChunk(s.id, 0, (await again.res.json()).grant, ip)).status).toBe(200);
    // A loop: 409 until the route's own limit, then 429 rate_limited (guard.invalid.max is 60).
    let r;
    let n = MAX_GRANT_EXTENSIONS + 1;
    for (; n < 200; n++) { r = await extend(s.id, grant, ip); if (r.status === 429) break; expect(r.status).toBe(409); }
    expect(r.status).toBe(429);
    expect((await r.json()).error).toBe('rate_limited');
    expect(r.headers.get('retry-after')).toBe('600');
    expect(n).toBeGreaterThan(60); // more 409s than guard.invalid.max: none of them counted as invalid
    // Never the invalid block: the network still opens shares and downloads (only extending waits).
    const after = await openShare(s.id, s.fragment, '', ip);
    expect(after.res.status).toBe(200);
    expect((await getChunk(s.id, 0, (await after.res.json()).grant, ip)).status).toBe(200);
  }, 180000);

  // Security audit F1: every extension is in the share owner's activity log, with the share,
  // which extension it was and the new end; never the grant.
  it('records each extension in the share owner\'s activity log (share id, extension, new end), not the grant', async () => {
    const u = await makeUser('extend-log');
    const s = await upload(u.cookie, [{ path: 'log.txt', bytes: utf8('log') }], { views: 1, expire: '1d' });
    const ip = freshIp();
    const { grant } = await (await openShare(s.id, s.fragment, '', ip)).res.json();
    const ends = [];
    for (let i = 0; i < 2; i++) ends.push((await (await extend(s.id, grant, ip)).json()).grantExpires);
    const { rows } = await (await fetchJson('/api/private/me/activity', { cookie: u.cookie })).json();
    const ext = rows.filter((a) => a.action === 'share.download_extended');
    expect(ext.map((a) => a.detail).sort()).toEqual([`id=${s.id} extension=1 until=${ends[0]}`, `id=${s.id} extension=2 until=${ends[1]}`].sort());
    expect(JSON.stringify(rows)).not.toContain(grant);
  });

  // Security audit F3: a full grant table of extended grants no longer keeps a share busy for
  // everyone: a grant past its first window gives way to a new open. Grants still in their first
  // window keep the table full ("busy"), as before extensions existed.
  it('a full table: a new open displaces a grant past its first window; grants in their first window still mean busy', async () => {
    const s = await upload(oc, [{ path: 'full.txt', bytes: utf8('full') }], { views: null, expire: '1d' });
    const first = await openShare(s.id, s.fragment, '', freshIp());
    expect(first.res.status).toBe(200);
    const stub = env.FILESHARE.get(env.FILESHARE.idFromName(s.id));
    const t = Math.floor(Date.now() / 1000);
    const fill = (f) => runInDurableObject(stub, async (_i, state) => {
      const g = await state.storage.get('grants');
      const fillers = Array.from({ length: MAX_ACTIVE_GRANTS - g.length }, (_, i) => ({ h: i.toString(16).padStart(64, '0'), exp: t + 3600, f, c: `x${i}` }));
      await state.storage.put('grants', [...g, ...fillers]);
    });
    await fill(t + 600); // every grant in its first window
    expect((await openShare(s.id, s.fragment, '', freshIp())).res.status).toBe(429);
    await runInDurableObject(stub, async (_i, state) => { await state.storage.put('grants', (await state.storage.get('grants')).slice(0, 1)); });
    await fill(t - 60); // every filler living on an extension
    const o = await openShare(s.id, s.fragment, '', freshIp());
    expect(o.res.status).toBe(200);
    const after = await runInDurableObject(stub, (_i, state) => state.storage.get('grants'));
    expect(after).toHaveLength(MAX_ACTIVE_GRANTS);
    expect(after.filter((g) => g.f <= t)).toHaveLength(MAX_ACTIVE_GRANTS - 2);
  });

  // Security audit F4: the open and extend responses carry the server's time.
  it('the open and extend responses carry the server\'s time (now)', async () => {
    const s = await upload(oc, [{ path: 'now.txt', bytes: utf8('now') }], { views: null, expire: '1d' });
    const ip = freshIp();
    const o = await (await openShare(s.id, s.fragment, '', ip)).res.json();
    const t = Math.floor(Date.now() / 1000);
    expect(Math.abs(o.now - t)).toBeLessThanOrEqual(2);
    const e = await (await extend(s.id, o.grant, ip)).json();
    expect(Math.abs(e.now - t)).toBeLessThanOrEqual(2);
  });

  it('after the last view, the purge waits for the extended window', async () => {
    const s = await upload(oc, [{ path: 'once.txt', bytes: utf8('last') }], { views: 1, expire: '1d' });
    const o = await openShare(s.id, s.fragment);
    const { grant } = await o.res.json();
    vi.useFakeTimers({ now: Date.now() + 50 * 60 * 1000, toFake: ['Date'] });
    expect((await extend(s.id, grant)).status).toBe(200);
    vi.useFakeTimers({ now: Date.now() + 20 * 60 * 1000, toFake: ['Date'] }); // 70 min after opening: past the first window
    const stub = env.FILESHARE.get(env.FILESHARE.idFromName(s.id));
    await runDurableObjectAlarm(stub);
    vi.useRealTimers();
    expect((await getChunk(s.id, 0, grant)).status).toBe(200);
    expect(await env.FILES.get(`f/${s.id}/0`)).not.toBeNull();
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

describe('"delete now" after a file share\'s last view', () => {
  it('is refused: downloads already granted run out on their own', async () => {
    const u = await makeUser('files-deletable-closed');
    await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: u.id, channel: 'all', patch: { openerDelete: true } } });
    const s = await upload(u.cookie, [{ path: 'a.txt', bytes: utf8('last view') }], { views: 1, deletable: true });
    expect(s.fin.status).toBe(200);
    const o = await openShare(s.id, s.fragment);
    expect(o.res.status).toBe(200);
    const { headers } = await proofHeaders(o.head.adata, s.fragment, '');
    expect((await fetchJson(`/api/file/${s.id}/expire`, { method: 'POST', headers })).status).toBe(410);
    expect(await env.FILES.get(`f/${s.id}/0`)).not.toBeNull();
  });
});

describe('C1: chunk fetches of a share that ended are never counted as invalid', () => {
  const settings = (patch) => fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: patch });
  it('revoked or deleted during a download: the recipient\'s correct grant gets 410, never a block; an id that was never a share is counted', async () => {
    expect((await settings({ 'guard.invalid.max': 3 })).status).toBe(200);
    invalidateGuardCaches();
    try {
      const recipient = freshIp();
      const live = await upload(oc, [{ path: 'other.txt', bytes: utf8('unrelated, still live') }]);
      for (const end of ['revoke', 'delete']) {
        const s = await upload(oc, [{ path: 'a.txt', bytes: utf8('ends mid-download') }]);
        const { grant } = await (await openShare(s.id, s.fragment, '', recipient)).res.json();
        expect((await getChunk(s.id, 0, grant, recipient)).status).toBe(200);
        if (end === 'revoke') expect((await fetchJson(`/api/private/shares/${s.id}/revoke`, { method: 'POST', cookie: oc, headers: intent })).status).toBe(200);
        else expect((await fetchJson(`/api/file/${s.id}`, { method: 'DELETE', headers: { 'x-delete-token': s.deletetoken } })).status).toBe(200);
        for (let i = 0; i < 8; i++) {
          const r = await getChunk(s.id, 0, grant, recipient);
          expect(r.status, `${end} #${i}`).toBe(410); // never 429
          expect((await r.json()).error).toBe('gone');
        }
      }
      // The recipient's network still opens other shares with their links.
      expect((await openShare(live.id, live.fragment, '', recipient)).res.status).toBe(200);
      // A made-up id (never a share) is a guess: counted, then blocked.
      const prober = freshIp();
      const codes = [];
      for (let i = 0; i < 5; i++) codes.push((await getChunk(`f${b64urlFromBytes(randomBytes(16))}`, 0, 'A'.repeat(43), prober)).status);
      expect(codes).toContain(429);
    } finally {
      await settings({ 'guard.invalid.max': 60 });
      invalidateGuardCaches();
    }
  }, 30000);
});
