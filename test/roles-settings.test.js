// roles-settings.test.js — what Settings and the Viewer tab held for every
// account now lives on the roles: the file-share download window and upload
// deadline, the share-size cap and the viewer (each open carries the sender's
// role's current viewer policy). The owner's own values are settings (the
// Owner role). The built-in Public role belongs to the public account only.
import { SELF } from 'cloudflare:test';
import { describe, it, expect, beforeAll } from 'vitest';
import { ORIGIN, owner, makeUser, fetchJson, proofHeaders, freshIp, proofFor, csrfHeaders } from './helpers.js';
import { encryptPaste } from '../public/js/crypto.js';
import { layout, buildManifest, importFileKey, encryptChunk, readStreamChunk } from '../public/js/files.js';
import { utf8 } from '../public/js/bytes.js';

let oc;
beforeAll(async () => { oc = await owner(); });
const CURRENT = proofFor('owner-password');
const admin = (path, method, body) => fetchJson(`/api/private/admin/${path}`, { method, cookie: oc, body, ip: freshIp(), headers: { 'x-secbin-intent': '1' } });
const limits = (scope, patch) => admin('limits', 'PATCH', { scope, channel: 'all', patch });
const newRole = async (name) => { const r = await admin('roles', 'POST', { name }); expect(r.status).toBe(201); return (await r.json()).id; };
const nowSec = () => Math.floor(Date.now() / 1000);

async function upload(cookie, text = 'hello') {
  const bytes = utf8(text);
  const l = layout([{ path: 'a.txt', type: 'text/plain', size: bytes.length, mtime: 0 }], []);
  const manifest = buildManifest({ entries: l.entries, total: l.total, view: { rules: [], maxBytes: 1024 * 1024 } });
  const init = await fetchJson('/api/private/file', { method: 'POST', cookie, body: { views: null, expire: '1h', padded: l.padded, files: 1, maxFile: bytes.length } });
  expect(init.status).toBe(201);
  const { id, uploadtoken, chunks } = await init.json();
  const key = await importFileKey(manifest.fk);
  const sources = [{ off: l.entries[0].off, size: bytes.length, read: async (a, b) => bytes.slice(a, b) }];
  for (let i = 0; i < chunks; i++) {
    const ct = await encryptChunk(key, i, chunks, await readStreamChunk(sources, i, l.total));
    const r = await SELF.fetch(`${ORIGIN}/api/private/file/${id}/chunk/${i}`, { method: 'PUT', headers: { cookie, ...(await csrfHeaders(cookie)), 'x-upload-token': uploadtoken, 'content-type': 'application/octet-stream' }, body: ct });
    expect(r.status).toBe(200);
  }
  const { body, fragment } = await encryptPaste({ text: JSON.stringify(manifest), fmt: 'files', expire: '1h' });
  expect((await fetchJson(`/api/private/file/${id}/finalize`, { method: 'POST', cookie, headers: { 'x-upload-token': uploadtoken }, body: { paste: body } })).status).toBe(200);
  return { id, fragment };
}
async function open({ id, fragment }) {
  const ip = freshIp();
  const head = await (await fetchJson(`/api/file/${id}`, { ip })).json();
  const { headers } = await proofHeaders(head.adata, fragment);
  const res = await fetchJson(`/api/file/${id}/open`, { method: 'POST', headers, ip });
  expect(res.status).toBe(200);
  return res.json();
}

describe('file shares follow the sender\'s role', () => {
  it('the download window is the role\'s; the owner\'s is the setting', async () => {
    const rid = await newRole('Short window');
    expect((await limits(`role:${rid}`, { fileGrantSec: 600, filePendingSec: 900 })).status).toBe(200);
    const u = await makeUser('rs-window');
    expect((await admin(`users/${u.id}/role`, 'PUT', { roleId: rid })).status).toBe(200);
    const me = await (await fetchJson('/api/private/me', { cookie: u.cookie })).json();
    expect(me.caps.grantSec).toBe(600);
    const r = await open(await upload(u.cookie));
    expect(Math.abs(r.grantExpires - (nowSec() + 600))).toBeLessThan(30);
    // The owner has no role options: their share uses files.grantSec.
    const s = (await (await admin('overview', 'GET')).json()).settings['files.grantSec'];
    const o = await open(await upload(oc));
    expect(Math.abs(o.grantExpires - (nowSec() + s))).toBeLessThan(30);
  });

  it('each open carries the sender\'s role\'s current viewer policy (off at once for existing links)', async () => {
    const rid = await newRole('Viewers');
    expect((await limits(`role:${rid}`, { viewer: true, viewerMaxBytes: 2 * 1024 * 1024 })).status).toBe(200);
    const u = await makeUser('rs-viewer');
    await admin(`users/${u.id}/role`, 'PUT', { roleId: rid });
    const share = await upload(u.cookie);
    expect((await open(share)).viewer).toMatchObject({ enabled: true, maxBytes: 2 * 1024 * 1024 });
    expect((await limits(`role:${rid}`, { viewer: false })).status).toBe(200);
    expect((await open(share)).viewer).toEqual({ enabled: false, maxBytes: 2 * 1024 * 1024, rules: [] });
    // /api/config no longer carries a viewer policy.
    expect((await (await fetchJson('/api/config')).json()).viewer).toBeUndefined();
  });
});

describe('built-in Public role', () => {
  it('is listed, cannot be assigned, renamed into, or taken as a name', async () => {
    const list = (await (await admin('roles', 'GET')).json()).roles;
    expect(list.find((r) => r.id === 'public')).toMatchObject({ name: 'Public', builtin: true, fixed: true });
    const u = await makeUser('rs-public');
    const r = await admin(`users/${u.id}/role`, 'PUT', { roleId: 'public' });
    expect(r.status).toBe(403);
    expect((await r.json()).error).toBe('public_role');
    expect((await admin('roles', 'POST', { name: 'public' })).status).toBe(409);
    expect((await admin('roles', 'POST', { from: 'public', name: 'Copy of public' })).status).toBe(404);
    const other = await newRole('Not public');
    expect((await admin(`roles/${other}`, 'PATCH', { name: 'Public' })).status).toBe(409);
  });
});

describe('retired settings', () => {
  it('are refused by the settings API and absent from the overview', async () => {
    for (const k of ['files.maxShareBytes', 'viewer.enabled', 'viewer.maxBytes']) {
      expect((await admin('settings', 'PATCH', { [k]: k === 'viewer.enabled' ? true : 1024 * 1024 })).status).toBe(400);
    }
    const s = (await (await admin('overview', 'GET')).json()).settings;
    expect(Object.keys(s).filter((k) => k === 'files.maxShareBytes' || k.startsWith('viewer.'))).toEqual([]);
  });

  it('an export file that still has them is refused', async () => {
    const post = (path, body) => fetchJson(path, { method: 'POST', body, cookie: oc, ip: freshIp() });
    const doc = (await (await post('/api/private/admin/export', { current: CURRENT, system: { settings: true } })).json()).document;
    doc.system.settings['viewer.enabled'] = true;
    const r = await post('/api/private/admin/import', { current: CURRENT, document: doc, decisions: { system: { settings: true }, users: {} }, dryRun: true });
    expect(r.status).toBe(400);
    expect((await r.json()).message).toMatch(/unknown setting/);
  });
});
