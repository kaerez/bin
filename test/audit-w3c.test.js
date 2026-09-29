// audit-w3c.test.js — regression tests for security audit W3, part C (the
// Drive, Drive keys v2, Receive links), in workerd with the real Worker and
// Durable Objects. Synthetic data only.
//   C-1 a rename or a metadata change is held to the role's file-type rule;
//   C-2 a Receive link's reservations that send nothing cannot fill the Drive
//       (bytes count as they arrive; what a link has reserved and not sent is
//       capped; an idle reservation is released; the user sees them);
//   C-3 deleting a link's folder, or the account, never counts an uploader's
//       late requests as guesses;
//   C-4 loosening a link's own file types or size limits needs the step-up;
//   C-5 files received count under drive-bytes (quota-kinds.test.js too);
//   C-6 "Go back" on a root change re-checks the sub-MEKs before it writes;
//   kg F4 the owner acting as the user gets no personal-kit state;
//   RT2-4 a link key stored in plain text is never handed out.
import { env, runDurableObjectAlarm, runInDurableObject } from 'cloudflare:test';
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import { owner, makeUser, fetchJson, intent, freshIp, proofFor, USER_PW, cookieOf } from './helpers.js';
import { enableDrive, driveLimits, driveKeys, sealed, createFile, mkdir, node, drive } from './drive-helpers.js';
import {
  dirStub, driveOf, errorOf, receiver, newReverse, rv, openLink, grantOf, reserve, send, received, putChunk, overhead,
} from './reverse-helpers.js';
import { CHUNK, encryptChunk, importFileKey } from '../public/js/files.js';
import { utf8, randomBytes, b64urlFromBytes } from '../public/js/bytes.js';
import { sealName, keyBytes, openAtRest, isAtRest } from '../public/js/drivekeys.js';
import { RECEIVE_HOLD_MAX, RECEIVE_IDLE_SEC } from '../src/drive-do.js';
import { invalidateGuardCaches } from '../src/lib/guard.js';

vi.setConfig({ testTimeout: 120000 });

let oc;
beforeAll(async () => { oc = await owner(); });
afterEach(async () => {
  vi.useRealTimers();
  await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'guard.invalid.max': 60 } });
  invalidateGuardCaches();
});

const MiB = 1024 * 1024;
const CONFIRM = { current: proofFor(USER_PW) };
const errorBody = async (r) => ({ status: r.status, ...(await r.json()) });
const invalidMax = async (n) => {
  expect((await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'guard.invalid.max': n } })).status).toBe(200);
  invalidateGuardCaches();
};
const listed = async (cookie, id) => (await (await fetchJson('/api/private/drive/reverse', { cookie })).json()).reverse.find((x) => x.id === id);
const finalize = (r, g, f, ip) => rv(r.id, `/files/${f.node}/finalize`, { headers: { 'x-reverse-grant': g, 'x-upload-token': f.data.uploadToken }, ip });
/** Chunk `i` of reserved file `f` (its real content, encrypted as the uploader's page does). */
async function chunkOf(f, i) {
  const n = f.data.chunks;
  return encryptChunk(await importFileKey(b64urlFromBytes(f.fk)), i, n, f.bytes.slice(i * CHUNK, (i + 1) * CHUNK));
}

describe('C-2: a Receive link cannot fill the Drive without sending data', () => {
  it('the PoC: a reservation that sends nothing takes only its sealed fields; the user and other links still upload', async () => {
    const u = await receiver('w3c-c2-poc', { driveMaxBytes: 4 * MiB });
    const r = await newReverse(u.cookie);
    const before = (await drive(u.cookie)).used;
    const ip = freshIp();
    const g = await grantOf(r, { ip });
    // One file as large as the space left, reserved; no chunk is ever sent.
    const f = await reserve(r, g, { ip, size: 4 * MiB - 64 * 1024 });
    expect(f.res.status).toBe(201);
    const after = (await drive(u.cookie)).used;
    expect(after).toBe(before + (await overhead(u.id)));
    expect(after - before).toBeLessThan(4000);
    // The user's own 100 KiB upload fits (it got 413 drive_full before the fix)…
    expect((await createFile(u.cookie, 'root', 100 * 1024)).res.status).toBe(201);
    // …and so does another link's upload.
    const r2 = await newReverse(u.cookie);
    const ip2 = freshIp();
    expect((await reserve(r2, await grantOf(r2, { ip: ip2 }), { ip: ip2, size: 3 * MiB })).res.status).toBe(201);
    // The user sees what is in progress, and its size so far.
    expect((await listed(u.cookie, r.id)).uploading).toMatchObject({ files: 1, bytes: 0, size: 4 * MiB - 64 * 1024 });
  });

  it(`what a link has reserved and not sent is capped at ${RECEIVE_HOLD_MAX / MiB} MiB (a chunk per parallel upload); the Drive counts none of it`, async () => {
    const u = await receiver('w3c-c2-hold');
    const r = await newReverse(u.cookie);
    const before = (await drive(u.cookie)).used;
    const ip = freshIp();
    const g = await grantOf(r, { ip });
    const held = [];
    for (let k = 0; k < RECEIVE_HOLD_MAX / CHUNK; k++) {
      const f = await reserve(r, g, { ip, size: 64 * MiB }); // each holds its next chunk only
      expect(f.res.status, String(k)).toBe(201);
      held.push(f);
    }
    for (const size of [CHUNK, 10]) {
      const more = await reserve(r, g, { ip, size });
      expect([more.res.status, await errorOf(more.res)], String(size)).toEqual([429, 'busy']);
    }
    expect((await drive(u.cookie)).used).toBe(before + (await overhead(u.id)));
    // One cancelled: room for another.
    expect((await rv(r.id, `/files/${held[0].node}`, { method: 'DELETE', headers: { 'x-reverse-grant': g, 'x-upload-token': held[0].data.uploadToken }, ip })).status).toBe(200);
    expect((await reserve(r, g, { ip, size: 64 * MiB })).res.status).toBe(201);
  });

  it(`a reservation with no chunk for ${RECEIVE_IDLE_SEC} s is released (uncounted late chunks); the uploader reserves it again and finishes`, async () => {
    const u = await receiver('w3c-c2-idle', { filePendingSec: 3600 });
    const r = await newReverse(u.cookie, { maxFiles: 3 });
    const ip = freshIp();
    const g = await grantOf(r, { ip });
    const f = await reserve(r, g, { ip, bytes: randomBytes(10) });
    expect(f.res.status).toBe(201);
    expect((await (await openLink(r, ip)).json()).limits.filesLeft).toBe(2);
    const t0 = Date.now();
    vi.useFakeTimers({ now: t0 + (RECEIVE_IDLE_SEC + 1) * 1000, toFake: ['Date'] });
    await runDurableObjectAlarm(driveOf(u.id));
    // Released: its row and its share of the link go (the role's filePendingSec is an hour).
    const left = await runInDurableObject(driveOf(u.id), (i, s) => s.storage.sql.exec('SELECT COUNT(*) AS c FROM nodes WHERE id = ?', f.node).one().c);
    expect(left).toBe(0);
    expect((await (await openLink(r, ip)).json()).limits.filesLeft).toBe(3);
    expect((await listed(u.cookie, r.id)).uploading).toMatchObject({ files: 0 });
    // Its late chunks are answered 410 released and never counted as guesses.
    await invalidMax(3);
    const codes = [];
    for (let k = 0; k < 4; k++) {
      const res = await putChunk(r.id, f.node, 0, await chunkOf(f, 0), f.data.uploadToken, ip);
      codes.push(`${res.status} ${(await res.json()).error}`);
    }
    expect(codes).toEqual(Array(4).fill('410 released'));
    // The session is still open: the file is reserved again and finished.
    const again = await send(r, g, { ip, bytes: f.bytes });
    expect(again.data.chunks).toBe(1);
    expect((await received(u.cookie)).items.map((x) => x.id)).toEqual([again.node]);
  });

  it('an idle reservation is released even before the alarm runs', async () => {
    const u = await receiver('w3c-c2-idle-now', { filePendingSec: 3600 });
    const r = await newReverse(u.cookie);
    const ip = freshIp();
    const g = await grantOf(r, { ip });
    const f = await reserve(r, g, { ip, bytes: randomBytes(10) });
    vi.useFakeTimers({ now: Date.now() + (RECEIVE_IDLE_SEC + 1) * 1000, toFake: ['Date'] });
    const res = await putChunk(r.id, f.node, 0, await chunkOf(f, 0), f.data.uploadToken, ip);
    expect([res.status, (await res.json()).error]).toEqual([410, 'released']);
  });

  it('a large multi-chunk upload still works: its bytes count as they arrive, each chunk must fit, the user sees its progress', async () => {
    const size = 2 * CHUNK + 5; // three chunks
    const u = await receiver('w3c-c2-large', { driveMaxBytes: size + 60000 });
    const r = await newReverse(u.cookie);
    const base = (await drive(u.cookie)).used;
    const ip = freshIp();
    const g = await grantOf(r, { ip });
    const content = new Uint8Array(size).map((_, i) => (i * 31) & 0xff);
    const f = await reserve(r, g, { ip, bytes: content, path: 'scans/big.bin', type: 'application/octet-stream' });
    expect(f.res.status).toBe(201);
    expect(f.data.chunks).toBe(3);
    const sealedBytes = await overhead(u.id);
    const usedNow = async () => (await drive(u.cookie)).used;
    expect(await usedNow()).toBe(base + sealedBytes);
    expect((await putChunk(r.id, f.node, 0, await chunkOf(f, 0), f.data.uploadToken, ip)).status).toBe(200);
    expect(await usedNow()).toBe(base + sealedBytes + CHUNK);
    // The link's details (Drive list and Receive API) show it in progress.
    expect((await listed(u.cookie, r.id)).uploading).toMatchObject({ files: 1, bytes: CHUNK, size });
    expect((await (await fetchJson(`/api/private/receive/${r.id}`, { cookie: u.cookie })).json()).link.uploading).toMatchObject({ files: 1, bytes: CHUNK, size });
    // A chunk sent again counts once.
    expect((await putChunk(r.id, f.node, 0, await chunkOf(f, 0), f.data.uploadToken, ip)).status).toBe(200);
    expect(await usedNow()).toBe(base + sealedBytes + CHUNK);
    expect((await putChunk(r.id, f.node, 1, await chunkOf(f, 1), f.data.uploadToken, ip)).status).toBe(200);
    expect((await putChunk(r.id, f.node, 2, await chunkOf(f, 2), f.data.uploadToken, ip)).status).toBe(200);
    expect((await finalize(r, g, f, ip)).status).toBe(200);
    expect(await usedNow()).toBe(base + sealedBytes + size);
    expect((await listed(u.cookie, r.id)).uploading).toMatchObject({ files: 0, bytes: 0, size: 0 });
    expect((await received(u.cookie)).items.map((x) => x.id)).toEqual([f.node]);
  });

  it('a chunk that no longer fits is refused (413 drive_full) and not stored', async () => {
    const u = await receiver('w3c-c2-full');
    const r = await newReverse(u.cookie);
    const ip = freshIp();
    const g = await grantOf(r, { ip });
    const f = await reserve(r, g, { ip, bytes: new Uint8Array(CHUNK + 100).map((_, i) => i & 0xff) });
    expect(f.res.status).toBe(201);
    expect((await putChunk(r.id, f.node, 0, await chunkOf(f, 0), f.data.uploadToken, ip)).status).toBe(200);
    // The Drive fills up meanwhile (here: the capacity lowered to what it holds now).
    await driveLimits(u.id, { driveMaxBytes: (await drive(u.cookie)).used + 50 });
    const res = await putChunk(r.id, f.node, 1, await chunkOf(f, 1), f.data.uploadToken, ip);
    expect([res.status, await errorOf(res)]).toEqual([413, 'drive_full']);
    expect(await env.FILES.get(`d/${u.id}/${f.node}/1`)).toBeNull();
  });
});

describe('C-3: late requests after the link\'s folder or its account is deleted are never counted', () => {
  it('the folder deleted under reserved uploads: late chunk PUTs get an uncounted 410', async () => {
    const u = await receiver('w3c-c3-folder');
    const { id: folder } = await mkdir(u.cookie);
    const r = await newReverse(u.cookie, { folder });
    const live = await newReverse(u.cookie);
    const ip = freshIp();
    const g = await grantOf(r, { ip });
    const files = [];
    for (let k = 0; k < 4; k++) files.push(await reserve(r, g, { ip }));
    await invalidMax(3);
    expect((await fetchJson(`/api/private/drive/nodes/${folder}`, { method: 'DELETE', cookie: u.cookie, headers: intent })).status).toBe(200);
    const codes = [];
    for (const f of files) codes.push((await putChunk(r.id, f.node, 0, await chunkOf(f, 0), f.data.uploadToken, ip)).status);
    expect(codes).toEqual([410, 410, 410, 410]);
    expect((await finalize(r, g, files[0], ip)).status).toBe(410);
    // The network is not blocked: a live link still opens with its proof.
    expect((await openLink(live, ip)).status).toBe(200);
    // A token the link never issued is still a guess.
    const other = freshIp();
    const forged = [];
    for (let k = 0; k < 3; k++) forged.push((await putChunk(r.id, files[0].node, 0, new Uint8Array(27), b64urlFromBytes(randomBytes(32)), other)).status);
    expect(forged.at(-1)).toBe(429);
  });

  it('the account deleted under reserved uploads: late chunk PUTs and done get an uncounted 410; guesses still count', async () => {
    const u = await receiver('w3c-c3-account');
    const r = await newReverse(u.cookie);
    const bystander = await receiver('w3c-c3-bystander');
    const live = await newReverse(bystander.cookie);
    const ip = freshIp();
    const g = await grantOf(r, { ip });
    const files = [await reserve(r, g, { ip }), await reserve(r, g, { ip })];
    await invalidMax(3);
    expect((await fetchJson(`/api/private/admin/users/${u.id}`, { method: 'DELETE', cookie: oc, headers: intent })).status).toBe(200);
    const codes = [];
    for (const f of [...files, ...files]) codes.push((await putChunk(r.id, f.node, 0, await chunkOf(f, 0), f.data.uploadToken, ip)).status);
    expect(codes).toEqual([410, 410, 410, 410]);
    expect((await rv(r.id, '/done', { headers: { 'x-reverse-grant': g }, ip })).status).toBe(410);
    expect((await finalize(r, g, files[0], ip)).status).toBe(410);
    expect((await openLink(live, ip)).status).toBe(200);
    // Only hashes are kept, for a day at most.
    const rows = await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec('SELECT hash, exp FROM reverse_late WHERE rid = ?', r.id).toArray());
    expect(rows.length).toBeGreaterThanOrEqual(3); // the session and both uploads
    expect(JSON.stringify(rows)).not.toContain(g);
    for (const x of rows) expect(x.exp).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + 86400 + 5);
    // A token or grant the link never issued is still a guess.
    const other = freshIp();
    const forged = [];
    for (let k = 0; k < 3; k++) forged.push((await putChunk(r.id, files[0].node, 0, new Uint8Array(27), b64urlFromBytes(randomBytes(32)), other)).status);
    expect(forged).toEqual([404, 404, 429]);
  });
});

describe('C-4: loosening a link\'s own file types or size limits needs the step-up', () => {
  const R = (id) => `/api/private/receive/${id}`;
  const bearer = (k) => ({ authorization: `Bearer ${k}` });
  async function withKey(name) {
    const u = await receiver(name, { apiEnabled: true, reverseMaxBytes: 100000 });
    const k = await fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body: { name: 'manage', scopes: ['manage'], ...CONFIRM } });
    expect(k.status).toBe(201);
    return { ...u, key: (await k.json()).key };
  }
  const LIMITS = { types: { mode: 'allow', rules: ['ext:pdf', 'ext:txt'] }, maxFileBytes: 1000, maxFiles: 5, maxBytes: 5000 };

  it('an API key is refused (403 step_up_required) each loosening, the link unchanged; tightening passes', async () => {
    const u = await withKey('w3c-c4-key');
    const r = await newReverse(u.cookie, LIMITS);
    expect(r.res.status).toBe(201);
    const patch = (body) => fetchJson(R(r.id), { method: 'PATCH', headers: bearer(u.key), body });
    const cases = [
      [{ types: null }, ['types']],
      [{ types: { mode: 'block', rules: ['ext:exe'] } }, ['types']],
      [{ types: { mode: 'allow', rules: ['ext:pdf', 'ext:txt', 'ext:exe'] } }, ['types']],
      [{ maxFileBytes: null }, ['maxFileBytes']],
      [{ maxFileBytes: 1001 }, ['maxFileBytes']],
      [{ maxFiles: null }, ['maxFiles']],
      [{ maxFiles: 6 }, ['maxFiles']],
      [{ maxBytes: 5001 }, ['maxBytes']],
      [{ maxBytes: null }, ['maxBytes']], // "none" is the role's limit (100000): a raise
      [{ types: null, maxFileBytes: null, maxFiles: null, views: 100000 }, ['types', 'maxFiles', 'maxFileBytes']],
    ];
    for (const [body, weakens] of cases) {
      const res = await patch(body);
      expect(await errorBody(res), JSON.stringify(body)).toMatchObject({ status: 403, error: 'step_up_required', weakens: expect.arrayContaining(weakens) });
    }
    expect(await listed(u.cookie, r.id)).toMatchObject(LIMITS);
    // Tighter: fewer types, smaller limits.
    expect((await patch({ types: { mode: 'allow', rules: ['ext:pdf'] }, maxFileBytes: 500, maxFiles: 2, maxBytes: 4000 })).status).toBe(200);
    expect(await listed(u.cookie, r.id)).toMatchObject({ types: { mode: 'allow', rules: ['ext:pdf'] }, maxFileBytes: 500, maxFiles: 2, maxBytes: 4000 });
    // A block list may grow (tighter), not shrink.
    const b = await newReverse(u.cookie, { types: { mode: 'block', rules: ['ext:exe', 'ext:js'] } });
    expect((await fetchJson(R(b.id), { method: 'PATCH', headers: bearer(u.key), body: { types: { mode: 'block', rules: ['ext:exe', 'ext:js', 'ext:bat'] } } })).status).toBe(200);
    expect(await errorBody(await fetchJson(R(b.id), { method: 'PATCH', headers: bearer(u.key), body: { types: { mode: 'block', rules: ['ext:exe'] } } })))
      .toMatchObject({ status: 403, error: 'step_up_required', weakens: ['types'] });
  });

  it('the browser: a loosening asks for the password or a passkey (400 reauth_required), then passes', async () => {
    const u = await withKey('w3c-c4-session');
    const r = await newReverse(u.cookie, LIMITS);
    const patch = (body) => fetchJson(`/api/private/shares/${r.id}`, { method: 'PATCH', cookie: u.cookie, body });
    expect(await errorOf(await patch({ types: null, maxFileBytes: null }))).toBe('reauth_required');
    expect(await errorBody(await patch({ types: null, maxFileBytes: null, current: proofFor('not the password') }))).toMatchObject({ status: 403 });
    expect((await patch({ types: null, maxFileBytes: null, ...CONFIRM })).status).toBe(200);
    expect(await listed(u.cookie, r.id)).toMatchObject({ types: null, maxFileBytes: null });
    // The owner acting as the user confirms nothing.
    const ic = cookieOf(await fetchJson(`/api/private/admin/users/${u.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent }));
    expect((await fetchJson(`/api/private/shares/${r.id}`, { method: 'PATCH', cookie: ic, body: { maxFiles: null } })).status).toBe(200);
  });
});

describe('C-1: a rename or a metadata change is held to the role\'s file-type rule', () => {
  /** A file with a real sealed name and metadata (as the browser seals them), uploaded (reserved) → its id. */
  async function file(cookie, name, type) {
    const f = await sealed(cookie, 'file', { name: utf8(name), meta: utf8(JSON.stringify({ type, mtime: 0, size: 10 })) });
    const ext = name.split('.').pop();
    const res = await fetchJson('/api/private/drive/files', { method: 'POST', cookie, body: { parent: 'root', name: f.name, meta: f.meta, dek: f.dek, ks: f.ks, mek: f.mek, size: 10, types: [{ ext, mime: type }] } });
    expect(res.status, await res.clone().text()).toBe(201);
    return (await res.json()).id;
  }
  /** PATCH a new name and / or metadata, sealed under the item's own keys as the browser does. */
  async function change(cookie, id, { name, meta } = {}) {
    const n = (await (await node(cookie, id)).json()).node;
    const k = await driveKeys(cookie);
    const at = { userId: k.userId, mekId: n.mek, salt: n.ks };
    const body = { ks: n.ks, mek: n.mek };
    if (name !== undefined) body.name = await sealName(k.keks.get(n.mek), at, 'name', utf8(name));
    if (meta !== undefined) body.meta = meta === null ? null : await sealName(k.keks.get(n.mek), at, 'meta', utf8(JSON.stringify(meta)));
    return fetchJson(`/api/private/drive/nodes/${id}`, { method: 'PATCH', cookie, body });
  }

  it('a rename to a blocked extension and a metadata change to a blocked type are refused; meta null is refused for a file', async () => {
    const u = await makeUser('w3c-c1');
    await enableDrive(u.id, { fileTypeMode: 'block', fileTypeRules: ['ext:exe', 'mime:application/x-msdownload'] });
    const id = await file(u.cookie, 'report.pdf', 'application/pdf');
    expect(await errorBody(await change(u.cookie, id, { name: 'tool.exe' }))).toMatchObject({ status: 403, error: 'file_type_not_allowed' });
    expect(await errorBody(await change(u.cookie, id, { meta: { type: 'application/x-msdownload', mtime: 0, size: 10 } }))).toMatchObject({ status: 403, error: 'file_type_not_allowed' });
    expect(await errorBody(await change(u.cookie, id, { meta: { mtime: 0, size: 10 } }))).toMatchObject({ status: 403, error: 'file_type_not_allowed' }); // no type: cannot be checked
    expect(await errorBody(await change(u.cookie, id, { meta: null }))).toMatchObject({ status: 400, error: 'invalid' });
    // Nothing changed; an allowed rename passes.
    expect((await change(u.cookie, id, { name: 'summary.pdf' })).status).toBe(200);
    expect((await change(u.cookie, id, { name: 'summary.txt', meta: { type: 'text/plain', mtime: 0, size: 10 } })).status).toBe(200);
    // A folder may still drop its metadata.
    const { id: dir } = await mkdir(u.cookie);
    const n = (await (await node(u.cookie, dir)).json()).node;
    expect((await fetchJson(`/api/private/drive/nodes/${dir}`, { method: 'PATCH', cookie: u.cookie, body: { meta: null, ks: n.ks, mek: n.mek } })).status).toBe(200);
  });

  it('an allow list: a rename out of it is refused; a file already there keeps its type and can still be renamed', async () => {
    const u = await makeUser('w3c-c1-allow');
    await enableDrive(u.id);
    const old = await file(u.cookie, 'old.exe', 'application/x-msdownload'); // before the rule
    await driveLimits(u.id, { fileTypeMode: 'allow', fileTypeRules: ['ext:pdf', 'ext:txt'] });
    const id = await file(u.cookie, 'report.pdf', 'application/pdf');
    expect(await errorBody(await change(u.cookie, id, { name: 'tool.exe' }))).toMatchObject({ status: 403, error: 'file_type_not_allowed' });
    // The rule is for new files and changes of type (docs/DRIVE.md §5): old.exe stays an .exe.
    expect((await change(u.cookie, old, { name: 'older.exe' })).status).toBe(200);
    expect((await change(u.cookie, old, { name: 'older.pdf' })).status).toBe(200);
    // With no type policy nothing is checked (meta null for a file is still refused).
    await driveLimits(u.id, { fileTypeMode: 'any', fileTypeRules: [] });
    expect((await change(u.cookie, id, { name: 'tool.exe' })).status).toBe(200);
    expect(await errorBody(await change(u.cookie, id, { meta: null }))).toMatchObject({ status: 400, error: 'invalid' });
  });
});

describe('kg F4: the owner acting as the user gets no personal-kit state', () => {
  it('GET /api/private/drive omits `kit` while impersonating; the user\'s own session has it', async () => {
    const u = await makeUser('w3c-f4');
    await enableDrive(u.id);
    const own = await drive(u.cookie);
    expect(own.kit).toMatchObject({ stale: false, last: null });
    const ic = cookieOf(await fetchJson(`/api/private/admin/users/${u.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent }));
    const imp = await drive(ic);
    expect(imp.enabled).toBe(true);
    expect('kit' in imp).toBe(false);
  });
});

describe('RT2-4: a link key stored in plain text is never handed out', () => {
  it('a plain-text link key (written to storage directly) lists with no key, in the links and with its received items', async () => {
    const u = await receiver('w3c-rt24');
    const r = await newReverse(u.cookie);
    const ip = freshIp();
    await send(r, await grantOf(r, { ip }), { ip });
    expect((await listed(u.cookie, r.id)).priv).toMatchObject({ iv: expect.any(String), ct: expect.any(String) });
    // Someone with write access to the Drive's storage replaces the sealed value with its plain JSON.
    const fk = await dirStub().fieldKeys(u.id, ['linkKey']);
    await runInDurableObject(driveOf(u.id), async (i, s) => {
      const stored = s.storage.sql.exec('SELECT priv FROM reverse WHERE id = ?', r.id).one().priv;
      expect(isAtRest(stored)).toBe(true);
      const plain = await openAtRest(keyBytes(fk.cur.linkKey), { userId: u.id, field: 'linkKey', ref: r.id }, stored);
      s.storage.sql.exec('UPDATE reverse SET priv = ? WHERE id = ?', plain, r.id);
    });
    expect((await listed(u.cookie, r.id)).priv).toBeNull();
    const rec = await received(u.cookie);
    expect(rec.keys.find((k) => k.id === r.id).priv).toBeNull();
  });
});

describe('C-6: "Go back" re-checks the sub-MEKs after its awaits', () => {
  it('a sub-MEK added while the swap seals is never left under the root that goes', async () => {
    const stub = env.DIRECTORY.get(env.DIRECTORY.idFromName('w3c-c6'));
    const ownerId = 'ownw3cc6xxxxxxxx';
    await runInDurableObject(stub, async (d) => {
      const t = Math.floor(Date.now() / 1000);
      d.sql.exec("INSERT OR IGNORE INTO users (id, username, role, pw_salt, pw_t, pw_verifier, created, updated) VALUES (?, 'o-w3c-c6', 'owner', 's', 3, 'v', ?, ?)", ownerId, t, t);
      await d.ensureKeys();
      const key = () => b64urlFromBytes(randomBytes(32));
      expect((await d.mekChangeRoot(ownerId, { key: key() })).ok).toBe(true);
      // Both at once, as two of the owner's requests: the add runs while the swap awaits its seals.
      const [swap, add] = await Promise.all([d.mekRootSwap(ownerId), d.mekAdd(ownerId, { key: key() })]);
      expect(swap.ok && add.ok).toBe(false); // one of them sees the other's change and is refused
      expect([swap, add].find((x) => !x.ok)).toMatchObject({ error: 'changed' });
      // Every sub-MEK opens under the root now.
      const st = await d.mekStatus();
      expect(st.subs.length).toBeGreaterThanOrEqual(1);
      for (const s of st.subs) expect(s.opens, s.id).toBe(true);
    });
  });
});
