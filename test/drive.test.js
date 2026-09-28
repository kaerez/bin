// drive.test.js — the Drive server (docs/DRIVE.md §4–§6) in workerd: access
// (role option, public account, API keys, impersonation), the folder tree
// (create, rename, move with cycle refusal, recursive delete), files (exact
// chunk sizes, finalize, download, the ciphertext hash), capacity and
// largest-file limits, the pending-upload purge, the session's KEKs and the
// server's check of every seal (key model v2), and isolation between users.
import { env, runDurableObjectAlarm, runInDurableObject } from 'cloudflare:test';
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import { owner, makeUser, fetchJson, intent, cookieOf, proofFor, salt16, USER_PW } from './helpers.js';
import { someBytes, enc, newNodeId, driveLimits, enableDrive, mkdir, createFile, putChunk, finalize, getChunk, uploadFile, del, node, drive, DIR_BYTES, FILE_BYTES, driveKeys, sealed, openStored } from './drive-helpers.js';
import { driveChunkSize, driveChunks, ciphertextHash, chunkHash } from '../src/drive-do.js';
import { SCHEMA_VERSION, PUBLIC_ID } from '../src/directory-do.js';
import { CHUNK } from '../public/js/files.js';
import { randomBytes, utf8 } from '../public/js/bytes.js';
import { sealName, newSalt, KEY_RE, MEK_ID_RE } from '../public/js/drivekeys.js';

let oc;
beforeAll(async () => { oc = await owner(); });
afterEach(() => vi.useRealTimers());

const dirStub = () => env.DIRECTORY.get(env.DIRECTORY.idFromName('directory'));
const driveOf = (uid) => env.DRIVE.get(env.DRIVE.idFromName(`drive:${uid}`));

describe('Drive access', () => {
  it('is a role option: off by default, on for the owner; everything but the summary is refused when off', async () => {
    const u = await makeUser('drv-off');
    const s = await drive(u.cookie);
    expect(s).toMatchObject({ enabled: false });
    expect(Object.keys(s).sort()).toEqual(['capacity', 'enabled', 'maxFile', 'used']);
    const r = await mkdir(u.cookie, 'root', { fields: { name: enc(), ks: newSalt(), mek: `m${'A'.repeat(11)}` } });
    expect(r.res.status).toBe(403);
    expect((await r.res.json()).error).toBe('drive_disabled');
    expect((await node(u.cookie, 'root')).status).toBe(403);
    const o = await drive(oc);
    expect(o).toMatchObject({ enabled: true, capacity: null, maxFile: null, used: 0 }); // no limit (the hard 100 GiB)
    // /api/private/me says whether the role has a Drive.
    expect((await (await fetchJson('/api/private/me', { cookie: oc })).json()).caps.driveEnabled).toBe(true);
    expect((await (await fetchJson('/api/private/me', { cookie: u.cookie })).json()).caps.driveEnabled).toBe(false);
    await enableDrive(u.id);
    expect((await (await fetchJson('/api/private/me', { cookie: u.cookie })).json()).caps.driveEnabled).toBe(true);
    await driveLimits(u.id, { driveEnabled: false });
    // The role options live in LIMITS; migration 13 put them in the Default role.
    expect(await dirStub().schemaVersion()).toBe(SCHEMA_VERSION);
    expect(SCHEMA_VERSION).toBe(16); // 13: the Drive; 14: reverse shares (reverse.test.js); 15: CAPTCHA on shares (captcha.test.js); 16: the Drive key model v2
    const rows = await runInDurableObject(dirStub(), (inst, state) => state.storage.sql.exec("SELECT key, value FROM limits WHERE user_id = '' AND channel = 'all' AND key LIKE 'drive%' ORDER BY key").toArray());
    expect(rows).toEqual([
      { key: 'driveEnabled', value: 'false' },
      { key: 'driveMaxBytes', value: String(1024 ** 3) },
      { key: 'driveMaxFileBytes', value: 'null' },
    ]);
  });

  it('the public account has no Drive (and its role cannot be given one)', async () => {
    const r = await dirStub().driveAccess(PUBLIC_ID);
    expect(r).toMatchObject({ ok: false, status: 403, error: 'drive_unavailable' });
    const set = await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: PUBLIC_ID, channel: 'all', patch: { driveEnabled: true } } });
    expect(set.status).toBe(400);
  });

  it('refuses API keys, even with every scope', async () => {
    const u = await makeUser('drv-api');
    await enableDrive(u.id, { apiEnabled: true });
    const key = (await (await fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body: { current: proofFor(USER_PW), name: 'k' } })).json()).key;
    for (const [path, method, body] of [['/api/private/drive', 'GET'], ['/api/private/drive/keys', 'POST', {}], ['/api/private/drive/folders', 'POST', { parent: 'root', name: enc() }], ['/api/private/drive/nodes/root', 'GET']]) {
      const r = await fetchJson(path, { method, body, headers: { authorization: `Bearer ${key}` } });
      expect(r.status).toBe(403);
      expect((await r.json()).error).toBe('api_key_not_allowed');
    }
  });

  it('needs a session and the CSRF guards', async () => {
    expect((await fetchJson('/api/private/drive')).status).toBe(401);
    const u = await makeUser('drv-csrf');
    await enableDrive(u.id);
    const f = await sealed(u.cookie);
    const cross = await fetchJson('/api/private/drive/folders', { method: 'POST', cookie: u.cookie, body: { parent: 'root', name: f.name, ks: f.ks, mek: f.mek }, headers: { 'sec-fetch-site': 'cross-site' } });
    expect(cross.status).toBe(403);
    // The keys too: never to another site; a POST with a JSON body (it may make the salt, and is audited
    // for the owner acting as the user), so the request shape and the session's CSRF token are checked.
    expect((await fetchJson('/api/private/drive/keys', { method: 'POST', cookie: u.cookie, body: {}, headers: { 'sec-fetch-site': 'cross-site' } })).status).toBe(403);
    expect((await fetchJson('/api/private/drive/keys', { method: 'POST', cookie: u.cookie, body: {}, csrf: false })).status).toBe(403);
    expect((await fetchJson('/api/private/drive/keys', { method: 'POST', cookie: u.cookie })).status).toBe(400); // no body: missing_intent
    expect((await fetchJson('/api/private/drive/keys', { cookie: u.cookie })).status).toBe(405); // not a GET
    const { id } = await mkdir(u.cookie);
    expect((await fetchJson(`/api/private/drive/nodes/${id}`, { method: 'DELETE', cookie: u.cookie })).status).toBe(400); // no intent header
  });
});

describe('Drive tree', () => {
  let u;
  beforeAll(async () => { u = await makeUser('drv-tree'); await enableDrive(u.id); });

  it('creates folders (client-chosen ids too), lists children and the path', async () => {
    const a = await mkdir(u.cookie);
    expect(a.res.status).toBe(201);
    const mine = newNodeId();
    const b = await mkdir(u.cookie, a.id, { id: mine });
    expect(b.id).toBe(mine);
    expect((await mkdir(u.cookie, a.id, { id: mine })).res.status).toBe(409); // taken
    expect((await mkdir(u.cookie, newNodeId())).res.status).toBe(404); // no such parent
    const r = await (await node(u.cookie, b.id)).json();
    expect(r.node).toMatchObject({ id: b.id, parent: a.id, kind: 'dir', ks: b.fields.ks, mek: b.fields.mek, mfp: expect.any(String) });
    expect(r.node.name).toEqual(b.fields.name);
    expect(r.path.map((x) => x.id)).toEqual(['root', a.id]);
    const root = await (await node(u.cookie, 'root')).json();
    expect(root.node).toMatchObject({ id: 'root', parent: null, name: null });
    expect(root.children.map((c) => c.id)).toContain(a.id);
    // Encrypted fields must look like {iv, ct}, with the item's salt and sub-MEK.
    const f = await sealed(u.cookie);
    for (const body of [{ name: 'plain text' }, { name: { iv: 'x', ct: 'y' } }, { name: f.name }, { name: f.name, ks: f.ks }, { name: f.name, mek: f.mek }, { name: f.name, ks: 'short', mek: f.mek }, { name: f.name, ks: f.ks, mek: 'nope' }]) {
      expect((await fetchJson('/api/private/drive/folders', { method: 'POST', cookie: u.cookie, body: { parent: 'root', ...body } })).status, JSON.stringify(body)).toBe(400);
    }
  });

  it('renames and moves; a folder cannot go into itself or below itself; files are not folders', async () => {
    const a = await mkdir(u.cookie);
    const b = await mkdir(u.cookie, a.id);
    const c = await mkdir(u.cookie, b.id);
    const patch = (id, body) => fetchJson(`/api/private/drive/nodes/${id}`, { method: 'PATCH', cookie: u.cookie, body });
    // A new name is sealed under the item's own sub-MEK and salt (and checked).
    const k = await driveKeys(u.cookie);
    const name = await sealName(k.keks.get(b.fields.mek), { userId: k.userId, mekId: b.fields.mek, salt: b.fields.ks }, 'name', utf8('renamed'));
    expect((await patch(b.id, { name })).status).toBe(400); // without its keys
    expect((await patch(b.id, { name, ks: b.fields.ks, mek: b.fields.mek })).status).toBe(200);
    expect((await (await node(u.cookie, b.id)).json()).node.name).toEqual(name);
    expect(new TextDecoder().decode((await openStored(u.cookie, { ...b.fields, name })).name)).toBe('renamed');
    const other = await patch(b.id, { name: enc(), ks: b.fields.ks, mek: b.fields.mek });
    expect(other.status).toBe(400);
    expect((await other.json()).error).toBe('bad_seal');
    // Another item's keys: its name does not open with them there, or the keys are stale.
    const stale = await patch(b.id, { name: a.fields.name, ks: a.fields.ks, mek: a.fields.mek });
    expect(stale.status).toBe(409);
    expect((await stale.json()).error).toBe('stale_keys');
    for (const target of [a.id, b.id, c.id]) {
      const r = await patch(a.id, { parent: target });
      expect(r.status).toBe(409);
      expect((await r.json()).error).toBe('cycle');
    }
    expect((await patch(c.id, { parent: 'root' })).status).toBe(200);
    expect((await (await node(u.cookie, c.id)).json()).node.parent).toBe('root');
    const f = await uploadFile(u.cookie, a.id, 10);
    expect((await patch(c.id, { parent: f.id })).status).toBe(400); // not a folder
    expect((await patch('root', { parent: a.id })).status).toBe(400);
    expect((await patch(a.id, {})).status).toBe(400);
  });

  it('uploads with exact chunk sizes and the upload token, finalizes, downloads', async () => {
    const size = CHUNK + 100; // two chunks: 8 MiB and 100 bytes, each + the 16-byte tag
    const f = await createFile(u.cookie, 'root', size);
    expect(f.res.status).toBe(201);
    expect(f.chunks).toBe(2);
    expect(f.uploadToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const c0 = someBytes(driveChunkSize(size, 0));
    const c1 = randomBytes(driveChunkSize(size, 1));
    expect(c1.length).toBe(116);
    expect((await putChunk(u.cookie, f.id, 1, c1.slice(1), f.uploadToken)).status).toBe(400); // wrong size
    expect((await putChunk(u.cookie, f.id, 2, c1, f.uploadToken)).status).toBe(400); // no such index
    expect((await putChunk(u.cookie, f.id, 1, c1, 'A'.repeat(43))).status).toBe(403); // wrong token
    expect((await putChunk(u.cookie, f.id, 1, c1, f.uploadToken, { 'content-type': 'text/plain' })).status).toBe(415);
    expect((await putChunk(u.cookie, f.id, 1, c1, f.uploadToken)).status).toBe(200);
    const early = await finalize(u.cookie, f.id, f.uploadToken);
    expect(early.status).toBe(409);
    expect((await early.json()).error).toBe('incomplete');
    expect((await getChunk(u.cookie, f.id, 1)).status).toBe(404); // not ready yet
    expect((await putChunk(u.cookie, f.id, 0, c0, f.uploadToken)).status).toBe(200);
    const pending = (await (await node(u.cookie, f.id)).json()).node;
    expect(pending).toMatchObject({ state: 'pending', done: 2, size, chunks: 2 });
    expect((await finalize(u.cookie, f.id, 'B'.repeat(43))).status).toBe(403);
    expect((await finalize(u.cookie, f.id, f.uploadToken)).status).toBe(200);
    expect((await finalize(u.cookie, f.id, f.uploadToken)).status).toBe(410); // once
    expect((await putChunk(u.cookie, f.id, 0, c0, f.uploadToken)).status).toBe(410);
    const got = await getChunk(u.cookie, f.id, 1);
    expect(got.status).toBe(200);
    expect(got.headers.get('content-type')).toBe('application/octet-stream');
    expect(Array.from(new Uint8Array(await got.arrayBuffer()))).toEqual(Array.from(c1));
    expect((await getChunk(u.cookie, f.id, 2)).status).toBe(404);
    // Stored under d/<user>/<node>/<i>, never f/.
    expect(await env.FILES.get(`d/${u.id}/${f.id}/0`)).not.toBeNull();
    const ready = (await (await node(u.cookie, f.id)).json()).node;
    expect(ready).toMatchObject({ state: 'ready', size, chunks: 2, dek: f.fields.dek, ks: f.fields.ks, mek: f.fields.mek });
    expect(ready.fk).toBeUndefined();
    // The ciphertext hash: of the stored chunks, never of the plaintext (docs/DRIVE.md §3).
    const hs = [await chunkHash(c0), await chunkHash(c1)];
    expect(ready.ch).toBe(await ciphertextHash(2, (i) => hs[i]));
    expect(ready.ch).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // An empty file has no chunks: it is finalized at once.
    expect(driveChunks(0)).toBe(0);
    const e = await createFile(u.cookie, 'root', 0);
    expect(e.chunks).toBe(0);
    expect((await putChunk(u.cookie, e.id, 0, new Uint8Array(16), e.uploadToken)).status).toBe(400);
    expect((await finalize(u.cookie, e.id, e.uploadToken)).status).toBe(200);
    expect((await getChunk(u.cookie, e.id, 0)).status).toBe(404);
    expect(driveChunks(CHUNK)).toBe(1);
    expect(driveChunkSize(CHUNK, 0)).toBe(CHUNK + 16);
  });

  it('deletes recursively: frees capacity, removes the R2 objects', async () => {
    const before = (await drive(u.cookie)).used;
    const a = await mkdir(u.cookie);
    const b = await mkdir(u.cookie, a.id);
    const f1 = await uploadFile(u.cookie, a.id, 1000);
    const f2 = await uploadFile(u.cookie, b.id, 2000);
    const pend = await createFile(u.cookie, b.id, 3000); // an unfinished upload goes too
    // Content, plus the sealed fields of 2 folders and 3 files.
    expect((await drive(u.cookie)).used).toBe(before + 6000 + 2 * DIR_BYTES + 3 * FILE_BYTES);
    const r = await del(u.cookie, a.id);
    expect(r.status).toBe(200);
    expect(await r.json()).toMatchObject({ ok: true, deleted: 5 });
    expect((await drive(u.cookie)).used).toBe(before);
    for (const id of [f1.id, f2.id]) expect(await env.FILES.get(`d/${u.id}/${id}/0`)).toBeNull();
    for (const id of [a.id, b.id, f1.id, pend.id]) expect((await node(u.cookie, id)).status).toBe(404);
    expect((await del(u.cookie, a.id)).status).toBe(404);
    expect((await del(u.cookie, 'root')).status).toBe(400);
    // Admin → Users shows the usage.
    const users = (await (await fetchJson('/api/private/admin/users', { cookie: oc })).json()).users;
    expect(users.find((x) => x.id === u.id).drive).toEqual({ enabled: true, used: before, capacity: 1024 ** 3 });
    expect(users.find((x) => x.id === PUBLIC_ID).drive).toBeNull();
  });
});

describe('Drive limits', () => {
  it('capacity and the largest file are enforced when the file is created', async () => {
    const u = await makeUser('drv-cap');
    // Each file also takes its sealed fields (FILE_BYTES) of the capacity.
    const cap = 1000 + 2 * FILE_BYTES;
    await enableDrive(u.id, { driveMaxBytes: cap, driveMaxFileBytes: 700 });
    expect(await drive(u.cookie)).toMatchObject({ capacity: cap, maxFile: 700, used: 0 });
    const big = await createFile(u.cookie, 'root', 701);
    expect(big.res.status).toBe(413);
    expect((await big.res.json()).error).toBe('file_too_large');
    await uploadFile(u.cookie, 'root', 600);
    const over = await createFile(u.cookie, 'root', 401);
    expect(over.res.status).toBe(413);
    expect(await over.res.json()).toMatchObject({ error: 'drive_full', max: cap, used: 600 + FILE_BYTES });
    expect((await createFile(u.cookie, 'root', 400)).res.status).toBe(201); // exactly full (pending counts)
    expect((await createFile(u.cookie, 'root', 1)).res.status).toBe(413);
    // No limit (null) = the hard 100 GiB.
    await driveLimits(u.id, { driveMaxBytes: null, driveMaxFileBytes: null });
    expect(await drive(u.cookie)).toMatchObject({ capacity: null, maxFile: null });
    expect((await createFile(u.cookie, 'root', 100 * 1024 ** 3 + 1)).res.status).toBe(400);
    expect((await createFile(u.cookie, 'root', 100 * 1024 ** 3 - cap - FILE_BYTES)).res.status).toBe(201); // exactly full
    const full = await createFile(u.cookie, 'root', 1);
    expect(full.res.status).toBe(413);
    expect((await full.res.json()).max).toBe(100 * 1024 ** 3);
    const users = (await (await fetchJson('/api/private/admin/users', { cookie: oc })).json()).users;
    expect(users.find((x) => x.id === u.id).drive.capacity).toBeNull();
  });

  it('a pending upload with no progress for the role’s filePendingSec is purged by the alarm', async () => {
    const u = await makeUser('drv-pend');
    await enableDrive(u.id, { filePendingSec: 600 });
    const f = await createFile(u.cookie, 'root', 50);
    expect((await putChunk(u.cookie, f.id, 0, randomBytes(66), f.uploadToken)).status).toBe(200);
    const keep = await uploadFile(u.cookie, 'root', 20);
    expect((await drive(u.cookie)).used).toBe(70 + 2 * FILE_BYTES);
    vi.useFakeTimers({ now: Date.now() + 601 * 1000, toFake: ['Date'] });
    await runDurableObjectAlarm(driveOf(u.id));
    vi.useRealTimers();
    expect((await node(u.cookie, f.id)).status).toBe(404);
    expect(await env.FILES.get(`d/${u.id}/${f.id}/0`)).toBeNull();
    expect((await node(u.cookie, keep.id)).status).toBe(200); // complete files stay
    expect((await drive(u.cookie)).used).toBe(20 + FILE_BYTES);
    // The mirror the admin sees was updated by the alarm itself.
    const users = (await (await fetchJson('/api/private/admin/users', { cookie: oc })).json()).users;
    expect(users.find((x) => x.id === u.id).drive.used).toBe(20 + FILE_BYTES);
  });
});

describe('Drive keys (key model v2, docs/DRIVE.md §3)', () => {
  const post = (cookie, f) => fetchJson('/api/private/drive/folders', { method: 'POST', cookie, body: { parent: 'root', name: f.name, ks: f.ks, mek: f.mek } });

  it('the session gets its KEKs from the server with no prompt; the summary holds no key', async () => {
    const u = await makeUser('drv-keys');
    await enableDrive(u.id);
    const r = await fetchJson('/api/private/drive/keys', { method: 'POST', cookie: u.cookie, body: {} });
    expect(r.status).toBe(200);
    expect(r.headers.get('cache-control')).toBe('no-store');
    const k = await r.json();
    expect(k.userId).toBe(u.id);
    expect(k.current).toMatch(MEK_ID_RE);
    expect(k.keys).toHaveLength(1);
    expect(k.keys[0]).toMatchObject({ mekId: k.current, kek: expect.stringMatching(KEY_RE), fp: expect.any(String), until: null });
    expect(k.missing).toEqual([]);
    expect(k.broken).toEqual([]);
    // No key, salt or wrap in the Drive's summary.
    const s = await drive(u.cookie);
    expect(s).toMatchObject({ enabled: true, current: k.current, migration: null });
    for (const x of ['keys', 'kek', 'wraps', 'driveSalt', 'kcv', 'escrowPub', 'escrowPriv', 'salt']) expect(s[x]).toBeUndefined();
    // Every user has a KEK of their own (their own salt).
    const v = await makeUser('drv-keys2');
    await enableDrive(v.id);
    const kv = await (await fetchJson('/api/private/drive/keys', { method: 'POST', cookie: v.cookie, body: {} })).json();
    expect(kv.current).toBe(k.current);
    expect(kv.keys[0].kek).not.toBe(k.keys[0].kek);
  });

  it('refuses what does not open under the current KEK (another user’s, random bytes, another sub-MEK)', async () => {
    const u = await makeUser('drv-seal');
    const v = await makeUser('drv-seal2');
    await enableDrive(u.id);
    await enableDrive(v.id);
    const theirs = await post(u.cookie, await sealed(v.cookie));
    expect(theirs.status).toBe(400);
    expect((await theirs.json()).error).toBe('bad_seal');
    const mine = await sealed(u.cookie);
    const random = await post(u.cookie, { ...mine, name: enc() });
    expect((await random.json()).error).toBe('bad_seal');
    const salt = await post(u.cookie, { ...mine, ks: (await sealed(u.cookie)).ks }); // the salt is part of the key
    expect((await salt.json()).error).toBe('bad_seal');
    const gone = await post(u.cookie, { ...mine, mek: `m${'A'.repeat(11)}` });
    expect(gone.status).toBe(409);
    expect((await gone.json()).error).toBe('mek_not_current');
    expect((await post(u.cookie, mine)).status).toBe(201);
    // A file: its DEK too.
    const f = await sealed(u.cookie, 'file');
    const bad = await fetchJson('/api/private/drive/files', { method: 'POST', cookie: u.cookie, body: { parent: 'root', name: f.name, meta: f.meta, dek: enc(32), ks: f.ks, mek: f.mek, size: 1 } });
    expect((await bad.json()).error).toBe('bad_seal');
    expect((await createFile(u.cookie, 'root', 1, { fields: f })).res.status).toBe(201);
  });

  it('the owner acting as the user gets the user’s keys (admin audit only; the user’s activity shows no key use)', async () => {
    const u = await makeUser('drv-imp');
    await enableDrive(u.id);
    const mine = await driveKeys(u.cookie);
    const ic = cookieOf(await fetchJson(`/api/private/admin/users/${u.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent }));
    const theirs = await driveKeys(ic, { fresh: true });
    expect(theirs.userId).toBe(u.id);
    expect([...theirs.keks.values()].map((x) => [...x])).toEqual([...mine.keks.values()].map((x) => [...x]));
    // It works as the user: the item opens with the user's own keys.
    const d = await mkdir(ic);
    expect(d.res.status).toBe(201);
    const n = (await (await node(u.cookie, d.id)).json()).node;
    expect((await openStored(u.cookie, n)).name).toEqual(expect.any(Uint8Array));
    const audit = (await (await fetchJson(`/api/private/admin/audit?user=${u.id}`, { cookie: oc })).json()).rows;
    expect(audit.some((x) => x.action === 'drive.keys_used')).toBe(true);
    const act = (await (await fetchJson('/api/private/me/activity', { cookie: u.cookie })).json()).rows;
    expect(act.some((x) => x.action === 'drive.keys_used')).toBe(false);
    // The personal kit is the user's own.
    const kit = await fetchJson('/api/private/drive/kit', { method: 'POST', cookie: ic, headers: intent, body: {} });
    expect(kit.status).toBe(403);
    expect((await kit.json()).error).toBe('impersonating');
  });

  it('the keys never change with a password change or an admin reset', async () => {
    const u = await makeUser('drv-pw');
    await enableDrive(u.id);
    const before = (await driveKeys(u.cookie)).raw.keys;
    expect((await fetchJson(`/api/private/admin/users/${u.id}/password`, { method: 'POST', cookie: oc, body: { salt: salt16(), t: 3, proof: proofFor('new-pass-1') } })).status).toBe(200);
    const c = cookieOf(await fetchJson('/api/auth/login', { method: 'POST', body: { username: 'drv-pw', proof: proofFor('new-pass-1') } }));
    expect((await driveKeys(c, { fresh: true })).raw.keys).toEqual(before);
  });

  it('a role without a Drive gets no keys', async () => {
    const u = await makeUser('drv-nokeys');
    const r = await fetchJson('/api/private/drive/keys', { method: 'POST', cookie: u.cookie, body: {} });
    expect(r.status).toBe(403);
    expect((await r.json()).error).toBe('drive_disabled');
  });

  it('the old key routes are gone', async () => {
    const u = await makeUser('drv-oldroutes');
    await enableDrive(u.id);
    expect((await fetchJson('/api/private/drive/keys', { method: 'PUT', cookie: u.cookie, headers: intent, body: {} })).status).toBe(405);
    for (const p of ['/api/private/drive/start-over', '/api/private/drive/archive', `/api/private/admin/drive/escrow/${u.id}`, `/api/private/admin/drive/keys/${u.id}`]) {
      expect((await fetchJson(p, { method: 'POST', cookie: oc, headers: intent, body: { reason: 'x' } })).status, p).toBe(404);
    }
  });
});

describe('Drive isolation', () => {
  it('one user can never reach another user’s items (IDOR)', async () => {
    const a = await makeUser('drv-alice');
    const b = await makeUser('drv-bob');
    await enableDrive(a.id);
    await enableDrive(b.id);
    const dA = await mkdir(a.cookie);
    const fA = await uploadFile(a.cookie, dA.id, 100);
    // Bob's Drive is a different object: Alice's ids do not exist there.
    expect((await node(b.cookie, dA.id)).status).toBe(404);
    expect((await getChunk(b.cookie, fA.id, 0)).status).toBe(404);
    expect((await del(b.cookie, fA.id)).status).toBe(404);
    expect((await fetchJson(`/api/private/drive/nodes/${fA.id}`, { method: 'PATCH', cookie: b.cookie, body: { parent: 'root' } })).status).toBe(404);
    expect((await mkdir(b.cookie, dA.id)).res.status).toBe(404);
    expect((await fetchJson(`/api/private/drive/nodes/${fA.id}/shares`, { cookie: b.cookie })).status).toBe(404);
    // Re-using Alice's upload token on "her" id in Bob's Drive gets nowhere either.
    const f = await createFile(a.cookie, 'root', 10);
    expect((await putChunk(b.cookie, f.id, 0, randomBytes(26), f.uploadToken)).status).toBe(410);
    // Alice's data is untouched.
    const mine = await getChunk(a.cookie, fA.id, 0);
    expect(mine.status).toBe(200);
    await mine.arrayBuffer();
    expect((await node(a.cookie, dA.id)).status).toBe(200);
    // A Drive object refuses calls for another user.
    await runInDurableObject(driveOf(a.id), async (inst) => { await expect(inst.usage(b.id)).rejects.toThrow('wrong user'); });
  });

  it('deleting an account deletes its Drive and its ciphertext', async () => {
    const u = await makeUser('drv-gone');
    await enableDrive(u.id);
    const f = await uploadFile(u.cookie, 'root', 100);
    expect(await env.FILES.get(`d/${u.id}/${f.id}/0`)).not.toBeNull();
    expect((await fetchJson(`/api/private/admin/users/${u.id}`, { method: 'DELETE', cookie: oc, headers: intent })).status).toBe(200);
    expect(await env.FILES.get(`d/${u.id}/${f.id}/0`)).toBeNull();
  });
});
