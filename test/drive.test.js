// drive.test.js — the Drive server (docs/DRIVE.md §4–§6) in workerd: access
// (role option, public account, API keys, impersonation), the folder tree
// (create, rename, move with cycle refusal, recursive delete), files (exact
// chunk sizes, finalize, download), capacity and largest-file limits, the
// pending-upload purge, key wraps, the owner's escrow key and escrow route,
// and isolation between users.
import { env, runDurableObjectAlarm, runInDurableObject } from 'cloudflare:test';
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import { owner, makeUser, fetchJson, intent, cookieOf, proofFor, salt16, USER_PW } from './helpers.js';
import { someBytes, enc, newNodeId, driveLimits, enableDrive, mkdir, createFile, putChunk, finalize, getChunk, uploadFile, del, node, drive, DIR_BYTES, FILE_BYTES, escrowWrap, ensureEscrow, KCV } from './drive-helpers.js';
import { driveChunkSize, driveChunks } from '../src/drive-do.js';
import { SCHEMA_VERSION, PUBLIC_ID } from '../src/directory-do.js';
import { CHUNK } from '../public/js/files.js';
import { randomBytes } from '../public/js/bytes.js';

let oc;
beforeAll(async () => { oc = await owner(); });
afterEach(() => vi.useRealTimers());

const dirStub = () => env.DIRECTORY.get(env.DIRECTORY.idFromName('directory'));
const driveOf = (uid) => env.DRIVE.get(env.DRIVE.idFromName(`drive:${uid}`));
const JWK = { kty: 'EC', crv: 'P-256', x: 'A'.repeat(43), y: `${'B'.repeat(42)}A` }; // stand-in coordinates (32 bytes each)
const keys = (cookie, body) => fetchJson('/api/private/drive/keys', { method: 'PUT', cookie, body });

describe('Drive access', () => {
  it('is a role option: off by default, on for the owner; everything but the summary is refused when off', async () => {
    const u = await makeUser('drv-off');
    const s = await drive(u.cookie);
    expect(s).toMatchObject({ enabled: false, wraps: [], driveSalt: null });
    const r = await mkdir(u.cookie);
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
    expect(SCHEMA_VERSION).toBe(15); // 13: the Drive; 14: reverse shares (reverse.test.js); 15: CAPTCHA on shares (captcha.test.js)
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
    for (const [path, method, body] of [['/api/private/drive', 'GET'], ['/api/private/drive/folders', 'POST', { parent: 'root', name: enc() }], ['/api/private/drive/nodes/root', 'GET']]) {
      const r = await fetchJson(path, { method, body, headers: { authorization: `Bearer ${key}` } });
      expect(r.status).toBe(403);
      expect((await r.json()).error).toBe('api_key_not_allowed');
    }
  });

  it('needs a session and the CSRF guards', async () => {
    expect((await fetchJson('/api/private/drive')).status).toBe(401);
    const u = await makeUser('drv-csrf');
    await enableDrive(u.id);
    const cross = await fetchJson('/api/private/drive/folders', { method: 'POST', cookie: u.cookie, body: { parent: 'root', name: enc() }, headers: { 'sec-fetch-site': 'cross-site' } });
    expect(cross.status).toBe(403);
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
    expect(r.node).toMatchObject({ id: b.id, parent: a.id, kind: 'dir' });
    expect(r.node.name).toMatchObject({ iv: expect.any(String), ct: expect.any(String) });
    expect(r.path.map((x) => x.id)).toEqual(['root', a.id]);
    const root = await (await node(u.cookie, 'root')).json();
    expect(root.node).toMatchObject({ id: 'root', parent: null, name: null });
    expect(root.children.map((c) => c.id)).toContain(a.id);
    // Encrypted fields must look like {iv, ct}.
    expect((await fetchJson('/api/private/drive/folders', { method: 'POST', cookie: u.cookie, body: { parent: 'root', name: 'plain text' } })).status).toBe(400);
    expect((await fetchJson('/api/private/drive/folders', { method: 'POST', cookie: u.cookie, body: { parent: 'root', name: { iv: 'x', ct: 'y' } } })).status).toBe(400);
  });

  it('renames and moves; a folder cannot go into itself or below itself; files are not folders', async () => {
    const a = await mkdir(u.cookie);
    const b = await mkdir(u.cookie, a.id);
    const c = await mkdir(u.cookie, b.id);
    const patch = (id, body) => fetchJson(`/api/private/drive/nodes/${id}`, { method: 'PATCH', cookie: u.cookie, body });
    const name = enc();
    expect((await patch(b.id, { name })).status).toBe(200);
    expect((await (await node(u.cookie, b.id)).json()).node.name).toEqual(name);
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
    expect(ready).toMatchObject({ state: 'ready', size, chunks: 2 });
    expect(ready.fk).toMatchObject({ iv: expect.any(String) });
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

describe('Drive keys', () => {
  // Wrap data is opaque to the server: base64url segments joined by "." (docs/DRIVE.md §3).
  const W = (n = 1) => `1.${'A'.repeat(16)}.${'B'.repeat(64 + n)}`;
  let ESC; // an escrow wrap for the owner's current escrow key (it exists before any user's Drive)

  it('sets and removes wraps and the salt; refuses unknown kinds, bad data and credentials the account does not have', async () => {
    const u = await makeUser('drv-keys');
    await enableDrive(u.id);
    ESC = (await escrowWrap()).data;
    const salt = salt16();
    // A first set-up without the key check value (or the pin) is refused (R5-L3).
    expect((await keys(u.cookie, { driveSalt: salt, set: [{ kind: 'pw', ref: 'pw', data: W() }, { kind: 'escrow', ref: 'escrow', data: ESC }], remove: [], escrowPin: enc(40) })).status).toBe(400);
    expect((await keys(u.cookie, { driveSalt: salt, set: [{ kind: 'pw', ref: 'pw', data: W() }, { kind: 'escrow', ref: 'escrow', data: ESC }], remove: [], kcv: KCV })).status).toBe(400);
    expect((await keys(u.cookie, { driveSalt: salt, set: [{ kind: 'pw', ref: 'pw', data: W() }, { kind: 'escrow', ref: 'escrow', data: ESC }], remove: [], escrowPin: enc(40), kcv: KCV })).status).toBe(200);
    let s = await drive(u.cookie);
    expect(s.driveSalt).toBe(salt);
    expect(s.wraps).toEqual([{ kind: 'escrow', ref: 'escrow', data: ESC }, { kind: 'pw', ref: 'pw', data: W() }]);
    expect(s.escrowPriv).toBeUndefined();
    // Replacing the pw wrap or removing a wrap needs the password (or a passkey), as on Account.
    const noStep = await keys(u.cookie, { set: [{ kind: 'pw', ref: 'pw', data: W(2) }] });
    expect(noStep.status).toBe(400);
    expect((await noStep.json()).error).toBe('reauth_required');
    expect((await keys(u.cookie, { set: [{ kind: 'pw', ref: 'pw', data: W(2) }], current: proofFor(USER_PW) })).status).toBe(400); // kcv_required
    expect((await keys(u.cookie, { set: [{ kind: 'pw', ref: 'pw', data: W(2) }], current: proofFor(USER_PW), kcv: KCV })).status).toBe(200); // replaced
    expect((await drive(u.cookie)).wraps.find((w) => w.kind === 'pw').data).toBe(W(2));
    expect((await keys(u.cookie, { remove: [{ kind: 'pw', ref: 'pw' }] })).status).toBe(400);
    expect((await keys(u.cookie, { remove: [{ kind: 'pw', ref: 'pw' }], current: proofFor('not-the-password') })).status).toBe(403);
    // Never without a wrap of the user's own, and never without the escrow wrap.
    const own = await keys(u.cookie, { remove: [{ kind: 'pw', ref: 'pw' }], current: proofFor(USER_PW) });
    expect(own.status).toBe(409);
    expect((await own.json()).error).toBe('last_own_wrap');
    const esc = await keys(u.cookie, { remove: [{ kind: 'escrow', ref: 'escrow' }], current: proofFor(USER_PW) });
    expect(esc.status).toBe(403);
    expect((await esc.json()).error).toBe('escrow_required');
    s = await drive(u.cookie);
    expect(s.wraps.map((w) => w.kind)).toEqual(['escrow', 'pw']);
    const bad = [
      { set: [{ kind: 'magic', ref: 'x', data: W() }] },
      { set: [{ kind: 'pw', ref: 'other', data: W() }] }, // one pw wrap: ref "pw"
      { set: [{ kind: 'escrow', ref: '', data: ESC }] },
      { set: [{ kind: 'pw', ref: 'pw', data: { iv: 'x', ct: 'y' } }] }, // an opaque string
      { set: [{ kind: 'pw', ref: 'pw', data: 'x'.repeat(1025) }] },
      { set: [{ kind: 'pw', ref: 'pw', data: '1.<script>' }] },
      { set: [{ kind: 'passkey', ref: 'Q'.repeat(22), data: W() }] }, // not one of the account's passkeys
      { set: [{ kind: 'recovery', ref: 'a'.repeat(64), data: W() }] }, // not a current recovery code
      { driveSalt: 'short' },
      {},
    ];
    for (const b of bad) expect((await keys(u.cookie, b)).status, JSON.stringify(b)).toBe(400);
    // Wraps of passkeys / codes the account no longer has are dropped by the server.
    await driveOf(u.id).setKeys(u.id, { set: [{ kind: 'passkey', ref: 'gone-credential-id', data: W() }, { kind: 'recovery', ref: 'f'.repeat(64), data: W() }] });
    expect((await drive(u.cookie)).wraps).toHaveLength(4);
    await fetchJson(`/api/private/admin/users/${u.id}/passkeys`, { method: 'POST', cookie: oc, headers: intent, body: {} });
    expect((await drive(u.cookie)).wraps.map((w) => w.kind)).toEqual(['escrow', 'pw']);
  });

  it('cannot change keys while impersonating (the rest works as the user)', async () => {
    const u = await makeUser('drv-imp');
    await enableDrive(u.id);
    const imp = await fetchJson(`/api/private/admin/users/${u.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent });
    const ic = cookieOf(imp);
    const r = await keys(ic, { driveSalt: salt16() });
    expect(r.status).toBe(403);
    expect((await r.json()).error).toBe('impersonating');
    expect((await fetchJson('/api/private/drive', { cookie: ic })).status).toBe(200);
    expect((await mkdir(ic)).res.status).toBe(201);
  });

  it('escrowPub / escrowPriv are the owner’s only; every Drive sees escrowPub', async () => {
    const u = await makeUser('drv-esc');
    await enableDrive(u.id);
    const no = await keys(u.cookie, { escrowPub: JWK });
    expect(no.status).toBe(403);
    expect((await no.json()).error).toBe('owner_only');
    expect((await keys(u.cookie, { escrowPriv: W() })).status).toBe(403);
    expect((await keys(oc, { escrowPub: { ...JWK, d: 'C'.repeat(43) } })).status).toBe(400); // a private key
    expect((await keys(oc, { escrowPub: { kty: 'RSA', n: 'x', e: 'AQAB' } })).status).toBe(400);
    expect((await keys(oc, { escrowPriv: { iv: 'x', ct: 'y' } })).status).toBe(400);
    const priv = W(150);
    await ensureEscrow(); // the owner's key exists (before any user's Drive): replacing it needs the owner's password
    expect((await keys(oc, { escrowPub: { ...JWK, ext: true, key_ops: [] }, escrowPriv: priv, set: [], remove: [] })).status).toBe(400);
    expect((await keys(oc, { escrowPub: { ...JWK, ext: true, key_ops: [] }, escrowPriv: priv, set: [], remove: [], current: proofFor('owner-password') })).status).toBe(200);
    expect((await drive(u.cookie)).escrowPub).toEqual(JWK);
    const o = await drive(oc);
    expect(o.escrowPub).toEqual(JWK);
    expect(o.escrowPriv).toBe(priv);
    const audit = (await (await fetchJson('/api/private/admin/audit', { cookie: oc })).json()).rows;
    expect(audit.some((r) => r.action === 'drive.escrow_key_set')).toBe(true);
  });

  it('the escrow route: owner only, needs a reason, logged', async () => {
    const u = await makeUser('drv-escuse');
    await enableDrive(u.id);
    ESC = (await escrowWrap()).data;
    await keys(u.cookie, { set: [{ kind: 'escrow', ref: 'escrow', data: ESC }, { kind: 'pw', ref: 'pw', data: W() }], escrowPin: enc(40), kcv: KCV });
    const path = `/api/private/admin/drive/escrow/${u.id}`;
    expect((await fetchJson(path, { method: 'POST', cookie: u.cookie, body: { reason: 'curious' } })).status).toBe(403);
    expect((await fetchJson(path, { method: 'POST', cookie: oc, body: {} })).status).toBe(400);
    expect((await fetchJson(`/api/private/admin/drive/escrow/${PUBLIC_ID}`, { method: 'POST', cookie: oc, body: { reason: 'nope' } })).status).toBe(404);
    const r = await fetchJson(path, { method: 'POST', cookie: oc, headers: intent, body: { reason: 'password reset requested by the user' } });
    expect(r.status).toBe(200);
    const body = await r.json();
    // Only the escrow wrap, and the number of wraps (R5-I3): never the user's own wraps.
    expect(body).toEqual({ wrap: { kind: 'escrow', ref: 'escrow', data: ESC }, wraps: 2 });
    const audit = (await (await fetchJson(`/api/private/admin/audit?user=${u.id}`, { cookie: oc })).json()).rows;
    const row = audit.find((x) => x.action === 'drive.escrow_used');
    expect(row.detail).toContain('password reset requested by the user');
    // Not in the user's own log (a direct admin action).
    const mine = (await (await fetchJson('/api/private/me/activity', { cookie: u.cookie })).json()).rows;
    expect(mine.some((x) => x.action === 'drive.escrow_used')).toBe(false);
    // A user without an escrow wrap: null.
    const v = await makeUser('drv-escnone');
    expect((await (await fetchJson(`/api/private/admin/drive/escrow/${v.id}`, { method: 'POST', cookie: oc, body: { reason: 'check' } })).json()).wrap).toBeNull();
    // While impersonating, the admin surface (escrow included) is closed.
    const ic = cookieOf(await fetchJson(`/api/private/admin/users/${u.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent }));
    expect((await fetchJson(path, { method: 'POST', cookie: ic, body: { reason: 'imp' } })).status).toBe(403);
  });

  it('after a password reset the owner writes the user’s new pw wrap — only that, logged', async () => {
    const u = await makeUser('drv-reset');
    await enableDrive(u.id);
    ESC = (await escrowWrap()).data;
    expect((await keys(u.cookie, { driveSalt: salt16(), set: [{ kind: 'pw', ref: 'pw', data: W() }, { kind: 'escrow', ref: 'escrow', data: ESC }], escrowPin: enc(40), kcv: KCV })).status).toBe(200);
    const put = (body, cookie = oc, id = u.id) => fetchJson(`/api/private/admin/drive/keys/${id}`, { method: 'PUT', cookie, headers: intent, body });
    const salt = salt16();
    expect((await put({ driveSalt: salt, set: [{ kind: 'pw', ref: 'pw', data: W(9) }] }, u.cookie)).status).toBe(403); // owner only
    expect((await put({ driveSalt: salt, set: [{ kind: 'pw', ref: 'pw', data: W(9) }] }, oc, (await (await fetchJson('/api/private/me', { cookie: oc })).json()).user.id)).status).toBe(400); // not for the owner's own
    expect((await fetchJson(`/api/private/admin/users/${u.id}/password`, { method: 'POST', cookie: oc, body: { salt: salt16(), t: 3, proof: proofFor('new-pass-1') } })).status).toBe(200);
    expect((await put({ driveSalt: salt, set: [{ kind: 'escrow', ref: 'escrow', data: ESC }] })).status).toBe(400); // pw only
    expect((await put({ driveSalt: salt, set: [{ kind: 'pw', ref: 'pw', data: W(9) }], remove: [{ kind: 'escrow', ref: 'escrow' }] })).status).toBe(400); // nothing removed
    expect((await put({ set: [{ kind: 'pw', ref: 'pw', data: W(9) }] })).status).toBe(400); // the salt goes with it
    expect((await put({ driveSalt: salt, set: [{ kind: 'pw', ref: 'pw', data: W(9) }] }, oc, PUBLIC_ID)).status).toBe(404);
    expect((await (await put({ driveSalt: salt, set: [{ kind: 'pw', ref: 'pw', data: W(9) }] })).json()).error).toBe('kcv_required'); // only as a wrap of the Drive's key
    expect((await put({ driveSalt: salt, set: [{ kind: 'pw', ref: 'pw', data: W(9) }], kcv: KCV })).status).toBe(200);
    expect((await (await put({ driveSalt: salt, set: [{ kind: 'pw', ref: 'pw', data: W(9) }], kcv: KCV.replace(/^./, KCV[0] === 'A' ? 'B' : 'A') })).json()).error).toBe('kcv_mismatch');
    const s = await driveOf(u.id).summary(u.id);
    expect(s.driveSalt).toBe(salt);
    expect(s.wraps).toEqual([{ kind: 'escrow', ref: 'escrow', data: ESC }, { kind: 'pw', ref: 'pw', data: W(9) }]);
    const audit = (await (await fetchJson(`/api/private/admin/audit?user=${u.id}`, { cookie: oc })).json()).rows;
    expect(audit.some((x) => x.action === 'drive.pw_rewrapped')).toBe(true);
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
    expect((await fetchJson(`/api/private/drive/nodes/${fA.id}`, { method: 'PATCH', cookie: b.cookie, body: { name: enc() } })).status).toBe(404);
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
