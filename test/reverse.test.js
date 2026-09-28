// reverse.test.js — reverse shares ("Receive files", docs/REVERSE.md) in
// workerd: the role options and migration 14, creating one (validation, the
// role's limits), every uploader route (link proof, password gate and its
// Guard accounting and log, the human check, sessions, files, chunks,
// finalize, cancel, done), the share's limits and the Drive's capacity, the
// received files (hidden from the tree until taken in; the take-in, sealed
// under the user's KEK and checked), expiry, revoke, the admin lock, deleting
// the folder, the pending-upload purge, My shares / Admin → Shares, the
// uploader page's headers, the link keys (sealed under the KEK, at rest under
// the field layer), and a full round trip with the real client crypto
// (uploader encrypts, user unwraps and takes in).
import { env, SELF, runDurableObjectAlarm, runInDurableObject, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import worker from '../src/index.js';
import { owner, makeUser, fetchJson, intent, freshIp, ORIGIN, proofFor, USER_PW, cookieOf } from './helpers.js';
import { enableDrive, driveLimits, mkdir, uploadFile, node, drive, sealed, openStored } from './drive-helpers.js';
import { SCHEMA_VERSION, PUBLIC_ID } from '../src/directory-do.js';
import { setSiteverify } from '../src/lib/turnstile.js';
import { CSP, TURNSTILE_CSP, API_CSP } from '../src/lib/http.js';
import { invalidateGuardCaches } from '../src/lib/guard.js';
import { driveChunkSize } from '../src/drive-do.js';
import {
  createReverseKey, linkProof,
  sealNote, openNote, sealUpload, openUpload, newReverseId, newNodeId, fragmentOf,
} from '../public/js/reversekeys.js';
import { isAtRest } from '../public/js/drivekeys.js';
import { randomBytes, utf8, fromUtf8, b64urlFromBytes } from '../public/js/bytes.js';
import { CHUNK, decryptChunk, importFileKey } from '../public/js/files.js';
import {
  dirStub, driveOf, errorOf, receiver, newReverse, rv, openLink, begin, grantOf, putChunk, reserve, send, received, overhead, ownSealed,
  openLinkPriv, takeInAny,
} from './reverse-helpers.js';

let oc;
beforeAll(async () => { oc = await owner(); });

/** A received file taken in as the user's browser does: its name, metadata and DEK (the uploader's file key) sealed under the KEK. */
async function takeIn(cookie, it, got, parent, { name = got.path.split('/').pop() } = {}) {
  const f = await sealed(cookie, 'file', { name: utf8(name), meta: utf8(JSON.stringify({ type: got.type, mtime: got.mtime, size: it.size })), dek: got.fk });
  return fetchJson(`/api/private/drive/received/${it.id}`, { method: 'POST', cookie, headers: intent, body: { parent, name: f.name, meta: f.meta, dek: f.dek, ks: f.ks, mek: f.mek } });
}
afterEach(() => vi.useRealTimers());

const audit = async (subject) => (await (await fetchJson(`/api/private/admin/audit?user=${subject}`, { cookie: oc })).json()).rows;

describe('role options and migration 14', () => {
  it('reverse shares are off by default, need the Drive too, and join the Default role', async () => {
    expect(SCHEMA_VERSION).toBe(16); // 15: CAPTCHA on shares (captcha.test.js); 16: the Drive key model v2 (drive-keys.test.js)
    expect(await dirStub().schemaVersion()).toBe(16);
    const rows = await runInDurableObject(dirStub(), (inst, state) => state.storage.sql.exec("SELECT key, value FROM limits WHERE user_id = '' AND channel = 'all' AND key LIKE 'reverse%' ORDER BY key").toArray());
    expect(rows).toEqual([
      // Migration 15: the reverse-share CAPTCHA (required, as every link had it before).
      { key: 'reverseCaptcha', value: '"require"' },
      { key: 'reverseCaptchaDefault', value: '"on"' },
      { key: 'reverseEnabled', value: 'false' },
      { key: 'reverseMaxActive', value: '10' },
      { key: 'reverseMaxBytes', value: String(1024 ** 3) },
    ]);
    const u = await makeUser('rev-off');
    const me = async () => (await (await fetchJson('/api/private/me', { cookie: u.cookie })).json()).caps.reverseEnabled;
    expect(await me()).toBe(false);
    // The Drive alone is not enough.
    await enableDrive(u.id);
    expect(await me()).toBe(false);
    let r = await newReverse(u.cookie);
    expect(r.res.status).toBe(403);
    expect(await errorOf(r.res)).toBe('reverse_disabled');
    // reverseEnabled without the Drive: the Drive routes are closed anyway.
    await driveLimits(u.id, { driveEnabled: false, reverseEnabled: true });
    expect(await me()).toBe(false);
    r = await newReverse(u.cookie);
    expect(r.res.status).toBe(403);
    expect(await errorOf(r.res)).toBe('drive_disabled');
    await driveLimits(u.id, { driveEnabled: true });
    expect(await me()).toBe(true);
    // The Drive needs no set-up: the link's key is sealed under the KEK the server hands the session.
    expect((await newReverse(u.cookie)).res.status).toBe(201);
    // The owner: allowed; the public account: the options cannot be set.
    expect((await (await fetchJson('/api/private/me', { cookie: oc })).json()).caps.reverseEnabled).toBe(true);
    const pub = await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: PUBLIC_ID, channel: 'all', patch: { reverseEnabled: true } } });
    expect(pub.status).toBe(400);
  });
});

describe('creating a reverse share', () => {
  it('validates what the browser sends and records a "reverse" row in My shares', async () => {
    const u = await receiver('rev-create');
    const { id: fileId } = await uploadFile(u.cookie, 'root', 10);
    const { id: dirId } = await mkdir(u.cookie);
    const bad = [
      { id: 'nope' }, { folder: 'x' }, { priv: 'x' }, { mek: 'x' }, { mek: undefined }, { priv: { iv: 'A'.repeat(16), ct: 'B'.repeat(80) } }, { lh: 'short' }, { expire: 'forever' }, { maxFiles: 0 }, { maxFiles: 10001 },
      { maxBytes: -1 }, { maxFileBytes: 1.5 }, { types: { mode: 'allow', rules: [] } }, { types: { mode: 'allow', rules: ['exe'] } },
      { types: { mode: 'weird', rules: ['ext:pdf'] } }, { password: { salt: 'x', t: 3, ph: 'y' } }, { note: { iv: 'x', ct: 'plain text' } }, { note: 42 },
    ];
    for (const b of bad) {
      const r = await newReverse(u.cookie, b);
      expect(r.res.status, JSON.stringify(b)).toBe(400);
    }
    expect((await newReverse(u.cookie, { folder: newNodeId() })).res.status).toBe(404);
    const onFile = await newReverse(u.cookie, { folder: fileId });
    expect(onFile.res.status).toBe(400);
    expect(await errorOf(onFile.res)).toBe('not_a_folder');
    const ok = await newReverse(u.cookie, { folder: dirId, label: 'Tax docs', maxFiles: 5, types: { mode: 'allow', rules: ['ext:pdf', 'ext:PDF'] } });
    expect(ok.res.status).toBe(201);
    expect(await ok.res.json()).toMatchObject({ id: ok.id });
    const again = await newReverse(u.cookie, { id: ok.id });
    expect(again.res.status).toBe(409);
    // My shares: kind "reverse", what it received so far.
    const mine = await (await fetchJson('/api/private/shares', { cookie: u.cookie })).json();
    const row = mine.rows.find((x) => x.id === ok.id);
    expect(row).toMatchObject({ kind: 'reverse', label: 'Tax docs', status: 'active', views_total: null, received: { files: 0, bytes: 0 } });
    // The Drive's own list (this folder's), with the sealed key the user's browser opens.
    const list = await (await fetchJson(`/api/private/drive/reverse?folder=${dirId}`, { cookie: u.cookie })).json();
    expect(list.reverse).toHaveLength(1);
    const x = list.reverse[0];
    expect(x).toMatchObject({ id: ok.id, folder: dirId, label: 'Tax docs', status: 'active', password: false, note: false, maxFiles: 5, maxBytes: 1024 ** 3, types: { mode: 'allow', rules: ['ext:pdf'] }, files: 0, bytes: 0 });
    expect(x.mek).toBe(ok.body.mek);
    const opened = await openLinkPriv(u.cookie, ok.id, x.priv, x.mek);
    expect(fragmentOf(opened.pub)).toBe(fragmentOf(ok.pub)); // the link can be rebuilt
    await expect(openLinkPriv(u.cookie, newReverseId(), x.priv, x.mek)).rejects.toThrow(); // bound to its id
    // Stored at rest under the field layer: the Drive object holds no {iv, ct} of it.
    const stored = await runInDurableObject(driveOf(u.id), (inst, state) => state.storage.sql.exec('SELECT priv, mek FROM reverse WHERE id = ?', ok.id).one());
    expect(isAtRest(stored.priv)).toBe(true);
    expect(stored.mek).toBe(x.mek);
    expect((await (await fetchJson('/api/private/drive/reverse', { cookie: u.cookie })).json()).reverse.length).toBe(1);
    // Logged as a share creation (with the CAPTCHA: the Default role requires it for reverse shares).
    expect((await audit(u.id)).some((e) => e.action === 'share.created' && e.detail === `id=${ok.id} kind=reverse captcha`)).toBe(true);
  });

  it('obeys the role: expiry, bytes per share, active shares at once; session only, CSRF guards', async () => {
    const u = await receiver('rev-role', { reverseMaxActive: 2, reverseMaxBytes: 1000, maxExpireSec: 3600, apiEnabled: true });
    let r = await newReverse(u.cookie, { expire: '2h' });
    expect(r.res.status).toBe(403);
    expect(await errorOf(r.res)).toBe('expiry_too_long');
    r = await newReverse(u.cookie, { expire: '1h', maxBytes: 1001 });
    expect(r.res.status).toBe(403);
    expect(await errorOf(r.res)).toBe('reverse_too_large');
    const a = await newReverse(u.cookie, { expire: '1h' });
    expect(a.res.status).toBe(201);
    // No byte limit asked for: the role's applies.
    expect((await (await fetchJson('/api/private/drive/reverse', { cookie: u.cookie })).json()).reverse[0].maxBytes).toBe(1000);
    expect((await newReverse(u.cookie, { expire: '1h' })).res.status).toBe(201);
    r = await newReverse(u.cookie, { expire: '1h' });
    expect(r.res.status).toBe(409);
    expect(await errorOf(r.res)).toBe('too_many_reverse');
    // A revoked one no longer counts.
    expect((await fetchJson(`/api/private/shares/${a.id}/revoke`, { method: 'POST', cookie: u.cookie, headers: intent })).status).toBe(200);
    expect((await newReverse(u.cookie, { expire: '1h' })).res.status).toBe(201);
    // API keys never reach the Drive; cross-site and intent-less calls are refused.
    const key = (await (await fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body: { current: proofFor(USER_PW), name: 'k' } })).json()).key;
    const byKey = await fetchJson('/api/private/drive/reverse', { headers: { authorization: `Bearer ${key}` } });
    expect(byKey.status).toBe(403);
    // A key with "read" and "manage" lists, extends and revokes reverse shares like any share (it cannot create one).
    const mk = (await (await fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body: { current: proofFor(USER_PW), name: 'm', scopes: ['read', 'manage'] } })).json()).key;
    const auth = { authorization: `Bearer ${mk}` };
    const listed = await (await fetchJson('/api/private/shares', { headers: auth })).json();
    expect(listed.rows.filter((x) => x.kind === 'reverse').length).toBe(3); // one revoked, two active
    const b = listed.rows.find((x) => x.kind === 'reverse' && x.status === 'active');
    expect(b.received).toEqual({ files: 0, bytes: 0 });
    const ext = await fetchJson(`/api/private/shares/${b.id}`, { method: 'PATCH', headers: auth, body: { expires: b.expires + 60 } });
    expect([ext.status, await errorOf(ext)]).toEqual([403, 'expiry_too_long']); // the role's 1 h applies to the key too
    expect((await fetchJson(`/api/private/shares/${b.id}`, { method: 'PATCH', headers: auth, body: { label: 'by key' } })).status).toBe(200);
    expect((await fetchJson(`/api/private/shares/${b.id}/revoke`, { method: 'POST', headers: { ...auth, ...intent } })).status).toBe(200);
    expect((await fetchJson('/api/private/drive/reverse', { method: 'POST', headers: auth, body: {} })).status).toBe(403);
    const cross = await fetchJson('/api/private/drive/reverse', { method: 'POST', cookie: u.cookie, body: {}, headers: { ...intent, 'sec-fetch-site': 'cross-site' } });
    expect(cross.status).toBe(403);
    expect((await fetchJson('/api/private/drive/reverse')).status).toBe(401);
  });
});

describe('the uploader', () => {
  it('a full round trip: the uploader encrypts, the user unwraps and re-wraps; the server never sees a name', async () => {
    const u = await receiver('rev-trip');
    const { id: folder } = await mkdir(u.cookie);
    const r = await newReverse(u.cookie, { folder, note: 'Please send the contract.' });
    const ip = freshIp();
    const head = await openLink(r, ip);
    expect(head.status).toBe(200);
    const h = await head.json();
    expect(h.password).toBeNull();
    expect(h.limits).toMatchObject({ maxFiles: null, maxBytes: 1024 ** 3, filesLeft: null, bytesLeft: 1024 ** 3, types: null });
    expect(await openNote(r.pub, r.id, h.note)).toBe('Please send the contract.');
    const grant = await grantOf(r, { ip });
    const content = new Uint8Array(CHUNK + 5000).map((_, i) => (i * 7) & 0xff); // two chunks
    const f1 = await send(r, grant, { path: 'contract.pdf', bytes: content, type: 'application/pdf', ip });
    const f2 = await send(r, grant, { path: 'scans/page 1.png', bytes: utf8('png!'), type: 'image/png', ip });
    const done = await rv(r.id, '/done', { headers: { 'x-reverse-grant': grant }, ip });
    expect(await done.json()).toEqual({ files: 2, bytes: content.length + 4 });
    // The grant is spent.
    expect((await rv(r.id, '/done', { headers: { 'x-reverse-grant': grant }, ip })).status).toBe(403);
    // Logged: count and size only.
    const log = await audit(u.id);
    expect(log.some((e) => e.action === 'reverse.received' && e.detail === `id=${r.id} files=2 bytes=${content.length + 4}`)).toBe(true);
    // Until re-wrapped: counted, not in the tree, not shareable, not downloadable.
    const st = await drive(u.cookie);
    expect(st.received).toBe(2);
    const extra = await overhead(u.id);
    expect(extra).toBeGreaterThan(2 * 300); // two sealed paths, metadata and wraps
    expect(extra).toBeLessThan(2 * 2700);
    expect(st.used).toBe(content.length + 4 + extra + await ownSealed(u.id));
    expect((await (await node(u.cookie, folder)).json()).children).toEqual([]);
    expect((await node(u.cookie, f1.node)).status).toBe(404);
    expect((await fetchJson(`/api/private/drive/files/${f1.node}/chunk/0`, { cookie: u.cookie })).status).toBe(404);
    // The received files, with the share's sealed key.
    const rec = await received(u.cookie);
    expect(rec.items.map((i) => i.id).sort()).toEqual([f1.node, f2.node].sort());
    expect(rec.keys).toHaveLength(1);
    const { privateKey } = await openLinkPriv(u.cookie, r.id, rec.keys[0].priv, rec.keys[0].mek);
    const it = rec.items.find((i) => i.id === f1.node);
    expect(it.fk.kind).toBe('rs');
    expect(JSON.stringify(rec)).not.toContain('contract');
    const got = await openUpload(privateKey, r.id, it);
    expect(got).toMatchObject({ path: 'contract.pdf', type: 'application/pdf', size: content.length });
    // The received items are stored at rest under the field layer (names, metadata and wraps).
    const rows = await runInDurableObject(driveOf(u.id), (inst, state) => state.storage.sql.exec('SELECT name, meta, fk FROM nodes WHERE rs IS NOT NULL').toArray());
    for (const x of rows) for (const v of [x.name, x.meta, x.fk]) expect(isAtRest(v)).toBe(true);
    // Taken in, sealed under the user's KEK like any Drive file (checked); the content is untouched.
    const bad = await fetchJson(`/api/private/drive/received/${it.id}`, { method: 'POST', cookie: u.cookie, headers: intent, body: { parent: folder, name: it.name, meta: it.meta, dek: { iv: 'A'.repeat(16), ct: 'B'.repeat(64) }, ks: 'C'.repeat(43), mek: rec.keys[0].mek } });
    expect([bad.status, await errorOf(bad)]).toEqual([400, 'bad_seal']);
    const acc = await takeIn(u.cookie, it, got, folder, { name: 'contract.pdf' });
    expect(acc.status).toBe(200);
    // Taken in: the other received file's sealed fields, and the Drive's own items' (the taken-in file now among them).
    const left = await overhead(u.id);
    expect(left).toBeGreaterThan(0);
    expect(left).toBeLessThan(extra);
    expect((await drive(u.cookie)).used).toBe(content.length + 4 + left + await ownSealed(u.id));
    const kids = (await (await node(u.cookie, folder)).json()).children;
    expect(kids.map((k) => k.id)).toEqual([f1.node]);
    const mine = await openStored(u.cookie, kids[0]);
    expect(fromUtf8(mine.name)).toBe('contract.pdf');
    const key = await importFileKey(b64urlFromBytes(mine.dek));
    const plain = [];
    for (let i = 0; i < kids[0].chunks; i++) {
      const c = new Uint8Array(await (await fetchJson(`/api/private/drive/files/${it.id}/chunk/${i}`, { cookie: u.cookie })).arrayBuffer());
      plain.push(await decryptChunk(key, i, kids[0].chunks, c));
    }
    expect(Buffer.concat(plain).equals(Buffer.from(content))).toBe(true);
    // Accepting twice, or an ordinary file: refused.
    expect((await takeInAny(u.cookie, it.id, folder)).status).toBe(409);
    expect((await received(u.cookie)).items.map((i) => i.id)).toEqual([f2.node]);
    // Another user cannot see or take them.
    const v = await receiver('rev-trip-other');
    expect((await received(v.cookie)).items).toEqual([]);
    expect((await takeInAny(v.cookie, f2.node, 'root')).status).toBe(409);
    // The received file can be discarded like any item.
    expect((await fetchJson(`/api/private/drive/nodes/${f2.node}`, { method: 'DELETE', cookie: u.cookie, headers: intent })).status).toBe(200);
    expect((await drive(u.cookie)).received).toBe(0);
  });

  it('the link proof: unknown ids and wrong keys are refused and counted by the Guard; cross-site is refused first', async () => {
    const u = await receiver('rev-link');
    const r = await newReverse(u.cookie);
    const ip = freshIp();
    const other = await createReverseKey();
    const wrong = await openLink(r, ip, other.pub);
    expect(wrong.status).toBe(403);
    expect(await errorOf(wrong)).toBe('bad_link');
    expect((await begin(r, { ip, pub: other.pub })).status).toBe(403);
    expect((await rv(newReverseId(), '/open', { headers: { 'x-link-proof': await linkProof(r.pub) }, ip })).status).toBe(404);
    expect((await rv('rnope', '/open', { ip })).status).toBe(404);
    expect((await rv(r.id, '/open', { ip })).status).toBe(400); // no proof header
    expect((await rv(r.id, '/open', { ip, headers: { 'x-secbin-intent': '' } })).status).toBe(400);
    const cross = await rv(r.id, '/open', { ip, headers: { 'x-link-proof': await linkProof(r.pub), 'sec-fetch-site': 'cross-site' } });
    expect(cross.status).toBe(403);
    expect(await errorOf(cross)).toBe('cross_site');
    // A bad grant is a guess too.
    const g = await reserve(r, b64urlFromBytes(randomBytes(32)), { ip });
    expect(g.res.status).toBe(403);
    expect(await errorOf(g.res)).toBe('bad_grant');
    // Enough guesses block the network (guard.invalid.max).
    expect((await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'guard.invalid.max': 6 } })).status).toBe(200);
    invalidateGuardCaches();
    let last;
    for (let i = 0; i < 6; i++) last = await openLink(r, ip, other.pub);
    expect(last.status).toBe(429);
    expect((await openLink(r, ip)).status).toBe(429); // even with the right key, for a while
    expect((await openLink(r, freshIp())).status).toBe(200);
    await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'guard.invalid.max': 60 } });
    invalidateGuardCaches();
  });

  it('the password gates the uploader only: needed, wrong ones refused, counted and logged', async () => {
    const u = await receiver('rev-pw');
    const r = await newReverse(u.cookie, { password: 'open sesame' });
    const ip = freshIp();
    const h = await (await openLink(r, ip)).json();
    expect(h.password).toMatchObject({ t: 3 });
    expect(h.password.salt).toMatch(/^[A-Za-z0-9_-]{22}$/);
    const none = await begin(r, { ip });
    expect(none.status).toBe(401);
    expect(await none.json()).toMatchObject({ error: 'password_required', salt: h.password.salt, t: 3 });
    const wrong = await begin(r, { ip, password: 'open sesame!' });
    expect(wrong.status).toBe(403);
    expect(await errorOf(wrong)).toBe('bad_password');
    expect((await begin(r, { ip, password: 'nope' })).status).toBe(403);
    // Logged once a minute at most.
    const bad = (await audit(u.id)).filter((e) => e.action === 'reverse.bad_password');
    expect(bad).toHaveLength(1);
    expect(bad[0].detail).toBe(`id=${r.id}`);
    // The right one opens a session; what is uploaded is still encrypted to the user's key only.
    const grant = await grantOf(r, { ip, password: 'open sesame' });
    const f = await send(r, grant, { ip });
    const rec = await received(u.cookie);
    const { privateKey } = await openLinkPriv(u.cookie, r.id, rec.keys[0].priv, rec.keys[0].mek);
    expect((await openUpload(privateKey, r.id, rec.items[0])).path).toBe('a.txt');
    expect(rec.items[0].id).toBe(f.node);
    // The server stores only the proof's hash, not the password or the proof.
    const row = await runInDurableObject(driveOf(u.id), (inst, state) => state.storage.sql.exec('SELECT ph, salt, t FROM reverse WHERE id = ?', r.id).one());
    expect(row.ph).toBe(r.body.password.ph);
    expect(JSON.stringify(row)).not.toContain('sesame');
  });

  it('limits: files, bytes, file size, declared types, the Drive capacity and largest file; cancel gives a reservation back', async () => {
    const u = await receiver('rev-lim', { driveMaxBytes: 1000000, driveMaxFileBytes: 60 });
    const ip = freshIp();
    // A file's sealed path, metadata and wrap count towards the link's bytes too:
    // measure them once (the same for every file below: same path, a 2-digit size).
    const probe = await newReverse(u.cookie);
    const pg = await grantOf(probe, { ip });
    const pf = await reserve(probe, pg, { ip });
    const P = await runInDurableObject(driveOf(u.id), (inst, state) => state.storage.sql.exec('SELECT sealed FROM reverse WHERE id = ?', probe.id).one().sealed);
    expect(P).toBeGreaterThan(300);
    expect((await rv(probe.id, `/files/${pf.node}`, { method: 'DELETE', headers: { 'x-reverse-grant': pg, 'x-upload-token': pf.data.uploadToken }, ip })).status).toBe(200);
    const r = await newReverse(u.cookie, { maxFiles: 2, maxBytes: 90 + 2 * P, maxFileBytes: 50, types: { mode: 'allow', rules: ['ext:txt'] } });
    const grant = await grantOf(r, { ip });
    const txt = [{ ext: 'txt', mime: 'text/plain' }];
    let f = await reserve(r, grant, { size: 51, types: txt, ip });
    expect(f.res.status).toBe(413);
    expect(await errorOf(f.res)).toBe('file_too_large');
    f = await reserve(r, grant, { ip });
    expect(f.res.status).toBe(400);
    expect(await errorOf(f.res)).toBe('declaration_required');
    f = await reserve(r, grant, { types: [{ ext: 'exe', mime: 'application/x-msdownload' }], ip });
    expect(f.res.status).toBe(403);
    expect(await errorOf(f.res)).toBe('file_type_not_allowed');
    const a = await reserve(r, grant, { size: 50, types: txt, ip });
    expect(a.res.status).toBe(201);
    f = await reserve(r, grant, { size: 41, types: txt, ip });
    expect(f.res.status).toBe(413);
    expect(await errorOf(f.res)).toBe('share_full');
    // Cancelling the first gives its 50 bytes and its file back.
    const cancel = await rv(r.id, `/files/${a.node}`, { method: 'DELETE', headers: { 'x-reverse-grant': grant, 'x-upload-token': a.data.uploadToken }, ip });
    expect(cancel.status).toBe(200);
    expect((await (await openLink(r, ip)).json()).limits).toMatchObject({ filesLeft: 2, bytesLeft: 90 + 2 * P });
    await send(r, grant, { bytes: new Uint8Array(40), types: txt, ip });
    await send(r, grant, { bytes: new Uint8Array(40), types: txt, ip });
    f = await reserve(r, grant, { size: 1, types: txt, ip });
    expect(f.res.status).toBe(409);
    expect(await errorOf(f.res)).toBe('too_many_files');
    expect((await (await openLink(r, ip)).json()).limits).toMatchObject({ filesLeft: 0, bytesLeft: 10 });
    // The Drive's own limits apply too: its largest file (60), and its capacity, where a
    // received file's sealed path, metadata and wrap count as well as its content.
    const per = (await overhead(u.id)) / 2; // two received files, same path and metadata lengths
    expect(Number.isInteger(per)).toBe(true);
    const used = (await drive(u.cookie)).used;
    expect(used).toBe(80 + 2 * per);
    await driveLimits(u.id, { driveMaxBytes: used + per + 20 });
    const r2 = await newReverse(u.cookie);
    const g2 = await grantOf(r2, { ip });
    f = await reserve(r2, g2, { size: 61, ip });
    expect(f.res.status).toBe(413);
    expect(await errorOf(f.res)).toBe('file_too_large');
    f = await reserve(r2, g2, { size: 21, ip });
    expect(f.res.status).toBe(413);
    expect(await errorOf(f.res)).toBe('drive_full');
    // Chunks: exact sizes, the right token, this share's files only.
    const small = await reserve(r2, g2, { bytes: new Uint8Array(10), ip });
    expect(small.res.status).toBe(201);
    // No room left for even an empty file's sealed fields.
    f = await reserve(r2, g2, { size: 0, ip });
    expect(f.res.status).toBe(413);
    expect(await errorOf(f.res)).toBe('drive_full');
    expect((await putChunk(r2.id, small.node, 0, new Uint8Array(27), small.data.uploadToken, ip)).status).toBe(400);
    expect((await putChunk(r2.id, small.node, 0, new Uint8Array(26), b64urlFromBytes(randomBytes(32)), ip)).status).toBe(403);
    expect((await putChunk(r.id, small.node, 0, new Uint8Array(26), small.data.uploadToken, ip)).status).toBe(410);
    const early = await rv(r2.id, `/files/${small.node}/finalize`, { headers: { 'x-reverse-grant': g2, 'x-upload-token': small.data.uploadToken }, ip });
    expect(early.status).toBe(409);
    expect((await putChunk(r2.id, small.node, 0, new Uint8Array(26), small.data.uploadToken, ip)).status).toBe(200);
    expect((await rv(r2.id, `/files/${small.node}/finalize`, { headers: { 'x-reverse-grant': g2, 'x-upload-token': small.data.uploadToken }, ip })).status).toBe(200);
    // A node id already in use is refused.
    const dup = await rv(r2.id, '/files', { headers: { 'x-reverse-grant': g2 }, body: { ...(await sealUpload(r2.pub, r2.id, small.node, randomBytes(32), { path: 'x', type: 'text/plain', mtime: 0, size: 1 })), id: small.node, size: 1 }, ip });
    expect(dup.status).toBe(409);
  });

  it('the human check, when configured, is needed to start a session (the page gets its CSP)', async () => {
    const u = await receiver('rev-ts');
    const r = await newReverse(u.cookie);
    const TS_ENV = { ...env, TURNSTILE_SITEKEY: '0x4AAAAAAAtestsitekey', TURNSTILE_SECRET: '0x4AAAAAAAtestsecretvalue' };
    const tsFetch = async (path, headers = {}) => {
      const ctx = createExecutionContext();
      const res = await worker.fetch(new Request(`${ORIGIN}${path}`, { method: path.startsWith('/api/') ? 'POST' : 'GET', headers }), TS_ENV, ctx);
      await waitOnExecutionContext(ctx);
      return res;
    };
    const prev = setSiteverify(async (form) => {
      const m = /^ok:(.+)$/.exec(form.get('response'));
      return Response.json(m ? { success: true, hostname: new URL(ORIGIN).hostname, action: m[1] } : { success: false });
    });
    try {
      const ip = freshIp();
      const base = { ...intent, 'x-link-proof': await linkProof(r.pub), 'cf-connecting-ip': ip };
      let res = await tsFetch(`/api/reverse/${r.id}/begin`, base);
      expect(res.status).toBe(403);
      expect(await errorOf(res)).toBe('captcha_required'); // the link has the CAPTCHA (the Default role requires it)
      res = await tsFetch(`/api/reverse/${r.id}/begin`, { ...base, 'x-secbin-turnstile': 'ok:login' });
      expect(await errorOf(res)).toBe('turnstile_failed'); // a token for another form
      res = await tsFetch(`/api/reverse/${r.id}/begin`, { ...base, 'x-secbin-turnstile': 'ok:reverse-upload' });
      expect(res.status).toBe(200);
      expect(typeof (await res.json()).grant).toBe('string');
      // Opening the link (read only) needs no token.
      expect((await tsFetch(`/api/reverse/${r.id}/open`, base)).status).toBe(200);
      // The uploader page keeps the strict policy even with Turnstile on (the
      // link's key is in its #fragment); the widget is on the check page
      // (/r/<id>?check: Turnstile's CSP, no COEP), which has no uploader code. Never stored.
      const on = await tsFetch(`/r/${r.id}`);
      expect(on.status).toBe(200);
      expect(on.headers.get('content-security-policy')).toBe(CSP);
      expect(on.headers.get('cross-origin-embedder-policy')).toBe('require-corp');
      expect(on.headers.get('cache-control')).toBe('no-store');
      expect(await on.text()).toContain('/js/reverse.js');
      const check = await tsFetch(`/r/${r.id}?check`);
      expect(check.status).toBe(200);
      // The Turnstile policy with no workers at all (no service worker registration from the check page).
      expect(check.headers.get('content-security-policy')).toBe(TURNSTILE_CSP.replace("worker-src 'self'", "worker-src 'none'"));
      expect(check.headers.get('cross-origin-embedder-policy')).toBeNull();
      expect(check.headers.get('cross-origin-opener-policy')).toBe('same-origin-allow-popups');
      expect(check.headers.get('cache-control')).toBe('no-store');
      const html = await check.text();
      expect(html).toContain('/js/check.js');
      expect(html).not.toContain('/js/reverse.js');
    } finally {
      setSiteverify(prev);
    }
    const off = await SELF.fetch(`${ORIGIN}/r/${r.id}`);
    expect(off.status).toBe(200);
    expect(off.headers.get('content-security-policy')).toBe(CSP);
    expect(off.headers.get('cross-origin-embedder-policy')).toBe('require-corp');
    await off.text();
    for (const p of ['/r/', '/r/nope', '/r/index.html', `/r/${r.id}/x`]) {
      const res = await SELF.fetch(`${ORIGIN}${p}`);
      expect(res.status, p).toBe(404);
      expect(res.headers.get('content-security-policy')).toBe(API_CSP); // plain text: sandboxed, no script at all
      await res.text();
    }
  });
});

describe('ending: revoke, expiry, the admin lock, the folder deleted, the purge', () => {
  it('revoking stops uploads at once (unfinished ones go); files already received stay', async () => {
    const u = await receiver('rev-revoke');
    const r = await newReverse(u.cookie);
    const ip = freshIp();
    const grant = await grantOf(r, { ip });
    await send(r, grant, { ip });
    const half = await reserve(r, grant, { bytes: new Uint8Array(CHUNK + 1), ip });
    expect((await putChunk(r.id, half.node, 0, new Uint8Array(CHUNK + 16), half.data.uploadToken, ip)).status).toBe(200);
    expect((await drive(u.cookie)).used).toBe(11 + CHUNK + 1 + (await overhead(u.id)));
    expect((await fetchJson(`/api/private/shares/${r.id}/revoke`, { method: 'POST', cookie: u.cookie, headers: intent })).status).toBe(200);
    for (const res of [await openLink(r, ip), await begin(r, { ip }), await reserve(r, grant, { ip }).then((x) => x.res),
      await putChunk(r.id, half.node, 1, new Uint8Array(17), half.data.uploadToken, ip)]) {
      expect(res.status).toBe(410);
    }
    // The unfinished upload and its chunk are gone; the finished file stays (and can be taken in).
    expect(await env.FILES.get(`d/${u.id}/${half.node}/0`)).toBeNull();
    expect((await drive(u.cookie)).used).toBe(11 + (await overhead(u.id)));
    expect((await received(u.cookie)).items).toHaveLength(1);
    const row = (await (await fetchJson('/api/private/shares', { cookie: u.cookie })).json()).rows.find((x) => x.id === r.id);
    expect(row).toMatchObject({ status: 'revoked', received: { files: 1, bytes: 11 } });
    expect((await audit(u.id)).some((e) => e.action === 'share.revoked' && e.detail.startsWith(`id=${r.id}`))).toBe(true);
    // A late visitor with the right link is not counted as a guess; a wrong link is.
    await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'guard.invalid.max': 3 } });
    invalidateGuardCaches();
    const late = freshIp();
    for (let i = 0; i < 5; i++) expect((await openLink(r, late)).status).toBe(410);
    const other = await createReverseKey();
    const codes = [];
    for (let i = 0; i < 3; i++) codes.push((await openLink(r, late, other.pub)).status);
    expect(codes).toEqual([403, 403, 429]);
    await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'guard.invalid.max': 60 } });
    invalidateGuardCaches();
  });

  it('expiry stops uploads; My shares can extend it (views cannot be set)', async () => {
    const u = await receiver('rev-exp');
    const r = await newReverse(u.cookie, { expire: '1h' });
    const ip = freshIp();
    expect((await fetchJson(`/api/private/shares/${r.id}`, { method: 'PATCH', cookie: u.cookie, body: { views: 5 } })).status).toBe(400);
    const later = Math.floor(Date.now() / 1000) + 7200;
    expect((await fetchJson(`/api/private/shares/${r.id}`, { method: 'PATCH', cookie: u.cookie, body: { expires: later } })).status).toBe(200);
    expect((await (await openLink(r, ip)).json()).expires).toBe(later);
    vi.useFakeTimers({ now: Date.now() + 7300 * 1000, toFake: ['Date'] });
    expect((await openLink(r, ip)).status).toBe(410);
    expect((await begin(r, { ip })).status).toBe(410);
    vi.useRealTimers();
  });

  it('an admin lock pauses uploads (423); the admin sees, revokes and filters reverse shares', async () => {
    const u = await receiver('rev-admin');
    const r = await newReverse(u.cookie, { label: 'inbox' });
    const ip = freshIp();
    expect((await fetchJson(`/api/private/admin/shares/${r.id}/lock`, { method: 'POST', cookie: oc, body: { locked: true } })).status).toBe(200);
    const locked = await openLink(r, ip);
    expect(locked.status).toBe(423);
    expect((await fetchJson(`/api/private/shares/${r.id}/revoke`, { method: 'POST', cookie: u.cookie, headers: intent })).status).toBe(423);
    expect((await fetchJson(`/api/private/admin/shares/${r.id}/lock`, { method: 'POST', cookie: oc, body: { locked: false } })).status).toBe(200);
    expect((await openLink(r, ip)).status).toBe(200);
    const list = await (await fetchJson(`/api/private/admin/shares?kind=reverse&users=${u.id}`, { cookie: oc })).json();
    expect(list.rows.map((x) => x.id)).toEqual([r.id]);
    expect(list.rows[0]).toMatchObject({ kind: 'reverse', label: 'inbox', received: { files: 0, bytes: 0 } });
    expect((await fetchJson(`/api/private/admin/shares/${r.id}/revoke`, { method: 'POST', cookie: oc, headers: intent })).status).toBe(200);
    expect((await openLink(r, ip)).status).toBe(410);
    expect((await (await fetchJson('/api/private/drive/reverse', { cookie: u.cookie })).json()).reverse[0].status).toBe('revoked');
  });

  it('deleting the folder ends its reverse shares; the role losing the option stops uploads', async () => {
    const u = await receiver('rev-del');
    const { id: folder } = await mkdir(u.cookie);
    const r = await newReverse(u.cookie, { folder });
    const r2 = await newReverse(u.cookie);
    const ip = freshIp();
    expect((await fetchJson(`/api/private/drive/nodes/${folder}`, { method: 'DELETE', cookie: u.cookie, headers: intent })).status).toBe(200);
    expect((await openLink(r, ip)).status).toBe(410);
    const row = (await (await fetchJson('/api/private/shares', { cookie: u.cookie })).json()).rows.find((x) => x.id === r.id);
    expect(row.status).toBe('revoked');
    await driveLimits(u.id, { reverseEnabled: false });
    expect((await openLink(r2, ip)).status).toBe(410);
    await driveLimits(u.id, { reverseEnabled: true });
    expect((await openLink(r2, ip)).status).toBe(200);
  });

  it('pending uploads are purged like Drive uploads (their allowance comes back); a lapsed session is logged', async () => {
    const u = await receiver('rev-purge', { filePendingSec: 600 });
    const r = await newReverse(u.cookie, { maxFiles: 3 });
    const ip = freshIp();
    const grant = await grantOf(r, { ip });
    await send(r, grant, { ip });
    const half = await reserve(r, grant, { bytes: new Uint8Array(100), ip });
    expect((await (await openLink(r, ip)).json()).limits.filesLeft).toBe(1);
    vi.useFakeTimers({ now: Date.now() + 601 * 1000, toFake: ['Date'] });
    await runDurableObjectAlarm(driveOf(u.id));
    vi.useRealTimers();
    expect((await (await openLink(r, ip)).json()).limits.filesLeft).toBe(2);
    expect((await drive(u.cookie)).used).toBe(11 + (await overhead(u.id)));
    const gone = await runInDurableObject(driveOf(u.id), (inst, state) => state.storage.sql.exec('SELECT COUNT(*) AS c FROM nodes WHERE id = ?', half.node).one().c);
    expect(gone).toBe(0);
    // The session lapsed without "done": what it received is logged anyway.
    expect((await audit(u.id)).some((e) => e.action === 'reverse.received' && e.detail === `id=${r.id} files=1 bytes=11`)).toBe(true);
    expect((await rv(r.id, '/done', { headers: { 'x-reverse-grant': grant }, ip })).status).toBe(403);
    // Upload tokens and grants are stored hashed.
    const rows = await runInDurableObject(driveOf(u.id), (inst, state) => [
      ...state.storage.sql.exec('SELECT upload_hash FROM nodes').toArray(), ...state.storage.sql.exec('SELECT hash FROM rsessions').toArray()]);
    expect(JSON.stringify(rows)).not.toContain(grant);
  });
  it('a file still being uploaded keeps its session open: its chunks count as progress', async () => {
    const u = await receiver('rev-slow', { filePendingSec: 600 });
    const r = await newReverse(u.cookie);
    const ip = freshIp();
    const t0 = Date.now();
    const grant = await grantOf(r, { ip });
    const f = await reserve(r, grant, { bytes: new Uint8Array(10), ip });
    expect(f.res.status).toBe(201);
    vi.useFakeTimers({ now: t0 + 500 * 1000, toFake: ['Date'] });
    expect((await putChunk(r.id, f.node, 0, new Uint8Array(26), f.data.uploadToken, ip)).status).toBe(200);
    vi.setSystemTime(t0 + 1000 * 1000); // past the session's first 600 s, within 600 s of the chunk
    const fin = await rv(r.id, `/files/${f.node}/finalize`, { headers: { 'x-reverse-grant': grant, 'x-upload-token': f.data.uploadToken }, ip });
    expect(fin.status).toBe(200);
    expect(await (await rv(r.id, '/done', { headers: { 'x-reverse-grant': grant }, ip })).json()).toEqual({ files: 1, bytes: 10 });
    vi.useRealTimers();
  });
});

describe('isolation and the account', () => {
  it('the owner acting as the user ("Log in as") can do all of it, with no confirmation; the user sees it as their own', async () => {
    const u = await receiver('rev-imp');
    const ic = cookieOf(await fetchJson(`/api/private/admin/users/${u.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent }));
    const { id: folder } = await mkdir(ic);
    const r = await newReverse(ic, { folder, confirm: false, label: 'by the owner' });
    expect(r.res.status).toBe(201);
    // Listed with the sealed key: the tab that holds the user's Drive key rebuilds the link.
    const x = (await (await fetchJson(`/api/private/drive/reverse?folder=${folder}`, { cookie: ic })).json()).reverse[0];
    expect(x).toMatchObject({ id: r.id, label: 'by the owner', status: 'active' });
    expect(fragmentOf((await openLinkPriv(ic, r.id, x.priv, x.mek)).pub)).toBe(fragmentOf(r.pub));
    const ip = freshIp();
    const grant = await grantOf(r, { ip });
    const f = await send(r, grant, { ip });
    expect((await rv(r.id, '/done', { headers: { 'x-reverse-grant': grant }, ip })).status).toBe(200);
    // The received files and their keys; the re-wrap.
    const rec = await received(ic);
    expect(rec.items.map((i) => i.id)).toEqual([f.node]);
    expect(rec.keys.map((k) => k.id)).toEqual([r.id]);
    const { privateKey } = await openLinkPriv(ic, r.id, rec.keys[0].priv, rec.keys[0].mek);
    const acc = await takeIn(ic, rec.items[0], await openUpload(privateKey, r.id, rec.items[0]), folder);
    expect(acc.status).toBe(200);
    expect((await (await node(ic, folder)).json()).children.map((k) => k.id)).toEqual([f.node]);
    // And downloads it (the chunk as stored: the content was never re-encrypted).
    const chunk = await fetchJson(`/api/private/drive/files/${f.node}/chunk/0`, { cookie: ic });
    expect(chunk.status).toBe(200);
    const key = await importFileKey(b64urlFromBytes(f.fk));
    expect(fromUtf8(await decryptChunk(key, 0, 1, new Uint8Array(await chunk.arrayBuffer())))).toBe('hello world');
    // Revoke (My shares).
    expect((await fetchJson(`/api/private/shares/${r.id}/revoke`, { method: 'POST', cookie: ic, headers: intent })).status).toBe(200);
    expect((await openLink(r, ip)).status).toBe(410);
    // The user's own activity shows the actions as theirs; the owner-only audit keeps the real actor.
    const mine = (await (await fetchJson('/api/private/me/activity', { cookie: u.cookie })).json()).rows;
    const log = await audit(u.id);
    for (const [action, detail] of [['share.created', `id=${r.id} kind=reverse`], ['drive.received_taken_in', `id=${r.id} files=1`], ['share.revoked', `id=${r.id}`]]) {
      const own = mine.find((e) => e.action === action && e.detail.startsWith(detail));
      expect(own, action).toBeTruthy();
      expect(Object.keys(own).sort()).toEqual(['action', 'detail', 'id', 'ts']);
      const real = log.find((e) => e.id === own.id);
      expect(real, action).toMatchObject({ imp: 1, adm: 0 });
      expect(real.actor_id).not.toBe(u.id);
    }
    expect(mine.filter((e) => e.detail.includes(r.id)).some((e) => /imperson/i.test(`${e.action} ${e.detail}`))).toBe(false);
  });

  it('the user confirms a new link with the password (or a passkey): none, or a wrong one, is refused', async () => {
    const u = await receiver('rev-step');
    let r = await newReverse(u.cookie, { confirm: false });
    expect(r.res.status).toBe(400);
    expect(await errorOf(r.res)).toBe('reauth_required');
    r = await newReverse(u.cookie, { confirm: false, current: proofFor('not the password') });
    expect(r.res.status).toBe(403);
    expect(await errorOf(r.res)).toBe('wrong_password');
    expect((await (await fetchJson('/api/private/drive/reverse', { cookie: u.cookie })).json()).reverse).toEqual([]);
    expect((await newReverse(u.cookie)).res.status).toBe(201);
  });

  it('a user cannot list, revoke or take in another user\'s reverse shares; deleting the account ends them', async () => {
    const u = await receiver('rev-iso-a');
    const v = await receiver('rev-iso-b');
    const r = await newReverse(u.cookie);
    expect((await (await fetchJson('/api/private/drive/reverse', { cookie: v.cookie })).json()).reverse).toEqual([]);
    expect((await fetchJson(`/api/private/shares/${r.id}/revoke`, { method: 'POST', cookie: v.cookie, headers: intent })).status).toBe(404);
    const ip = freshIp();
    expect((await openLink(r, ip)).status).toBe(200);
    expect((await fetchJson(`/api/private/admin/users/${u.id}`, { method: 'DELETE', cookie: oc, headers: intent })).status).toBe(200);
    expect((await openLink(r, ip)).status).toBe(404);
  });
});

// Keys that must not open what they were not made for.
describe('keys', () => {
  it('a wrap is bound to its share and node; a note to its share', async () => {
    const { pub, privateKey } = await createReverseKey();
    const id = newReverseId();
    const nodeId = newNodeId();
    const fk = randomBytes(32);
    const s = await sealUpload(pub, id, nodeId, fk, { path: 'x/y.txt', type: 'text/plain', mtime: 5, size: 3 });
    const item = { id: nodeId, ...s, fk: { kind: 'rs', data: s.wrap } };
    const got = await openUpload(privateKey, id, item);
    expect(got.path).toBe('x/y.txt');
    expect(Buffer.from(got.fk).equals(Buffer.from(fk))).toBe(true);
    await expect(openUpload(privateKey, newReverseId(), item)).rejects.toThrow();
    await expect(openUpload(privateKey, id, { ...item, id: newNodeId() })).rejects.toThrow();
    const other = await createReverseKey();
    await expect(openUpload(other.privateKey, id, item)).rejects.toThrow();
    const note = await sealNote(pub, id, 'hi');
    expect(await openNote(pub, id, note)).toBe('hi');
    await expect(openNote(pub, newReverseId(), note)).rejects.toThrow();
    // The size of one chunk of a received file is a Drive chunk's.
    expect(driveChunkSize(10, 0)).toBe(26);
  });
});
