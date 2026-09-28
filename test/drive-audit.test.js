// drive-audit.test.js — regression tests for the Drive findings of security
// audit round 2 (each one failed before its fix) and the owner's use of a
// user's Drive while impersonating them (docs/DRIVE.md §3, §6, §9):
//   L-1  a late chunk write never deletes a chunk of a finished file;
//   L-2  an item with 100+ shares still lists them; ended shares leave refs;
//   L-3  sealed names / metadata are capped and count towards the capacity;
//   L-7  deleting an account removes its Drive first, and stays retryable;
//   impersonation: the full Drive with the user's keys (key model v2); each
//   action shows in the user's activity as theirs, the admin audit keeps the
//   real actor.
// (H-1, L-4 and L-5 covered the escrow key pair and the key wraps of the key
// model before v2, removed with them; L-5's wrap hygiene for Drives still
// waiting for their upgrade is in drive-upgrade.test.js.)
import { env, SELF, runInDurableObject, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeAll } from 'vitest';
import worker from '../src/index.js';
import { ORIGIN, owner, makeUser, fetchJson, intent, cookieOf, freshIp, proofHeaders } from './helpers.js';
import { enableDrive, mkdir, createFile, putChunk, finalize, getChunk, uploadFile, del, drive, DIR_BYTES, sealed, driveKeys } from './drive-helpers.js';
import { driveChunkSize } from '../src/drive-do.js';
import { encryptPaste } from '../public/js/crypto.js';
import { b64urlFromBytes, randomBytes, utf8 } from '../public/js/bytes.js';
import { sealName } from '../public/js/drivekeys.js';
import { genId } from '../src/lib/ids.js';

let oc;
beforeAll(async () => { oc = await owner(); });

const driveOf = (uid) => env.DRIVE.get(env.DRIVE.idFromName(`drive:${uid}`));
const dirStub = () => env.DIRECTORY.get(env.DIRECTORY.idFromName('directory'));
const audit = async (uid) => (await (await fetchJson(`/api/private/admin/audit?user=${uid}&limit=500`, { cookie: oc })).json()).rows;
const activity = async (cookie) => (await (await fetchJson('/api/private/me/activity', { cookie })).json()).rows;
const impersonate = async (uid) => cookieOf(await fetchJson(`/api/private/admin/users/${uid}/impersonate`, { method: 'POST', cookie: oc, headers: intent }));
const ownerId = async () => (await (await fetchJson('/api/private/me', { cookie: oc })).json()).user.id;

async function shareOf(cookie, nodes) {
  const manifest = { v: 3, kind: 'refs', entries: nodes.map((id, ref) => ({ path: `f${ref}`, size: 0, type: 'application/octet-stream', mtime: 0, ref, fk: b64urlFromBytes(randomBytes(32)) })), dirs: [] };
  const { body, fragment } = await encryptPaste({ text: JSON.stringify(manifest), fmt: 'files', bar: false, expire: '1h' });
  const res = await fetchJson('/api/private/drive/shares', { method: 'POST', cookie, body: { nodes, views: null, expire: '1h', paste: body } });
  return { res, fragment, ...(res.status === 201 ? await res.json() : {}) };
}

describe('L-1: a chunk write that lands after finalize', () => {
  it('finalize waits for chunk writes in flight, and the late write never removes a chunk of the finished file', async () => {
    const u = await makeUser('aud-race');
    await enableDrive(u.id);
    const size = 1000;
    const f = await createFile(u.cookie, 'root', size);
    const bytes = randomBytes(driveChunkSize(size, 0));
    expect((await putChunk(u.cookie, f.id, 0, bytes, f.uploadToken)).status).toBe(200);
    // Slow R2 writes for this Drive: a retry of chunk 0 is still being written…
    await runInDurableObject(driveOf(u.id), (inst) => {
      const r2 = inst.env.FILES;
      inst.env = { ...inst.env, FILES: { put: async (...a) => { await new Promise((res) => setTimeout(res, 400)); return r2.put(...a); }, delete: (...a) => r2.delete(...a), get: (...a) => r2.get(...a) } };
    });
    const late = putChunk(u.cookie, f.id, 0, bytes, f.uploadToken);
    await new Promise((res) => setTimeout(res, 100));
    // …so finalize answers "busy" instead of finishing under it.
    const early = await finalize(u.cookie, f.id, f.uploadToken);
    expect(early.status).toBe(409);
    expect((await early.json()).error).toBe('busy');
    expect((await late).status).toBe(200);
    expect((await finalize(u.cookie, f.id, f.uploadToken)).status).toBe(200);
    const g = await getChunk(u.cookie, f.id, 0);
    expect(g.status).toBe(200);
    expect(new Uint8Array(await g.arrayBuffer())).toEqual(bytes);
  });

  it('a late write for an upload that was deleted leaves nothing behind', async () => {
    const u = await makeUser('aud-race2');
    await enableDrive(u.id);
    const f = await createFile(u.cookie, 'root', 10);
    await runInDurableObject(driveOf(u.id), (inst) => {
      const r2 = inst.env.FILES;
      inst.env = { ...inst.env, FILES: { put: async (...a) => { await new Promise((res) => setTimeout(res, 300)); return r2.put(...a); }, delete: (...a) => r2.delete(...a), get: (...a) => r2.get(...a) } };
    });
    const late = putChunk(u.cookie, f.id, 0, randomBytes(driveChunkSize(10, 0)), f.uploadToken);
    await new Promise((res) => setTimeout(res, 50));
    expect((await del(u.cookie, f.id)).status).toBe(200);
    expect((await late).status).toBe(410);
    expect(await env.FILES.get(`d/${u.id}/${f.id}/0`)).toBeNull();
  });
});

describe('L-2: many shares of one item', () => {
  it('lists 150 shares of a folder (batched queries), and a share that ends leaves the Drive’s refs', { timeout: 120000 }, async () => {
    const u = await makeUser('aud-refs');
    await enableDrive(u.id);
    const folder = await mkdir(u.cookie);
    const files = [];
    for (let i = 0; i < 3; i++) files.push((await uploadFile(u.cookie, folder.id, 10)).id);
    const N = 150;
    const created = Math.floor(Date.now() / 1000);
    const paste = { v: 2, ct: 'x', wk: 'x', adata: { bar: false }, meta: { expire: '1d' } };
    const ids = [];
    for (let k = 0; k < N; k++) {
      const id = genId('f');
      const fid = files[k % files.length];
      const r = await env.FILESHARE.get(env.FILESHARE.idFromName(id)).initRefs({ id, dth: 'a'.repeat(64), refs: [{ key: `d/${u.id}/${fid}`, chunks: 1, size: 10 }], views: null, expire: '1d', ttl: 86400, paste, acc: {} });
      expect(r.status).toBe('ok');
      ids.push([id, fid]);
    }
    await runInDurableObject(dirStub(), (inst, state) => {
      for (const [id] of ids) state.storage.sql.exec("INSERT INTO shares (id, user_id, kind, label, created, expires, views_total, status) VALUES (?, ?, 'drive', '', ?, ?, NULL, 'active')", id, u.id, created, created + 86400);
    });
    for (const [id, fid] of ids) await driveOf(u.id).addRefs(u.id, id, [fid]);
    const list = await fetchJson(`/api/private/drive/nodes/${folder.id}/shares`, { cookie: u.cookie });
    expect(list.status).toBe(200);
    expect((await list.json()).shares).toHaveLength(N);
    // Revoking one (My shares' revoke) drops its refs in the Drive.
    const [gone] = ids[0];
    expect((await fetchJson(`/api/private/shares/${gone}/revoke`, { method: 'POST', cookie: u.cookie, headers: intent })).status).toBe(200);
    const refs = await runInDurableObject(driveOf(u.id), (i, s) => s.storage.sql.exec('SELECT COUNT(*) AS c FROM refs WHERE share_id = ?', gone).one().c);
    expect(refs).toBe(0);
    expect((await (await fetchJson(`/api/private/drive/nodes/${folder.id}/shares`, { cookie: u.cookie })).json()).shares).toHaveLength(N - 1);
    // The admin filter by owner of many shares works too (batched lookups).
    expect((await del(u.cookie, folder.id)).status).toBe(200);
  });

  it('a share deleted by its recipient, or ended by the admin, also leaves the refs', async () => {
    const u = await makeUser('aud-refs2');
    await enableDrive(u.id);
    const f = await uploadFile(u.cookie, 'root', 10);
    const a = await shareOf(u.cookie, [f.id]);
    const b = await shareOf(u.cookie, [f.id]);
    expect(a.res.status).toBe(201);
    expect((await fetchJson(`/api/private/admin/shares/${a.id}/revoke`, { method: 'POST', cookie: oc, headers: intent })).status).toBe(200);
    await dirStub().markShareEnded(b.id, 'consumed');
    const left = await runInDurableObject(driveOf(u.id), (i, s) => s.storage.sql.exec('SELECT COUNT(*) AS c FROM refs').one().c);
    expect(left).toBe(0);
  });
});

describe('names in every script (shared checks, run in the Worker runtime)', () => {
  const REAL = ['דוח שנתי 2026.pdf', 'שָׁלוֹם.txt', 'report-דוח.docx', 'تقرير.pdf', 'می\u200cخواهم.txt', '👨\u200d👩\u200d👧 family.jpg', 'תיקייה/משנה/דוח.pdf'];
  it('file-share (v2) and Drive-share (v3) manifests keep them unchanged; spoofing characters are cleaned, not refused', async () => {
    const files = await import('../public/js/files.js');
    const { buildRefsManifest, validateRefsManifest } = await import('../public/js/refsmanifest.js');
    const l = files.layout(REAL.map((path, i) => ({ path, type: 'application/octet-stream', size: i + 1, mtime: 0 })), ['תיקייה/ריקה']);
    const v2 = files.validateManifest(JSON.parse(JSON.stringify(files.buildManifest({ entries: l.entries, total: l.total }))));
    expect(v2.entries.filter((e) => !e.dir).map((e) => e.path)).toEqual(REAL);
    const v3 = validateRefsManifest(JSON.parse(JSON.stringify(buildRefsManifest({ files: REAL.map((path) => ({ path, size: 1, type: 'text/plain', mtime: 0, fk: b64urlFromBytes(randomBytes(32)) })), dirs: ['תיקייה'] }))));
    expect(v3.entries.filter((e) => !e.dir).map((e) => e.path)).toEqual(REAL);
    for (const n of REAL) expect(files.cleanName(n)).toBe(n);
    expect(files.cleanName('invoice\u202efdp.exe')).toBe('invoicefdp.exe');
    expect(files.checkPath('invoice\u202efdp.exe')).toBe('invoice\u202efdp.exe'); // a received one is cleaned for display, not refused
  });
});

describe('audit round 3: a share id never changes hands', () => {
  it('recordShare refuses an id another account holds (the row stays theirs); the same account may re-record it', async () => {
    const a = await makeUser('aud-rec-a');
    const b = await makeUser('aud-rec-b');
    const id = genId('f');
    const t = Math.floor(Date.now() / 1000);
    expect(await dirStub().recordShare({ id, uid: a.id, kind: 'drive', label: 'mine', created: t, expires: t + 60, views: null })).toMatchObject({ ok: true });
    expect(await dirStub().recordShare({ id, uid: b.id, kind: 'drive', label: 'taken', created: t, expires: t + 60, views: null })).toMatchObject({ ok: false, status: 409 });
    const row = await runInDurableObject(dirStub(), (i, st) => st.storage.sql.exec('SELECT user_id, label FROM shares WHERE id = ?', id).one());
    expect(row).toEqual({ user_id: a.id, label: 'mine' });
    expect(await dirStub().recordShare({ id, uid: a.id, kind: 'drive', label: 'again', created: t, expires: t + 60, views: null })).toMatchObject({ ok: true });
  });
});

describe('L-3: sealed names and metadata', () => {
  it('are capped (512 / 1024 characters) and count towards the capacity', async () => {
    const u = await makeUser('aud-meta');
    const big = (n) => ({ iv: b64urlFromBytes(randomBytes(12)), ct: 'A'.repeat(n) });
    // A sealed name of `ct` characters: (ct · 3/4) − 16 bytes of plaintext.
    const sealedOf = (ct) => sealed(u.cookie, 'dir', { name: randomBytes((ct * 3) / 4 - 16) });
    await enableDrive(u.id, { driveMaxBytes: 2 * DIR_BYTES + 700 });
    const f = await sealed(u.cookie, 'file');
    const post = (path, body) => fetchJson(path, { method: 'POST', cookie: u.cookie, body: { parent: 'root', ks: f.ks, mek: f.mek, ...body } });
    expect((await post('/api/private/drive/folders', { name: big(513) })).status).toBe(400);
    expect((await post('/api/private/drive/folders', { name: big(100), meta: big(1025) })).status).toBe(400);
    expect((await post('/api/private/drive/files', { name: f.name, meta: big(1025), size: 0, dek: f.dek })).status).toBe(400);
    expect((await mkdir(u.cookie)).res.status).toBe(201);
    expect((await drive(u.cookie)).used).toBe(DIR_BYTES);
    const s512 = await sealedOf(512);
    expect(s512.name.ct).toHaveLength(512);
    const ok = await mkdir(u.cookie, 'root', { fields: s512 });
    expect(ok.res.status).toBe(201);
    expect((await drive(u.cookie)).used).toBe(DIR_BYTES + JSON.stringify(s512.name).length + 43);
    // Full: no more folders, and a rename that grows a name is refused too.
    const full = await mkdir(u.cookie, 'root', { fields: await sealedOf(400) });
    expect(full.res.status).toBe(413);
    expect((await full.res.json()).error).toBe('drive_full');
    const k = await driveKeys(u.cookie);
    const meta = await sealName(k.keks.get(s512.mek), { userId: u.id, mekId: s512.mek, salt: s512.ks }, 'meta', randomBytes(734));
    expect(meta.ct).toHaveLength(1000);
    expect((await fetchJson(`/api/private/drive/nodes/${ok.id}`, { method: 'PATCH', cookie: u.cookie, headers: intent, body: { meta, ks: s512.ks, mek: s512.mek } })).status).toBe(413);
    expect((await createFile(u.cookie, 'root', 0)).res.status).toBe(413);
  });
});

describe('L-7: deleting an account', () => {
  it('removes the Drive first: without R2 the account stays; the retry deletes the Drive, its shares and the account', async () => {
    const u = await makeUser('aud-del');
    await enableDrive(u.id);
    const f = await uploadFile(u.cookie, 'root', 10);
    const s = await shareOf(u.cookie, [f.id]);
    expect(s.res.status).toBe(201);
    const ctx = createExecutionContext();
    const res = await worker.fetch(new Request(`${ORIGIN}/api/private/admin/users/${u.id}`, { method: 'DELETE', headers: { cookie: oc, ...intent } }), { ...env, FILES: undefined }, ctx);
    await waitOnExecutionContext(ctx);
    expect(res.status).toBe(503);
    expect((await fetchJson(`/api/private/admin/users/${u.id}`, { cookie: oc })).status).toBe(200); // still there
    expect(await env.FILES.get(`d/${u.id}/${f.id}/0`)).not.toBeNull();
    const again = await fetchJson(`/api/private/admin/users/${u.id}`, { method: 'DELETE', cookie: oc, headers: intent });
    expect(again.status).toBe(200);
    expect((await fetchJson(`/api/private/admin/users/${u.id}`, { cookie: oc })).status).toBe(404);
    expect(await env.FILES.get(`d/${u.id}/${f.id}/0`)).toBeNull();
    expect([404, 410]).toContain((await fetchJson(`/api/file/${s.id}`, { ip: freshIp() })).status); // the share ended with it
    // The Drive object is empty (and a late call finds an empty Drive, not an error).
    expect((await driveOf(u.id).usage(u.id)).items).toBe(0);
  });
});

describe('Impersonation: the owner uses the user’s whole Drive', () => {
  it('opens it with the user’s keys (logged), reads, uploads, shares, revokes and deletes; the user sees each as theirs, the admin audit the real actor', async () => {
    const oid = await ownerId();
    const u = await makeUser('aud-imp');
    await enableDrive(u.id);
    const mine = await uploadFile(u.cookie, 'root', 20);
    const before = await activity(u.cookie);
    const ic = await impersonate(u.id);
    // No prompt and no escrow: the server hands the user's keys to the owner acting as them (admin audit).
    const k = await driveKeys(ic, { fresh: true });
    expect(k.userId).toBe(u.id);
    expect(k.raw.keys.map((x) => x.kek)).toEqual((await driveKeys(u.cookie)).raw.keys.map((x) => x.kek));
    // Every Drive action works.
    const g = await getChunk(ic, mine.id, 0);
    expect(g.status).toBe(200);
    const folder = await mkdir(ic);
    expect(folder.res.status).toBe(201);
    const up = await uploadFile(ic, folder.id, 30);
    const name = await sealName(k.keks.get(up.fields.mek), { userId: u.id, mekId: up.fields.mek, salt: up.fields.ks }, 'name', utf8('by the owner'));
    expect((await fetchJson(`/api/private/drive/nodes/${up.id}`, { method: 'PATCH', cookie: ic, headers: intent, body: { name, ks: up.fields.ks, mek: up.fields.mek } })).status).toBe(200);
    const sh = await shareOf(ic, [up.id]);
    expect(sh.res.status).toBe(201);
    const sh2 = await shareOf(ic, [mine.id]);
    expect((await fetchJson(`/api/private/shares/${sh2.id}/revoke`, { method: 'POST', cookie: ic, headers: intent })).status).toBe(200);
    expect((await fetchJson(`/api/private/drive/nodes/${up.id}/shares`, { cookie: ic })).status).toBe(200);
    expect((await del(ic, folder.id)).status).toBe(200);
    // The personal kit and the upgrade are the user's own.
    for (const [p, body] of [['/api/private/drive/kit', {}], ['/api/private/drive/kit/verify', { keks: {} }], ['/api/private/drive/migrate/finish', {}]]) {
      const r = await fetchJson(p, { method: 'POST', cookie: ic, headers: intent, body });
      expect(r.status, p).toBe(403);
      expect((await r.json()).error).toBe('impersonating');
    }
    expect((await fetchJson('/api/private/admin/users/' + u.id + '/impersonate', { method: 'POST', cookie: ic, headers: intent })).status).toBe(403);
    expect((await fetchJson('/api/private/admin/keys', { cookie: ic })).status).toBe(403); // the keyring: never while acting as a user
    expect((await fetchJson('/api/private/admin/unimpersonate', { method: 'POST', cookie: ic, headers: intent })).status).toBe(200);
    // The user's own activity lists each Drive action as theirs, with no trace
    // of the impersonation: not its start or end, not the use of the keys.
    const after = (await activity(u.cookie)).filter((r) => !before.some((x) => x.id === r.id));
    const DRIVE_ACTS = ['drive.file_read', 'drive.folder_created', 'drive.file_uploaded', 'drive.item_changed', 'share.created', 'share.revoked', 'drive.item_deleted'];
    expect([...new Set(after.map((r) => r.action))].sort()).toEqual([...DRIVE_ACTS].sort());
    for (const r of after) {
      expect(Object.keys(r).sort()).toEqual(['action', 'detail', 'id', 'ts']);
      expect(`${r.action} ${r.detail}`).not.toMatch(/imperson|acting as|escrow|owner|keys/i);
    }
    // The admin audit shows the real actor for each: the Drive actions as done
    // as the user (imp), the use of the keys as the owner's own (admin audit only).
    const rows = (await audit(u.id)).filter((r) => r.actor_id === oid);
    const acts = rows.map((r) => r.action);
    for (const a of ['impersonate.start', 'impersonate.end', 'drive.keys_used', ...DRIVE_ACTS]) expect(acts, a).toContain(a);
    for (const r of rows.filter((x) => DRIVE_ACTS.includes(x.action))) {
      expect(r).toMatchObject({ actor: 'owner', imp: 1, adm: 0 });
      expect(after.some((x) => x.id === r.id), r.action).toBe(true);
    }
    expect(rows.find((r) => r.action === 'drive.keys_used')).toMatchObject({ actor: 'owner', imp: 1, adm: 1 });
  });

  it('a user who has never signed in: the owner acting as them uses their Drive; the user later gets the same keys', async () => {
    const oc2 = await owner();
    const r = await fetchJson('/api/private/admin/users', { method: 'POST', cookie: oc2, body: { username: 'aud-imp-new', salt: b64urlFromBytes(randomBytes(16)), t: 3, proof: b64urlFromBytes(randomBytes(32)) } });
    expect(r.status).toBe(201);
    const { user } = await r.json();
    await enableDrive(user.id);
    const ic = await impersonate(user.id);
    const k = await driveKeys(ic, { fresh: true });
    const d = await mkdir(ic);
    expect(d.res.status).toBe(201);
    expect((await drive(ic)).used).toBe(DIR_BYTES);
    // The keys are derived from the user's salt (made with the account): the same for the user.
    const kv = await runInDurableObject(dirStub(), (inst) => inst.driveKeys(user.id, {}));
    expect(kv.keys.map((x) => x.kek)).toEqual(k.raw.keys.map((x) => x.kek));
  });
});

void SELF; void proofHeaders;

describe('Drive activity: logged like every other action (docs/DRIVE.md §9)', () => {
  it('the user’s own Drive actions are in their activity; their file reads are throttled, the owner’s never', async () => {
    const u = await makeUser('aud-log');
    await enableDrive(u.id);
    const f = await uploadFile(u.cookie, 'root', 10);
    const acts = (await activity(u.cookie)).map((r) => `${r.action} ${r.detail}`);
    expect(acts).toContain(`drive.file_uploaded id=${f.id}`);
    // Getting the keys is no activity of the user's (nothing they did).
    expect(acts.some((x) => x.startsWith('drive.keys'))).toBe(false);
    // The same file read again within a minute: one row.
    for (let i = 0; i < 3; i++) expect((await getChunk(u.cookie, f.id, 0)).status).toBe(200);
    const reads = async () => (await audit(u.id)).filter((r) => r.action === 'drive.file_read');
    expect(await reads()).toHaveLength(1);
    // At most 30 reads a minute of the user's own…
    const files = [];
    for (let i = 0; i < 32; i++) files.push((await uploadFile(u.cookie, 'root', 1)).id);
    for (const id of files) expect((await getChunk(u.cookie, id, 0)).status).toBe(200);
    expect(await reads()).toHaveLength(30);
    // …while every read the owner makes as the user is recorded.
    const ic = await impersonate(u.id);
    for (let i = 0; i < 3; i++) expect((await getChunk(ic, f.id, 0)).status).toBe(200);
    const byOwner = (await reads()).filter((r) => r.actor === 'owner');
    expect(byOwner).toHaveLength(3);
    for (const r of byOwner) expect(r).toMatchObject({ imp: 1, adm: 0 });
    // Only the Drive's own user, or the owner acting as them, can be named as the actor.
    const oid = await ownerId();
    const other = await makeUser('aud-log-2');
    const bad = await runInDurableObject(dirStub(), (inst) => Promise.all([
      inst.driveLog(other.id, u.id, 'drive.folder_created', 'x'),
      inst.driveLog({ id: other.id, imp: true }, u.id, 'drive.folder_created', 'x'),
      inst.driveLog({ id: oid, imp: true, adm: true }, u.id, 'drive.folder_created', 'x'),
      inst.driveLog(u.id, u.id, 'drive.escrow_used', 'x'),
    ]));
    expect(bad.map((r) => r.status)).toEqual([403, 403, 403, 400]);
  }, 60000);
});
