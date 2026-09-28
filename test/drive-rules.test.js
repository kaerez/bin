// drive-rules.test.js — the role's file rules for the Drive (public/js/
// filepolicy.js, as for file shares; src/lib/drivepolicy.js, src/drive-do.js):
// the file-type rules (fileTypeMode / fileTypeRules) are checked on a Drive
// upload's reservation against the type the browser declares (never stored),
// and the folder-depth limit (maxFolderDepth) against the Drive's own tree on
// an upload, a new folder and a move; files already in a Drive stay. Files
// taken in from a Receive link follow the role's Drive rules too, on top of the
// link's own: the type (declared at the take-in) and the depth.
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, fetchJson } from './helpers.js';
import { enableDrive, driveLimits, sealed, mkdir, createFile, uploadFile, node, drive } from './drive-helpers.js';
import { receiver, newReverse, grantOf, send, received, takeInAny } from './reverse-helpers.js';

beforeAll(async () => { await owner(); });

const errorBody = async (r) => ({ status: r.status, ...(await r.json()) });
/** POST /api/private/drive/files as the browser sends it, with `types` (the declaration) when given. */
async function reserve(cookie, parent, size, types) {
  const f = await sealed(cookie, 'file');
  return fetchJson('/api/private/drive/files', { method: 'POST', cookie, body: { parent, name: f.name, meta: f.meta, dek: f.dek, ks: f.ks, mek: f.mek, size, ...(types !== undefined ? { types } : {}) } });
}
const move = (cookie, id, parent) => fetchJson(`/api/private/drive/nodes/${id}`, { method: 'PATCH', cookie, body: { parent } });
const EXE = { ext: 'exe', mime: 'application/x-msdownload' };
const TXT = { ext: 'txt', mime: 'text/plain' };
const usedQuotas = async (cookie) => Object.fromEntries((await (await fetchJson('/api/private/me', { cookie })).json()).quotas.map((x) => [x.kind, x.used]));
const setQuotas = async (scope, list) => fetchJson('/api/private/admin/quotas', { method: 'PUT', cookie: await owner(), body: { scope, list } });
const q = (kind, max) => ({ channel: 'all', kind, n: 100, unit: 'y', max });

describe('Drive uploads follow the role\'s file-type rules', () => {
  it('a block list: the type is declared and checked at the reservation; a refused one reserves and counts nothing', async () => {
    const u = await makeUser('dr-block');
    await enableDrive(u.id, { fileTypeMode: 'block', fileTypeRules: ['ext:exe', 'mime:application/x-msdownload'] });
    await setQuotas(u.id, [q('drive-upload', 10), q('drive-bytes', 1000)]);
    const before = await drive(u.cookie);
    // No declaration: refused, with the policy for the browser to check and declare.
    expect(await errorBody(await reserve(u.cookie, 'root', 10))).toEqual({
      status: 400, error: 'declaration_required', message: 'Your role has a file-type policy: declare the file’s type.',
      policy: { mode: 'block', rules: ['ext:exe', 'mime:application/x-msdownload'], maxFolderDepth: null },
    });
    // A blocked type.
    expect(await errorBody(await reserve(u.cookie, 'root', 10, [EXE]))).toEqual({
      status: 403, error: 'file_type_not_allowed', message: 'This file type may not be uploaded to your Drive: .exe (application/x-msdownload).', refused: [EXE],
    });
    // One type exactly: none (which no rule matches) or two are not a declaration of this file.
    for (const types of [[], [TXT, EXE], [{ ext: '../x', mime: 'text/plain' }], 'txt']) {
      expect((await errorBody(await reserve(u.cookie, 'root', 10, types))).error).toBe('invalid_declaration');
    }
    expect(await drive(u.cookie)).toEqual(before); // nothing reserved
    expect(await usedQuotas(u.cookie)).toEqual({ 'drive-upload': 0, 'drive-bytes': 0 }); // nothing counted
    // An allowed type goes through.
    expect((await reserve(u.cookie, 'root', 10, [TXT])).status).toBe(201);
    expect(await usedQuotas(u.cookie)).toEqual({ 'drive-upload': 1, 'drive-bytes': 10 });
  });

  it('an allow list refuses every other type; without a type policy nothing is declared', async () => {
    const u = await makeUser('dr-allow');
    await enableDrive(u.id, { fileTypeMode: 'allow', fileTypeRules: ['mime:image/*'] });
    expect((await errorBody(await reserve(u.cookie, 'root', 10, [TXT]))).error).toBe('file_type_not_allowed');
    expect((await reserve(u.cookie, 'root', 10, [{ ext: 'png', mime: 'image/png' }])).status).toBe(201);
    await driveLimits(u.id, { fileTypeMode: 'any', fileTypeRules: [] });
    expect((await reserve(u.cookie, 'root', 10)).status).toBe(201);
  });

  it('files already in the Drive stay when a rule later refuses their type', async () => {
    const u = await makeUser('dr-keep');
    await enableDrive(u.id);
    const f = await uploadFile(u.cookie, 'root', 10);
    await driveLimits(u.id, { fileTypeMode: 'allow', fileTypeRules: ['ext:pdf'] });
    const r = await node(u.cookie, 'root');
    expect((await r.json()).children.map((c) => c.id)).toContain(f.id);
    expect((await fetchJson(`/api/private/drive/files/${f.id}/chunk/0`, { cookie: u.cookie })).status).toBe(200);
  });
});

describe('the role\'s folder-depth limit in the Drive', () => {
  it('a new folder past the limit is refused; an upload into a folder deeper than the limit too; what is there stays', async () => {
    const u = await makeUser('dr-depth');
    await enableDrive(u.id);
    const a = await mkdir(u.cookie, 'root');
    const b = await mkdir(u.cookie, a.id); // level 2, made before the limit
    const inB = await uploadFile(u.cookie, b.id, 10);
    await driveLimits(u.id, { maxFolderDepth: 1 });
    // A folder at level 2: refused.
    const deep = await mkdir(u.cookie, a.id);
    expect(await errorBody(deep.res)).toEqual({ status: 403, error: 'folder_too_deep', message: 'Folders may be nested at most 1 level deep in your Drive.', max: 1 });
    // A file in a level-1 folder is fine; one in the level-2 folder is not (nothing reserved, the quota given back).
    await setQuotas(u.id, [q('drive-upload', 10), q('drive-bytes', 1000)]);
    expect((await createFile(u.cookie, a.id, 10)).res.status).toBe(201);
    const into = await createFile(u.cookie, b.id, 10);
    expect(await errorBody(into.res)).toMatchObject({ status: 403, error: 'folder_too_deep', max: 1 });
    expect(await usedQuotas(u.cookie)).toEqual({ 'drive-upload': 1, 'drive-bytes': 10 });
    // What was there stays, and opens.
    expect((await (await node(u.cookie, b.id)).json()).children.map((c) => c.id)).toEqual([inB.id]);
    expect((await fetchJson(`/api/private/drive/files/${inB.id}/chunk/0`, { cookie: u.cookie })).status).toBe(200);
    // Level 0: only the top folder.
    await driveLimits(u.id, { maxFolderDepth: 0 });
    expect((await mkdir(u.cookie, 'root')).res.status).toBe(403);
    expect((await createFile(u.cookie, 'root', 10)).res.status).toBe(201);
    expect((await createFile(u.cookie, a.id, 10)).res.status).toBe(403);
  });

  it('a move that would put a folder, what is inside it, or a file past the limit is refused', async () => {
    const u = await makeUser('dr-move');
    await enableDrive(u.id);
    const a = await mkdir(u.cookie, 'root');
    const b = await mkdir(u.cookie, a.id); // level 2
    const x = await mkdir(u.cookie, 'root');
    const y = await mkdir(u.cookie, x.id); // x has one folder level inside
    const f = await mkdir(u.cookie, 'root'); // a folder with only a file inside
    await uploadFile(u.cookie, f.id, 5);
    const file = await uploadFile(u.cookie, 'root', 5);
    const other = await uploadFile(u.cookie, 'root', 5);
    await driveLimits(u.id, { maxFolderDepth: 2 });
    // x into b: x at 3. x into a: x at 2 but y at 3.
    expect(await errorBody(await move(u.cookie, x.id, b.id))).toEqual({ status: 403, error: 'folder_too_deep', message: 'Folders may be nested at most 2 levels deep in your Drive.', max: 2 });
    expect((await errorBody(await move(u.cookie, x.id, a.id))).error).toBe('folder_too_deep');
    // A folder holding only files adds no level; a file sits at its folder's level.
    expect((await move(u.cookie, f.id, a.id)).status).toBe(200);
    expect((await move(u.cookie, file.id, b.id)).status).toBe(200);
    expect((await move(u.cookie, y.id, a.id)).status).toBe(200); // y alone at 2
    // Deeper than the limit already: nothing goes in (a file included).
    await driveLimits(u.id, { maxFolderDepth: 1 });
    expect((await errorBody(await move(u.cookie, other.id, b.id))).error).toBe('folder_too_deep');
    expect((await move(u.cookie, file.id, a.id)).status).toBe(200); // out of b, into a: level 1
    expect((await move(u.cookie, other.id, a.id)).status).toBe(200);
  });
});

describe('files taken in from a Receive link follow the role\'s Drive rules (on top of the link\'s)', () => {
  it('the file type is declared at the take-in and checked against the role\'s rules', async () => {
    const u = await receiver('dr-take-type');
    const link = await newReverse(u.cookie);
    const grant = await grantOf(link);
    await send(link, grant, { path: 'a.exe', type: 'application/x-msdownload' });
    await send(link, grant, { path: 'b.txt' });
    const [x, y] = (await received(u.cookie)).items;
    await driveLimits(u.id, { fileTypeMode: 'block', fileTypeRules: ['ext:exe'] });
    const take = async (id, types) => {
      const f = await sealed(u.cookie, 'file');
      return fetchJson(`/api/private/drive/received/${id}`, { method: 'POST', cookie: u.cookie, body: { parent: 'root', name: f.name, meta: f.meta, dek: f.dek, ks: f.ks, mek: f.mek, ...(types ? { types } : {}) } });
    };
    expect((await errorBody(await takeInAny(u.cookie, x.id))).error).toBe('declaration_required');
    expect(await errorBody(await take(x.id, [EXE]))).toMatchObject({ status: 403, error: 'file_type_not_allowed', message: 'This file type may not be added to your Drive: .exe (application/x-msdownload).' });
    expect((await take(y.id, [TXT])).status).toBe(200);
    // The browser records the refused one as failed, with its own reason.
    const failed = await fetchJson(`/api/private/drive/received/${x.id}/failed`, { method: 'POST', cookie: u.cookie, body: { reason: 'type' } });
    expect(failed.status).toBe(200);
    expect((await received(u.cookie, '?failed=1')).items).toMatchObject([{ id: x.id, reason: 'type' }]);
  });

  it('the depth limit: nothing is taken into a folder deeper than the role allows', async () => {
    const u = await receiver('dr-take-depth');
    const a = await mkdir(u.cookie, 'root');
    const b = await mkdir(u.cookie, a.id);
    const link = await newReverse(u.cookie, { folder: b.id });
    expect(link.res.status).toBe(201);
    const grant = await grantOf(link);
    await send(link, grant, { path: 'one.txt' });
    await send(link, grant, { path: 'two.txt' });
    const [one, two] = (await received(u.cookie)).items;
    await driveLimits(u.id, { maxFolderDepth: 1 });
    expect(await errorBody(await takeInAny(u.cookie, one.id, b.id))).toMatchObject({ status: 403, error: 'folder_too_deep', max: 1 });
    expect((await takeInAny(u.cookie, one.id, a.id)).status).toBe(200);
    await driveLimits(u.id, { maxFolderDepth: null });
    expect((await takeInAny(u.cookie, two.id, b.id)).status).toBe(200);
  });
});
