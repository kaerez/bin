// driveclient.test.js — the Drive client (public/js/driveclient.js) against an
// in-memory stand-in for the §6 API (docs/DRIVE.md) behind a mocked fetch
// (drive-fake-server.js):
// first-time setup and unlock, the owner's escrow key, names decrypted on
// list (and never sent in the clear), exact chunk sizes on upload, download
// round trips, manifest v3 contents of a share (decrypted as a recipient
// would), reading v3 shares in downloads.js, and the wrap upkeep helpers.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  openDrive, unlockDrive, unlockAtSignIn, DriveLocked, DriveDisabled, escrowPasswordReset, updatePasswordWrap,
  replaceRecoveryWraps, removeRecoveryWraps, removePasskeyWrap, addPasskeyWrap, checkName,
} from '../public/js/driveclient.js';
import {
  loadSessionKey, clearSessionKey, saveSessionKey, createDriveKey, createEscrowKeyPair, sealEscrowPriv, wrapEscrow,
  wrapPassword, unlockWithPassword, unlockWithRecovery, unlockWithPrf, recoveryRef,
} from '../public/js/drivekeys.js';
import { deriveAccess, openPaste } from '../public/js/crypto.js';
import { validateRefsManifest } from '../public/js/refsmanifest.js';
import { RefsReader } from '../public/js/downloads.js';
import { CHUNK, TAG, encryptChunk, importFileKey } from '../public/js/files.js';
import { b64urlFromBytes, randomBytes } from '../public/js/bytes.js';
import { fakeServer } from './drive-fake-server.js';

const PASSWORD = 'drive password 1';
const CODE = 'ABCD-EFGH-JKMN-PQRS';

/** A File-like object over bytes (only what the client uses). */
function fakeFile(name, bytes, type = 'text/plain') {
  return { name, size: bytes.length, type, lastModified: 1700000000000, slice: (a, b) => ({ arrayBuffer: async () => bytes.slice(a, b).buffer }) };
}

/** The paste as a recipient's open returns it (the server keeps the proof hashes to itself). */
const served = ({ acc, ...paste }) => { void acc; return paste; };

function pattern(n, seed = 1) {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (i * 31 + seed) & 0xff;
  return b;
}

let S;
const install = (opts) => { S = fakeServer(opts); globalThis.fetch = S.fetch; return S; };
beforeEach(() => { clearSessionKey(); });
afterEach(() => { vi.restoreAllMocks(); });

describe('unlock and set-up', () => {
  it('sets up a new Drive with the password (pw wrap, escrow wrap), then opens from the tab', async () => {
    install();
    const owner = await createEscrowKeyPair();
    S.escrowPub = owner.publicJwk;
    const d = await unlockDrive({ password: PASSWORD });
    expect(d.user.id).toBe('u1');
    const wraps = [...S.wraps.values()];
    expect(wraps.map((w) => w.kind).sort()).toEqual(['escrow', 'pw']);
    const dk = loadSessionKey('u1');
    expect(dk).toBeInstanceOf(Uint8Array);
    expect(await unlockWithPassword(PASSWORD, S.driveSalt, wraps)).toEqual(dk);
    // No secret material in any request body.
    const all = JSON.stringify(S.requests.map((r) => r.body));
    expect(all).not.toContain(PASSWORD);
    expect(all).not.toContain(b64urlFromBytes(dk));
    const again = await openDrive();
    expect(again.dk).toEqual(dk);
  }, 30000);

  it('the owner\'s first unlock creates and publishes the escrow key pair', async () => {
    install({ role: 'owner' });
    await unlockDrive({ password: PASSWORD });
    expect(S.escrowPub).toMatchObject({ kty: 'EC', crv: 'P-256' });
    expect(S.escrowPriv).toMatch(/^1\./);
    expect([...S.wraps.values()].map((w) => w.kind)).toEqual(['pw']);
  }, 30000);

  it('refuses a wrong password, a set-up without the password, and a disabled Drive', async () => {
    install();
    await expect(unlockDrive({ code: CODE })).rejects.toMatchObject({ name: 'DriveLocked', reason: 'setup' });
    await unlockDrive({ password: PASSWORD });
    clearSessionKey();
    await expect(openDrive()).rejects.toBeInstanceOf(DriveLocked);
    await expect(unlockDrive({ password: 'nope' })).rejects.toMatchObject({ reason: 'wrong' });
    install({ enabled: false });
    await expect(openDrive()).rejects.toBeInstanceOf(DriveDisabled);
    await expect(unlockDrive({ password: PASSWORD })).rejects.toBeInstanceOf(DriveDisabled);
  }, 30000);

  it('never gives a Drive with content but no wraps a new key', async () => {
    install();
    S.nodes.set('x'.repeat(22), { id: 'x'.repeat(22), parent: 'root', kind: 'dir', name: '{}', size: 0, chunks: 0, state: 'ready' });
    await expect(unlockDrive({ password: PASSWORD })).rejects.toMatchObject({ reason: 'wrong' });
    expect(S.wraps.size).toBe(0);
  });

  it('the tab key belongs to one user', async () => {
    install();
    await unlockDrive({ password: PASSWORD });
    S.user = { id: 'someone-else', role: 'user' };
    await expect(openDrive()).rejects.toBeInstanceOf(DriveLocked);
  }, 30000);
});

describe('sign-in upkeep', () => {
  it('a spent recovery code unlocks and loses its wrap; a verified password re-wraps a stale pw wrap', async () => {
    install();
    const d = await unlockDrive({ password: PASSWORD });
    await replaceRecoveryWraps('u1', [CODE, 'ZZZZ-YYYY-XXXX-WWWW']);
    expect([...S.wraps.values()].filter((w) => w.kind === 'recovery')).toHaveLength(2);
    // An admin reset without escrow: the pw wrap no longer matches the password.
    const stale = await wrapPassword(d.dk, 'the old password');
    S.driveSalt = stale.driveSalt;
    S.wraps.set('pw|pw', stale.wrap);
    expect(await unlockAtSignIn({ user: S.user, password: 'the new password', code: CODE })).toBe(true);
    expect(loadSessionKey('u1')).toEqual(d.dk);
    const wraps = [...S.wraps.values()];
    const spent = await recoveryRef(CODE);
    expect(wraps.find((w) => w.kind === 'recovery' && w.ref === spent)).toBeUndefined();
    expect(await unlockWithRecovery('ZZZZ-YYYY-XXXX-WWWW', wraps)).toEqual(d.dk);
    expect(await unlockWithPassword('the new password', S.driveSalt, wraps)).toEqual(d.dk);
    // A failed unlock never throws.
    clearSessionKey();
    expect(await unlockAtSignIn({ user: S.user, password: 'wrong' })).toBe(false);
    expect(loadSessionKey('u1')).toBeNull();
  }, 60000);

  it('passkey wraps: added with PRF output, used to unlock, removed; password change; recovery wraps removed', async () => {
    install();
    const d = await unlockDrive({ password: PASSWORD });
    const prf = randomBytes(32);
    expect(await addPasskeyWrap('u1', prf, 'cred-1')).toBe(true);
    expect(await unlockWithPrf(prf, 'cred-1', [...S.wraps.values()])).toEqual(d.dk);
    clearSessionKey();
    await unlockDrive({ prfOutput: prf, credentialId: 'cred-1' });
    expect(loadSessionKey('u1')).toEqual(d.dk);
    await removePasskeyWrap('cred-1');
    expect([...S.wraps.values()].some((w) => w.kind === 'passkey')).toBe(false);
    // Password change with the key in the tab, and without it (the old password unlocks first).
    expect(await updatePasswordWrap({ userId: 'u1', newPassword: 'second password' })).toBe('ok');
    clearSessionKey();
    expect(await updatePasswordWrap({ userId: 'u1', newPassword: 'third password' })).toBe('locked');
    expect(await updatePasswordWrap({ userId: 'u1', newPassword: 'third password', oldPassword: 'second password' })).toBe('ok');
    expect(await unlockWithPassword('third password', S.driveSalt, [...S.wraps.values()])).toEqual(d.dk);
    await replaceRecoveryWraps('u1', [CODE]);
    await removeRecoveryWraps();
    expect([...S.wraps.values()].some((w) => w.kind === 'recovery')).toBe(false);
    // New codes while the Drive is locked here: the old codes' wraps still go.
    await replaceRecoveryWraps('u1', [CODE]);
    clearSessionKey();
    expect(await replaceRecoveryWraps('u1', ['ZZZZ-YYYY-XXXX-WWWW'])).toBe(false);
    expect([...S.wraps.values()].some((w) => w.kind === 'recovery')).toBe(false);
  }, 60000);

  it('an owner password reset re-keys the user\'s Drive through the escrow', async () => {
    install({ role: 'owner' });
    const ownerDk = createDriveKey();
    const kp = await createEscrowKeyPair();
    S.escrowPriv = await sealEscrowPriv(ownerDk, kp.privateKey);
    S.escrowPub = kp.publicJwk;
    const userDk = createDriveKey();
    S.userWraps = [await wrapEscrow(userDk, kp.publicJwk)];
    expect(await escrowPasswordReset({ ownerId: 'owner1', userId: 'u9', newPassword: 'reset pw' })).toBe('locked');
    saveSessionKey(ownerDk, 'owner1');
    expect(await escrowPasswordReset({ ownerId: 'owner1', userId: 'u9', newPassword: 'reset pw' })).toBe('ok');
    const call = S.requests.find((r) => r.path === '/api/private/admin/drive/escrow/u9');
    expect(call.body).toEqual({ reason: 'password reset' });
    const [{ userId, body }] = S.adminKeys;
    expect(userId).toBe('u9');
    expect(body.set.map((w) => w.kind)).toEqual(['pw']);
    expect(await unlockWithPassword('reset pw', body.driveSalt, body.set)).toEqual(userDk);
    S.userWraps = [];
    expect(await escrowPasswordReset({ ownerId: 'owner1', userId: 'u9', newPassword: 'x' })).toBe('no_wrap');
  }, 30000);
});

describe('files and folders', () => {
  it('names are sealed on the wire, decrypted on list, sorted folders first, with the path', async () => {
    install();
    const d = await unlockDrive({ password: PASSWORD });
    const docs = await d.mkdir('root', 'Documents — private');
    const sub = await d.mkdir(docs, 'Sub');
    await d.upload(docs, fakeFile('b-notes.txt', pattern(10)));
    await d.upload(docs, fakeFile('a-plan.md', pattern(3)), { type: 'text/markdown' });
    const wire = JSON.stringify(S.requests.map((r) => (r.body instanceof Uint8Array ? null : r.body)));
    for (const name of ['Documents — private', 'b-notes.txt', 'a-plan.md', 'text/markdown']) expect(wire).not.toContain(name);
    const l = await d.list(docs);
    expect(l.children.map((c) => [c.kind, c.name])).toEqual([['dir', 'Sub'], ['file', 'a-plan.md'], ['file', 'b-notes.txt']]);
    expect(l.children[1]).toMatchObject({ type: 'text/markdown', size: 3, mtime: 1700000000000 });
    expect(l.path).toEqual([{ id: 'root', name: 'Drive' }, { id: docs, name: 'Documents — private' }]);
    expect((await d.list(sub)).path.map((p) => p.name)).toEqual(['Drive', 'Documents — private', 'Sub']);
    await d.rename(sub, 'Renamed');
    await d.move(sub, 'root');
    expect((await d.list('root')).children.map((c) => c.name)).toEqual(['Documents — private', 'Renamed']);
    await d.remove(sub);
    expect((await d.list('root')).children.map((c) => c.name)).toEqual(['Documents — private']);
    expect(await d.usage()).toEqual({ used: 13, capacity: 1 << 30 });
    expect(() => checkName('a/b')).toThrow();
    expect(() => checkName('..')).toThrow();
    await expect(d.mkdir('root', 'x\u0000y')).rejects.toThrow();
  }, 30000);

  it('a name moved by the server to another node does not decrypt (AAD)', async () => {
    install();
    const d = await unlockDrive({ password: PASSWORD });
    const a = await d.mkdir('root', 'alpha');
    const b = await d.mkdir('root', 'beta');
    S.nodes.get(b).name = S.nodes.get(a).name;
    const kids = (await d.list('root')).children;
    expect(kids.find((c) => c.id === a).name).toBe('alpha');
    expect(kids.find((c) => c.id === b)).toMatchObject({ name: null, unreadable: true });
  }, 30000);

  it('uploads in exact chunks (8 MiB + tag, no padding) and downloads the same bytes', async () => {
    install();
    const d = await unlockDrive({ password: PASSWORD });
    const size = 2 * CHUNK + 12345;
    const bytes = pattern(size, 7);
    const progress = [];
    const id = await d.upload('root', fakeFile('big.bin', bytes, 'application/octet-stream'), { onProgress: (done, total) => progress.push([done, total]) });
    const puts = S.requests.filter((r) => r.method === 'PUT' && r.path.includes('/chunk/'));
    expect(puts.map((r) => r.body.length)).toEqual([CHUNK + TAG, CHUNK + TAG, 12345 + TAG]);
    expect(puts.every((r) => r.headers['x-upload-token'] === `tok-${id}`)).toBe(true);
    expect(S.requests.find((r) => r.path === '/api/private/drive/files').body.size).toBe(size);
    expect(S.requests.some((r) => r.path.endsWith(`/files/${id}/finalize`))).toBe(true);
    expect(progress.at(-1)).toEqual([size, size]);
    const dl = await d.download(id);
    expect(dl.entry).toMatchObject({ path: 'big.bin', size, type: 'application/octet-stream' });
    const got = new Uint8Array(await (await dl.blob()).arrayBuffer());
    expect(got.length).toBe(size);
    expect(Buffer.from(got).equals(Buffer.from(bytes))).toBe(true);
    // A swapped chunk fails authentication.
    S.chunks.set(`${id}/1`, S.chunks.get(`${id}/0`));
    await expect((await d.download(id)).blob()).rejects.toThrow(/authentication/);
  }, 60000);

  it('an empty file has no chunks; a failed upload deletes its node; uploadTree builds folders', async () => {
    install();
    const d = await unlockDrive({ password: PASSWORD });
    const empty = await d.upload('root', fakeFile('empty.txt', new Uint8Array(0)));
    expect(S.nodes.get(empty)).toMatchObject({ chunks: 0, state: 'ready' });
    expect(new Uint8Array(await (await (await d.download(empty)).blob()).arrayBuffer()).length).toBe(0);
    // A refused chunk: the pending node is removed.
    const orig = S.fetch.getMockImplementation();
    S.fetch.mockImplementation(async (url, init = {}) => (init.method === 'PUT' && String(url).includes('/chunk/')
      ? { ok: false, status: 400, type: 'basic', json: async () => ({ error: 'bad', message: 'bad' }) } : orig(url, init)));
    await expect(d.upload('root', fakeFile('x.txt', pattern(5)))).rejects.toThrow();
    await new Promise((r) => setTimeout(r, 0));
    expect([...S.nodes.values()].filter((n) => n.state === 'pending')).toHaveLength(0);
    S.fetch.mockImplementation(orig);
    const ids = await d.uploadTree('root', [
      { path: 'proj/src/a.js', file: fakeFile('a.js', pattern(4)) },
      { path: 'proj/src/b.js', file: fakeFile('b.js', pattern(5)) },
      { path: 'proj/readme.md', file: fakeFile('readme.md', pattern(6)) },
      { path: 'proj/empty', dir: true },
    ]);
    expect(ids).toHaveLength(3);
    const top = await d.list('root');
    const proj = top.children.find((c) => c.name === 'proj');
    expect((await d.list(proj.id)).children.map((c) => c.name)).toEqual(['empty', 'src', 'readme.md']);
    // Uploading into existing folders reuses them.
    await d.uploadTree('root', [{ path: 'proj/src/c.js', file: fakeFile('c.js', pattern(1)) }]);
    expect((await d.list('root')).children.filter((c) => c.name === 'proj')).toHaveLength(1);
  }, 60000);
});

describe('folder download', () => {
  it('saves a folder as a ZIP of its content (downloads.js saveZip)', async () => {
    install();
    const d = await unlockDrive({ password: PASSWORD });
    await d.uploadTree('root', [
      { path: 'proj/src/a.js', file: fakeFile('a.js', new TextEncoder().encode('alpha-content')) },
      { path: 'proj/readme.md', file: fakeFile('readme.md', new TextEncoder().encode('readme-content')) },
      { path: 'proj/empty', dir: true },
    ]);
    const proj = (await d.list('root')).children.find((c) => c.name === 'proj');
    let saved = null;
    vi.spyOn(URL, 'createObjectURL').mockImplementation((b) => { saved = b; return 'blob:zip'; });
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function click() { saved.name = this.download; });
    await d.downloadFolder(proj.id);
    expect(saved.name).toBe('proj.zip');
    const text = new TextDecoder().decode(new Uint8Array(await saved.arrayBuffer()));
    for (const s of ['src/a.js', 'readme.md', 'empty/', 'alpha-content', 'readme-content']) expect(text).toContain(s);
    expect(text).not.toContain('proj/');
  }, 30000);
});

describe('shares (manifest v3)', () => {
  it('flattens folders into a v3 manifest with per-file keys, sealed like a file share', async () => {
    install();
    const d = await unlockDrive({ password: PASSWORD });
    const photos = await d.mkdir('root', 'Photos');
    await d.mkdir(photos, 'Empty');
    const one = pattern(100, 3);
    const two = pattern(CHUNK + 5, 4);
    const f1 = await d.upload(photos, fakeFile('one.png', one, 'image/png'));
    const f2 = await d.upload(photos, fakeFile('two.bin', two, 'application/octet-stream'));
    const solo = await d.upload('root', fakeFile('one.png', pattern(9), 'image/png')); // same name as in Photos, different folder
    const r = await d.share([photos, solo], { views: 3, expire: '1d', deletable: true, label: 'holiday', view: { rules: [], maxBytes: 10 } });
    expect(r).toMatchObject({ id: 'fSHARE1', deletetoken: 'dt1' });
    const fragment = r.url.split('#')[1];
    expect(r.url).toContain('/p/fSHARE1#');
    const [body] = S.shareBodies;
    expect(body).toMatchObject({ views: 3, expire: '1d', deletable: true, label: 'holiday' });
    expect(body.acc).toEqual(body.paste.acc);
    expect(JSON.stringify(body)).not.toContain('Photos');
    // Open the paste as a recipient would.
    const access = await deriveAccess({ adata: body.paste.adata, fragment });
    const { text } = await openPaste({ paste: served(body.paste), access });
    const raw = JSON.parse(text);
    expect(raw).toMatchObject({ v: 3, kind: 'refs', dirs: ['Photos', 'Photos/Empty'], view: { rules: [], maxBytes: 10 } });
    const m = validateRefsManifest(raw);
    const files = m.entries.filter((e) => !e.dir);
    expect(files.map((e) => [e.path, e.size, e.type, e.ref])).toEqual([
      ['Photos/one.png', 100, 'image/png', 0], ['Photos/two.bin', CHUNK + 5, 'application/octet-stream', 1], ['one.png', 9, 'image/png', 2],
    ]);
    // refs[i] is nodes[i], and each entry's fk decrypts that node's chunks.
    expect(body.nodes).toEqual([f1, f2, solo]);
    const reader = new RefsReader({ manifest: m, fetch: (e, i) => Promise.resolve(S.chunks.get(`${body.nodes[e.ref]}/${i}`)), refs: body.nodes.map((id) => ({ chunks: S.nodes.get(id).chunks })) });
    expect(Buffer.from(await reader.bytes(files[1])).equals(Buffer.from(two))).toBe(true);
    expect(Buffer.from(await reader.bytes(files[0])).equals(Buffer.from(one))).toBe(true);
    expect((await d.shares(photos)).map((x) => x.id)).toEqual(['fSHARE1']); // a folder's shares: those of the files under it
  }, 60000);

  it('a password share needs the password; policy limits are applied and declared', async () => {
    install();
    const d = await unlockDrive({ password: PASSWORD });
    const f = await d.upload('root', fakeFile('run.exe', pattern(4), 'application/x-msdownload'));
    await expect(d.share([f], { views: null, expire: '1h', limits: { fileTypeMode: 'block', fileTypeRules: ['ext:exe'] } })).rejects.toThrow(/does not allow/);
    const r = await d.share([f], { views: null, expire: '1h', password: 'share pw', limits: { fileTypeMode: 'allow', fileTypeRules: ['ext:exe'], maxFolderDepth: 3 } });
    const body = S.shareBodies.at(-1);
    expect(body.types).toEqual([{ ext: 'exe', mime: 'application/x-msdownload' }]);
    expect(body.depth).toBe(0);
    expect(body.views).toBeNull();
    expect(body.paste.adata.bar).toBe(false);
    const fragment = r.url.split('#')[1];
    await expect(deriveAccess({ adata: body.paste.adata, fragment })).rejects.toThrow(/password/);
    const access = await deriveAccess({ adata: body.paste.adata, fragment, password: 'share pw' });
    expect(JSON.parse((await openPaste({ paste: served(body.paste), access })).text).entries[0].path).toBe('run.exe');
  }, 60000);
});

describe('downloads.js reads v3 shares', () => {
  it('fetches /api/file/<id>/chunk/<ref>/<i> with the grant and checks chunk counts', async () => {
    const fk = b64urlFromBytes(randomBytes(32));
    const key = await importFileKey(fk);
    const data = pattern(CHUNK + 3, 9);
    const cts = [await encryptChunk(key, 0, 2, data.slice(0, CHUNK)), await encryptChunk(key, 1, 2, data.slice(CHUNK))];
    const manifest = validateRefsManifest({ v: 3, kind: 'refs', entries: [{ path: 'x.bin', size: data.length, type: 'application/octet-stream', mtime: 0, ref: 0, fk }], dirs: [] });
    const calls = [];
    globalThis.fetch = vi.fn(async (url, init) => {
      calls.push([url, init.headers['x-download-grant']]);
      const i = Number(url.split('/').pop());
      return { ok: true, status: 200, type: 'basic', arrayBuffer: async () => cts[i].slice().buffer };
    });
    const reader = RefsReader.forShare({ id: 'fABC', grant: 'g1', refs: [{ chunks: 2, size: data.length + 32 }], manifest });
    const got = await reader.bytes(manifest.entries[0]);
    expect(Buffer.from(got).equals(Buffer.from(data))).toBe(true);
    expect(calls).toEqual([['/api/file/fABC/chunk/0/0', 'g1'], ['/api/file/fABC/chunk/0/1', 'g1']]);
    // A server that lies about the chunk count, or a missing ref, fails closed.
    const liar = RefsReader.forShare({ id: 'fABC', grant: 'g1', refs: [{ chunks: 1 }], manifest });
    await expect(liar.bytes(manifest.entries[0])).rejects.toThrow(/size mismatch/);
    expect(() => RefsReader.forShare({ id: 'fABC', grant: 'g1', refs: [], manifest })).toThrow();
    expect(() => RefsReader.forShare({ id: 'fABC', grant: 'g1', manifest })).toThrow();
  });
});
