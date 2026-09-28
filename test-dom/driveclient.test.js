// driveclient.test.js — the Drive client (public/js/driveclient.js) against an
// in-memory stand-in for the §6 API (docs/DRIVE.md) behind a mocked fetch
// (drive-fake-server.js): the Drive opens with the KEKs the server hands the
// session (no prompt; kept in the page's memory only, the impersonated user's too), the
// keys that cannot be had, a new sub-MEK picked up on the server's word, names
// decrypted on list (and never sent in the clear), exact chunk sizes on upload,
// download round trips, manifest v3 contents of a share (decrypted as a
// recipient would), reading v3 shares in downloads.js, and the personal kit.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  openDrive, DriveDisabled, DriveUnavailable, checkName, buildPersonalKit, verifyPersonalKit,
} from '../public/js/driveclient.js';
import { clearSessionKey, openName, openDek, chunkHash, ciphertextHash } from '../public/js/drivekeys.js';
import { keyCheckValueV1, saveLegacyKey } from '../public/js/drivev1.js';
import { parseDriveKit, openDriveKit, sealDriveKit } from '../public/js/drivekit.js';
import { deriveAccess, openPaste } from '../public/js/crypto.js';
import { validateRefsManifest } from '../public/js/refsmanifest.js';
import { RefsReader } from '../public/js/downloads.js';
import { CHUNK, TAG, encryptChunk, importFileKey } from '../public/js/files.js';
import { b64urlFromBytes, randomBytes, fromUtf8 } from '../public/js/bytes.js';
import { fakeServer } from './drive-fake-server.js';

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
const install = (opts = {}) => {
  S = fakeServer(opts);
  globalThis.fetch = S.fetch;
  return S;
};
beforeEach(() => { clearSessionKey(); });
afterEach(() => { vi.restoreAllMocks(); });

describe('opening the Drive', () => {
  it('opens with the KEKs the server hands the session: no prompt, no password, nothing secret sent', async () => {
    install();
    const d = await openDrive();
    expect(d.user.id).toBe(S.user.id);
    const cur = S.current();
    expect(d.keys.current).toBe(cur.id);
    expect([...d.keys.keks.get(cur.id)[0]]).toEqual([...await S.kekOf(cur.id)]);
    // In this page's memory only: nothing in the tab's storage.
    expect(sessionStorage.length).toBe(0);
    expect(localStorage.length).toBe(0);
    expect(S.requests.map((r) => r.path)).toEqual(['/api/auth/session', '/api/private/drive', '/api/private/drive/keys']);
    const docs = await d.mkdir('root', 'Docs');
    const wire = JSON.stringify(S.requests.map((r) => r.body));
    expect(wire).not.toContain(b64urlFromBytes(await S.kekOf(cur.id)));
    expect(wire).not.toContain('Docs');
    // The folder is sealed under the current KEK with its own salt.
    const n = S.nodes.get(docs);
    expect(n.mek).toBe(cur.id);
    expect(fromUtf8(await openName(await S.kekOf(cur.id), { userId: S.user.id, mekId: cur.id, salt: n.ks }, 'name', n.name))).toBe('Docs');
  });

  it('a disabled Drive, and keys that cannot be had (the keyring lost, the salt lost)', async () => {
    install({ enabled: false });
    await expect(openDrive()).rejects.toBeInstanceOf(DriveDisabled);
    install();
    S.keysError = 'keys_missing';
    await expect(openDrive()).rejects.toMatchObject({ name: 'DriveUnavailable', reason: 'keys_missing' });
    S.keysError = 'salt_missing';
    const e = await openDrive().catch((x) => x);
    expect(e).toBeInstanceOf(DriveUnavailable);
    expect(e.reason).toBe('salt_missing');
  });

  it('the owner acting as the user: the user’s keys, in the page’s memory only', async () => {
    install();
    S.impersonatedBy = 'owner';
    const d = await openDrive();
    expect(d.user).toMatchObject({ id: S.user.id, impersonating: true });
    expect([...d.keys.keks.get(S.current().id)[0]]).toEqual([...await S.kekOf(S.current().id)]);
    expect(sessionStorage.length).toBe(0);
    expect(S.audit.some((x) => x.action === 'drive.keys_used')).toBe(true);
    expect(await d.mkdir('root', 'by the owner')).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });

  it('a key planted in the tab’s storage is never used: the KEKs come from the server, new items are sealed under them, the planted slots go', async () => {
    install();
    await openDrive(); // the keyring is made at the first request
    const cur = S.current();
    const planted = randomBytes(32);
    const slot = JSON.stringify({ u: S.user.id, c: cur.id, k: { [cur.id]: b64urlFromBytes(planted) } });
    sessionStorage.setItem('secbin_kek', slot);
    sessionStorage.setItem('secbin_kek_imp', slot);
    sessionStorage.setItem('secbin_dk_imp', b64urlFromBytes(randomBytes(32)));
    sessionStorage.setItem('secbin_dk_imp_uid', S.user.id);
    localStorage.setItem('secbin_kek', slot);
    const d = await openDrive();
    expect([...d.keys.keks.get(cur.id)[0]]).toEqual([...await S.kekOf(cur.id)]);
    for (const k of ['secbin_kek', 'secbin_kek_imp', 'secbin_dk_imp', 'secbin_dk_imp_uid']) expect(sessionStorage.getItem(k), k).toBeNull();
    // A new folder and a new file: sealed under the server's KEK (the fake server checks each seal), never the planted one.
    const dir = await d.mkdir('root', 'after the plant');
    const file = await d.upload('root', fakeFile('new.txt', pattern(10)));
    for (const id of [dir, file]) {
      const n = S.nodes.get(id);
      const at = { userId: S.user.id, mekId: n.mek, salt: n.ks };
      expect(fromUtf8(await openName(await S.kekOf(n.mek), at, 'name', n.name))).toMatch(/after the plant|new\.txt/);
      await expect(openName(planted, at, 'name', n.name)).rejects.toThrow();
      if (n.dek) await expect(openDek(planted, at, n.dek)).rejects.toThrow();
    }
    localStorage.clear();
  });

  it('when the server does not hand out the keys, the Drive does not open: no stored key to fall back on', async () => {
    install();
    await openDrive(); // the keyring is made at the first request
    const cur = S.current();
    sessionStorage.setItem('secbin_kek', JSON.stringify({ u: S.user.id, c: cur.id, k: { [cur.id]: b64urlFromBytes(randomBytes(32)) } }));
    S.keysError = 'keys_missing';
    await expect(openDrive()).rejects.toMatchObject({ name: 'DriveUnavailable', reason: 'keys_missing' });
    S.keysError = null;
    const real = globalThis.fetch;
    globalThis.fetch = async (url, init) => (String(url).endsWith('/api/private/drive/keys') ? Promise.reject(new TypeError('network down')) : real(url, init));
    await expect(openDrive()).rejects.toThrow(/network down/);
    globalThis.fetch = real;
  });

  it('an old Drive key planted in the tab is used only once its check value is the server’s (a Drive waiting for its upgrade)', async () => {
    install();
    const dk = randomBytes(32);
    S.migration = { pending: true, v1Items: 1, v1Links: 0, legacy: true };
    S.legacyState = { state: 'pending', v1Items: 1, v1Links: 0, archived: 0, legacy: true, kcv: await keyCheckValueV1(dk), driveSalt: null, wraps: [] };
    sessionStorage.setItem('secbin_dk', b64urlFromBytes(randomBytes(32))); // not this Drive's
    sessionStorage.setItem('secbin_dk_uid', S.user.id);
    let d = await openDrive();
    expect(d.legacy).toBeNull();
    expect(sessionStorage.getItem('secbin_dk')).toBeNull(); // removed
    saveLegacyKey(dk, S.user.id); // this Drive's (the sign-in opened it)
    d = await openDrive();
    expect([...d.legacy]).toEqual([...dk]);
    // A Drive with no check value: the key must open one of its old items.
    S.legacyState = { ...S.legacyState, kcv: null };
    S.legacyItems = { items: [{ id: 'AAAAAAAAAAAAAAAAAAAAAA', kind: 'dir', name: JSON.stringify({ iv: b64urlFromBytes(randomBytes(12)), ct: b64urlFromBytes(randomBytes(40)) }) }], links: [], next: null };
    d = await openDrive();
    expect(d.legacy).toBeNull();
    expect(sessionStorage.getItem('secbin_dk')).toBeNull();
  });

  it('a new sub-MEK on the server: the next item is sealed under it after one retry; older items still open', async () => {
    install();
    const d = await openDrive();
    const old = await d.upload('root', fakeFile('old.txt', pattern(10)));
    const B = await S.addSub({ from: Math.floor(Date.now() / 1000) - 1 });
    const fresh = await d.mkdir('root', 'after the rotation');
    expect(S.nodes.get(fresh).mek).toBe(B.id);
    expect(S.requests.filter((r) => r.path === '/api/private/drive/keys')).toHaveLength(2); // fetched again once
    const kids = (await d.list('root')).children;
    expect(kids.map((c) => c.name).sort()).toEqual(['after the rotation', 'old.txt']);
    const dl = await d.download(old);
    expect(new Uint8Array(await (await dl.blob()).arrayBuffer())).toEqual(pattern(10));
  });

  it('a rename is sealed under the item’s own sub-MEK and salt; re-sealed meanwhile, it is read again', async () => {
    install();
    const d = await openDrive();
    const id = await d.mkdir('root', 'before');
    await d.rename(id, 'after');
    expect((await d.list('root')).children[0].name).toBe('after');
    // The server re-seals the item (a new salt) between the read and the write: one more try.
    const n = S.nodes.get(id);
    const orig = S.fetch.getMockImplementation();
    let once = true;
    S.fetch.mockImplementation(async (url, init = {}) => {
      if (once && init.method === 'PATCH') {
        once = false;
        return { ok: false, status: 409, type: 'basic', json: async () => ({ error: 'stale_keys', message: 'stale' }) };
      }
      return orig(url, init);
    });
    await d.rename(id, 'third');
    expect(S.nodes.get(id).ks).toBe(n.ks);
    expect((await d.list('root')).children[0].name).toBe('third');
  });

  it('an item of the release before (waiting for its upgrade) shows as waiting, never as broken data', async () => {
    install();
    const d = await openDrive();
    S.nodes.set('v'.repeat(22), { id: 'v'.repeat(22), parent: 'root', kind: 'file', v1: true, name: { iv: 'A'.repeat(16), ct: 'B'.repeat(40) }, fk: { iv: 'A'.repeat(16), ct: 'B'.repeat(64) }, size: 3, chunks: 1, state: 'ready' });
    const it = (await d.list('root')).children.find((c) => c.id === 'v'.repeat(22));
    expect(it).toMatchObject({ upgrading: true, unreadable: true, name: null });
    await expect(d.download(it.id)).rejects.toThrow(/upgrade/);
  });
});

describe('the personal kit', () => {
  it('download (the step-up), verify with a date (read-only, check values only); no restore', async () => {
    install();
    S.proof = 'proof-1';
    const d = await openDrive();
    await d.mkdir('root', 'x');
    await expect(buildPersonalKit({ user: S.user, passphrase: 'pp', step: {} })).rejects.toMatchObject({ code: 'reauth_required' });
    const kit = await buildPersonalKit({ user: S.user, passphrase: 'kit pass', step: { current: 'proof-1' } });
    expect(kit.keks).toBe(1);
    const env = parseDriveKit(kit.text);
    expect(env).toMatchObject({ kind: 'user', accountId: S.user.id });
    const payload = await openDriveKit(env, { kind: 'user', accountId: S.user.id, origin: location.origin, passphrase: 'kit pass' });
    expect(payload).toMatchObject({ v: 2, id: S.user.id, username: 'alice', userSalt: S.salt, current: S.current().id, keyVersion: S.keyVersion.n });
    expect(kit.keyVersion).toBe(1);
    expect(kit.status).toMatchObject({ version: 1, last: { version: 1 }, stale: false });
    expect(payload.keks[0].kek).toBe(b64urlFromBytes(await S.kekOf(S.current().id)));
    // Verify: nothing but check values leaves the page.
    const before = S.requests.length;
    const v = await verifyPersonalKit({ user: S.user, text: kit.text, passphrase: 'kit pass' });
    expect(v.verdict).toBe('complete');
    expect(v.checks.map((c) => [c.id, c.status])).toEqual([['format', 'pass'], ['auth', 'pass'], ['salt', 'pass'], ['keks', 'pass'], ['date', 'pass'], ['version', 'pass']]);
    expect(v).toMatchObject({ keyVersion: 1, version: 1 });
    const sent = JSON.stringify(S.requests.slice(before).map((r) => r.body));
    expect(sent).not.toContain(payload.keks[0].kek);
    expect(sent).not.toContain(S.salt);
    // A date when a later sub-MEK (not in the kit) is in effect: a warning, and the fix.
    const later = await S.addSub({ from: Math.floor(Date.now() / 1000) + 30 * 86400 });
    const v2 = await verifyPersonalKit({ user: S.user, text: kit.text, passphrase: 'kit pass', date: Math.floor(Date.now() / 1000) + 40 * 86400 });
    expect(v2.atDate).toMatchObject({ mekId: later.id, inKit: false });
    expect(v2.checks.find((c) => c.id === 'date').status).toBe('warn');
    // The keys changed after the kit (a sub-MEK added): its version is older than the server's, said as a warning.
    expect(v2.checks.find((c) => c.id === 'version')).toMatchObject({ status: 'warn', detail: expect.stringMatching(/Version 1; the keys are now version 2/) });
    // A wrong passphrase, another account's kit: failed before anything is sent.
    expect((await verifyPersonalKit({ user: S.user, text: kit.text, passphrase: 'wrong' })).verdict).toBe('failed');
    const other = await sealDriveKit('user', { ...payload }, { accountId: 'someoneelse00000', origin: location.origin, passphrase: '' });
    expect((await verifyPersonalKit({ user: S.user, text: other, passphrase: '' })).checks[0]).toMatchObject({ id: 'format', status: 'fail' });
    // No restore from here: only the owner restores from a personal kit (Admin → Security → Keys, keysclient.js).
    expect(Object.keys(await import('../public/js/driveclient.js'))).not.toContain('restorePersonalKit');
    // Never while the owner acts as the user.
    await expect(buildPersonalKit({ user: { ...S.user, impersonating: true }, step: { current: 'proof-1' } })).rejects.toMatchObject({ code: 'impersonating' });
  }, 60000);
});

describe('files and folders', () => {
  it('names are sealed on the wire, decrypted on list, sorted folders first, with the path', async () => {
    install();
    const d = await openDrive();
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

  it('a sealed name moved to another item does not open with that item’s salt; the item id itself is not bound (docs/DRIVE.md §9)', async () => {
    install();
    const d = await openDrive();
    const a = await d.mkdir('root', 'alpha');
    const b = await d.mkdir('root', 'beta');
    S.nodes.get(b).name = S.nodes.get(a).name;
    let kids = (await d.list('root')).children;
    expect(kids.find((c) => c.id === a).name).toBe('alpha');
    expect(kids.find((c) => c.id === b)).toMatchObject({ name: null, unreadable: true });
    // With its salt moved too, it opens: a DEK or a name is bound to the user, the sub-MEK and the salt, not to the item id.
    S.nodes.get(b).ks = S.nodes.get(a).ks;
    kids = (await d.list('root')).children;
    expect(kids.find((c) => c.id === b).name).toBe('alpha');
  }, 30000);

  it('uploads in exact chunks (8 MiB + tag, no padding) and downloads the same bytes', async () => {
    install();
    const d = await openDrive();
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

  // Audit B I4: the ciphertext hash the server records (nodes.ch) is checked on download: a file whose
  // stored chunks do not give it is refused, its last chunk never handed over.
  it('a download checks the chunks against the recorded ciphertext hash, and refuses a file that does not match', async () => {
    install();
    const d = await openDrive();
    const size = CHUNK + 999;
    const bytes = pattern(size, 3);
    const id = await d.upload('root', fakeFile('two.bin', bytes, 'application/octet-stream'));
    const n = S.nodes.get(id);
    const hs = [];
    for (let i = 0; i < n.chunks; i++) hs.push(await chunkHash(S.chunks.get(`${id}/${i}`)));
    n.ch = await ciphertextHash(n.chunks, (i) => hs[i]);
    const got = new Uint8Array(await (await (await d.download(id)).blob()).arrayBuffer());
    expect(Buffer.from(got).equals(Buffer.from(bytes))).toBe(true);
    // A hash that is not the stored chunks' (the record or the chunks changed): refused before the end.
    n.ch = await ciphertextHash(n.chunks, (i) => (i === 1 ? hs[0] : hs[i]));
    const seen = [];
    await expect((await d.download(id)).blob((k) => seen.push(k))).rejects.toThrow(/does not match the hash/);
    expect(seen).toEqual([CHUNK]); // the first chunk only: the last one was never handed over
    // No hash recorded yet (a file from before the chunk hashes): read as before.
    n.ch = null;
    expect(new Uint8Array(await (await (await d.download(id)).blob()).arrayBuffer()).length).toBe(size);
  }, 60000);

  it('an empty file has no chunks; a failed upload deletes its node; uploadTree builds folders', async () => {
    install();
    const d = await openDrive();
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
    const d = await openDrive();
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
    const d = await openDrive();
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
    // Each entry's key is the file's DEK.
    const n1 = S.nodes.get(f1);
    expect(files[0].fk).toBe(b64urlFromBytes(await openDek(await S.kekOf(n1.mek), { userId: S.user.id, mekId: n1.mek, salt: n1.ks }, n1.dek)));
    expect(Buffer.from(await reader.bytes(files[1])).equals(Buffer.from(two))).toBe(true);
    expect(Buffer.from(await reader.bytes(files[0])).equals(Buffer.from(one))).toBe(true);
    expect((await d.shares(photos)).map((x) => x.id)).toEqual(['fSHARE1']); // a folder's shares: those of the files under it
  }, 60000);

  it('a password share needs the password; policy limits are applied and declared', async () => {
    install();
    const d = await openDrive();
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
