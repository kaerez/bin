// reverse.test.js — the crypto of reverse shares (docs/REVERSE.md §3) on
// Node's Web Crypto and the real Argon2id: the link key pair and its private
// key sealed with the Drive key, the link proof, the password gate (bound to
// the link's public key), the note, and the full round trip — the uploader's
// client (public/js/reverseclient.js) encrypts files against a stand-in API,
// the user's side unwraps each one and re-wraps it into the Drive's own
// format, and the content decrypts with the re-wrapped key.
import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import {
  createReverseKey, sealReversePriv, openReversePriv, linkProof, linkHash, passwordGate, passwordProof, sealNote, openNote,
  sealUpload, openUpload, pubFromFragment, fragmentOf, newReverseId, newNodeId, REVERSE_ID_RE,
} from '../public/js/reversekeys.js';
import { openLink, parseLink, checkFiles, cleanPath, LinkError } from '../public/js/reverseclient.js';
import { createDriveKey, deriveSubkeys, sealField, openField } from '../public/js/drivekeys.js';
import { DecryptError } from '../public/js/crypto.js';
import { ApiError } from '../public/js/api.js';
import { randomBytes, fromUtf8, utf8, bytesFromB64url, b64urlFromBytes } from '../public/js/bytes.js';
import { CHUNK, decryptChunk, importFileKey } from '../public/js/files.js';

const sha = (b64) => createHash('sha256').update(bytesFromB64url(b64)).digest('base64url');

describe('the link key pair', () => {
  it('the public key is the fragment; the private key is sealed with DK and bound to the share', async () => {
    const dk = createDriveKey();
    const id = newReverseId();
    expect(id).toMatch(REVERSE_ID_RE);
    const { pub, privateKey } = await createReverseKey();
    expect(pub.length).toBe(65);
    const frag = fragmentOf(pub);
    expect(frag).toHaveLength(87);
    expect(Buffer.from(pubFromFragment(`#${frag}`)).equals(Buffer.from(pub))).toBe(true);
    expect(pubFromFragment('abc')).toBeNull();
    expect(pubFromFragment(`${frag.slice(0, -1)}!`)).toBeNull();
    const sealed = await sealReversePriv(dk, id, privateKey);
    expect(Object.keys(sealed).sort()).toEqual(['ct', 'iv']);
    const back = await openReversePriv(dk, id, sealed);
    expect(Buffer.from(back.pub).equals(Buffer.from(pub))).toBe(true); // the link can be shown again
    expect(back.privateKey.extractable).toBe(false);
    await expect(openReversePriv(createDriveKey(), id, sealed)).rejects.toThrow(DecryptError);
    await expect(openReversePriv(dk, newReverseId(), sealed)).rejects.toThrow(DecryptError);
    // The files sub-key seals it: the names key does not open it.
    const { names } = await deriveSubkeys(dk);
    await expect(openField(names, 'reversePriv', id, sealed)).rejects.toThrow(DecryptError);
  });

  it('the link proof is derived from the public key; the server keeps its SHA-256', async () => {
    const { pub } = await createReverseKey();
    const lp = await linkProof(pub);
    expect(lp).toHaveLength(43);
    expect(await linkProof(pub)).toBe(lp);
    expect(await linkHash(pub)).toBe(sha(lp));
    expect(await linkProof((await createReverseKey()).pub)).not.toBe(lp);
  });

  it('the password gate: Argon2id, bound to the link\'s public key; the server keeps only a hash', async () => {
    const { pub } = await createReverseKey();
    const gate = await passwordGate('correct horse', pub, 1);
    expect(gate.t).toBe(1);
    expect(bytesFromB64url(gate.salt)).toHaveLength(16);
    const proof = await passwordProof('correct horse', gate.salt, 1, pub);
    expect(sha(proof)).toBe(gate.ph);
    expect(sha(await passwordProof('correct horse!', gate.salt, 1, pub))).not.toBe(gate.ph);
    // NFC: the same password typed either way.
    const g2 = await passwordGate('café', pub, 1);
    expect(sha(await passwordProof('café', g2.salt, 1, pub))).toBe(g2.ph);
    // Without the link's key the same password gives another proof: the server's data alone cannot be checked against guesses.
    const other = (await createReverseKey()).pub;
    expect(await passwordProof('correct horse', gate.salt, 1, other)).not.toBe(proof);
    await expect(passwordProof('', gate.salt, 1, pub)).rejects.toThrow(TypeError);
    await expect(passwordProof('x', gate.salt, 99, pub)).rejects.toThrow(TypeError);
  });

  it('the note opens only with the link\'s key and only for its share', async () => {
    const { pub } = await createReverseKey();
    const id = newReverseId();
    const n = await sealNote(pub, id, 'Please send the signed contract.');
    expect(await openNote(pub, id, n)).toBe('Please send the signed contract.');
    await expect(openNote((await createReverseKey()).pub, id, n)).rejects.toThrow(DecryptError);
    await expect(openNote(pub, newReverseId(), n)).rejects.toThrow(DecryptError);
    expect(await openNote(pub, id, await sealNote(pub, id, 'x'.repeat(5000)))).toHaveLength(1000);
  });
});

describe('one upload', () => {
  it('path and metadata under a metadata key; file key and metadata key wrapped to the public key', async () => {
    const { pub, privateKey } = await createReverseKey();
    const id = newReverseId();
    const node = newNodeId();
    const fk = randomBytes(32);
    const s = await sealUpload(pub, id, node, fk, { path: 'Scans/März/page 1.png', type: 'image/png', mtime: 1700000000000, size: 12 });
    expect(s.wrap).toMatch(/^1\.[A-Za-z0-9_-]{87}\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{107}$/);
    const item = { id: node, name: s.name, meta: s.meta, fk: { kind: 'rs', data: s.wrap } };
    const got = await openUpload(privateKey, id, item);
    expect(got).toMatchObject({ path: 'Scans/März/page 1.png', type: 'image/png', mtime: 1700000000000, size: 12 });
    expect(Buffer.from(got.fk).equals(Buffer.from(fk))).toBe(true);
    // Every value is bound: another share, another node, a swapped name, another key.
    await expect(openUpload(privateKey, newReverseId(), item)).rejects.toThrow(DecryptError);
    await expect(openUpload(privateKey, id, { ...item, id: newNodeId() })).rejects.toThrow(DecryptError);
    const s2 = await sealUpload(pub, id, node, fk, { path: 'other.txt', type: 'text/plain', mtime: 0, size: 1 });
    await expect(openUpload(privateKey, id, { ...item, name: s2.name })).rejects.toThrow(DecryptError);
    await expect(openUpload((await createReverseKey()).privateKey, id, item)).rejects.toThrow(DecryptError);
    await expect(openUpload(privateKey, id, { ...item, fk: { kind: 'rs', data: '2.x.y.z' } })).rejects.toThrow(DecryptError);
    await expect(openUpload(privateKey, id, { ...item, fk: s.name })).rejects.toThrow(DecryptError);
    // Each wrap uses a fresh ephemeral key.
    expect((await sealUpload(pub, id, node, fk, { path: 'a', type: 'x/y', mtime: 0, size: 0 })).wrap.split('.')[1]).not.toBe(s.wrap.split('.')[1]);
  });
});

/** A stand-in for /api/reverse/<id>/… that keeps what the real server would. */
function fakeApi({ pub, id, password = null, limits = {} }) {
  const S = { files: new Map(), chunks: new Map(), begun: [], done: 0, cancelled: [] };
  S.api = {
    async open(rid, lp) {
      if (rid !== id) throw new ApiError('Not found.', 404, 'not_found');
      if (lp !== await linkProof(pub)) throw new ApiError('bad link', 403, 'bad_link');
      return { note: null, password: password ? { salt: password.salt, t: password.t } : null, expires: 2e9, limits: { maxFiles: null, maxBytes: null, maxFileBytes: null, types: null, filesLeft: null, bytesLeft: null, ...limits } };
    },
    async begin(rid, { linkProof: lp, keyProof, turnstile }) {
      S.begun.push({ lp, keyProof, turnstile });
      if (password && sha(keyProof || 'AA') !== password.ph) throw new ApiError('Wrong password.', 403, 'bad_password');
      return { grant: 'g'.repeat(43), expires: 2e9 };
    },
    async createFile(rid, grant, body) {
      S.files.set(body.id, { ...body, done: false });
      return { id: body.id, uploadToken: 't'.repeat(43), chunks: Math.ceil(body.size / CHUNK) };
    },
    async putChunk(rid, node, i, bytes) { S.chunks.set(`${node}/${i}`, bytes.slice()); return { ok: true }; },
    async finalize(rid, grant, node) { S.files.get(node).done = true; return { ok: true }; },
    async cancel(rid, grant, node) { S.cancelled.push(node); return { ok: true }; },
    async done() { S.done++; return { files: [...S.files.values()].filter((f) => f.done).length, bytes: 0 }; },
  };
  return S;
}

describe('the round trip', () => {
  it('the uploader encrypts files and folders; the user unwraps, re-wraps into the Drive format and reads them', async () => {
    const dk = createDriveKey();
    const id = newReverseId();
    const { pub, privateKey } = await createReverseKey();
    const gate = await passwordGate('pw-123', pub, 1);
    const S = fakeApi({ pub, id, password: gate });
    const up = await openLink({ pathname: `/r/${id}`, hash: `#${fragmentOf(pub)}`, api: S.api });
    expect(up.needsPassword).toBe(true);
    await expect(up.begin({ password: 'wrong' })).rejects.toMatchObject({ code: 'bad_password' });
    await up.begin({ password: 'pw-123', turnstile: 'tok' });
    expect(S.begun.at(-1).turnstile).toBe('tok');
    const big = new Uint8Array(CHUNK + 777).map((_, i) => (i * 13) & 0xff);
    const entries = [
      { path: 'report.txt', file: new Blob([utf8('quarterly numbers')], { type: 'text/plain' }) },
      { path: 'photos/2026/big.bin', file: new Blob([big]) },
      { path: 'empty.txt', file: new Blob([]) },
    ];
    let last = 0;
    const r = await up.upload(entries, { onProgress: (d, t) => { expect(d).toBeGreaterThanOrEqual(last); last = d; expect(t).toBe(17 + big.length); } });
    expect(r).toEqual({ files: 3, bytes: 17 + big.length });
    await up.done();
    expect(S.done).toBe(1);
    // Nothing on the wire names a file.
    const wire = JSON.stringify([...S.files.values()]);
    for (const w of ['report', 'photos', 'big.bin', 'quarterly', 'text/plain']) expect(wire).not.toContain(w);
    // The user's side: the sealed private key (from the server) opens with DK.
    const sealedPriv = await sealReversePriv(dk, id, privateKey);
    const { privateKey: priv } = await openReversePriv(dk, id, sealedPriv);
    const keys = await deriveSubkeys(dk);
    const out = new Map();
    for (const f of S.files.values()) {
      const item = { id: f.id, name: f.name, meta: f.meta, fk: { kind: 'rs', data: f.wrap } };
      const got = await openUpload(priv, id, item);
      // Re-wrap into the Drive's own format (what driveclient.receivePending sends).
      const leaf = got.path.slice(got.path.lastIndexOf('/') + 1);
      const name = await sealField(keys.names, 'name', f.id, leaf);
      const fkField = await sealField(keys.files, 'fk', f.id, got.fk);
      // …and read the file back as the Drive does: the chunks were never re-encrypted.
      const fk = await openField(keys.files, 'fk', f.id, fkField);
      const key = await importFileKey(b64urlFromBytes(fk));
      const n = Math.ceil(f.size / CHUNK);
      const parts = [];
      for (let i = 0; i < n; i++) parts.push(await decryptChunk(key, i, n, S.chunks.get(`${f.id}/${i}`)));
      out.set(got.path, { name: fromUtf8(await openField(keys.names, 'name', f.id, name)), bytes: Buffer.concat(parts), type: got.type });
    }
    expect([...out.keys()].sort()).toEqual(['empty.txt', 'photos/2026/big.bin', 'report.txt']);
    expect(out.get('report.txt')).toMatchObject({ name: 'report.txt', type: 'text/plain' });
    expect(out.get('report.txt').bytes.toString()).toBe('quarterly numbers');
    expect(out.get('photos/2026/big.bin').bytes.equals(Buffer.from(big))).toBe(true);
    expect(out.get('photos/2026/big.bin').name).toBe('big.bin');
    expect(out.get('empty.txt').bytes.length).toBe(0);
  });

  it('a failed upload is cancelled (its reservation given back); a bad link never reaches the server', async () => {
    const id = newReverseId();
    const { pub } = await createReverseKey();
    const S = fakeApi({ pub, id });
    S.api.putChunk = async () => { throw new ApiError('gone', 410, 'gone'); };
    const up = await openLink({ pathname: `/r/${id}`, hash: fragmentOf(pub), api: S.api });
    await up.begin({});
    await expect(up.upload([{ path: 'a.txt', file: new Blob([utf8('x')]) }])).rejects.toMatchObject({ status: 410 });
    expect(S.cancelled).toHaveLength(1);
    expect(() => parseLink(`/r/${id}`, '')).toThrow(LinkError);
    expect(() => parseLink('/r/bad', fragmentOf(pub))).toThrow(LinkError);
    await expect(openLink({ pathname: `/r/${id}`, hash: fragmentOf((await createReverseKey()).pub), api: S.api })).rejects.toThrow(LinkError);
  });

  it('checkFiles applies the link\'s limits before anything is sent', () => {
    const f = (path, n) => ({ path, file: new Blob([new Uint8Array(n)]) });
    expect(checkFiles([], {}).ok).toBe(false);
    expect(checkFiles([f('a.txt', 5)], {})).toEqual({ ok: true, count: 1, bytes: 5 });
    expect(checkFiles([f('a.txt', 5), f('b.txt', 5)], { filesLeft: 1 }).error).toMatch(/1 more file/);
    expect(checkFiles([f('a.txt', 5)], { filesLeft: 0 }).error).toMatch(/does not accept any more/);
    expect(checkFiles([f('a.txt', 5)], { bytesLeft: 4 }).ok).toBe(false);
    expect(checkFiles([f('a.txt', 5)], { maxFileBytes: 4 }).error).toMatch(/larger than/);
    expect(checkFiles([f('a.exe', 5)], { types: { mode: 'allow', rules: ['ext:pdf'] } }).error).toMatch(/\.exe/);
    expect(checkFiles([f('a.pdf', 5)], { types: { mode: 'allow', rules: ['ext:pdf'] } }).ok).toBe(true);
    expect(checkFiles([f('a.pdf', 5)], { types: { mode: 'block', rules: ['ext:pdf'] } }).ok).toBe(false);
    expect(checkFiles([f('../x', 1)], {}).ok).toBe(false);
    expect(cleanPath('/lead/slash.txt')).toBe('lead/slash.txt');
    expect(() => cleanPath('a//b')).toThrow();
    expect(() => cleanPath(`${'x'.repeat(256)}.txt`)).toThrow();
  });
});
