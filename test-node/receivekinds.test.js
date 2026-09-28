// receivekinds.test.js — what a "Receive" link may be sent (docs/REVERSE.md
// §3.1, public/js/receivekinds.js) on Node's Web Crypto: the accepted kinds
// (validation, links from before, which additions weaken a link), the
// encoding of a note, a link and a credential (bounded, checked as a
// recipient checks them), the kind marker read back fail-closed, the names
// and downloads the Drive gives them; the marker sealed to the link's key
// with the uploader's metadata (reversekeys.js) and carried by a Drive
// share's manifest (refsmanifest.js); and the uploader client's typed send
// (reverseclient.js), end to end against a stand-in API. Synthetic data only.
import { describe, it, expect } from 'vitest';
import {
  RECEIVE_KINDS, DEFAULT_ACCEPT, normalizeAccept, acceptOf, allowedKinds, widening, encodeItem, itemOf, itemName, nameDate, itemExt, withExt,
  itemExport, ITEM_MAX_BYTES, KIND_OPTIONS, KIND_ACTIONS, SECRET_EXPORT_WARNING,
} from '../public/js/receivekinds.js';
import { RECEIVE_UPLOAD_ACTIONS, ACTIONS, KINDS, quotaCovers } from '../public/js/quotakinds.js';
import { createReverseKey, sealUpload, openUpload, newReverseId, newNodeId, linkProof, fragmentOf } from '../public/js/reversekeys.js';
import { buildRefsManifest, validateRefsManifest } from '../public/js/refsmanifest.js';
import { openLink, checkItem, ITEM_OVERHEAD } from '../public/js/reverseclient.js';
import { ApiError } from '../public/js/api.js';
import { randomBytes, utf8, fromUtf8, b64urlFromBytes } from '../public/js/bytes.js';
import { CHUNK, decryptChunk, importFileKey } from '../public/js/files.js';

describe('the accepted kinds', () => {
  it('a non-empty list of files, note, url and secret, in that order; files only for a link from before', () => {
    expect(RECEIVE_KINDS).toEqual(['files', 'note', 'url', 'secret']);
    expect(normalizeAccept(['secret', 'files', 'files'])).toEqual(['files', 'secret']);
    for (const bad of [[], ['photo'], 'files', null, ['files', 1], new Array(9).fill('note')]) expect(() => normalizeAccept(bad), JSON.stringify(bad)).toThrow();
    expect(acceptOf({})).toEqual(DEFAULT_ACCEPT);
    expect(acceptOf({ accept: ['note'] })).toEqual(['note']);
    expect(acceptOf({ accept: ['bogus'] })).toEqual(['files']); // fail closed to what links always took
    expect(allowedKinds(['files', 'url'], { reverseFiles: true, reverseUrl: false })).toEqual(['files']);
    expect(Object.values(KIND_OPTIONS)).toEqual(['reverseFiles', 'reverseText', 'reverseUrl', 'reverseSecret']);
  });

  it('adding files, links or credentials widens a link; a note does not; removing never does', () => {
    expect(widening(['note'], ['note', 'files'])).toEqual(['files']);
    expect(widening(['files'], ['files', 'note'])).toEqual([]);
    expect(widening(['files'], ['url', 'secret'])).toEqual(['url', 'secret']);
    expect(widening(RECEIVE_KINDS, ['note'])).toEqual([]);
  });

  it('each kind of send is a quota action of its own, all under receive-upload and receive', () => {
    expect(Object.values(KIND_ACTIONS)).toEqual(RECEIVE_UPLOAD_ACTIONS);
    for (const a of RECEIVE_UPLOAD_ACTIONS) {
      expect(ACTIONS).toContain(a);
      expect(quotaCovers('receive-upload', a)).toBe(true);
      expect(quotaCovers('receive', a)).toBe(true);
      expect(quotaCovers('all', a)).toBe(false);
      expect(KINDS[a].gui).toBe(true);
    }
    expect(quotaCovers('receive-note', 'receive-url')).toBe(false);
    expect(ACTIONS).not.toContain('receive-upload'); // a kind now, not an action
  });
});

describe('an item\'s content', () => {
  it('a note: its text, a format of the composer\'s, an optional title', () => {
    const n = encodeItem('note', { text: '# hi', fmt: 'markdown', title: '  Minutes  ' });
    expect(fromUtf8(n.bytes)).toBe('# hi');
    expect(n.meta).toEqual({ kind: 'note', fmt: 'markdown', title: 'Minutes' });
    expect(n.type).toBe('text/markdown');
    expect(encodeItem('note', { text: 'x', fmt: 'html' }).meta).toEqual({ kind: 'note', fmt: 'plaintext' });
    expect(() => encodeItem('note', { text: '   ' })).toThrow(/Write the note/);
    expect(() => encodeItem('note', { text: 'x', title: 't'.repeat(201) })).toThrow(/title/);
    expect(() => encodeItem('note', { text: 'x'.repeat(ITEM_MAX_BYTES.note + 1) })).toThrow(/too long/);
  });

  it('a link: normalized, any scheme a recipient may be shown but the forbidden ones; never with credentials in it', () => {
    expect(fromUtf8(encodeItem('url', { url: ' https://EXAMPLE.com/a%20b ' }).bytes)).toBe('https://example.com/a%20b');
    expect(fromUtf8(encodeItem('url', { url: 'ssh://example.com/repo' }).bytes)).toBe('ssh://example.com/repo');
    for (const bad of ['javascript:alert(1)', 'data:text/html,x', 'https://user:pw@example.com/', 'not a link', '']) expect(() => encodeItem('url', { url: bad }), bad).toThrow();
  });

  it('a credential: the regular credential payload, at least one field', () => {
    const c = encodeItem('secret', { title: ' DB ', username: 'u', password: ' p ', notes: ' n ' });
    expect(JSON.parse(fromUtf8(c.bytes))).toEqual({ v: 1, title: 'DB', username: 'u', password: ' p ', notes: ' n ' });
    expect(() => encodeItem('secret', {})).toThrow(/at least one field/);
    expect(() => encodeItem('secret', { password: 'x'.repeat(4097) })).toThrow(/too long/);
    expect(() => encodeItem('files', {})).toThrow();
  });

  it('the kind marker read back fails closed: anything unknown is a file', () => {
    expect(itemOf({ kind: 'note', fmt: 'code', title: ' T ' })).toEqual({ kind: 'note', fmt: 'code', title: 'T' });
    expect(itemOf({ kind: 'note' })).toEqual({ kind: 'note', fmt: 'plaintext' });
    expect(itemOf({ kind: 'url', fmt: 'x' })).toEqual({ kind: 'url' });
    for (const m of [null, {}, { kind: 'files' }, { kind: 'script' }, { kind: ['note'] }, 'note']) expect(itemOf(m), JSON.stringify(m)).toBeNull();
  });

  it('names and downloads', () => {
    expect(nameDate(0)).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/);
    expect(nameDate(1700000000)).not.toContain('/');
    expect(itemName({ kind: 'url' }, 1700000000)).toBe(`Link from ${nameDate(1700000000)}`);
    expect(itemName({ kind: 'note', title: 'Plan' }, 1)).toBe('Plan');
    expect(itemExt({ kind: 'note', fmt: 'markdown' })).toBe('.md');
    expect(itemExt({ kind: 'secret' }, { stored: true })).toBe('.json');
    expect(withExt('a.MD', '.md')).toBe('a.MD');
    expect(itemExport({ kind: 'note', fmt: 'code' }, 'x', utf8('let a = 1'))).toEqual({ filename: 'x.txt', text: 'let a = 1' });
    // A link: a text file with the URL only, never an Internet Shortcut.
    expect(itemExport({ kind: 'url' }, 'L', utf8('https://example.com/'))).toEqual({ filename: 'L.txt', text: 'https://example.com/\n' });
    expect(() => itemExport({ kind: 'url' }, 'L', utf8('javascript:alert(1)'))).toThrow();
    const sec = itemExport({ kind: 'secret' }, 'C', utf8(JSON.stringify({ v: 1, username: 'u', notes: 'a\nb' })));
    expect(sec.filename).toBe('C.txt');
    expect(sec.text.startsWith(`${SECRET_EXPORT_WARNING}\n\nUser name: u\nNotes:\na\nb\n`)).toBe(true);
    expect(() => itemExport({ kind: 'secret' }, 'C', utf8('{"v":2}'))).toThrow();
  });
});

describe('the marker, sealed to the link\'s key', () => {
  it('rides in the uploader\'s sealed metadata and comes back only with the link\'s private key', async () => {
    const { pub, privateKey } = await createReverseKey();
    const id = newReverseId();
    const node = newNodeId();
    const fk = randomBytes(32);
    const s = await sealUpload(pub, id, node, fk, { path: 'Note', type: 'text/markdown', mtime: 1, size: 4, item: { kind: 'note', fmt: 'markdown', title: 'T', extra: 'dropped' } });
    expect(JSON.stringify(s)).not.toMatch(/note|markdown/);
    const got = await openUpload(privateKey, id, { id: node, ...s, fk: { kind: 'rs', data: s.wrap } });
    expect(got.item).toEqual({ kind: 'note', fmt: 'markdown', title: 'T' });
    const file = await sealUpload(pub, id, node, fk, { path: 'a.txt', type: 'text/plain', mtime: 1, size: 4 });
    expect((await openUpload(privateKey, id, { id: node, ...file, fk: { kind: 'rs', data: file.wrap } })).item).toBeNull();
  });

  it('a Drive share\'s manifest carries { kind, fmt? } per entry, checked strictly', () => {
    const fk = b64urlFromBytes(randomBytes(32));
    const m = buildRefsManifest({ files: [{ path: 'n.md', size: 1, type: 'text/markdown', mtime: 0, fk, item: { kind: 'note', fmt: 'markdown', title: 'x' } }, { path: 'c.json', size: 1, type: 'application/json', mtime: 0, fk, item: { kind: 'secret' } }] });
    expect(m.entries.map((e) => e.item)).toEqual([{ kind: 'note', fmt: 'markdown' }, { kind: 'secret' }]);
    const v = validateRefsManifest(m);
    expect(v.entries.filter((e) => !e.dir).map((e) => e.item)).toEqual([{ kind: 'note', fmt: 'markdown' }, { kind: 'secret' }]);
    const bad = (item) => ({ ...m, entries: [{ ...m.entries[0], item }] });
    for (const item of [{ kind: 'note' }, { kind: 'note', fmt: 'html' }, { kind: 'url', fmt: 'x' }, { kind: 'script' }, null, 'note']) expect(() => validateRefsManifest(bad(item)), JSON.stringify(item)).toThrow();
    const plain = { ...m.entries[0] };
    delete plain.item;
    expect(validateRefsManifest({ ...m, entries: [plain] }).entries[0].item).toBeUndefined(); // an ordinary file
  });
});

describe('the uploader\'s client: a typed send', () => {
  it('checks the item against the link\'s limits, declares only its kind, and sends one encrypted item', async () => {
    expect(checkItem('note', { text: 'hi' }, { bytesLeft: ITEM_OVERHEAD + 1 })).toMatchObject({ ok: false });
    expect(checkItem('note', { text: 'hi' }, { filesLeft: 0 })).toMatchObject({ ok: false });
    expect(checkItem('url', { url: 'nope' })).toMatchObject({ ok: false });
    const { pub, privateKey } = await createReverseKey();
    const id = newReverseId();
    const lp = await linkProof(pub);
    const calls = [];
    const stored = new Map();
    const api = {
      open: async (rid, proof) => { calls.push(['open', proof]); return { note: null, password: null, expires: null, accept: ['note', 'url'], limits: {} }; },
      begin: async (rid, b) => { calls.push(['begin', b.type]); if (!['note', 'url'].includes(b.type)) throw new ApiError('no', 403, 'kind_not_accepted'); return { grant: 'G'.repeat(43) }; },
      createFile: async (rid, grant, body) => { calls.push(['createFile', body]); stored.set(body.id, { body, chunks: [] }); return { id: body.id, uploadToken: 'T'.repeat(43), chunks: Math.ceil(body.size / CHUNK) }; },
      putChunk: async (rid, node, i, ct) => { stored.get(node).chunks[i] = ct; return { ok: true }; },
      finalize: async () => ({ ok: true }),
      cancel: async () => ({ ok: true }),
      done: async () => ({ files: 1, bytes: 0 }),
    };
    const up = await openLink({ pathname: `/r/${id}`, hash: `#${fragmentOf(pub)}`, api });
    expect(up.accept).toEqual(['note', 'url']);
    expect(calls[0][1]).toBe(lp);
    await expect(up.begin({ type: 'secret' })).rejects.toMatchObject({ code: 'kind_not_accepted' });
    await up.begin({ type: 'url' });
    const c = checkItem('url', { url: 'https://example.com/x' }, up.limits);
    expect(await up.sendItem('url', c)).toEqual({ files: 1, bytes: utf8('https://example.com/x').length });
    const [f] = [...stored.values()];
    expect(f.body.types).toBeUndefined();
    expect(JSON.stringify(f.body)).not.toMatch(/example|url/);
    const got = await openUpload(privateKey, id, { id: f.body.id, name: f.body.name, meta: f.body.meta, fk: { kind: 'rs', data: f.body.wrap } });
    expect(got).toMatchObject({ path: 'Link', item: { kind: 'url' }, size: 21 });
    const key = await importFileKey(b64urlFromBytes(got.fk));
    expect(fromUtf8(await decryptChunk(key, 0, 1, f.chunks[0]))).toBe('https://example.com/x');
    expect(calls.filter((x) => x[0] === 'begin').map((x) => x[1])).toEqual(['secret', 'url']);
  });
});
