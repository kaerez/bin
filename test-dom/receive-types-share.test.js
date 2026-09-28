// receive-types-share.test.js (DOM) — a Drive share's recipient page
// (public/js/view.js) and the notes, links and credentials it carries:
//   - RT-3: an entry is shown as a note, link or credential only where the
//     server says the sender's role allowed sharing that kind when the share
//     was made (`kinds` on the open); otherwise (or for a share made before
//     that record) it is a plain file: Download only, no Open, no card;
//   - RT-2: an item larger than its kind can be is never read or rendered;
//   - RT-4: a credential leaves in plain text only after a confirmed click,
//     and never inside a ZIP.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { b64urlFromBytes, randomBytes, fromUtf8, utf8 } from '../public/js/bytes.js';
import { encryptPaste } from '../public/js/crypto.js';
import { encryptChunk, importFileKey } from '../public/js/files.js';
import { buildRefsManifest, refChunks } from '../public/js/refsmanifest.js';
import { encodeItem, ITEM_MAX_BYTES, SECRET_EXPORT_WARNING } from '../public/js/receivekinds.js';

const T = 30000;
const until = async (fn, ms = 10000) => {
  const t0 = Date.now();
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 10));
  }
};
const $ = (s) => document.querySelector(s);
const read = (p) => readFileSync(join(process.cwd(), p), 'utf8');
const mainOf = (p) => `${read(p).match(/<main[\s\S]*<\/main>/)[0]}<div id="toast" role="status"></div>`;
const reply = (data, status = 200, bytes = null) => ({
  ok: status < 400, status, type: 'basic', headers: new Headers(), json: async () => data,
  arrayBuffer: async () => (bytes ? bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) : new ArrayBuffer(0)),
});

afterEach(() => { vi.restoreAllMocks(); });

const PASSWORD = 'not-a-real-password';
const note = encodeItem('note', { text: '# Plan\n\nSome **bold** words.', fmt: 'markdown' });
const link = encodeItem('url', { url: 'https://example.com/doc' });
const secret = encodeItem('secret', { title: 'DB', username: 'synthetic', password: PASSWORD });
const ENTRIES = [
  { path: 'Plan.md', bytes: note.bytes, type: note.type, item: note.meta },
  { path: 'Link.txt', bytes: link.bytes, type: 'text/plain', item: link.meta },
  { path: 'Credential.json', bytes: secret.bytes, type: 'application/json', item: secret.meta },
  { path: 'plain.txt', bytes: utf8('a plain file'), type: 'text/plain' },
];

/**
 * Open a Drive share (a v3 manifest, each file its own chunks under its own
 * key) whose open response carries `kinds` (omitted: a share made before the
 * record). `sizes` overrides an entry's declared size (its chunks are never
 * served then). → { chunkFetches, saved }.
 */
async function openShare({ kinds, entries = ENTRIES, sizes = {} } = {}) {
  const ID = `f${b64urlFromBytes(randomBytes(16))}`;
  const chunks = new Map();
  const files = [];
  for (const [ref, e] of entries.entries()) {
    const fk = b64urlFromBytes(randomBytes(32));
    const size = sizes[e.path] ?? e.bytes.length;
    if (!(e.path in sizes)) chunks.set(`${ref}/0`, await encryptChunk(await importFileKey(fk), 0, 1, e.bytes));
    files.push({ path: e.path, size, type: e.type, mtime: 0, fk, ...(e.item ? { item: e.item } : {}) });
  }
  const manifest = buildRefsManifest({ files, dirs: [], view: null });
  const t = Math.floor(Date.now() / 1000);
  const enc = await encryptPaste({ text: JSON.stringify(manifest), fmt: 'files', expire: '1h' });
  const paste = { v: enc.body.v, ct: enc.body.ct, wk: enc.body.wk, adata: enc.body.adata, meta: { expire: '1h', created: t, expires: t + 3600 } };
  const chunkFetches = [];
  globalThis.fetch = vi.fn(async (url) => {
    const u = new URL(url, 'https://bin.example');
    let m;
    if (u.pathname === `/api/file/${ID}`) return reply({ v: paste.v, adata: paste.adata, meta: paste.meta });
    if (u.pathname === `/api/file/${ID}/open`) {
      return reply({ paste, grant: 'g'.repeat(43), chunks: 0, padded: 0, grantExpires: t + 600, now: t,
        refs: files.map((f) => ({ chunks: refChunks(f.size), size: f.size })), ...(kinds === undefined ? {} : { kinds }) });
    }
    if ((m = u.pathname.match(new RegExp(`^/api/file/${ID}/chunk/(\\d+)/(\\d+)$`)))) {
      chunkFetches.push(`${m[1]}/${m[2]}`);
      const c = chunks.get(`${m[1]}/${m[2]}`);
      return c ? reply(null, 200, c) : reply({ error: 'not_found', message: 'x' }, 404);
    }
    return reply({ error: 'not_found', message: 'x' }, 404);
  });
  const saved = [];
  let blob = null;
  URL.createObjectURL = vi.fn((b) => { blob = b; return 'blob:x'; });
  URL.revokeObjectURL = vi.fn();
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function click() { saved.push({ name: this.download, blob }); });
  window.happyDOM.setURL(`https://bin.example/p/${ID}#${enc.fragment}`);
  document.head.replaceChildren();
  document.body.innerHTML = mainOf('public/index.html');
  vi.resetModules();
  await import('../public/js/view.js');
  await until(() => !$('#view-files').hidden && $('#files-tree').textContent.includes('plain.txt'));
  return { chunkFetches, saved };
}
const rowOf = (name) => [...document.querySelectorAll('#files-tree li.tree-file')].find((li) => li.querySelector('.tree-name').textContent === name);
const buttonOf = (root, text) => [...root.querySelectorAll('button')].find((b) => b.textContent.trim() === text);
const blobText = async (b) => fromUtf8(new Uint8Array(await b.arrayBuffer()));

describe('a Drive share\'s notes, links and credentials: shown only as the sender\'s role allowed (RT-3)', () => {
  it('all allowed: each opens in its viewer', async () => {
    await openShare({ kinds: { note: true, url: true, secret: true } });
    for (const name of ['Plan.md', 'Link.txt', 'Credential.json']) expect(buttonOf(rowOf(name), 'Open'), name).toBeDefined();
    buttonOf(rowOf('Plan.md'), 'Open').click();
    await until(() => $('#preview-body h1'));
    expect($('#preview-body h1').textContent).toBe('Plan');
    buttonOf(rowOf('Link.txt'), 'Open').click();
    await until(() => $('#preview-body .link-card'));
    expect($('#preview-body .link-full').textContent).toBe('https://example.com/doc');
  }, T);

  it('a share made before the record (no `kinds`): none is shown as a note, link or credential — plain files, Download only', async () => {
    const { saved } = await openShare({});
    for (const [name, what] of [['Plan.md', 'note'], ['Link.txt', 'link'], ['Credential.json', 'credential']]) {
      const row = rowOf(name);
      expect(buttonOf(row, 'Open'), name).toBeUndefined();
      expect(row.textContent, name).toContain(`not available as a ${what}`);
      expect(buttonOf(row, 'Download'), name).toBeDefined();
    }
    // Its bytes as they are (no export, no card).
    buttonOf(rowOf('Link.txt'), 'Download').click();
    await until(() => saved.length === 1);
    expect(saved[0].name).toBe('Link.txt');
    expect(await blobText(saved[0].blob)).toBe(fromUtf8(link.bytes));
    expect($('#preview-body .link-card')).toBeNull();
  }, T);

  it('links and credentials not allowed: those two are plain files; the note still opens', async () => {
    await openShare({ kinds: { note: true, url: false, secret: false } });
    expect(buttonOf(rowOf('Plan.md'), 'Open')).toBeDefined();
    expect(rowOf('Link.txt').textContent).toContain('not available as a link: this share may not show links');
    expect(rowOf('Credential.json').textContent).toContain('not available as a credential: this share may not show credentials');
    expect(buttonOf(rowOf('Link.txt'), 'Open')).toBeUndefined();
    expect(buttonOf(rowOf('Credential.json'), 'Open')).toBeUndefined();
  }, T);
});

describe('an item larger than its kind can be is never read or rendered (RT-2)', () => {
  it('Open says so and fetches none of it', async () => {
    const { chunkFetches } = await openShare({ kinds: { note: true, url: true, secret: true }, sizes: { 'Plan.md': ITEM_MAX_BYTES.note + 1 } });
    buttonOf(rowOf('Plan.md'), 'Open').click();
    await until(() => $('#preview-body .msg.error'));
    expect($('#preview-body').textContent).toMatch(/This note is larger than one can be, so it is not shown\./);
    expect($('#preview-body .md, #preview-body h1')).toBeNull();
    expect(chunkFetches.filter((c) => c.startsWith('0/'))).toEqual([]);
  }, T);
});

describe('a credential leaves in plain text only after a confirmation, never in a ZIP (RT-4)', () => {
  it('Download asks first; the export starts with its warning', async () => {
    const { saved } = await openShare({ kinds: { note: true, url: true, secret: true } });
    const btn = buttonOf(rowOf('Credential.json'), 'Download');
    expect(btn.getAttribute('aria-describedby')).toBe('files-secret-warning');
    expect($('#files-secret-warning').textContent).toContain(SECRET_EXPORT_WARNING);
    btn.click();
    expect(btn.textContent).toBe('Download in plain text?');
    await new Promise((r) => setTimeout(r, 50));
    expect(saved).toHaveLength(0); // nothing yet
    btn.click();
    await until(() => saved.length === 1);
    const text = await blobText(saved[0].blob);
    expect(text.startsWith(SECRET_EXPORT_WARNING)).toBe(true);
    expect(text).toContain(`Password: ${PASSWORD}`);
  }, T);

  it('a credential shown as a plain file (not allowed) also asks first', async () => {
    const { saved } = await openShare({ kinds: { note: true, url: true, secret: false } });
    const btn = buttonOf(rowOf('Credential.json'), 'Download');
    btn.click();
    await new Promise((r) => setTimeout(r, 50));
    expect(saved).toHaveLength(0);
    btn.click();
    await until(() => saved.length === 1);
  }, T);

  it('"Download all" leaves the credentials out and says so', async () => {
    const { saved, chunkFetches } = await openShare({ kinds: { note: true, url: true, secret: true } });
    expect($('#files-secret-warning').textContent).toMatch(/Credentials are left out of ZIP downloads/);
    $('#download-all').click();
    await until(() => saved.length === 1);
    expect(saved[0].name).toBe('secbin-files.zip');
    const zip = new TextDecoder('utf-8', { fatal: false }).decode(await saved[0].blob.arrayBuffer());
    expect(zip).toContain('Plan.md');
    expect(zip).toContain('plain.txt');
    expect(zip).not.toContain('Credential.json');
    expect(zip).not.toContain(PASSWORD);
    expect(chunkFetches).not.toContain('2/0'); // the credential was never even fetched
  }, T);
});
