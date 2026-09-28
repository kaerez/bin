// zip-slip.test.js (DOM) — received names are cleaned first, then checked
// again (A-1): a manifest path that passes checkPath raw but becomes unsafe
// once its hidden characters are removed (".", U+200B, "." → ".."; a leading
// U+200B segment → an absolute path) must never reach a ZIP.
//   - the recipient's viewer (public/js/view.js) refuses such a manifest and
//     shows nothing to save; a name with hidden characters that stays safe
//     opens under its cleaned name, marked "renamed";
//   - downloads.js saveZip refuses such names itself (and zip.js checks each
//     member again), so no archive is produced even from an unchecked reader.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect, afterEach, vi } from 'vitest';
import { b64urlFromBytes, randomBytes, utf8 } from '../public/js/bytes.js';
import { encryptPaste } from '../public/js/crypto.js';
import { CHUNK } from '../public/js/files.js';
import { saveZip } from '../public/js/downloads.js';

const T = 30000;
const Z = '\u200b';
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
const reply = (data, status = 200) => ({ ok: status < 400, status, type: 'basic', headers: new Headers(), json: async () => data, arrayBuffer: async () => new ArrayBuffer(0) });

afterEach(() => { vi.restoreAllMocks(); });

/** A v2 manifest over `paths` (one byte each). */
const manifestOf = (paths) => ({
  v: 2, fk: b64urlFromBytes(randomBytes(32)), chunk: CHUNK, total: paths.length, view: null,
  entries: paths.map((path, i) => ({ path, type: 'text/plain', size: 1, mtime: 0, off: i })),
});

describe('the viewer: received names are cleaned, then checked again', () => {
  const ID = `f${b64urlFromBytes(randomBytes(16))}`;
  async function openShare(paths) {
    const t = Math.floor(Date.now() / 1000);
    const enc = await encryptPaste({ text: JSON.stringify(manifestOf(paths)), fmt: 'files', expire: '1h' });
    const paste = { v: enc.body.v, ct: enc.body.ct, wk: enc.body.wk, adata: enc.body.adata, meta: { expire: '1h', created: t, expires: t + 3600 } };
    globalThis.fetch = vi.fn(async (url) => {
      const u = new URL(url, 'https://bin.example');
      if (u.pathname === `/api/file/${ID}`) return reply({ v: paste.v, adata: paste.adata, meta: paste.meta });
      if (u.pathname === `/api/file/${ID}/open`) return reply({ paste, grant: 'g'.repeat(43), chunks: 1, padded: 65536, grantExpires: t + 600, now: t });
      return reply({ error: 'not_found', message: 'x' }, 404);
    });
    window.happyDOM.setURL(`https://bin.example/p/${ID}#${enc.fragment}`);
    document.head.replaceChildren();
    document.body.innerHTML = mainOf('public/index.html');
    vi.resetModules();
    await import('../public/js/view.js');
  }
  const filesShown = () => !$('#view-files').hidden;

  for (const [what, path] of [['".", U+200B, "." segments (→ "../")', `docs/.${Z}./.${Z}./tmp/x.txt`], ['a leading U+200B segment (→ "/")', `${Z}/etc/x.txt`]]) {
    it(`refuses a manifest with ${what}: nothing is listed or can be saved`, async () => {
      await openShare(['ok.txt', path]);
      await until(() => /Could not decrypt this share/.test($('#status-msg').textContent));
      expect(filesShown()).toBe(false);
    }, T);
  }

  it('two names that clean to the same path refuse the manifest', async () => {
    await openShare(['a.txt', `a${Z}.txt`]);
    await until(() => /Could not decrypt this share/.test($('#status-msg').textContent));
    expect(filesShown()).toBe(false);
  }, T);

  it('a name whose hidden characters leave it safe opens under its cleaned name, marked renamed', async () => {
    await openShare(['plain.txt', `in\u202evoice${Z}.pdf`]);
    await until(() => filesShown() && $('#view-files').textContent.includes('invoice'));
    expect($('#view-files').textContent).not.toMatch(/[\u200b\u202e]/);
    expect(document.querySelectorAll('#view-files .renamed-note')).toHaveLength(1);
  }, T);
});

describe('saveZip checks each name itself (defence in depth)', () => {
  /** A reader as the viewer builds it, over entries that were never cleaned or re-checked. */
  const readerOf = (paths) => ({
    manifest: { entries: paths.map((path) => (path.endsWith('/') ? { path: path.slice(0, -1), dir: true } : { path, size: 1, mtime: 0, off: 0 })) },
    async *stream() { yield utf8('x'); },
  });
  const captureDownloads = () => {
    const blobs = [];
    URL.createObjectURL = vi.fn((b) => { blobs.push(b); return 'blob:x'; });
    URL.revokeObjectURL = vi.fn();
    return blobs;
  };

  for (const path of [`docs/.${Z}./.${Z}./tmp/x.txt`, `${Z}/etc/x.txt`, `a/${Z}/b.txt`, 'C:/x.txt', `.${Z}./`]) {
    it(`refuses ${JSON.stringify(path)}: no archive is produced`, async () => {
      const blobs = captureDownloads();
      await expect(saveZip(readerOf(['ok.txt', path]), '', 'x.zip')).rejects.toThrow();
      expect(blobs).toHaveLength(0);
    });
  }

  it('a safe tree is zipped under its cleaned names', async () => {
    const blobs = captureDownloads();
    await saveZip(readerOf(['docs/', `docs/in\u202evoice${Z}.pdf`, 'b.txt']), '', 'x.zip');
    expect(blobs).toHaveLength(1);
    const bytes = new Uint8Array(await blobs[0].arrayBuffer());
    const text = new TextDecoder().decode(bytes);
    expect(text).toContain('docs/invoice.pdf');
    expect(text).toContain('docs/');
    expect(text).not.toMatch(/[\u200b\u202e]/);
  });
});
