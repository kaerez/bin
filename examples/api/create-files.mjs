#!/usr/bin/env node
// create-files.mjs — share files and folders end-to-end encrypted over REST
// from Node.js 22, using this repository's own protocol modules (the same code
// the browser runs). Run from a clone of the repository:
//
//   export SECBIN_API_KEY=sbk_...            # an API key with the "files" scope
//   node examples/api/create-files.mjs https://bin.example.com report.pdf photos/ --views 3 --expire 7d
//
// The upload flow (SPEC.md §12): POST /api/private/file (sizes only) → PUT
// every encrypted chunk → POST …/finalize with the encrypted manifest (names,
// types, sizes). The server never sees a name, a type or a byte of content.
//
// --encrypt-only <dir> (no server, no key): write the three request bodies to
// <dir> (init.json, chunk-<i>.bin, finalize.json) and print the fragment, for
// sending with another client such as curl (docs/API.md).
//
// Symlinks are skipped. The optional password comes from SECBIN_NOTE_PASSWORD.
import { parseArgs } from 'node:util';
import { lstat, mkdir, open, readdir, writeFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { encryptPaste } from '../../public/js/crypto.js';
import { layout, buildManifest, importFileKey, encryptChunk, readStreamChunk } from '../../public/js/files.js';
import { declare } from '../../public/js/filepolicy.js';
import { fromExtension, OCTET } from '../../public/js/mime.js';

const USAGE = 'usage: node create-files.mjs <server> <path>... [--views N|unlimited] [--expire 24h] [--label TEXT]\n       node create-files.mjs --encrypt-only <dir> <path>... [--views N|unlimited] [--expire 24h]';
let values, positionals;
try {
  ({ values, positionals } = parseArgs({
    allowPositionals: true,
    options: { views: { type: 'string', default: '1' }, expire: { type: 'string', default: '24h' }, label: { type: 'string', default: '' }, 'encrypt-only': { type: 'string' } },
  }));
} catch (e) { console.error(`${e.message}\n${USAGE}`); process.exit(2); }
const outDir = values['encrypt-only'];
const [server, ...paths] = outDir === undefined ? positionals : [null, ...positionals];
if (!paths.length) { console.error(USAGE); process.exit(2); }
const key = process.env.SECBIN_API_KEY || '';
if (outDir === undefined && !key.startsWith('sbk_')) { console.error('set SECBIN_API_KEY to an API key (sbk_...)'); process.exit(2); }
const views = values.views === 'unlimited' ? null : Number(values.views);

// ── collect: files (in stream order) and empty folders, as share paths ──────
const files = [];
const dirs = [];
async function walk(disk, rel) {
  const st = await lstat(disk);
  if (st.isSymbolicLink()) return;
  if (st.isFile()) { files.push({ disk, path: rel, size: st.size, type: fromExtension(rel) || OCTET, mtime: Math.floor(st.mtimeMs) }); return; }
  if (!st.isDirectory()) return;
  const names = (await readdir(disk)).sort();
  if (!names.length) dirs.push(rel);
  for (const n of names) await walk(join(disk, n), `${rel}/${n}`);
}
for (const p of paths) await walk(p, basename(p.replace(/\/+$/, '')));

const l = layout(files, dirs);
const manifest = buildManifest({ entries: l.entries, total: l.total, view: null });
const { body: paste, fragment } = await encryptPaste({
  text: JSON.stringify(manifest), fmt: 'files', password: process.env.SECBIN_NOTE_PASSWORD || '',
  bar: views !== null, views: views ?? undefined, expire: values.expire,
});
const init = { views, expire: values.expire, padded: l.padded, files: files.length, maxFile: Math.max(0, ...files.map((f) => f.size)) };
const fk = await importFileKey(manifest.fk);
const sources = files.map((f, i) => ({
  off: l.entries[i].off, size: f.size,
  read: async (a, b) => { const fh = await open(f.disk); try { const buf = Buffer.alloc(b - a); await fh.read(buf, 0, b - a, a); return new Uint8Array(buf); } finally { await fh.close(); } },
}));
const chunk = async (i) => encryptChunk(fk, i, l.chunks, await readStreamChunk(sources, i, l.total));

if (outDir !== undefined) {
  await mkdir(outDir, { recursive: true });
  await writeFile(join(outDir, 'init.json'), JSON.stringify(init));
  for (let i = 0; i < l.chunks; i++) await writeFile(join(outDir, `chunk-${i}.bin`), await chunk(i));
  await writeFile(join(outDir, 'finalize.json'), JSON.stringify({ paste, label: values.label }));
  console.log(`chunks: ${l.chunks}`);
  console.error(`fragment: ${fragment}`); // the link is <server>/p/<id>#<fragment>
  process.exit(0);
}

// ── upload ───────────────────────────────────────────────────────────────────
const base = server.replace(/\/+$/, '');
const auth = { authorization: `Bearer ${key}`, 'user-agent': 'secbin-example-node/1' };
async function call(path, init2) {
  const res = await fetch(`${base}${path}`, { redirect: 'error', ...init2, headers: { ...auth, ...init2.headers } });
  const out = await res.json().catch(() => ({}));
  if (!res.ok) { const e = new Error(`error ${res.status}: ${out.message || out.error || res.statusText}`); e.body = out; throw e; }
  return out;
}
const post = (path, body, headers = {}) => call(path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
async function upload() {
  let started;
  try {
    started = await post('/api/private/file', init);
  } catch (e) {
    // A file-type or folder-depth policy asks for more: declare it and retry.
    if (e.body?.error !== 'declaration_required') throw e;
    const { types, depth } = declare([...files, ...dirs.map((d) => ({ path: d, dir: true }))]);
    started = await post('/api/private/file', { ...init, types, depth });
  }
  const { id, uploadtoken, deletetoken } = started;
  try {
    for (let i = 0; i < l.chunks; i++) {
      await call(`/api/private/file/${id}/chunk/${i}`, { method: 'PUT', headers: { 'content-type': 'application/octet-stream', 'x-upload-token': uploadtoken }, body: await chunk(i) });
    }
    await post(`/api/private/file/${id}/finalize`, { paste, label: values.label }, { 'x-upload-token': uploadtoken });
  } catch (e) {
    // Remove the half-finished upload now rather than at the server's deadline.
    await fetch(`${base}/api/file/${id}`, { method: 'DELETE', headers: { 'x-delete-token': deletetoken } }).catch(() => {});
    throw e;
  }
  console.log(`${base}/p/${id}#${fragment}`);
  console.error(`delete token: ${deletetoken}`);
}
await upload().catch((e) => { console.error(e.message); process.exit(1); });
