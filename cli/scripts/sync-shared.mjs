#!/usr/bin/env node
// sync-shared.mjs — vendor the frozen shared modules into cli/vendor/.
//
// npm cannot pack files outside the package root, so the CLI ships byte-identical
// copies of the protocol modules public/js/{bytes,format,crypto,kdf,files,zip,mime,filepolicy,sharetypes}.js,
// the pinned hash-wasm Argon2id build (public/js/vendor/argon2.js → vendor/vendor/,
// so kdf.js's relative "./vendor/argon2.js" import resolves unchanged) with its
// license, @noble/hashes' pure-JS Argon2id (vendor/noble/, kdf.js's fallback), the repo LICENSE, and qrcode.js renamed to qrcode.cjs so Node's
// CommonJS loader takes the UMD module.exports branch. vendor/ is committed;
// runtime imports always point at ./vendor/, so dev, tests, and the published
// package resolve identically. public/js/ stays the single source of truth:
// this script re-aligns vendor/, and the vendor-drift test (plus `--check`, run
// by prepack) fails whenever the copies diverge.
import { copyFile, mkdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..', '..');
const cliRoot = path.resolve(here, '..');
const pub = path.join(repoRoot, 'public', 'js');

/** [source relative to public/js, destination relative to cli/] — keep in sync with test/vendor-drift.test.js. */
const SHARED = [
  ...['bytes.js', 'format.js', 'crypto.js', 'kdf.js', 'files.js', 'zip.js', 'mime.js', 'filepolicy.js', 'sharetypes.js'].map((f) => [f, `vendor/${f}`]),
  ['vendor/argon2.js', 'vendor/vendor/argon2.js'],
  ['vendor/argon2.LICENSE', 'vendor/vendor/argon2.LICENSE'],
  // kdf.js's pure-JavaScript fallback (only when WebAssembly is unavailable,
  // e.g. `node --jitless`), at the same relative path "./vendor/noble/".
  ...['argon2.js', 'blake2.js', '_blake.js', '_md.js', '_u64.js', 'utils.js', 'LICENSE'].map((f) => [`vendor/noble/${f}`, `vendor/vendor/noble/${f}`]),
  ['qrcode.js', 'vendor/qrcode.cjs'],
];

const COPIES = [
  ...SHARED.map(([src, dest]) => [path.join(pub, src), path.join(cliRoot, dest)]),
  [path.join(repoRoot, 'LICENSE'), path.join(cliRoot, 'LICENSE')],
];

const check = process.argv.includes('--check');

// Publishing only works from the monorepo: the drift check compares vendor/
// against ../../public/js, and prepack's vitest is hoisted from the root
// install. A standalone cli/ checkout must fail with a real explanation, not
// an ENOENT stack (or worse, skip the safety gate).
const sources = await Promise.all(COPIES.map(([src]) => readFile(src).catch(() => null)));
if (sources.some((s) => s === null)) {
  console.error('cannot find the shared sources in ../../public/js — this script (and npm publish,');
  console.error('whose prepack runs it) must run from a full monorepo checkout, not a standalone cli/ copy.');
  console.error('Clone https://github.com/kaerez/bin and publish from its cli/ directory.');
  process.exit(1);
}

let drifted = 0;
for (const [i, [src, dest]] of COPIES.entries()) {
  const rel = path.relative(cliRoot, dest);
  if (check) {
    const a = sources[i];
    const b = await readFile(dest).catch(() => null);
    if (b === null || !a.equals(b)) {
      console.error(`drift: ${rel} does not match ${path.relative(cliRoot, src)}`);
      drifted++;
    }
  } else {
    await mkdir(path.dirname(dest), { recursive: true });
    await copyFile(src, dest);
    console.log(`synced ${rel}`);
  }
}

if (drifted > 0) {
  console.error('vendored copies are stale — run: node scripts/sync-shared.mjs');
  process.exit(1);
}
