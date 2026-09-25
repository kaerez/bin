// vendor-drift.test.js — the vendored copies in cli/vendor/ MUST stay
// byte-identical to public/js/ (the single source of truth for the frozen
// protocol). Any drift fails CI in the same run that changed the shared files.
// Re-align with: node cli/scripts/sync-shared.mjs
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';

// [source in public/js/, vendored path under cli/vendor/] — must match
// scripts/sync-shared.mjs. qrcode.js is renamed .cjs so Node's CommonJS loader
// takes its UMD module.exports branch; the Argon2id build keeps its relative
// location (vendor/vendor/) so kdf.js's "./vendor/argon2.js" import resolves.
const FILES = [
  ['bytes.js', 'bytes.js'],
  ['format.js', 'format.js'],
  ['crypto.js', 'crypto.js'],
  ['kdf.js', 'kdf.js'],
  ['files.js', 'files.js'],
  ['zip.js', 'zip.js'],
  ['mime.js', 'mime.js'],
  ['filepolicy.js', 'filepolicy.js'],
  ['sharetypes.js', 'sharetypes.js'],
  ['vendor/argon2.js', 'vendor/argon2.js'],
  ['vendor/argon2.LICENSE', 'vendor/argon2.LICENSE'],
  ...['argon2.js', 'blake2.js', '_blake.js', '_md.js', '_u64.js', 'utils.js', 'LICENSE'].map((f) => [`vendor/noble/${f}`, `vendor/noble/${f}`]),
  ['qrcode.js', 'qrcode.cjs'],
];

describe('vendored shared modules match public/js/', () => {
  for (const [source, vendored] of FILES) {
    it(`vendor/${vendored} is byte-identical`, async () => {
      const a = await readFile(fileURLToPath(new URL(`../../public/js/${source}`, import.meta.url)));
      const b = await readFile(fileURLToPath(new URL(`../vendor/${vendored}`, import.meta.url)));
      expect(
        b.equals(a),
        `cli/vendor/${vendored} has drifted from public/js/${source} — run: node cli/scripts/sync-shared.mjs`,
      ).toBe(true);
    });
  }

  it('cli/LICENSE is byte-identical to the repo LICENSE', async () => {
    const a = await readFile(fileURLToPath(new URL('../../LICENSE', import.meta.url)));
    const b = await readFile(fileURLToPath(new URL('../LICENSE', import.meta.url)));
    expect(
      b.equals(a),
      'cli/LICENSE has drifted from the repo LICENSE — run: node cli/scripts/sync-shared.mjs',
    ).toBe(true);
  });

  it('the vendored crypto resolves its Argon2id import in plain Node', async () => {
    const { argon2idRaw } = await import('../vendor/kdf.js');
    const out = await argon2idRaw(new TextEncoder().encode('pw'), new Uint8Array(16), { t: 1 });
    expect(out).toHaveLength(32);
  });
});
