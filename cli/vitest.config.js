// Vitest configuration for the secbin CLI.
//
// A second, separate vitest project: the root suites run inside workerd
// (vitest-pool-workers), but the CLI targets plain Node — these tests prove
// Node's WebCrypto + CompressionStream reproduce the frozen SPEC.md §11
// vectors byte-for-byte, and exercise the commands against a mocked API.
// Run from the repo root with `npm test`, or directly:
//   vitest run --config cli/vitest.config.js
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  root: fileURLToPath(new URL('.', import.meta.url)),
  test: {
    environment: 'node',
    include: ['test/**/*.test.js'],
    // Real Argon2id (64 MiB) and multi-chunk file round trips take a moment.
    testTimeout: 30000,
  },
});
