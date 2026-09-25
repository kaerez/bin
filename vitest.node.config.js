// Vitest configuration for the plain-Node suites (test-node/).
//
// The shared client crypto (Argon2id via WebAssembly) cannot run inside the
// workerd pool — workerd forbids runtime WASM compilation, and the Worker never
// runs it anyway — so the protocol vectors, Argon2id KATs and the file-share /
// ZIP / MIME modules are exercised here, on Node's Web Crypto and streams, the
// same way the CLI runs them.
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test-node/**/*.test.js'],
    testTimeout: 30000,
  },
});
