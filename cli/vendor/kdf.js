// kdf.js — Argon2id password stretching (RFC 9106) for the browser and CLI.
//
// Wraps the vendored hash-wasm Argon2 build (public/js/vendor/argon2.js, pinned
// and reproducible via tools/vendor.mjs). WebAssembly compilation needs the CSP
// source 'wasm-unsafe-eval' (it does not permit JavaScript eval). The Worker
// never runs this: workerd forbids runtime WASM compilation, and the server only
// ever sees derived values.

import { argon2id } from './vendor/argon2.js';
import { ARGON2 } from './format.js';

/**
 * Argon2id(password, salt) → 32 raw bytes.
 * `password` and `salt` are Uint8Arrays; the caller NFC-normalizes and UTF-8
 * encodes the password. `t` is the time cost; memory/lanes are protocol constants
 * unless overridden (tests only).
 */
export async function argon2idRaw(password, salt, { t = ARGON2.tDefault, mKiB = ARGON2.mKiB, p = ARGON2.p } = {}) {
  if (!(password instanceof Uint8Array) || !(salt instanceof Uint8Array)) throw new TypeError('bytes expected');
  if (!Number.isInteger(t) || t < 1) throw new RangeError('invalid t');
  return argon2id({
    password,
    salt,
    parallelism: p,
    iterations: t,
    memorySize: mKiB,
    hashLength: 32,
    outputType: 'binary',
  });
}
