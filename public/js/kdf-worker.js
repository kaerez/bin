// kdf-worker.js — runs the pure-JavaScript Argon2id (@noble/hashes) off the
// main thread, so the page keeps painting its progress bar and stays
// responsive while a derivation takes up to about a minute (WebAssembly and
// the JIT off, e.g. iOS Lockdown Mode). Started by kdf.js through the factory
// public/js/kdf-progress.js registers (the worker URL is minted by the
// Trusted Types policy in tt.js; the CSP's worker-src 'self' covers it).
//
// Protocol: in  { password, salt, t, m, p }  (Uint8Arrays + integers)
//           out { type: 'progress', fraction }  (at most ~100 per run)
//               { type: 'done', out }  (32-byte Uint8Array, transferred)
//               { type: 'error', message }
// One job per worker; the caller terminates it afterwards.

import { argon2id } from './vendor/noble/argon2.js';

self.onmessage = (e) => {
  const { password, salt, t, m, p } = e.data || {};
  let last = -1;
  try {
    if (!(password instanceof Uint8Array) || !(salt instanceof Uint8Array)) throw new TypeError('bytes expected');
    const out = argon2id(password, salt, {
      t, m, p, dkLen: 32, maxmem: m * 1024,
      onProgress: (fraction) => {
        const pct = Math.floor(fraction * 100);
        if (pct !== last) { last = pct; self.postMessage({ type: 'progress', fraction }); }
      },
    });
    self.postMessage({ type: 'done', out }, [out.buffer]);
  } catch (err) {
    self.postMessage({ type: 'error', message: String((err && err.message) || err) });
  }
};
