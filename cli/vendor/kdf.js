// kdf.js — Argon2id password stretching (RFC 9106) for the browser and CLI.
//
// Two implementations of the same function, byte-for-byte:
//   • the vendored hash-wasm Argon2 build (public/js/vendor/argon2.js) — the
//     normal path. WebAssembly compilation needs the CSP source
//     'wasm-unsafe-eval' (it does not permit JavaScript eval);
//   • @noble/hashes' pure-JavaScript Argon2id (public/js/vendor/noble/) — used
//     only when WebAssembly is missing or refused, e.g. iOS/macOS Lockdown Mode
//     (which also turns the JavaScript JIT off, so it is much slower there).
// Both are pinned and reproducible via tools/vendor.mjs. The Worker never runs
// this: workerd forbids runtime WASM compilation, and the server only ever sees
// derived values.

import { argon2id } from './vendor/argon2.js';
import { ARGON2 } from './format.js';

const listeners = new Set();
let workerFactory = null;

/**
 * Browser pages register how to start public/js/kdf-worker.js (a Trusted
 * Types-minted module worker); the pure-JavaScript Argon2id then runs off the
 * main thread. Without a factory (the CLI, tests) it runs inline, yielding to
 * the event loop between slices.
 */
export function setKdfWorkerFactory(factory) {
  workerFactory = typeof factory === 'function' ? factory : null;
}

/**
 * Observe slow derivations (browser UI only; see public/js/kdf-progress.js).
 * `fn({ phase: 'start' | 'progress' | 'end', fraction })` is called only on the
 * pure-JavaScript path, where one derivation can take many seconds.
 * Returns an unsubscribe function.
 */
export function onKdfProgress(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function emit(phase, fraction) {
  for (const fn of listeners) {
    try { fn({ phase, fraction }); } catch { /* a UI listener must never break the KDF */ }
  }
}

let wasmState; // undefined → not probed, true/false afterwards

/** True when this runtime can compile WebAssembly at all (probed once). */
export function wasmAvailable() {
  if (wasmState === undefined) {
    try {
      // The smallest valid module: magic + version.
      wasmState = typeof WebAssembly === 'object' && WebAssembly !== null
        && WebAssembly.validate(new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]));
    } catch {
      wasmState = false;
    }
  }
  return wasmState;
}

/**
 * Run one derivation in a worker → Promise<Uint8Array | null>, or null when no
 * worker could be created. A worker that fails to load resolves null (the
 * caller then runs inline); an Argon2id error inside it rejects.
 */
function inWorker(password, salt, t, mKiB, p) {
  let w;
  try { w = workerFactory && workerFactory(); } catch { w = null; }
  if (!w) return null;
  return new Promise((resolve, reject) => {
    const done = (fn, v) => { try { w.terminate(); } catch { /* already gone */ } fn(v); };
    w.onmessage = (e) => {
      const d = e.data || {};
      if (d.type === 'progress') emit('progress', Number(d.fraction) || 0);
      else if (d.type === 'done' && d.out instanceof Uint8Array && d.out.length === 32) done(resolve, d.out);
      else if (d.type === 'error') done(reject, new Error(`Argon2id failed: ${d.message}`));
    };
    w.onerror = (e) => { e.preventDefault?.(); done(resolve, null); };
    // Copies, not transfers: the caller keeps its buffers.
    w.postMessage({ password: password.slice(), salt: salt.slice(), t, m: mKiB, p });
  });
}

async function argon2idJs(password, salt, t, mKiB, p) {
  emit('start', 0);
  try {
    const viaWorker = inWorker(password, salt, t, mKiB, p);
    const out = viaWorker ? await viaWorker : null;
    if (out) return out;
    const { argon2idAsync } = await import('./vendor/noble/argon2.js');
    return await argon2idAsync(password, salt, {
      t, m: mKiB, p, dkLen: 32, maxmem: mKiB * 1024,
      asyncTick: 25, // yield to the event loop every ~25 ms
      onProgress: (fraction) => emit('progress', fraction),
    });
  } finally {
    emit('end', 1);
  }
}

/**
 * Argon2id(password, salt) → 32 raw bytes.
 * `password` and `salt` are Uint8Arrays; the caller NFC-normalizes and UTF-8
 * encodes the password. `t` is the time cost; memory/lanes are protocol constants
 * unless overridden (tests only). `forceJs` (tests only) skips WebAssembly.
 */
export async function argon2idRaw(password, salt, { t = ARGON2.tDefault, mKiB = ARGON2.mKiB, p = ARGON2.p, forceJs = false } = {}) {
  if (!(password instanceof Uint8Array) || !(salt instanceof Uint8Array)) throw new TypeError('bytes expected');
  if (!Number.isInteger(t) || t < 1) throw new RangeError('invalid t');
  if (!forceJs && wasmAvailable()) {
    try {
      return await argon2id({
        password,
        salt,
        parallelism: p,
        iterations: t,
        memorySize: mKiB,
        hashLength: 32,
        outputType: 'binary',
      });
    } catch (e) {
      // WebAssembly exists but compiling or instantiating was refused (a CSP
      // or an embedder policy) — fall through to the JavaScript build. Any
      // other failure (e.g. out of memory) would recur there too, so rethrow.
      if (!(e instanceof Error) || !/WebAssembly|wasm|CompileError|LinkError|not supported/i.test(`${e.name} ${e.message}`)) throw e;
      wasmState = false;
    }
  }
  return argon2idJs(password, salt, t, mKiB, p);
}
