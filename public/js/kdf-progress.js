// kdf-progress.js — a progress indicator for slow password derivations.
//
// Argon2id normally runs through WebAssembly in well under a second. When the
// browser has WebAssembly turned off (iOS/macOS Lockdown Mode — which also
// disables the JavaScript JIT — or a policy that refuses it), kdf.js falls back
// to pure JavaScript, and one derivation can take from seconds to about a
// minute. This shows a live percentage while that runs (role="status", so
// screen readers announce it), and says why. Built with createElement /
// textContent only; styled by ".kdf-progress" in public/css/styles.css.
// It also registers the worker that runs that fallback off the main thread
// (public/js/kdf-worker.js). Import it once from each page's entry module.

import { onKdfProgress, setKdfWorkerFactory } from './kdf.js';
import { scriptURL } from './tt.js';

// Run the slow path off the main thread so this indicator can repaint.
setKdfWorkerFactory(() => (typeof Worker === 'function' ? new Worker(scriptURL('/js/kdf-worker.js'), { type: 'module', name: 'argon2id' }) : null));

let box = null;
let bar = null;
let pct = null;
let active = 0;

function build() {
  const d = document;
  box = d.createElement('div');
  box.className = 'kdf-progress';
  box.setAttribute('role', 'status');
  box.setAttribute('aria-live', 'polite');
  const title = d.createElement('div');
  title.className = 'kdf-progress-title';
  title.textContent = 'Deriving the key…';
  pct = d.createElement('span');
  pct.className = 'kdf-progress-pct';
  pct.textContent = '0%';
  title.append(' ', pct);
  bar = d.createElement('progress');
  bar.className = 'kdf-progress-bar';
  bar.max = 100;
  bar.value = 0;
  bar.setAttribute('aria-label', 'Key derivation progress');
  const why = d.createElement('div');
  why.className = 'kdf-progress-why';
  why.textContent = 'WebAssembly is turned off in this browser (for example by Lockdown Mode), so this runs in plain JavaScript and can take up to a minute. Excluding this site from Lockdown Mode makes it instant.';
  box.append(title, bar, why);
}

onKdfProgress(({ phase, fraction }) => {
  if (typeof document === 'undefined' || !document.body) return;
  if (phase === 'start') {
    active++;
    if (!box) build();
    bar.value = 0;
    pct.textContent = '0%';
    if (!box.isConnected) document.body.append(box);
  } else if (phase === 'progress' && box) {
    const v = Math.max(0, Math.min(100, Math.floor(fraction * 100)));
    if (bar.value !== v) { bar.value = v; pct.textContent = `${v}%`; }
  } else if (phase === 'end') {
    active = Math.max(0, active - 1);
    if (!active && box) box.remove();
  }
});
