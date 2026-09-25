// tt.js — the page's only Trusted Types policy.
//
// The CSP enforces `require-trusted-types-for 'script'` and allows exactly one
// policy, "secbin". It mints script URLs only for this origin's own /js/ scripts
// and the service worker, and refuses to create HTML or script strings at all,
// so no code path can turn a string into markup or code. Browsers without
// Trusted Types get the plain (already validated) URL string.

const ALLOWED_SCRIPT_PATH = /^\/(js\/[A-Za-z0-9._/-]+\.m?js|sw\.js)$/;

function checkScriptURL(input) {
  const url = new URL(String(input), location.origin);
  if (url.origin !== location.origin || !ALLOWED_SCRIPT_PATH.test(url.pathname) || url.search || url.hash) {
    throw new TypeError(`Refusing to load script from ${url.origin}${url.pathname}`);
  }
  return url.href;
}

const policy = globalThis.trustedTypes?.createPolicy
  ? globalThis.trustedTypes.createPolicy('secbin', {
    createScriptURL: checkScriptURL,
    createHTML: () => { throw new TypeError('HTML strings are not allowed'); },
    createScript: () => { throw new TypeError('Script strings are not allowed'); },
  })
  : null;

/** A same-origin script URL, as a TrustedScriptURL where Trusted Types exist. */
export function scriptURL(path) {
  return policy ? policy.createScriptURL(path) : checkScriptURL(path);
}
