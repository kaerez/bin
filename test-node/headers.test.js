// headers.test.js — the security headers Workers Static Assets serves
// (public/_headers) must be exactly the set the Worker applies to what it
// serves itself (src/lib/http.js), and the CSP must keep its core guarantees.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { SECURITY_HEADERS, CSP } from '../src/lib/http.js';

function staticHeaders() {
  const text = readFileSync(new URL('../public/_headers', import.meta.url), 'utf8');
  const lines = text.split('\n');
  const start = lines.indexOf('/*');
  const out = {};
  for (const line of lines.slice(start + 1)) {
    if (!line.startsWith('  ')) break;
    const i = line.indexOf(':');
    out[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
  }
  return out;
}

describe('security headers', () => {
  it('public/_headers matches the Worker header set exactly', () => {
    expect(staticHeaders()).toEqual(SECURITY_HEADERS);
  });

  it('the CSP keeps its core guarantees', () => {
    const d = Object.fromEntries(CSP.split(';').map((p) => p.trim().split(/\s+/)).map(([k, ...v]) => [k, v]));
    expect(d['default-src']).toEqual(["'none'"]);
    expect(d['script-src']).toEqual(["'self'", "'wasm-unsafe-eval'"]); // no 'unsafe-inline', no 'unsafe-eval'
    expect(d['frame-ancestors']).toEqual(["'none'"]);
    expect(d['frame-src']).toEqual(["'none'"]);
    expect(d['object-src']).toEqual(["'none'"]);
    expect(d['base-uri']).toEqual(["'none'"]);
    expect(d['require-trusted-types-for']).toEqual(["'script'"]);
    expect(d['trusted-types']).toEqual(['secbin']);
    expect(CSP).not.toMatch(/'unsafe-inline'|'unsafe-eval'|\*|https?:/);
  });

  it('framing and cross-origin isolation are denied', () => {
    expect(SECURITY_HEADERS['x-frame-options']).toBe('DENY');
    expect(SECURITY_HEADERS['cross-origin-opener-policy']).toBe('same-origin');
    expect(SECURITY_HEADERS['cross-origin-embedder-policy']).toBe('require-corp');
    for (const f of ['camera', 'microphone', 'geolocation', 'payment', 'usb']) {
      expect(SECURITY_HEADERS['permissions-policy']).toContain(`${f}=()`);
    }
  });
});
