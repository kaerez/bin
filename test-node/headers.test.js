// headers.test.js — the security headers Workers Static Assets serves
// (public/_headers) must be exactly the set the Worker applies to what it
// serves itself (src/lib/http.js), the CSP must keep its core guarantees, and
// the caching rules must stay out of everything the Worker runs for (Workers
// Caching, wrangler.toml [cache]).
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { SECURITY_HEADERS, CSP, EDGE_CACHE_CONTROL } from '../src/lib/http.js';

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
    // PWA: the service worker and the manifest are first-party only.
    expect(d['worker-src']).toEqual(["'self'"]);
    expect(d['manifest-src']).toEqual(["'self'"]);
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

/** public/_headers → [{ pattern, headers: { name: value } }], in file order. */
function headerRules() {
  const rules = [];
  for (const line of readFileSync(new URL('../public/_headers', import.meta.url), 'utf8').split('\n')) {
    if (!line.trim() || line.startsWith('#')) continue;
    if (!line.startsWith(' ')) { rules.push({ pattern: line.trim(), headers: {} }); continue; }
    const i = line.indexOf(':');
    rules.at(-1).headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
  }
  return rules;
}

const configs = ['wrangler.toml', 'wrangler.toml.example'].map((name) => [name, readFileSync(new URL(`../${name}`, import.meta.url), 'utf8')]);
/** The body of `[table]` (up to the next table header), comments dropped. */
const table = (toml, name) => {
  const m = toml.match(new RegExp(`^\\[${name.replace('.', '\\.')}\\]\\n([\\s\\S]*?)(?=^\\[|(?![\\s\\S]))`, 'm'));
  return m ? m[1].split('\n').filter((l) => l.trim() && !l.trim().startsWith('#')).join('\n') : null;
};

describe('placement and caching', () => {
  it.each(configs)('%s enables Smart Placement and Workers Caching, with no entrypoint overrides', (_, toml) => {
    expect(table(toml, 'placement')).toBe('mode = "smart"');
    expect(table(toml, 'cache')).toBe('enabled = true');
    // The default export is the only fetch entrypoint; an [exports.*] override
    // would need its own review against the no-store rule.
    expect(toml).not.toMatch(/^\[exports\./m);
  });

  it('long-lived caching in public/_headers only covers paths the Worker never runs for', () => {
    for (const [, toml] of configs) {
      const rwf = JSON.parse(table(toml, 'assets').match(/^run_worker_first = (\[.*\])$/m)[1]);
      const cached = headerRules().filter((r) => /public|max-age=[1-9]/.test(r.headers['cache-control'] || ''));
      expect(cached.map((r) => r.pattern)).toEqual(['/fonts/*', '/js/vendor/*']);
      for (const { pattern } of cached) {
        const prefix = pattern.replace(/\*$/, '');
        for (const w of rwf) {
          const wp = w.replace(/\*$/, '');
          expect([pattern, w, prefix.startsWith(wp) && w.endsWith('*')]).toEqual([pattern, w, false]);
          expect([pattern, w, wp.startsWith(prefix)]).toEqual([pattern, w, false]);
        }
      }
    }
  });

  it('the Worker header set leaves caching to the per-response policy', () => {
    expect(Object.keys(SECURITY_HEADERS)).not.toContain('cache-control');
    expect(EDGE_CACHE_CONTROL).toBe('cloudflare-cdn-cache-control');
  });
});
