// audit-cross-site.test.js — regression tests from the security audit:
// (1) cross-site subresource requests (<img src>, <link>, <script src> on
// another site, which browsers send with Sec-Fetch-Site: cross-site and no
// preflight) must not be able to spend a visitor's "invalid" Guard budget and
// get their network blocked from opening shares; (2) the POSTs that mint
// WebAuthn challenges refuse cross-site callers like every other POST.
import { describe, it, expect, beforeAll } from 'vitest';
import { fetchJson, freshIp, makeUser } from './helpers.js';

const randomId = (cls) => cls + btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

describe('public share routes and cross-site requests', () => {
  it('refuse cross-site / same-site requests without counting them against the caller', async () => {
    const ip = freshIp();
    // Default guard.invalid.max is 60 per window: go well past it.
    for (let i = 0; i < 70; i++) {
      const site = i % 2 ? 'cross-site' : 'same-site';
      const kind = i % 3 ? 'paste' : 'file';
      const path = kind === 'file' ? `/api/file/${randomId('f')}/chunk/0` : `/api/paste/${randomId('k')}`;
      const r = await fetchJson(path, { ip, headers: { 'sec-fetch-site': site, 'sec-fetch-mode': 'no-cors', 'sec-fetch-dest': 'image' } });
      expect(r.status).toBe(403);
      expect((await r.json()).error).toBe('cross_site');
    }
    // The victim's own (same-origin) request afterwards is not blocked.
    const own = await fetchJson(`/api/paste/${randomId('k')}`, { ip, headers: { 'sec-fetch-site': 'same-origin' } });
    expect(own.status).toBe(404);
    // Header-less clients (the CLI) are unaffected.
    const cli = await fetchJson(`/api/paste/${randomId('k')}`, { ip });
    expect(cli.status).toBe(404);
  });
});

describe('WebAuthn challenge endpoints', () => {
  let u;
  beforeAll(async () => { u = await makeUser('audit-xsite'); });
  it('refuse cross-site and same-site POSTs', async () => {
    for (const p of ['/api/private/me/reauth', '/api/private/me/passkeys/options']) {
      for (const site of ['cross-site', 'same-site']) {
        const r = await fetchJson(p, { method: 'POST', cookie: u.cookie, body: {}, headers: { 'sec-fetch-site': site } });
        expect([p, site, r.status]).toEqual([p, site, 403]);
        expect((await r.json()).error).toBe('cross_site');
      }
    }
  });
});
