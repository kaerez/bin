// limits.test.js — configurable view limits and custom expiry (internal fork).
import { env, SELF, runDurableObjectAlarm } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import { encryptPaste, decryptPaste } from '../public/js/crypto.js';
import { validatePaste, expireSeconds, FormatError, MAX_VIEWS, MAX_TTL } from '../public/js/format.js';
import { b64urlFromBytes } from '../public/js/bytes.js';

const ORIGIN = 'https://binthere.test';
const JSON_CT = { 'content-type': 'application/json' };
const postPaste = (body) =>
  SELF.fetch(`${ORIGIN}/api/paste`, { method: 'POST', headers: JSON_CT, body: JSON.stringify(body) });
const peek = (id) => SELF.fetch(`${ORIGIN}/api/paste/${id}?meta=1`);
const consume = (id) =>
  SELF.fetch(`${ORIGIN}/api/paste/${id}/consume`, { method: 'POST', headers: { 'x-burn-intent': 'consume' } });

const fill = (v, n) => new Uint8Array(n).fill(v);
const base = (bar = false) => structuredClone({
  v: 1, ct: b64urlFromBytes(fill(1, 40)), wk: b64urlFromBytes(fill(2, 48)),
  adata: { alg: 'A256GCM', kdf: 'hkdf', iter: 0, comp: 'none', fmt: 'plaintext', bar,
    ivc: b64urlFromBytes(fill(3, 12)), ivw: b64urlFromBytes(fill(4, 12)), skdf: '' },
  meta: { expire: '24h' },
});
const reject = (p) => expect(() => validatePaste(p)).toThrow(FormatError);

describe('expireSeconds', () => {
  it('accepts presets and custom m/h/d durations', () => {
    expect(expireSeconds('1day')).toBe(86400);
    expect(expireSeconds('never')).toBe(0);
    expect(expireSeconds('1m')).toBe(60);
    expect(expireSeconds('90m')).toBe(5400);
    expect(expireSeconds('24h')).toBe(86400);
    expect(expireSeconds('365d')).toBe(MAX_TTL);
  });
  it('rejects out-of-range, malformed, and prototype-shaped values', () => {
    for (const v of ['0m', '366d', '8761h', '525601m', '01h', '1.5h', '1w', 'h', '', ' 1h', '1h ',
      '-1h', '1H', '__proto__', 'constructor', 'toString', null, 5, undefined]) {
      expect(expireSeconds(v)).toBeNull();
    }
  });
});

describe('meta.views / meta.left validation', () => {
  it('accepts views on bar pastes within [1, MAX_VIEWS]', () => {
    const p = base(true); p.meta.views = 5; p.meta.left = 3;
    expect(validatePaste(p).meta).toEqual({ expire: '24h', views: 5, left: 3 });
    const q = base(true); q.meta.views = MAX_VIEWS;
    expect(() => validatePaste(q)).not.toThrow();
  });
  it('rejects bad views/left and views on unlimited (non-bar) pastes', () => {
    for (const v of [0, -1, 1.5, '3', MAX_VIEWS + 1, null]) { const p = base(true); p.meta.views = v; reject(p); }
    { const p = base(true); p.meta.views = 2; p.meta.left = 3; reject(p); }
    { const p = base(true); p.meta.left = 2; reject(p); } // left > implicit views (1)
    { const p = base(false); p.meta.views = 3; reject(p); }
    { const p = base(false); p.meta.left = 0; reject(p); }
  });
});

describe('N-view pastes (Durable Object)', () => {
  it('serves exactly N views with a decreasing count, then 410', async () => {
    const { body, fragment } = await encryptPaste({ text: 'three times', bar: true, views: 3, expire: '90m' });
    const res = await postPaste(body);
    expect(res.status).toBe(201);
    const { id } = await res.json();
    expect(id[0]).toBe('b');

    const head = await (await peek(id)).json();
    expect(head.meta).toMatchObject({ expire: '90m', views: 3, left: 3 });

    for (const expectLeft of [2, 1, 0]) {
      const r = await consume(id);
      expect(r.status).toBe(200);
      const paste = await r.json();
      expect(paste.meta.left).toBe(expectLeft);
      expect(() => validatePaste(paste)).not.toThrow();
      expect((await decryptPaste({ paste, fragment })).text).toBe('three times');
    }
    expect((await consume(id)).status).toBe(410);
    expect((await peek(id)).status).toBe(410);
  });

  it('CONCURRENCY: N views under a burst of consumes → exactly N succeed', async () => {
    const { body } = await encryptPaste({ text: 'x', bar: true, views: 4 });
    const { id } = await (await postPaste(body)).json();
    const statuses = (await Promise.all(Array.from({ length: 20 }, () => consume(id)))).map((r) => r.status);
    expect(statuses.filter((s) => s === 200)).toHaveLength(4);
    expect(statuses.filter((s) => s === 410)).toHaveLength(16);
  });

  it('peek never spends a view', async () => {
    const { body } = await encryptPaste({ text: 'x', bar: true, views: 2 });
    const { id } = await (await postPaste(body)).json();
    for (let i = 0; i < 5; i++) expect((await (await peek(id)).json()).meta.left).toBe(2);
  });

  it('defaults to 1 view when views is absent (classic burn)', async () => {
    const { body } = await encryptPaste({ text: 'x', bar: true, expire: '24h' });
    const { id } = await (await postPaste(body)).json();
    expect((await (await peek(id)).json()).meta).toMatchObject({ views: 1, left: 1 });
    expect((await consume(id)).status).toBe(200);
    expect((await consume(id)).status).toBe(410);
  });

  it('custom expiry is enforced by the DO alarm', async () => {
    const { body } = await encryptPaste({ text: 'x', bar: true, views: 10, expire: '5m' });
    const { id } = await (await postPaste(body)).json();
    const stub = env.BURN.get(env.BURN.idFromName(id));
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect((await consume(id)).status).toBe(410);
  });
});

describe('unlimited views (KV) and create-time validation', () => {
  it('unlimited paste with a custom expiry reads repeatably', async () => {
    const { body, fragment } = await encryptPaste({ text: 'many', bar: false, expire: '36h' });
    const { id } = await (await postPaste(body)).json();
    expect(id[0]).toBe('k');
    for (let i = 0; i < 3; i++) {
      const paste = await (await SELF.fetch(`${ORIGIN}/api/paste/${id}`)).json();
      expect(paste.meta.expire).toBe('36h');
      expect((await decryptPaste({ paste, fragment })).text).toBe('many');
    }
  });

  it('rejects invalid expiry / view values with 400', async () => {
    const bad = [
      { bar: true, views: 0 }, { bar: true, views: MAX_VIEWS + 1 }, { bar: false, views: 3 },
      { bar: true, expire: '0m' }, { bar: true, expire: '400d' },
    ];
    for (const o of bad) {
      const { body } = await encryptPaste({ text: 'x', expire: '24h', ...o });
      expect((await postPaste(body)).status).toBe(400);
    }
  });

  it('ignores a client-supplied meta.left (server owns the counter)', async () => {
    const { body } = await encryptPaste({ text: 'x', bar: true, views: 3 });
    body.meta.left = 1;
    const { id } = await (await postPaste(body)).json();
    expect((await (await peek(id)).json()).meta.left).toBe(3);
  });
});

describe('cross-site create guard', () => {
  it('rejects Sec-Fetch-Site: cross-site with 403, allows same-origin', async () => {
    const { body } = await encryptPaste({ text: 'x', bar: true });
    const send = (site) => SELF.fetch(`${ORIGIN}/api/paste`, {
      method: 'POST', headers: { ...JSON_CT, 'sec-fetch-site': site }, body: JSON.stringify(body),
    });
    expect((await send('cross-site')).status).toBe(403);
    expect((await send('same-origin')).status).toBe(201);
  });
});
