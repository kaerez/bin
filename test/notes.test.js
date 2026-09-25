// notes.test.js — notes end-to-end in workerd (KV + BurnPaste DO): creation
// requires an account, heads never carry wk/ct, opens need both access proofs,
// wrong link / wrong password never spend a view, strict view counting under
// concurrency, expiry via alarm, delete-by-token, and request validation.
import { env, SELF, runDurableObjectAlarm } from 'cloudflare:test';
import { describe, it, expect, beforeAll } from 'vitest';
import { ORIGIN, owner, fetchJson, createNote, openNote, proofHeaders, freshIp } from './helpers.js';
import { openPaste, encryptPaste } from '../public/js/crypto.js';
import { genDeleteToken } from '../src/lib/ids.js';

let oc;
beforeAll(async () => { oc = await owner(); });

const del = (id, token) => fetchJson(`/api/paste/${id}`, { method: 'DELETE', headers: { 'x-delete-token': token } });

describe('creation requires an account', () => {
  it('the old anonymous endpoint is gone (410) and private create needs a session', async () => {
    const { body } = await encryptPaste({ text: 'x' });
    expect((await fetchJson('/api/paste', { method: 'POST', body })).status).toBe(410);
    expect((await fetchJson('/api/private/paste', { method: 'POST', body: { paste: body } })).status).toBe(401);
  });

  it('rejects non-JSON, cross-site and malformed bodies', async () => {
    const { body } = await encryptPaste({ text: 'x' });
    const r1 = await SELF.fetch(`${ORIGIN}/api/private/paste`, { method: 'POST', headers: { cookie: oc, 'content-type': 'text/plain' }, body: JSON.stringify({ paste: body }) });
    expect(r1.status).toBe(415);
    const r2 = await fetchJson('/api/private/paste', { method: 'POST', cookie: oc, body: { paste: body }, headers: { 'sec-fetch-site': 'cross-site' } });
    expect(r2.status).toBe(403);
    const r3 = await fetchJson('/api/private/paste', { method: 'POST', cookie: oc, body: { paste: { ...body, v: 1 } } });
    expect(r3.status).toBe(400);
    const { acc: _acc, ...noAcc } = body;
    expect((await fetchJson('/api/private/paste', { method: 'POST', cookie: oc, body: { paste: noAcc } })).status).toBe(400);
  });
});

describe('unlimited-view notes (KV)', () => {
  it('head has no wk/ct; open needs proofs; reads repeat; delete by token', async () => {
    const n = await createNote(oc, { text: 'a normal note' });
    expect(n.res.status).toBe(201);
    expect(n.id[0]).toBe('k');
    const head = await (await fetchJson(`/api/paste/${n.id}`)).json();
    expect(head.wk).toBeUndefined();
    expect(head.ct).toBeUndefined();
    expect(head.meta.expires).toBeGreaterThan(head.meta.created);
    for (let i = 0; i < 2; i++) {
      const o = await openNote(n.id, n.fragment);
      expect(o.res.status).toBe(200);
      expect((await openPaste({ paste: await o.res.json(), access: o.access })).text).toBe('a normal note');
    }
    expect((await fetchJson(`/api/paste/${n.id}/open`, { method: 'POST' })).status).toBe(400); // no proofs
    expect((await del(n.id, genDeleteToken())).status).toBe(403);
    expect((await del(n.id, n.deletetoken)).status).toBe(200);
    expect((await fetchJson(`/api/paste/${n.id}`)).status).toBe(404);
  });
});

describe('view-limited notes (Durable Object)', () => {
  it('serves exactly N views, then 410', async () => {
    const n = await createNote(oc, { text: 'three', bar: true, views: 3, expire: '90m' });
    expect(n.id[0]).toBe('b');
    const lefts = [];
    for (let i = 0; i < 3; i++) {
      const o = await openNote(n.id, n.fragment);
      expect(o.res.status).toBe(200);
      lefts.push((await o.res.json()).meta.left);
    }
    expect(lefts).toEqual([2, 1, 0]);
    expect((await fetchJson(`/api/paste/${n.id}`)).status).toBe(410);
  });

  it('CONCURRENCY: many simultaneous opens → exactly one 200', async () => {
    const n = await createNote(oc, { text: 'once', bar: true });
    const head = await (await fetchJson(`/api/paste/${n.id}`)).json();
    const { headers } = await proofHeaders(head.adata, n.fragment);
    const ip = freshIp();
    const statuses = (await Promise.all(Array.from({ length: 20 }, () => fetchJson(`/api/paste/${n.id}/open`, { method: 'POST', headers, ip })))).map((r) => r.status);
    expect(statuses.filter((s) => s === 200)).toHaveLength(1);
    expect(statuses.filter((s) => s === 410)).toHaveLength(19);
  });

  it('a wrong #fragment or wrong password never spends a view', async () => {
    const n = await createNote(oc, { text: 'guarded', bar: true, password: 'right-password' });
    const ip = freshIp();
    const badLink = await openNote(n.id, n.fragment, 'right-password', { ip, tamper: true });
    expect(badLink.res.status).toBe(403);
    expect((await badLink.res.json()).error).toBe('bad_link');
    const badPw = await openNote(n.id, n.fragment, 'wrong-password', { ip });
    expect(badPw.res.status).toBe(403);
    expect((await badPw.res.json()).error).toBe('bad_password');
    const ok = await openNote(n.id, n.fragment, 'right-password', { ip });
    expect(ok.res.status).toBe(200);
    expect((await openPaste({ paste: await ok.res.json(), access: ok.access })).text).toBe('guarded');
  });

  it('cross-site opens are refused and do not consume', async () => {
    const n = await createNote(oc, { text: 'same-site', bar: true });
    const head = await (await fetchJson(`/api/paste/${n.id}`)).json();
    const { headers } = await proofHeaders(head.adata, n.fragment);
    expect((await fetchJson(`/api/paste/${n.id}/open`, { method: 'POST', headers: { ...headers, 'sec-fetch-site': 'cross-site' } })).status).toBe(403);
    expect((await fetchJson(`/api/paste/${n.id}/open`, { method: 'POST', headers })).status).toBe(200);
  });

  it('expires via the DO alarm', async () => {
    const n = await createNote(oc, { text: 'soon', bar: true, expire: '5m' });
    const stub = env.BURN.get(env.BURN.idFromName(n.id));
    expect(await runDurableObjectAlarm(stub)).toBe(true);
    expect((await fetchJson(`/api/paste/${n.id}`)).status).toBe(410);
  });

  it('delete by token works', async () => {
    const n = await createNote(oc, { text: 'x', bar: true });
    expect((await del(n.id, n.deletetoken)).status).toBe(200);
    expect((await fetchJson(`/api/paste/${n.id}`)).status).toBe(410);
  });
});

describe('ids and methods', () => {
  it('malformed ids are 404, wrong methods 405', async () => {
    const ip = freshIp();
    for (const id of ['short', '%zz', 'x' + 'A'.repeat(22)]) expect((await fetchJson(`/api/paste/${id}`, { ip })).status).toBe(404);
    const n = await createNote(oc, { text: 'm' });
    const r = await fetchJson(`/api/paste/${n.id}/open`);
    expect(r.status).toBe(405);
    expect(r.headers.get('allow')).toBe('POST');
  });
});
