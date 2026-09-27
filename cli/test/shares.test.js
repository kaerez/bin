// shares.test.js — `secbin list`, `show`, `receipts`, `label`, `extend` and
// `revoke` against the mocked API: the key goes only in the Authorization
// header, pages are followed, server strings cannot steer the terminal, and
// scope / lock refusals are explained.
import { describe, expect, it } from 'vitest';
import { run } from '../src/cli.js';
import { KEY, makeIo, makeServer } from './helpers.js';

async function create(server, text, args = []) {
  const a = makeIo({ stdin: text, server });
  expect(await run(['create', '--json', ...args], a.io)).toBe(0);
  return JSON.parse(a.text.out());
}

describe('secbin list', () => {
  it('lists every page of the account\'s shares, as text or JSON', async () => {
    const server = makeServer({ policy: { pageSize: 2 } });
    const made = [];
    for (let i = 0; i < 5; i++) made.push(await create(server, `note ${i}`, ['--label', `label ${i}`]));
    const a = makeIo({ server });
    expect(await run(['list'], a.io)).toBe(0);
    const lines = a.text.out().trim().split('\n');
    expect(lines).toHaveLength(5);
    for (const m of made) expect(a.text.out()).toContain(m.id);
    expect(a.text.out()).toContain('label 3');
    expect(a.text.err()).toMatch(/5 of 5 shares/);
    const listCalls = server.calls.filter((c) => c.path === '/api/private/shares');
    expect(listCalls).toHaveLength(3);
    for (const c of listCalls) expect(c.headers.authorization).toBe(`Bearer ${KEY}`);

    const j = makeIo({ server });
    expect(await run(['list', '--json', '--status', 'active'], j.io)).toBe(0);
    const out = JSON.parse(j.text.out());
    expect(out.total).toBe(5);
    expect(out.rows.map((r) => r.id).sort()).toEqual(made.map((m) => m.id).sort());
  });

  it('strips control characters from server strings', async () => {
    const server = makeServer();
    await create(server, 'x', ['--label', 'plain']);
    for (const r of server.notes.values()) r.label = 'evil\u001b]52;c;aGk=\u0007\u001b[2Jlabel';
    const a = makeIo({ server });
    expect(await run(['list'], a.io)).toBe(0);
    // eslint-disable-next-line no-control-regex
    expect(a.text.out()).not.toMatch(/[\u0000-\u0009\u000b-\u001f]/);
    expect(a.text.out()).toContain('label');
    // --json: JSON escapes C0 controls itself; DEL and C1 (an 8-bit CSI is U+009B) are escaped too.
    for (const r of server.notes.values()) r.label = 'c1\u009b2J\u007fdel';
    const j = makeIo({ server });
    expect(await run(['list', '--json'], j.io)).toBe(0);
    // eslint-disable-next-line no-control-regex
    expect(j.text.out()).not.toMatch(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/);
    expect(JSON.parse(j.text.out()).rows[0].label).toBe('c1\u009b2J\u007fdel');
  });

  it('explains a missing "read" scope, a bad status and a missing key', async () => {
    const server = makeServer({ policy: { noRead: true } });
    const a = makeIo({ server });
    expect(await run(['list'], a.io)).toBe(1);
    expect(a.text.err()).toMatch(/does not have the "read" scope/);
    const b = makeIo({ server });
    expect(await run(['list', '--status', 'nope'], b.io)).toBe(2);
    const c = makeIo({ server, env: { SECBIN_API_KEY: undefined } });
    expect(await run(['list'], c.io)).toBe(2);
    expect(c.text.err()).toMatch(/listing your shares needs an API key/);
    const d = makeIo({ server });
    expect(await run(['list', '--api-key', 'sbk_x'], d.io)).toBe(2);
  });
});

describe('secbin revoke', () => {
  it('revokes by id or URL with the intent header; the note is gone', async () => {
    const server = makeServer();
    const one = await create(server, 'first');
    const two = await create(server, 'second');
    const a = makeIo({ server });
    expect(await run(['revoke', one.id], a.io)).toBe(0);
    expect(a.text.err()).toContain(`revoked ${one.id}`);
    const call = server.calls.at(-1);
    expect(call).toMatchObject({ method: 'POST', path: `/api/private/shares/${one.id}/revoke` });
    expect(call.headers).toMatchObject({ authorization: `Bearer ${KEY}`, 'x-secbin-intent': '1' });
    expect(server.notes.has(one.id)).toBe(false);
    const b = makeIo({ server });
    expect(await run(['revoke', two.url], b.io)).toBe(0);
    expect(server.notes.has(two.id)).toBe(false);
    // The URL's #fragment never leaves the process.
    expect(JSON.stringify(server.calls.at(-1))).not.toContain(two.url.split('#')[1]);
  });

  it('explains a locked share, a missing "manage" scope and bad input', async () => {
    const server = makeServer();
    const n = await create(server, 'locked');
    server.notes.get(n.id).locked = true;
    const a = makeIo({ server });
    expect(await run(['revoke', n.id], a.io)).toBe(1);
    expect(a.text.err()).toMatch(/locked this share/);
    const noManage = makeServer({ policy: { noManage: true } });
    const m = await create(noManage, 'x');
    const b = makeIo({ server: noManage });
    expect(await run(['revoke', m.id], b.io)).toBe(1);
    expect(b.text.err()).toMatch(/"manage" scope/);
    const c = makeIo({ server });
    expect(await run(['revoke'], c.io)).toBe(2);
    expect(await run(['revoke', 'not-an-id'], c.io)).toBe(2);
  });
});

describe('secbin show / receipts', () => {
  it('shows one share and its receipts, as text or JSON, with the key only in the header', async () => {
    const server = makeServer({ policy: { receiptFields: ['receiptLocation'] } });
    const n = await create(server, 'x', ['--views', '3', '--label', 'report']);
    server.notes.get(n.id).receipts = [{ ts: 1700000000, country: 'NL' }, { ts: 1700000100, country: 'evil\u001b[2J' }];
    const a = makeIo({ server });
    expect(await run(['show', n.url], a.io)).toBe(0);
    expect(a.text.out()).toMatch(new RegExp(`id\\s+${n.id}`));
    expect(a.text.out()).toMatch(/views\s+3 of 3 left/);
    expect(a.text.out()).toMatch(/opens\s+2/);
    expect(a.text.out()).toMatch(/label\s+report/);
    const call = server.calls.at(-1);
    expect(call).toMatchObject({ method: 'GET', path: `/api/private/shares/${n.id}` });
    expect(call.headers.authorization).toBe(`Bearer ${KEY}`);
    expect(JSON.stringify(call)).not.toContain(n.url.split('#')[1]);
    const j = makeIo({ server });
    expect(await run(['show', n.id, '--json'], j.io)).toBe(0);
    expect(JSON.parse(j.text.out())).toMatchObject({ id: n.id, views_total: 3, left: 3, label: 'report' });

    const r = makeIo({ server });
    expect(await run(['receipts', n.id], r.io)).toBe(0);
    const lines = r.text.out().trim().split('\n');
    expect(lines).toHaveLength(2);
    expect(lines[0]).toMatch(/^2023-11-14 22:13 {2}NL$/);
    // eslint-disable-next-line no-control-regex
    expect(r.text.out()).not.toMatch(/[\u0000-\u0009\u000b-\u001f]/);
    expect(r.text.err()).toMatch(/2 opens; details: receiptLocation/);
    const rj = makeIo({ server });
    expect(await run(['receipts', n.id, '-j'], rj.io)).toBe(0);
    expect(JSON.parse(rj.text.out())).toMatchObject({ total: 2, fields: ['receiptLocation'] });
  });

  it('explains a missing "read" scope, an unknown share and bad input', async () => {
    const server = makeServer({ policy: { noRead: true } });
    const n = await create(server, 'x');
    for (const cmd of ['show', 'receipts']) {
      const a = makeIo({ server });
      expect(await run([cmd, n.id], a.io)).toBe(1);
      expect(a.text.err()).toMatch(/does not have the "read" scope/);
      const b = makeIo({ server });
      expect(await run([cmd], b.io)).toBe(2);
      expect(await run([cmd, n.id, 'extra'], b.io)).toBe(2);
    }
    const ok = makeServer();
    const c = makeIo({ server: ok });
    expect(await run(['show', `k${'A'.repeat(22)}`], c.io)).toBe(1);
    expect(c.text.err()).toMatch(/not found/i);
    const d = makeIo({ server: ok, env: { SECBIN_API_KEY: undefined } });
    expect(await run(['receipts', `k${'A'.repeat(22)}`], d.io)).toBe(2);
    expect(d.text.err()).toMatch(/reading receipts needs an API key/);
  });
});

describe('secbin label / extend', () => {
  it('labels (and clears), and extends views and expiry with PATCH', async () => {
    const server = makeServer();
    const n = await create(server, 'x', ['--views', '2', '--expire', '1h']);
    const a = makeIo({ server });
    expect(await run(['label', n.id, 'quarterly report'], a.io)).toBe(0);
    let call = server.calls.at(-1);
    expect(call).toMatchObject({ method: 'PATCH', path: `/api/private/shares/${n.id}` });
    expect(call.headers).toMatchObject({ authorization: `Bearer ${KEY}`, 'content-type': 'application/json' });
    expect(JSON.parse(call.body)).toEqual({ label: 'quarterly report' });
    expect(server.notes.get(n.id).label).toBe('quarterly report');
    expect(a.text.err()).toMatch(/not encrypted/);
    expect(await run(['label', n.url, ''], makeIo({ server }).io)).toBe(0);
    expect(server.notes.get(n.id).label).toBe('');

    const before = Math.floor(Date.now() / 1000);
    const e = makeIo({ server });
    expect(await run(['extend', n.id, '--views', '5', '--expire', '7d'], e.io)).toBe(0);
    call = server.calls.at(-1);
    const body = JSON.parse(call.body);
    expect(body.views).toBe(5);
    expect(body.expires).toBeGreaterThanOrEqual(before + 7 * 86400);
    expect(body.expires).toBeLessThanOrEqual(Math.floor(Date.now() / 1000) + 7 * 86400);
    expect(server.notes.get(n.id)).toMatchObject({ views: 5, left: 5 });
    expect(e.text.err()).toMatch(/extended .*views 5, expires/);
    expect(await run(['extend', n.id, '--views', 'unlimited'], makeIo({ server }).io)).toBe(0);
    expect(JSON.parse(server.calls.at(-1).body)).toEqual({ views: null });
  });

  it('refuses bad input locally, and explains locks and a missing "manage" scope', async () => {
    const server = makeServer();
    const n = await create(server, 'x', ['--views', '2']);
    const calls = server.calls.length;
    for (const args of [['extend', n.id], ['extend', n.id, '--views', '0'], ['extend', n.id, '--views', 'many'], ['extend', n.id, '--expire', '400d'],
      ['label', n.id], ['label', n.id, 'bad\u001b[2Jlabel'], ['label', n.id, 'x'.repeat(101)], ['label', n.id, 'x', '--api-key', 'sbk_x']]) {
      expect(await run(args, makeIo({ server }).io)).toBe(2);
    }
    expect(server.calls.length).toBe(calls); // nothing was sent
    server.notes.get(n.id).locked = true;
    const a = makeIo({ server });
    expect(await run(['extend', n.id, '--views', '4'], a.io)).toBe(1);
    expect(a.text.err()).toMatch(/locked this share; it cannot be extended/);
    const b = makeIo({ server });
    expect(await run(['label', n.id, 'y'], b.io)).toBe(1);
    expect(b.text.err()).toMatch(/locked this share; it cannot be changed/);
    const noManage = makeServer({ policy: { noManage: true } });
    const m = await create(noManage, 'x', ['--views', '2']);
    for (const args of [['label', m.id, 'y'], ['extend', m.id, '--views', '3']]) {
      const c = makeIo({ server: noManage });
      expect(await run(args, c.io)).toBe(1);
      expect(c.text.err()).toMatch(/"manage" scope/);
    }
  });
});
