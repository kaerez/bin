// shares.test.js — `secbin list` and `secbin revoke` against the mocked API:
// the key goes only in the Authorization header, pages are followed, server
// strings cannot steer the terminal, and scope / lock refusals are explained.
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
