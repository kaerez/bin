// sharetypes.test.js — link ("url") and credential ("secret") notes and
// recipient "delete now" through the CLI, against the mocked v2 API: payloads
// are validated before anything is sent, credentials never come from argv,
// `get` prints links without opening them and credentials as escaped JSON or
// one field, and it never throws away a spent view over a bad --field.
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { run } from '../src/cli.js';
import { makeIo, makeServer, scripted } from './helpers.js';

let tmp;
beforeEach(async () => { tmp = await mkdtemp(join(tmpdir(), 'secbin-types-')); });
afterEach(async () => { await rm(tmp, { recursive: true, force: true }); });

async function make(server, args, opts = {}) {
  const a = makeIo({ server, ...opts });
  const code = await run(['create', ...args], a.io);
  return { code, url: a.text.out().trim(), err: a.text.err() };
}
async function get(server, url, args = []) {
  const b = makeIo({ server });
  const code = await run(['get', url, ...args], b.io);
  return { code, out: b.text.out(), err: b.text.err() };
}

describe('link shares (--fmt url)', () => {
  it('normalizes and round-trips a link; get prints it with its real host and never opens it', async () => {
    const server = makeServer();
    const c = await make(server, ['--fmt', 'url', '--text', ' https://xn--80ak6aa92e.com/path?q=1 ']);
    expect(c.code).toBe(0);
    const g = await get(server, c.url);
    expect(g.code).toBe(0);
    expect(g.out).toBe('https://xn--80ak6aa92e.com/path?q=1\n');
    expect(g.err).toMatch(/link to xn--80ak6aa92e\.com \(displayed as аррӏе\.com — international characters can imitate another site\)/);
  });

  it('refuses non-http(s) links and embedded credentials before any request', async () => {
    const server = makeServer();
    for (const bad of ['javascript:alert(1)', 'https://user:pw@example.com/', 'two words', 'file:///etc/passwd']) {
      const c = await make(server, ['--fmt', 'url', '--text', bad]);
      expect(c.code).toBe(2);
    }
    expect(server.calls).toHaveLength(0);
  });

  it('applies the account\'s URL rules from the server (tel: needs scheme:tel)', async () => {
    const plain = makeServer();
    const refused = await make(plain, ['--fmt', 'url', '--text', 'tel:+15551234']);
    expect(refused.code).toBe(2); // an older server without /policy: the default rules apply
    expect(refused.err).toMatch(/not allowed for your account: you may share http and https links/);
    expect(plain.calls.filter((c) => c.path === '/api/private/paste')).toHaveLength(0);
    const server = makeServer({ policy: { urlRules: ['scheme:https', 'scheme:tel'] } });
    const c = await make(server, ['--fmt', 'url', '--text', 'tel:+15551234']);
    expect(c.code).toBe(0);
    const g = await get(server, c.url);
    expect(g.out).toBe('tel:+15551234\n');
    expect(g.err).toMatch(/tel: link \(opens another app\)/);
    const regex = makeServer({ policy: { urlRules: ['re:^https://([a-z0-9-]+\\.)*example\\.com/'] } });
    expect((await make(regex, ['--fmt', 'url', '--text', 'https://docs.example.com/a'])).code).toBe(0);
    expect((await make(regex, ['--fmt', 'url', '--text', 'https://example.org/'])).code).toBe(2);
  });

  it('flags plain-http links', async () => {
    const server = makeServer();
    const c = await make(server, ['--fmt', 'url', '--text', 'http://example.com/']);
    expect((await get(server, c.url)).err).toMatch(/not HTTPS/);
  });
});

describe('credential shares (--fmt secret)', () => {
  const SEED = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // RFC 6238 SHA-1 test key, base32

  it('reads the fields as JSON from a file and prints them as JSON', async () => {
    const server = makeServer();
    const f = join(tmp, 'cred.json');
    await writeFile(f, JSON.stringify({ title: 'DB', username: 'svc', password: 'synthetic-pw\u009b31m', totp: SEED }));
    const c = await make(server, ['--fmt', 'secret', '--file', f, '--views', '3']);
    expect(c.code).toBe(0);
    const g = await get(server, c.url);
    expect(JSON.parse(g.out)).toEqual({ title: 'DB', username: 'svc', password: 'synthetic-pw\u009b31m', totp: SEED });
    expect(g.out).not.toContain('\u009b'); // the C1 CSI is escaped, not emitted
    expect(g.err).toMatch(/--field code/);
    const pw = await get(server, c.url, ['--field', 'username']);
    expect(pw.out).toBe('svc\n');
    const code = await get(server, c.url, ['--field', 'code']);
    expect(code.out).toMatch(/^\d{6}\n$/);
  });

  it('never takes a credential from argv, and refuses unknown fields locally', async () => {
    const server = makeServer();
    expect((await make(server, ['--fmt', 'secret', '--text', '{"password":"x"}'])).code).toBe(2);
    expect((await make(server, ['--fmt', 'secret'], { stdin: '{"pasword":"typo"}' })).code).toBe(2);
    expect((await make(server, ['--fmt', 'secret'], { stdin: 'not json' })).code).toBe(2);
    expect((await make(server, ['--fmt', 'secret'], { stdin: '{"totp":"not base32!"}' })).code).toBe(2);
    expect(server.calls).toHaveLength(0);
  });

  it('asks for the fields on a terminal, hiding the password and seed', async () => {
    const server = makeServer();
    const hidden = [];
    const c = await make(server, ['--fmt', 'secret'], {
      tty: true,
      promptLine: scripted(['VPN', 'alice', '', '']),
      promptHidden: (q) => { hidden.push(q); return Promise.resolve(q.startsWith('Password') ? 'synthetic-secret' : ''); },
    });
    expect(c.code).toBe(0);
    expect(hidden).toEqual(['Password: ', 'One-time-code seed or otpauth:// URI: ']);
    expect(JSON.parse((await get(server, c.url)).out)).toEqual({ title: 'VPN', username: 'alice', password: 'synthetic-secret' });
  });

  it('a missing --field after the view is spent prints the whole credential instead of losing it', async () => {
    const server = makeServer();
    const c = await make(server, ['--fmt', 'secret'], { stdin: '{"username":"only"}' });
    const g = await get(server, c.url, ['--field', 'password']);
    expect(g.code).toBe(0);
    expect(JSON.parse(g.out)).toEqual({ username: 'only' });
    expect(g.err).toMatch(/no "password" field/);
    expect((await get(server, c.url, ['--field', 'nope'])).code).toBe(2);
  });
});

describe('recipient "delete now"', () => {
  it('--recipient-can-delete lets the opener delete with the URL (and password), no token', async () => {
    const server = makeServer();
    const c = await make(server, ['--views', 'unlimited', '--recipient-can-delete', '--password-env', 'PW'], { stdin: 'bye', env: { PW: 'synthetic-pass-1' } });
    expect(c.code).toBe(0);
    const b = makeIo({ server, env: { PW: 'synthetic-pass-1' } });
    expect(await run(['get', c.url, '--password-env', 'PW'], b.io)).toBe(0);
    expect(b.text.err()).toMatch(/delete --now/);
    const wrong = makeIo({ server, env: { PW: 'not-it' } });
    expect(await run(['delete', '--now', c.url, '--password-env', 'PW'], wrong.io)).toBe(1);
    expect(server.notes.size).toBe(1);
    const d = makeIo({ server, stdin: c.url, env: { PW: 'synthetic-pass-1' } });
    expect(await run(['delete', '--now', '-', '--password-env', 'PW'], d.io)).toBe(0);
    expect(server.notes.size).toBe(0);
  });

  it('is refused locally when the sender did not allow it, and the flag is refused where the admin forbids it', async () => {
    const server = makeServer();
    const c = await make(server, ['--views', 'unlimited'], { stdin: 'keep' });
    const d = makeIo({ server });
    expect(await run(['delete', '--now', c.url], d.io)).toBe(2);
    expect(server.notes.size).toBe(1);
    const strict = makeServer({ policy: { openerDelete: false } });
    expect((await make(strict, ['--recipient-can-delete'], { stdin: 'x' })).code).toBe(1);
  });

  it('works for file shares sent with --recipient-can-delete', async () => {
    const server = makeServer();
    const f = join(tmp, 'a.txt');
    await writeFile(f, 'file body');
    const s = makeIo({ server });
    expect(await run(['send', f, '--views', 'unlimited', '--recipient-can-delete'], s.io)).toBe(0);
    const url = s.text.out().trim();
    expect([...server.files.values()][0].paste.meta.deletable).toBe(true);
    const d = makeIo({ server });
    expect(await run(['delete', '--now', url], d.io)).toBe(0);
    expect(server.files.size).toBe(0);
  });
});
