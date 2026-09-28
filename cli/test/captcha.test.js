// captcha.test.js — the CLI and shares with the CAPTCHA: `--captcha` /
// `--no-captcha` on create and send (neither: the role's default; the server
// has the last word), the JSON and stderr say whether the share has one, and
// `secbin get` of such a share explains that it opens in a browser only.
import { describe, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run } from '../src/cli.js';
import { makeIo, makeServer } from './helpers.js';

const MSG = 'secbin: This share requires a CAPTCHA; open it in a browser';
const bodyOf = (server, path) => JSON.parse(server.calls.find((c) => c.method === 'POST' && c.path === path).body);

async function cli(server, argv, opts = {}) {
  const a = makeIo({ server, ...opts });
  const code = await run(argv, a.io);
  return { code, out: a.text.out(), err: a.text.err() };
}

describe('create --captcha / --no-captcha', () => {
  it('sends the choice; neither sends nothing (the role\'s default); both is a usage error', async () => {
    let s = makeServer();
    let r = await cli(s, ['create', '--captcha', '--json'], { stdin: 'hello' });
    expect(r.code).toBe(0);
    expect(bodyOf(s, '/api/private/paste').captcha).toBe(true);
    expect(JSON.parse(r.out).captcha).toBe(true);
    s = makeServer();
    r = await cli(s, ['create', '--captcha'], { stdin: 'hello' });
    expect(r.err).toMatch(/CAPTCHA: recipients complete a CAPTCHA in a browser before the share opens/);
    s = makeServer();
    r = await cli(s, ['create', '--no-captcha', '--json'], { stdin: 'hello' });
    expect(bodyOf(s, '/api/private/paste').captcha).toBe(false);
    expect(JSON.parse(r.out).captcha).toBe(false);
    expect(r.err).not.toMatch(/CAPTCHA/);
    s = makeServer({ policy: { captchaDefault: true } });
    r = await cli(s, ['create', '--json'], { stdin: 'hello' });
    expect('captcha' in bodyOf(s, '/api/private/paste')).toBe(false);
    expect(JSON.parse(r.out).captcha).toBe(true); // the role's default
    s = makeServer();
    r = await cli(s, ['create', '--captcha', '--no-captcha'], { stdin: 'hello' });
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/--captcha and --no-captcha are mutually exclusive/);
    expect(s.calls).toHaveLength(0);
  });

  it('the role decides in the end: "require" turns it on; "off" refuses --captcha', async () => {
    let s = makeServer({ policy: { captcha: 'require' } });
    let r = await cli(s, ['create', '--no-captcha', '--json'], { stdin: 'x' });
    expect(JSON.parse(r.out).captcha).toBe(true);
    s = makeServer({ policy: { captcha: 'off' } });
    r = await cli(s, ['create', '--captcha'], { stdin: 'x' });
    expect(r.code).toBe(1);
    expect(r.err).toMatch(/CAPTCHA is disabled for shares of your role\. \(leave out --captcha\)/);
  });
});

describe('send --captcha', () => {
  it('declares it with the upload and reports it', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'secbin-captcha-'));
    try {
      await writeFile(join(dir, 'a.txt'), 'file content');
      const s = makeServer();
      const r = await cli(s, ['send', join(dir, 'a.txt'), '--captcha', '--json']);
      expect(r.code).toBe(0);
      expect(bodyOf(s, '/api/private/file').captcha).toBe(true);
      expect(JSON.parse(r.out).captcha).toBe(true);
      const t = makeServer();
      const q = await cli(t, ['send', join(dir, 'a.txt')]);
      expect(q.code).toBe(0);
      expect('captcha' in bodyOf(t, '/api/private/file')).toBe(false);
      expect(q.err).not.toMatch(/CAPTCHA/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('get of a share with the CAPTCHA', () => {
  it('says it opens in a browser only (nothing opened, nothing spent)', async () => {
    const s = makeServer();
    const c = await cli(s, ['create', '--captcha', '--views', '2'], { stdin: 'hidden' });
    const url = c.out.trim();
    const g = await cli(s, ['get', url, '--yes']);
    expect(g.code).toBe(1);
    expect(g.err.trim()).toBe(MSG);
    expect(g.out).toBe('');
    const note = [...s.notes.values()][0];
    expect(note.left).toBe(2);
    // A share without it opens as always.
    const plain = (await cli(s, ['create'], { stdin: 'visible' })).out.trim();
    const p = await cli(s, ['get', plain, '--yes']);
    expect(p.code).toBe(0);
    expect(p.out).toBe('visible');
  });
});
