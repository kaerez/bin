// cli.test.js — end-to-end note/command tests against the mocked v2 API
// (test/helpers.js): creation with an API key, head → proofs → open, view
// counting, password flows, deletes, the wizard, failure mapping, update and
// help. The crucial assertions: a wrong link or password is refused by the
// server's proof check and NEVER spends a view, nothing that can fail locally
// happens after the view-spending open, and the #fragment never leaves the
// process.
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { run } from '../src/cli.js';
import { KEY, makeIo, makeServer, OTHER_KEY, scripted, SERVER } from './helpers.js';

const URL_RE = (cls) => new RegExp(`^${SERVER}/p/${cls}[A-Za-z0-9_-]{22}#[A-Za-z0-9_-]{43}$`);

async function createNote(server, text, args = [], env = {}) {
  const a = makeIo({ stdin: text, server, env });
  expect(await run(['create', ...args], a.io)).toBe(0);
  return a.text.out().trim();
}

let tmp;
beforeEach(async () => { tmp = await mkdtemp(join(tmpdir(), 'secbin-cli-')); });
afterEach(async () => { await rm(tmp, { recursive: true, force: true }); });

describe('create → get round trip', () => {
  it('creates from stdin (one view by default) and decrypts from the printed URL', async () => {
    const server = makeServer();
    const a = makeIo({ stdin: 'round trip me\n', server });
    expect(await run(['create'], a.io)).toBe(0);
    const url = a.text.out().trim();
    expect(url).toMatch(URL_RE('b'));
    expect(a.text.err()).toMatch(/delete token: [A-Za-z0-9_-]{43}/);
    expect(a.text.err()).toMatch(/can be opened once, then it is deleted; unopened, it expires in 24 hours/);

    const b = makeIo({ server });
    expect(await run(['get', url], b.io)).toBe(0);
    expect(b.text.out()).toBe('round trip me\n');
    expect(b.text.err()).toMatch(/last view — the share is now deleted/);
    expect(server.notes.size).toBe(0);
  });

  it('authenticates creation with the API key as a Bearer header only', async () => {
    const server = makeServer();
    await createNote(server, 'keyed');
    const post = server.calls.find((c) => c.path === '/api/private/paste');
    expect(post.headers.authorization).toBe(`Bearer ${KEY}`);
    expect(post.body).not.toContain(KEY);
    // Reading needs no key at all.
    const url = await createNote(server, 'public read');
    const b = makeIo({ server, env: { SECBIN_API_KEY: undefined } });
    expect(await run(['get', url], b.io)).toBe(0);
    expect(server.calls.filter((c) => !c.path.startsWith('/api/private')).every((c) => !c.headers.authorization)).toBe(true);
  });

  it('defaults to create when stdin is piped with no command', async () => {
    const server = makeServer();
    const a = makeIo({ stdin: 'implicit create', server });
    expect(await run(['--json'], a.io)).toBe(0);
    expect(JSON.parse(a.text.out()).url).toMatch(/\/p\/b[A-Za-z0-9_-]{22}#/);
  });

  it('--json emits the documented object on stdout only', async () => {
    const server = makeServer();
    const a = makeIo({ stdin: 'json me', server });
    expect(await run(['create', '--json', '--views', '3', '--expire', '90m'], a.io)).toBe(0);
    const parsed = JSON.parse(a.text.out());
    expect(Object.keys(parsed).sort()).toEqual(['deletetoken', 'expires', 'id', 'url', 'views']);
    expect(parsed.views).toBe(3);
    expect(Number.isInteger(parsed.expires)).toBe(true);
    expect(a.text.err()).toBe('');
  });

  it('--views unlimited makes an ordinary (k) note that survives reads', async () => {
    const server = makeServer();
    const url = await createNote(server, 'read me often', ['--views', 'unlimited', '--expire', '7d']);
    expect(url).toMatch(URL_RE('k'));
    for (let i = 0; i < 3; i++) {
      const b = makeIo({ server, tty: true, confirm: () => Promise.reject(new Error('must not confirm')) });
      expect(await run(['get', url], b.io)).toBe(0);
      expect(b.text.out()).toBe('read me often');
    }
  });

  it('--views n counts down and says how many are left', async () => {
    const server = makeServer();
    const url = await createNote(server, 'twice', ['--views', '2']);
    const [note] = server.notes.values();
    expect(note.paste.meta.views).toBe(2);
    const b = makeIo({ server });
    expect(await run(['get', url], b.io)).toBe(0);
    expect(b.text.err()).toMatch(/1 view left/);
    const c = makeIo({ server });
    expect(await run(['get', url], c.io)).toBe(0);
    expect(c.text.err()).toMatch(/last view/);
    const d = makeIo({ server });
    expect(await run(['get', url], d.io)).toBe(1);
    expect(d.text.err()).toMatch(/gone/);
  });

  it('--label is sent to the account (not inside the ciphertext)', async () => {
    const server = makeServer();
    await createNote(server, 'labelled', ['--label', 'deploy creds']);
    expect([...server.notes.values()][0].label).toBe('deploy creds');
  });

  it('the fragment secret is never sent to the server', async () => {
    const server = makeServer();
    const url = await createNote(server, 'keep the key local', ['--views', '2']);
    const fragment = url.split('#')[1];
    const b = makeIo({ server });
    expect(await run(['get', url], b.io)).toBe(0);
    for (const c of server.calls) {
      expect(c.path).not.toContain(fragment);
      expect(JSON.stringify(c.headers)).not.toContain(fragment);
      expect(String(c.body ?? '')).not.toContain(fragment);
    }
    // The open carries the two proofs instead.
    const [open] = server.opens();
    expect(open.headers['x-link-proof']).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(open.headers['x-key-proof']).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});

describe('server and API key configuration', () => {
  it('there is no default server: create/send without one is a usage error', async () => {
    for (const cmd of [['create', '-t', 'x'], ['send', 'whatever']]) {
      const server = makeServer();
      const a = makeIo({ server, tty: true, env: { SECBIN_SERVER: undefined } });
      expect(await run(cmd, a.io)).toBe(2);
      expect(a.text.err()).toMatch(/--server|SECBIN_SERVER/);
      expect(server.calls).toHaveLength(0);
    }
  });

  it('--server overrides SECBIN_SERVER', async () => {
    const server = makeServer();
    const a = makeIo({ server, tty: true, env: { SECBIN_SERVER: 'https://elsewhere.example' } });
    expect(await run(['create', '-t', 'x', '-s', SERVER], a.io)).toBe(0);
    expect(a.text.out().trim()).toMatch(URL_RE('b'));
  });

  it('a missing API key is a usage error that says where to get one', async () => {
    const server = makeServer();
    const a = makeIo({ server, tty: true, env: { SECBIN_API_KEY: undefined } });
    expect(await run(['create', '-t', 'x'], a.io)).toBe(2);
    expect(a.text.err()).toMatch(/SECBIN_API_KEY/);
    expect(a.text.err()).toMatch(/API keys/);
    expect(server.calls).toHaveLength(0);
  });

  it('a malformed key is rejected locally and never printed', async () => {
    const server = makeServer();
    for (const bad of ['sbk_short', 'xyz_' + 'A'.repeat(43), KEY + 'A']) {
      const a = makeIo({ server, tty: true, env: { SECBIN_API_KEY: bad } });
      expect(await run(['create', '-t', 'x'], a.io)).toBe(2);
      expect(a.text.err()).toMatch(/not a valid API key/);
      expect(a.text.err()).not.toContain(bad);
    }
    expect(server.calls).toHaveLength(0);
  });

  it('--api-key is refused: keys never go on the command line', async () => {
    const server = makeServer();
    const a = makeIo({ server, tty: true });
    expect(await run(['create', '-t', 'x', '--api-key', KEY], a.io)).toBe(2);
    expect(a.text.err()).toMatch(/SECBIN_API_KEY or --api-key-file/);
    expect(server.calls).toHaveLength(0);
  });

  it('--api-key-file (0600) wins over SECBIN_API_KEY', async () => {
    const server = makeServer({ keys: [OTHER_KEY] });
    const file = join(tmp, 'key');
    await writeFile(file, OTHER_KEY + '\n', { mode: 0o600 });
    await chmod(file, 0o600);
    const a = makeIo({ server, tty: true });
    expect(await run(['create', '-t', 'from file', '--api-key-file', file], a.io)).toBe(0);
    expect(server.calls[0].headers.authorization).toBe(`Bearer ${OTHER_KEY}`);
  });

  it.skipIf(process.platform === 'win32')('refuses a world-readable key file and warns on a group-readable one', async () => {
    const server = makeServer();
    const file = join(tmp, 'key');
    await writeFile(file, KEY);
    await chmod(file, 0o644);
    const a = makeIo({ server, tty: true });
    expect(await run(['create', '-t', 'x', '--api-key-file', file], a.io)).toBe(2);
    expect(a.text.err()).toMatch(/chmod 600/);
    expect(server.calls).toHaveLength(0);

    await chmod(file, 0o640);
    const b = makeIo({ server, tty: true });
    expect(await run(['create', '-t', 'x', '--api-key-file', file], b.io)).toBe(0);
    expect(b.text.err()).toMatch(/warning: .*group/);
  });

  it('an unreadable or malformed key file is a usage error', async () => {
    const server = makeServer();
    const a = makeIo({ server, tty: true });
    expect(await run(['create', '-t', 'x', '--api-key-file', join(tmp, 'nope')], a.io)).toBe(2);
    expect(a.text.err()).toMatch(/cannot read --api-key-file/);
    const file = join(tmp, 'bad');
    await writeFile(file, 'not a key', { mode: 0o600 });
    await chmod(file, 0o600);
    const b = makeIo({ server, tty: true });
    expect(await run(['create', '-t', 'x', '--api-key-file', file], b.io)).toBe(2);
    expect(b.text.err()).toMatch(/not a valid API key/);
  });

  it.each([
    [{ keys: [OTHER_KEY] }, /rejected the API key: Invalid, expired or disabled API key/],
    [{ policy: { text: false } }, /refused by the server: Creating notes is not allowed/],
    [{ policy: { quota: true } }, /limit reached: Quota reached: 5 shares per 1d/],
    [{ policy: { maxViews: 5 } }, /At most 5 views are allowed via the API/],
  ])('prints the server’s reason for 401/403/429 (%#)', async (opts, re) => {
    const server = makeServer(opts);
    const a = makeIo({ server, tty: true });
    expect(await run(['create', '-t', 'x', '--views', '10'], a.io)).toBe(1);
    expect(a.text.err()).toMatch(re);
  });
});

describe('create validation', () => {
  it.each([
    [['--views', '0']], [['--views', '100001']], [['--views', 'abc']], [['--views', '-1']], [['--views', '1.5']],
    [['--expire', '0m']], [['--expire', '366d']], [['--expire', '5s']], [['--expire', '1w']], [['--expire', '1day']],
    [['--label', 'x'.repeat(101)]], [['--label', 'bad\u001b[2Jlabel']],
    [['--fmt', 'html']], [['--fmt', 'files']], [['--burn']], [['--nonsense']],
  ])('rejects %j with exit 2 before any request', async (flags) => {
    const server = makeServer();
    const a = makeIo({ stdin: 'x', server });
    expect(await run(['create', ...flags], a.io)).toBe(2);
    expect(server.calls).toHaveLength(0);
  });

  it('accepts the bounds: 1 minute, 365 days, 100000 views, a 100-char label', async () => {
    const server = makeServer();
    for (const flags of [['--expire', '1m'], ['--expire', '365d'], ['--views', '100000'], ['--label', 'x'.repeat(100)]]) {
      const a = makeIo({ stdin: 'x', server });
      expect(await run(['create', ...flags], a.io)).toBe(0);
    }
  });

  it('rejects empty and oversized input', async () => {
    const server = makeServer();
    const empty = makeIo({ stdin: '', server });
    expect(await run(['create'], empty.io)).toBe(2);
    const big = makeIo({ stdin: 'a'.repeat((1 << 20) + 1), server });
    expect(await run(['create'], big.io)).toBe(2);
    expect(big.text.err()).toMatch(/too large/);
    expect(server.calls).toHaveLength(0);
  });

  it('requires input when stdin is a TTY and no --file is given', async () => {
    const server = makeServer();
    const a = makeIo({ tty: true, server });
    expect(await run(['create'], a.io)).toBe(2);
    expect(a.text.err()).toMatch(/pipe content|--file/);
  });

  it('--text and --file are mutually exclusive; empty --text is refused', async () => {
    const server = makeServer();
    const both = makeIo({ tty: true, server });
    expect(await run(['create', '--text', 'x', '--file', 'y.txt'], both.io)).toBe(2);
    expect(both.text.err()).toMatch(/mutually exclusive/);
    const empty = makeIo({ tty: true, server });
    expect(await run(['create', '--text', ''], empty.io)).toBe(2);
    expect(empty.text.err()).toMatch(/empty/);
    expect(server.calls).toHaveLength(0);
  });
});

describe('inline --text and short flags', () => {
  it('creates from --text on a TTY (no stdin) and round-trips via the view alias', async () => {
    const server = makeServer();
    const a = makeIo({ tty: true, server });
    expect(await run(['create', '--text', 'inline note'], a.io)).toBe(0);
    const url = a.text.out().trim();
    const b = makeIo({ server });
    expect(await run(['view', url], b.io)).toBe(0);
    expect(b.text.out()).toBe('inline note');
  });

  it('bare `secbin -t "…"` on a TTY defaults to create', async () => {
    const server = makeServer();
    const a = makeIo({ tty: true, server });
    expect(await run(['-t', 'quick one'], a.io)).toBe(0);
    expect(a.text.out().trim()).toMatch(URL_RE('b'));
  });

  it('short flags: -t -j on create, -y on get, -s on delete', async () => {
    const server = makeServer();
    const a = makeIo({ tty: true, server });
    expect(await run(['create', '-t', 'shorty', '-j'], a.io)).toBe(0);
    const { url } = JSON.parse(a.text.out());

    const b = makeIo({ server, tty: true, confirm: () => Promise.reject(new Error('must not prompt')) });
    expect(await run(['get', url, '-y'], b.io)).toBe(0);
    expect(b.text.out()).toBe('shorty');

    const c = makeIo({ tty: true, server });
    expect(await run(['create', '-t', 'doomed', '-j'], c.io)).toBe(0);
    const made = JSON.parse(c.text.out());
    const d = makeIo({ server, env: { TK: made.deletetoken, SECBIN_SERVER: undefined } });
    expect(await run(['delete', made.id, '-s', SERVER, '--token-env', 'TK'], d.io)).toBe(0);
    expect(server.notes.has(made.id)).toBe(false);
  });
});

describe('password notes', () => {
  it('round-trips via --password-env on both ends (real Argon2id)', async () => {
    const server = makeServer();
    const url = await createNote(server, 'sekrit', ['--password-env', 'PW'], { PW: 'correct horse' });
    expect([...server.notes.values()][0].paste.adata.kdf).toBe('argon2id-hkdf');
    const b = makeIo({ server, env: { PW: 'correct horse' } });
    expect(await run(['get', url, '--password-env', 'PW'], b.io)).toBe(0);
    expect(b.text.out()).toBe('sekrit');
  });

  it('NFC and NFD spellings of a password open the same note', async () => {
    const server = makeServer();
    const url = await createNote(server, 'café note', ['--password-env', 'PW'], { PW: 'caf\u00e9' });
    const b = makeIo({ server, env: { PW: 'cafe\u0301' } });
    expect(await run(['get', url, '--password-env', 'PW'], b.io)).toBe(0);
    expect(b.text.out()).toBe('café note');
  });

  it('--password prompts twice on a TTY and refuses a mismatch before any request', async () => {
    const server = makeServer();
    const bad = makeIo({ server, tty: true, promptHidden: scripted(['one', 'two']) });
    expect(await run(['create', '-t', 'x', '--password'], bad.io)).toBe(2);
    expect(bad.text.err()).toMatch(/do not match/);
    expect(server.calls).toHaveLength(0);

    const ok = makeIo({ server, tty: true, promptHidden: scripted(['pw', 'pw']) });
    expect(await run(['create', '-t', 'guarded', '--password'], ok.io)).toBe(0);
    const b = makeIo({ server, env: { PW: 'pw' } });
    expect(await run(['get', ok.text.out().trim(), '--password-env', 'PW'], b.io)).toBe(0);
    expect(b.text.out()).toBe('guarded');
  });

  it('--password without a TTY, or an unset --password-env, is a usage error', async () => {
    const server = makeServer();
    const a = makeIo({ stdin: 'x', server });
    expect(await run(['create', '--password'], a.io)).toBe(2);
    const b = makeIo({ stdin: 'x', server });
    expect(await run(['create', '--password-env', 'MISSING'], b.io)).toBe(2);
    expect(server.calls).toHaveLength(0);
  });

  it('get: no TTY and no --password-env is a usage error; the view is not spent', async () => {
    const server = makeServer();
    const url = await createNote(server, 'sekrit', ['--password-env', 'PW'], { PW: 'pw' });
    const a = makeIo({ server });
    expect(await run(['get', url], a.io)).toBe(2);
    expect(a.text.err()).toMatch(/--password-env/);
    expect(server.opens()).toHaveLength(0);
    expect([...server.notes.values()][0].left).toBe(1);
  });

  it('a wrong password is refused by the proof check and NEVER spends a view', async () => {
    const server = makeServer();
    const url = await createNote(server, 'view me once', ['--password-env', 'PW'], { PW: 'pw' });
    server.calls.length = 0;

    const b = makeIo({ server, env: { PW: 'wrong' } });
    expect(await run(['get', url, '--password-env', 'PW'], b.io)).toBe(1);
    expect(b.text.err()).toMatch(/wrong password \(the share was not opened\)/);
    // head → open(403); the view is intact.
    expect(server.calls.map((c) => c.method)).toEqual(['GET', 'POST']);
    expect([...server.notes.values()][0].left).toBe(1);

    const c = makeIo({ server, env: { PW: 'pw' } });
    expect(await run(['get', url, '--password-env', 'PW'], c.io)).toBe(0);
    expect(c.text.out()).toBe('view me once');
  });

  it('on a TTY a wrong password is re-prompted once', async () => {
    const server = makeServer();
    const url = await createNote(server, 'second try', ['--password-env', 'PW'], { PW: 'pw' });
    const a = makeIo({ server, tty: true, confirm: () => Promise.resolve(true), promptHidden: scripted(['typo', 'pw']) });
    expect(await run(['get', url], a.io)).toBe(0);
    expect(a.text.out()).toBe('second try');
    expect(a.text.err()).toMatch(/wrong password — try again/);

    const url2 = await createNote(server, 'no luck', ['--password-env', 'PW'], { PW: 'pw' });
    const b = makeIo({ server, tty: true, confirm: () => Promise.resolve(true), promptHidden: scripted(['x', 'y']) });
    expect(await run(['get', url2], b.io)).toBe(1);
    expect(b.text.err()).toMatch(/wrong password \(the share was not opened\)/);
    expect([...server.notes.values()].at(-1).left).toBe(1);
  });

  it('a corrupted #fragment is refused as a bad link without spending a view', async () => {
    const server = makeServer();
    const url = await createNote(server, 'intact');
    const frag = url.split('#')[1];
    const other = (frag[0] === 'A' ? 'B' : 'A') + frag.slice(1);
    const a = makeIo({ server });
    expect(await run(['get', url.split('#')[0] + '#' + other], a.io)).toBe(1);
    expect(a.text.err()).toMatch(/link is incomplete or corrupted \(the share was not opened\)/);
    expect([...server.notes.values()][0].left).toBe(1);
  });
});

describe('view-limited confirmation', () => {
  it('declining the TTY confirmation leaves the note intact', async () => {
    const server = makeServer();
    const url = await createNote(server, 'still here');
    server.calls.length = 0;
    const b = makeIo({ server, tty: true, confirm: () => Promise.resolve(false) });
    expect(await run(['get', url], b.io)).toBe(0);
    expect(b.text.out()).toBe('');
    expect(b.text.err()).toMatch(/NOT opened/);
    expect(server.opens()).toHaveLength(0);
    expect(server.notes.size).toBe(1);
  });

  it('asks with the remaining count; --yes and non-TTY both skip it', async () => {
    const server = makeServer();
    const url = await createNote(server, 'counted', ['--views', '3']);
    let asked = '';
    const a = makeIo({ server, tty: true, confirm: (q) => { asked = q; return Promise.resolve(true); } });
    expect(await run(['get', url], a.io)).toBe(0);
    expect(asked).toMatch(/1 of the 3 remaining views/);

    const b = makeIo({ server, tty: true, confirm: () => Promise.reject(new Error('must not ask')) });
    expect(await run(['get', url, '--yes'], b.io)).toBe(0);
    const c = makeIo({ server });
    expect(await run(['get', url], c.io)).toBe(0);
    expect(c.text.out()).toBe('counted');
  });

  it('reads the share URL from stdin with "-"', async () => {
    const server = makeServer();
    const url = await createNote(server, 'via stdin');
    const b = makeIo({ server, stdin: url + '\n' });
    expect(await run(['get', '-'], b.io)).toBe(0);
    expect(b.text.out()).toBe('via stdin');
  });

  it('file-share flags are refused for a note before any request', async () => {
    const server = makeServer();
    const url = await createNote(server, 'n');
    server.calls.length = 0;
    const a = makeIo({ server });
    expect(await run(['get', url, '--list'], a.io)).toBe(2);
    expect(server.calls).toHaveLength(0);
  });
});

describe('delete', () => {
  it('deletes with the right token; a wrong token is 403 and keeps the note', async () => {
    const server = makeServer();
    const a = makeIo({ stdin: 'delete me', server });
    expect(await run(['create', '--json'], a.io)).toBe(0);
    const { url, deletetoken } = JSON.parse(a.text.out());

    const wrong = makeIo({ server, env: { TK: 'not-the-token' } });
    expect(await run(['delete', url, '--token-env', 'TK'], wrong.io)).toBe(1);
    expect(wrong.text.err()).toMatch(/wrong delete token/);
    expect(server.notes.size).toBe(1);

    const right = makeIo({ server, env: { TK: deletetoken } });
    expect(await run(['delete', url, '--token-env', 'TK'], right.io)).toBe(0);
    expect(server.notes.size).toBe(0);

    const gone = makeIo({ server });
    expect(await run(['get', url], gone.io)).toBe(1);
    expect(gone.text.err()).toMatch(/gone/);
  });

  it('a bare id resolves against SECBIN_SERVER, and needs one', async () => {
    const server = makeServer();
    const a = makeIo({ stdin: 'by id', server });
    expect(await run(['create', '--json'], a.io)).toBe(0);
    const { id, deletetoken } = JSON.parse(a.text.out());
    const none = makeIo({ server, env: { TK: deletetoken, SECBIN_SERVER: undefined } });
    expect(await run(['delete', id, '--token-env', 'TK'], none.io)).toBe(2);
    expect(none.text.err()).toMatch(/--server|SECBIN_SERVER/);
    const b = makeIo({ server, env: { TK: deletetoken } });
    expect(await run(['delete', id, '--token-env', 'TK'], b.io)).toBe(0);
    expect(server.notes.size).toBe(0);
  });

  it('prompts for the token on a TTY and needs no API key', async () => {
    const server = makeServer();
    const a = makeIo({ stdin: 'prompted', server });
    expect(await run(['create', '--json'], a.io)).toBe(0);
    const { url, deletetoken } = JSON.parse(a.text.out());
    const b = makeIo({ server, tty: true, env: { SECBIN_API_KEY: undefined }, promptHidden: scripted([deletetoken]) });
    expect(await run(['delete', url], b.io)).toBe(0);
    expect(server.calls.at(-1).headers['x-delete-token']).toBe(deletetoken);
    expect(server.calls.at(-1).path).not.toContain(deletetoken);
  });
});

describe('interactive wizard (bare `secbin` on a TTY)', () => {
  it('writes a note → URL on stdout; QR, token, and lifecycle on stderr', async () => {
    const server = makeServer();
    const a = makeIo({
      server,
      tty: true,
      readKey: scripted(['enter']), // menu: Create
      promptMultiline: scripted(['wizard note\nsecond line']),
      confirm: () => Promise.resolve(false), // no password
    });
    expect(await run([], a.io)).toBe(0);

    const url = a.text.out().trim();
    expect(url).toMatch(URL_RE('b'));
    expect(a.text.out()).toBe(url + '\n'); // stdout is ONLY the URL (pipe-friendly)
    expect(a.text.err()).toMatch(/delete token: /);
    expect(a.text.err()).toMatch(/The note can be opened once, then it is deleted; unopened, it expires in 24 hours\./);
    const braille = new RegExp(`[${String.fromCharCode(0x2801)}-${String.fromCharCode(0x28ff)}]`);
    expect(a.text.err()).toMatch(braille);

    const b = makeIo({ server });
    expect(await run(['get', url], b.io)).toBe(0);
    expect(b.text.out()).toBe('wizard note\nsecond line');
  });

  it('asks for the server when SECBIN_SERVER is unset', async () => {
    const server = makeServer();
    const a = makeIo({
      server, tty: true, env: { SECBIN_SERVER: undefined },
      readKey: scripted(['enter']),
      promptLine: scripted([SERVER]),
      promptMultiline: scripted(['where to?']),
    });
    expect(await run([], a.io)).toBe(0);
    expect(a.text.err()).toMatch(/not set/);
    expect(a.text.out().trim()).toMatch(URL_RE('b'));
  });

  it('create without SECBIN_API_KEY explains how to get one and exits 2', async () => {
    const server = makeServer();
    const a = makeIo({
      server, tty: true, env: { SECBIN_API_KEY: undefined },
      readKey: scripted(['enter']),
      promptMultiline: () => Promise.reject(new Error('must not ask for the note first')),
    });
    expect(await run([], a.io)).toBe(2);
    expect(a.text.err()).toMatch(/SECBIN_API_KEY/);
    expect(server.calls).toHaveLength(0);
  });

  it('re-prompts once on an empty note, then errors with exit 2', async () => {
    const server = makeServer();
    const retried = makeIo({
      server, tty: true,
      readKey: scripted(['enter']),
      promptMultiline: scripted(['', 'second try']),
      confirm: () => Promise.resolve(false),
    });
    expect(await run([], retried.io)).toBe(0);
    expect(retried.text.out()).toMatch(/\/p\/b/);

    const gaveUp = makeIo({
      server, tty: true,
      readKey: scripted(['enter']),
      promptMultiline: scripted(['', '  ']),
    });
    expect(await run([], gaveUp.io)).toBe(2);
    expect(gaveUp.text.err()).toMatch(/empty note/);
    expect(server.calls.filter((c) => c.method === 'POST')).toHaveLength(1);
  });

  it('password: retries once on mismatch, and the note round-trips', async () => {
    const server = makeServer();
    const a = makeIo({
      server,
      tty: true,
      readKey: scripted(['enter']),
      promptMultiline: scripted(['guard me']),
      confirm: () => Promise.resolve(true), // add a password
      promptHidden: scripted(['typo', 'other', 'pw', 'pw']), // mismatch, then match
    });
    expect(await run([], a.io)).toBe(0);
    expect(a.text.err()).toMatch(/do not match/);
    const url = a.text.out().trim();

    const b = makeIo({ server, env: { PW: 'pw' } });
    expect(await run(['get', url, '--password-env', 'PW'], b.io)).toBe(0);
    expect(b.text.out()).toBe('guard me');
  });

  it('two password mismatches abort with exit 2 and nothing is uploaded', async () => {
    const server = makeServer();
    const a = makeIo({
      server,
      tty: true,
      readKey: scripted(['enter']),
      promptMultiline: scripted(['never sent']),
      confirm: () => Promise.resolve(true),
      promptHidden: scripted(['a', 'b', 'c', 'd']),
    });
    expect(await run([], a.io)).toBe(2);
    expect(server.calls).toHaveLength(0);
  });

  it('result screen copies the link with c and the token with t on a TTY', async () => {
    const server = makeServer();
    const copied = [];
    const a = makeIo({
      server, tty: true, stderrIsTTY: true, env: { NO_COLOR: '1' },
      readKey: scripted(['enter', 'c', 't', 'enter']), // menu: Create, then copy both
      promptMultiline: scripted(['copy me']),
      copy: (text) => { copied.push(text); return Promise.resolve(true); },
    });
    expect(await run([], a.io)).toBe(0);
    const url = a.text.out().trim();
    const token = a.text.err().match(/delete token: (\S+)/)[1];
    expect(copied).toEqual([url, token]);
    expect(a.text.err()).toContain('link copied to clipboard');
    expect(a.text.err()).toContain('delete token copied to clipboard');
    expect(a.text.err().split(`${String.fromCharCode(0x1b)}[2J`).length - 1).toBeGreaterThanOrEqual(3);
  });

  it('supports a static full-screen wizard without disabling color', async () => {
    const server = makeServer();
    const a = makeIo({
      server, tty: true, stderrIsTTY: true,
      env: { SECBIN_NO_ANIMATION: '1', COLORTERM: 'truecolor' },
      readKey: scripted(['enter', 'enter']),
      promptMultiline: scripted(['still and readable']),
    });
    expect(await run([], a.io)).toBe(0);
    expect(a.text.err()).toContain(`${String.fromCharCode(0x1b)}[38;2;`); // color remains
    expect(a.text.err()).not.toContain(`\r${String.fromCharCode(0x1b)}[2K`); // no animated line rewrites
    expect(a.text.out()).toMatch(/\/p\/b/);
    expect(a.text.err().split(`${String.fromCharCode(0x1b)}[2J`).length - 1).toBe(3);
  });

  it('result screen skips the copy prompt when stderr is not a TTY', async () => {
    const server = makeServer();
    const a = makeIo({
      server, tty: true,
      readKey: scripted(['enter']),
      promptMultiline: scripted(['plain run']),
      copy: () => Promise.reject(new Error('must not be called')),
    });
    expect(await run([], a.io)).toBe(0);
    expect(a.text.err()).not.toContain('copy link');
  });

  it('menu shows the header and all three actions', async () => {
    const server = makeServer();
    const a = makeIo({ server, tty: true, readKey: scripted(['ctrl-c']) });
    expect(await run([], a.io)).toBe(130);
    expect(a.text.err()).toMatch(/Zero-knowledge encrypted notes/);
    expect(a.text.err()).toMatch(/Create a note/);
    expect(a.text.err()).toMatch(/View a note/);
    expect(a.text.err()).toMatch(/Delete a share/);
    expect(server.calls).toHaveLength(0);
  });

  it('view: navigates the menu, uses the only view, and says so', async () => {
    const server = makeServer();
    const url = await createNote(server, 'peekaboo');
    const a = makeIo({
      server, tty: true,
      readKey: scripted(['down', 'enter']), // menu: View
      promptLine: scripted([url]),
      confirm: () => Promise.resolve(true),
    });
    expect(await run([], a.io)).toBe(0);
    expect(a.text.out()).toBe('peekaboo'); // stdout is ONLY the plaintext
    expect(a.text.err()).toMatch(/now deleted/);
    const again = makeIo({ server });
    expect(await run(['get', url], again.io)).toBe(1);
  });

  it('view: declining the confirmation shows no "deleted" notice', async () => {
    const server = makeServer();
    const url = await createNote(server, 'still here');
    const a = makeIo({
      server, tty: true,
      readKey: scripted(['2']), // hotkey jump to View
      promptLine: scripted([url]),
      confirm: () => Promise.resolve(false),
    });
    expect(await run([], a.io)).toBe(0);
    expect(a.text.out()).toBe('');
    expect(a.text.err()).not.toMatch(/now deleted/);
    expect(server.notes.size).toBe(1);
  });

  it('delete: wraps up from Create and deletes with the prompted token', async () => {
    const server = makeServer();
    const c = makeIo({ stdin: 'condemned', server });
    expect(await run(['create', '--json'], c.io)).toBe(0);
    const { url, deletetoken } = JSON.parse(c.text.out());
    const a = makeIo({
      server, tty: true,
      readKey: scripted(['up', 'enter']), // wrap-around: Create → Delete
      promptLine: scripted([url]),
      promptHidden: scripted([deletetoken]),
    });
    expect(await run([], a.io)).toBe(0);
    expect(a.text.err()).toMatch(/deleted b/);
    expect(server.notes.size).toBe(0);
  });
});

// ── failure paths: network, malformed responses, file I/O ───────────────────

describe('network and server failure paths', () => {
  const netFail = (code) => async () => {
    const e = new TypeError('fetch failed');
    e.cause = { code };
    throw e;
  };

  it('names the host and cause when the server is unreachable', async () => {
    const server = makeServer();
    const a = makeIo({ stdin: 'x', server });
    a.io.fetch = netFail('ECONNREFUSED');
    expect(await run(['create'], a.io)).toBe(1);
    expect(a.text.err()).toContain('ECONNREFUSED');
    expect(a.text.err()).toContain('secbin.test.example');
    expect(a.text.err()).not.toContain('HTTP 0');
  });

  it('never follows redirects (they would replay secret headers)', async () => {
    const server = makeServer();
    const a = makeIo({ stdin: 'x', server });
    let seen;
    a.io.fetch = (url, init) => { seen = init.redirect; return server.fetchImpl(url, init); };
    expect(await run(['create'], a.io)).toBe(0);
    expect(seen).toBe('error');
  });

  it('maps a non-JSON success body to a malformed-response error', async () => {
    const server = makeServer();
    const a = makeIo({ stdin: 'x', server });
    a.io.fetch = async () => new Response('<html>proxy error</html>', { status: 200 });
    expect(await run(['create'], a.io)).toBe(1);
    expect(a.text.err()).toMatch(/malformed response/i);
  });

  it('refuses a created id of the wrong class (it would go into the URL)', async () => {
    const server = makeServer();
    const a = makeIo({ stdin: 'x', server });
    a.io.fetch = async () => new Response(JSON.stringify({ id: 'k/../evil', deletetoken: 'A'.repeat(43), expires: 1 }), { status: 201 });
    expect(await run(['create'], a.io)).toBe(1);
    expect(a.text.out()).toBe('');
  });

  it.each([
    [413, /too large/],
    [429, /limit reached/],
    [500, /HTTP 500/],
  ])('maps HTTP %i to a readable message', async (status, re) => {
    const server = makeServer();
    const a = makeIo({ stdin: 'x', server });
    a.io.fetch = async () => new Response(JSON.stringify({ error: 'nope', message: 'nope' }), { status });
    expect(await run(['create'], a.io)).toBe(1);
    expect(a.text.err()).toMatch(re);
  });

  it('a 404 / 410 on get is explained', async () => {
    const server = makeServer();
    const url = await createNote(server, 'x');
    const k = url.replace('/p/b', '/p/k');
    const a = makeIo({ server });
    expect(await run(['get', k], a.io)).toBe(1);
    expect(a.text.err()).toMatch(/not found/);
  });

  it('sanitizes ANSI escapes out of server-controlled error strings', async () => {
    const server = makeServer();
    const a = makeIo({ stdin: 'x', server });
    const ESC = String.fromCharCode(0x1b);
    const hostile = `bad${ESC}]52;c;evil${String.fromCharCode(7)}request${ESC}[2J` + 'x'.repeat(500);
    a.io.fetch = async () => new Response(JSON.stringify({ error: `${ESC}[31m`, message: hostile }), { status: 400 });
    expect(await run(['create'], a.io)).toBe(1);
    expect(a.text.err()).not.toContain(ESC);
    expect(a.text.err()).not.toContain(String.fromCharCode(7));
    expect(a.text.err().length).toBeLessThan(400); // capped
  });
});

describe('file I/O failure paths (notes)', () => {
  it('unreadable --file fails with exit 2 and touches nothing', async () => {
    const server = makeServer();
    const a = makeIo({ server });
    expect(await run(['create', '-f', 'definitely/does-not-exist.txt'], a.io)).toBe(2);
    expect(a.text.err()).toMatch(/cannot read --file/);
    expect(server.calls).toHaveLength(0);
  });

  it('unwritable --out fails BEFORE the view-spending open', async () => {
    const server = makeServer();
    const url = await createNote(server, 'precious one-time note');
    const a = makeIo({ server });
    expect(await run(['get', '--yes', '-o', join(tmp, 'no-such-dir/deep/out.txt'), url], a.io)).toBe(2);
    expect(a.text.err()).toMatch(/cannot write --out/);
    expect(server.opens()).toHaveLength(0);
    expect(server.notes.size).toBe(1);

    const b = makeIo({ server });
    expect(await run(['get', '--yes', url], b.io)).toBe(0);
    expect(b.text.out()).toBe('precious one-time note');
  });

  it('writes --out with owner-only permissions', async () => {
    const outPath = join(tmp, 'note.txt');
    const server = makeServer();
    const url = await createNote(server, 'to disk');
    const a = makeIo({ server });
    expect(await run(['get', '--yes', '-o', outPath, url], a.io)).toBe(0);
    expect(await readFile(outPath, 'utf8')).toBe('to disk');
    if (process.platform !== 'win32') expect((await stat(outPath)).mode & 0o777).toBe(0o600);
  });

  it('a failed open does not leave an empty --out file behind', async () => {
    const outPath = join(tmp, 'never.txt');
    const server = makeServer();
    const url = await createNote(server, 'x', ['--password-env', 'PW'], { PW: 'pw' });
    const a = makeIo({ server, env: { PW: 'wrong' } });
    expect(await run(['get', '-o', outPath, '--password-env', 'PW', url], a.io)).toBe(1);
    await expect(stat(outPath)).rejects.toMatchObject({ code: 'ENOENT' });
  });
});

describe('dispatch and help ergonomics', () => {
  it('secbin <command> --help shows help instead of exit 2', async () => {
    for (const args of [['create', '--help'], ['get', '-h'], ['delete', '--help'], ['send', '--help']]) {
      const server = makeServer();
      const a = makeIo({ server });
      expect(await run(args, a.io)).toBe(0);
      expect(a.text.out()).toMatch(/Usage:/);
      expect(a.text.out()).toMatch(/secbin send <file\|dir>/);
      expect(server.calls).toHaveLength(0);
    }
  });

  it('help documents the required server and API key, with no built-in server', async () => {
    const a = makeIo({ server: makeServer() });
    expect(await run(['--help'], a.io)).toBe(0);
    expect(a.text.out()).toMatch(/SECBIN_SERVER/);
    expect(a.text.out()).toMatch(/SECBIN_API_KEY/);
    expect(a.text.out()).toMatch(/UNENCRYPTED/);
    expect(a.text.out()).not.toMatch(/binthere|gaury/i);
  });

  it('bare -f dispatches to create like bare -t does', async () => {
    const server = makeServer();
    const a = makeIo({ server, tty: true });
    expect(await run(['-f', 'definitely/does-not-exist.txt'], a.io)).toBe(2);
    expect(a.text.err()).toMatch(/cannot read --file/);
  });

  it('errors are prefixed with the new name', async () => {
    const a = makeIo({ server: makeServer(), tty: true });
    expect(await run(['frobnicate'], a.io)).toBe(2);
    expect(a.text.err()).toMatch(/^secbin: unknown command/);
  });
});

describe('update', () => {
  function updateIo(responses, options = {}) {
    const server = makeServer();
    const a = makeIo({ server });
    const calls = [];
    a.io.platform = options.platform ?? 'linux';
    a.io.runProcess = async (command, args) => {
      calls.push([command, args]);
      const response = responses.shift();
      if (response instanceof Error) throw response;
      return response;
    };
    if (options.global !== undefined) {
      a.io.isGlobalInstall = async () => options.global;
    }
    a.io.mkdtemp = async () => '/tmp/secbin-update-test';
    a.io.rmdir = async () => {};
    return { ...a, calls };
  }

  const ok = (stdout = '', stderr = '') => ({ code: 0, stdout, stderr });
  // `npm view secbin@latest <fields> --json` for a provenance-attested release of this repo.
  const INTEGRITY = `sha512-${'A'.repeat(86)}==`;
  const meta = (version, extra = {}) => ({
    version, 'repository.url': 'git+https://github.com/kaerez/bin.git', 'dist.integrity': INTEGRITY,
    'dist.attestations.provenance.predicateType': 'https://slsa.dev/provenance/v1', ...extra,
  });
  const release = (version, extra) => ok(JSON.stringify(meta(version, extra)) + '\n');
  const packed = (version, integrity = INTEGRITY) => ok(JSON.stringify([{ filename: `secbin-${version}.tgz`, integrity }]) + '\n');
  const VIEW = ['view', 'secbin@latest', 'version', 'repository.url', 'dist.integrity', 'dist.attestations.provenance.predicateType', '--json'];

  it('reports when the installed version is current', async () => {
    const a = updateIo([release('0.1.0')]);
    expect(await run(['update'], a.io)).toBe(0);
    expect(a.text.out()).toBe('secbin 0.1.0 is up to date\n');
    expect(a.calls).toEqual([['npm', VIEW]]);
  });

  it('version reports an available version without locating or changing npm globals', async () => {
    const a = updateIo([release('0.2.0')]);
    expect(await run(['version'], a.io)).toBe(0);
    expect(a.text.out()).toBe('secbin 0.1.0; update available: 0.2.0\n');
    expect(a.calls).toHaveLength(1);
  });

  it('-v aliases version', async () => {
    const a = updateIo([release('0.1.0')]);
    expect(await run(['-v'], a.io)).toBe(0);
    expect(a.text.out()).toBe('secbin 0.1.0 is up to date\n');
    expect(a.calls).toHaveLength(1);
  });

  it('updates a global installation from the integrity-checked tarball, without a shell', async () => {
    const a = updateIo([
      release('0.2.0'),
      ok('/usr/local/lib/node_modules\n'),
      packed('0.2.0'),
      ok('changed 1 package\n'),
    ], { global: true });
    expect(await run(['update'], a.io)).toBe(0);
    expect(a.text.err()).toBe('updating secbin 0.1.0 → 0.2.0…\n');
    expect(a.text.out()).toBe('updated secbin 0.1.0 → 0.2.0\n');
    expect(a.calls[2]).toEqual(['npm', ['pack', 'secbin@0.2.0', '--json', '--pack-destination', '/tmp/secbin-update-test']]);
    expect(a.calls[3]).toEqual(['npm', [
      'install', '--global', '--no-audit', '--no-fund', '--ignore-scripts', '/tmp/secbin-update-test/secbin-0.2.0.tgz',
    ]]);
  });

  it('refuses to install a downloaded tarball whose integrity differs from the verified release', async () => {
    const a = updateIo([
      release('0.2.0'),
      ok('/usr/local/lib/node_modules\n'),
      packed('0.2.0', `sha512-${'B'.repeat(86)}==`),
      ok(''),
    ], { global: true });
    expect(await run(['update'], a.io)).toBe(1);
    expect(a.text.err()).toMatch(/does not match the verified release/);
    expect(a.calls).toHaveLength(3); // never reached `npm install`
  });

  it('uses npm.cmd on Windows', async () => {
    const a = updateIo([release('0.1.0')], { platform: 'win32' });
    a.io.env.ComSpec = 'C:\\Windows\\System32\\cmd.exe';
    expect(await run(['version'], a.io)).toBe(0);
    expect(a.calls[0]).toEqual([
      'C:\\Windows\\System32\\cmd.exe',
      ['/d', '/s', '/c', 'npm.cmd', ...VIEW],
    ]);
  });

  it('refuses to modify a checkout or temporary npx copy', async () => {
    const a = updateIo([
      release('0.2.0'),
      ok('/usr/local/lib/node_modules\n'),
    ], { global: false });
    expect(await run(['update'], a.io)).toBe(1);
    expect(a.text.err()).toContain('npm install -g ./cli');
    expect(a.text.err()).not.toContain('secbin@latest'); // never suggest an unverified registry install
    expect(a.calls).toHaveLength(2);
  });

  it('rejects malformed registry versions and npm failures (version still reports the installed one)', async () => {
    const malformed = updateIo([ok(JSON.stringify(meta('latest; rm -rf /')))]);
    expect(await run(['update'], malformed.io)).toBe(1);
    expect(malformed.text.err()).toContain('invalid version');
    const mv = updateIo([ok(JSON.stringify(meta('latest; rm -rf /')))]);
    expect(await run(['version'], mv.io)).toBe(0);
    expect(mv.text.out()).toBe('secbin 0.1.0\n');
    expect(mv.text.err()).toContain('invalid version');

    const failed = updateIo([{ code: 1, stdout: '', stderr: 'network error' }]);
    expect(await run(['version'], failed.io)).toBe(0);
    expect(failed.text.err()).toContain('checking for updates failed');
    expect(failed.text.err()).not.toContain('network error');
  });

  it('refuses a registry package that is not published from this repository', async () => {
    // The npm name "secbin" is held by an unrelated package (no repository) —
    // `update` must never globally install it.
    for (const stdout of ['"3.1.3"\n', JSON.stringify({ version: '9.9.9', 'repository.url': 'git+https://github.com/someone/else.git' })]) {
      const a = updateIo([ok(stdout), ok('/usr/local/lib/node_modules\n'), ok('')], { global: true });
      expect(await run(['update'], a.io)).toBe(1);
      expect(a.text.err()).toMatch(/not published from github\.com\/kaerez\/bin/);
      expect(a.calls).toHaveLength(1); // never reached `npm install`
      const b = updateIo([ok(stdout)]);
      expect(await run(['version'], b.io)).toBe(0);
      expect(b.text.err()).toMatch(/not published from github\.com\/kaerez\/bin/);
    }
  });

  it('refuses a release without provenance or integrity, even with the right repository URL', async () => {
    // A look-alike package can claim this repository in its package.json; only
    // an npm provenance attestation proves where it was built.
    for (const [extra, reason] of [
      [{ 'dist.attestations.provenance.predicateType': undefined }, /no provenance attestation/],
      [{ 'dist.attestations.provenance.predicateType': 'https://evil.example/provenance' }, /no provenance attestation/],
      [{ 'dist.integrity': undefined }, /no sha512 integrity/],
      [{ 'dist.integrity': 'sha1-abc' }, /no sha512 integrity/],
    ]) {
      const a = updateIo([release('0.2.0', extra), ok('/usr/local/lib/node_modules\n'), ok('')], { global: true });
      expect(await run(['update'], a.io)).toBe(1);
      expect(a.text.err()).toMatch(reason);
      expect(a.calls).toHaveLength(1); // never reached `npm install`
    }
  });

  it('rejects unknown options as usage errors', async () => {
    const a = updateIo([]);
    expect(await run(['update', '--force'], a.io)).toBe(2);
    expect(a.text.err()).toContain('unknown update option');
    expect(a.calls).toHaveLength(0);

    expect(await run(['version', '--json'], a.io)).toBe(2);
    expect(a.text.err()).toContain('unknown version option');
    expect(a.calls).toHaveLength(0);
  });
});
