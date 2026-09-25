// files.test.js — `secbin send` / `secbin get` for file shares against the
// mocked v2 API: a real directory tree (nested folders, an empty folder, a
// multi-chunk file, a symlink that must be skipped) is sent and downloaded
// back byte for byte; --list, --path, --force, view counting, and the
// extraction safety rules (no traversal, never writing through a symlink,
// no silent overwrite, 0600/0700 modes).
import { lstat, mkdir, mkdtemp, readdir, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { CHUNK } from '../vendor/files.js';
import { run } from '../src/cli.js';
import { selectEntries } from '../src/commands/get.js';
import { UsageError } from '../src/errors.js';
import { ensureDir, preflight, targetPath, UnsafePathError, writeFile as extractFile } from '../src/extract.js';
import { makeIo, makeServer, SERVER } from './helpers.js';

const posix = process.platform !== 'win32';
let tmp;
beforeEach(async () => { tmp = await mkdtemp(join(tmpdir(), 'secbin-files-')); });
afterEach(async () => { await rm(tmp, { recursive: true, force: true }); });

const BIG = new Uint8Array(randomBytes(CHUNK + 300_000)); // spans two chunks
const PNG = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13]);

/** tmp/tree: a.txt, nested/deep/big.bin, nested/pic.dat (PNG magic), empty/, link → a.txt */
async function makeTree() {
  const root = join(tmp, 'tree');
  await mkdir(join(root, 'nested', 'deep'), { recursive: true });
  await mkdir(join(root, 'empty'));
  await writeFile(join(root, 'a.txt'), 'hello files\n');
  await writeFile(join(root, 'nested', 'deep', 'big.bin'), BIG);
  await writeFile(join(root, 'nested', 'pic.dat'), PNG);
  if (posix) await symlink(join(root, 'a.txt'), join(root, 'link'));
  return root;
}

async function send(server, args, env = {}) {
  const a = makeIo({ server, env });
  const code = await run(['send', ...args], a.io);
  return { code, url: a.text.out().trim(), err: a.text.err(), out: a.text.out() };
}

async function get(server, args, opts = {}) {
  const a = makeIo({ server, ...opts });
  const code = await run(['get', ...args], a.io);
  return { code, out: a.text.out(), err: a.text.err() };
}

async function listTree(dir, base = '') {
  const out = [];
  for (const name of (await readdir(dir)).sort()) {
    const p = base ? `${base}/${name}` : name;
    const st = await lstat(join(dir, name));
    if (st.isDirectory()) {
      out.push(p + '/');
      out.push(...await listTree(join(dir, name), p));
    } else out.push(p);
  }
  return out;
}

describe('send → get round trip', () => {
  it('sends a directory tree and downloads it back byte for byte', async () => {
    const server = makeServer();
    const src = await makeTree();
    const s = await send(server, [src, '--views', 'unlimited', '--label', 'tree upload']);
    expect(s.code).toBe(0);
    expect(s.url).toMatch(new RegExp(`^${SERVER}/p/f[A-Za-z0-9_-]{22}#[A-Za-z0-9_-]{43}$`));
    expect(s.err).toMatch(/delete token: /);
    expect(s.err).toMatch(/3 files and 1 empty folder/);
    if (posix) expect(s.err).toMatch(/warning: skipping symbolic link .*link/);

    // What the server saw: counts for limit checks, never names or types.
    const [rec] = server.files.values();
    expect(rec.init).toMatchObject({ views: null, expire: '24h', files: 3, maxFile: BIG.length });
    expect(rec.chunks).toBe(2);
    expect(rec.label).toBe('tree upload');
    const wire = JSON.stringify(server.calls.map((c) => [c.path, c.headers, typeof c.body === 'string' ? c.body : '']));
    for (const secret of ['a.txt', 'big.bin', 'nested', 'text/plain', 'image/png']) expect(wire).not.toContain(secret);

    const dest = join(tmp, 'out');
    const g = await get(server, [s.url, '--out', dest]);
    expect(g.code).toBe(0);
    expect(g.err).toMatch(/saved 3 files/);
    expect(await listTree(dest)).toEqual([
      'tree/', 'tree/a.txt', 'tree/empty/', 'tree/nested/', 'tree/nested/deep/', 'tree/nested/deep/big.bin', 'tree/nested/pic.dat',
    ]);
    expect(await readFile(join(dest, 'tree', 'a.txt'), 'utf8')).toBe('hello files\n');
    expect(Buffer.from(await readFile(join(dest, 'tree', 'nested', 'deep', 'big.bin'))).equals(Buffer.from(BIG))).toBe(true);
    expect(Buffer.from(await readFile(join(dest, 'tree', 'nested', 'pic.dat'))).equals(Buffer.from(PNG))).toBe(true);
    if (posix) {
      expect((await stat(join(dest, 'tree', 'a.txt'))).mode & 0o777).toBe(0o600);
      expect((await stat(join(dest, 'tree', 'nested'))).mode & 0o777).toBe(0o700);
    }
    // Each chunk was fetched exactly once.
    expect(server.chunkGets()).toHaveLength(2);
  });

  it('--list prints the tree with sizes and detected types, writing nothing', async () => {
    const server = makeServer();
    const src = await makeTree();
    const s = await send(server, [src, '--views', '2', '--mime', 'tree/a.txt=text/markdown']);
    expect(s.code).toBe(0);
    const g = await get(server, [s.url, '--list']);
    expect(g.code).toBe(0);
    const lines = g.out.trim().split('\n');
    expect(lines.find((l) => l.endsWith(' tree/a.txt'))).toMatch(/12 B\s+text\/markdown/);
    expect(lines.find((l) => l.endsWith(' tree/nested/pic.dat'))).toMatch(/image\/png/); // magic bytes win
    expect(lines.find((l) => l.endsWith(' tree/nested/deep/big.bin'))).toMatch(/application\/octet-stream/);
    expect(lines.some((l) => /\bfolder\s+tree\/empty\/$/.test(l))).toBe(true);
    expect(g.err).toMatch(/1 view left/);
    expect(server.chunkGets()).toHaveLength(0); // listing fetches no content
  });

  it('--path downloads one folder (keeping its name) or one file, fetching only its chunks', async () => {
    const server = makeServer();
    const src = await makeTree();
    const s = await send(server, [src, '--views', 'unlimited']);

    const d1 = join(tmp, 'sub');
    const g1 = await get(server, [s.url, '--out', d1, '--path', 'tree/nested/']);
    expect(g1.code).toBe(0);
    expect(await listTree(d1)).toEqual(['nested/', 'nested/deep/', 'nested/deep/big.bin', 'nested/pic.dat']);

    server.calls.length = 0;
    const d2 = join(tmp, 'one');
    const g2 = await get(server, [s.url, '--out', d2, '-p', 'tree/a.txt']);
    expect(g2.code).toBe(0);
    expect(await listTree(d2)).toEqual(['a.txt']);
    expect(server.chunkGets().map((c) => c.path.split('/').pop())).toEqual(['0']);

    const g3 = await get(server, [s.url, '--out', d2, '--path', 'tree/missing']);
    expect(g3.code).toBe(2);
    expect(g3.err).toMatch(/no file or folder "tree\/missing"/);
  });

  it('sends several arguments by basename and refuses duplicate share paths', async () => {
    const server = makeServer();
    await mkdir(join(tmp, 'x'));
    await mkdir(join(tmp, 'y'));
    await writeFile(join(tmp, 'x', 'same.txt'), 'one');
    await writeFile(join(tmp, 'y', 'same.txt'), 'two');
    await writeFile(join(tmp, 'solo.txt'), 'solo');
    const dup = await send(server, [join(tmp, 'x', 'same.txt'), join(tmp, 'y', 'same.txt')]);
    expect(dup.code).toBe(2);
    expect(dup.err).toMatch(/same path "same.txt"/);
    expect(server.calls).toHaveLength(0);

    const ok = await send(server, [join(tmp, 'x', 'same.txt'), join(tmp, 'solo.txt'), '--views', 'unlimited']);
    expect(ok.code).toBe(0);
    const g = await get(server, [ok.url, '--list']);
    expect(g.out).toMatch(/ same\.txt\n.* solo\.txt\n$/);
  });

  it('a password-protected, view-limited share opens once with the password', async () => {
    const server = makeServer();
    await writeFile(join(tmp, 'secret.txt'), 'classified');
    const s = await send(server, [join(tmp, 'secret.txt'), '--password-env', 'PW'], { PW: 'pw' });
    expect(s.code).toBe(0);
    expect(s.err).toMatch(/can be opened once/);

    const wrong = await get(server, [s.url, '--out', join(tmp, 'o1'), '--password-env', 'PW'], { env: { PW: 'nope' } });
    expect(wrong.code).toBe(1);
    expect(wrong.err).toMatch(/wrong password \(the share was not opened\)/);
    expect([...server.files.values()][0].left).toBe(1);

    const right = await get(server, [s.url, '--out', join(tmp, 'o2'), '--password-env', 'PW'], { env: { PW: 'pw' } });
    expect(right.code).toBe(0);
    expect(await readFile(join(tmp, 'o2', 'secret.txt'), 'utf8')).toBe('classified');
    expect(right.err).toMatch(/last view — the share can no longer be opened/);

    const again = await get(server, [s.url, '--out', join(tmp, 'o3'), '--password-env', 'PW'], { env: { PW: 'pw' } });
    expect(again.code).toBe(1);
    expect(again.err).toMatch(/gone/);
  });

  it('declining the confirmation opens nothing', async () => {
    const server = makeServer();
    await writeFile(join(tmp, 'f.txt'), 'f');
    const s = await send(server, [join(tmp, 'f.txt')]);
    const g = await get(server, [s.url, '--out', join(tmp, 'o')], { tty: true, confirm: () => Promise.resolve(false) });
    expect(g.code).toBe(0);
    expect(g.err).toMatch(/NOT opened/);
    expect(server.opens()).toHaveLength(0);
  });
});

describe('send validation', () => {
  it.each([
    [['--views', '0']], [['--expire', '2y']], [['--mime', 'f.txt=not a type']], [['--mime', 'nope.txt=text/plain']], [['--mime', 'noequals']],
  ])('rejects %j before any request', async (flags) => {
    const server = makeServer();
    await writeFile(join(tmp, 'f.txt'), 'f');
    const s = await send(server, [join(tmp, 'f.txt'), ...flags]);
    expect(s.code).toBe(2);
    expect(server.calls).toHaveLength(0);
  });

  it('needs at least one path, and readable ones', async () => {
    const server = makeServer();
    expect((await send(server, [])).code).toBe(2);
    const missing = await send(server, [join(tmp, 'nope')]);
    expect(missing.code).toBe(2);
    expect(missing.err).toMatch(/cannot read/);
    expect(server.calls).toHaveLength(0);
  });

  it.skipIf(!posix)('a symlink argument is skipped, and nothing left to send is an error', async () => {
    const server = makeServer();
    await writeFile(join(tmp, 'real.txt'), 'r');
    await symlink(join(tmp, 'real.txt'), join(tmp, 'alias.txt'));
    const s = await send(server, [join(tmp, 'alias.txt')]);
    expect(s.code).toBe(2);
    expect(s.err).toMatch(/skipping symbolic link/);
    expect(s.err).toMatch(/nothing to send/);
  });

  it('prints the server’s reason when a limit refuses the upload', async () => {
    const server = makeServer({ policy: { maxFilesPerShare: 1 } });
    const src = await makeTree();
    const s = await send(server, [src]);
    expect(s.code).toBe(1);
    expect(s.err).toMatch(/At most 1 files per share/);
  });

  it('a failed upload is deleted instead of lingering', async () => {
    const server = makeServer();
    await writeFile(join(tmp, 'f.txt'), 'f');
    const a = makeIo({ server });
    a.io.fetch = async (url, init) => (String(url).includes('/chunk/')
      ? new Response(JSON.stringify({ error: 'bad_size', message: 'nope' }), { status: 400 })
      : server.fetchImpl(url, init));
    expect(await run(['send', join(tmp, 'f.txt')], a.io)).toBe(1);
    expect(server.files.size).toBe(0); // deleted with its delete token
    expect(a.text.out()).toBe('');
  });
});

describe('download safety', () => {
  async function shared(server, opts = ['--views', 'unlimited']) {
    const src = await makeTree();
    const s = await send(server, [src, ...opts]);
    expect(s.code).toBe(0);
    return s.url;
  }

  it('refuses to overwrite existing files unless --force', async () => {
    const server = makeServer();
    const url = await shared(server);
    const dest = join(tmp, 'o');
    expect((await get(server, [url, '--out', dest])).code).toBe(0);
    await writeFile(join(dest, 'tree', 'a.txt'), 'local edits');

    const again = await get(server, [url, '--out', dest]);
    expect(again.code).toBe(2);
    expect(again.err).toMatch(/refusing to overwrite existing files \(use --force\)/);
    expect(await readFile(join(dest, 'tree', 'a.txt'), 'utf8')).toBe('local edits');

    const forced = await get(server, [url, '--out', dest, '--force']);
    expect(forced.code).toBe(0);
    expect(await readFile(join(dest, 'tree', 'a.txt'), 'utf8')).toBe('hello files\n');
  });

  it('a view-limited share whose files collide is saved into a new folder, never abandoned', async () => {
    const server = makeServer();
    const url = await shared(server, ['--views', '2']);
    const id = [...server.files.keys()][0];
    const dest = join(tmp, 'o');
    expect((await get(server, [url, '--out', dest])).code).toBe(0);
    await writeFile(join(dest, 'tree', 'a.txt'), 'local edits');

    const again = await get(server, [url, '--out', dest]); // spends the last view
    expect(again.code).toBe(0);
    expect(again.err).toMatch(/already exist .*saving into .*secbin-/);
    expect(await readFile(join(dest, 'tree', 'a.txt'), 'utf8')).toBe('local edits');
    expect(await readFile(join(dest, `secbin-${id}`, 'tree', 'a.txt'), 'utf8')).toBe('hello files\n');
  });

  it.skipIf(!posix)('never writes through a symlinked folder planted in the output dir', async () => {
    const server = makeServer();
    const url = await shared(server);
    const dest = join(tmp, 'o');
    const elsewhere = join(tmp, 'elsewhere');
    await mkdir(dest);
    await mkdir(elsewhere);
    await symlink(elsewhere, join(dest, 'tree'));
    const g = await get(server, [url, '--out', dest, '--force']);
    expect(g.code).toBe(1);
    expect(g.err).toMatch(/symbolic link/);
    expect(await readdir(elsewhere)).toEqual([]);
  });

  it.skipIf(!posix)('never writes through a (dangling) symlink planted at a file path, even with --force', async () => {
    const server = makeServer();
    const url = await shared(server);
    const dest = join(tmp, 'o');
    await mkdir(join(dest, 'tree'), { recursive: true });
    const victim = join(tmp, 'victim.txt');
    await symlink(victim, join(dest, 'tree', 'a.txt'));
    const g = await get(server, [url, '--out', dest, '--force']);
    expect(g.code).toBe(1);
    expect(g.err).toMatch(/symbolic link/);
    await expect(lstat(victim)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(server.chunkGets()).toHaveLength(0); // refused before downloading anything
  });

  it('an uncreatable --out fails before the view-spending open', async () => {
    const server = makeServer();
    const url = await shared(server, []);
    await writeFile(join(tmp, 'file'), 'x');
    const g = await get(server, [url, '--out', join(tmp, 'file', 'sub')]);
    expect(g.code).toBe(2);
    expect(server.opens()).toHaveLength(0);
    expect([...server.files.values()][0].left).toBe(1);
  });

  it('targetPath confines every write to the output directory', () => {
    const root = join(tmp, 'root');
    expect(targetPath(root, 'a/b.txt')).toBe(join(root, 'a', 'b.txt'));
    for (const bad of ['../x', 'a/../../x', '/etc/passwd', 'a//b', '.', 'a/./b', 'a\\..\\x', 'nul\u0000x', '']) {
      expect(() => targetPath(root, bad)).toThrow(UnsafePathError);
    }
    for (const bad of ['C:x', 'a/con.txt', 'trailing.', 'x|y']) {
      expect(() => targetPath(root, bad, 'win32')).toThrow(UnsafePathError);
    }
  });

  it.skipIf(!posix)('ensureDir / preflight / writeFile refuse symlinked components', async () => {
    const root = join(tmp, 'root');
    await mkdir(root);
    await mkdir(join(tmp, 'outside'));
    await symlink(join(tmp, 'outside'), join(root, 'dir'));
    await expect(ensureDir(root, 'dir/sub')).rejects.toThrow(UnsafePathError);
    await expect(preflight(root, [{ rel: 'dir/f.txt', dir: false }], { force: true })).rejects.toThrow(UnsafePathError);
    const chunks = (async function* () { yield new Uint8Array([1]); })();
    await expect(extractFile(root, 'dir/f.txt', chunks, { force: true, mtime: 0 })).rejects.toThrow(UnsafePathError);
    expect(await readdir(join(tmp, 'outside'))).toEqual([]);
    // A plain file in the way of a folder is refused too.
    await writeFile(join(root, 'plain'), 'x');
    await expect(ensureDir(root, 'plain/sub')).rejects.toThrow(/not a folder/);
  });

  it('an interrupted write removes the partial file', async () => {
    const root = join(tmp, 'root');
    await mkdir(root);
    const chunks = (async function* () {
      yield new Uint8Array([1, 2, 3]);
      throw new Error('network died');
    })();
    await expect(extractFile(root, 'part.bin', chunks, { force: false, mtime: 0 })).rejects.toThrow('network died');
    await expect(lstat(join(root, 'part.bin'))).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('selectEntries keeps the selected item’s own name', () => {
    const entries = [
      { path: 'a/b/c.txt', type: 'text/plain', size: 1, mtime: 0, off: 0 },
      { path: 'a/b/d/e.txt', type: 'text/plain', size: 1, mtime: 0, off: 1 },
      { path: 'a/bb.txt', type: 'text/plain', size: 1, mtime: 0, off: 2 },
      { path: 'a/b/empty', dir: true },
    ];
    expect(selectEntries(entries, 'a/b', false).map((s) => s.rel)).toEqual(['b/c.txt', 'b/d/e.txt', 'b/empty']);
    expect(selectEntries(entries, 'a/bb.txt', false).map((s) => s.rel)).toEqual(['bb.txt']);
    expect(() => selectEntries(entries, 'a/x', true)).toThrow(UsageError);
  });
});

describe('file policy', () => {
  it('declares nothing without a policy', async () => {
    const server = makeServer();
    const s = await send(server, [await makeTree(), '--views', 'unlimited']);
    expect(s.code).toBe(0);
    const init = server.calls.filter((c) => c.path === '/api/private/file').map((c) => JSON.parse(c.body));
    expect(init).toHaveLength(1);
    expect(init[0].types).toBeUndefined();
    expect(init[0].depth).toBeUndefined();
  });

  it('retries with only what the policy needs: types for a type policy, depth for a depth limit', async () => {
    const src = await makeTree();
    const server = makeServer({ policy: { fileTypeMode: 'block', fileTypeRules: ['ext:exe'] } });
    const s = await send(server, [src, '--views', 'unlimited']);
    expect(s.code).toBe(0);
    const init = server.calls.filter((c) => c.path === '/api/private/file').map((c) => JSON.parse(c.body));
    expect(init).toHaveLength(2);
    expect(init[1].types.map((t) => t.ext).sort()).toEqual(['bin', 'dat', 'txt']);
    expect(init[1].depth).toBeUndefined();

    const d = makeServer({ policy: { maxFolderDepth: 5 } });
    expect((await send(d, [src, '--views', 'unlimited'])).code).toBe(0);
    const di = d.calls.filter((c) => c.path === '/api/private/file').map((c) => JSON.parse(c.body));
    expect(di[1].depth).toBe(3); // tree/nested/deep/big.bin
    expect(di[1].types).toBeUndefined();
  });

  it('refuses locally, naming the offending paths, before anything is uploaded', async () => {
    const src = await makeTree();
    const server = makeServer({ policy: { fileTypeMode: 'allow', fileTypeRules: ['ext:txt'] } });
    const s = await send(server, [src, '--views', 'unlimited']);
    expect(s.code).toBe(2);
    expect(s.err).toMatch(/may not share these file types: .*\.bin/);
    expect(s.err).toMatch(/tree\/nested\/deep\/big\.bin/);
    expect(server.calls.some((c) => c.path.includes('/chunk/'))).toBe(false);

    const deep = makeServer({ policy: { maxFolderDepth: 1 } });
    const r = await send(deep, [src, '--views', 'unlimited']);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/at most 1 levels deep/);
  });
});
