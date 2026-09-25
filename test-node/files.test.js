// files.test.js — file-share format v2 (SPEC.md §12): path rules, manifest
// validation, packed/padded layout, chunk crypto (reorder/truncation), the ZIP
// writer (validated by an independent unzip) and MIME detection.
import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import {
  checkPath, checkMime, layout, buildManifest, validateManifest, paddedLength, chunkCount,
  importFileKey, encryptChunk, decryptChunk, readStreamChunk, chunkSpan, buildTree, filesUnder,
  CHUNK, PAD, ManifestError,
} from '../public/js/files.js';
import { createZipWriter, crc32 } from '../public/js/zip.js';
import { detectMime, sniff, fromExtension, normalizeMime, OCTET } from '../public/js/mime.js';
import { utf8 } from '../public/js/bytes.js';

describe('path rules — fail closed, never repair', () => {
  it('accepts ordinary relative paths', () => {
    for (const p of ['a.txt', 'dir/sub/file.bin', 'ünï cödé/файл.md', 'a b/c-d_e.f']) expect(checkPath(p)).toBe(p);
  });
  it('rejects traversal, absolute, empty segments, backslashes and control characters', () => {
    for (const p of ['', '/etc/passwd', '../x', 'a/../b', 'a/./b', './a', 'a//b', 'a/', 'a\\b', 'a\u0000b', 'a\nb', 'x\u007f',
      'a'.repeat(256), `${'a/'.repeat(2100)}b`]) {
      expect(() => checkPath(p), JSON.stringify(p.slice(0, 20))).toThrow(ManifestError);
    }
  });
  it('validates MIME types strictly', () => {
    expect(checkMime('image/png')).toBe('image/png');
    for (const t of ['image', 'IMAGE/PNG', 'text/plain; charset=utf-8', '', 'a/b/c', '<script>/x']) {
      expect(() => checkMime(t), t).toThrow(ManifestError);
    }
  });
});

describe('layout + manifest', () => {
  const files = [
    { path: 'docs/a.txt', type: 'text/plain', size: 5, mtime: 1 },
    { path: 'docs/sub/b.png', type: 'image/png', size: 3, mtime: 2 },
    { path: 'c.bin', type: OCTET, size: 0, mtime: 3 },
  ];
  it('lays files out back to back and pads to a PAD multiple', () => {
    const l = layout(files, ['empty/dir']);
    expect(l.total).toBe(8);
    expect(l.padded).toBe(PAD);
    expect(l.chunks).toBe(1);
    expect(l.entries.map((e) => e.off ?? 'dir')).toEqual([0, 5, 8, 'dir']);
    expect(paddedLength(0)).toBe(PAD);
    expect(chunkCount(CHUNK + 1)).toBe(2);
  });
  it('rejects duplicates and file/folder conflicts', () => {
    expect(() => layout([files[0], files[0]])).toThrow(/duplicate/);
    expect(() => layout([{ ...files[0], path: 'docs' }, files[1]])).toThrow(/conflict/);
    expect(() => layout([files[0]], ['docs/a.txt'])).toThrow(/conflict/);
  });
  it('round-trips a manifest and rejects tampered structure', () => {
    const l = layout(files, ['empty/dir']);
    const m = buildManifest({ entries: l.entries, total: l.total });
    expect(validateManifest(JSON.parse(JSON.stringify(m)))).toEqual(m);
    const bad = [
      { ...m, extra: 1 },
      { ...m, v: 1 },
      { ...m, total: m.total + 1 },
      { ...m, entries: [{ ...m.entries[0], off: 1 }, ...m.entries.slice(1)] },
      { ...m, entries: [{ ...m.entries[0], path: '../evil' }, ...m.entries.slice(1)] },
      { ...m, view: { rules: [{ match: 'mime', value: 'x', renderer: 'html' }], maxBytes: 1 } },
    ];
    for (const b of bad) expect(() => validateManifest(b)).toThrow(ManifestError);
  });
  it('builds a tree and selects files under a folder', () => {
    const l = layout(files, ['empty/dir']);
    const t = buildTree(l.entries);
    expect([...t.dirs.keys()].sort()).toEqual(['docs', 'empty']);
    expect(t.dirs.get('docs').dirs.get('sub').files[0].path).toBe('docs/sub/b.png');
    expect(filesUnder(l.entries, 'docs').map((e) => e.path)).toEqual(['docs/a.txt', 'docs/sub/b.png']);
    expect(filesUnder(l.entries, '').length).toBe(3);
  });
});

describe('chunk crypto', () => {
  it('round-trips, and rejects reordering, truncation and tampering', async () => {
    const m = buildManifest({ entries: [{ path: 'x', type: OCTET, size: 1, mtime: 0, off: 0 }], total: 1 });
    const key = await importFileKey(m.fk);
    const c0 = await encryptChunk(key, 0, 2, utf8('zero'));
    const c1 = await encryptChunk(key, 1, 2, utf8('one'));
    expect(new TextDecoder().decode(await decryptChunk(key, 0, 2, c0))).toBe('zero');
    await expect(decryptChunk(key, 1, 2, c0)).rejects.toThrow(/authentication/); // reorder
    await expect(decryptChunk(key, 0, 1, c0)).rejects.toThrow(/authentication/); // truncated share
    const t = c1.slice(); t[0] ^= 1;
    await expect(decryptChunk(key, 1, 2, t)).rejects.toThrow(/authentication/);
  });
  it('reads a packed stream chunk with zero padding across file boundaries', async () => {
    const data = [utf8('hello'), utf8('world!')];
    const sources = [{ off: 0, size: 5 }, { off: 5, size: 6 }].map((s, i) => ({ ...s, read: async (a, b) => data[i].slice(a, b) }));
    const c = await readStreamChunk(sources, 0, 11);
    expect(c.length).toBe(PAD);
    expect(new TextDecoder().decode(c.slice(0, 11))).toBe('helloworld!');
    expect(c.slice(11).every((b) => b === 0)).toBe(true);
    expect(chunkSpan(0, 0)).toBeNull();
    expect(chunkSpan(CHUNK - 1, 2)).toEqual([0, 1]);
  });
});

describe('zip writer', () => {
  it('produces an archive an independent unzip accepts, with folders and UTF-8 names', async () => {
    const parts = [];
    const z = createZipWriter({ write: async (b) => { parts.push(b); } });
    await z.addDir('empty dir');
    async function* gen(s) { yield utf8(s.slice(0, 3)); yield utf8(s.slice(3)); }
    await z.addFile('docs/ünï.txt', Date.UTC(2024, 0, 2, 3, 4, 6), gen('hello zip'));
    await z.addFile('b.bin', 0, gen(''));
    await z.finish();
    const buf = Buffer.concat(parts.map((p) => Buffer.from(p)));
    const dir = mkdtempSync(path.join(tmpdir(), 'secbin-zip-'));
    try {
      const f = path.join(dir, 'a.zip');
      writeFileSync(f, buf);
      const out = execFileSync('unzip', ['-t', f]).toString();
      expect(out).toMatch(/No errors detected/);
      const listing = execFileSync('python3', ['-c', `import zipfile,sys;z=zipfile.ZipFile(sys.argv[1]);print("|".join(sorted(z.namelist())));print(z.read("docs/ünï.txt").decode())`, f]).toString();
      expect(listing).toContain('b.bin|docs/ünï.txt|empty dir/');
      expect(listing).toContain('hello zip');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
  it('crc32 matches the standard check value', () => {
    expect(crc32(utf8('123456789')).toString(16)).toBe('cbf43926');
  });
});

describe('MIME detection', () => {
  it('sniffs signatures, falls back to extension, then octet-stream', () => {
    expect(sniff(Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]))).toBe('image/png');
    expect(sniff(utf8('%PDF-1.7 blah'))).toBe('application/pdf');
    expect(fromExtension('notes.MD')).toBe('text/markdown');
    expect(detectMime({ name: 'x', platformType: '', head: utf8('%PDF-1.4') })).toBe('application/pdf');
    expect(detectMime({ name: 'x.png', platformType: 'Image/PNG; foo=1', head: null })).toBe('image/png');
    expect(detectMime({ name: 'unknown', platformType: '', head: utf8('abcd') })).toBe(OCTET);
    expect(normalizeMime('bad type')).toBeNull();
  });
});
