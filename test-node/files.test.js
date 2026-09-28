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
  CHUNK, PAD, ManifestError, cleanPath, cleanEntries,
} from '../public/js/files.js';
import { validateRefsManifest } from '../public/js/refsmanifest.js';
import { createZipWriter, crc32, memberName } from '../public/js/zip.js';
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

// A-1 (ZIP slip): names that pass checkPath raw but not once cleaned (cleanName).
const Z = '\u200b';
const SLIPS = [`docs/.${Z}./.${Z}./tmp/x`, `${Z}/etc/x`, `a/${Z}/b`, `.${Z}`, `${Z}`, `a/.${Z}./..${Z}/b`];

describe('received paths: cleaned first, then checked (ZIP slip)', () => {
  it('cleanPath refuses what cleaning makes unsafe, and keeps real names', () => {
    for (const p of SLIPS) {
      expect(() => checkPath(p), JSON.stringify(p)).not.toThrow(); // the raw check alone lets them through
      expect(() => cleanPath(p), JSON.stringify(p)).toThrow(ManifestError);
    }
    expect(cleanPath(`in\u202evoice${Z}.pdf`)).toBe('invoice.pdf');
    expect(cleanPath('שלום/ملف.txt')).toBe('שלום/ملف.txt');
  });

  const v2 = (paths) => {
    const body = paths.map((path, i) => ({ path, type: 'text/plain', size: 1, mtime: 0, off: i }));
    return validateManifest({ v: 2, fk: 'A'.repeat(43), chunk: CHUNK, total: paths.length, entries: body, view: null });
  };
  const v3 = (paths, dirs = []) => validateRefsManifest({
    v: 3, kind: 'refs', dirs, view: null,
    entries: paths.map((path, ref) => ({ path, size: 1, type: 'text/plain', mtime: 0, ref, fk: 'A'.repeat(43) })),
  });

  it('v2 and v3 manifests: a path that is only safe before cleaning refuses the manifest', () => {
    for (const p of SLIPS) {
      expect(() => cleanEntries(v2([p]).entries), JSON.stringify(p)).toThrow(ManifestError);
      expect(() => cleanEntries(v3([p]).entries), JSON.stringify(p)).toThrow(ManifestError);
      expect(() => cleanEntries(v3(['ok.txt'], [p]).entries), JSON.stringify(p)).toThrow(ManifestError);
    }
  });

  it('two names that clean to the same path, or a file that becomes a folder, refuse the manifest', () => {
    expect(() => cleanEntries(v2(['a.txt', `a${Z}.txt`]).entries)).toThrow(/duplicate path/);
    expect(() => cleanEntries(v3(['a.txt', `a.txt${Z}`]).entries)).toThrow(/duplicate path/);
    expect(() => cleanEntries(v2(['d', `d${Z}/x.txt`]).entries)).toThrow(/file\/folder conflict/);
    expect(() => cleanEntries(v3(['d'], [`${Z}d`]).entries)).toThrow(/file\/folder conflict/);
  });

  it('cleaned names are kept and marked renamed; an unchanged manifest is returned as is', () => {
    const m = v2(['plain.txt', `in\u202evoice.pdf`]);
    const out = cleanEntries(m.entries);
    expect(out.map((e) => [e.path, e.renamed === true])).toEqual([['plain.txt', false], ['invoice.pdf', true]]);
    const same = v2(['a.txt', 'b/c.txt']);
    expect(cleanEntries(same.entries)).toBe(same.entries);
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
  it('checks every member name itself, cleaned, right before writing it: no "..", absolute, drive-letter, backslash, empty or duplicate names', async () => {
    const bad = [...SLIPS, '../x', '/etc/x', 'a//b', 'a/', '', 'C:/x', 'c:x', `${Z}C:/x`, 'a\\..\\x', 'a\u0000b'];
    for (const name of bad) {
      expect(() => memberName(name), JSON.stringify(name)).toThrow(ManifestError);
      const parts = [];
      const z = createZipWriter({ write: async (b) => { parts.push(b); } });
      await expect(z.addFile(name, 0, (async function* () { yield utf8('x'); })()), JSON.stringify(name)).rejects.toThrow(/unsafe name in the ZIP/);
      if (name !== 'a/') await expect(z.addDir(name), JSON.stringify(name)).rejects.toThrow(/unsafe name in the ZIP/); // a folder may end in "/"
      expect(parts, 'nothing is written for a refused name').toEqual([]);
    }
    // Hidden characters are removed from what is written; the same name twice is refused.
    expect(memberName(`in\u202evoice${Z}.pdf`)).toBe('invoice.pdf');
    const z = createZipWriter({ write: async () => {} });
    await z.addFile('a.txt', 0, (async function* () {})());
    await expect(z.addFile(`a${Z}.txt`, 0, (async function* () {})())).rejects.toThrow(/duplicate/);
    await z.addDir('d/');
    await expect(z.addDir('d')).rejects.toThrow(/duplicate/);
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
