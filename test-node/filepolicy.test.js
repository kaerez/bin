// filepolicy.test.js — the shared file-policy rules (browser, Worker, CLI).
import { describe, it, expect } from 'vitest';
import { parseRule, normalizeRules, fileExt, pathDepth, declare, refusedTypes, checkDeclaredTypes, describeType, uncheckableExt } from '../public/js/filepolicy.js';
import { resolveLimits } from '../src/lib/settings.js';

describe('file policy rules', () => {
  it('parses ext and mime rules and refuses anything else', () => {
    expect(parseRule('ext:PDF')).toEqual({ kind: 'ext', value: 'pdf' });
    expect(parseRule('ext:.tar')).toEqual({ kind: 'ext', value: 'tar' });
    expect(parseRule('mime:image/*')).toEqual({ kind: 'mime', value: 'image/*' });
    for (const bad of ['pdf', 'ext:', 'ext:a b', 'mime:*/*', 'mime:image', 'mime:image/png;x', 'glob:*', 42, null]) expect(parseRule(bad)).toBeNull();
    expect(normalizeRules(['ext:PDF', 'ext:pdf', 'mime:image/*'])).toEqual(['ext:pdf', 'mime:image/*']);
    expect(() => normalizeRules(['nope'])).toThrow(/invalid rule/);
    expect(() => normalizeRules(Array(201).fill('ext:a'))).toThrow(/at most/);
  });

  it('derives extensions and folder depth from share paths', () => {
    expect(fileExt('docs/Report.PDF')).toBe('pdf');
    expect(fileExt('.bashrc')).toBe('');
    expect(fileExt('noext')).toBe('');
    expect(fileExt('trailing.')).toBe('');
    expect(pathDepth('a.txt')).toBe(0);
    expect(pathDepth('x/y/a.txt')).toBe(2);
    expect(pathDepth('x/y', true)).toBe(2);
  });

  it('declares de-duplicated types and the maximum depth', () => {
    const d = declare([
      { path: 'a/b/one.pdf', type: 'application/pdf' },
      { path: 'two.PDF', type: 'application/pdf' },
      { path: 'a/b/c/d', dir: true },
      { path: 'x.bin' },
    ]);
    expect(d.depth).toBe(4);
    expect(d.types).toEqual([{ ext: 'pdf', mime: 'application/pdf' }, { ext: 'bin', mime: 'application/octet-stream' }]);
  });

  it('allow and block lists refuse the right types', () => {
    const types = [{ ext: 'pdf', mime: 'application/pdf' }, { ext: 'png', mime: 'image/png' }, { ext: 'exe', mime: 'application/x-msdownload' }];
    expect(refusedTypes('any', ['ext:pdf'], types)).toEqual([]);
    expect(refusedTypes('allow', ['ext:pdf', 'mime:image/*'], types)).toEqual([types[2]]);
    expect(refusedTypes('block', ['ext:exe'], types)).toEqual([types[2]]);
    expect(refusedTypes('allow', [], types)).toEqual(types);
    expect(describeType(types[2])).toBe('.exe (application/x-msdownload)');
    expect(describeType({ ext: '', mime: 'text/plain' })).toBe('(no extension) (text/plain)');
  });

  it('validates untrusted declarations', () => {
    expect(checkDeclaredTypes([{ ext: 'PDF', mime: 'Application/PDF' }])).toEqual([{ ext: 'pdf', mime: 'application/pdf' }]);
    for (const bad of [null, 'x', [{}], [{ ext: 'a b', mime: 'text/plain' }], [{ ext: 'a', mime: 'text' }], Array(1001).fill({ ext: 'a', mime: 'text/plain' })]) {
      expect(checkDeclaredTypes(bad)).toBeNull();
    }
  });

  it('sees the extension the recipient’s OS will: trailing dots and spaces cannot hide it', () => {
    for (const p of ['tool.exe.', 'tool.exe ', 'dir/tool.EXE. .']) expect(fileExt(p)).toBe('exe');
    expect(refusedTypes('block', ['ext:exe'], declare([{ path: 'tool.exe.', type: 'application/octet-stream' }]).types)).toHaveLength(1);
    expect(uncheckableExt(`a.${'x'.repeat(40)}`)).toBe(true);
    expect(uncheckableExt('a.t@r')).toBe(true);
    for (const p of ['a.pdf', 'README', '.bashrc', 'a.']) expect(uncheckableExt(p)).toBe(false);
  });

  it('accepts every MIME type a manifest accepts', () => {
    const long = `application/${'x'.repeat(120)}`;
    expect(checkDeclaredTypes([{ ext: 'bin', mime: long }])).toEqual([{ ext: 'bin', mime: long }]);
  });

  it('resolves the type mode and its rule list together, from the same level', () => {
    const global = { fileTypeMode: 'block', fileTypeRules: ['ext:exe'] };
    expect(resolveLimits(global, { fileTypeMode: 'allow' })).toMatchObject({ fileTypeMode: 'allow', fileTypeRules: [] });
    expect(resolveLimits(global, { fileTypeRules: ['ext:pdf'] })).toMatchObject({ fileTypeMode: 'any', fileTypeRules: ['ext:pdf'] });
    expect(resolveLimits(global, {})).toMatchObject({ fileTypeMode: 'block', fileTypeRules: ['ext:exe'] });
  });
});
