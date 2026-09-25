// viewer.test.js — the safe file viewer and composer helpers under happy-dom:
// policy intersection (sender snapshot ∩ live global policy ∩ size caps),
// inert text rendering of hostile content, image refusal by signature /
// dimensions (SVG is never rendered), the DOM builder's unsafe-prop guard, and
// the dropped-folder walker (batched readEntries, empty folders).
import { describe, it, expect } from 'vitest';
import { allowedRenderer, matchRenderer, renderPreview, imageSize, MAX_IMAGE_PIXELS } from '../public/js/viewer.js';
import { h } from '../public/js/common.js';
import { walkEntry } from '../public/js/walk.js';

const enc = (s) => new TextEncoder().encode(s);
const rules = [
  { match: 'mime', value: 'image/*', renderer: 'image' },
  { match: 'ext', value: 'md', renderer: 'markdown' },
  { match: 'mime', value: 'text/plain', renderer: 'text' },
];
const file = (path, type, size = 10) => ({ path, type, size, mtime: 0, off: 0 });

describe('viewer policy', () => {
  const global = { enabled: true, maxBytes: 1000, rules };
  it('first matching rule wins; ext and mime globs work', () => {
    expect(matchRenderer(file('a.png', 'image/png'), rules)).toBe('image');
    expect(matchRenderer(file('notes.md', 'text/plain'), rules)).toBe('markdown');
    expect(matchRenderer(file('x.bin', 'application/octet-stream'), rules)).toBeNull();
  });
  it('requires the sender snapshot AND the live global policy AND both size caps', () => {
    const snap = { maxBytes: 500, rules };
    expect(allowedRenderer(file('a.png', 'image/png'), snap, global)).toBe('image');
    expect(allowedRenderer(file('a.png', 'image/png'), null, global)).toBeNull(); // sender did not allow viewing
    expect(allowedRenderer(file('a.png', 'image/png'), snap, { ...global, enabled: false })).toBeNull(); // switched off globally
    expect(allowedRenderer(file('a.png', 'image/png'), snap, { ...global, rules: [] })).toBeNull(); // no longer allowed globally
    expect(allowedRenderer(file('a.png', 'image/png', 600), snap, global)).toBeNull(); // over the sender cap
    expect(allowedRenderer(file('a.png', 'image/png', 1001), { ...snap, maxBytes: 5000 }, global)).toBeNull(); // over the global cap
    expect(allowedRenderer({ path: 'dir', dir: true }, snap, global)).toBeNull();
  });
});

describe('renderPreview — nothing executes', () => {
  it('renders hostile HTML as inert text', async () => {
    const div = document.createElement('div');
    await renderPreview(div, file('x.txt', 'text/plain'), enc('<script>alert(1)</script><img src=x onerror=alert(1)>'), 'text');
    expect(div.querySelector('script, img, iframe')).toBeNull();
    expect(div.textContent).toContain('<script>');
  });
  it('refuses to render SVG (or anything not a raster signature) as an image', async () => {
    const div = document.createElement('div');
    const svg = enc('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><script>alert(1)</script></svg>');
    await expect(renderPreview(div, file('x.svg', 'image/svg+xml'), svg, 'image')).rejects.toThrow(/not a supported image/);
    await expect(renderPreview(div, file('x.png', 'image/png'), enc('not really a png'), 'image')).rejects.toThrow(/not a supported image/);
    expect(div.querySelector('img, svg')).toBeNull();
  });
  it('refuses decompression-bomb dimensions before decoding', async () => {
    const png = new Uint8Array(33);
    png.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52]);
    new DataView(png.buffer).setUint32(16, 50000);
    new DataView(png.buffer).setUint32(20, 50000);
    expect(imageSize(png, 'image/png')).toEqual({ width: 50000, height: 50000 });
    expect(50000 * 50000).toBeGreaterThan(MAX_IMAGE_PIXELS);
    const div = document.createElement('div');
    await expect(renderPreview(div, file('big.png', 'image/png'), png, 'image')).rejects.toThrow(/too large/);
  });
  it('refuses PDFs that are not PDFs and unknown renderers', async () => {
    const div = document.createElement('div');
    await expect(renderPreview(div, file('x.pdf', 'application/pdf'), enc('hello'), 'pdf')).rejects.toThrow(/not a PDF/);
    await expect(renderPreview(div, file('x', 'x/y'), enc('hello'), 'html')).rejects.toThrow(/cannot be previewed/);
  });
});

describe('h() — DOM construction only', () => {
  it('sets text via textContent and refuses event handlers / innerHTML / style', () => {
    const el = h('div.a.b', { text: '<b>x</b>', title: 't' });
    expect(el.innerHTML).toBe('&lt;b&gt;x&lt;/b&gt;');
    expect(el.className).toBe('a b');
    for (const bad of [{ onclick: 'alert(1)' }, { innerHTML: '<b>' }, { outerHTML: '<b>' }, { style: 'x' }, { srcdoc: 'x' }]) expect(() => h('div', bad)).toThrow(/unsafe/);
  });
  it('refuses dangerous URL schemes in URL-valued attributes', () => {
    for (const bad of ['javascript:alert(1)', ' JaVaScRiPt:alert(1)', 'java\tscript:alert(1)', 'vbscript:x', 'data:text/html,<script>alert(1)</script>', 'file:///etc/passwd']) {
      expect(() => h('a', { href: bad })).toThrow(/unsafe URL/);
      expect(() => h('img', { src: bad })).toThrow(/unsafe URL/);
    }
    expect(() => h('a', { href: 'data:image/png;base64,AAAA' })).toThrow(/unsafe URL/); // data: only for image sources
    expect(h('a', { href: 'https://example.com/x' }).getAttribute('href')).toBe('https://example.com/x');
    expect(h('a', { href: '/dashboard/' }).getAttribute('href')).toBe('/dashboard/');
    expect(h('a', { href: 'mailto:a@b.c' }).getAttribute('href')).toBe('mailto:a@b.c');
    expect(h('img', { src: 'data:image/gif;base64,R0lGOD' }).getAttribute('src')).toBe('data:image/gif;base64,R0lGOD');
    expect(h('video', { src: 'blob:https://secbin.test/1234' }).getAttribute('src')).toMatch(/^blob:/);
  });
});

describe('dropped-folder walker', () => {
  // Fake File and Directory Entries API tree; readEntries returns batches of 2.
  const fileEntry = (fullPath, content) => ({ isFile: true, isDirectory: false, fullPath, file: (ok) => ok(new File([content], fullPath.split('/').pop())) });
  const dirEntry = (fullPath, children) => ({
    isFile: false, isDirectory: true, fullPath,
    createReader() {
      let i = 0;
      return { readEntries: (ok) => { const batch = children.slice(i, i + 2); i += 2; ok(batch); } };
    },
  });
  it('recurses through batched readEntries and reports empty folders', async () => {
    const root = dirEntry('/top', [
      fileEntry('/top/a.txt', 'a'), fileEntry('/top/b.txt', 'b'), fileEntry('/top/c.txt', 'c'),
      dirEntry('/top/sub', [fileEntry('/top/sub/d.txt', 'd')]),
      dirEntry('/top/empty', []),
    ]);
    const files = [];
    const empty = [];
    await walkEntry(root, async (p, f) => { files.push([p, await f.text()]); }, (p) => empty.push(p));
    expect(files).toEqual([['top/a.txt', 'a'], ['top/b.txt', 'b'], ['top/c.txt', 'c'], ['top/sub/d.txt', 'd']]);
    expect(empty).toEqual(['top/empty']);
  });
});
