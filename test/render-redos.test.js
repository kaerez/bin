// render-redos.test.js — the renderers run in linear time on hostile notes
// (security audit W3 B-4): the Markdown link pattern retried from every "[" to
// the end of the paragraph (300 000 "[" froze a tab for ~35 s), and the
// highlighter's heuristic and tokenizer did the same on long words, unclosed
// strings with escapes and unclosed block comments. Each shape at the size cap
// must finish well under a second, and the output is the one the original
// regular expressions give (kept here as the reference).
import { describe, it, expect } from 'vitest';
import { parse, sanitizeUrl, MAX_MD_BYTES } from '../public/js/markdown.js';
import { tokenize, looksLikeCode, highlightTokens, MAX_HIGHLIGHT_BYTES } from '../public/js/highlight.js';

const timed = (fn) => { const t0 = performance.now(); fn(); return performance.now() - t0; };

// ── the reference: the original patterns ──────────────────────────────────────
const REF_LINK = /\[([^\]]*)\]\(([^)\s]*)\)/g;
/** The original parseLinks' matches: [index, end, label, url]. */
function refLinks(str) {
  const out = [];
  REF_LINK.lastIndex = 0;
  let m;
  while ((m = REF_LINK.exec(str))) out.push([m.index, REF_LINK.lastIndex, m[1], m[2]]);
  return out;
}
const REF_TOKEN = new RegExp([
  '(#[^\\n]*|//[^\\n]*)', '(/\\*[\\s\\S]*?\\*/)',
  '("(?:[^"\\\\\\n]|\\\\.)*"|\'(?:[^\'\\\\\\n]|\\\\.)*\'|`(?:[^`\\\\]|\\\\.)*`)',
  '(\\b\\d[\\d_]*(?:\\.\\d+)?(?:[eE][+-]?\\d+)?\\b|\\b0x[0-9a-fA-F]+\\b)', '([A-Za-z_$][\\w$]*)', '(\\s+)', '([^\\w\\s])',
].join('|'), 'g');
/** The original tokenizer's spans: [group, text] (0 for the text between matches). */
function refSpans(src) {
  const out = [];
  let last = 0;
  REF_TOKEN.lastIndex = 0;
  let m;
  while ((m = REF_TOKEN.exec(src))) {
    if (m.index > last) out.push([0, src.slice(last, m.index)]);
    out.push([m.findIndex((g, i) => i > 0 && g !== undefined), m[0]]);
    last = REF_TOKEN.lastIndex;
  }
  if (last < src.length) out.push([0, src.slice(last)]);
  return out;
}
/** The kind of span each group gave (identifiers: keyword, call or text, decided the same way as before). */
const KIND = { 1: 'com', 2: 'com', 3: 'str', 4: 'num', 7: 'punc' };
const kinds = (toks) => toks.map((t) => [['kw', 'fn'].includes(t.type) ? 'text' : t.type, t.value]);
const refKinds = (src) => refSpans(src).map(([g, v]) => [KIND[g] ?? 'text', v]);
/** The original looksLikeCode. */
function refLooksLikeCode(text) {
  const t = text.trim();
  if (t.length < 12) return false;
  const lines = t.split('\n');
  let score = 0;
  if (/[{}]/.test(t)) score++;
  if (/[;]\s*(\n|$)/.test(t)) score++;
  if (/=>|::|->|!=|==|>=|<=|\+\+|--|&&|\|\|/.test(t)) score++;
  if (lines.filter((l) => /^\s{2,}\S/.test(l) || /^\t+\S/.test(l)).length >= 2) score++;
  if (/\b(function|def|class|import|const|let|var|public|private|package|func|fn|#include|return)\b/.test(t)) score++;
  if (/[A-Za-z_$][\w$]*\s*\(/.test(t)) score++;
  if (/[A-Za-z_$][\w$]*\s*=[^=]/.test(t)) score++;
  return score >= 3;
}

let seed = 20260928;
const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
const gen = (alphabet, n) => Array.from({ length: n }, () => alphabet[Math.floor(rnd() * alphabet.length)]).join('');

describe('B-4: Markdown links in linear time', () => {
  it('300 000 "[" (and "[a", "[](x", "](" shapes) at the size cap parse in well under a second', () => {
    expect(MAX_MD_BYTES).toBe(300_000);
    for (const src of ['['.repeat(300_000), '[a'.repeat(150_000), '[](x'.repeat(75_000), '[x]('.repeat(75_000), `${'['.repeat(150_000)}${']('.repeat(75_000)}`]) {
      expect(src.length).toBeLessThanOrEqual(MAX_MD_BYTES);
      let blocks;
      const ms = timed(() => { blocks = parse(src); });
      expect(ms, `${src.slice(0, 8)}…`).toBeLessThan(1000);
      expect(blocks.length).toBeGreaterThan(0);
    }
  });

  it('finds exactly the links the original pattern found, with the same text (normal and random input)', () => {
    // One paragraph without block syntax or inline code, so the links are all parse() changes.
    const expected = (md) => {
      const hrefs = [];
      let text = '';
      let last = 0;
      for (const [i, end, label, url] of refLinks(md)) {
        text += md.slice(last, i);
        const href = sanitizeUrl(url);
        if (href) hrefs.push(href);
        text += label;
        last = end;
      }
      return { hrefs, text: text + md.slice(last) };
    };
    const flat = (md) => {
      const hrefs = [];
      let text = '';
      const walk = (nodes) => { for (const n of nodes || []) { if (n.type === 'link') hrefs.push(n.href); if (n.value !== undefined) text += n.value; walk(n.children); } };
      for (const b of parse(md)) walk(b.inline);
      return { hrefs, text };
    };
    const strip = (x) => ({ hrefs: x.hrefs, text: x.text.replace(/[*_]/g, '') }); // emphasis markers aside
    const normal = [
      'see [the docs](https://example.com/docs) and [mail](mailto:a@example.com).',
      '[a](https://x.test) [b](javascript:alert(1)) [c](https://y.test/p?q=1)',
      '[nested [brackets]](https://z.test) [spaces](https://a.test b) [](https://empty.test)',
      'line one [split\nlabel](https://split.test) end',
      '[a](https://one.test)(extra) [b] (https://no.test) [c](https://c.test) [**bold**](https://b.test)',
    ];
    for (const md of normal) expect(strip(flat(md)), md).toEqual(strip(expected(md)));
    expect(flat(normal[0]).hrefs).toEqual(['https://example.com/docs', 'mailto:a@example.com']);
    for (let i = 0; i < 5000; i++) {
      const md = `x${gen(['[', ']', '(', ')', 'x', ' ', '\u00a0', '\n', 'https://h.test', '](', '**', 'mailto:m', 'y'], 1 + Math.floor(rnd() * 60))}`;
      // One paragraph only: no blank line, no line that starts a list, heading, quote or fence.
      if (md.split('\n').some((l) => l.trim() === '' || /^\s*[-*+#>`]/.test(l))) continue;
      expect(strip(flat(md)), JSON.stringify(md)).toEqual(strip(expected(md)));
    }
  });
});

describe('B-4: the highlighter in linear time', () => {
  const SHAPES = {
    'long words (heuristic)': '1_'.repeat(150_000),
    'long words with e': '1e'.repeat(150_000),
    'unclosed block comments': '/*a'.repeat(100_000),
    'unclosed \' strings with escapes': `'${"\\'".repeat(149_999)}`,
    'unclosed " strings with escapes': `"${'\\"'.repeat(149_999)}`,
    'unclosed ` strings with escapes': `\`${'\\`'.repeat(149_999)}`,
  };
  for (const [name, src] of Object.entries(SHAPES)) {
    it(`${name}: looksLikeCode and tokenize at the size cap finish in well under a second`, () => {
      expect(src.length).toBeLessThanOrEqual(MAX_HIGHLIGHT_BYTES);
      expect(timed(() => looksLikeCode(src))).toBeLessThan(1000);
      let toks;
      expect(timed(() => { toks = tokenize(src); })).toBeLessThan(1000);
      expect(toks.map((t) => t.value).join('')).toBe(src); // still lossless
      expect(timed(() => highlightTokens(src))).toBeLessThan(1000);
    });
  }

  it('the heuristic says what the original said (normal and random input)', () => {
    const normal = ['function f(x) {\n  return x;\n}\n', 'const a = 1;\nlet b = a + 2;\n', 'Dear Bob, see you at 10 (or later) = fine.', '1 = 2 and 3(4) and 5 = 6 x', 'x == y and z(w) and more words'];
    for (const t of normal) expect(looksLikeCode(t), t).toBe(refLooksLikeCode(t));
    for (let i = 0; i < 20000; i++) {
      const s = gen(['a', 'Z', '1', '_', '$', ' ', '  ', '\t', '\n', '(', '=', '==', ';', '{', '}', 'é', 'fn', '=>'], 1 + Math.floor(rnd() * 40));
      expect(looksLikeCode(s), JSON.stringify(s)).toBe(refLooksLikeCode(s));
    }
  });

  it('the tokenizer gives the original spans (normal and random input)', () => {
    const normal = [
      'const s = "a \\" b"; // comment\nlet t = \'x\'; /* block */ f(1.5e3, 0xff);',
      'ls src/*.js && echo "unterminated\nnext line',
      'a = `multi\nline ${x}` + \'\\\'\' + "\\\\"',
      '/* one */ /* two', "it's a 'test' of \\'escapes",
    ];
    for (const src of normal) expect(kinds(tokenize(src)), src).toEqual(refKinds(src));
    for (let i = 0; i < 20000; i++) {
      const src = gen(['a', '1', '_', '"', "'", '`', '\\', '\n', '\r', ' ', '/', '*', '#', '(', '.', 'e', '\u2028'], 1 + Math.floor(rnd() * 50));
      expect(kinds(tokenize(src)), JSON.stringify(src)).toEqual(refKinds(src));
    }
  });
});
