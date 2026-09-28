// statements.test.js — audit B M3: what secbin says about the Drive, Drive
// shares and reverse-share uploads matches the key model v2. The server
// derives every KEK (docs/DRIVE.md §2), so a Drive share's files and a
// reverse-share upload (whose link key is sealed under the KEK) are not
// end-to-end against the server. None of the pages, docs or comments may say
// otherwise; notes and file shares stay end-to-end, and may say so.
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (f) => readFileSync(join(ROOT, f), 'utf8');

/** Claims that are no longer true (each once was, somewhere below). */
const OVERCLAIMS = [
  /server cannot read the files/i,
  /(stays?|remains?) end-to-end(?: encrypted)? (?:to the link's key )?until/i,
  /uploads? (?:stay|stays|remain|remains) end-to-end/i,
  /share stays end-to-end/i,
  /Drive shares? \((?:the|its) keys? travel/i,
  /end-to-end until (?:it is |they are )?taken in/i,
  /ciphertext it cannot open/i,
  /never the link key, the note to the uploader/i, // the reverse share's key: the server can unseal it
  /Send files, end-to-end encrypted/i,
  /Notes and shares stay end-to-end/i,
  // Re-audit N3: the pages' description, API.md, the file policy.
  /Everything is encrypted in your browser; the server never sees it/i,
  /content of every share is \W*encrypted by the client/i,
  /(?:^|[^a-z] )File names and types are end-to-end encrypted, so/,
];

/**
 * Every page, browser script, Worker module and doc (re-audit N3: so that no
 * file is missed), with the vendored and generated files left out.
 */
const walk = (dir, out = []) => {
  for (const n of readdirSync(join(ROOT, dir))) {
    const f = join(dir, n);
    if (/(^|\/)(vendor|node_modules|\.wrangler)(\/|$)/.test(f)) continue;
    if (statSync(join(ROOT, f)).isDirectory()) walk(f, out);
    else if (/\.(html|js|mjs|md|webmanifest)$/.test(n) && n !== 'sw-manifest.js') out.push(f);
  }
  return out;
};
const FILES = [
  ...walk('public'), ...walk('src'), ...walk('docs'), ...walk('cli/src').filter((f) => existsSync(join(ROOT, f))),
  ...['README.md', 'SECURITY.md', 'AGENTS.md', 'ARCHITECTURE.md', 'SPEC.md', 'CONTRIBUTING.md', 'CHANGELOG.md', 'cli/README.md'].filter((f) => existsSync(join(ROOT, f))),
];
/** Text as read: tags out (a page's words), white space folded. */
const words = (f) => read(f).replace(/<[^>]+>/g, ' ').replace(/&amp;/g, '&').replace(/\s+/g, ' ');
/** A sentence about the Drive, a Drive share or a reverse share (its links, uploads, uploader). */
const DRIVE_CTX = /\bDrive\b|\breverse[- ]shares?\b|Receive files|upload links?\b|\buploader\b|\buploads?\b/i;
/** …that claims end-to-end or zero-knowledge protection, or that the server cannot see it… */
const CLAIM = /end-to-end|zero-knowledge|server (?:never|cannot|can['’]t|does not) (?:sees?|reads?|opens?|decrypts?)/i;
/** …must say where it stops (or that the server holds the keys). */
const LIMIT = /\bnot\b|n['’]t\b|\bno longer\b|\bexcept|\bexception|\bbut\b|\bonly\b|\bunlike\b|server (?:holds|keeps|derives|can)|can decrypt|different/i;
/** The pages that list or offer Drive shares or receive links: never "zero-knowledge", never the end-to-end badge. */
const DRIVE_PAGES = ['public/dashboard/drive/index.html', 'public/r/index.html', 'public/dashboard/shares/index.html'];

describe('the security statements about the Drive and reverse shares (audit B M3, re-audit N3)', () => {
  it('scans every page, script and doc', () => {
    for (const f of ['public/dashboard/shares/index.html', 'docs/API.md', 'public/js/filepolicy.js', 'public/manifest.webmanifest', 'src/routes/drive.js', 'README.md']) expect(FILES, f).toContain(f);
    expect(FILES.filter((f) => f.endsWith('.html')).length).toBeGreaterThanOrEqual(11);
  });

  it('no sentence about the Drive or reverse shares claims end-to-end or zero-knowledge protection without its limit', () => {
    const found = [];
    for (const f of FILES) {
      for (const sentence of words(f).split(/(?<=[.;!?])\s+|\s[—–]\s|\s\|\s/)) {
        if (DRIVE_CTX.test(sentence) && CLAIM.test(sentence) && !LIMIT.test(sentence)) found.push(`${f}: "${sentence.trim().slice(0, 200)}"`);
      }
    }
    expect(found).toEqual([]);
  });

  it('the pages that list Drive shares or receive links do not call themselves zero-knowledge or end-to-end', () => {
    for (const f of DRIVE_PAGES) {
      const s = read(f);
      expect(s, f).not.toMatch(/zero-knowledge/i);
      const foot = s.slice(s.indexOf('<footer'), s.indexOf('</footer>'));
      expect(foot, f).not.toMatch(/End-to-end encrypted/);
      expect(s.match(/<meta name="description" content="([^"]*)"/)[1], f).toMatch(/Drive|send files|can decrypt/i);
    }
    // My shares says which of its kinds are end-to-end and which are not.
    expect(read('public/dashboard/shares/index.html')).toMatch(/Drive shares and “Receive files” links are encrypted in the browser with keys the server holds, so the server can decrypt them/);
    // Every other page's description is about notes and file shares only, and says so.
    for (const f of FILES.filter((x) => x.endsWith('.html') && !DRIVE_PAGES.includes(x))) {
      const d = read(f).match(/<meta name="description" content="([^"]*)"/);
      if (d) expect(d[1], f).not.toMatch(/Everything is encrypted|never sees it\b/i);
    }
  });

  it('no page, doc or comment claims more than the key model v2 gives', () => {
    const found = [];
    for (const f of FILES) {
      const text = read(f).replace(/\s+/g, ' ');
      for (const re of OVERCLAIMS) { const m = text.match(re); if (m) found.push(`${f}: "${m[0]}"`); }
    }
    expect(found).toEqual([]);
  });

  it('the uploader\'s page and the Drive page say what the server can open; neither calls itself zero-knowledge', () => {
    const r = read('public/r/index.html');
    const d = read('public/dashboard/drive/index.html');
    for (const [f, s] of [['r', r], ['drive', d]]) {
      expect(s.match(/<meta property="og:title" content="([^"]*)"/)[1], f).not.toMatch(/zero-knowledge/i);
      expect(s, f).not.toMatch(/zero-knowledge/i);
    }
    expect(read('public/js/reverse.js')).toMatch(/the server can decrypt what you send/);
    expect(d).toMatch(/A share of Drive files is not/);
    expect(d).toMatch(/“Receive files” link are encrypted in their browser to a key the server keeps under your Drive keys/);
    // The glossary says the same.
    const g = read('public/accessibility/index.html');
    expect(g).toMatch(/<dt>Receive files \(link\)<\/dt>\s*<dd>[^<]*not end-to-end encrypted/);
    expect(g).toMatch(/<dt>Drive<\/dt>\s*<dd>[^<]*not end-to-end encrypted/);
  });
});
