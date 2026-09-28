// statements.test.js — audit B M3: what secbin says about the Drive, Drive
// shares and reverse-share uploads matches the key model v2. The server
// derives every KEK (docs/DRIVE.md §2), so a Drive share's files and a
// reverse-share upload (whose link key is sealed under the KEK) are not
// end-to-end against the server. None of the pages, docs or comments may say
// otherwise; notes and file shares stay end-to-end, and may say so.
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
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
];
const FILES = [
  'public/js/reverse.js', 'public/js/reversekeys.js', 'public/js/driveclient.js', 'public/r/index.html',
  'public/dashboard/drive/index.html', 'public/dashboard/js/drive-app.js', 'public/accessibility/index.html',
  'src/routes/reverse.js', 'src/routes/drive.js', 'README.md', 'SECURITY.md', 'AGENTS.md', 'docs/DRIVE.md', 'docs/REVERSE.md',
];

describe('the security statements about the Drive and reverse shares (audit B M3)', () => {
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
