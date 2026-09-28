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
  // Audit of #74, L4: a Receive link's note and password are sealed with the link's key, which
  // the server can unseal — "never sees" / "only link holders" say more than that.
  /\bnote\b[^.]{0,160}server never sees/i,
  /server never sees the note\b/i,
  /link['’]s key.{0,200}?The server never sees the password/i,
  /only (?:the )?link holders? can read/i,
  // Notes, links and credentials sent through a Receive link are Drive content: never end-to-end.
  /(?:received|sent through a “?Receive”? link)[^.]{0,120}(?:notes?|links?|credentials?)[^.]{0,80}(?:are|is|stay|stays|remain|remains) end-to-end/i,
  /server (?:never|cannot|can['’]t) (?:sees?|reads?|opens?|decrypts?) (?:a |the |any )?(?:received )?credentials?\b/i,
  /credential[^.]{0,80}only the recipient can (?:read|open|decrypt)/i,
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
const DRIVE_CTX = /\bDrive\b|\breverse[- ]shares?\b|[“"]Receive[”"]|Receive…|Receive \(link\)|\bReceive links?\b|\blink['’]s (?:private )?key\b|upload links?\b|\buploader\b|\buploads?\b/i;
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
      const parts = words(f).split(/(?<=[.;!?])\s+|\s[—–]\s|\s\|\s/);
      for (const [i, sentence] of parts.entries()) {
        // A part that goes on from the one before (after ";" or ":", lower case) takes its context too
        // ("…with the link's key; the server never sees them.").
        const ctx = /^\s*[a-z]/.test(sentence) ? `${parts[i - 1] ?? ''} ${sentence}` : sentence;
        if (DRIVE_CTX.test(ctx) && CLAIM.test(sentence) && !LIMIT.test(sentence)) found.push(`${f}: "${sentence.trim().slice(0, 200)}"`);
      }
    }
    expect(found).toEqual([]);
  });

  it('the pages that list Drive shares or receive links do not call themselves zero-knowledge or end-to-end', () => {
    for (const f of DRIVE_PAGES) {
      const s = read(f);
      expect(s, f).not.toMatch(/zero-knowledge/i);
      // The footer is the same on every page (below): "Encrypted in your browser".
      const foot = s.slice(s.indexOf('<footer'), s.indexOf('</footer>'));
      expect(foot, f).not.toMatch(/End-to-end encrypted/);
      expect(s.match(/<meta name="description" content="([^"]*)"/)[1], f).toMatch(/Drive|send files|can decrypt/i);
    }
    // My shares says which of its kinds are end-to-end and which are not.
    expect(read('public/dashboard/shares/index.html')).toMatch(/Drive shares and “Receive” links are encrypted in the browser with keys the server holds, so the server can decrypt them/);
    // Every other page's description is about notes and file shares only, and says so.
    for (const f of FILES.filter((x) => x.endsWith('.html') && !DRIVE_PAGES.includes(x))) {
      const d = read(f).match(/<meta name="description" content="([^"]*)"/);
      if (d) expect(d[1], f).not.toMatch(/Everything is encrypted|never sees it\b/i);
    }
  });

  it('every page\'s footer says "Encrypted in your browser" (true of everything, the Drive included); where notes and file shares are end-to-end, the page itself says so', () => {
    const pages = FILES.filter((f) => f.endsWith('.html') && f.startsWith('public/') && read(f).includes('<footer'));
    expect(pages.length).toBeGreaterThanOrEqual(11);
    for (const f of pages) {
      const s = read(f);
      const foot = s.slice(s.indexOf('<footer'), s.indexOf('</footer>'));
      expect(foot, f).toContain('<span class="feat" role="listitem">Encrypted in your browser</span>');
      expect(foot, f).not.toMatch(/end-to-end|zero-knowledge/i);
    }
    const index = words('public/index.html');
    // The landing page and the composer: notes and file shares, end-to-end, with the key in the link.
    expect(index).toMatch(/End-to-end encrypted notes and file shares that self-destruct/);
    expect(index).toMatch(/Notes and file shares are end-to-end encrypted: encrypted in your browser, with the key only in the link\./);
    expect(words('public/dashboard/index.html')).toMatch(/Notes and file shares are end-to-end encrypted: encrypted in your browser, with the key only in the link\./);
    // The viewer: a note always; a file share and a Drive share each as it is.
    expect(index).toMatch(/End-to-end encrypted: this note was decrypted in your browser with the key in its link\./);
    const view = read('public/js/view.js');
    expect(view).toMatch(/const END_TO_END = 'End-to-end encrypted: these files are decrypted in your browser with the key in the link\./);
    expect(view).toMatch(/const FROM_DRIVE = 'Shared from the sender’s Drive: encrypted in the sender’s browser, but not end-to-end\. The server holds the keys to the sender’s Drive and can decrypt these files\.'/);
    // The glossary: both terms, and which is which.
    const glossary = words('public/accessibility/index.html');
    expect(glossary).toMatch(/Encrypted in your browser What every page’s footer says/);
    expect(glossary).toMatch(/End-to-end encrypted Encrypted on the sender’s device and decrypted only on the recipient’s\..*Notes and file shares are; the Drive, shares of Drive files and files sent to you through a “Receive” link are not\./);
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
    expect(d).toMatch(/“Receive” link are encrypted in their browser to a key the server keeps under your Drive keys/);
    // A credential sent through a Receive link: the uploader page warns, on the form, that the recipient's server can decrypt it.
    const up = read('public/js/reverse.js');
    expect(up).toMatch(/The recipient’s server can decrypt this\. A credential sent here is encrypted in your browser, but to a key the server keeps under the recipient’s Drive keys, so it is not end-to-end encrypted/);
    expect(up).toMatch(/id: 'reverse-sec-warning', role: 'note', text: CREDENTIAL_WARNING/);
    expect(up).toMatch(/files with their names and types, notes, links and credentials — is encrypted in your browser[^']*the server can decrypt what you send/);
    // The Drive's viewer of a received note, link or credential, and the Receive dialog's hint, say it too.
    const app = read('public/dashboard/js/drive-app.js');
    expect(app).toMatch(/received through one of your “Receive” links\. Like your other Drive files it is encrypted with keys the server holds, so it is not end-to-end encrypted/);
    expect(read('public/dashboard/js/reverse-edit.js')).toMatch(/Senders are told that the server can decrypt it: like your Drive, it is not end-to-end encrypted/);
    // The docs.
    expect(read('docs/REVERSE.md')).toMatch(/### 3\.1 Notes, links and credentials[\s\S]*Like all Drive content they are \*\*not end-to-end\*\*: the server holds the keys/);
    expect(read('SECURITY.md')).toMatch(/Like every Drive item a received credential is \*\*not\s+end-to-end encrypted\*\*: the recipient's server can decrypt it/);
    expect(read('public/r/index.html')).toMatch(/<meta name="description" content="[^"]*the recipient’s server can decrypt\./);
    // The glossary says the same.
    const g = read('public/accessibility/index.html');
    expect(g).toMatch(/<dt>Receive \(link\)<\/dt>\s*<dd>[^<]*not end-to-end encrypted/);
    expect(g).toMatch(/<dt>Receive \(link\)<\/dt>\s*<dd>[^<]*a note, a link or a credential\. [^<]*not end-to-end encrypted/);
    expect(g).toMatch(/<dt>Drive<\/dt>\s*<dd>[^<]*not end-to-end encrypted/);
    // Audit RT-6: the glossary no longer says only files come through a Receive link.
    expect(g).toMatch(/anything sent to you through a “Receive” link are not/);
    expect(g).not.toMatch(/files sent to you through a “Receive” link are not/);
    expect(g).toMatch(/how many visits may start sending something — files, a note, a link or a credential/);
    expect(g).not.toMatch(/how many visits may start sending files \(/);
  });

  it('the per-kind receive quotas, the take-in checks and credential downloads are described as they are (audit RT-1, RT-4, RT-5)', () => {
    const sec = read('SECURITY.md');
    const rev = read('docs/REVERSE.md');
    // RT-5: counts only, no content, and for how long.
    expect(sec).toMatch(/keep counts only —\s+sessions per kind per quota window, no content — each count row until 400 days after its\s+window's first count/);
    expect(rev).toMatch(/the Directory keeps \*\*counts only\*\* — how many sessions of that kind the user\s+received in each quota window, no content, no link or sender — each count row until 400 days/);
    // RT-6 / RT-1: the server holds a session to one item of its size; what arrives is held at take-in by the user's browser.
    expect(sec).not.toMatch(/session reserves one item of bounded size/);
    expect(sec).toMatch(/the user's browser fails at take-in\s+an item whose sealed kind is not the one its session declared/);
    // RT-4: ZIPs never hold credentials.
    expect(rev).toMatch(/\*\*ZIPs\s+never include credentials\*\*/);
  });
});
