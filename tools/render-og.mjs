#!/usr/bin/env node
// Render tools/opengraph.html → public/opengraph.png (1200×630).
//
//     node tools/render-og.mjs [--out public/opengraph.png] [--browser <path>]
//
// Dependency-free by design (the repo ships no build step): a node:http static
// server over the repo root, plus headless Chrome's built-in --screenshot. The
// server exists because @font-face is blocked on file:// origins, and the card
// is nothing without Newsreader/Geist/JetBrains Mono.
//
// Chrome is found via $CHROME, --browser, or the usual install paths. Any
// Chromium build works (Edge, Brave, a Playwright download).
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { readFile, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, resolve, extname, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const args = process.argv.slice(2);
const flag = (name) => {
  const i = args.indexOf(`--${name}`);
  return i === -1 ? null : args[i + 1];
};

const OUT = resolve(ROOT, flag('out') ?? 'public/opengraph.png');
const WIDTH = 1200;
const HEIGHT = 630;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
};

const CHROME_CANDIDATES = [
  process.env.CHROME,
  flag('browser'),
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
];

function findChrome() {
  for (const p of CHROME_CANDIDATES) if (p && existsSync(p)) return p;
  throw new Error(
    'No Chrome/Chromium found. Pass one with --browser <path> or set $CHROME.',
  );
}

// Static server, repo-root relative. Paths are normalized and confined to ROOT —
// this only ever runs locally, but a path-traversal-free server is two lines.
function serve() {
  const server = createServer(async (req, res) => {
    try {
      const rel = normalize(decodeURIComponent(req.url.split('?')[0])).replace(
        /^([/\\])+/,
        '',
      );
      const file = join(ROOT, rel);
      if (!file.startsWith(ROOT)) throw new Error('escape');
      if ((await stat(file)).isDirectory()) throw new Error('dir');
      res.writeHead(200, {
        'content-type': MIME[extname(file)] ?? 'application/octet-stream',
      });
      res.end(await readFile(file));
    } catch {
      res.writeHead(404).end('not found');
    }
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

const chrome = findChrome();
const server = await serve();
const { port } = server.address();
const url = `http://127.0.0.1:${port}/tools/opengraph.html`;

// Chrome refuses to run without a writable profile dir; keep it out of the repo.
const profile = join(tmpdir(), `binthere-og-${process.pid}`);
const code = await new Promise((resolve, reject) => {
  const child = spawn(
    chrome,
    [
      '--headless=new',
      '--disable-gpu',
      '--hide-scrollbars',
      '--force-device-scale-factor=1',
      `--user-data-dir=${profile}`,
      `--window-size=${WIDTH},${HEIGHT}`,
      // Wall-clock is unreliable for "are the webfonts painted yet"; virtual time
      // lets the page's timers run out before the frame is captured.
      '--virtual-time-budget=5000',
      `--screenshot=${OUT}`,
      url,
    ],
    { stdio: 'inherit' },
  );
  child.on('error', reject);
  child.on('exit', resolve);
});

server.close();
if (code !== 0) {
  console.error(`chrome exited ${code}`);
  process.exit(1);
}
const { size } = await stat(OUT);
console.log(`wrote ${OUT} — ${WIDTH}×${HEIGHT}, ${(size / 1024).toFixed(1)} KB`);
