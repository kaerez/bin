#!/usr/bin/env node
// create-note.mjs — create an end-to-end encrypted secbin note over REST from
// Node.js 22, using this repository's own protocol module (the same code the
// browser runs). Run from a clone of the repository:
//
//   export SECBIN_API_KEY=sbk_...            # an API key with the "notes" scope
//   echo "the secret" | node examples/api/create-note.mjs https://bin.example.com --views 1
//
// --encrypt-only (no server, no key): print the encrypted request body on
// stdout and the link's fragment on stderr, for sending with another client
// (curl --data @note.json …/api/private/paste). See docs/API.md.
//
// The note is encrypted before it is sent; the printed link carries the key in
// its #fragment. The key and the optional password (SECBIN_NOTE_PASSWORD) come
// from the environment, never from the command line.
import { parseArgs } from 'node:util';
import { encryptPaste } from '../../public/js/crypto.js';

const USAGE = 'usage: node create-note.mjs <server> [--views N] [--expire 24h] [--label TEXT]\n       node create-note.mjs --encrypt-only [--views N] [--expire 24h] [--label TEXT] > note.json';
let values, positionals;
try {
  ({ values, positionals } = parseArgs({
    allowPositionals: true,
    options: { views: { type: 'string' }, expire: { type: 'string', default: '24h' }, label: { type: 'string', default: '' }, 'encrypt-only': { type: 'boolean', default: false } },
  }));
} catch (e) { console.error(`${e.message}\n${USAGE}`); process.exit(2); }
const encryptOnly = values['encrypt-only'];
const [server] = positionals;
if (encryptOnly ? positionals.length : positionals.length !== 1) { console.error(USAGE); process.exit(2); }
const key = process.env.SECBIN_API_KEY || '';
if (!encryptOnly && !key.startsWith('sbk_')) { console.error('set SECBIN_API_KEY to an API key (sbk_...)'); process.exit(2); }

let text = '';
for await (const chunk of process.stdin) text += chunk;
if (!text) { console.error('nothing on stdin'); process.exit(2); }

const views = values.views === undefined ? undefined : Number(values.views);
const { body, fragment } = await encryptPaste({
  text, password: process.env.SECBIN_NOTE_PASSWORD || '', bar: views !== undefined, views, expire: values.expire,
});
const request = { paste: body, label: values.label };
if (encryptOnly) {
  console.log(JSON.stringify(request));
  console.error(`fragment: ${fragment}`); // the link is <server>/p/<id>#<fragment>
  process.exit(0);
}
const base = server.replace(/\/+$/, '');
const res = await fetch(`${base}/api/private/paste`, {
  method: 'POST',
  headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json', 'user-agent': 'secbin-example-node/1' },
  body: JSON.stringify(request),
});
const out = await res.json().catch(() => ({}));
if (!res.ok) { console.error(`error ${res.status}: ${out.message || out.error || res.statusText}`); process.exit(1); }
console.log(`${base}/p/${out.id}#${fragment}`);
console.error(`delete token: ${out.deletetoken}`);
