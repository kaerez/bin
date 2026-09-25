#!/usr/bin/env node
// create-note.mjs — create an end-to-end encrypted secbin note over REST from
// Node.js 22, using this repository's own protocol module (the same code the
// browser runs). Run from a clone of the repository:
//
//   export SECBIN_API_KEY=sbk_...            # an API key with the "notes" scope
//   echo "the secret" | node examples/api/create-note.mjs https://bin.example.com --views 1
//
// The note is encrypted before it is sent; the printed link carries the key in
// its #fragment. The key and the optional password (SECBIN_NOTE_PASSWORD) come
// from the environment, never from the command line.
import { encryptPaste } from '../../public/js/crypto.js';

const [server, ...rest] = process.argv.slice(2);
if (!server) { console.error('usage: node create-note.mjs <server> [--views N] [--expire 24h]'); process.exit(2); }
const opt = (name, def) => { const i = rest.indexOf(name); return i >= 0 ? rest[i + 1] : def; };
const key = process.env.SECBIN_API_KEY || '';
if (!key.startsWith('sbk_')) { console.error('set SECBIN_API_KEY to an API key (sbk_...)'); process.exit(2); }

let text = '';
for await (const chunk of process.stdin) text += chunk;
if (!text) { console.error('nothing on stdin'); process.exit(2); }

const views = opt('--views') ? Number(opt('--views')) : undefined;
const { body, fragment } = await encryptPaste({
  text, password: process.env.SECBIN_NOTE_PASSWORD || '', bar: views !== undefined, views, expire: opt('--expire', '24h'),
});
const base = server.replace(/\/+$/, '');
const res = await fetch(`${base}/api/private/paste`, {
  method: 'POST',
  headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json', 'user-agent': 'secbin-example-node/1' },
  body: JSON.stringify({ paste: body, label: opt('--label', '') }),
});
const out = await res.json().catch(() => ({}));
if (!res.ok) { console.error(`error ${res.status}: ${out.message || out.error || res.statusText}`); process.exit(1); }
console.log(`${base}/p/${out.id}#${fragment}`);
console.error(`delete token: ${out.deletetoken}`);
