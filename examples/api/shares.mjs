#!/usr/bin/env node
// shares.mjs — manage your own secbin shares over REST from Node.js 22 (no
// dependencies): list them, show one, read its receipts, label, extend and
// revoke it, read your policy, or delete a share with its delete token.
//
//   export SECBIN_API_KEY=sbk_...     # "read" to look, "manage" to change, "policy" for policy
//   node examples/api/shares.mjs https://bin.example.com list [--status active]
//   node examples/api/shares.mjs https://bin.example.com show <id>
//   node examples/api/shares.mjs https://bin.example.com receipts <id>
//   node examples/api/shares.mjs https://bin.example.com label <id> "quarterly report"
//   node examples/api/shares.mjs https://bin.example.com extend <id> [--views 5] [--days 7]
//   node examples/api/shares.mjs https://bin.example.com revoke <id>
//   node examples/api/shares.mjs https://bin.example.com policy
//   SECBIN_DELETE_TOKEN=... node examples/api/shares.mjs https://bin.example.com delete <id>
//
// A key only ever reaches its user's own shares. Labels are NOT encrypted.
// Server strings are printed as JSON, so they cannot steer the terminal. The
// key and the delete token come from the environment, never the command line.
import { parseArgs } from 'node:util';

const USAGE = `usage: node shares.mjs <server> list [--status <s>] | show <id> | receipts <id> | label <id> <text>
       | extend <id> [--views N] [--days D] | revoke <id> | policy | delete <id>`;
const die = (msg, code = 2) => { console.error(msg); process.exit(code); };
let values, positionals;
try {
  ({ values, positionals } = parseArgs({
    allowPositionals: true,
    options: { status: { type: 'string' }, views: { type: 'string' }, days: { type: 'string' } },
  }));
} catch (e) { die(`${e.message}\n${USAGE}`); }
const [server, command, id, text] = positionals;
if (!server || !command) die(USAGE);
const base = server.replace(/\/+$/, '');
const needsId = ['show', 'receipts', 'label', 'extend', 'revoke', 'delete'].includes(command);
if (needsId && !/^[A-Za-z0-9_-]{1,64}$/.test(id || '')) die(`${command} needs a share id\n${USAGE}`);
if (positionals.length !== (command === 'label' ? 4 : needsId ? 3 : 2)) die(USAGE);
const key = process.env.SECBIN_API_KEY || '';
if (command !== 'delete' && !key.startsWith('sbk_')) die('set SECBIN_API_KEY to an API key (sbk_...)');

/** One JSON call; exits 1 with the server's error on failure. */
async function call(path, { method = 'GET', body, headers = {} } = {}) {
  const h = { 'user-agent': 'secbin-example-node/1', ...headers };
  if (command !== 'delete') h.authorization = `Bearer ${key}`;
  if (body !== undefined) h['content-type'] = 'application/json';
  const res = await fetch(`${base}${path}`, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'error' });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) die(`HTTP ${res.status} ${data.error || ''}: ${data.message || 'request failed'}`, 1);
  return data;
}
const share = `/api/private/shares/${id}`;
// JSON escapes C0 controls but not DEL / C1 (U+009B is an 8-bit CSI): escape those too.
const show = (v, indent) => console.log(JSON.stringify(v, null, indent).replace(/[\u007f-\u009f]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`));

switch (command) {
  case 'list': {
    // Follow every page (50 rows each).
    const rows = [];
    for (;;) {
      const qs = new URLSearchParams({ offset: String(rows.length) });
      if (values.status) qs.set('status', values.status);
      const page = await call(`/api/private/shares?${qs}`);
      rows.push(...page.rows);
      if (!page.rows.length || rows.length >= page.total) break;
    }
    for (const s of rows) show({ id: s.id, kind: s.kind, status: s.status, left: s.left, views: s.views_total, opens: s.opens, expires: s.expires, label: s.label });
    console.error(`${rows.length} shares`);
    break;
  }
  case 'show': show((await call(share)).share, 2); break;
  case 'receipts': {
    const { total, fields, rows } = await call(`${share}/opens`);
    console.error(`${total} opens; details: ${fields.join(', ') || 'times only'}`);
    for (const r of rows) show({ ...r, time: new Date(r.ts * 1000).toISOString() });
    break;
  }
  case 'label': show(await call(share, { method: 'PATCH', body: { label: text } })); break;
  case 'extend': {
    // Views and expiry only grow; views only for view-limited shares.
    const body = {};
    if (values.views !== undefined) body.views = values.views === 'unlimited' ? null : Number(values.views);
    if (values.days !== undefined) body.expires = Math.floor(Date.now() / 1000) + Math.round(Number(values.days) * 86400);
    if (!Object.keys(body).length) die(`extend needs --views and/or --days\n${USAGE}`);
    show(await call(share, { method: 'PATCH', body }));
    break;
  }
  case 'revoke': show(await call(`${share}/revoke`, { method: 'POST', headers: { 'x-secbin-intent': '1' } })); break;
  case 'policy': show(await call('/api/private/policy')); break;
  case 'delete': {
    // No API key: the delete token is the capability. File shares' ids start with "f".
    const token = process.env.SECBIN_DELETE_TOKEN || '';
    if (!token) die('set SECBIN_DELETE_TOKEN to the delete token');
    show(await call(`/api/${id.startsWith('f') ? 'file' : 'paste'}/${id}`, { method: 'DELETE', headers: { 'x-delete-token': token } }));
    break;
  }
  default: die(USAGE);
}
