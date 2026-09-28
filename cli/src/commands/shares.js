// shares — the account's own shares, with an API key: `list`, `show` and
// `receipts` (scope "read"), `label`, `extend` and `revoke` (scope "manage").
// The same calls as the dashboard's My shares page (docs/API.md): only the key
// user's own shares, under the administrator's locks and the API limits.
//
// Rows come from the server and are printed to the user's terminal, so every
// string is stripped of control characters (no ANSI/OSC injection) and capped.
import { parseArgs } from 'node:util';
import { refuseInlineApiKey, resolveApiKey } from '../apikey.js';
import { ApiError, Client } from '../client.js';
import { UsageError } from '../errors.js';
import { parseLabel } from '../lifecycle.js';
import { parseUrlOrId, requireServer } from '../url.js';
import { expireSeconds, MAX_VIEWS } from '../../vendor/format.js';

const STATUSES = ['active', 'revoked', 'expired', 'consumed', 'deleted', 'ended'];
const MAX_PAGES = 100; // 50 rows each

// eslint-disable-next-line no-control-regex
const safe = (v, n = 100) => String(v ?? '').replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').slice(0, n);
// JSON escapes C0 controls but not DEL / C1 (U+009B is an 8-bit CSI): escape those too.
const jsonLine = (v) => JSON.stringify(v).replace(/[\u007f-\u009f]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`) + '\n';
const when = (t) => (Number.isSafeInteger(t) && t > 0 ? new Date(t * 1000).toISOString().slice(0, 16).replace('T', ' ') : '-');
/** A share's expiry: a Receive link (reverse share) may have none (`expires: null`). */
const expiry = (t) => (t === null ? 'none' : when(t));

function parse(args, options) {
  refuseInlineApiKey(args);
  try {
    return parseArgs({ args, options: { server: { type: 'string', short: 's' }, 'api-key-file': { type: 'string' }, ...options }, allowPositionals: true, strict: true });
  } catch (e) {
    throw new UsageError(e.message);
  }
}

/** secbin list [--status <s>] [--json] */
export async function cmdList(args, io) {
  const { values, positionals } = parse(args, { status: { type: 'string' }, json: { type: 'boolean', short: 'j', default: false } });
  if (positionals.length) throw new UsageError('usage: secbin list [--status <status>] [--json]');
  if (values.status !== undefined && !STATUSES.includes(values.status)) {
    throw new UsageError(`invalid --status "${safe(values.status, 40)}" (one of: ${STATUSES.join(', ')})`);
  }
  const server = requireServer(values.server, io.env);
  const apiKey = await resolveApiKey({ file: values['api-key-file'], io, what: 'listing your shares' });
  const client = new Client(server, io.fetch, { apiKey });
  const rows = [];
  let total = 0;
  for (let page = 0; page < MAX_PAGES; page++) {
    const d = await client.listShares({ status: values.status, offset: rows.length });
    total = d.total;
    rows.push(...d.rows.filter((r) => r && typeof r === 'object' && typeof r.id === 'string'));
    if (!d.rows.length || rows.length >= total) break;
  }
  if (values.json) {
    io.stdout(jsonLine({ total, rows }));
    return 0;
  }
  for (const r of rows) {
    const views = r.left !== null && r.left !== undefined ? `${safe(r.left, 8)}/${safe(r.views_total, 8)} left` : r.views_total === null ? 'unlimited' : '-';
    io.stdout([safe(r.id, 30), safe(r.kind, 8).padEnd(6), safe(r.status, 10).padEnd(9), views.padEnd(12), `${safe(r.opens ?? 0, 8)} opens`.padEnd(10),
      `expires ${expiry(r.expires)}`, r.locked ? 'locked' : '', safe(r.label)].filter(Boolean).join('  ') + '\n');
  }
  io.stderr(`${rows.length} of ${total} share${total === 1 ? '' : 's'}\n`);
  return 0;
}

/** The share named by the one positional argument, with a client holding the API key. */
async function oneShare(args, io, options, usage, what) {
  const { values, positionals } = parse(args, options);
  if (positionals.length !== 1) throw new UsageError(`usage: ${usage}`);
  const { server, id } = parseUrlOrId(positionals[0], values.server ?? io.env.SECBIN_SERVER);
  const apiKey = await resolveApiKey({ file: values['api-key-file'], io, what });
  return { values, id, client: new Client(server, io.fetch, { apiKey }) };
}

/** A locked share is explained in words; other errors pass through. */
async function unlessLocked(fn, verb) {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof ApiError && e.code === 'share_locked') throw new ApiError(`the administrator has locked this share; it cannot be ${verb}`, 423, 'share_locked');
    throw e;
  }
}

/** secbin show <share-url | id> [--json] */
export async function cmdShow(args, io) {
  const { values, id, client } = await oneShare(args, io, { json: { type: 'boolean', short: 'j', default: false } },
    'secbin show <share-url | id> [--json]', 'showing a share');
  const r = await client.getShare(id);
  if (values.json) {
    io.stdout(jsonLine(r));
    return 0;
  }
  const views = r.views_total === null ? 'unlimited' : `${safe(r.left ?? '-', 8)} of ${safe(r.views_total, 8)} left`;
  io.stdout([`id       ${safe(r.id, 30)}`, `kind     ${safe(r.kind, 8)}`, `status   ${safe(r.status, 10)}${r.locked ? ' (locked by the administrator)' : ''}`,
    `views    ${views}`, `opens    ${safe(r.opens ?? 0, 8)}`, `created  ${when(r.created)}`, `expires  ${expiry(r.expires)}`, `label    ${safe(r.label)}`].join('\n') + '\n');
  return 0;
}

/** secbin receipts <share-url | id> [--json] */
export async function cmdReceipts(args, io) {
  const { values, id, client } = await oneShare(args, io, { json: { type: 'boolean', short: 'j', default: false } },
    'secbin receipts <share-url | id> [--json]', 'reading receipts');
  const d = await client.shareOpens(id);
  if (values.json) {
    io.stdout(jsonLine(d));
    return 0;
  }
  const cols = ['ip', 'country', 'region', 'city', 'browser', 'browser_ver', 'os', 'langs'];
  for (const r of d.rows) {
    if (!r || typeof r !== 'object') continue;
    io.stdout([when(r.ts), ...cols.filter((c) => r[c] !== undefined && r[c] !== null && r[c] !== '').map((c) => safe(r[c], 60))].join('  ') + '\n');
  }
  io.stderr(`${d.total} open${d.total === 1 ? '' : 's'}${d.rows.length < d.total ? ` (${d.rows.length} shown)` : ''}; details: ${d.fields.map((f) => safe(f, 30)).join(', ') || 'times only'}\n`);
  return 0;
}

/** secbin label <share-url | id> <text>   ("" clears the label) */
export async function cmdLabel(args, io) {
  const { values, positionals } = parse(args, {});
  if (positionals.length !== 2) throw new UsageError('usage: secbin label <share-url | id> <text>   (the label is NOT encrypted; "" clears it)');
  const { server, id } = parseUrlOrId(positionals[0], values.server ?? io.env.SECBIN_SERVER);
  const label = parseLabel(positionals[1]) ?? '';
  const apiKey = await resolveApiKey({ file: values['api-key-file'], io, what: 'labelling a share' });
  const client = new Client(server, io.fetch, { apiKey });
  await unlessLocked(() => client.updateShare(id, { label }), 'changed');
  io.stderr(label ? `labelled ${id} (the label is not encrypted)\n` : `cleared the label of ${id}\n`);
  return 0;
}

/** secbin extend <share-url | id> [--views <n|unlimited>] [--expire <n>m|h|d] */
export async function cmdExtend(args, io) {
  const usage = 'secbin extend <share-url | id> [--views <n|unlimited>] [--expire <n>m|h|d]';
  const { values, id, client } = await oneShare(args, io, { views: { type: 'string' }, expire: { type: 'string' } }, usage, 'extending a share');
  const patch = {};
  if (values.views !== undefined) {
    if (values.views === 'unlimited') patch.views = null;
    else {
      const n = /^[1-9][0-9]{0,5}$/.test(values.views) ? Number(values.views) : NaN;
      if (!(n >= 1 && n <= MAX_VIEWS)) throw new UsageError(`invalid --views "${safe(values.views, 20)}" (the new view limit, 1 to ${MAX_VIEWS}, or "unlimited")`);
      patch.views = n;
    }
  }
  if (values.expire !== undefined) {
    const sec = expireSeconds(values.expire);
    if (sec === null) throw new UsageError(`invalid --expire "${safe(values.expire, 20)}" (from now: <n>m, <n>h or <n>d, up to 365 days)`);
    patch.expires = Math.floor(Date.now() / 1000) + sec;
  }
  if (!Object.keys(patch).length) throw new UsageError(`usage: ${usage} — give --views, --expire or both`);
  await unlessLocked(() => client.updateShare(id, patch), 'extended');
  const said = [patch.views !== undefined ? `views ${patch.views === null ? 'unlimited' : patch.views}` : '', patch.expires ? `expires ${when(patch.expires)} UTC` : ''].filter(Boolean);
  io.stderr(`extended ${id}: ${said.join(', ')}\n`);
  return 0;
}

/** secbin revoke <share-url | id> */
export async function cmdRevoke(args, io) {
  const { id, client } = await oneShare(args, io, {}, 'secbin revoke <share-url | id>', 'revoking a share');
  await unlessLocked(() => client.revokeShare(id), 'revoked');
  io.stderr(`revoked ${id}\n`);
  return 0;
}
