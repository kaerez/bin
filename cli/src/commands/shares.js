// shares — the account's own shares, with an API key: `list` (scope "read")
// and `revoke` (scope "manage"). Everything else about a share (labels,
// extensions, receipts) is in the dashboard and the REST API (docs/API.md).
//
// Rows come from the server and are printed to the user's terminal, so every
// string is stripped of control characters (no ANSI/OSC injection) and capped.
import { parseArgs } from 'node:util';
import { refuseInlineApiKey, resolveApiKey } from '../apikey.js';
import { ApiError, Client } from '../client.js';
import { UsageError } from '../errors.js';
import { parseUrlOrId, requireServer } from '../url.js';

const STATUSES = ['active', 'revoked', 'expired', 'consumed', 'deleted', 'ended'];
const MAX_PAGES = 100; // 50 rows each

// eslint-disable-next-line no-control-regex
const safe = (v, n = 100) => String(v ?? '').replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').slice(0, n);
const when = (t) => (Number.isSafeInteger(t) && t > 0 ? new Date(t * 1000).toISOString().slice(0, 16).replace('T', ' ') : '-');

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
    io.stdout(JSON.stringify({ total, rows }) + '\n');
    return 0;
  }
  for (const r of rows) {
    const views = r.left !== null && r.left !== undefined ? `${safe(r.left, 8)}/${safe(r.views_total, 8)} left` : r.views_total === null ? 'unlimited' : '-';
    io.stdout([safe(r.id, 30), safe(r.kind, 8).padEnd(6), safe(r.status, 10).padEnd(9), views.padEnd(12), `${safe(r.opens ?? 0, 8)} opens`.padEnd(10),
      `expires ${when(r.expires)}`, r.locked ? 'locked' : '', safe(r.label)].filter(Boolean).join('  ') + '\n');
  }
  io.stderr(`${rows.length} of ${total} share${total === 1 ? '' : 's'}\n`);
  return 0;
}

/** secbin revoke <share-url | id> */
export async function cmdRevoke(args, io) {
  const { values, positionals } = parse(args, {});
  if (positionals.length !== 1) throw new UsageError('usage: secbin revoke <share-url | id>');
  const { server, id } = parseUrlOrId(positionals[0], values.server ?? io.env.SECBIN_SERVER);
  const apiKey = await resolveApiKey({ file: values['api-key-file'], io, what: 'revoking a share' });
  const client = new Client(server, io.fetch, { apiKey });
  try {
    await client.revokeShare(id);
  } catch (e) {
    if (e instanceof ApiError && e.code === 'share_locked') throw new ApiError('the administrator has locked this share; it cannot be revoked', 423, 'share_locked');
    throw e;
  }
  io.stderr(`revoked ${id}\n`);
  return 0;
}
