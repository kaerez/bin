// lifecycle.js — the share-lifecycle flags shared by `create` and `send`:
// --views, --expire and --label, validated locally against the protocol bounds
// (format.js) so a typo fails with exit 2 before anything is encrypted or sent.
// The server may apply stricter per-account limits; it refuses (never silently
// lowers) a request that exceeds them.
import { DEFAULT_EXPIRE, expireSeconds, MAX_VIEWS } from '../vendor/format.js';
import { UsageError } from './errors.js';

export const DEFAULT_VIEWS = 1;
export { DEFAULT_EXPIRE };
const MAX_LABEL = 100;

/** "--views <n|unlimited>" → integer 1…MAX_VIEWS, or null for unlimited. */
export function parseViews(raw) {
  if (raw === undefined) return DEFAULT_VIEWS;
  if (raw === 'unlimited') return null;
  const n = /^[1-9][0-9]{0,5}$/.test(raw) ? Number(raw) : NaN;
  if (!(n >= 1 && n <= MAX_VIEWS)) {
    throw new UsageError(`invalid --views "${raw}" (a number from 1 to ${MAX_VIEWS}, or "unlimited")`);
  }
  return n;
}

/** "--expire <n>m|h|d" → the validated expiry string (1 minute … 365 days). */
export function parseExpire(raw) {
  if (raw === undefined) return DEFAULT_EXPIRE;
  if (expireSeconds(raw) === null) {
    throw new UsageError(`invalid --expire "${raw}" (use <n>m, <n>h or <n>d, from 1 minute to 365 days — e.g. 90m, 24h, 7d)`);
  }
  return raw;
}

/**
 * "--label <text>" → the label, or undefined. Labels are stored UNENCRYPTED in
 * the account's share list (they are for the owner's own bookkeeping), so they
 * are length-capped and must be plain printable text.
 */
export function parseLabel(raw) {
  if (raw === undefined) return undefined;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f-\u009f]/.test(raw)) throw new UsageError('--label must not contain control characters');
  const v = raw.trim();
  if (v.length > MAX_LABEL) throw new UsageError(`--label is too long (${MAX_LABEL} characters max)`);
  return v === '' ? undefined : v;
}

/** "90m" → "90 minutes", "1d" → "1 day". Input is already validated. */
export function describeExpire(expire) {
  const n = Number(expire.slice(0, -1));
  const unit = { m: 'minute', h: 'hour', d: 'day' }[expire.slice(-1)];
  return `${n} ${unit}${n === 1 ? '' : 's'}`;
}

/** One accurate sentence about what happens to the share (stderr / wizard). */
export function lifecycleLine({ what, views, expire }) {
  const dur = describeExpire(expire);
  if (views === null) return `anyone with the link can open ${what} any number of times until it expires in ${dur}`;
  if (views === 1) return `${what} can be opened once, then it is deleted; unopened, it expires in ${dur}`;
  return `${what} can be opened ${views} times; it is deleted after the last view or in ${dur}, whichever comes first`;
}
