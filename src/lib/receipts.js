// receipts.js — read receipts (SECURITY.md, "Read receipts"): record that a
// share was opened, or that an upload session of a Receive link started (a
// view of a reverse share, docs/REVERSE.md §5), with what the request itself
// revealed. The Directory keeps them in `opens` (src/directory-do.js
// recordOpen: its throttles, limits and retention), whatever the share's kind.

import { directory } from './guard.js';
import { parseUserAgent, parseLanguages } from './ua.js';

// A flood guard in front of the single Directory object: beyond
// RECENT_OPEN_BURST opens of one share from one address within a minute, this
// isolate stops recording them (the Directory throttles stored receipts again
// for all isolates). Ordinary use, several people behind one address
// included, is counted in full.
const recentOpens = new Map();
const RECENT_OPEN_MS = 60_000;
const RECENT_OPEN_BURST = 5;
const RECENT_OPEN_MAX = 5000;
function flooding(key) {
  const t = Date.now();
  const e = recentOpens.get(key);
  if (e && t - e.start < RECENT_OPEN_MS) {
    e.n += 1;
    return e.n > RECENT_OPEN_BURST;
  }
  if (recentOpens.size >= RECENT_OPEN_MAX) recentOpens.clear();
  recentOpens.set(key, { start: t, n: 1 });
  return false;
}

/**
 * Read receipt: record that share `id` was opened (a Receive link: that an
 * upload session started), with what the request itself revealed (address,
 * Cloudflare's coarse location, browser, OS, languages). Never fails the
 * open.
 */
export async function recordOpen(env, request, id) {
  try {
    if (flooding(`${id}|${request.headers.get('cf-connecting-ip') || ''}`)) return;
    const ua = parseUserAgent(request.headers.get('user-agent'));
    const cf = request.cf || {};
    await directory(env).recordOpen(id, {
      ip: request.headers.get('cf-connecting-ip') || '',
      country: typeof cf.country === 'string' ? cf.country : '',
      region: typeof cf.region === 'string' ? cf.region : '',
      city: typeof cf.city === 'string' ? cf.city : '',
      browser: ua.browser, version: ua.version, os: ua.os,
      langs: parseLanguages(request.headers.get('accept-language')),
    });
  } catch (e) {
    console.warn('secbin: read receipt not recorded', e && e.message ? e.message : e);
  }
}
