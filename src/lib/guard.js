// guard.js — Worker-side brute-force protection: manual allow/block IP rules
// (cached per isolate), per-scope failure tracking in sharded Guard DOs, and
// the DISABLE_BFP / DISABLE_BFP_SETUP kill switches.
//
// The Guard never sees an address at rest: its rows are keyed by a keyed hash
// of the network (guardTag) and hold the address only sealed under the
// Guard's record key (or in the clear before there is a keyring), both keys
// handed out by the Directory and cached here like the settings
// (src/lib/records.js, SECURITY.md, "Records at rest").

import { bfpDisabled, binding } from './config.js';
import { parseIp, parseCidr, formatCidr, parseRule, ruleContains, trackingKey } from './ip.js';
import { clientIp } from './http.js';
import { GUARD_SHARDS, guardShardIndex } from '../guard-do.js';
import { guardTag, guardWhere, isGuardTag, sealRecord } from './records.js';
import { bytesFromB64url } from '../../public/js/bytes.js';

const CACHE_MS = 30 * 1000;
let rulesCache = { at: 0, rules: [] };
let settingsCache = { at: 0, settings: null };
let publicConfigCache = { at: 0, config: null };
let guardKeysCache = { at: 0, keys: null };
/**
 * The Guard shards whose legacy rows the Directory's pass has re-keyed
 * (legacyDone) → when this isolate learnt it. Asked again after CACHE_MS: a
 * shard clears its flag when a row keyed by an address arrives after it (an
 * isolate of the release before, during a rollout).
 */
let legacyDoneShards = new Map();

export const directory = (env) => {
  const ns = binding(env, 'DIRECTORY');
  return ns.get(ns.idFromName('directory'));
};

/** Drop the isolate caches (called after an admin changes rules/settings). */
export function invalidateGuardCaches() {
  rulesCache = { at: 0, rules: [] };
  settingsCache = { at: 0, settings: null };
  publicConfigCache = { at: 0, config: null };
  guardKeysCache = { at: 0, keys: null };
  legacyDoneShards = new Map();
}

/**
 * The Guard's keys (Directory.guardKeys): the tag key (HMAC) and, once there
 * is a keyring, the Guard's table key with its id → { tag, kid, seal | null }
 * (32-byte keys, in this isolate's memory only). Cached per isolate like the settings:
 * after a root change, addresses may be sealed under the previous root's key
 * for up to CACHE_MS (they stay readable; the Directory's pass re-seals them).
 */
async function guardKeys(env) {
  if (!guardKeysCache.keys || Date.now() - guardKeysCache.at > CACHE_MS) {
    const r = await directory(env).guardKeys();
    guardKeysCache = {
      at: Date.now(),
      keys: { tag: bytesFromB64url(r.tag), kid: r.kid ?? null, seal: r.key ? bytesFromB64url(r.key) : null },
    };
  }
  return guardKeysCache.keys;
}

/** The Guard key of a tracking key the owner typed (an address or a prefix, as the Guard's rows showed it before the tags). */
export async function guardKeyFor(env, trackingKeyText) {
  return guardTag((await guardKeys(env)).tag, trackingKeyText);
}

/**
 * A key the owner typed in the block / unblock routes, as the Guard keys a
 * network: a bare IPv4 address → "/32", a bare IPv6 address → the Guard's
 * IPv6 prefix (`guard.v6Prefix`, a /64 by default), a CIDR block in its
 * canonical form; a row key (a tag), or anything with a suffix ("…#<name
 * hash>"), keeps that suffix. Anything else is left as it is.
 */
export async function guardKeyTyped(env, text) {
  if (typeof text !== 'string' || isGuardTag(text)) return text;
  const hash = text.indexOf('#');
  const head = hash < 0 ? text : text.slice(0, hash);
  const tail = hash < 0 ? '' : text.slice(hash);
  let key = head;
  if (parseIp(head)) key = trackingKey(head, (await cachedSettings(env))['guard.v6Prefix']);
  else if (head.includes('/')) { const c = parseCidr(head); if (c) key = formatCidr(c); }
  return `${key}${tail}`;
}

/** An address the owner typed, sealed as the `scope` row of `tag` keeps it ({ addr, rk }). */
export async function sealedTyped(env, scope, tag, text) {
  const k = await guardKeys(env);
  return k.seal ? { addr: await sealRecord(k.seal, guardWhere(scope, tag), text), rk: k.kid } : { addr: text, rk: null };
}

/**
 * The caller's Guard key (a tag of its tracking key), once per request and
 * key: callers pass `{ ...g, key: other }` for a scope keyed otherwise (a
 * wider network, a network and a username), which must not reuse g's tag.
 */
async function tagOf(env, g) {
  if (!g.tag || g.tagFor !== g.key) {
    g.tagFor = g.key;
    g.tag = (async () => guardTag((await guardKeys(env)).tag, g.key))();
  }
  return g.tag;
}

/** The caller's address as a `scope` row keeps it ({ addr, rk }): sealed, or in the clear before there is a keyring. */
async function sealedAddr(env, g, scope, tag) {
  const k = await guardKeys(env);
  if (!k.seal) return { addr: g.key, rk: null };
  return { addr: await sealRecord(k.seal, guardWhere(scope, tag), g.key), rk: k.kid };
}

/**
 * The public /api/config body (anonymous, identical for everyone), cached per
 * isolate like the settings so a flood of anonymous requests does not reach
 * the single Directory object each time.
 */
export async function cachedPublicConfig(env) {
  if (!publicConfigCache.config || Date.now() - publicConfigCache.at > CACHE_MS) {
    publicConfigCache = { at: Date.now(), config: await directory(env).publicConfig() };
  }
  return publicConfigCache.config;
}

export async function cachedSettings(env) {
  if (!settingsCache.settings || Date.now() - settingsCache.at > CACHE_MS) {
    settingsCache = { at: Date.now(), settings: await directory(env).getSettings() };
  }
  return settingsCache.settings;
}

async function manualRules(env) {
  if (Date.now() - rulesCache.at > CACHE_MS) {
    const rows = await directory(env).ipRules();
    rulesCache = { at: Date.now(), rules: rows.map((r) => ({ ...r, c: parseRule(r.cidr) })).filter((r) => r.c) };
  }
  const t = Math.floor(Date.now() / 1000);
  return rulesCache.rules.filter((r) => !r.expires || r.expires > t);
}

function shard(env, key) {
  const ns = binding(env, 'GUARD');
  return ns.get(ns.idFromName(`shard-${guardShardIndex(key)}`));
}

export function guardShards(env) {
  const ns = binding(env, 'GUARD');
  return Array.from({ length: GUARD_SHARDS }, (_, i) => ns.get(ns.idFromName(`shard-${i}`)));
}

/**
 * Resolve the caller's IP context once per request:
 * { ip, key, manual: 'allow'|'block'|null, off: {all, setup} }. `key` (the
 * tracking key: the address, or its IPv6 prefix) stays in this request's
 * memory; the Guard gets its tag (tagOf).
 */
export async function ipContext(env, request) {
  const off = bfpDisabled(env);
  const ip = clientIp(request);
  const settings = await cachedSettings(env);
  const key = trackingKey(ip, settings['guard.v6Prefix']);
  let manual = null;
  if (!off.all) {
    const parsed = parseIp(ip);
    const rules = await manualRules(env);
    // Allow beats block.
    if (rules.some((r) => r.action === 'allow' && ruleContains(r.c, parsed))) manual = 'allow';
    else if (rules.some((r) => r.action === 'block' && ruleContains(r.c, parsed))) manual = 'block';
  }
  return { ip, key, manual, off, settings };
}

const scopeOff = (g, scope) => (scope === 'setup' ? g.off.setup : g.off.all);

/**
 * The wider network of an IPv6 caller (its /48, when the Guard tracks longer
 * prefixes), or null. Some counts are also kept per /48, so rotating the /64s
 * of one allocation does not multiply them: invalid requests (WIDE_INVALID)
 * and new anonymous senders (publicapi.js).
 */
export const WIDE_V6_PREFIX = 48;
export function wideNetwork(g) {
  const ip = parseIp(g.ip);
  if (!ip || ip.v !== 6 || g.settings['guard.v6Prefix'] <= WIDE_V6_PREFIX) return null;
  return trackingKey(g.ip, WIDE_V6_PREFIX);
}
/**
 * Invalid requests are counted per network (the `invalid` scope) and, for
 * IPv6, per /48 besides (the `invalid-wide` scope): a /48 may make
 * WIDE_INVALID_FACTOR times guard.invalid.max within the same window before
 * all of it is blocked for the same time.
 */
export const WIDE_INVALID_FACTOR = 16;
const WIDE_INVALID = 'invalid-wide';
const wideInvalidRule = (s) => ({ max: s['guard.invalid.max'] * WIDE_INVALID_FACTOR, windowSec: s['guard.invalid.windowSec'], blockSec: s['guard.invalid.blockSec'] });
/** The caller's /48 as a context of its own (its tag computed for that key), or null. */
const wideContext = (g) => { const key = wideNetwork(g); return key ? { ...g, key, tag: null, tagFor: null } : null; };

/** Is this caller blocked for `scope`? Manual block applies to every scope. */
export async function isBlocked(env, g, scope) {
  if (scopeOff(g, scope) || g.manual === 'allow') return { blocked: false };
  if (g.manual === 'block') return { blocked: true, manual: true };
  const tag = await tagOf(env, g);
  const [cur, before] = await Promise.all([shard(env, tag).check(scope, tag), legacy(env, g, (s) => s.legacyCheck(scope, g.key))]);
  const own = cur.blocked || !before?.blocked ? cur : { blocked: true, until: before.until };
  if (own.blocked || scope !== 'invalid') return own;
  const w = wideContext(g);
  if (!w) return own;
  const wtag = await tagOf(env, w);
  return shard(env, wtag).check(WIDE_INVALID, wtag);
}

/**
 * The caller's rows from before the tags (keyed by its tracking key, in that
 * key's shard; src/guard-do.js), until the Directory's pass has re-keyed that
 * shard: `ask(stub)` → its answer, or null once the shard is done.
 */
async function legacy(env, g, ask) {
  const i = guardShardIndex(g.key);
  if (Date.now() - (legacyDoneShards.get(i) ?? -Infinity) <= CACHE_MS) return null;
  const ns = binding(env, 'GUARD');
  const r = await ask(ns.get(ns.idFromName(`shard-${i}`)));
  if (r.done) { legacyDoneShards.set(i, Date.now()); return null; }
  return r;
}

/** One failure on the caller's tag, counting on (and taking) its failures from before the tags; a block from before refuses at once. */
async function failOnTag(env, g, scope, rule) {
  const tag = await tagOf(env, g);
  const before = await legacy(env, g, (s) => s.legacyTake(scope, g.key));
  if (before?.blocked) return { blocked: true, until: before.until };
  return shard(env, tag).fail(scope, tag, rule, await sealedAddr(env, g, scope, tag), before?.carry ?? null);
}

/** Record one failure for `scope`; returns the block state after it (an invalid request from IPv6 counts for its /48 too). */
export async function recordFailure(env, g, scope) {
  if (scopeOff(g, scope) || g.manual === 'allow') return { blocked: false };
  const s = g.settings;
  const rule = { max: s[`guard.${scope}.max`], windowSec: s[`guard.${scope}.windowSec`], blockSec: s[`guard.${scope}.blockSec`] };
  const own = await failOnTag(env, g, scope, rule);
  const w = scope === 'invalid' ? wideContext(g) : null;
  if (!w) return own;
  const wtag = await tagOf(env, w);
  const wide = await shard(env, wtag).fail(WIDE_INVALID, wtag, wideInvalidRule(s), await sealedAddr(env, w, WIDE_INVALID, wtag));
  if (!wide.blocked) return own;
  return { blocked: true, until: Math.max(own.until ?? 0, wide.until ?? 0) || null, newlyBlocked: !!(own.newlyBlocked || wide.newlyBlocked) };
}

/**
 * A per-network rate limit: every call counts (not only failures) in its own
 * Guard scope, and at `rule.max` calls within `rule.windowSec` the network is
 * refused for `rule.blockSec` → { ok: true } or { ok: false, until }. The
 * kill switch and allow rules apply as for the other scopes; a manual block
 * refuses at once.
 */
export async function rateLimit(env, g, scope, rule) {
  if (g.off.all || g.manual === 'allow') return { ok: true };
  if (g.manual === 'block') return { ok: false, until: null };
  const r = await failOnTag(env, g, scope, rule);
  return r.blocked ? { ok: false, until: r.until ?? null } : { ok: true };
}

/**
 * The limits in front of Cloudflare's siteverify and the check page (both
 * anonymous): a network may ask for at most CAPTCHA_VERIFY.max − 1 CAPTCHA
 * checks, and load CAPTCHA_PAGE.max − 1 check pages, per window.
 */
export const CAPTCHA_VERIFY = { max: 31, windowSec: 600, blockSec: 600 };
export const CAPTCHA_PAGE = { max: 61, windowSec: 600, blockSec: 600 };
/**
 * "Keep downloads open" (POST /api/file/:id/extend): a network may ask at most
 * EXTEND_DOWNLOADS.max − 1 times per window, whatever the answer. A recipient
 * extends a window about once per download window (at most ten times), so only
 * a loop reaches it; it is refused before the Directory is asked.
 */
export const EXTEND_DOWNLOADS = { max: 121, windowSec: 600, blockSec: 600 };
/**
 * The CAPTCHA on sign-in, account changes and anonymous creation
 * (turnstile.js requireTurnstile): once siteverify has rejected
 * TURNSTILE_VERIFY.max tokens from a network within a window, that network's
 * tokens are refused without a call for `blockSec`. Accepted tokens are never
 * counted (each one cost a solved CAPTCHA).
 */
export const TURNSTILE_VERIFY = { max: 60, windowSec: 600, blockSec: 600 };
/**
 * POST /api/auth/prelogin (anonymous; it reaches the Directory): a network may
 * ask at most PRELOGIN.max − 1 times per window, and at most
 * PRELOGIN_USER.max − 1 times for one username. Only prelogin itself is
 * refused beyond them (the sign-in routes do not look at these scopes), and the
 * answer never depends on whether the account exists.
 */
export const PRELOGIN = { max: 601, windowSec: 600, blockSec: 600 };
export const PRELOGIN_USER = { max: 21, windowSec: 600, blockSec: 600 };
/**
 * Chunk fetches of a share that has ended (GET /api/file/:id/chunk/…, answered
 * 410 and never counted as invalid, public.js downloadChunk): a network may make
 * at most ENDED_CHUNKS.max − 1 per window before `429 rate_limited`.
 */
export const ENDED_CHUNKS = { max: 601, windowSec: 600, blockSec: 600 };
/**
 * The set-up page's key proposals (POST /api/auth/setup/candidate, the setup
 * token checked first): a network may ask SETUP_CANDIDATE.max − 1 times per
 * window ("Generate again" a few times is plenty).
 */
export const SETUP_CANDIDATE = { max: 21, windowSec: 600, blockSec: 600 };
/**
 * Password attempts on a share whose password is locked (src/lib/sharepw.js):
 * refused before the password is checked and never counted as invalid (the
 * right one may be among them), so they have a limit of their own: at most
 * PASSWORD_LOCKED.max − 1 per network per window, then `429 rate_limited`.
 */
export const PASSWORD_LOCKED = { max: 121, windowSec: 600, blockSec: 600 };
/**
 * The anonymous tracker (GET /api/public/t, which reaches the Directory): a
 * network may ask at most TRACKER_FETCH.max − 1 times per window (a page asks
 * once per visit).
 */
export const TRACKER_FETCH = { max: 601, windowSec: 600, blockSec: 600 };
/** The Guard scopes of these rate limits (the admin can see and lift their blocks like the others). */
export const RATE_LIMIT_SCOPES = ['captcha-verify', 'captcha-page', 'download-extend', 'turnstile-verify', 'prelogin', 'prelogin-user', 'public-trackers', 'ended-chunks', 'setup-candidate',
  'invalid-wide', 'password-locked', 'tracker-fetch'];

export { shard as guardShardFor };
