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
import { parseIp, parseRule, ruleContains, trackingKey } from './ip.js';
import { clientIp } from './http.js';
import { GUARD_SHARDS, guardShardIndex } from '../guard-do.js';
import { guardTag, guardRowId, importTagKey, importTableKey, sealRecord } from './records.js';
import { bytesFromB64url } from '../../public/js/bytes.js';

const CACHE_MS = 30 * 1000;
let rulesCache = { at: 0, rules: [] };
let settingsCache = { at: 0, settings: null };
let publicConfigCache = { at: 0, config: null };
let guardKeysCache = { at: 0, keys: null };

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
}

/**
 * The Guard's keys (Directory.guardKeys): the tag key (HMAC) and, once there
 * is a keyring, the Guard's record key with its id → { tag, kid, seal | null }
 * (CryptoKeys, never extractable here). Cached per isolate like the settings:
 * after a root change, addresses may be sealed under the previous root's key
 * for up to CACHE_MS (they stay readable; the Directory's pass re-seals them).
 */
async function guardKeys(env) {
  if (!guardKeysCache.keys || Date.now() - guardKeysCache.at > CACHE_MS) {
    const r = await directory(env).guardKeys();
    guardKeysCache = {
      at: Date.now(),
      keys: { tag: await importTagKey(bytesFromB64url(r.tag)), kid: r.kid ?? null, seal: r.key ? await importTableKey(bytesFromB64url(r.key)) : null },
    };
  }
  return guardKeysCache.keys;
}

/** The Guard key of a tracking key the owner typed (an address or a prefix, as the Guard's rows showed it before the tags). */
export async function guardKeyFor(env, trackingKeyText) {
  return guardTag((await guardKeys(env)).tag, trackingKeyText);
}

/** The caller's Guard key (a tag of its tracking key), once per request. */
async function tagOf(env, g) {
  g.tag ??= (async () => guardTag((await guardKeys(env)).tag, g.key))();
  return g.tag;
}

/** The caller's address as a `scope` row keeps it ({ addr, rk }): sealed, or in the clear before there is a keyring. */
async function sealedAddr(env, g, scope, tag) {
  const k = await guardKeys(env);
  if (!k.seal) return { addr: g.key, rk: null };
  return { addr: await sealRecord(k.seal, { table: 'guard', col: 'addr', id: guardRowId(scope, tag) }, g.key), rk: k.kid };
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

/** Is this caller blocked for `scope`? Manual block applies to every scope. */
export async function isBlocked(env, g, scope) {
  if (scopeOff(g, scope) || g.manual === 'allow') return { blocked: false };
  if (g.manual === 'block') return { blocked: true, manual: true };
  const tag = await tagOf(env, g);
  return shard(env, tag).check(scope, tag);
}

/** Record one failure for `scope`; returns the block state after it. */
export async function recordFailure(env, g, scope) {
  if (scopeOff(g, scope) || g.manual === 'allow') return { blocked: false };
  const s = g.settings;
  const rule = { max: s[`guard.${scope}.max`], windowSec: s[`guard.${scope}.windowSec`], blockSec: s[`guard.${scope}.blockSec`] };
  const tag = await tagOf(env, g);
  return shard(env, tag).fail(scope, tag, rule, await sealedAddr(env, g, scope, tag));
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
  const tag = await tagOf(env, g);
  const r = await shard(env, tag).fail(scope, tag, rule, await sealedAddr(env, g, scope, tag));
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
 * The set-up page's key proposals (POST /api/auth/setup/candidate, the setup
 * token checked first): a network may ask SETUP_CANDIDATE.max − 1 times per
 * window ("Generate again" a few times is plenty).
 */
export const SETUP_CANDIDATE = { max: 21, windowSec: 600, blockSec: 600 };
/** The Guard scopes of these rate limits (the admin can see and lift their blocks like the others). */
export const RATE_LIMIT_SCOPES = ['captcha-verify', 'captcha-page', 'download-extend', 'setup-candidate'];

export { shard as guardShardFor };
