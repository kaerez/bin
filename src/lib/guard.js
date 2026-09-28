// guard.js — Worker-side brute-force protection: manual allow/block IP rules
// (cached per isolate), per-scope failure tracking in sharded Guard DOs, and
// the DISABLE_BFP / DISABLE_BFP_SETUP kill switches.

import { bfpDisabled, binding } from './config.js';
import { parseIp, parseRule, ruleContains, trackingKey } from './ip.js';
import { clientIp } from './http.js';
import { GUARD_SHARDS } from '../guard-do.js';

const CACHE_MS = 30 * 1000;
let rulesCache = { at: 0, rules: [] };
let settingsCache = { at: 0, settings: null };
let publicConfigCache = { at: 0, config: null };

export const directory = (env) => {
  const ns = binding(env, 'DIRECTORY');
  return ns.get(ns.idFromName('directory'));
};

/** Drop the isolate caches (called after an admin changes rules/settings). */
export function invalidateGuardCaches() {
  rulesCache = { at: 0, rules: [] };
  settingsCache = { at: 0, settings: null };
  publicConfigCache = { at: 0, config: null };
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
  let h = 0x811c9dc5;
  for (let i = 0; i < key.length; i++) { h ^= key.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
  const ns = binding(env, 'GUARD');
  return ns.get(ns.idFromName(`shard-${h % GUARD_SHARDS}`));
}

export function guardShards(env) {
  const ns = binding(env, 'GUARD');
  return Array.from({ length: GUARD_SHARDS }, (_, i) => ns.get(ns.idFromName(`shard-${i}`)));
}

/**
 * Resolve the caller's IP context once per request:
 * { ip, key, manual: 'allow'|'block'|null, off: {all, setup} }.
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
  return shard(env, g.key).check(scope, g.key);
}

/** Record one failure for `scope`; returns the block state after it. */
export async function recordFailure(env, g, scope) {
  if (scopeOff(g, scope) || g.manual === 'allow') return { blocked: false };
  const s = g.settings;
  const rule = { max: s[`guard.${scope}.max`], windowSec: s[`guard.${scope}.windowSec`], blockSec: s[`guard.${scope}.blockSec`] };
  return shard(env, g.key).fail(scope, g.key, rule);
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
  const r = await shard(env, g.key).fail(scope, g.key, rule);
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
/** The Guard scopes of these rate limits (the admin can see and lift their blocks like the others). */
export const RATE_LIMIT_SCOPES = ['captcha-verify', 'captcha-page', 'download-extend', 'turnstile-verify', 'prelogin', 'prelogin-user', 'public-trackers', 'ended-chunks'];

export { shard as guardShardFor };
