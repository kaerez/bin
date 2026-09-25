// guard.js — Worker-side brute-force protection: manual allow/block IP rules
// (cached per isolate), per-scope failure tracking in sharded Guard DOs, and
// the DISABLE_BFP / DISABLE_BFP_SETUP kill switches.

import { bfpDisabled } from './config.js';
import { parseIp, parseCidr, cidrContains, trackingKey } from './ip.js';
import { clientIp } from './http.js';
import { GUARD_SHARDS } from '../guard-do.js';

const CACHE_MS = 30 * 1000;
let rulesCache = { at: 0, rules: [] };
let settingsCache = { at: 0, settings: null };

export const directory = (env) => env.DIRECTORY.get(env.DIRECTORY.idFromName('directory'));

/** Drop the isolate caches (called after an admin changes rules/settings). */
export function invalidateGuardCaches() {
  rulesCache = { at: 0, rules: [] };
  settingsCache = { at: 0, settings: null };
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
    rulesCache = { at: Date.now(), rules: rows.map((r) => ({ ...r, c: parseCidr(r.cidr) })).filter((r) => r.c) };
  }
  const t = Math.floor(Date.now() / 1000);
  return rulesCache.rules.filter((r) => !r.expires || r.expires > t);
}

function shard(env, key) {
  let h = 0x811c9dc5;
  for (let i = 0; i < key.length; i++) { h ^= key.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
  return env.GUARD.get(env.GUARD.idFromName(`shard-${h % GUARD_SHARDS}`));
}

export function guardShards(env) {
  return Array.from({ length: GUARD_SHARDS }, (_, i) => env.GUARD.get(env.GUARD.idFromName(`shard-${i}`)));
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
    if (rules.some((r) => r.action === 'allow' && cidrContains(r.c, parsed))) manual = 'allow';
    else if (rules.some((r) => r.action === 'block' && cidrContains(r.c, parsed))) manual = 'block';
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

export { shard as guardShardFor };
