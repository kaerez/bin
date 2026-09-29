// sharepw.js — the per-share lockout of share passwords (SECURITY.md §6,
// "Brute-force protection"). The Guard counts wrong passwords per network; this
// counts them per share, from any network, so guesses spread over many
// networks are bounded too: `share.pwMaxFails` wrong passwords within
// `share.pwWindowSec` lock the share's password for `share.pwLockSec`, twice as
// long each time it locks again (at most PW_LOCK_MAX_FACTOR times as long, and
// never more than PW_LOCK_MAX_SEC). While it is locked every attempt is refused
// before its password is checked, the right one too, so a lock reveals nothing
// about a guess. The right password, when it is accepted, clears the count.
//
// Pure functions over a small state { n, since, until, strikes } (null: none):
// the store that checks the proof keeps it (BurnPaste and FileShare objects;
// the Directory for KV notes) and applies these in the same synchronous step
// as the check, so concurrent guesses are counted one after another.

import { SETTINGS } from './settings.js';

export const PW_LOCK_MAX_FACTOR = 64;
export const PW_LOCK_MAX_SEC = 30 * 86400;

/** The adata.kdf of a share with a password (the others have none to guess). */
export const PASSWORD_KDF = 'argon2id-hkdf';

const posInt = (v, def) => (Number.isSafeInteger(v) && v >= 1 ? v : def);

/** The lockout rule from the settings (the defaults for anything missing or malformed). */
export function sharePwRule(settings = {}) {
  return {
    max: posInt(settings['share.pwMaxFails'], SETTINGS['share.pwMaxFails'].def),
    windowSec: posInt(settings['share.pwWindowSec'], SETTINGS['share.pwWindowSec'].def),
    lockSec: posInt(settings['share.pwLockSec'], SETTINGS['share.pwLockSec'].def),
  };
}

/** A rule as a store received it (from the Worker), checked again. */
export const cleanRule = (rule) => sharePwRule(rule && typeof rule === 'object'
  ? { 'share.pwMaxFails': rule.max, 'share.pwWindowSec': rule.windowSec, 'share.pwLockSec': rule.lockSec } : {});

const cleanState = (st) => (st && typeof st === 'object' ? {
  n: Number.isSafeInteger(st.n) && st.n > 0 ? st.n : 0,
  since: Number.isSafeInteger(st.since) ? st.since : null,
  until: Number.isSafeInteger(st.until) ? st.until : null,
  strikes: Number.isSafeInteger(st.strikes) && st.strikes > 0 ? st.strikes : 0,
} : { n: 0, since: null, until: null, strikes: 0 });

/** Until when the password is locked at time `t` (unix seconds), or null. */
export function pwLockedUntil(st, t) {
  const s = cleanState(st);
  return s.until !== null && s.until > t ? s.until : null;
}

/** How long the `strike`-th lock lasts (1: the rule's lockSec). */
export function lockSeconds(rule, strike) {
  const factor = 2 ** Math.min(Math.max(0, strike - 1), Math.log2(PW_LOCK_MAX_FACTOR));
  return Math.min(rule.lockSec * factor, Math.max(rule.lockSec, PW_LOCK_MAX_SEC));
}

/**
 * One wrong password at time `t` (the password is not locked) → { next, locked }:
 * the state to store and, when this failure locked it, { until, strike } (else null).
 */
export function pwFailed(st, rule, t) {
  const s = cleanState(st);
  const r = cleanRule(rule);
  const n = (s.since !== null && s.since > t - r.windowSec ? s.n : 0) + 1;
  if (n >= r.max) {
    const strike = s.strikes + 1;
    const until = t + lockSeconds(r, strike);
    return { next: { n: 0, since: null, until, strikes: strike }, locked: { until, strike } };
  }
  return { next: { n, since: n === 1 ? t : s.since, until: s.until, strikes: s.strikes }, locked: null };
}

/** Anything to clear after the right password was accepted? */
export const pwDirty = (st) => { const s = cleanState(st); return s.n > 0 || s.until !== null || s.strikes > 0; };
