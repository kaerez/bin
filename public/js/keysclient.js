// keysclient.js — the owner's key kit, a restore from a user's personal kit
// and the keys parts of Import / export
// (docs/DRIVE.md §3.1), in the browser: the server hands the key material
// after the step-up, and it is sealed here under a passphrase (drivekit.js
// for the kit, exportcrypt.js for an export) before it is saved. Verify
// sends check values only (never a key; an export's DEKs excepted, each
// tried on its file's first chunk); Restore and Import send what the file
// holds, and the server takes only what is missing or broken there.

import { keysApi, ApiError } from './api.js';
import { sealDriveKit, parseDriveKit, openDriveKit, DriveKitError } from './drivekit.js';
import { sealExport, openExport, ExportCryptError } from './exportcrypt.js';
import { keyBytes, keyCheckValue, keyFingerprint, saltCheckValue, effectiveAt, KEY_RE, MEK_ID_RE } from './drivekeys.js';

export const KEYS_EXPORT_FORMAT = 'secbin-keys-export/1';
/** A key's fingerprint as the pages show it (xxxx-xxxx-xxx). */
export const fpText = (fp) => (typeof fp === 'string' && fp.length >= 8 ? `${fp.slice(0, 4)}-${fp.slice(4, 8)}-${fp.slice(8)}` : '—');

/**
 * Build the key kit → { text, subs, users, kit } (`text`: the file). The
 * server hands the root MEK, the sub-MEKs and the user salts only after the
 * step-up, and records the download (what it covers, for the fresh-kit
 * notice).
 */
export async function buildKeyKit({ ownerId, passphrase = '', step } = {}) {
  const r = await keysApi.kit(step || {});
  const m = r.material;
  if (!m || !m.root || !Array.isArray(m.subs) || !m.salts) throw new ApiError('Malformed response from the server.', 502, 'malformed');
  const payload = { v: 1, ownerId, ...m };
  const text = await sealDriveKit('key', payload, { accountId: ownerId, origin: location.origin, passphrase: String(passphrase ?? '') });
  return { text, subs: m.subs.length, users: Object.keys(m.salts).length, kit: r.kit };
}

/** Open a key kit's text → its payload (checked for form). Throws DriveKitError. */
export async function readKeyKit(text, passphrase, ownerId) {
  const p = await openDriveKit(parseDriveKit(text), { kind: 'key', accountId: ownerId, origin: location.origin, passphrase: String(passphrase ?? '') });
  if (!p.root || !KEY_RE.test(p.root.key ?? '') || !Array.isArray(p.subs) || !p.salts || typeof p.salts !== 'object') throw new DriveKitError('The kit opened, but its content is not valid.', 'payload');
  return p;
}

/**
 * The read-only check of a key kit: check values for the root MEK, each
 * sub-MEK and each user salt, compared on the server (match or no match
 * only). `date` (seconds; default now, future dates allowed): the sub-MEK in
 * effect then, and whether the kit holds it. → { verdict, checks, atDate }.
 */
export async function verifyKeyKit({ ownerId, text, passphrase = '', date = null } = {}) {
  const checks = [];
  const add = (id, status, label, detail) => checks.push({ id, status, label, detail });
  let kit;
  try {
    const env = parseDriveKit(text);
    if (env.kind !== 'key') throw new DriveKitError('This is a personal kit, not the key kit.', 'kind');
    if (env.accountId !== ownerId) throw new DriveKitError('This key kit was made by another owner account.', 'owner');
    add('format', 'pass', 'Format and account', `A key kit made by your account, for ${location.origin}.`);
    kit = await readKeyKit(text, passphrase, ownerId);
  } catch (e) {
    add(checks.length ? 'auth' : 'format', 'fail', checks.length ? 'Decrypts, authentication tag valid' : 'Format and account', e instanceof DriveKitError ? e.message : 'The kit could not be opened.');
    return { verdict: 'failed', checks, atDate: null };
  }
  add('auth', 'pass', 'Decrypts, authentication tag valid', 'The passphrase is right and the file is unchanged.');
  const body = { root: await keyCheckValue(keyBytes(kit.root.key), 'mek'), subs: {}, salts: {} };
  for (const s of kit.subs) if (MEK_ID_RE.test(s.id ?? '') && KEY_RE.test(s.key ?? '')) body.subs[s.id] = await keyCheckValue(keyBytes(s.key), 'mek');
  for (const [uid, v] of Object.entries(kit.salts)) {
    const salt = typeof v === 'string' ? v : v && v.salt;
    if (KEY_RE.test(salt ?? '')) body.salts[uid] = await saltCheckValue(salt, uid);
  }
  const r = await keysApi.verify(body);
  add('root', r.root === 'match' ? 'pass' : 'fail', 'Root MEK', r.root === 'match' ? 'It is this server’s root MEK.' : r.root === 'absent' ? 'Not in the kit.' : 'It is not this server’s root MEK (it was changed after this kit, or the kit is of another server).');
  const bad = r.subs.filter((s) => s.result !== 'match');
  add('subs', bad.length ? 'fail' : 'pass', 'Every sub-MEK', bad.length
    ? `Missing or different: ${bad.map((s) => `${s.id} (${fpText(s.fp)})`).join(', ')}.`
    : `All ${r.subs.length} with matching keys.`);
  add('salts', r.salts.match === r.salts.total ? 'pass' : 'fail', 'Every user salt', r.salts.match === r.salts.total
    ? `All ${r.salts.total}.`
    : `${r.salts.match} of ${r.salts.total} match${r.salts.absent ? `; ${r.salts.absent} not in the kit (accounts created after it)` : ''}${r.salts.mismatch ? `; ${r.salts.mismatch} differ` : ''}.`);
  const t = Number.isSafeInteger(date) ? date : r.now;
  const eff = effectiveAt(r.subs.map((s) => ({ id: s.id, from: s.from, until: s.until, created: 0 })), t);
  const hit = eff ? r.subs.find((s) => s.id === eff.id) : null;
  const atDate = hit ? { id: hit.id, fp: hit.fp, inKit: hit.result === 'match' } : null;
  add('date', atDate && atDate.inKit ? 'pass' : 'warn', 'The sub-MEK in effect on the chosen date', atDate
    ? `${atDate.id} (${fpText(atDate.fp)}) — ${atDate.inKit ? 'in this kit.' : 'not in this kit: download a fresh kit.'}`
    : 'No sub-MEK is in effect on that date.');
  return { verdict: checks.some((c) => c.status === 'fail') ? 'incomplete' : 'complete', checks, atDate, fixes: checks.some((c) => c.status !== 'pass') ? ['Download a fresh key kit and store it offline; then verify the new file.'] : [] };
}

/** Restore from a key kit (a dry run by default): only what this server lost comes back. → the server's plan / result. */
export async function restoreKeyKit({ ownerId, text, passphrase = '', step = {}, dryRun = true, useRoot = false } = {}) {
  const kit = await readKeyKit(text, passphrase, ownerId);
  // A kit made during a root change also holds the root being replaced (`rootOld`).
  return keysApi.restore({ root: kit.root, ...(kit.rootOld ? { rootOld: kit.rootOld } : {}), subs: kit.subs, salts: kit.salts, useRoot, dryRun, ...step });
}

/**
 * Restore from a user's personal kit (Admin → Security → Keys, the only place
 * one restores): the kit opens here for `userId` only (another account's kit
 * fails with DriveKitError 'owner' before any key is derived), then its salt
 * and KEKs go to the server, which takes only what it lost: the salt when the
 * account has none (and only if it opens that Drive), and the items under a
 * sub-MEK it can no longer open, sealed again under the current one. A large
 * Drive takes more than one call, each with the step-up: `step(n)` → the
 * step-up for call n (0 first). → { salt, unreadable, done, failed, left }.
 */
export async function restoreUserKit({ userId, text, passphrase = '', step, onProgress } = {}) {
  const p = await openDriveKit(parseDriveKit(text), { kind: 'user', accountId: userId, origin: location.origin, passphrase: String(passphrase ?? '') });
  if (p.id !== userId) throw new DriveKitError('This kit belongs to another account.', 'owner');
  if (typeof p.userSalt !== 'string' || !Array.isArray(p.keks)) throw new DriveKitError('The kit opened, but its content is not valid.', 'payload');
  const kit = { id: p.id, salt: p.userSalt, keks: p.keks.slice(0, 500).map((k) => ({ mekId: k?.mekId, kek: k?.kek })) };
  const out = { salt: 'absent', unreadable: [], done: 0, failed: 0, left: [] };
  let resume = null;
  for (let n = 0; n < 1000; n++) {
    const r = await keysApi.userKitRestore(userId, { kit, ...(resume ? { resume } : {}), ...(await step(n)) });
    if (n === 0) Object.assign(out, { salt: r.salt, unreadable: r.unreadable || [], left: r.left || [] });
    out.done += r.done || 0;
    out.failed += r.failed || 0;
    if (onProgress) onProgress(out.done);
    resume = r.next || null;
    if (!resume) break;
  }
  return out;
}

// ── Import / export: the keys parts ────────────────────────────────────────

/** Seal a keys export `document` (built by the server after the step-up) under `passphrase` → { text }. */
export async function exportKeys({ document: doc, passphrase = '' } = {}) {
  if (!doc || doc.format !== KEYS_EXPORT_FORMAT) throw new ApiError('Malformed response from the server.', 502, 'malformed');
  return { text: await sealExport(doc, String(passphrase ?? '')) };
}

/** Open a keys export's text → the document. Throws ExportCryptError. */
export async function openKeysExport(text, passphrase = '') {
  const doc = await openExport(text, passphrase);
  if (!doc || doc.format !== KEYS_EXPORT_FORMAT) throw new ExportCryptError('The decrypted file is not a Drive keys export.');
  return doc;
}

const UID_RE = /^[A-Za-z0-9_-]{16}$/;
const has = (v) => (Array.isArray(v) ? v.length > 0 : !!v);

/**
 * Verify a keys export `doc` (opened here) against this server, read-only:
 * the root MEK, the sub-MEKs, the user salts and the KEKs go as check values
 * (never the keys), the DEKs as they are (the server tries each on its file's
 * first chunk). `step`: the step-up. `date` (seconds; default now): the
 * sub-MEK in effect then, and whether the file holds it (as a sub-MEK or as
 * the users' KEKs). → { verdict: 'complete' | 'incomplete', summary, checks,
 * result } (checks as verifyKeyKit's).
 */
export async function verifyKeysExport({ doc, step = {}, date = null } = {}) {
  // A malformed value in the file is sent as "invalid" (never a match), not an error.
  const safe = async (fn, fallback) => { try { return await fn(); } catch { return fallback; } };
  const cv = (key, kind) => safe(() => keyCheckValue(keyBytes(key), kind), 'invalid');
  const fp = (key) => safe(() => keyFingerprint(keyBytes(key)), null);
  const users = new Map();
  const entry = (id) => { if (!users.has(id)) users.set(id, { id }); return users.get(id); };
  for (const [uid, v] of Object.entries(doc.salts || {})) {
    const salt = typeof v === 'string' ? v : v && v.salt;
    if (UID_RE.test(uid)) entry(uid).salt = await safe(() => saltCheckValue(salt, uid), 'invalid');
  }
  const names = new Map();
  for (const u of Array.isArray(doc.users) ? doc.users : []) {
    if (!UID_RE.test(u?.id ?? '')) continue;
    const e = entry(u.id);
    if (typeof u.username === 'string') names.set(u.id, u.username);
    if (Array.isArray(u.keks)) {
      e.keks = {};
      for (const k of u.keks) if (MEK_ID_RE.test(k?.mekId ?? '')) e.keks[k.mekId] = await cv(k.kek, 'kek');
    }
    if (Array.isArray(u.deks)) e.deks = u.deks.map((d) => ({ id: d?.id, dek: d?.dek }));
  }
  let subs = null;
  if (has(doc.subs)) {
    subs = {};
    for (const s of doc.subs) if (MEK_ID_RE.test(s?.id ?? '')) subs[s.id] = await cv(s.key, 'mek');
  }
  const r = await keysApi.verifyExport({ root: doc.root ? await cv(doc.root.key, 'mek') : null, subs, users: [...users.values()], ...step });

  const checks = [];
  const add = (id, status, label, detail) => checks.push({ id, status, label, detail });
  add('format', 'pass', 'Decrypts: a Drive keys export', `Made on ${doc.origin || 'an unknown origin'}; the passphrase is right and the file is unchanged.`);
  if (doc.root) {
    const mine = fpText(await fp(doc.root.key));
    add('root', r.root.result === 'match' ? 'pass' : 'fail', 'Root MEK', r.root.result === 'match'
      ? `It is this server’s root MEK (${mine}).`
      : `The file’s root MEK (${mine}) is not this server’s (${fpText(r.root.fp)}).`);
  } else add('root', 'skip', 'Root MEK', 'Not in the file.');
  if (subs) {
    for (const s of r.subs.list) {
      const label = `Sub-MEK ${s.id} (${fpText(s.fp)})`;
      if (s.result === 'match') add(`sub:${s.id}`, 'pass', label, 'Matches this server’s.');
      else if (s.result === 'mismatch') add(`sub:${s.id}`, 'fail', label, 'The file’s key with this id is not this server’s.');
      else add(`sub:${s.id}`, 'warn', label, 'On this server, missing from the file: items sealed under it do not open with the file’s sub-MEKs.');
    }
    for (const id of r.subs.unknown) add(`sub:${id}`, 'fail', `Sub-MEK ${id}`, 'In the file, unknown here: this server has no sub-MEK with this id.');
  } else add('subs', 'skip', 'Sub-MEKs', 'Not in the file.');
  const SALT = { match: 'the user salt matches', mismatch: 'the user salt differs from this server’s', none: 'this account has no user salt here', unknown: 'no such account here' };
  for (const u of r.users) {
    const bits = [];
    let bad = u.username === null;
    const sent = users.get(u.id) || {};
    if (SALT[u.salt]) bits.push(SALT[u.salt]);
    if (['mismatch', 'none'].includes(u.salt)) bad = true;
    if (sent.keks) {
      const by = (res) => u.keks.filter((k) => k.result === res).map((k) => k.mekId);
      const off = [['differ', by('mismatch')], ['are for no sub-MEK here', by('unknown')], ['cannot be derived here', by('unchecked')]].filter(([, ids]) => ids.length);
      bits.push(`KEKs: ${by('match').length} of ${u.keks.length} match${off.map(([what, ids]) => `; ${ids.length} ${what} (${ids.join(', ')})`).join('')}`);
      if (off.length) bad = true;
    }
    if (u.deks) {
      const d = u.deks;
      const off = [[d.fails, `do not open it${d.failed.length ? ` (${d.failed.join(', ')})` : ''}`], [d.missing, `are for no file here${d.missingIds.length ? ` (${d.missingIds.join(', ')})` : ''}`], [d.unchecked, 'were not checked (one check tries 10,000 at most)']].filter(([n]) => n);
      bits.push(`DEKs: ${d.opens} of ${d.total} open their file’s first chunk${off.map(([n, what]) => `; ${n} ${what}`).join('')}${d.empty ? `; ${d.empty} for empty files (nothing to check)` : ''}`);
      if (off.length) bad = true;
    }
    const name = u.username ?? names.get(u.id) ?? 'unknown account';
    add(`user:${u.id}`, bad ? 'fail' : u.deks?.empty ? 'warn' : 'pass', `${name} (${u.id})`, `${bits.join('; ') || 'nothing to check'}.`);
  }
  // The date: the sub-MEK in effect then, as a sub-MEK of the file or as the KEKs of its users.
  const withKeks = r.users.filter((u) => users.get(u.id)?.keks);
  if (subs || withKeks.length) {
    const t = Number.isSafeInteger(date) ? date : r.now;
    const eff = effectiveAt(r.subs.list.map((s) => ({ id: s.id, from: s.from, until: s.until, created: 0 })), t);
    const hit = eff ? r.subs.list.find((s) => s.id === eff.id) : null;
    if (!hit) add('date', 'warn', 'The sub-MEK in effect on the chosen date', 'No sub-MEK is in effect on that date.');
    else {
      const asSub = hit.result === 'match';
      const keks = withKeks.filter((u) => u.keks.some((k) => k.mekId === hit.id && k.result === 'match')).length;
      const inFile = asSub || (withKeks.length > 0 && keks === withKeks.length);
      add('date', inFile ? 'pass' : 'warn', 'The sub-MEK in effect on the chosen date', `${hit.id} (${fpText(hit.fp)}) — ${asSub ? 'in this file.' : withKeks.length ? `its KEK is in this file for ${keks} of ${withKeks.length} user${withKeks.length === 1 ? '' : 's'}.` : 'not in this file.'}`);
    }
  }
  const fails = checks.filter((c) => c.status === 'fail');
  const notes = checks.filter((c) => c.status === 'warn').length;
  const summary = fails.length
    ? `What does not match: ${fails.map((c) => c.label).join('; ')}.`
    : `Everything in this file matches this server.${notes ? ` ${notes} note${notes === 1 ? '' : 's'} below.` : ''}`;
  return { verdict: fails.length ? 'incomplete' : 'complete', summary, checks, result: r };
}

/** Import (a dry run by default) the chosen parts of a keys export. */
export function importKeys({ doc, take, useRoot = false, dryRun = true, step = {} } = {}) {
  return keysApi.importKeys({ document: doc, take, useRoot, dryRun, ...step });
}
