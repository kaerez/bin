// keysclient.js — the owner's key kit and the keys parts of Import / export
// (docs/DRIVE.md §3.1), in the browser: the server hands the key material
// after the step-up, and it is sealed here under a passphrase (drivekit.js
// for the kit, exportcrypt.js for an export) before it is saved. Verify
// sends check values only (never a key); Restore and Import send what the
// file holds, and the server takes only what is missing or broken there.

import { keysApi, ApiError } from './api.js';
import { sealDriveKit, parseDriveKit, openDriveKit, DriveKitError } from './drivekit.js';
import { sealExport, openExport, ExportCryptError } from './exportcrypt.js';
import { keyBytes, keyCheckValue, saltCheckValue, effectiveAt, KEY_RE, MEK_ID_RE } from './drivekeys.js';

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

/** Import (a dry run by default) the chosen parts of a keys export. */
export function importKeys({ doc, take, useRoot = false, dryRun = true, step = {} } = {}) {
  return keysApi.importKeys({ document: doc, take, useRoot, dryRun, ...step });
}
