// driveclient.js — the Drive in the browser (docs/DRIVE.md): unlock the
// Drive key (DK), then list, upload, download, rename, move, delete and share
// end-to-end encrypted files and folders. The server (/api/private/drive, §6)
// sees only ids, the tree's shape, sizes and ciphertext.
//
// Node names and metadata are sealed with DK's "names" key, each file key with
// its "files" key; AAD binds every value to its node id and field
// (drivekeys.js), so node ids are chosen here, before anything is sealed. File
// content is cut into CHUNK-sized pieces, each encryptChunk(fk, i, n) as for
// file shares but without padding: chunk i is exactly
// min(CHUNK, size − i·CHUNK) + 16 bytes, and an empty file has no chunks.

import { drive as api, session, ApiError } from './api.js';
import {
  createDriveKey, deriveSubkeys, sealField, openField, wrapPassword, unlockWithPassword, wrapRecovery, unlockWithRecovery,
  recoveryRef, DRIVE_PRF_SALT, wrapPrf, unlockWithPrf, createEscrowKeyPair, sealEscrowPriv, openEscrowKeyPair, sameEscrowKey,
  wrapEscrow, unlockWithEscrow, escrowKeyId, escrowWrapKeyId, sealEscrowPin, openEscrowPin, createSigningKeyPair, sealSigningKey,
  openSigningKey, endorseEscrowKey, escrowKeyEndorsed, signingKeyId,
  saveSessionKey, loadSessionKey, clearSessionKey, sessionKeyUser, saveImpersonationKey, loadImpersonationKey, clearImpersonationKey,
} from './drivekeys.js';
import { encryptPaste } from './crypto.js';
import { randomBytes, utf8, fromUtf8, b64urlFromBytes } from './bytes.js';
import { CHUNK, encryptChunk, importFileKey, checkPath, MAX_ENTRIES, cleanName } from './files.js';
import { detectMime, normalizeMime, OCTET } from './mime.js';
import { RefsReader, saveFile, saveZip } from './downloads.js';
import { buildRefsManifest, refChunks } from './refsmanifest.js';
import { declare, refusedTypes, uncheckableExt, describeType } from './filepolicy.js';
import { passkeyPrfOnly } from './passkeys.js';

/**
 * No usable DK in this tab (`reason`: 'locked' | 'wrong' | 'setup' |
 * 'not_ready' (a user's Drive cannot be set up yet: the owner has no escrow
 * key) | 'no_passkey', and while the owner acts as a user: 'no_drive' (the
 * user has not signed in since the Drive was enabled: nothing is created) |
 * 'owner_locked' (the owner's own Drive is not unlocked in this tab) |
 * 'no_escrow' (the owner has no escrow key yet, or it does not open) |
 * 'no_wrap' (the user's Drive has no escrow wrap yet) | 'escrow_failed' (the
 * wrap is for an escrow key the owner no longer holds) | 'escrow_mismatch'
 * (the server's escrow public key is not the owner's: see DriveClient#notice)). `credentialIds`
 * (from openDrive) lists the passkeys (base64url credential ids) that have a
 * Drive wrap, so a page can offer the passkey unlock only when one exists.
 */
export class DriveLocked extends Error {
  constructor(message = 'Unlock your Drive to continue.', reason = 'locked', credentialIds = []) {
    super(message);
    this.name = 'DriveLocked';
    this.reason = reason;
    this.credentialIds = credentialIds;
  }
}

/** The account's role has no Drive. */
export class DriveDisabled extends Error {
  constructor(message = 'The Drive is not enabled for your account.') {
    super(message);
    this.name = 'DriveDisabled';
  }
}

export const ROOT = 'root';
const ROOT_NAME = 'Drive';
const MAX_NAME_BYTES = 255;
const MAX_DEPTH = 64;
const newId = () => b64urlFromBytes(randomBytes(16));
const malformed = () => new ApiError('Malformed response from the server.', 502, 'malformed');

const aborted = (signal, what) => signal.reason ?? new DOMException(`${what} cancelled.`, 'AbortError');

/**
 * downloads.js reports each chunk's plaintext length (onBytes(n)); this turns
 * that into onProgress(bytesDone, total), as uploads report it, and stops the
 * transfer (with the signal's AbortError) once `signal` is aborted.
 */
function byteCounter(total, onProgress, signal) {
  let done = 0;
  if (onProgress) onProgress(0, total);
  return (n) => {
    if (signal?.aborted) throw aborted(signal, 'Download');
    done += n;
    if (onProgress) onProgress(done, total);
  };
}

/** `name`, or "name (2).ext", "name (3).ext"… when `taken` already has it. */
function uniqueName(taken, name) {
  let n = name;
  const dot = name.lastIndexOf('.');
  const [stem, ext] = dot > 0 ? [name.slice(0, dot), name.slice(dot)] : [name, ''];
  for (let k = 2; taken.has(n); k++) n = `${stem} (${k})${ext}`;
  taken.add(n);
  return n;
}

/**
 * A node name → the name to store (cleaned: files.js cleanName strips the
 * bidi overrides and isolates, U+200B, U+FEFF and U+0085 / U+2028 / U+2029,
 * then NFC), or throws: no "/", "\", control characters, "." or ".."; 1–255
 * bytes. Hebrew, Arabic, ZWNJ / ZWJ and LRM / RLM stay as they are.
 */
export function checkName(raw) {
  const name = typeof raw === 'string' ? cleanName(raw) : raw;
  // eslint-disable-next-line no-control-regex
  if (typeof name !== 'string' || !name || name === '.' || name === '..' || /[\u0000-\u001f\u007f/\\]/.test(name)) {
    throw new Error('Names cannot be empty, "." or "..", or contain "/", "\\" or control characters.');
  }
  if (utf8(name).length > MAX_NAME_BYTES) throw new Error(`Names can be at most ${MAX_NAME_BYTES} bytes long.`);
  return name;
}

const NOTICE_TEXT = {
  escrow_mismatch: 'The escrow public key the server gives every Drive is not the one your escrow private key belongs to: it may have been replaced. No Drive is wrapped to it from this browser until you restore it.',
  escrow_unreadable: 'Your escrow private key does not open with your Drive key, so it cannot be checked or used.',
  escrow_missing: 'The server has an escrow public key, but your Drive holds no escrow private key for it.',
  escrow_unsigned: 'Your escrow key is not signed by your escrow signing key on the server, so users’ Drives would not accept a new escrow key automatically.',
};

/** A sealed field as the server returns it (object, or its JSON text). */
const sealed = (v) => (typeof v === 'string' ? JSON.parse(v) : v);

async function whoAmI(user) {
  if (user && typeof user.id === 'string') return { id: user.id, role: user.role, impersonating: !!user.impersonating };
  const s = await session();
  if (!s.authenticated || !s.user) throw new ApiError('Please log in.', 401, 'unauthenticated');
  return { id: s.user.id, role: s.user.role, impersonating: !!s.impersonatedBy };
}

/** GET /api/private/drive, or DriveDisabled. */
async function loadState() {
  let st;
  try {
    st = await api.state();
  } catch (e) {
    if (e instanceof ApiError && (e.code === 'drive_disabled' || e.status === 404 || (e.status === 403 && e.code !== 'impersonating'))) throw new DriveDisabled(e.message);
    throw e;
  }
  if (st.enabled !== true) throw new DriveDisabled();
  if (!Array.isArray(st.wraps)) st.wraps = [];
  return st;
}

// ── unlocking ──────────────────────────────────────────────────────────────

const NOT_READY = 'The Drive is not ready yet: the owner must sign in once. Try again later.';

/**
 * The Drive with this tab's DK → DriveClient. Throws DriveLocked when the tab
 * has none (reason 'setup' when the Drive has no key yet, 'not_ready' when it
 * cannot have one yet), DriveDisabled when the role has no Drive. `user`
 * ({ id, role, impersonating }) saves a session lookup. While the owner acts
 * as the user, the Drive opens through the owner escrow (openAsOwner).
 */
export async function openDrive({ user } = {}) {
  const u = await whoAmI(user);
  const st = await loadState();
  if (u.impersonating) return openAsOwner(u, st);
  if (!st.wraps.length) {
    clearSessionKey();
    if (u.role !== 'owner' && !st.escrowPub) throw new DriveLocked(NOT_READY, 'not_ready');
    throw new DriveLocked('Set up your Drive with your password.', 'setup');
  }
  const dk = loadSessionKey(u.id);
  if (!dk) throw new DriveLocked(undefined, 'locked', passkeyRefs(st));
  const client = await DriveClient.create(dk, u);
  await client.maintain(st).catch(() => {});
  return client;
}

/**
 * Unlock DK with what the user has — { password } | { code } | { prfOutput,
 * credentialId } (several may be given; the first that opens a wrap wins) —
 * keep it for the tab and return a DriveClient. The first time (no wraps yet)
 * this creates DK, with a password wrap (or, with no password, a passkey wrap
 * from the PRF output) and the escrow wrap; a user's Drive only once the
 * owner's escrow key exists ('not_ready' before). Throws DriveLocked
 * ('wrong', 'setup', 'not_ready') or DriveDisabled.
 *
 * `passwordVerified` (sign-in only: the server has just accepted the password)
 * lets a stale or missing `pw` wrap be written; `spentWraps` are the wraps of
 * a recovery code this sign-in used up (the server removed them and returned
 * them once).
 */
export async function unlockDrive(creds = {}, { user, passwordVerified = false, spentWraps = [] } = {}) {
  const u = await whoAmI(user);
  let st = await loadState();
  if (u.impersonating) return openAsOwner(u, st);
  let dk = null;
  let via = null;
  if (!st.wraps.length) {
    if (u.role !== 'owner' && !st.escrowPub) throw new DriveLocked(NOT_READY, 'not_ready');
    if (!creds.password && !(creds.prfOutput && creds.credentialId)) throw new DriveLocked('Set up your Drive with your password.', 'setup');
    dk = await setUp(u, st, creds);
    via = creds.password ? 'pw' : 'passkey';
    st = await loadState(); // what the set-up stored (the owner's first escrow key pair included)
  } else {
    if (creds.password) { dk = await unlockWithPassword(creds.password, st.driveSalt, st.wraps); via = 'pw'; }
    if (!dk && creds.prfOutput && creds.credentialId) { dk = await unlockWithPrf(creds.prfOutput, creds.credentialId, st.wraps); via = 'passkey'; }
    if (!dk && creds.code) { dk = await unlockWithRecovery(creds.code, [...st.wraps, ...(Array.isArray(spentWraps) ? spentWraps : [])]); via = 'recovery'; }
    if (!dk) throw new DriveLocked('That does not unlock your Drive.', 'wrong');
  }
  saveSessionKey(dk, u.id);
  const client = await DriveClient.create(dk, u);
  await client.maintain(st, { ...creds, via, passwordVerified }).catch(() => {});
  return client;
}

const passkeyRefs = (st) => st.wraps.filter((w) => w.kind === 'passkey').map((w) => w.ref);

/**
 * Unlock with a passkey that has a Drive wrap: a local WebAuthn prompt with the
 * PRF extension (passkeys.js, the same helper the sign-in uses; the PRF output
 * stays in this tab), limited to those passkeys.
 */
export async function unlockDriveWithPasskey({ user } = {}) {
  const st = await loadState();
  const ids = passkeyRefs(st);
  if (!ids.length) throw new DriveLocked('None of your passkeys can unlock the Drive.', 'no_passkey');
  const { credentialId, prf } = await passkeyPrfOnly(DRIVE_PRF_SALT, ids);
  if (!prf) throw new DriveLocked('This passkey cannot unlock the Drive.', 'no_passkey');
  return unlockDrive({ prfOutput: prf, credentialId }, { user });
}

/** The pin for the server's current escrow key: its kid, and the signing key's when that key signed it. */
async function pinFor(st) {
  const escrow = await escrowKeyId(st.escrowPub);
  const signed = st.escrowSignPub && st.escrowSig && await escrowKeyEndorsed(st.escrowSignPub, st.escrowPub, st.escrowSig);
  return { escrow, sign: signed ? await signingKeyId(st.escrowSignPub) : null };
}

/**
 * The first DK: wraps for the password and / or a passkey (PRF), and for a
 * user the escrow wrap with the escrow key pinned; for the owner, the escrow
 * key pair and the signing key when there are none yet (a later change needs
 * the owner's confirmation: DriveClient#notice).
 */
async function setUp(u, st, creds) {
  // A Drive with content but no wraps is broken, not new: never replace its key.
  const top = await api.node(ROOT).catch(() => null);
  if (top && Array.isArray(top.children) && top.children.length) throw new DriveLocked('Your Drive has no keys. Contact the administrator.', 'wrong');
  const dk = createDriveKey();
  const set = [];
  const body = { set, remove: [] };
  let pwWrap = null;
  if (creds.password) {
    const { driveSalt, wrap } = await wrapPassword(dk, creds.password);
    body.driveSalt = driveSalt;
    set.push(wrap);
    pwWrap = wrap;
  }
  if (creds.prfOutput && creds.credentialId) set.push(await wrapPrf(dk, creds.prfOutput, creds.credentialId));
  if (u.role === 'owner') {
    if (!st.escrowPub) Object.assign(body, await newOwnerKeys(dk));
  } else {
    set.push(await wrapEscrow(dk, st.escrowPub));
    body.escrowPin = await sealEscrowPin(dk, await pinFor(st));
  }
  await api.setKeys(body);
  // Two tabs may set up at the same moment: the stored wraps decide.
  const after = await loadState();
  const mine = (w) => after.wraps.some((x) => x.kind === w.kind && x.ref === w.ref && x.data === w.data);
  if (set.filter((w) => w.kind !== 'escrow').every(mine)) return dk;
  const other = (pwWrap && await unlockWithPassword(creds.password, after.driveSalt, after.wraps))
    || (creds.prfOutput && creds.credentialId && await unlockWithPrf(creds.prfOutput, creds.credentialId, after.wraps));
  if (other) return other;
  throw new DriveLocked('That does not unlock your Drive.', 'wrong');
}

/** The owner's key material for a new escrow key: the pair, sealed, and signed (a new signing key unless `sign` is given). */
async function newOwnerKeys(dk, sign = null) {
  const kp = await createEscrowKeyPair();
  const out = { escrowPriv: await sealEscrowPriv(dk, kp.privateKey), escrowPub: kp.publicJwk };
  let signer = sign;
  if (!signer) {
    const sp = await createSigningKeyPair();
    signer = sp.privateKey;
    Object.assign(out, { escrowSignPriv: await sealSigningKey(dk, sp.privateKey), escrowSignPub: sp.publicJwk });
  }
  out.escrowSig = await endorseEscrowKey(signer, kp.publicJwk);
  return out;
}

/**
 * The owner's escrow private key for a wrap: the current one when the wrap is
 * for it, else an earlier one the owner still keeps (sealed under the owner's
 * DK until no user's wrap needs it), or null.
 */
async function escrowKeyFor(ownerDk, wrap, current, old) {
  const kid = escrowWrapKeyId(wrap);
  if (current && current.kid === kid) return current.privateKey;
  const sealed = old && typeof old === 'object' ? old[kid] : null;
  if (typeof sealed !== 'string') return null;
  try { return (await openEscrowKeyPair(ownerDk, sealed)).privateKey; } catch { return null; }
}

/**
 * The owner, acting as user `u`, opens that user's Drive with the owner
 * escrow (docs/DRIVE.md §3): the owner's own DK (already in this tab) opens
 * the owner's escrow private key (or the earlier one the wrap is for), which
 * opens the user's escrow wrap. The user's DK is kept in its own slot (never
 * the owner's) until the impersonation ends. Nothing is created: a user with
 * no Drive yet gets one at their own next sign-in. Every call of the escrow
 * route is in the admin audit.
 */
async function openAsOwner(u, st) {
  if (!st.wraps.length) throw new DriveLocked('The user hasn’t signed in since the Drive was enabled.', 'no_drive');
  const kept = loadImpersonationKey(u.id);
  if (kept) return DriveClient.create(kept, u);
  const ownerUid = sessionKeyUser();
  if (!ownerUid || ownerUid === u.id) throw new DriveLocked('Your own Drive is not unlocked in this tab.', 'owner_locked');
  const r = await api.impersonationEscrow();
  const ownerDk = loadSessionKey(r.ownerId);
  if (!ownerDk) throw new DriveLocked('Your own Drive is not unlocked in this tab.', 'owner_locked');
  if (typeof r.escrowPriv !== 'string' || !r.escrowPub) throw new DriveLocked('You have no escrow key yet.', 'no_escrow');
  let pair;
  try { pair = await openEscrowKeyPair(ownerDk, r.escrowPriv); } catch { throw new DriveLocked('Your escrow key does not open with your Drive key.', 'no_escrow'); }
  if (!sameEscrowKey(pair.publicJwk, r.escrowPub)) throw new DriveLocked(NOTICE_TEXT.escrow_mismatch, 'escrow_mismatch');
  if (!r.wrap) throw new DriveLocked('This user’s Drive has no escrow wrap yet.', 'no_wrap');
  const priv = await escrowKeyFor(ownerDk, r.wrap, { kid: await escrowKeyId(r.escrowPub), privateKey: pair.privateKey }, r.escrowPrivOld);
  const dk = priv ? await unlockWithEscrow(priv, r.wrap) : null;
  if (!dk) throw new DriveLocked('This user’s escrow wrap was made for an escrow key you no longer hold.', 'escrow_failed');
  saveImpersonationKey(dk, u.id);
  return DriveClient.create(dk, u);
}

// ── keeping wraps current (docs/DRIVE.md §3), for account.js / admin.js / login.js ──

/** After a successful sign-in: unlock (or set up) the Drive for this tab. Never throws. */
export async function unlockAtSignIn({ user, password, code, prfOutput, credentialId, spentWraps }) {
  clearSessionKey();
  try {
    await unlockDrive({ password, code, prfOutput, credentialId }, { user, passwordVerified: !!password, spentWraps });
    return true;
  } catch {
    return false; // the Drive page asks
  }
}

/**
 * The Drive key of `userId` for the Account page's upkeep, or null: the tab's
 * key; without it, `password` (just confirmed by the server) may unlock it.
 * The owner acting as the user (`impersonating`) uses that user's own tab
 * slot, opened through the owner escrow when needed — never the owner's slot.
 */
async function upkeepKey(userId, st, { password, impersonating = false } = {}) {
  if (impersonating) {
    const kept = loadImpersonationKey(userId);
    if (kept) return kept;
    try {
      return (await openAsOwner({ id: userId, role: 'user', impersonating: true }, st)).dk;
    } catch {
      return null;
    }
  }
  let dk = loadSessionKey(userId);
  if (!dk && password) {
    dk = await unlockWithPassword(password, st.driveSalt, st.wraps);
    if (dk) saveSessionKey(dk, userId);
  }
  return dk;
}

/** Write wraps with DK known → true, or false when the Drive is off or locked. */
async function withKey(userId, fn, opts) {
  let st;
  try { st = await loadState(); } catch { return false; }
  if (!st.wraps.length) return false;
  const dk = await upkeepKey(userId, st, opts);
  if (!dk) return false;
  await fn(dk, st);
  return true;
}

/**
 * The password changed: a new `pw` wrap → 'ok' | 'off' (no Drive, or no key
 * yet) | 'locked' (no DK here). Without DK in the tab, the old password (when
 * the change was confirmed with it) unlocks it first. The server marked the
 * old wrap stale, so this needs no second confirmation. The owner acting as
 * the user (`impersonating`): the server has dropped the old wrap (it opened
 * only with the old password), so the new one is added, not overwritten.
 */
export async function updatePasswordWrap({ userId, newPassword, oldPassword, impersonating = false }) {
  let st;
  try { st = await loadState(); } catch { return 'off'; }
  if (!st.wraps.length) return 'off';
  const dk = await upkeepKey(userId, st, { password: oldPassword, impersonating });
  if (!dk) return 'locked';
  if (impersonating && st.wraps.some((w) => w.kind === 'pw')) return 'kept';
  const { driveSalt, wrap } = await wrapPassword(dk, newPassword);
  await api.setKeys({ driveSalt, set: [wrap], remove: [] });
  return 'ok';
}

/**
 * New recovery codes: a wrap for each (the server has already dropped the old
 * codes' wraps). → false without DK in the tab.
 */
export async function replaceRecoveryWraps(userId, codes, { password, impersonating = false } = {}) {
  return withKey(userId, async (dk) => {
    const set = [];
    for (const c of codes) set.push(await wrapRecovery(dk, c, await recoveryRef(c)));
    if (set.length) await api.setKeys({ set });
  }, { password, impersonating });
}

/** A passkey with PRF output: add (or replace) its wrap. */
export function addPasskeyWrap(userId, prfOutput, credentialId, { password, impersonating = false } = {}) {
  return withKey(userId, async (dk) => {
    await api.setKeys({ set: [await wrapPrf(dk, prfOutput, credentialId)], remove: [] });
  }, { password, impersonating });
}

/**
 * The owner reset a user's password: with the owner's DK in this tab, open
 * the user's escrow wrap (the server records it in the admin audit as
 * drive.escrow_used) and write a `pw` wrap for the new password → 'ok' |
 * 'locked' (the owner's Drive is locked) | 'no_escrow' | 'mismatch' (the
 * server's escrow public key is not the owner's) | 'no_wrap' (the user has no
 * Drive key or escrow wrap) | 'failed'. The reset itself never depends on this.
 */
export async function escrowPasswordReset({ ownerId, userId, newPassword, reason = 'password reset' }) {
  const ownerDk = loadSessionKey(ownerId);
  if (!ownerDk) return 'locked';
  const st = await loadState().catch(() => null);
  if (!st || typeof st.escrowPriv !== 'string') return 'no_escrow';
  let pair;
  try { pair = await openEscrowKeyPair(ownerDk, st.escrowPriv); } catch { return 'no_escrow'; }
  if (!st.escrowPub || !sameEscrowKey(pair.publicJwk, st.escrowPub)) return 'mismatch';
  const current = { kid: await escrowKeyId(st.escrowPub), privateKey: pair.privateKey };
  let r;
  try {
    r = await api.escrow(userId, reason);
  } catch (e) {
    if (e instanceof ApiError && (e.status === 404 || e.status === 409)) return 'no_wrap';
    throw e;
  }
  const wraps = Array.isArray(r.wraps) ? r.wraps : [];
  const wrap = r.wrap || wraps.find((w) => w && w.kind === 'escrow');
  if (!wrap) return 'no_wrap';
  const priv = await escrowKeyFor(ownerDk, wrap, current, st.escrowPrivOld);
  const dk = priv ? await unlockWithEscrow(priv, wrap) : null;
  if (!dk) return 'failed';
  const { driveSalt, wrap: pw } = await wrapPassword(dk, newPassword);
  await api.setUserKeys(userId, { driveSalt, set: [pw] });
  return 'ok';
}

// ── the client ─────────────────────────────────────────────────────────────

export class DriveClient {
  constructor(dk, keys, user) {
    this.dk = dk;
    this.keys = keys;
    this.user = user;
    /**
     * Something about the escrow key the page must show (never handled
     * silently), or null: { kind, text } with kind 'escrow_changed' (a user's
     * Drive: the owner's escrow key is not the one this Drive pinned; nothing
     * was re-wrapped — acceptEscrowKey() does it on the user's say) or, for
     * the owner, 'escrow_mismatch' | 'escrow_unreadable' | 'escrow_missing'
     * (restoreEscrowKey / newEscrowKey, with the owner's confirmation).
     */
    this.notice = null;
  }

  static async create(dk, user) {
    return new DriveClient(dk, await deriveSubkeys(dk), user);
  }

  /**
   * Bring wraps up to date after an unlock (never while the owner acts as the
   * user): the escrow wrap (for the pinned escrow key, or for a new one the
   * pinned signing key signed), the owner's escrow key pair and signing key
   * checked against what the server hands out, a passkey's wrap, a stale or
   * missing `pw` wrap (the password just verified by a sign-in).
   */
  async maintain(st, { password, prfOutput, credentialId, via, passwordVerified = false } = {}) {
    if (this.user.impersonating) return;
    const body = { set: [], remove: [] };
    const wraps = st.wraps || [];
    if (this.user.role === 'owner') {
      await this.#checkOwnerKeys(st, body);
    } else if (st.escrowPub) {
      const current = wraps.find((w) => w.kind === 'escrow');
      const kid = await escrowKeyId(st.escrowPub);
      const wrapKid = current ? escrowWrapKeyId(current) : null;
      const pinned = st.escrowPin ? await openEscrowPin(this.dk, st.escrowPin) : null;
      const next = await pinFor(st);
      // Trust on first use: the first escrow key this Drive wraps to, and the
      // owner's signing key, are pinned. Another escrow key is wrapped to only
      // when the pinned signing key signed it; else the user decides (notice).
      const ok = pinned
        ? pinned.escrow === kid || (!!pinned.sign && pinned.sign === next.sign)
        : !st.escrowPin && (wrapKid ?? kid) === kid; // a pin that does not open counts as changed
      if (!ok) {
        this.notice = { kind: 'escrow_changed', kid, text: 'The administrator’s escrow key has changed since your Drive last used it, and the change is not signed by the key your Drive trusts, so your Drive was not re-keyed for it.' };
      } else {
        if (wrapKid !== kid) body.set.push(await wrapEscrow(this.dk, st.escrowPub));
        const pin = { escrow: kid, sign: (pinned && pinned.sign) || next.sign }; // a pinned signing key never changes silently
        if (!pinned || pinned.escrow !== pin.escrow || pinned.sign !== pin.sign) body.escrowPin = await sealEscrowPin(this.dk, pin);
      }
    }
    if (prfOutput && credentialId && via !== 'passkey' && !wraps.some((w) => w.kind === 'passkey' && w.ref === credentialId)) {
      body.set.push(await wrapPrf(this.dk, prfOutput, credentialId));
    }
    const hasPw = wraps.some((w) => w.kind === 'pw');
    if (password && passwordVerified && (st.pwStale || !hasPw)) {
      const { driveSalt, wrap } = await wrapPassword(this.dk, password);
      body.driveSalt = driveSalt;
      body.set.push(wrap);
    }
    if (body.set.length || body.escrowPriv || body.escrowPin) await api.setKeys(body);
  }

  /**
   * The owner's key material: the escrow private key must open and be the
   * server's public key, the signing key must open and be the server's, and
   * the server's escrow key must carry its signature — else a notice (never a
   * silent replacement). The very first time (no key anywhere) they are made.
   */
  async #checkOwnerKeys(st, body) {
    if (typeof st.escrowPriv !== 'string') {
      if (st.escrowPub) { this.#warn('escrow_missing'); return; }
      Object.assign(body, await newOwnerKeys(this.dk));
      return;
    }
    let pair;
    try { pair = await openEscrowKeyPair(this.dk, st.escrowPriv); } catch { this.#warn('escrow_unreadable'); return; }
    if (!sameEscrowKey(pair.publicJwk, st.escrowPub)) { this.#warn('escrow_mismatch'); return; }
    let sign = null;
    if (typeof st.escrowSignPriv === 'string') {
      try { sign = await openSigningKey(this.dk, st.escrowSignPriv); } catch { this.#warn('escrow_unreadable'); return; }
    }
    if (!sign || !st.escrowSignPub || !sameEscrowKey(sign.publicJwk, st.escrowSignPub)
        || !(await escrowKeyEndorsed(st.escrowSignPub, st.escrowPub, st.escrowSig))) this.#warn('escrow_unsigned');
  }

  #warn(kind) {
    this.notice = { kind, text: NOTICE_TEXT[kind] };
  }

  /**
   * The user accepts the owner's new escrow key (after the notice): wrap DK to
   * it and pin it (with the signing key that signed it, if any).
   */
  async acceptEscrowKey() {
    const st = await loadState();
    if (!st.escrowPub) return false;
    await api.setKeys({ set: [await wrapEscrow(this.dk, st.escrowPub)], escrowPin: await sealEscrowPin(this.dk, await pinFor(st)) });
    this.notice = null;
    return true;
  }

  /**
   * The owner puts back the escrow public key that belongs to their escrow
   * private key, signed by their signing key. `step` is the confirmation
   * ({ current } | { reauth }).
   */
  async restoreEscrowKey(step) {
    const st = await loadState();
    const pair = await openEscrowKeyPair(this.dk, st.escrowPriv);
    const sign = typeof st.escrowSignPriv === 'string' ? await openSigningKey(this.dk, st.escrowSignPriv).catch(() => null) : null;
    const body = { escrowPub: pair.publicJwk, ...step };
    if (sign) Object.assign(body, { escrowSignPub: sign.publicJwk, escrowSig: await endorseEscrowKey(sign.privateKey, pair.publicJwk) });
    else Object.assign(body, await this.#newSigner(pair.publicJwk));
    await api.setKeys(body);
    this.notice = null;
  }

  async #newSigner(escrowJwk) {
    const sp = await createSigningKeyPair();
    return { escrowSignPriv: await sealSigningKey(this.dk, sp.privateKey), escrowSignPub: sp.publicJwk, escrowSig: await endorseEscrowKey(sp.privateKey, escrowJwk) };
  }

  /**
   * The owner replaces the escrow key pair (a rotation), with the owner's
   * confirmation (`step`). The new key is signed by the owner's signing key,
   * so every user's browser re-wraps to it at its next unlock; the old private
   * key stays, sealed, until no user's wrap needs it. Without a readable
   * signing key a new one is made, and users are asked (notice) instead.
   */
  async rotateEscrowKey(step) {
    const st = await loadState();
    const sign = typeof st.escrowSignPriv === 'string' ? await openSigningKey(this.dk, st.escrowSignPriv).catch(() => null) : null;
    const signed = sign && st.escrowSignPub && sameEscrowKey(sign.publicJwk, st.escrowSignPub);
    await api.setKeys({ ...(await newOwnerKeys(this.dk, signed ? sign.privateKey : null)), ...step });
    this.notice = null;
  }

  /** A new escrow key pair after the notice (the old key does not open): as rotateEscrowKey. */
  async newEscrowKey(step) {
    return this.rotateEscrowKey(step);
  }

  /** { used, capacity } in bytes (capacity null = no limit). */
  async usage() {
    const st = await loadState();
    return { used: st.used, capacity: st.capacity ?? null };
  }

  async #text(field, id, value) {
    return fromUtf8(await openField(this.keys.names, field, id, sealed(value)));
  }

  /**
   * A server node → { id, parent, kind, name, type, mtime, size, chunks,
   * created, updated } (name null if unreadable). A file is readable only
   * with its sealed metadata, whose size must be the server's and match the
   * chunk count: a file whose metadata is missing, altered or disagrees is
   * `unreadable`, never an empty (or cut) file (SECURITY.md §1).
   */
  async decode(n) {
    if (!n || typeof n.id !== 'string') throw malformed();
    const base = { id: n.id, parent: n.parent ?? null, kind: n.kind === 'file' ? 'file' : 'dir', size: n.size ?? 0, chunks: n.chunks ?? 0, created: n.created ?? 0, updated: n.updated ?? 0 };
    if (n.id === ROOT) return { ...base, kind: 'dir', name: ROOT_NAME, type: null, mtime: 0 };
    let name = null;
    let renamed = false;
    try {
      const raw = await this.#text('name', n.id, n.name);
      name = cleanName(raw); // an older name with spoofing characters shows (and downloads) cleaned
      renamed = name !== raw;
    } catch { /* unreadable */ }
    const badName = name === null;
    let type = null;
    let mtime = 0;
    if (base.kind === 'file') {
      let ok = false;
      try {
        const m = JSON.parse(await this.#text('meta', n.id, n.meta));
        type = normalizeMime(m.type) || OCTET;
        mtime = Number.isSafeInteger(m.mtime) && m.mtime >= 0 ? m.mtime : 0;
        ok = Number.isSafeInteger(m.size) && m.size === base.size && base.chunks === refChunks(base.size);
      } catch { /* missing or unreadable metadata */ }
      if (!ok) name = null;
    }
    return { ...base, name, type: base.kind === 'file' ? (type || OCTET) : null, mtime, ...(name === null ? { unreadable: true } : {}), ...(badName ? { badName: true } : {}), ...(renamed && name !== null ? { renamed: true } : {}) };
  }

  async #fileKey(n) {
    const raw = n.fk ? n : (await api.node(n.id)).node;
    return b64urlFromBytes(await openField(this.keys.files, 'fk', n.id, sealed(raw.fk)));
  }

  /**
   * A folder's content → { node, path, children }: `path` is [{ id, name }]
   * from the root down to and including the node; children are sorted,
   * folders first. A Drive whose names none decrypt is locked with the wrong
   * key: the tab's key is dropped and DriveLocked thrown.
   */
  async list(nodeId = ROOT) {
    const r = await api.node(nodeId);
    if (!r || !r.node || !Array.isArray(r.children)) throw malformed();
    const raw = r.children.filter((c) => c && c.state !== 'pending');
    const children = await Promise.all(raw.map((c) => this.decode(c)));
    // A Drive whose names none decrypt: this tab's key is not its key.
    if (children.length && children.every((c) => c.badName)) {
      if (this.user.impersonating) clearImpersonationKey(); else clearSessionKey();
      throw new DriveLocked('This tab holds the wrong key for your Drive. Unlock it again.', 'wrong');
    }
    children.sort((a, b) => (a.kind === b.kind ? String(a.name ?? '').localeCompare(String(b.name ?? '')) : a.kind === 'dir' ? -1 : 1));
    const node = await this.decode(r.node);
    let anc = Array.isArray(r.path) ? r.path.filter((p) => p && p.id !== node.id) : [];
    if (anc.length && anc[0].id !== ROOT && anc[anc.length - 1].id === ROOT) anc = anc.reverse();
    const path = [];
    for (const p of anc) { const d = await this.decode(p); path.push({ id: d.id, name: d.name }); }
    path.push({ id: node.id, name: node.name });
    return { node, path, children };
  }

  /** A new folder → its id. */
  async mkdir(parentId, name) {
    const id = newId();
    const r = await api.mkdir({ id, parent: parentId, name: await sealField(this.keys.names, 'name', id, checkName(name)) });
    if (r.id !== undefined && r.id !== id) throw malformed();
    return id;
  }

  /**
   * Upload a File (or a Blob with `name`) into `parentId` → its id. Options:
   * onProgress(bytesDone, total), signal (AbortSignal), name, type, mtime,
   * taken (a Set of the names already in the folder, from names(); updated
   * here — else the folder is read). A name already taken gets " (2)"….
   */
  async upload(parentId, file, { onProgress, signal, name, type, mtime, taken } = {}) {
    // A name already used in the folder gets " (2)", " (3)"… (the server cannot see names).
    const fileName = uniqueName(taken ?? (await this.names(parentId)).names, checkName(name ?? file.name));
    const size = file.size;
    const head = new Uint8Array(await file.slice(0, 64).arrayBuffer());
    const mime = normalizeMime(type) || detectMime({ name: fileName, platformType: file.type, head });
    const time = Number.isSafeInteger(mtime) && mtime >= 0 ? mtime : (file.lastModified || 0);
    const id = newId();
    const fk = randomBytes(32);
    const n = refChunks(size);
    const init = await api.createFile({
      id,
      parent: parentId,
      name: await sealField(this.keys.names, 'name', id, fileName),
      meta: await sealField(this.keys.names, 'meta', id, JSON.stringify({ type: mime, mtime: time, size })),
      size,
      fk: await sealField(this.keys.files, 'fk', id, fk),
    });
    const token = init.uploadToken ?? init.uploadtoken;
    if ((init.id !== undefined && init.id !== id) || init.chunks !== n || typeof token !== 'string') throw malformed();
    try {
      const key = await importFileKey(b64urlFromBytes(fk));
      let done = 0;
      if (onProgress) onProgress(0, size);
      for (let i = 0; i < n; i++) {
        if (signal?.aborted) throw aborted(signal, 'Upload');
        const plain = new Uint8Array(await file.slice(i * CHUNK, Math.min(size, (i + 1) * CHUNK)).arrayBuffer());
        const ct = await encryptChunk(key, i, n, plain);
        try {
          await api.putChunk(id, i, ct, token, signal);
        } catch (e) {
          if ((e instanceof ApiError && e.status < 500) || e?.name === 'AbortError') throw e;
          await api.putChunk(id, i, ct, token, signal); // one retry for transient failures
        }
        done += plain.length;
        if (onProgress) onProgress(done, size);
      }
      if (signal?.aborted) throw aborted(signal, 'Upload');
      // "busy": an earlier attempt of a chunk (one this loop retried) is still being written.
      for (let tries = 0; ; tries++) {
        try {
          await api.finalize(id, token);
          break;
        } catch (e) {
          if (!(e instanceof ApiError && e.code === 'busy') || tries >= 20) throw e;
          await new Promise((res) => setTimeout(res, 250));
        }
      }
    } catch (e) {
      api.remove(id).catch(() => {}); // free the capacity now (the server purges it later anyway)
      throw e;
    }
    return id;
  }

  /**
   * Upload many files by relative path into `parentId`, creating (or reusing)
   * folders on the way. `entries` = [{ path, file } | { path, dir: true }].
   * opts: onProgress(bytesDone, total), onFile(path), signal. → [ids of files].
   */
  async uploadTree(parentId, entries, { onProgress, onFile, signal } = {}) {
    const total = entries.reduce((s, e) => s + (e.dir ? 0 : e.file.size), 0);
    const folders = new Map([['', parentId]]);
    const inside = new Map(); // folder id → { dirs: Map(name → id), names: Set }
    const contentOf = async (id) => {
      if (!inside.has(id)) inside.set(id, await this.names(id).catch(() => ({ dirs: new Map(), names: new Set() })));
      return inside.get(id);
    };
    const ensure = async (dirPath) => {
      if (folders.has(dirPath)) return folders.get(dirPath);
      const cut = dirPath.lastIndexOf('/');
      const parent = await ensure(cut < 0 ? '' : dirPath.slice(0, cut));
      const leaf = dirPath.slice(cut + 1);
      const here = await contentOf(parent);
      // An existing folder of that name is reused (merged into); a file of that name is not.
      let id = here.dirs.get(leaf);
      if (!id) {
        id = await this.mkdir(parent, uniqueName(here.names, leaf));
        here.dirs.set(leaf, id);
        inside.set(id, { dirs: new Map(), names: new Set() });
      }
      folders.set(dirPath, id);
      return id;
    };
    const ids = [];
    let before = 0;
    for (const e of entries) {
      if (signal?.aborted) throw aborted(signal, 'Upload');
      const path = checkPath(cleanName(e.path));
      path.split('/').forEach(checkName);
      if (e.dir) { await ensure(path); continue; }
      const cut = path.lastIndexOf('/');
      const dir = await ensure(cut < 0 ? '' : path.slice(0, cut));
      if (onFile) onFile(path);
      const base = before;
      const { names: taken } = await contentOf(dir);
      ids.push(await this.upload(dir, e.file, { name: path.slice(cut + 1), taken, signal, onProgress: onProgress && ((d) => onProgress(base + d, total)) }));
      before += e.file.size;
    }
    if (onProgress) onProgress(total, total);
    return ids;
  }

  /**
   * The names in folder `id` → { names: Set (every readable name), dirs:
   * Map(folder name → id) }, for picking names that do not clash. Unlike
   * list(), an unreadable name is skipped, never a reason to lock.
   */
  async names(id) {
    const r = await api.node(id);
    if (!r || !Array.isArray(r.children)) throw malformed();
    const names = new Set();
    const dirs = new Map();
    for (const c of r.children.filter((x) => x && x.state !== 'pending')) {
      const d = await this.decode(c).catch(() => null);
      if (!d || d.name === null) continue;
      names.add(d.name);
      if (d.kind === 'dir' && !dirs.has(d.name)) dirs.set(d.name, d.id);
    }
    return { names, dirs };
  }

  async rename(id, name) {
    await api.update(id, { name: await sealField(this.keys.names, 'name', id, checkName(name)) });
  }

  async move(id, parentId) {
    await api.update(id, { parent: parentId });
  }

  /** Delete a node (recursively); every share that references it ends. */
  async remove(id) {
    await api.remove(id);
  }

  /** The file entry (with its key) and a reader for one file node. */
  async #fileEntry(raw, path) {
    const d = await this.decode(raw);
    if (d.kind !== 'file' || d.unreadable) throw new Error('This file cannot be read.');
    return { path: path ?? d.name, size: d.size, type: d.type, mtime: d.mtime, fk: await this.#fileKey(raw), node: d.id, chunks: d.chunks };
  }

  #reader(entries, total) {
    return new RefsReader({
      manifest: { v: 3, entries, total, view: null },
      fetch: (entry, i) => api.chunk(entry.node, i),
      refs: entries.filter((e) => !e.dir).map((e) => ({ chunks: e.chunks })),
    });
  }

  /**
   * One file → { entry, reader, save(onBytes?), blob(onBytes?) }: `reader` and
   * `entry` work with downloads.js saveFile; save() streams it to disk (or a
   * download), blob() returns it in memory (small files, previews). Options
   * (used when save/blob get no onBytes): onProgress(bytesDone, total) and
   * signal (AbortSignal: the transfer stops with its AbortError).
   */
  async download(id, { onProgress, signal } = {}) {
    const r = await api.node(id);
    if (!r || !r.node) throw malformed();
    const entry = { ...(await this.#fileEntry(r.node)), ref: 0 };
    const reader = this.#reader([entry], entry.size);
    const counter = () => byteCounter(entry.size, onProgress, signal);
    return {
      entry,
      reader,
      save: (onBytes) => saveFile(reader, entry, onBytes ?? counter()),
      blob: async (onBytes) => new Blob([await reader.bytes(entry, onBytes ?? counter())], { type: entry.type }),
    };
  }

  /**
   * Flatten nodes into { files: [{ path, id, ...entry }], dirs: [path] }:
   * each top-level node by its own name, folders recursively; duplicate
   * names get " (2)", " (3)"… so every path is unique.
   */
  async #collect(nodeIds) {
    const out = { files: [], dirs: [], count: 0 };
    const top = new Set();
    for (const id of nodeIds) {
      if (id === ROOT) { await this.#walk(ROOT, '', out, 1); continue; }
      const r = await api.node(id);
      if (!r || !r.node) throw malformed();
      const d = await this.decode(r.node);
      if (d.unreadable) throw new Error('A file or folder name cannot be read.');
      const name = uniqueName(top, checkName(d.name)); // paths for ZIPs and manifests: never ".." or "/" from a name
      if (++out.count > MAX_ENTRIES) throw new Error(`At most ${MAX_ENTRIES} files and folders at once.`);
      if (d.kind === 'file') {
        out.files.push({ ...(await this.#fileEntry(r.node, name)), id });
      } else {
        out.dirs.push(name);
        await this.#walk(id, name, out, 2);
      }
    }
    return out;
  }

  /** Walk folder `dirId` into `out` ({ files, dirs, count }), with paths under `path`. */
  async #walk(dirId, path, out, depth) {
    if (depth > MAX_DEPTH) throw new Error('The folders are nested too deeply.');
    const r = await api.node(dirId);
    if (!r || !Array.isArray(r.children)) throw malformed();
    const taken = new Set();
    for (const c of r.children.filter((x) => x && x.state !== 'pending')) {
      if (++out.count > MAX_ENTRIES) throw new Error(`At most ${MAX_ENTRIES} files and folders at once.`);
      const d = await this.decode(c);
      if (d.unreadable) throw new Error('A file or folder name cannot be read.');
      const leaf = uniqueName(taken, checkName(d.name)); // paths for ZIPs and manifests: never ".." or "/" from a name
      const p = path ? `${path}/${leaf}` : leaf;
      if (d.kind === 'file') {
        out.files.push({ ...(await this.#fileEntry(c, p)), id: c.id });
      } else {
        out.dirs.push(p);
        await this.#walk(c.id, p, out, depth + 1);
      }
    }
  }

  /**
   * Save a folder as a ZIP of its content (downloads.js saveZip) → resolves
   * when saved. opts: onProgress(bytesDone, total), signal, zipName.
   */
  async downloadFolder(id, { onProgress, signal, zipName } = {}) {
    const r = await api.node(id);
    if (!r || !r.node) throw malformed();
    const d = await this.decode(r.node);
    const out = { files: [], dirs: [], count: 0 };
    await this.#walk(id, '', out, 1);
    const entries = [...out.files.map((f, ref) => ({ ...f, ref })), ...out.dirs.map((path) => ({ path, dir: true }))];
    const total = out.files.reduce((s, f) => s + f.size, 0);
    const reader = this.#reader(entries, total);
    await saveZip(reader, '', zipName || `${d.name || 'drive'}.zip`, byteCounter(total, onProgress, signal));
  }

  /**
   * Share files and folders → { url, id, deletetoken }. opts: views (null =
   * unlimited), expire, password, deletable, label; `limits` (the profile's)
   * applies the administrator's file-type and folder-depth policy here, as the
   * composer does; `view` is the viewer snapshot ({ rules, maxBytes } or null).
   * The manifest (v3: paths, sizes, types and each file's key) is sealed with
   * a fresh link key and optional password exactly like a file share's.
   */
  async share(nodeIds, { views = null, expire, password = '', deletable = false, label = '', limits = null, view = null } = {}) {
    if (!Array.isArray(nodeIds) || !nodeIds.length) throw new Error('Choose what to share.');
    const { files, dirs } = await this.#collect(nodeIds);
    if (!files.length) throw new Error('There are no files to share.');
    const body = { nodes: files.map((f) => f.id), views, expire };
    const typePolicy = limits && ['allow', 'block'].includes(limits.fileTypeMode);
    const depthPolicy = limits && Number.isInteger(limits.maxFolderDepth);
    if (typePolicy || depthPolicy) {
      const d = declare([...files, ...dirs.map((p) => ({ path: p, dir: true }))]);
      if (depthPolicy && d.depth > limits.maxFolderDepth) throw new Error(`Folders may nest at most ${limits.maxFolderDepth} levels deep for your account; this share has ${d.depth}.`);
      if (typePolicy) {
        const odd = files.find((f) => uncheckableExt(f.path));
        if (odd) throw new Error(`"${odd.path}" has an unusual extension that cannot be checked against your administrator's file-type policy.`);
        const refused = refusedTypes(limits.fileTypeMode, limits.fileTypeRules, d.types);
        if (refused.length) throw new Error(`Your administrator does not allow ${refused.map(describeType).join(', ')} files.`);
        body.types = d.types;
      }
      if (depthPolicy) body.depth = d.depth;
    }
    const manifest = buildRefsManifest({ files: files.map((f) => ({ path: f.path, size: f.size, type: f.type, mtime: f.mtime, fk: f.fk })), dirs, view });
    const { body: paste, fragment } = await encryptPaste({
      text: JSON.stringify(manifest), fmt: 'files', password, bar: views !== null, views: views ?? undefined, expire, deletable,
    });
    Object.assign(body, { paste, acc: paste.acc });
    if (deletable) body.deletable = true;
    if (label) body.label = label;
    const r = await api.share(body);
    if (typeof r.id !== 'string' || typeof r.deletetoken !== 'string') throw malformed();
    return { url: `${location.origin}/p/${r.id}#${fragment}`, id: r.id, deletetoken: r.deletetoken };
  }

  /** The shares that reference a node. */
  async shares(nodeId) {
    const r = await api.shares(nodeId);
    return Array.isArray(r.shares) ? r.shares : [];
  }
}
