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
  wrapEscrow, unlockWithEscrow, escrowKeyId, escrowWrapKeyId, sealEscrowPin, openEscrowPin, wrapHandoff, unlockWithHandoff,
  saveSessionKey, loadSessionKey, clearSessionKey, sessionKeyUser, saveImpersonationKey, loadImpersonationKey, clearImpersonationKey,
} from './drivekeys.js';
import { encryptPaste } from './crypto.js';
import { randomBytes, utf8, fromUtf8, b64urlFromBytes } from './bytes.js';
import { CHUNK, encryptChunk, importFileKey, checkPath, MAX_ENTRIES, INVISIBLE_RE } from './files.js';
import { detectMime, normalizeMime, OCTET } from './mime.js';
import { RefsReader, saveFile, saveZip } from './downloads.js';
import { buildRefsManifest, refChunks } from './refsmanifest.js';
import { declare, refusedTypes, uncheckableExt, describeType } from './filepolicy.js';
import { passkeyPrfOnly } from './passkeys.js';
import { createReverseKey, sealReversePriv, openReversePriv, linkHash, passwordGate, sealNote, fragmentOf, openUpload, newReverseId } from './reversekeys.js';

/**
 * No usable DK in this tab (`reason`: 'locked' | 'wrong' | 'setup' |
 * 'handoff' | 'no_passkey', and while the owner acts as a user:
 * 'owner_locked' (the owner's own Drive is not unlocked in this tab) |
 * 'no_escrow' (the owner has no escrow key yet, or it does not open) |
 * 'no_wrap' (the user's Drive has no escrow wrap yet) | 'escrow_failed' (the
 * wrap is for another escrow key) | 'escrow_mismatch' (the server's escrow
 * public key is not the owner's: see DriveClient#notice)). `credentialIds`
 * (from openDrive) lists the passkeys (base64url credential ids) that have a
 * Drive wrap, so a page can offer the passkey unlock only when one exists.
 */
export class DriveLocked extends Error {
  constructor(message = 'Unlock your Drive to continue.', reason = 'locked', credentialIds = [], received = 0) {
    super(message);
    this.name = 'DriveLocked';
    this.reason = reason;
    this.credentialIds = credentialIds;
    /** Received files (reverse shares) waiting for the Drive to be unlocked. */
    this.received = received;
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
 * A node name as typed, or throws: no "/", "\", control characters, bidi or
 * invisible characters (files.js INVISIBLE_RE), "." or ".."; 1–255 bytes.
 */
export function checkName(name) {
  // eslint-disable-next-line no-control-regex
  if (typeof name !== 'string' || !name || name === '.' || name === '..' || /[\u0000-\u001f\u007f/\\]/.test(name) || INVISIBLE_RE.test(name)) {
    throw new Error('Names cannot be empty, "." or "..", or contain "/", "\\", control characters or invisible (bidi, zero-width) characters.');
  }
  if (utf8(name).length > MAX_NAME_BYTES) throw new Error(`Names can be at most ${MAX_NAME_BYTES} bytes long.`);
  return name;
}

const NOTICE_TEXT = {
  escrow_mismatch: 'The escrow public key the server gives every Drive is not the one your escrow private key belongs to: it may have been replaced. No Drive is wrapped to it from this browser until you restore it.',
  escrow_unreadable: 'Your escrow private key does not open with your Drive key, so it cannot be checked or used.',
  escrow_missing: 'The server has an escrow public key, but your Drive holds no escrow private key for it.',
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

/**
 * The Drive with this tab's DK → DriveClient. Throws DriveLocked when the tab
 * has none (reason 'setup' when the Drive has no key yet, 'handoff' when the
 * owner created it and the user's password finishes the set-up),
 * DriveDisabled when the role has no Drive. `user` ({ id, role,
 * impersonating }) saves a session lookup. While the owner acts as the user,
 * the Drive opens through the owner escrow (openAsOwner).
 */
export async function openDrive({ user } = {}) {
  const u = await whoAmI(user);
  const st = await loadState();
  if (u.impersonating) return openAsOwner(u, st);
  if (!st.wraps.length) {
    clearSessionKey();
    throw new DriveLocked('Set up your Drive with your password.', 'setup');
  }
  const dk = loadSessionKey(u.id);
  if (!dk) {
    if (st.handoffKey) throw new DriveLocked('Your administrator created your Drive: enter your account password to finish setting it up.', 'handoff');
    throw new DriveLocked(undefined, 'locked', passkeyRefs(st), Number(st.received) || 0);
  }
  const client = await DriveClient.create(dk, u);
  await client.maintain(st).catch(() => {});
  return client;
}

/**
 * Unlock DK with what the user has — { password } | { code } | { prfOutput,
 * credentialId } (several may be given; the first that opens a wrap wins) —
 * keep it for the tab and return a DriveClient. The first time (no wraps yet)
 * this creates DK, which needs the password. Throws DriveLocked ('wrong',
 * 'setup') or DriveDisabled.
 *
 * `passwordVerified` (sign-in only: the server has just accepted the password)
 * lets a stale `pw` wrap be replaced; `spentWraps` are the wraps of a recovery
 * code this sign-in used up (the server removed them and returned them once).
 */
export async function unlockDrive(creds = {}, { user, passwordVerified = false, spentWraps = [] } = {}) {
  const u = await whoAmI(user);
  let st = await loadState();
  if (u.impersonating) return openAsOwner(u, st);
  let dk = null;
  let via = null;
  if (!st.wraps.length) {
    if (!creds.password) throw new DriveLocked('Set up your Drive with your password.', 'setup');
    dk = await setUp(u, st, creds);
    via = 'pw';
    st = await loadState(); // what the set-up stored (the owner's first escrow key pair included)
  } else {
    if (creds.password) { dk = await unlockWithPassword(creds.password, st.driveSalt, st.wraps); via = 'pw'; }
    if (!dk && creds.prfOutput && creds.credentialId) { dk = await unlockWithPrf(creds.prfOutput, creds.credentialId, st.wraps); via = 'passkey'; }
    if (!dk && creds.code) { dk = await unlockWithRecovery(creds.code, [...st.wraps, ...(Array.isArray(spentWraps) ? spentWraps : [])]); via = 'recovery'; }
    // A Drive the owner created while acting as this user: its one-time hand-over.
    if (!dk && st.handoffKey) { dk = await unlockWithHandoff(st.handoffKey, st.wraps); via = 'handoff'; }
    if (!dk) throw new DriveLocked('That does not unlock your Drive.', 'wrong');
  }
  saveSessionKey(dk, u.id);
  const client = await DriveClient.create(dk, u);
  await client.maintain(st, { ...creds, via, passwordVerified: passwordVerified || via === 'handoff' }).catch(() => {});
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

/**
 * The first DK: wraps for the password (and passkey, escrow, with the escrow
 * key pinned); the owner's escrow key pair when there is none yet (a later
 * one needs the owner's confirmation: DriveClient#notice).
 */
async function setUp(u, st, creds) {
  // A Drive with content but no wraps is broken, not new: never replace its key.
  const top = await api.node(ROOT).catch(() => null);
  if (top && Array.isArray(top.children) && top.children.length) throw new DriveLocked('Your Drive has no keys. Contact the administrator.', 'wrong');
  const dk = createDriveKey();
  const { driveSalt, wrap } = await wrapPassword(dk, creds.password);
  const set = [wrap];
  if (creds.prfOutput && creds.credentialId) set.push(await wrapPrf(dk, creds.prfOutput, creds.credentialId));
  const body = { driveSalt, set, remove: [] };
  if (u.role === 'owner') {
    if (!st.escrowPub) {
      const kp = await createEscrowKeyPair();
      body.escrowPriv = await sealEscrowPriv(dk, kp.privateKey);
      body.escrowPub = kp.publicJwk;
    }
  } else if (st.escrowPub) {
    set.push(await wrapEscrow(dk, st.escrowPub));
    body.escrowPin = await sealEscrowPin(dk, await escrowKeyId(st.escrowPub));
  }
  await api.setKeys(body);
  // Two tabs may set up at the same moment: the stored `pw` wrap decides.
  const after = await loadState();
  const stored = after.wraps.find((w) => w.kind === 'pw');
  if (stored && stored.data === wrap.data) return dk;
  const other = await unlockWithPassword(creds.password, after.driveSalt, after.wraps);
  if (other) return other;
  throw new DriveLocked('That does not unlock your Drive.', 'wrong');
}

/**
 * The owner, acting as user `u`, opens that user's Drive with the owner
 * escrow (docs/DRIVE.md §3): the owner's own DK (already in this tab) opens
 * the owner's escrow private key, which opens the user's escrow wrap. The
 * user's DK is kept in its own slot (never the owner's) until the
 * impersonation ends. A Drive with no key yet is created here (an escrow wrap
 * and a one-time hand-over wrap; the user's password wrap follows at their
 * next sign-in). Every call of the escrow route is in the admin audit.
 */
async function openAsOwner(u, st) {
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
  let dk;
  if (!st.wraps.length) {
    // The user's Drive, created for them: never over content (that would hide it).
    const top = await api.node(ROOT).catch(() => null);
    if (top && Array.isArray(top.children) && top.children.length) throw new DriveLocked('This Drive has content but no keys.', 'no_wrap');
    dk = createDriveKey();
    const handoff = await wrapHandoff(dk);
    await api.setKeys({
      set: [await wrapEscrow(dk, r.escrowPub), handoff.wrap],
      handoffKey: handoff.handoffKey,
      escrowPin: await sealEscrowPin(dk, await escrowKeyId(r.escrowPub)),
    });
  } else {
    if (!r.wrap) throw new DriveLocked('This user’s Drive has no escrow wrap yet.', 'no_wrap');
    dk = await unlockWithEscrow(pair.privateKey, r.wrap);
    if (!dk) throw new DriveLocked('This user’s escrow wrap was made for another escrow key.', 'escrow_failed');
  }
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
  const dk = await unlockWithEscrow(pair.privateKey, wrap);
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
   * user): the escrow wrap (for the pinned escrow key only), the owner's
   * escrow key pair checked against the server's public key, a passkey's
   * wrap, a stale or missing `pw` wrap (the password just verified by a
   * sign-in, or a hand-over being finished).
   */
  async maintain(st, { password, prfOutput, credentialId, via, passwordVerified = false } = {}) {
    if (this.user.impersonating) return;
    const body = { set: [], remove: [] };
    const wraps = st.wraps || [];
    if (this.user.role === 'owner') {
      if (typeof st.escrowPriv === 'string') {
        let pair = null;
        try { pair = await openEscrowKeyPair(this.dk, st.escrowPriv); } catch { this.#warn('escrow_unreadable'); }
        if (pair && !sameEscrowKey(pair.publicJwk, st.escrowPub)) this.#warn('escrow_mismatch');
      } else if (st.escrowPub) {
        this.#warn('escrow_missing');
      } else {
        // The very first escrow key pair (no key anywhere yet).
        const kp = await createEscrowKeyPair();
        body.escrowPriv = await sealEscrowPriv(this.dk, kp.privateKey);
        body.escrowPub = kp.publicJwk;
      }
    } else if (st.escrowPub) {
      const current = wraps.find((w) => w.kind === 'escrow');
      const kid = await escrowKeyId(st.escrowPub);
      const wrapKid = current ? escrowWrapKeyId(current) : null;
      const pinned = st.escrowPin ? await openEscrowPin(this.dk, st.escrowPin) : null;
      // Trust on first use: the first escrow key this Drive wraps to is pinned;
      // a different key later is never wrapped to without the user's say.
      const trusted = pinned ?? (st.escrowPin ? null : (wrapKid ?? kid));
      if (trusted !== kid) {
        this.notice = { kind: 'escrow_changed', kid, text: 'The administrator’s escrow key has changed since your Drive last used it, so your Drive was not re-keyed for the new one.' };
      } else {
        if (wrapKid !== kid) body.set.push(await wrapEscrow(this.dk, st.escrowPub));
        if (!pinned) body.escrowPin = await sealEscrowPin(this.dk, kid);
      }
    }
    if (prfOutput && credentialId && via !== 'passkey' && !wraps.some((w) => w.kind === 'passkey' && w.ref === credentialId)) {
      body.set.push(await wrapPrf(this.dk, prfOutput, credentialId));
    }
    const hasPw = wraps.some((w) => w.kind === 'pw');
    if (password && passwordVerified && (st.pwStale || !hasPw || via === 'handoff')) {
      const { driveSalt, wrap } = await wrapPassword(this.dk, password);
      body.driveSalt = driveSalt;
      body.set.push(wrap);
    }
    if (body.set.length || body.escrowPriv || body.escrowPin) await api.setKeys(body);
  }

  #warn(kind) {
    this.notice = { kind, text: NOTICE_TEXT[kind] };
  }

  /**
   * The user accepts the owner's new escrow key (after the notice): wrap DK to
   * it and pin it.
   */
  async acceptEscrowKey() {
    const st = await loadState();
    if (!st.escrowPub) return false;
    const kid = await escrowKeyId(st.escrowPub);
    await api.setKeys({ set: [await wrapEscrow(this.dk, st.escrowPub)], escrowPin: await sealEscrowPin(this.dk, kid) });
    this.notice = null;
    return true;
  }

  /**
   * The owner puts back the escrow public key that belongs to their escrow
   * private key. `step` is the confirmation ({ current } | { reauth }).
   */
  async restoreEscrowKey(step) {
    const st = await loadState();
    const pair = await openEscrowKeyPair(this.dk, st.escrowPriv);
    await api.setKeys({ escrowPub: pair.publicJwk, ...step });
    this.notice = null;
  }

  /**
   * The owner makes a new escrow key pair (when theirs cannot be opened, or
   * none matches the server). Every user's Drive then shows a notice before
   * it is wrapped to it; escrow wraps for the old key no longer open.
   */
  async newEscrowKey(step) {
    const kp = await createEscrowKeyPair();
    await api.setKeys({ escrowPriv: await sealEscrowPriv(this.dk, kp.privateKey), escrowPub: kp.publicJwk, ...step });
    this.notice = null;
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
    try { name = await this.#text('name', n.id, n.name); } catch { /* unreadable */ }
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
    return { ...base, name, type: base.kind === 'file' ? (type || OCTET) : null, mtime, ...(name === null ? { unreadable: true } : {}), ...(badName ? { badName: true } : {}) };
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
      const path = checkPath(e.path);
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
      checkName(d.name); // paths for ZIPs and manifests: never ".." or "/" from a name
      const name = uniqueName(top, d.name);
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
      checkName(d.name); // paths for ZIPs and manifests: never ".." or "/" from a name
      const p = path ? `${path}/${uniqueName(taken, d.name)}` : uniqueName(taken, d.name);
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

  // ── reverse shares (docs/REVERSE.md) ───────────────────────────────────

  /**
   * A reverse share on folder `folderId` → { url, id, expires }: a new link key
   * pair (its private key sealed with this Drive's key), the link proof's
   * hash, the note sealed with the link key, and — with a password — the
   * gate the server checks (it only lets the uploader in; it protects nothing).
   * opts: label, note, password, expire ("7d"), maxFiles, maxBytes,
   * maxFileBytes (null = none), types ({ mode, rules } or null), and `step`:
   * the "confirm it's you" part ({ current } or { reauth }, as for API keys) —
   * a link adds key material to the Drive, so the server asks for it.
   */
  async createReverse(folderId, { label = '', note = '', password = '', expire = '7d', maxFiles = null, maxBytes = null, maxFileBytes = null, types = null, step = {} } = {}) {
    const id = newReverseId();
    const { pub, privateKey } = await createReverseKey();
    const body = {
      id, folder: folderId, priv: await sealReversePriv(this.dk, id, privateKey), lh: await linkHash(pub), expire,
      maxFiles, maxBytes, maxFileBytes, types,
    };
    if (note) body.note = await sealNote(pub, id, note);
    if (password) body.password = await passwordGate(password, pub);
    if (label) body.label = label;
    Object.assign(body, step);
    const r = await api.createReverse(body);
    if (r.id !== id) throw malformed();
    return { url: reverseUrl(id, pub), id, expires: r.expires };
  }

  /**
   * Reverse shares (of one folder, or all) → rows as the server lists them,
   * each with `url` (the link, rebuilt from its private key here) or null.
   */
  async reverseShares(folderId = null) {
    const r = await api.reverse(folderId);
    const rows = Array.isArray(r.reverse) ? r.reverse : [];
    return Promise.all(rows.map(async (x) => {
      let url = null;
      try { url = reverseUrl(x.id, (await openReversePriv(this.dk, x.id, x.priv)).pub); } catch { /* not this Drive's key */ }
      const { priv, ...rest } = x; // eslint-disable-line no-unused-vars
      return { ...rest, url };
    }));
  }

  /**
   * Take in the files reverse shares have received: open each with its
   * share's private key, create (or reuse, by name) the upload's folders in
   * the target folder, and re-wrap its name, metadata and key into the normal
   * Drive format (the content is not touched) → { added, failed, more }.
   * Items that do not open are left as they are (counted in `failed`).
   */
  async receivePending({ onItem } = {}) {
    const r = await api.received();
    const items = Array.isArray(r.items) ? r.items : [];
    const keys = new Map();
    for (const k of Array.isArray(r.keys) ? r.keys : []) {
      try { keys.set(k.id, (await openReversePriv(this.dk, k.id, k.priv)).privateKey); } catch { /* sealed under another key */ }
    }
    // As uploadTree: an existing folder of a name is reused, a clashing file name gets " (2)"….
    const folders = new Map(); // `${parent}\n${path}` → id
    const inside = new Map(); // folder id → { dirs: Map(name → id), names: Set }
    const contentOf = async (id) => {
      if (!inside.has(id)) inside.set(id, await this.names(id).catch(() => ({ dirs: new Map(), names: new Set() })));
      return inside.get(id);
    };
    const ensure = async (parent, dirPath) => {
      if (!dirPath) return parent;
      const key = `${parent}\n${dirPath}`;
      if (folders.has(key)) return folders.get(key);
      const cut = dirPath.lastIndexOf('/');
      const up = await ensure(parent, cut < 0 ? '' : dirPath.slice(0, cut));
      const leaf = dirPath.slice(cut + 1);
      const here = await contentOf(up);
      let id = here.dirs.get(leaf);
      if (!id) {
        id = await this.mkdir(up, uniqueName(here.names, leaf));
        here.dirs.set(leaf, id);
        inside.set(id, { dirs: new Map(), names: new Set() });
      }
      folders.set(key, id);
      return id;
    };
    let added = 0;
    let failed = 0;
    for (const it of items) {
      const priv = keys.get(it.rs);
      try {
        if (!priv) throw new Error('no key');
        const got = await openUpload(priv, it.rs, it);
        // The uploader's sealed size must be the server's (the chunks follow from it): else it fails closed.
        if (got.size !== it.size) throw new Error('size mismatch');
        const path = checkPath(got.path);
        path.split('/').forEach(checkName);
        const cut = path.lastIndexOf('/');
        const parent = await ensure(it.parent, cut < 0 ? '' : path.slice(0, cut));
        const type = normalizeMime(got.type) || OCTET;
        const { names: taken } = await contentOf(parent);
        const leaf = uniqueName(taken, path.slice(cut + 1));
        await api.acceptReceived(it.id, {
          parent,
          name: await sealField(this.keys.names, 'name', it.id, leaf),
          // The server's size is the one the chunks have: the metadata says the same.
          meta: await sealField(this.keys.names, 'meta', it.id, JSON.stringify({ type, mtime: got.mtime, size: it.size })),
          fk: await sealField(this.keys.files, 'fk', it.id, got.fk),
        });
        added++;
        if (onItem) onItem({ id: it.id, path, name: leaf, parent });
      } catch {
        failed++;
      }
    }
    return { added, failed, more: !!r.more };
  }
}

/** The uploader's link of a reverse share: /r/<id>#<the raw public key>. */
function reverseUrl(id, pub) {
  return `${location.origin}/r/${id}#${fragmentOf(pub)}`;
}
