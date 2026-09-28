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
  openSigningKey, endorseEscrowKey, escrowKeyEndorsed, signingKeyId, openPrivateKeyBytes, sealPrivateKeyBytes, privateKeyFromBytes, keyCheckValue,
  saveSessionKey, loadSessionKey, clearSessionKey, sessionKeyUser, saveImpersonationKey, loadImpersonationKey, clearImpersonationKey,
} from './drivekeys.js';
import { encryptPaste } from './crypto.js';
import { randomBytes, utf8, fromUtf8, b64urlFromBytes, bytesFromB64url } from './bytes.js';
import { sealDriveKit, parseDriveKit, openDriveKit, DriveKitError, kitKindFor } from './drivekit.js';
import { CHUNK, encryptChunk, importFileKey, checkPath, MAX_ENTRIES, cleanName } from './files.js';
import { detectMime, normalizeMime, OCTET } from './mime.js';
import { RefsReader, saveFile, saveZip } from './downloads.js';
import { buildRefsManifest, refChunks } from './refsmanifest.js';
import { declare, refusedTypes, uncheckableExt, describeType } from './filepolicy.js';
import { passkeyPrfOnly } from './passkeys.js';
import { createReverseKey, sealReversePriv, openReversePriv, linkHash, passwordGate, sealNote, fragmentOf, openUpload, newReverseId } from './reversekeys.js';

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
  constructor(message = 'Unlock your Drive to continue.', reason = 'locked', credentialIds = [], { ownerRecovery = false, received = 0 } = {}) {
    super(message);
    this.name = 'DriveLocked';
    this.reason = reason;
    this.credentialIds = credentialIds;
    /** Received files (reverse shares) waiting for the Drive to be unlocked. */
    this.received = received;
    /**
     * The owner's Drive, and nothing the owner can sign in with opens it (no
     * passkey or recovery-code wrap; no password wrap, or only a stale one —
     * e.g. after AUTHN recovery): the page offers the recovery kit, and
     * starting over without one.
     */
    this.ownerRecovery = ownerRecovery;
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
/**
 * Folder levels a received file's path may create below its link's folder
 * (never past MAX_DEPTH in all): deeper folders are flattened — the file goes
 * into the deepest folder allowed. And new folders one take-in may create:
 * past that, files go into the deepest of their folders that exists.
 */
export const RECEIVED_MAX_DEPTH = 8;
export const RECEIVED_MAX_NEW_FOLDERS = 200;
/** Pages of received files one take-in reads at most (500 each). */
const RECEIVED_MAX_PAGES = 40;
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

const NO_SIGNER = 'Your escrow signing key cannot be opened, so the escrow key cannot be signed: restore it from your owner recovery kit (Admin → Import / export), or replace the escrow key.';

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

const NOT_READY = 'The Drive is not ready yet: the administrator must sign in once. Try again later.';
const OWNER_LOST = 'Your Drive has no key you can open with your account now: restore it from your owner recovery kit, or start over.';

/**
 * Nothing the owner can sign in with opens the owner's Drive: no passkey or
 * recovery-code wrap, and no password wrap or only a stale one (the password
 * changed, e.g. by AUTHN recovery, and the wrap opens only with the old one).
 * The server applies the same rule to starting over.
 */
const ownerCannotUnlock = (st) => !st.wraps.some((w) => w.kind === 'passkey' || w.kind === 'recovery' || (w.kind === 'pw' && !st.pwStale));

/**
 * A Drive key read from this tab's storage (`sessionStorage`), used only once
 * it is proven to be this Drive's key against what the server holds: its key
 * check value must be the Drive's (`st.kcv`, stored with the first wraps). A
 * script on this origin can write the tab's storage (a share's CAPTCHA page
 * runs Cloudflare's script; SECURITY.md, "CAPTCHA on shares"), so a key that
 * does not match — or any key while the server has no check value — is
 * removed (`drop`) and not used: the Drive then asks to be unlocked the
 * normal way. → dk or null.
 */
async function provenKey(dk, st, drop) {
  if (!dk) return null;
  let ok;
  try { ok = typeof st.kcv === 'string' && st.kcv.length > 0 && (await keyCheckValue(dk)) === st.kcv; } catch { ok = false; }
  if (ok) return dk;
  drop();
  return null;
}

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
    // The owner's Drive with no key but an escrow key that some DK sealed: a
    // new DK would lose it. The recovery kit (or starting over) instead.
    if (u.role === 'owner' && !noOwnerKeys(st)) throw new DriveLocked(OWNER_LOST, 'locked', [], { ownerRecovery: true });
    throw new DriveLocked('Set up your Drive with your password.', 'setup');
  }
  const dk = await provenKey(loadSessionKey(u.id), st, clearSessionKey);
  if (!dk) throw new DriveLocked(undefined, 'locked', passkeyRefs(st), { ownerRecovery: u.role === 'owner' && ownerCannotUnlock(st), received: Number(st.received) || 0 });
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
    if (u.role === 'owner' && !noOwnerKeys(st)) throw new DriveLocked(OWNER_LOST, 'locked', [], { ownerRecovery: true });
    if (!creds.password && !(creds.prfOutput && creds.credentialId)) throw new DriveLocked('Set up your Drive with your password.', 'setup');
    dk = await setUp(u, st, creds);
    via = creds.password ? 'pw' : 'passkey';
    st = await loadState(); // what the set-up stored (the owner's first escrow key pair included)
  } else {
    if (creds.password) { dk = await unlockWithPassword(creds.password, st.driveSalt, st.wraps); via = 'pw'; }
    if (!dk && creds.prfOutput && creds.credentialId) { dk = await unlockWithPrf(creds.prfOutput, creds.credentialId, st.wraps); via = 'passkey'; }
    if (!dk && creds.code) { dk = await unlockWithRecovery(creds.code, [...st.wraps, ...(Array.isArray(spentWraps) ? spentWraps : [])]); via = 'recovery'; }
    if (!dk) throw new DriveLocked('That does not unlock your Drive.', 'wrong', [], { ownerRecovery: u.role === 'owner' && ownerCannotUnlock(st) });
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

/**
 * The pin for the server's current escrow key: its kid, the signing key's when
 * that key signed it, and the latest owner reset's epoch.
 */
async function pinFor(st) {
  const escrow = await escrowKeyId(st.escrowPub);
  const signed = st.escrowSignPub && st.escrowSig && await escrowKeyEndorsed(st.escrowSignPub, st.escrowPub, st.escrowSig);
  return { escrow, sign: signed ? await signingKeyId(st.escrowSignPub) : null, epoch: resetEpoch(st) };
}

const resetOf = (st) => (st.ownerReset && typeof st.ownerReset === 'object' && Number.isSafeInteger(st.ownerReset.epoch) && st.ownerReset.epoch > 0 ? st.ownerReset : null);
const resetEpoch = (st) => (resetOf(st) ? resetOf(st).epoch : 0);

/**
 * The one case where a user's browser accepts an escrow key its pinned
 * signing key did not sign (the maintainer's accepted exception, docs/DRIVE.md
 * §3.2): the server reports that the owner started over without a kit. Every
 * rule of that exception is here, and nowhere else:
 * - an owner reset exactly one epoch after the one pinned;
 * - whose new signing key is the server's signing key and signed the escrow key.
 * Every such reset applies, however soon after the last one (the maintainer's
 * rule: automatic, every time); each epoch applies once, since its epoch is
 * then pinned.
 * → { epoch, pin } (the pin to seal: the new key, the reset's signing key and
 * epoch), or null: the usual notice and "Trust the new key".
 * Nothing the browser holds ties such a reset to a real start over: anyone
 * able to change the server's responses can report one, at any time
 * (SECURITY.md).
 */
async function resetApplies(st, pinned) {
  const r = resetOf(st);
  if (!r || !pinned || r.epoch !== (pinned.epoch ?? 0) + 1) return null;
  if (!st.escrowSignPub || !sameEscrowKey(r.signPub, st.escrowSignPub)) return null;
  if (!st.escrowSig || !(await escrowKeyEndorsed(r.signPub, st.escrowPub, st.escrowSig))) return null;
  return { epoch: r.epoch, pin: { escrow: await escrowKeyId(st.escrowPub), sign: await signingKeyId(r.signPub), epoch: r.epoch } };
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
  const body = { first: true, set, remove: [] };
  let pwWrap = null;
  if (creds.password) {
    const { driveSalt, wrap } = await wrapPassword(dk, creds.password);
    body.driveSalt = driveSalt;
    set.push(wrap);
    pwWrap = wrap;
  }
  if (creds.prfOutput && creds.credentialId) set.push(await wrapPrf(dk, creds.prfOutput, creds.credentialId));
  if (u.role === 'owner') {
    if (noOwnerKeys(st)) Object.assign(body, await newOwnerKeys(dk));
  } else {
    set.push(await wrapEscrow(dk, st.escrowPub));
    body.escrowPin = await sealEscrowPin(dk, await pinFor(st));
  }
  body.kcv = await keyCheckValue(dk);
  try {
    await api.setKeys(body);
  } catch (e) {
    // Another tab (or the owner, for a new account) set this Drive up first: the stored wraps decide.
    if (!(e instanceof ApiError && e.code === 'drive_exists')) throw e;
  }
  // Two tabs may set up at the same moment: the stored wraps decide.
  const after = await loadState();
  const mine = (w) => after.wraps.some((x) => x.kind === w.kind && x.ref === w.ref && x.data === w.data);
  if (set.filter((w) => w.kind !== 'escrow').every(mine)) return dk;
  const other = (pwWrap && await unlockWithPassword(creds.password, after.driveSalt, after.wraps))
    || (creds.prfOutput && creds.credentialId && await unlockWithPrf(creds.prfOutput, creds.credentialId, after.wraps));
  if (other) return other;
  throw new DriveLocked('That does not unlock your Drive.', 'wrong');
}

/**
 * No escrow key or signing key anywhere yet: only then are they created
 * without the owner's say (the first set-up). Every later new pair or signing
 * key is a rotation the owner confirms (rotateEscrowKey).
 */
const noOwnerKeys = (st) => !st.escrowPub && typeof st.escrowPriv !== 'string' && !st.escrowSignPub && typeof st.escrowSignPriv !== 'string';

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
  const kept = await provenKey(loadImpersonationKey(u.id), st, clearImpersonationKey);
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
async function upkeepKey(userId, st, { password, prfOutput, credentialId, impersonating = false } = {}) {
  if (impersonating) {
    const kept = await provenKey(loadImpersonationKey(userId), st, clearImpersonationKey);
    if (kept) return kept;
    try {
      return (await openAsOwner({ id: userId, role: 'user', impersonating: true }, st)).dk;
    } catch {
      return null;
    }
  }
  let dk = await provenKey(loadSessionKey(userId), st, clearSessionKey);
  if (!dk && password) dk = await unlockWithPassword(password, st.driveSalt, st.wraps);
  // A step-up with a passkey that gave a PRF output (the Drive's salt) opens it too.
  if (!dk && prfOutput && credentialId) dk = await unlockWithPrf(prfOutput, credentialId, st.wraps);
  if (dk) saveSessionKey(dk, userId);
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
export async function updatePasswordWrap({ userId, newPassword, oldPassword, prfOutput, credentialId, impersonating = false }) {
  let st;
  try { st = await loadState(); } catch { return 'off'; }
  if (!st.wraps.length) return 'off';
  // The same DK, always: opened from the tab, the old password or the step-up's passkey (PRF).
  const dk = await upkeepKey(userId, st, { password: oldPassword, prfOutput, credentialId, impersonating });
  if (!dk) return 'locked';
  if (impersonating && st.wraps.some((w) => w.kind === 'pw')) return 'kept';
  const { driveSalt, wrap } = await wrapPassword(dk, newPassword);
  await api.setKeys({ driveSalt, set: [wrap], remove: [], kcv: await keyCheckValue(dk) });
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
    if (set.length) await api.setKeys({ set, kcv: await keyCheckValue(dk) });
  }, { password, impersonating });
}

/** A passkey with PRF output: add (or replace) its wrap. */
export function addPasskeyWrap(userId, prfOutput, credentialId, { password, impersonating = false } = {}) {
  return withKey(userId, async (dk) => {
    await api.setKeys({ set: [await wrapPrf(dk, prfOutput, credentialId)], remove: [], kcv: await keyCheckValue(dk) });
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
  // Only the escrow wrap comes back, with how many wraps the Drive has.
  const count = Number.isSafeInteger(r.wraps) ? r.wraps : 0;
  const wrap = r.wrap && r.wrap.kind === 'escrow' ? r.wrap : null;
  // No Drive yet: the owner, who knows the new password, sets it up now.
  if (!wrap && !count) return ownerSetsUpUserDrive({ ownerId, userId, password: newPassword });
  if (!wrap) return 'no_wrap';
  const priv = await escrowKeyFor(ownerDk, wrap, current, st.escrowPrivOld);
  const dk = priv ? await unlockWithEscrow(priv, wrap) : null;
  if (!dk) return 'failed';
  // The same DK: only its password wrap is new (the server checks the key check value).
  const { driveSalt, wrap: pw } = await wrapPassword(dk, newPassword);
  await api.setUserKeys(userId, { driveSalt, set: [pw], kcv: await keyCheckValue(dk) });
  return 'ok';
}

/**
 * The owner sets up the Drive of a user who has none yet (an account just
 * created, or reset before its first sign-in), knowing the password the
 * owner set (docs/DRIVE.md §3): a new DK for the user, a `pw` wrap for that
 * password, the `escrow` wrap for the current escrow key and the user's pin —
 * only after the owner's own escrow key checks out (the private key opens and
 * is the server's escrowPub, and the signing key signed it). → 'created' |
 * 'locked' (the owner's Drive is locked here) | 'no_escrow' | 'mismatch' |
 * 'exists' (the user has a Drive) | 'disabled' (their role has no Drive).
 * The account never depends on it: without it, the user's first sign-in sets
 * the Drive up.
 */
export async function ownerSetsUpUserDrive({ ownerId, userId, password }) {
  const ownerDk = loadSessionKey(ownerId);
  if (!ownerDk) return 'locked';
  const st = await loadState().catch(() => null);
  if (!st || typeof st.escrowPriv !== 'string' || !st.escrowPub) return 'no_escrow';
  let pair;
  try { pair = await openEscrowKeyPair(ownerDk, st.escrowPriv); } catch { return 'no_escrow'; }
  if (!sameEscrowKey(pair.publicJwk, st.escrowPub)) return 'mismatch';
  // As the owner's own unlock: the signing key opens, is the server's, and signed the escrow key.
  if (st.escrowSignPub || typeof st.escrowSignPriv === 'string') {
    const sign = typeof st.escrowSignPriv === 'string' ? await openSigningKey(ownerDk, st.escrowSignPriv).catch(() => null) : null;
    if (!sign || !st.escrowSignPub || !sameEscrowKey(sign.publicJwk, st.escrowSignPub) || !(await escrowKeyEndorsed(st.escrowSignPub, st.escrowPub, st.escrowSig))) return 'mismatch';
  }
  const dk = createDriveKey();
  try {
    const { driveSalt, wrap } = await wrapPassword(dk, password);
    await api.setUserKeys(userId, {
      first: true, driveSalt, set: [wrap, await wrapEscrow(dk, st.escrowPub)], escrowPin: await sealEscrowPin(dk, await pinFor(st)), kcv: await keyCheckValue(dk),
    });
    return 'created';
  } catch (e) {
    if (e instanceof ApiError && e.code === 'drive_exists') return 'exists';
    if (e instanceof ApiError && e.code === 'drive_disabled') return 'disabled';
    if (e instanceof ApiError && e.code === 'escrow_not_ready') return 'no_escrow';
    throw e;
  } finally {
    dk.fill(0); // the owner's browser keeps nothing of the user's DK
  }
}

// ── the owner recovery kit (docs/DRIVE.md §3), for the export screen ──────
//
// A file the owner downloads and keeps offline: the owner's DK and a
// snapshot of the escrow keys (the current one, the signing key, every
// earlier one still kept), sealed with a passphrase (drivekit.js, kind 'owner'). It is made,
// opened and checked only here; nothing of it reaches the server, which only
// records that a kit was downloaded, used or checked (admin audit).

/** A kid's short fingerprint: its first 8 characters, in two groups. */
export const kidFingerprint = (kid) => (typeof kid === 'string' && kid.length >= 8 ? `${kid.slice(0, 4)}-${kid.slice(4, 8)}` : '—');

async function ownerOnly(user) {
  const u = await whoAmI(user);
  if (u.role !== 'owner') throw new ApiError('Only the administrator has this recovery kit.', 403, 'owner_only');
  if (u.impersonating) throw new ApiError('The recovery kit is the owner’s own: return to your account first.', 403, 'impersonating');
  return u;
}

/**
 * The kit status from the owner's Drive state → { state: 'fresh' | 'stale'
 * (the escrow key was replaced since the latest kit) | 'none' (no kit yet) |
 * 'no_escrow', version, kid, fingerprint, created, kit: { version, kid, at }
 * | null } (times in seconds; `version` null when not recorded).
 */
export function kitStatusOf(st) {
  const v = st && st.escrowVersion && typeof st.escrowVersion === 'object' ? st.escrowVersion : null;
  const kit = st && st.kit && typeof st.kit === 'object' ? st.kit : null;
  if (!v || typeof v.kid !== 'string') return { state: 'no_escrow', version: null, kid: null, fingerprint: '—', created: null, kit };
  return {
    state: kit && kit.kid === v.kid ? 'fresh' : kit ? 'stale' : 'none',
    version: Number.isSafeInteger(v.version) ? v.version : null, kid: v.kid, fingerprint: kidFingerprint(v.kid), created: v.created ?? null, kit,
  };
}

/** The owner's kit status (a fresh read of the Drive state). */
export async function ownerKitStatus({ user } = {}) {
  await ownerOnly(user);
  return kitStatusOf(await loadState());
}

/** A sealed private key of the owner's Drive opened with `dk` → { privateKey, publicJwk, kid, pkcs8 }, or null. */
async function serverKey(dk, kind, data) {
  if (typeof data !== 'string') return null;
  try {
    const pkcs8 = await openPrivateKeyBytes(dk, kind, data);
    return { ...(await privateKeyFromBytes(kind, pkcs8)), pkcs8 };
  } catch {
    return null;
  }
}

const keyEntry = (k) => ({ kid: k.kid, pub: k.publicJwk, priv: b64urlFromBytes(k.pkcs8) });

/**
 * Build a kit with the owner's DK from this tab → { text, version, kit,
 * unreadable } (`text`: the file; `kit`: what the server recorded;
 * `unreadable`: fingerprints of earlier keys that did not open, left out).
 * The server records the download (with the escrow key's version) only
 * after the owner's password or a passkey (`step`); the file is given out
 * only then. Each call makes a new file with the whole current snapshot.
 */
export async function buildOwnerKit({ user, passphrase = '', step } = {}) {
  const u = await ownerOnly(user);
  const dk = loadSessionKey(u.id);
  if (!dk) throw new DriveLocked('Unlock your own Drive in this tab first (Drive), then download the kit.', 'owner_locked');
  const st = await loadState();
  if (!st.escrowPub || typeof st.escrowPriv !== 'string') throw new Error('Your Drive holds no escrow key yet: open your Drive once, then download the kit.');
  const cur = await serverKey(dk, 'escrow', st.escrowPriv);
  if (!cur) throw new Error('Your escrow private key does not open with the Drive key in this tab: fix it on the Drive page (or restore from a kit) first.');
  if (!sameEscrowKey(cur.publicJwk, st.escrowPub)) throw new Error('The escrow public key on the server is not the one your escrow private key belongs to: review it on the Drive page first.');
  let sign = null;
  if (st.escrowSignPub || typeof st.escrowSignPriv === 'string') {
    const k = await serverKey(dk, 'sign', st.escrowSignPriv);
    if (!k || !st.escrowSignPub || !sameEscrowKey(k.publicJwk, st.escrowSignPub)) throw new Error('Your escrow signing key does not open, or is not the server’s: review it on the Drive page first.');
    sign = keyEntry(k);
  }
  const old = [];
  const unreadable = [];
  for (const [kid, data] of Object.entries(st.escrowPrivOld && typeof st.escrowPrivOld === 'object' ? st.escrowPrivOld : {})) {
    if (kid === cur.kid) continue;
    const k = await serverKey(dk, 'escrow', data);
    if (k && k.kid === kid) old.push(keyEntry(k)); else unreadable.push(kidFingerprint(kid));
  }
  const v = st.escrowVersion || {};
  const payload = {
    v: 1, ownerId: u.id, made: Math.floor(Date.now() / 1000),
    version: Number.isSafeInteger(v.version) ? v.version : null, created: v.created ?? null, kid: cur.kid,
    dk: b64urlFromBytes(dk), escrow: keyEntry(cur), sign, old,
  };
  const text = await sealDriveKit('owner', payload, { accountId: u.id, origin: location.origin, passphrase: String(passphrase ?? '') });
  const r = await api.kit({ event: 'exported', ...(step || {}) });
  return { text, version: payload.version, kit: r.kit ?? null, unreadable };
}

/**
 * Open a kit file's text for `u` → { dk, keys: Map(kid → escrow key), sign,
 * version, created, currentKid, made }. Every key's public key and kid are
 * derived from its private key here, never taken from the file. Throws
 * DriveKitError ('format' | 'kind' | 'owner' | 'auth' | 'payload').
 */
async function readKit(text, passphrase, u) {
  const payload = await openDriveKit(parseDriveKit(text), { kind: kitKindFor(u.role), accountId: u.id, origin: location.origin, passphrase: String(passphrase ?? '') });
  let dk;
  try { dk = bytesFromB64url(payload.dk); } catch { dk = null; }
  if (!dk || dk.length !== 32 || payload.ownerId !== u.id) throw new DriveKitError('The kit opened, but its content is not valid.', 'payload');
  const load = async (kind, e) => {
    if (!e || typeof e.priv !== 'string') return null;
    try {
      const pkcs8 = bytesFromB64url(e.priv);
      return { ...(await privateKeyFromBytes(kind, pkcs8)), pkcs8 };
    } catch {
      return null;
    }
  };
  const keys = new Map();
  const current = await load('escrow', payload.escrow);
  for (const k of [current, ...await Promise.all((Array.isArray(payload.old) ? payload.old : []).slice(0, 64).map((e) => load('escrow', e)))]) if (k) keys.set(k.kid, k);
  return {
    dk, keys, sign: await load('sign', payload.sign), currentKid: current ? current.kid : null,
    version: Number.isSafeInteger(payload.version) ? payload.version : null, created: Number.isSafeInteger(payload.created) ? payload.created : null,
    made: Number.isSafeInteger(payload.made) ? payload.made : null,
  };
}

/** Overwrite a kit's key bytes once they are no longer needed (best effort). */
function forget(kit, keepDk = false) {
  if (!kit) return;
  if (!keepDk && kit.dk) kit.dk.fill(0);
  for (const k of kit.keys.values()) k.pkcs8.fill(0);
  if (kit.sign) kit.sign.pkcs8.fill(0);
}

/**
 * Restore the owner's Drive from a kit file's text (after AUTHN recovery, or
 * when the owner's Drive lost an escrow key). `password` is the account's
 * password now and `step` its confirmation ({ current }): the server checks
 * it first (and records `drive.kit_used`), then the kit's DK is confirmed —
 * the server's sealed escrow key must open with it and be the server's
 * escrowPub, or, when that copy is missing or does not open, the kit's
 * snapshot must hold the server's current escrow key — and any escrow key the
 * server's copy of which is missing or wrong is re-sealed from the snapshot
 * and put back (only for the server's own public keys and kids in use). Then
 * DK goes into the tab's slot and a fresh `pw` wrap is written. Nothing new
 * is created: no escrow key, no signing key. → { client, restored, missing }.
 */
export async function restoreOwnerKit({ user, text, passphrase = '', password, step } = {}) {
  const u = await ownerOnly(user);
  if (typeof password !== 'string' || !password || !step) throw new Error('Enter your account password: the Drive’s new password key is made with it.');
  const kit = await readKit(text, passphrase, u);
  let done = false;
  try {
    const st = await loadState();
    if (!st.escrowPub) throw new DriveKitError('The server has no escrow public key, so this kit cannot be checked against it.', 'dk');
    const currentKid = await escrowKeyId(st.escrowPub);
    const cur = await serverKey(kit.dk, 'escrow', st.escrowPriv);
    const curOk = !!cur && sameEscrowKey(cur.publicJwk, st.escrowPub);
    const snapCur = kit.keys.get(currentKid) || null;
    if (!curOk && !snapCur) {
      // Not this Drive's DK: perhaps the Drive's before the owner started over (an archive).
      const arch = cur ? null : await findArchive(kit, st);
      if (arch) {
        const r = await restoreArchive(u, kit, st, arch, password, step);
        done = true;
        return r;
      }
      throw new DriveKitError(cur
        ? 'The escrow public key on the server is not the one your Drive and this kit hold: it may have been replaced. Nothing was changed.'
        : 'This kit’s Drive key does not open your escrow key, and its snapshot does not hold the server’s current escrow key: it is not a kit of this Drive. Nothing was changed.', 'dk');
    }
    const body = {};
    const missing = [];
    if (!curOk) body.escrowPriv = { pub: snapCur.publicJwk, data: await sealPrivateKeyBytes(kit.dk, 'escrow', snapCur.pkcs8) };
    if (st.escrowSignPub) {
      const sk = await serverKey(kit.dk, 'sign', st.escrowSignPriv);
      if (!sk || !sameEscrowKey(sk.publicJwk, st.escrowSignPub)) {
        if (kit.sign && sameEscrowKey(kit.sign.publicJwk, st.escrowSignPub)) body.escrowSignPriv = { pub: kit.sign.publicJwk, data: await sealPrivateKeyBytes(kit.dk, 'sign', kit.sign.pkcs8) };
        else missing.push('signing key');
      }
    }
    const old = {};
    const kept = st.escrowPrivOld && typeof st.escrowPrivOld === 'object' ? st.escrowPrivOld : {};
    for (const kid of (Array.isArray(st.escrowKids) ? st.escrowKids : []).filter((x) => x !== currentKid)) {
      const k = await serverKey(kit.dk, 'escrow', kept[kid]);
      if (k && k.kid === kid) continue;
      const s = kit.keys.get(kid);
      if (s) old[kid] = { pub: s.publicJwk, data: await sealPrivateKeyBytes(kit.dk, 'escrow', s.pkcs8) };
      else missing.push(`earlier escrow key ${kidFingerprint(kid)}`);
    }
    if (Object.keys(old).length) body.escrowPrivOld = old;
    // The password first (the new pw wrap is made with it), and the record.
    await api.kit({ event: 'used', ...(kit.version ? { version: kit.version } : {}), ...step });
    if (Object.keys(body).length) await api.kitKeys({ ...body, ...step });
    saveSessionKey(kit.dk, u.id);
    const { driveSalt, wrap } = await wrapPassword(kit.dk, password);
    await api.setKeys({ driveSalt, set: [wrap], remove: [], kcv: await keyCheckValue(kit.dk), ...step });
    const client = await DriveClient.create(kit.dk, u);
    await client.maintain(await loadState()).catch(() => {});
    done = true;
    return {
      client, missing,
      restored: { escrow: !!body.escrowPriv, signing: !!body.escrowSignPriv, earlier: Object.keys(old).length },
    };
  } finally {
    forget(kit, done);
  }
}

/** The archive (after starting over) whose sealed escrow key opens with the kit's DK → { gen, view }, or null. */
async function findArchive(kit, st) {
  for (const a of Array.isArray(st.archives) ? st.archives : []) {
    const view = await api.archive(a.gen);
    if (await serverKey(kit.dk, 'escrow', view.escrowPriv)) return { gen: a.gen, view };
  }
  return null;
}

/**
 * Restore archive `arch` (the owner's Drive before starting over, under the
 * kit's DK) into the Drive as it is now (under its own DK: this tab's, or
 * opened with `password`): every item comes back, its name, metadata and file
 * key re-sealed under the Drive's DK (content is untouched: each file has its
 * own key); a top-level name the Drive already has gets " (2)"… (as uploads
 * do); the archive's escrow keys that users' wraps are still made for join
 * the owner's earlier keys, so those Drives open again. The archive's reverse
 * links (paused when the owner started over) get their private keys re-sealed
 * under the Drive's DK and resume; the items they received come back as they
 * arrived (sealed to the link's key) and are taken in like any received file.
 * The kit's DK is not kept.
 */
async function restoreArchive(u, kit, st, arch, password, step) {
  const dk = (await provenKey(loadSessionKey(u.id), st, clearSessionKey)) || await unlockWithPassword(password, st.driveSalt, st.wraps);
  if (!dk) throw new DriveLocked('This kit is for your Drive before you started over. Unlock your Drive (with your password) first, then restore.', 'locked');
  await api.kit({ event: 'used', ...(kit.version ? { version: kit.version } : {}), ...step });
  const all = [];
  for (let v = arch.view; ; v = await api.archive(arch.gen, v.next)) {
    all.push(...(Array.isArray(v.nodes) ? v.nodes : []));
    if (!v.next) break;
  }
  const byId = new Map(all.map((n) => [n.id, n]));
  const depth = (n) => { let d = 0; for (let x = n; x && x.parent !== ROOT && byId.has(x.parent) && d < 70; x = byId.get(x.parent)) d++; return d; };
  all.sort((a, b) => depth(a) - depth(b));
  const from = await deriveSubkeys(kit.dk);
  const to = await deriveSubkeys(dk);
  const client = await DriveClient.create(dk, u);
  const taken = (await client.names(ROOT)).names;
  const reseal = async (key, field, n, v, name) => {
    try {
      const bytes = await openField(key.from, field, n.id, sealed(v));
      return sealField(key.to, field, n.id, name ? name(fromUtf8(bytes)) : bytes);
    } catch {
      return v; // does not open: kept as it was (unreadable, as before)
    }
  };
  const names = { from: from.names, to: to.names };
  const files = { from: from.files, to: to.files };
  const out = [];
  for (const n of all) {
    // A received item: sealed to its link's key, not the DK — it comes back as it is.
    if (n.rs) { out.push({ id: n.id }); continue; }
    const top = n.parent === ROOT;
    const x = { id: n.id, name: await reseal(names, 'name', n, n.name, (t) => (top ? uniqueName(taken, cleanName(t)) : t)) };
    if (n.meta) x.meta = await reseal(names, 'meta', n, n.meta);
    if (n.fk) x.fk = await reseal(files, 'fk', n, n.fk);
    out.push(x);
  }
  for (let i = 0; i < out.length; i += 200) await api.archiveNodes(arch.gen, { nodes: out.slice(i, i + 200), ...step });
  // The archive's escrow keys users are still on: back among the owner's earlier keys.
  const pool = new Map(kit.keys);
  for (const data of [arch.view.escrowPriv, ...Object.values(arch.view.escrowPrivOld || {})]) {
    const k = await serverKey(kit.dk, 'escrow', data);
    if (k && !pool.has(k.kid)) pool.set(k.kid, k);
  }
  const currentKid = st.escrowPub ? await escrowKeyId(st.escrowPub) : null;
  const old = {};
  const missing = [];
  for (const kid of (Array.isArray(st.escrowKids) ? st.escrowKids : []).filter((x) => x !== currentKid)) {
    const have = await serverKey(dk, 'escrow', st.escrowPrivOld && st.escrowPrivOld[kid]);
    if (have && have.kid === kid) continue;
    const k = pool.get(kid);
    if (k) old[kid] = { pub: k.publicJwk, data: await sealPrivateKeyBytes(dk, 'escrow', k.pkcs8) }; else missing.push(`earlier escrow key ${kidFingerprint(kid)}`);
  }
  for (const k of pool.values()) if (!kit.keys.has(k.kid)) k.pkcs8.fill(0);
  // The archive's reverse links: each private key from the kit's DK to the Drive's DK.
  const links = {};
  for (const l of Array.isArray(arch.view.reverse) ? arch.view.reverse : []) {
    let pkcs8 = null;
    try {
      pkcs8 = await openField(files.from, 'reversePriv', l.id, sealed(l.priv));
      links[l.id] = await sealField(files.to, 'reversePriv', l.id, pkcs8);
    } catch {
      links[l.id] = l.priv; // does not open: kept as it was (the Drive shows no link for it)
    } finally {
      if (pkcs8) pkcs8.fill(0);
    }
  }
  await api.archiveFinish(arch.gen, { ...(Object.keys(old).length ? { escrowPrivOld: old } : {}), ...(Object.keys(links).length ? { reverse: links } : {}), ...step });
  saveSessionKey(dk, u.id);
  await client.maintain(await loadState()).catch(() => {});
  return { client, missing, restored: { escrow: false, signing: false, earlier: Object.keys(old).length, archive: arch.gen, items: all.length } };
}

/**
 * The owner deletes archive `gen` (the Drive before starting over): with the
 * typed username (`confirm`) and the step-up. No kit can restore it after.
 */
export async function deleteOwnerArchive({ user, gen, confirm, step } = {}) {
  await ownerOnly(user);
  await api.archiveDelete(gen, { confirm, ...(step || {}) });
}

/**
 * The owner starts over without a recovery kit (docs/DRIVE.md §3): only when
 * nothing the owner can sign in with opens the owner's Drive, with the typed
 * username (`confirm`) and the step-up of the account's password (`password`,
 * `step`). A new DK, a new escrow pair and signing key and a `pw` wrap are
 * made here; the server empties the owner's Drive (items, files, wraps, sealed
 * keys; its shares end) and stores them. No user's Drive changes: each user's
 * browser sees an escrow key its pinned signing key did not sign and asks the
 * user ("Trust the new key") before re-wrapping. → a DriveClient.
 */
export async function startOverOwnerDrive({ user, confirm, password, step } = {}) {
  const u = await ownerOnly(user);
  if (typeof password !== 'string' || !password || !step) throw new Error('Enter your account password.');
  const st = await loadState();
  if (!ownerCannotUnlock(st) || (st.wraps.some((w) => w.kind === 'pw') && await unlockWithPassword(password, st.driveSalt, st.wraps))) {
    throw new DriveLocked('Your Drive can still be unlocked: unlock it instead of starting over.', 'unlockable');
  }
  const dk = createDriveKey();
  const { driveSalt, wrap } = await wrapPassword(dk, password);
  const r = await api.startOver({ confirm, driveSalt, set: [wrap], ...(await newOwnerKeys(dk)), kcv: await keyCheckValue(dk), ...step });
  saveSessionKey(dk, u.id);
  const client = await DriveClient.create(dk, u);
  await client.maintain(await loadState()).catch(() => {});
  return { client, escrowVersion: r.escrowVersion ?? null };
}

/**
 * The read-only check of a kit file's text (docs/DRIVE.md §3, "Verify kit"):
 * nothing is written except the admin audit's `drive.kit_verified` (and the
 * `drive.escrow_used` of each user's escrow wrap opened as a live proof).
 * → { verdict: 'complete' | 'incomplete' | 'failed', checks: [{ id, status:
 * 'pass' | 'warn' | 'fail' | 'skip', label, detail }], fixes: [text],
 * version, logged }.
 */
export async function verifyOwnerKit({ user, text, passphrase = '' } = {}) {
  const u = await ownerOnly(user);
  const checks = [];
  const issues = new Set();
  const add = (id, status, label, detail, issue = id) => { checks.push({ id, status, label, detail }); if (status === 'fail' || status === 'warn') issues.add(issue); };
  let kit = null;
  const finish = async (verdict, fixes) => {
    forget(kit);
    let logged = true;
    try { await api.kit({ event: 'verified', verdict, issues: [...issues], ...(kit && kit.version ? { version: kit.version } : {}) }); } catch { logged = false; }
    return { verdict, checks, fixes, version: kit ? kit.version : null, logged };
  };
  const FRESH = 'Download a fresh kit (Download kit, above) and store it offline; then verify the new file.';
  // 1. The format, and that it is this owner's kit (bound to this server).
  let env;
  try { env = parseDriveKit(text); } catch (e) { add('format', 'fail', 'Format and owner', e.message); return finish('failed', ['Choose the kit file you saved (secbin-owner-kit-….json).']); }
  if (env.kind !== 'owner') { add('format', 'fail', 'Format and owner', 'This is a user’s Drive recovery kit, not an owner recovery kit.', 'format'); return finish('failed', ['Choose an owner recovery kit.']); }
  if (env.accountId !== u.id) { add('format', 'fail', 'Format and owner', 'This kit belongs to another owner account.', 'owner'); return finish('failed', ['Choose a kit made by this owner account.']); }
  add('format', 'pass', 'Format and owner', `An owner recovery kit for your account, for ${location.origin}.`);
  // 2. It decrypts and its authentication tag is valid (the passphrase, this owner, this origin).
  try {
    kit = await readKit(text, passphrase, u);
  } catch (e) {
    add('auth', 'fail', 'Decrypts, authentication tag valid', e instanceof DriveKitError ? e.message : 'The kit could not be opened.');
    return finish('failed', ['Check the passphrase. A kit opens only on the server it was made on, and a changed file never opens.']);
  }
  add('auth', 'pass', 'Decrypts, authentication tag valid', 'The passphrase is right and the file is unchanged.');
  const st = await loadState();
  const cv = st.escrowVersion && Number.isSafeInteger(st.escrowVersion.version) ? st.escrowVersion.version : null;
  const currentKid = st.escrowPub ? await escrowKeyId(st.escrowPub) : null;
  // 3. Its DK is the owner's DK: it opens the server's sealed escrow key, which is escrowPub.
  const cur = await serverKey(kit.dk, 'escrow', st.escrowPriv);
  const dkOk = !!cur && !!st.escrowPub && sameEscrowKey(cur.publicJwk, st.escrowPub);
  if (dkOk) add('dk', 'pass', 'The Drive key is your Drive’s', 'It opens the server’s sealed escrow key, whose public key is the server’s escrow public key.');
  else if (typeof st.escrowPriv !== 'string') add('dk', 'warn', 'The Drive key is your Drive’s', 'Not confirmed: the server holds no sealed escrow key to open (Restore puts it back from this kit).');
  else add('dk', 'fail', 'The Drive key is your Drive’s', cur ? 'It opens the server’s sealed escrow key, but that key is not the server’s escrow public key.' : 'It does not open the server’s sealed escrow key: this kit cannot restore your Drive.');
  // What the Drive key still reaches on the server (for keys the snapshot lacks).
  const viaDk = async (kid) => {
    if (kid === currentKid) return dkOk ? cur : null;
    const k = await serverKey(kit.dk, 'escrow', st.escrowPrivOld && st.escrowPrivOld[kid]);
    return k && k.kid === kid ? k : null;
  };
  // A snapshot that lacks something the Drive key still reaches is stale (a warning), else it fails.
  const addStale = (id, label, detail, issue = id) => add(id, dkOk ? 'warn' : 'fail', label, dkOk ? `${detail} It still works through the Drive key.` : detail, issue);
  // 4. The snapshot's current escrow key is the server's.
  const snapCur = currentKid ? kit.keys.get(currentKid) : null;
  if (!currentKid) add('current', 'fail', 'Current escrow key in the snapshot', 'The server has no escrow public key.');
  else if (snapCur && sameEscrowKey(snapCur.publicJwk, st.escrowPub)) add('current', 'pass', 'Current escrow key in the snapshot', `Key ${kidFingerprint(currentKid)}${cv ? ` (version ${cv})` : ''}, the server’s escrow public key.`);
  else addStale('current', 'Current escrow key in the snapshot', `The snapshot holds key ${kidFingerprint(kit.currentKid)}, not the server’s current key ${kidFingerprint(currentKid)}${cv ? ` (version ${cv})` : ''}.`);
  // 5. The signing key is the server's, and its signature over escrowPub verifies.
  if (!st.escrowSignPub) add('signing', 'skip', 'Signing key and signature', 'The server has no escrow signing key.');
  else if (!kit.sign || !sameEscrowKey(kit.sign.publicJwk, st.escrowSignPub)) {
    const sk = await serverKey(kit.dk, 'sign', st.escrowSignPriv);
    if (sk && sameEscrowKey(sk.publicJwk, st.escrowSignPub)) addStale('signing', 'Signing key and signature', 'The snapshot does not hold the server’s signing key.');
    else add('signing', 'fail', 'Signing key and signature', 'The snapshot does not hold the server’s signing key.');
  } else if (!st.escrowPub || !(await escrowKeyEndorsed(st.escrowSignPub, st.escrowPub, st.escrowSig))) add('signing', 'fail', 'Signing key and signature', 'The snapshot’s signing key is the server’s, but the signature over the escrow public key does not verify.');
  else add('signing', 'pass', 'Signing key and signature', `Key ${kidFingerprint(kit.sign.kid)}: the server’s, and its signature over the escrow public key verifies.`);
  // 6. Every earlier key still in use is in the snapshot.
  const past = [...new Set([...(Array.isArray(st.escrowKids) ? st.escrowKids : []), ...Object.keys(st.escrowPrivOld && typeof st.escrowPrivOld === 'object' ? st.escrowPrivOld : {})])].filter((k) => k && k !== currentKid);
  const lacking = [];
  const lost = [];
  for (const kid of past) {
    if (kit.keys.has(kid)) continue;
    if (await viaDk(kid)) lacking.push(kidFingerprint(kid)); else lost.push(kidFingerprint(kid));
  }
  if (!past.length) add('past', 'pass', 'Earlier escrow keys still in use', 'None is in use: every user’s Drive is on the current key.');
  else if (!lacking.length && !lost.length) add('past', 'pass', 'Earlier escrow keys still in use', `All ${past.length} in the snapshot: ${past.map(kidFingerprint).join(', ')}.`);
  else if (lost.length) add('past', 'fail', 'Earlier escrow keys still in use', `Not in the snapshot: ${[...lost, ...lacking].join(', ')}.${lacking.length ? ` (${lacking.join(', ')} still work through the Drive key.)` : ''}`);
  else add('past', 'warn', 'Earlier escrow keys still in use', `Not in the snapshot: ${lacking.join(', ')}. They still work through the Drive key.`);
  // 7. The kit's version against the current one.
  if (currentKid && kit.currentKid === currentKid) add('version', 'pass', 'Kit version', `Current${cv ? ` (version ${cv})` : ''}.`);
  else if (dkOk) add('version', 'warn', 'Kit version', `Older version ${kit.version ?? '?'}${cv ? ` (the current one is ${cv})` : ''}: still works through the Drive key, but download a fresh kit for a complete snapshot.`);
  else add('version', 'fail', 'Kit version', `Older version ${kit.version ?? '?'}${cv ? ` (the current one is ${cv})` : ''}, and its Drive key does not open your escrow key.`);
  // 8. A live proof: one user's escrow wrap per kid in use opens (nothing is written; the DK found is discarded).
  let probes;
  try { probes = (await api.kitProbe()).probes || []; } catch { probes = null; }
  if (probes === null) add('proof', 'fail', 'Users’ escrow wraps open', 'The users’ escrow wraps could not be fetched.');
  else if (!probes.length) add('proof', 'skip', 'Users’ escrow wraps open', 'No user’s Drive has an escrow wrap yet.');
  else {
    const direct = [];
    const through = [];
    const failed = [];
    for (const { kid, wrap } of probes) {
      const s = kit.keys.get(kid);
      let opened = s ? await unlockWithEscrow(s.privateKey, wrap) : null;
      if (opened) { opened.fill(0); direct.push(kidFingerprint(kid)); continue; }
      const k = await viaDk(kid);
      opened = k ? await unlockWithEscrow(k.privateKey, wrap) : null;
      if (opened) { opened.fill(0); through.push(kidFingerprint(kid)); } else failed.push(kidFingerprint(kid));
    }
    if (failed.length) add('proof', 'fail', 'Users’ escrow wraps open', `Not opened: a Drive wrapped to ${failed.join(', ')}.`);
    else if (through.length) add('proof', 'warn', 'Users’ escrow wraps open', `Opened with the snapshot: ${direct.join(', ') || 'none'}; only through the Drive key: ${through.join(', ')}.`);
    else add('proof', 'pass', 'Users’ escrow wraps open', `One user’s Drive per key opened with the snapshot: ${direct.join(', ')}.`);
  }
  const bad = checks.filter((c) => c.status === 'fail' || c.status === 'warn');
  if (!bad.length) return finish('complete', []);
  const fixes = [FRESH];
  if (checks.some((c) => c.id === 'dk' && c.status === 'fail')) fixes.unshift('This kit’s Drive key does not open your escrow key: it cannot restore your Drive.');
  return finish('incomplete', fixes);
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
    /** The owner's recovery-kit status (kitStatusOf), after maintain(); null for users. */
    this.kit = null;
    /** The owner's archived Drives (after starting over): [{ gen, at, items, bytes }]. */
    this.archives = [];
  }

  /**
   * `dk` must be a key this page generated (a first set-up), unwrapped (a
   * password, recovery code, passkey or the owner escrow) or read from the
   * tab's storage and proven (provenKey): never a stored key taken as it is.
   */
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
      this.kit = kitStatusOf(st);
      this.archives = Array.isArray(st.archives) ? st.archives : [];
      await this.#checkOwnerKeys(st, body);
    } else if (st.escrowPub) {
      const current = wraps.find((w) => w.kind === 'escrow');
      const kid = await escrowKeyId(st.escrowPub);
      const wrapKid = current ? escrowWrapKeyId(current) : null;
      const pinned = st.escrowPin ? await openEscrowPin(this.dk, st.escrowPin) : null;
      const next = await pinFor(st);
      // Every user's Drive has, from its first set-up (setUp here, or
      // ownerSetsUpUserDrive), an escrow wrap and a pin, and the wrap is always
      // for the pinned escrow key (both change together). A pin that is
      // missing or does not open, no escrow wrap, or a wrap for another key is
      // tampering, never a first use (R5-M2): the notice, and no re-wrap.
      const intact = !!pinned && !!wrapKid && wrapKid === pinned.escrow;
      // Another escrow key is wrapped to only when the pinned signing key
      // signed it; else the user decides (notice).
      const ok = intact && (pinned.escrow === kid || (!!pinned.sign && pinned.sign === next.sign));
      const reset = intact && !ok ? await resetApplies(st, pinned) : null;
      if (reset) {
        // The owner started over: moved to the reset's key once, and the
        // reset's epoch pinned so the same reset never applies twice.
        body.set.push(await wrapEscrow(this.dk, st.escrowPub));
        body.escrowPin = await sealEscrowPin(this.dk, reset.pin);
        body.escrowReset = reset.epoch;
        this.notice = { kind: 'escrow_rotated', text: 'Your administrator rotated a security key; nothing for you to do.' };
      } else if (!intact) {
        this.notice = { kind: 'escrow_changed', kid, tampered: true, text: 'Your Drive’s record of the administrator’s escrow key is missing or does not match its escrow wrap, so your Drive was not re-keyed. The server’s data may have been altered.' };
      } else if (!ok) {
        this.notice = { kind: 'escrow_changed', kid, text: 'The administrator’s escrow key has changed since your Drive last used it, and the change is not signed by the key your Drive trusts, so your Drive was not re-keyed for it.' };
      } else {
        if (wrapKid !== kid) body.set.push(await wrapEscrow(this.dk, st.escrowPub));
        // A pinned signing key never changes, and none is adopted silently; the pinned reset epoch stays.
        const pin = { escrow: kid, sign: pinned.sign, epoch: pinned.epoch ?? 0 };
        if (pinned.escrow !== pin.escrow) body.escrowPin = await sealEscrowPin(this.dk, pin);
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
    // Every wrap or pin written comes with the key check value: proof that it is of this Drive's DK.
    if (body.set.length || body.escrowPin) body.kcv = await keyCheckValue(this.dk);
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
      if (!noOwnerKeys(st)) { this.#warn('escrow_missing'); return; }
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
   * it and pin it (with the signing key that signed it, if any). A Drive whose escrow wrap is
   * already for that key (the pin was missing) gets only the new pin: a
   * replacement of that wrap would need the step-up.
   */
  async acceptEscrowKey() {
    const st = await loadState();
    if (!st.escrowPub) return false;
    const kid = await escrowKeyId(st.escrowPub);
    const cur = (st.wraps || []).find((w) => w.kind === 'escrow');
    const set = cur && escrowWrapKeyId(cur) === kid ? [] : [await wrapEscrow(this.dk, st.escrowPub)];
    await api.setKeys({ set, escrowPin: await sealEscrowPin(this.dk, await pinFor(st)), kcv: await keyCheckValue(this.dk) });
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
    // A restore never makes a new key: without the owner's own signing key it
    // cannot sign (the recovery kit can put the signing key back; a new one
    // comes only with "Replace the escrow key").
    if (sign) Object.assign(body, { escrowSignPub: sign.publicJwk, escrowSig: await endorseEscrowKey(sign.privateKey, pair.publicJwk) });
    else if (st.escrowSignPub || typeof st.escrowSignPriv === 'string') throw new Error(NO_SIGNER);
    await api.setKeys(body);
    this.notice = null;
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
    this.kit = kitStatusOf(await loadState()); // the kit is stale now: the page says so
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
        if (m.renamed === true) renamed = true; // a received file whose name was cleaned when it was taken in
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
   * `captcha`: true / false (the role allows a choice), undefined (its default).
   */
  async share(nodeIds, { views = null, expire, password = '', deletable = false, label = '', limits = null, view = null, captcha } = {}) {
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
    if (typeof captcha === 'boolean') body.captcha = captcha;
    const r = await api.share(body);
    if (typeof r.id !== 'string' || typeof r.deletetoken !== 'string') throw malformed();
    return { url: `${location.origin}/p/${r.id}#${fragment}`, id: r.id, deletetoken: r.deletetoken, captcha: r.captcha === true };
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
   * `captcha`: uploaders pass the CAPTCHA first (true / false where the role
   * allows a choice; undefined: its default).
   */
  async createReverse(folderId, { label = '', note = '', password = '', expire = '7d', maxFiles = null, maxBytes = null, maxFileBytes = null, types = null, step = {}, captcha } = {}) {
    const id = newReverseId();
    const { pub, privateKey } = await createReverseKey();
    const body = {
      id, folder: folderId, priv: await sealReversePriv(this.dk, id, privateKey), lh: await linkHash(pub), expire,
      maxFiles, maxBytes, maxFileBytes, types,
    };
    if (note) body.note = await sealNote(pub, id, note);
    if (password) body.password = await passwordGate(password, pub);
    if (label) body.label = label;
    if (typeof captcha === 'boolean') body.captcha = captcha;
    Object.assign(body, step);
    const r = await api.createReverse(body);
    if (r.id !== id) throw malformed();
    return { url: reverseUrl(id, pub), id, expires: r.expires, captcha: r.captcha === true };
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
   * Drive format (the content is not touched) → { added, failed, renamed,
   * flattened, deferred, more }.
   * - Names are cleaned (files.js cleanName: direction overrides and
   *   invisible separators removed, NFC); a file whose name changed is marked
   *   `renamed` in its metadata, which the Drive shows.
   * - At most RECEIVED_MAX_DEPTH folder levels (and MAX_DEPTH in all) are
   *   created for a path, and RECEIVED_MAX_NEW_FOLDERS folders per take-in:
   *   past either, the file lands in the deepest folder allowed (`flattened`).
   * - An item that cannot be taken in (it does not open, its name is not
   *   usable, the Drive refuses its place) is recorded as failed on the
   *   server: it leaves the queue (the Drive lists it to delete or try again),
   *   so it never holds up the items behind it. A network or server error
   *   leaves it for the next time (`deferred`). The queue is read page by
   *   page (`next`), so failures never hide later items.
   */
  async receivePending({ onItem } = {}) {
    const keys = new Map(); // share id → private key, or null (does not open with this Drive's key)
    // As uploadTree: an existing folder of a name is reused, a clashing file name gets " (2)"….
    const folders = new Map(); // `${parent}\n${path}` → id
    const inside = new Map(); // folder id → { dirs: Map(name → id), names: Set }
    const depthOf = new Map(); // a link's folder → its depth in the tree
    let newFolders = 0;
    const contentOf = async (id) => {
      if (!inside.has(id)) inside.set(id, await this.names(id).catch(() => ({ dirs: new Map(), names: new Set() })));
      return inside.get(id);
    };
    // The folder for `dirPath` under `parent`, made where needed while the budget lasts; else the deepest one there is.
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
        if (newFolders >= RECEIVED_MAX_NEW_FOLDERS) return up;
        newFolders++;
        id = await this.mkdir(up, uniqueName(here.names, leaf));
        here.dirs.set(leaf, id);
        inside.set(id, { dirs: new Map(), names: new Set() });
      }
      folders.set(key, id);
      return id;
    };
    const levelsUnder = async (parent) => {
      if (!depthOf.has(parent)) {
        let d;
        try { const r = await api.node(parent); d = Array.isArray(r.path) ? r.path.filter((x) => x && x.id !== parent).length : 0; } catch { d = MAX_DEPTH; }
        depthOf.set(parent, d);
      }
      return Math.max(0, Math.min(RECEIVED_MAX_DEPTH, MAX_DEPTH - depthOf.get(parent)));
    };
    const failure = (reason) => Object.assign(new Error(reason), { receivedReason: reason });
    // A refusal by the Drive (full, folder full, too deep) fails the item; being signed out or losing the Drive stops the take-in.
    const refused = (e) => e instanceof ApiError && e.status >= 400 && e.status < 500 && e.status !== 401 && e.status !== 403;
    const out = { added: 0, failed: 0, renamed: 0, flattened: 0, deferred: 0, more: false };
    let after = null;
    for (let page = 0; page < RECEIVED_MAX_PAGES; page++) {
      const r = await api.received(after);
      const items = Array.isArray(r.items) ? r.items : [];
      for (const k of Array.isArray(r.keys) ? r.keys : []) {
        if (keys.has(k.id)) continue;
        try { keys.set(k.id, (await openReversePriv(this.dk, k.id, k.priv)).privateKey); } catch { keys.set(k.id, null); /* sealed under another key */ }
      }
      for (const it of items) {
        try {
          const priv = keys.get(it.rs);
          if (!priv) throw failure('unreadable');
          let got;
          try { got = await openUpload(priv, it.rs, it); } catch { throw failure('unreadable'); }
          // The uploader's sealed size must be the server's (the chunks follow from it): else it fails closed.
          if (got.size !== it.size) throw failure('unreadable');
          let path;
          try {
            path = checkPath(cleanName(got.path));
            path.split('/').forEach(checkName);
          } catch { throw failure('name'); }
          const renamed = path !== got.path;
          const segs = path.split('/');
          const leafName = segs.pop();
          const allowed = await levelsUnder(it.parent);
          const want = segs.slice(0, allowed).join('/');
          let parent;
          try { parent = await ensure(it.parent, want); } catch (e) {
            if (!(e instanceof ApiError)) throw failure('name'); // a folder name this Drive cannot store
            throw refused(e) ? failure('place') : e;
          }
          // Deeper than allowed, or out of new folders: in the deepest folder there is.
          const flattened = segs.length > allowed || (want !== '' && folders.get(`${it.parent}\n${want}`) !== parent);
          const type = normalizeMime(got.type) || OCTET;
          const { names: taken } = await contentOf(parent);
          const leaf = uniqueName(taken, leafName);
          const meta = { type, mtime: got.mtime, size: it.size, ...(renamed ? { renamed: true } : {}) };
          try {
            await api.acceptReceived(it.id, {
              parent,
              name: await sealField(this.keys.names, 'name', it.id, leaf),
              // The server's size is the one the chunks have: the metadata says the same.
              meta: await sealField(this.keys.names, 'meta', it.id, JSON.stringify(meta)),
              fk: await sealField(this.keys.files, 'fk', it.id, got.fk),
            });
          } catch (e) {
            taken.delete(leaf);
            throw refused(e) ? failure('place') : e;
          }
          out.added++;
          if (renamed) out.renamed++;
          if (flattened) out.flattened++;
          if (onItem) onItem({ id: it.id, path, name: leaf, parent, renamed, flattened });
        } catch (e) {
          if (!e || !e.receivedReason) {
            if (e instanceof ApiError && (e.status === 401 || e.status === 403)) throw e; // signed out, or no Drive: stop
            out.deferred++; // a network or server error: next time
            continue;
          }
          out.failed++;
          await api.receivedFailed(it.id, e.receivedReason).catch(() => {});
        }
      }
      out.more = !!r.more;
      after = typeof r.next === 'string' ? r.next : null;
      if (!out.more || !after) break;
    }
    return out;
  }

  /**
   * Received files that could not be taken in → { items: [{ id, rs, label,
   * size, created, failed, reason }], more, next, total } (`total`, the count
   * of all of them, on the first page only).
   */
  async failedReceived(after = null) {
    let total;
    if (!after) {
      const st = await api.state();
      total = Number.isSafeInteger(st.receivedFailed) ? st.receivedFailed : null;
      if (total === 0) return { items: [], more: false, next: null, total };
    }
    const r = await api.receivedFailedList(after);
    const items = Array.isArray(r.items) ? r.items : [];
    return { items, more: !!r.more, next: typeof r.next === 'string' ? r.next : null, ...(after ? {} : { total: total ?? items.length }) };
  }

  /** Put a failed received file back in the queue (the next take-in tries it again). */
  async retryReceived(id) {
    await api.receivedRetry(id);
  }
}

/** The uploader's link of a reverse share: /r/<id>#<the raw public key>. */
function reverseUrl(id, pub) {
  return `${location.origin}/r/${id}#${fragmentOf(pub)}`;
}
