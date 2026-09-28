// driveupgrade.js — the one-time upgrade of a Drive made before the key
// model v2 (docs/DRIVE.md §3.3), in a browser: the old Drive key (DK) is
// opened with what the old release used — at the user's sign-in (their
// password, a passkey's PRF output or a recovery code), or in the owner's
// browser through the owner's escrow of that release — and every item's
// name, metadata and file key (now its DEK), and every reverse-link key, is
// sealed again under the user's KEK of the current sub-MEK. Each re-sealed
// value is opened again here before it is sent; the server checks it opens
// under the KEK and stores it only where the item is still sealed the old way
// (so the upgrade can stop at any time and resume, and a repeat changes
// nothing). Then the server verifies that every item opens under v2, page by
// page, and only then removes the old key wraps (the owner's own, and the
// escrow records, once every Drive is upgraded).

import { drive as api, ApiError } from './api.js';
import { keyBytes, newSalt, sealName, openName, sealDek, openDek, sealLinkKey, openLinkKey } from './drivekeys.js';
import {
  deriveSubkeysV1, openFieldV1, openReversePrivV1, keyCheckValueV1, unlockWithPassword, unlockWithRecovery, unlockWithPrf,
  openEscrowKey, unlockWithEscrow, escrowWrapKeyId, saveLegacyKey, loadLegacyKey, clearLegacyKey,
} from './drivev1.js';
import { utf8 } from './bytes.js';

/** Why an upgrade cannot run now: 'locked' (no old Drive key in this tab), 'wrong' (it is not this Drive's), 'no_wrap', 'no_escrow', 'escrow_failed'. */
export class UpgradeBlocked extends Error {
  constructor(message, reason) {
    super(message);
    this.name = 'UpgradeBlocked';
    this.reason = reason;
  }
}

const PUT_BATCH = 100;
const sameBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * Whether `dk` is this Drive's old key (docs/DRIVE.md §3.3): its key check
 * value is the server's (`kcv`, from GET …/migrate or the escrow route); a
 * Drive with none (made before check values) must have an item name or a
 * link key that `dk` opens (AES-GCM), unless it has nothing sealed the old
 * way. An old key read from the tab's storage is used only once this holds:
 * a value planted there by other script on the origin is never a key, and a
 * wrong key never marks the Drive's items as damaged.
 */
export async function isThisDrivesKey(dk, kcv, target = null) {
  if (!(dk instanceof Uint8Array) || dk.length !== 32) return false;
  if (typeof kcv === 'string' && kcv) return (await keyCheckValueV1(dk)) === kcv;
  const page = await api.migrateItems(null, target);
  const items = (page.items || []).filter((it) => it.name);
  const links = page.links || [];
  if (!items.length && !links.length) return true;
  const sub = await deriveSubkeysV1(dk);
  for (const it of items) {
    try { await openFieldV1(sub.names, 'name', it.id, it.name); return true; } catch { /* the next */ }
  }
  for (const l of links) {
    try { (await openReversePrivV1(dk, l.id, l.priv)).fill(0); return true; } catch { /* the next */ }
  }
  return false;
}

/**
 * The old DK the tab holds for `userId` (the sign-in opened it), once proven
 * to be this Drive's (isThisDrivesKey), or null; a key that is not is removed
 * from the tab. `m`: GET …/migrate, when the caller has it.
 */
export async function provenLegacyKey(userId, m = null) {
  const dk = loadLegacyKey(userId);
  if (!dk) return null;
  const info = m || await api.migrate();
  if (await isThisDrivesKey(dk, info.kcv)) return dk;
  dk.fill(0);
  clearLegacyKey();
  return null;
}

/** The old DK from what this sign-in used (password, recovery code, passkey PRF), or null. */
async function openLegacy(m, { password, code, prfOutput, credentialId, spentWraps = [] }) {
  const wraps = [...(m.wraps || []), ...(Array.isArray(spentWraps) ? spentWraps : [])];
  let dk = null;
  if (password) dk = await unlockWithPassword(password, m.driveSalt, wraps).catch(() => null);
  if (!dk && prfOutput && credentialId) dk = await unlockWithPrf(prfOutput, credentialId, wraps).catch(() => null);
  if (!dk && code) dk = await unlockWithRecovery(code, wraps).catch(() => null);
  if (dk && !(await isThisDrivesKey(dk, m.kcv))) return null;
  return dk;
}

/**
 * After a successful sign-in: when this account's Drive still has the old
 * key wraps, open the old Drive key with what was used and keep it in this
 * tab (the Drive page then upgrades the Drive; for the owner it also opens
 * users' Drives through the escrow of that release). Never throws. → true
 * when the old key is in the tab.
 */
export async function legacyUnlockAtSignIn({ user, ...creds }) {
  clearLegacyKey();
  try {
    const m = await api.migrate();
    if (!m.legacy) return false;
    const dk = await openLegacy(m, creds);
    if (!dk) return false;
    return saveLegacyKey(dk, user.id);
  } catch {
    return false;
  }
}

/** The Drive page: open the old Drive key with the account password (or a recovery code) → true, or UpgradeBlocked 'wrong'. */
export async function legacyUnlock({ user, password, code }) {
  const m = await api.migrate();
  if (!m.legacy) throw new UpgradeBlocked('This Drive has no key of the release before any more.', 'none');
  const dk = await openLegacy(m, { password, code });
  if (!dk) throw new UpgradeBlocked('That does not open your Drive’s old key.', 'wrong');
  saveLegacyKey(dk, user.id);
  return true;
}

/**
 * One Drive's items and link keys re-sealed and sent, then verified → {
 * upgraded, damaged, verified }. `dk`: its old Drive key; `uid`: its user;
 * `mek` / `kek`: the user's current sub-MEK and KEK; `target`: null (one's
 * own Drive) or the user's id (the owner, from Admin). An item the old key
 * cannot open (damaged in storage — the old key itself is checked first) is
 * sealed under v2 with a placeholder name ("damaged-<id>") and, for a file
 * whose key is lost too, a random DEK: its content was already unreadable.
 */
async function run({ dk, uid, mek, kek, target = null, onProgress }) {
  const sub = await deriveSubkeysV1(dk);
  const out = { upgraded: 0, damaged: 0, verified: 0 };
  const at = (ks) => ({ userId: uid, mekId: mek, salt: ks });
  let pending = [];
  let links = [];
  const flush = async () => {
    if (!pending.length && !links.length) return;
    const r = await api.migratePut({ items: pending, links }, target);
    out.upgraded += r.done;
    pending = [];
    links = [];
    if (onProgress) onProgress({ phase: 'upgrade', done: out.upgraded, left: (r.v1Items ?? 0) + (r.v1Links ?? 0) });
  };
  for (let after = null, pages = 0; pages < 100000; pages++) {
    const page = await api.migrateItems(after, target);
    for (const it of page.items || []) {
      let damaged = false;
      const open = async (key, field, v) => {
        try { return await openFieldV1(key, field, it.id, v); } catch { damaged = true; return null; }
      };
      let name = it.name ? await open(sub.names, 'name', it.name) : null;
      let meta = it.meta ? await open(sub.names, 'meta', it.meta) : null;
      let dek = it.kind === 'file' ? (it.fk ? await open(sub.files, 'fk', it.fk) : null) : null;
      if (!name) { name = utf8(`damaged-${it.id}`); damaged = true; }
      if (it.kind === 'file' && !meta) { meta = utf8(JSON.stringify({ type: 'application/octet-stream', mtime: 0, size: it.size ?? 0 })); damaged = true; }
      if (it.kind === 'file' && (!dek || dek.length !== 32)) { dek = crypto.getRandomValues(new Uint8Array(32)); damaged = true; }
      if (damaged) out.damaged++;
      const ks = newSalt();
      const x = { id: it.id, ks, mek, name: await sealName(kek, at(ks), 'name', name) };
      if (meta) x.meta = await sealName(kek, at(ks), 'meta', meta);
      if (dek) x.dek = await sealDek(kek, at(ks), dek);
      // Opened again before it is sent: what is stored is what the old key held.
      if (!sameBytes(await openName(kek, at(ks), 'name', x.name), name) || (dek && !sameBytes(await openDek(kek, at(ks), x.dek), dek))) {
        throw new Error('A re-sealed item did not open again: nothing was sent for it.');
      }
      if (dek) dek.fill(0);
      pending.push(x);
      if (pending.length >= PUT_BATCH) await flush();
    }
    for (const l of page.links || []) {
      let pkcs8;
      try { pkcs8 = await openReversePrivV1(dk, l.id, l.priv); } catch { continue; } // not this Drive's key: the link stays as it was (it shows no link)
      const priv = await sealLinkKey(kek, { userId: uid, mekId: mek, linkId: l.id }, pkcs8);
      if (!sameBytes(await openLinkKey(kek, { userId: uid, mekId: mek, linkId: l.id }, priv), pkcs8)) throw new Error('A re-sealed link key did not open again.');
      pkcs8.fill(0);
      links.push({ id: l.id, mek, priv });
      if (pending.length + links.length >= PUT_BATCH) await flush();
    }
    after = page.next;
    if (!after) break;
  }
  await flush();
  // The server's check that everything opens under v2 (a page per call, from where it stopped), then the old wraps go.
  for (let n = 0; n < 100000; n++) {
    const r = await api.migrateFinish(target);
    out.verified += r.verified || 0;
    if (onProgress) onProgress({ phase: 'verify', done: out.verified });
    if (r.done || !r.next) break;
  }
  return out;
}

/**
 * Upgrade one's own Drive with the old Drive key this tab holds (the sign-in
 * opened it) → { upgraded, damaged, verified }; UpgradeBlocked 'locked' when
 * the tab has none. `keys`: the Drive client's (current sub-MEK and KEK).
 */
export async function upgradeOwnDrive({ user, current, kek, onProgress }) {
  if (!loadLegacyKey(user.id)) throw new UpgradeBlocked('Your Drive’s old key is not open in this tab.', 'locked');
  const dk = await provenLegacyKey(user.id);
  if (!dk) throw new UpgradeBlocked('The old key in this tab is not this Drive’s.', 'wrong');
  const r = await run({ dk, uid: user.id, mek: current, kek, onProgress });
  // The owner keeps the old key until every Drive is upgraded (it opens users' Drives through the escrow).
  if (user.role !== 'owner') clearLegacyKey();
  return r;
}

/**
 * The owner upgrades a user's Drive (Admin → Security → Keys): the owner's
 * own old Drive key (in this tab, from the owner's sign-in) opens the
 * owner's escrow private key of that release, which opens the user's escrow
 * wrap; the server hands the user's current KEK (both in the admin audit).
 * The user's old key is not kept. → { upgraded, damaged, verified }.
 */
export async function upgradeUserDrive({ ownerId, userId, onProgress }) {
  const own = await api.migrate();
  const ownerDk = await provenLegacyKey(ownerId, own);
  if (!ownerDk) throw new UpgradeBlocked('Your own Drive’s old key is not open in this tab: sign out and sign in again with your password, then retry.', 'locked');
  const r = await api.migrateEscrow(userId);
  if (!r.kek || !r.current) throw new ApiError('The user’s Drive keys are not available.', 503, 'keys_missing');
  let dk = null;
  if (r.v1Items || r.v1Links) {
    if (!r.wrap) throw new UpgradeBlocked('This Drive has no escrow wrap: its user upgrades it at their next sign-in.', 'no_wrap');
    if (typeof own.escrowPriv !== 'string') throw new UpgradeBlocked('Your old escrow key is not on the server.', 'no_escrow');
    const kid = escrowWrapKeyId(r.wrap);
    let key;
    try { key = await openEscrowKey(ownerDk, own.escrowPriv); } catch { throw new UpgradeBlocked('Your old escrow key does not open with your old Drive key.', 'no_escrow'); }
    if (key.kid !== kid) {
      const old = own.escrowPrivOld && typeof own.escrowPrivOld === 'object' ? own.escrowPrivOld[kid] : null;
      key = old ? await openEscrowKey(ownerDk, old).catch(() => null) : null;
    }
    dk = key ? await unlockWithEscrow(key.privateKey, r.wrap) : null;
    if (!dk) throw new UpgradeBlocked('This Drive’s escrow wrap is for an escrow key you no longer hold: its user upgrades it at their next sign-in.', 'escrow_failed');
    if (!(await isThisDrivesKey(dk, r.kcv, userId))) throw new UpgradeBlocked('The escrow wrap did not give this Drive’s key.', 'escrow_failed');
  }
  try {
    if (!dk) {
      // Nothing sealed the old way: only the verification and the clean-up.
      let out = { upgraded: 0, damaged: 0, verified: 0 };
      for (let n = 0; n < 100000; n++) {
        const f = await api.migrateFinish(userId);
        out = { ...out, verified: out.verified + (f.verified || 0) };
        if (f.done || !f.next) break;
      }
      return out;
    }
    return await run({ dk, uid: userId, mek: r.current, kek: keyBytes(r.kek), target: userId, onProgress });
  } finally {
    if (dk) dk.fill(0);
  }
}
