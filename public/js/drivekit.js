// drivekit.js — a Drive kit's file (docs/DRIVE.md §3.1): one module, two
// kinds, made and read only in the browser (the file never goes to the
// server; its content does come from the server, which holds the keys):
//
//   user  "secbin-user-kit/2" { format, userId, salt, t, m, iv, ct } — a
//         personal kit (Account page, every user, the owner included): the
//         user's id, username, user salt and the KEK of each sub-MEK their
//         Drive uses. It opens that user's files and reverse shares.
//   key   "secbin-key-kit/1"  { format, ownerId, salt, t, m, iv, ct } — the
//         key kit (Admin → Security → Keys): the root MEK, every sub-MEK
//         with its dates, and every user salt. It restores everything.
//
//   key  = Argon2id(UTF8(NFC(passphrase)), salt16, m = 64 MiB, t = 3, p = 1) → 32 B
//   ct   = AES-256-GCM(key, iv12, UTF8(JSON(payload)), AAD)
//   AAD  = "<format>\nargon2id\nm=65536\nt=3\np=1\nsalt=<b64url>\niv=<b64url>\n"
//          + "<user|key>=<account id>\norigin=<origin>\n"
//
// The KDF parameters are the export's (public/js/exportcrypt.js) and fixed: a
// crafted file cannot ask for more work. The format (so the kind), the
// account id and the server's origin are bound into the AAD: a kit opens only
// as its kind, for its account, on its server, and any change to the file
// fails authentication. The passphrase is optional with no minimum length,
// like the export's; an empty one still goes through Argon2id (from the same
// substitute input as the export: the Argon2 build refuses an empty input),
// so the file looks the same either way.

import { argon2idRaw } from './kdf.js';
import { b64urlFromBytes, bytesFromB64url, randomBytes, utf8, fromUtf8 } from './bytes.js';

export const KIT_FORMATS = Object.freeze({ user: 'secbin-user-kit/2', key: 'secbin-key-kit/1' });
const ID_FIELD = { user: 'userId', key: 'ownerId' };
/** The payload version inside each kind. */
const PAYLOAD_V = { user: 2, key: 1 };
const KDF = Object.freeze({ alg: 'argon2id', m: 65536, t: 3, p: 1 });
const B64_RE = /^[A-Za-z0-9_-]+$/;
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const NO_PASSPHRASE = Uint8Array.of(0xff); // as exportcrypt.js: no UTF-8 text is this byte

/**
 * A kit that cannot be used: `check` says which step failed — 'format' (not a
 * kit, or an incompatible one), 'kind' (a key kit where a personal kit is
 * expected, or the other way round), 'owner' (another account's kit), 'auth'
 * (wrong passphrase, another server, or the file was changed) or 'payload'.
 */
export class DriveKitError extends Error {
  constructor(message, check) { super(message); this.name = 'DriveKitError'; this.check = check; }
}

const aad = (kind, accountId, origin, salt, iv) => utf8(`${KIT_FORMATS[kind]}\n${KDF.alg}\nm=${KDF.m}\nt=${KDF.t}\np=${KDF.p}\nsalt=${salt}\niv=${iv}\n${kind}=${accountId}\norigin=${origin}\n`);

async function keyFrom(passphrase, saltBytes) {
  const text = String(passphrase).normalize('NFC');
  const raw = await argon2idRaw(text === '' ? NO_PASSPHRASE : utf8(text), saltBytes, { t: KDF.t, mKiB: KDF.m, p: KDF.p });
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/** Seal a kit's payload: `kind` 'user' | 'key', for `accountId` on `origin` → the file's text. */
export async function sealDriveKit(kind, payload, { accountId, origin, passphrase }) {
  if (!KIT_FORMATS[kind]) throw new DriveKitError('Unknown kind of kit.', 'format');
  if (typeof passphrase !== 'string') throw new DriveKitError('The kit passphrase must be text.', 'format');
  if (typeof accountId !== 'string' || !ID_RE.test(accountId) || typeof origin !== 'string' || !origin) throw new DriveKitError('Missing account or origin.', 'format');
  const salt = b64urlFromBytes(randomBytes(16));
  const iv = randomBytes(12);
  const i = b64urlFromBytes(iv);
  const key = await keyFrom(passphrase, bytesFromB64url(salt));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(kind, accountId, origin, salt, i) }, key, utf8(JSON.stringify(payload))));
  return JSON.stringify({ format: KIT_FORMATS[kind], [ID_FIELD[kind]]: accountId, salt, t: KDF.t, m: KDF.m, iv: i, ct: b64urlFromBytes(ct) }, null, 2);
}

/** A kit file's envelope (untrusted text), checked for form only → { kind, accountId, salt, iv, ct }; DriveKitError('format'). */
export function parseDriveKit(text) {
  let env;
  try { env = JSON.parse(text); } catch { throw new DriveKitError('This is not a Drive kit.', 'format'); }
  const kind = env && typeof env === 'object' && !Array.isArray(env) ? Object.keys(KIT_FORMATS).find((k) => KIT_FORMATS[k] === env.format) : null;
  const idf = kind ? ID_FIELD[kind] : null;
  const ok = !!kind
    && Object.keys(env).sort().join() === ['ct', 'format', 'iv', 'm', idf, 'salt', 't'].sort().join()
    && env.t === KDF.t && env.m === KDF.m
    && typeof env[idf] === 'string' && ID_RE.test(env[idf])
    && typeof env.salt === 'string' && env.salt.length === 22 && B64_RE.test(env.salt)
    && typeof env.iv === 'string' && env.iv.length === 16 && B64_RE.test(env.iv)
    && typeof env.ct === 'string' && env.ct.length >= 24 && env.ct.length <= 200000 && B64_RE.test(env.ct);
  if (!ok) throw new DriveKitError('This is not a Drive kit, or it was made by an incompatible version.', 'format');
  return { kind, accountId: env[idf], salt: env.salt, iv: env.iv, ct: env.ct };
}

/**
 * Open a parsed kit as `kind`, for `accountId` on `origin` → the payload.
 * DriveKitError 'kind' for the other kind of kit and 'owner' for another
 * account's (both checked before any key is derived), 'auth' for a wrong
 * passphrase, another server or a changed file.
 */
export async function openDriveKit(env, { kind, accountId, origin, passphrase }) {
  if (env.kind !== kind) {
    throw new DriveKitError(kind === 'key' ? 'This is a personal kit, not the key kit.' : 'This is the key kit (Admin → Security → Keys), not a personal kit.', 'kind');
  }
  if (env.accountId !== accountId) throw new DriveKitError(kind === 'key' ? 'This key kit was made by another owner account.' : 'This kit belongs to another account.', 'owner');
  const key = await keyFrom(typeof passphrase === 'string' ? passphrase : '', bytesFromB64url(env.salt));
  let pt;
  try {
    pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytesFromB64url(env.iv), additionalData: aad(kind, accountId, origin, env.salt, env.iv) }, key, bytesFromB64url(env.ct));
  } catch {
    throw new DriveKitError('Wrong passphrase, or the kit was made on another server or has been changed.', 'auth');
  }
  let payload;
  try { payload = JSON.parse(fromUtf8(new Uint8Array(pt))); } catch { payload = null; }
  if (!payload || typeof payload !== 'object' || payload.v !== PAYLOAD_V[kind]) throw new DriveKitError('The kit opened, but its content is not valid.', 'payload');
  return payload;
}
