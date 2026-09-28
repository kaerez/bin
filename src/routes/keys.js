// keys.js — /api/private/admin/keys*: the Drive key model v2 keyring (docs/
// DRIVE.md §3, §3.1): the root MEK and the sub-MEKs (generate a candidate,
// add, rotate, edit dates, set current, show, delete after a re-seal, change
// the root), the re-seal jobs the owner's browser drives, the key kit
// (download, verify, restore), the keys part of Import / export, and one
// user's keys (view). The owner only, never while impersonating (the admin
// route checks both); every change and every view needs the step-up and is
// in the admin audit by fingerprint, never with a key.
//
// The server can open everything it re-seals here: the DEKs and names of
// every Drive item are unwrapped in this Worker, re-sealed and stored again,
// and never kept or logged in the clear.

import { json, err, readJsonBody, assertIntent, methodNotAllowed, HttpError } from '../lib/http.js';
import { directory } from '../lib/guard.js';
import { driveStub } from '../lib/store.js';
import { binding } from '../lib/config.js';
import { stepUp, saltCheck } from './drive.js';
import { NODE_ID_RE, driveChunkKey } from '../drive-do.js';
import { parseManualKey, isAtRest, keyCheckValue, sameCheck, KEY_RE, MEK_ID_RE, keyBytes, openDek, openLinkKey } from '../../public/js/drivekeys.js';
import { b64urlFromBytes } from '../../public/js/bytes.js';
import { importFileKey, decryptChunk } from '../../public/js/files.js';
import { userKeys, keksOf, currentKek, openItem, sealItem, openLink, resealLink, fieldKeys, toRest, fromRest } from '../lib/mek.js';

const fromDir = (r) => err(r.status, r.error, r.message, r.retryAfter !== undefined || r.items !== undefined ? { retryAfter: r.retryAfter, items: r.items } : undefined);
const invalid = (message) => err(400, 'invalid', message);
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const UID_RE = /^[A-Za-z0-9_-]{16}$/;
export const KEYS_EXPORT_FORMAT = 'secbin-keys-export/1';
/** DEKs one export or import handles per user at most (the Worker opens each). */
const MAX_DEKS = 10000;
/** One re-seal step works this long at most (ms), then answers with its progress. */
const STEP_MS = 3000;
const STEP_PAGES = 20;

/** A key the owner entered (any of base64, base64url or hex, 32 bytes) → base64url, or throws 400. */
function manualKey(v) {
  try { return b64urlFromBytes(parseManualKey(v)); } catch (e) { throw new HttpError(400, 'invalid_key', e.message); }
}
/** `{ candidate }` (a generated key's id) or `{ key }` (entered) from a body. */
function keyChoice(body) {
  if (typeof body.candidate === 'string' && /^[A-Za-z0-9_-]{16}$/.test(body.candidate)) return { candidate: body.candidate };
  if (body.key !== undefined) return { key: manualKey(body.key) };
  throw new HttpError(400, 'invalid_key', 'Choose "Use this key" for a generated key, or enter one.');
}
const dateOf = (v, what) => {
  if (v === undefined) return undefined;
  if (v === null) return null;
  if (!Number.isSafeInteger(v) || v < 0) throw new HttpError(400, 'invalid_date', `${what} must be a time in seconds.`);
  return v;
};

/** Items and link keys sealed under each sub-MEK, over every Drive → { counts: { mekId: n }, v1, drives }. */
async function usage(env, dir) {
  const counts = {};
  let v1 = 0;
  const users = await dir.driveUsers();
  for (const uid of users) {
    const u = await driveStub(env, uid).mekUsage(uid);
    for (const [k, n] of Object.entries(u.counts)) counts[k] = (counts[k] || 0) + n;
    v1 += u.v1 || 0;
  }
  return { counts, v1, drives: users.length };
}

/**
 * Drives still waiting for their upgrade with something of the release
 * before left in them (docs/DRIVE.md §3.3) → [{ id, username, v1Items,
 * v1Links }]. A root change waits for them: the upgrade re-seals those items
 * under the KEK the root gives.
 */
async function waitingDrives(env, dir) {
  const out = [];
  for (const r of await dir.migrationList()) {
    if (r.state === 'done') continue;
    const s = await driveStub(env, r.id).summary(r.id);
    if (s.migration.v1Items || s.migration.v1Links) out.push({ id: r.id, username: r.username, v1Items: s.migration.v1Items, v1Links: s.migration.v1Links });
  }
  return out;
}
const migrationPending = (list) => err(409, 'migration_pending', `${list.length} Drive(s) still wait for their upgrade to the new Drive keys: upgrade them first (below), then change the root.`, { drives: list.slice(0, 50) });

export async function handleKeys(request, env, url, a) {
  const p = url.pathname;
  const dir = directory(env);
  const me = a.user.id;
  const sid = a.claims?.sid || 'none';
  const needStep = async (body) => stepUp(request, env, url, dir, me, body);
  const done = (r) => (r.ok ? json(r) : fromDir(r));

  if (p === '/api/private/admin/keys') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    await dir.ensureKeys();
    return json(await dir.mekStatus());
  }
  if (p === '/api/private/admin/keys/usage') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    return json({ ok: true, ...(await usage(env, dir)) });
  }

  // Everything below changes or reveals key material: a JSON body with the step-up.
  if (request.method === 'GET') return err(404, 'not_found', 'Not found.');
  assertIntent(request);
  const body = await readJsonBody(request, 4 * 1024 * 1024);

  if (p === '/api/private/admin/keys/candidate') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const refused = await needStep(body);
    if (refused) return refused;
    return done(await dir.mekCandidate(me, sid, body.purpose)); // 'root' or 'sub' (the Directory refuses anything else)
  }
  if (p === '/api/private/admin/keys/subs') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const choice = keyChoice(body);
    const refused = await needStep(body);
    if (refused) return refused;
    return done(await dir.mekAdd(me, { sid, ...choice, from: dateOf(body.from, 'from') ?? null, note: body.note ?? '', rotate: body.rotate === true }));
  }
  const sm = p.match(/^\/api\/private\/admin\/keys\/subs\/(m[A-Za-z0-9_-]{11})(\/current|\/show)?$/);
  if (sm) {
    const [, id, sub] = sm;
    if (!sub && request.method === 'PATCH') {
      const patch = { from: dateOf(body.from, 'from'), until: dateOf(body.until, 'until'), note: body.note };
      const refused = await needStep(body);
      if (refused) return refused;
      return done(await dir.mekEdit(me, id, patch));
    }
    if (!sub && request.method === 'DELETE') {
      const refused = await needStep(body);
      if (refused) return refused;
      // Only once nothing is sealed under it (a re-seal moves every item first).
      const u = await usage(env, dir);
      if (u.counts[id]) return err(409, 'in_use', `${u.counts[id]} item(s) are still sealed under this sub-MEK: re-seal them first.`, { items: u.counts[id] });
      return done(await dir.mekDelete(me, id));
    }
    if (request.method !== 'POST' || !sub) return methodNotAllowed(sub ? 'POST' : 'PATCH, DELETE');
    const refused = await needStep(body);
    if (refused) return refused;
    if (sub === '/current') return done(await dir.mekSetCurrent(me, id));
    return done(await dir.mekShow(me, { id }));
  }
  if (p === '/api/private/admin/keys/root' || p === '/api/private/admin/keys/root/show') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const choice = p.endsWith('/show') ? null : keyChoice(body);
    const refused = await needStep(body);
    if (refused) return refused;
    if (!choice) return done(await dir.mekShow(me, { root: true }));
    const waiting = await waitingDrives(env, dir);
    if (waiting.length) return migrationPending(waiting);
    const r = await dir.mekChangeRoot(me, { sid, ...choice });
    if (!r.ok) return fromDir(r);
    // Every KEK changes with the root: every item is re-sealed (a job the owner's browser drives).
    const job = await newJob(dir, me, { kind: 'root', from: null });
    return json({ ok: true, fp: r.fp, job });
  }

  // A root change that could not finish (items opened under neither root):
  // go back to the previous root (every item is re-sealed under it again), or
  // drop the previous one and leave those items unreadable (typed confirmation).
  if (p === '/api/private/admin/keys/root/undo') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const refused = await needStep(body);
    if (refused) return refused;
    const cur = await dir.mekJob();
    if (cur && !cur.finished && cur.kind !== 'root') return err(409, 'job_running', 'A re-seal is running: let it finish (or cancel it) first.');
    const r = await dir.mekRootSwap(me);
    if (!r.ok) return fromDir(r);
    return json({ ok: true, fp: r.fp, job: await newJob(dir, me, { kind: 'root', from: null }) });
  }
  if (p === '/api/private/admin/keys/root/drop-old') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const refused = await needStep(body);
    if (refused) return refused;
    const status = await dir.mekStatus();
    if (!status.root || !status.root.changing) return err(409, 'not_changing', 'No root change is running.');
    const cur = await dir.mekJob();
    if (cur && !cur.finished) return err(409, 'job_running', 'The root change is still running: let it finish first.');
    // As stored, or as the page shows it (xxxx-xxxx-xxx).
    const typed = typeof body.confirm === 'string' ? body.confirm.trim() : '';
    const fp = status.root.oldFp;
    if (typed !== fp && typed !== `${fp.slice(0, 4)}-${fp.slice(4, 8)}-${fp.slice(8)}`) return err(400, 'confirm', 'Type the previous root MEK’s fingerprint to confirm.');
    const lost = cur && cur.kind === 'root' ? cur.failed : 0;
    const r = await dir.mekRootDropOld(me, { items: lost });
    if (!r.ok) return fromDir(r);
    if (cur && cur.kind === 'root') await dir.mekJobSet(me, { ...cur, result: { ok: true, dropped: true, message: `The previous root MEK was removed; ${lost} item(s) that opened only under it, or under neither, stay unreadable.` } });
    return json({ ok: true, lost });
  }

  if (p === '/api/private/admin/keys/jobs') {
    if (request.method === 'DELETE') {
      const refused = await needStep(body);
      if (refused) return refused;
      const job = await dir.mekJob();
      if (job && job.kind === 'root' && !job.finished) return err(409, 'root_job', 'A root change is completed, not cancelled: keep it running (or go back to the previous root).');
      await dir.mekJobSet(me, null);
      return json({ ok: true });
    }
    if (request.method !== 'POST') return methodNotAllowed('POST, DELETE');
    if (body.kind === 'root') {
      // Run the root change's re-seal again (after items that did not open were put right).
      const status = await dir.mekStatus();
      if (!status.root || !status.root.changing) return err(409, 'not_changing', 'No root change is running.');
      const cur = await dir.mekJob();
      if (cur && !cur.finished) return err(409, 'job_running', 'A re-seal is already running: let it finish first.');
      const refused = await needStep(body);
      if (refused) return refused;
      const waiting = await waitingDrives(env, dir);
      if (waiting.length) return migrationPending(waiting);
      return json({ ok: true, job: await newJob(dir, me, { kind: 'root', from: null }) });
    }
    const status = await dir.mekStatus();
    if (typeof body.from !== 'string' || !status.subs.some((s) => s.id === body.from)) return invalid('from must be one of the sub-MEKs.');
    if (body.from === status.current) return invalid('Items sealed under the current sub-MEK stay under it: choose an older one.');
    const cur = await dir.mekJob();
    if (cur && !cur.finished) return err(409, 'job_running', 'A re-seal is already running: let it finish (or cancel it) first.');
    const refused = await needStep(body);
    if (refused) return refused;
    return json({ ok: true, job: await newJob(dir, me, { kind: 'reseal', from: body.from, remove: body.remove === true }) });
  }
  if (p === '/api/private/admin/keys/jobs/step') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    return json(await jobStep(env, dir, me));
  }

  if (p === '/api/private/admin/keys/kit') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const refused = await needStep(body);
    if (refused) return refused;
    return done(await dir.keyKit(me));
  }
  if (p === '/api/private/admin/keys/verify') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const checks = (v) => (isObj(v) ? Object.fromEntries(Object.entries(v).filter(([, x]) => typeof x === 'string' && x.length <= 64).slice(0, 10000)) : {});
    return done(await dir.keyKitVerify(me, sid, { root: typeof body.root === 'string' ? body.root : null, subs: checks(body.subs), salts: checks(body.salts) }));
  }
  if (p === '/api/private/admin/keys/restore') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const dryRun = body.dryRun !== false;
    const parts = restoreParts(body);
    // The preview too: it tells which of the file's keys match this server's.
    const refused = await needStep(body);
    if (refused) return refused;
    if (parts.useRoot) {
      const u = await usage(env, dir);
      if (Object.values(u.counts).some((n) => n > 0) || u.v1) return err(409, 'in_use', 'Items are sealed under the keys here: an imported root MEK replaces the root only on an empty instance.');
    }
    return done(await dir.keyRestore(me, { ...parts, dryRun, checks: await restoreChecks(env, dir, me, parts) }));
  }
  if (p === '/api/private/admin/keys/export') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const refused = await needStep(body);
    if (refused) return refused;
    return keysExport(env, dir, me, body, url);
  }
  if (p === '/api/private/admin/keys/import') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const dryRun = body.dryRun !== false;
    // The preview too: it checks the file's KEKs against the users' and names them.
    const refused = await needStep(body);
    if (refused) return refused;
    return keysImport(env, dir, me, body, dryRun);
  }
  const um = p.match(/^\/api\/private\/admin\/keys\/users\/([A-Za-z0-9_-]{16})\/view$/);
  if (um) {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const refused = await needStep(body);
    if (refused) return refused;
    return userView(env, dir, me, um[1], body);
  }
  return err(404, 'not_found', 'Not found.');
}

/**
 * What a restore or an import must prove before the Directory adds it
 * (docs/DRIVE.md §3.1): each sub-MEK this server does not have opens an
 * item or a link key sealed under its id here ('ok'; 'unused' when nothing
 * is, 'wrong' when it does not open), and each user salt for an account with
 * none opens something of that Drive's (saltCheck) → { subs, salts }.
 */
async function restoreChecks(env, dir, me, parts) {
  const checks = { subs: {}, salts: {} };
  const status = await dir.mekStatus();
  const here = new Set(status.subs.map((x) => x.id));
  const unknown = parts.subs.filter((x) => typeof x.id === 'string' && MEK_ID_RE.test(x.id) && !here.has(x.id) && typeof x.key === 'string' && KEY_RE.test(x.key));
  if (unknown.length) {
    const where = new Map(); // mek id → a Drive that holds something sealed under it
    for (const uid of await dir.driveUsers()) {
      const u = await driveStub(env, uid).mekUsage(uid);
      for (const [k, n] of Object.entries(u.counts)) if (n && !where.has(k)) where.set(k, uid);
    }
    for (const x of unknown) {
      const uid = where.get(x.id);
      checks.subs[x.id] = uid ? ((await subOpens(env, dir, me, uid, x.id, x.key, { root: parts.root?.key, salt: saltOf(parts.salts[uid]) })) ? 'ok' : 'wrong') : 'unused';
    }
  }
  // Keys lost together are checked together: the file's root and sub-MEKs stand in for those this server lacks.
  const extra = { root: parts.root?.key ?? null, subs: Object.fromEntries(parts.subs.filter((x) => typeof x.id === 'string' && typeof x.key === 'string').map((x) => [x.id, x.key])) };
  for (const [uid, v] of Object.entries(parts.salts).slice(0, 5000)) {
    const salt = saltOf(v);
    if (!UID_RE.test(uid) || !salt) continue;
    checks.salts[uid] = await saltCheck(env, dir, uid, salt, { ownerId: me, extra });
  }
  return checks;
}
/** A salt as a kit or an export holds it (the text, or { salt, username }). */
const saltOf = (v) => {
  const x = isObj(v) ? v.salt : v;
  return typeof x === 'string' && KEY_RE.test(x) ? x : null;
};

/** Does sub-MEK `key` (as `mekId`) open the first item, or link key, `uid`'s Drive holds under that id? */
async function subOpens(env, dir, me, uid, mekId, key, extra) {
  const r = await dir.probeSub(me, uid, mekId, key, extra);
  if (!r.ok) return false;
  const kek = keyBytes(r.kek);
  const page = await driveStub(env, uid).sealedPage(uid, { meks: [mekId], limit: 1 });
  try {
    if (page.items[0]) {
      const got = await openItem(uid, [kek], page.items[0]);
      got.name.fill(0);
      if (got.dek) got.dek.fill(0);
      return true;
    }
    const l = page.links[0];
    if (!l) return false;
    const sealed = JSON.parse(await fromRest(await fieldKeys(env, uid), uid, 'linkKey', l.id, l.priv));
    (await openLinkKey(kek, { userId: uid, mekId, linkId: l.id }, sealed)).fill(0);
    return true;
  } catch {
    return false;
  } finally {
    kek.fill(0);
  }
}

/** The root MEK, sub-MEKs and user salts a restore or an import brings (validated). */
function restoreParts(body) {
  const out = { root: null, rootOld: null, subs: [], salts: {}, useRoot: body.useRoot === true };
  if (body.root !== undefined && body.root !== null) {
    if (!isObj(body.root) || !KEY_RE.test(body.root.key ?? '')) throw new HttpError(400, 'invalid', 'root must be { key }.');
    out.root = { key: body.root.key, created: Number.isSafeInteger(body.root.created) ? body.root.created : null };
  }
  // A key kit made during a root change: the root being replaced.
  if (body.rootOld !== undefined && body.rootOld !== null) {
    if (!isObj(body.rootOld) || !KEY_RE.test(body.rootOld.key ?? '')) throw new HttpError(400, 'invalid', 'rootOld must be { key }.');
    out.rootOld = { key: body.rootOld.key, created: Number.isSafeInteger(body.rootOld.created) ? body.rootOld.created : null };
  }
  if (body.subs !== undefined) {
    if (!Array.isArray(body.subs) || body.subs.length > 500) throw new HttpError(400, 'invalid', 'subs must be a list (at most 500).');
    out.subs = body.subs.map((s) => ({ id: s?.id, key: s?.key, from: s?.from, until: s?.until ?? null, created: s?.created, note: typeof s?.note === 'string' ? s.note : '' }));
  }
  if (body.salts !== undefined) {
    if (!isObj(body.salts)) throw new HttpError(400, 'invalid', 'salts must be { userId: salt }.');
    out.salts = body.salts;
  }
  return out;
}

// ── re-seal jobs (a sub-MEK before its removal, or every item after a root change) ──
/**
 * A new job over every Drive: `reseal` moves everything sealed under sub-MEK
 * `from` to the current one (and, with `remove`, deletes `from` once nothing
 * is left under it); `root` re-seals everything under the new root MEK (the
 * sub-MEKs stay), and the field layer too, then checks every Drive once more
 * and drops the old root only when everything opens under the new one.
 */
async function newJob(dir, me, { kind, from, remove = false }) {
  const job = { kind, from, remove, users: await dir.driveUsers(), u: 0, after: null, phase: 'items', done: 0, skipped: 0, failed: 0, failedIds: [], pass: 1, verify: false, started: Math.floor(Date.now() / 1000), finished: false };
  await dir.mekJobSet(me, job);
  return jobView(job);
}
const jobView = (j) => (j ? { kind: j.kind, from: j.from, remove: !!j.remove, drives: j.users.length, drive: Math.min(j.u + 1, j.users.length), phase: j.phase, done: j.done, failed: j.failed, failedIds: j.failedIds, pass: j.pass, verifying: !!j.verify, finished: !!j.finished, result: j.result ?? null } : null);
const cursor = (n) => (n ? { kind: n.kind, id: n.id } : null);
const failOf = (job) => (id) => { job.failed++; if (job.failedIds.length < 20) job.failedIds.push(id); };
/** What each phase does with one page of one Drive, and the phase after it on the same Drive (root jobs). */
const PHASES = {
  items: (env, uid, job) => sealStep(env, uid, job),
  atrest: (env, uid, job) => atRestStep(env, uid, job),
  verify: (env, uid, job) => verifyStep(env, uid, job),
  verifyrest: (env, uid, job) => verifyRestStep(env, uid, job),
};
const NEXT_PHASE = { items: 'atrest', verify: 'verifyrest' };

/** Run the job for a few seconds → its progress; finished jobs record their result. */
async function jobStep(env, dir, me) {
  const job = await dir.mekJob();
  if (!job) return { job: null };
  if (job.finished) return { job: jobView(job) };
  const t0 = Date.now();
  let pages = 0;
  while (job.u < job.users.length && Date.now() - t0 < STEP_MS && pages < STEP_PAGES) {
    const uid = job.users[job.u];
    let next = null;
    try {
      next = await PHASES[job.phase](env, uid, job);
    } catch (e) {
      if (!(e instanceof HttpError)) throw e;
      // A Drive whose keys the Directory cannot give (no salt): counted, and left as it is.
      failOf(job)(`user:${uid}`);
    }
    pages++;
    if (next) { job.after = next; continue; }
    job.after = null;
    if (job.kind === 'root' && NEXT_PHASE[job.phase]) { job.phase = NEXT_PHASE[job.phase]; continue; }
    job.phase = job.verify ? 'verify' : 'items';
    job.u++;
  }
  if (job.u >= job.users.length) {
    if (!job.verify && job.skipped > 0 && job.pass < 3) {
      // Items changed while the pass ran (a compare-and-set missed): one more pass picks them up.
      Object.assign(job, { u: 0, after: null, phase: 'items', skipped: 0, pass: job.pass + 1 });
    } else if (job.kind === 'root' && !job.verify) {
      // Every Drive once more (those made meanwhile too): everything must open under the new root only.
      Object.assign(job, { verify: true, users: await dir.driveUsers(), u: 0, after: null, phase: 'verify', sealFailed: job.failed, failed: 0, failedIds: [] });
    } else {
      job.finished = true;
      job.result = await jobFinish(env, dir, me, job);
    }
  }
  await dir.mekJobSet(me, job);
  return { job: jobView(job) };
}

async function jobFinish(env, dir, me, job) {
  if (job.kind === 'root') {
    if (job.failed) return { ok: false, message: `${job.failed} item(s) do not open under the new root MEK: the old root MEK is kept for them. Run the re-seal again, go back to the previous root, or remove it and leave those items unreadable.` };
    await dir.mekRootDone(me);
    return { ok: true, message: 'Every item is re-sealed under the new root MEK and was checked; the old one was removed.' };
  }
  // Every Drive that can hold anything sealed under it (Directory driveUsers) is counted again.
  const u = await usage(env, dir);
  const left = u.counts[job.from] || 0;
  if (left) return { ok: false, left, message: `${left} item(s) are still sealed under ${job.from}${job.failed ? ` (${job.failed} could not be opened)` : ''}.` };
  if (!job.remove) return { ok: true, left: 0, message: `Nothing is sealed under ${job.from} any more.` };
  const d = await dir.mekDelete(me, job.from);
  return d.ok ? { ok: true, left: 0, removed: true, message: `Everything was re-sealed and ${job.from} was deleted.` } : { ok: false, left: 0, message: d.message };
}

/** One page of one Drive's items and link keys, re-sealed → the next cursor, or null when that Drive is done. */
async function sealStep(env, uid, job) {
  const drive = driveStub(env, uid);
  const page = await drive.sealedPage(uid, { meks: job.kind === 'reseal' ? [job.from] : null, after: cursor(job.after) });
  if (!page.items.length && !page.links.length) return null;
  const meks = [...new Set([...page.items.map((i) => i.mek), ...page.links.map((l) => l.mek)])];
  const keys = await userKeys(env, uid, { meks });
  const cur = currentKek(keys);
  const items = [];
  const links = [];
  const fail = failOf(job);
  for (const it of page.items) {
    const k = keys.keks.get(it.mek);
    if (!k) { fail(it.id); continue; }
    let got;
    try {
      if (job.kind === 'root') {
        // Already under the new root, every field (made or re-sealed after the change): nothing to do.
        try { const r = await openItem(uid, [k.kek], it); r.name.fill(0); if (r.dek) r.dek.fill(0); if (r.meta) r.meta.fill(0); continue; } catch { /* a field under the old root */ }
      }
      // Each field under either root (a rename during the change seals the name under the new one only).
      got = await openItem(uid, keksOf(keys, it.mek), it);
    } catch {
      fail(it.id);
      continue;
    }
    // A sub-MEK re-seal moves the item to the current sub-MEK; a root change keeps its sub-MEK (under the new root).
    const to = job.kind === 'root' ? { kek: k.kek, mek: it.mek, mfp: k.fp } : cur;
    const s = await sealItem(uid, to, { name: got.name, meta: got.meta, dek: got.dek });
    got.name.fill(0);
    if (got.dek) got.dek.fill(0);
    items.push({ id: it.id, ...s, fromMek: it.mek, fromKs: it.ks, from: it.from });
  }
  const fk = page.links.length ? await fieldKeys(env, uid) : null;
  for (const l of page.links) {
    try {
      const sealed = JSON.parse(await fromRest(fk, uid, 'linkKey', l.id, l.priv));
      const k = keys.keks.get(l.mek);
      let opened;
      if (job.kind === 'root') {
        let fresh = false;
        try { (await openLink(uid, { keks: new Map([[l.mek, { kek: k.kek }]]) }, l.id, l.mek, sealed)).pkcs8.fill(0); fresh = true; } catch { /* under the old root */ }
        if (fresh) continue;
        opened = await openLink(uid, { keks: new Map([[l.mek, { kek: k.kekOld }]]) }, l.id, l.mek, sealed);
      } else {
        opened = await openLink(uid, keys, l.id, l.mek, sealed);
      }
      const to = job.kind === 'root' ? { kek: k.kek, mek: l.mek } : cur;
      const priv = JSON.stringify(await resealLink(uid, to, l.id, opened.pkcs8));
      opened.pkcs8.fill(0);
      links.push({ id: l.id, mek: to.mek, priv: await toRest(fk, uid, 'linkKey', l.id, priv), fromMek: l.mek, fromPriv: l.priv });
    } catch {
      fail(l.id);
    }
  }
  if (items.length || links.length) {
    const r = await drive.applySealed(uid, { items, links });
    job.done += r.done;
    job.skipped += r.skipped;
  }
  return page.next;
}

/**
 * One page of one Drive's field-layer values (a root change): re-sealed under
 * the new field keys. Link keys of the release before (their Drive waits for
 * its upgrade) are not listed: they stay as that release sealed them.
 */
async function atRestStep(env, uid, job) {
  const drive = driveStub(env, uid);
  const page = await drive.atRestPage(uid, { after: cursor(job.after) });
  if (!page.links.length && !page.received.length) return null;
  const fk = await fieldKeys(env, uid);
  const fresh = async (field, ref, v) => {
    if (!v) return v;
    if (isAtRest(v)) {
      try { await fromRest({ cur: fk.cur, old: null }, uid, field, ref, v); return null; } catch { /* under the old root */ }
    }
    return toRest(fk, uid, field, ref, await fromRest(fk, uid, field, ref, v));
  };
  const links = [];
  const received = [];
  const fail = failOf(job);
  for (const l of page.links) {
    try { const priv = await fresh('linkKey', l.id, l.priv); if (priv) links.push({ id: l.id, priv, from: l.priv }); } catch { fail(l.id); }
  }
  for (const r of page.received) {
    try {
      const name = await fresh('received', `name:${r.id}`, r.name);
      const meta = await fresh('received', `meta:${r.id}`, r.meta);
      const wrap = await fresh('received', `wrap:${r.id}`, r.fk);
      if (name || meta || wrap) received.push({ id: r.id, name: name ?? r.name, meta: meta ?? r.meta, fk: wrap ?? r.fk, from: { name: r.name, meta: r.meta, fk: r.fk } });
    } catch {
      fail(r.id);
    }
  }
  if (links.length || received.length) {
    const r = await drive.applyAtRest(uid, { links, received });
    job.done += r.done;
    // A value that changed meanwhile is checked (and counted) by the verification that follows.
  }
  return page.next;
}

/**
 * The root change's check (after every Drive was re-sealed): one page of one
 * Drive's items and link keys must open under the KEK of the new root only.
 */
async function verifyStep(env, uid, job) {
  const page = await driveStub(env, uid).sealedPage(uid, { after: cursor(job.after) });
  if (!page.items.length && !page.links.length) return null;
  const meks = [...new Set([...page.items.map((i) => i.mek), ...page.links.map((l) => l.mek)])];
  const keys = await userKeys(env, uid, { meks });
  const fail = failOf(job);
  for (const it of page.items) {
    const k = keys.keks.get(it.mek);
    try {
      if (!k) throw new Error('no key');
      const r = await openItem(uid, [k.kek], it);
      r.name.fill(0);
      if (r.meta) r.meta.fill(0);
      if (r.dek) r.dek.fill(0);
    } catch {
      fail(it.id);
    }
  }
  const fk = page.links.length ? await fieldKeys(env, uid) : null;
  for (const l of page.links) {
    const k = keys.keks.get(l.mek);
    try {
      if (!k) throw new Error('no key');
      const sealed = JSON.parse(await fromRest({ cur: fk.cur, old: null }, uid, 'linkKey', l.id, l.priv));
      (await openLinkKey(k.kek, { userId: uid, mekId: l.mek, linkId: l.id }, sealed)).fill(0);
    } catch {
      fail(l.id);
    }
  }
  return page.next;
}

/** The same for the field layer: every value it seals opens under the new field keys only. */
async function verifyRestStep(env, uid, job) {
  const page = await driveStub(env, uid).atRestPage(uid, { after: cursor(job.after) });
  if (!page.links.length && !page.received.length) return null;
  const fk = await fieldKeys(env, uid);
  const only = { cur: fk.cur, old: null };
  const fail = failOf(job);
  // A value stored before the field layer (plain) needs no root; a sealed one must open under the new one.
  const check = async (field, ref, v) => { if (v && isAtRest(v)) await fromRest(only, uid, field, ref, v); };
  for (const l of page.links) {
    try { await check('linkKey', l.id, l.priv); } catch { fail(l.id); }
  }
  for (const r of page.received) {
    try {
      await check('received', `name:${r.id}`, r.name);
      await check('received', `meta:${r.id}`, r.meta);
      await check('received', `wrap:${r.id}`, r.fk);
    } catch {
      fail(r.id);
    }
  }
  return page.next;
}

// ── Import / export: the keys parts (docs/DRIVE.md §3.1) ─────────────────────
/**
 * `{ root, subs: 'all' | [ids], salts: [userIds], users: [{ id, keks, deks:
 * 'all' | [nodeIds] | false }] }` → a `secbin-keys-export/1` document for the
 * owner's browser to seal under the export passphrase. KEKs are derived
 * here; each DEK is opened here (node id → DEK, no content).
 */
async function keysExport(env, dir, me, body, url) {
  const parts = await dir.keysExport(me, {
    root: body.root === true,
    subs: body.subs === 'all' ? 'all' : Array.isArray(body.subs) ? body.subs.filter((x) => typeof x === 'string').slice(0, 500) : [],
    salts: Array.isArray(body.salts) ? body.salts.filter((x) => typeof x === 'string' && UID_RE.test(x)).slice(0, 5000) : [],
  });
  if (!parts.ok) return fromDir(parts);
  const doc = { format: KEYS_EXPORT_FORMAT, created: Math.floor(Date.now() / 1000), origin: url.origin, ...parts.parts, users: [] };
  const users = Array.isArray(body.users) ? body.users.slice(0, 5000) : [];
  let deks = 0;
  for (const x of users) {
    if (!isObj(x) || !UID_RE.test(x.id ?? '')) return invalid('Each user is { id, keks, deks }.');
    const username = await dir.userName(x.id);
    if (!username) return err(404, 'not_found', `No user ${x.id}.`);
    const entry = { id: x.id, username };
    let keys = null;
    try { keys = await userKeys(env, x.id, { all: true }); } catch (e) { if (!(e instanceof HttpError)) throw e; }
    if (x.keks === true) entry.keks = keys ? [...keys.keks].map(([mekId, v]) => ({ mekId, fp: v.fp, from: v.from, until: v.until, kek: b64urlFromBytes(v.kek) })) : [];
    if (x.deks === 'all' || Array.isArray(x.deks)) {
      entry.deks = [];
      const want = Array.isArray(x.deks) ? new Set(x.deks.filter((n) => typeof n === 'string' && NODE_ID_RE.test(n))) : null;
      let after = null;
      do {
        const page = await driveStub(env, x.id).sealedPage(x.id, { after });
        for (const it of page.items) {
          if (it.kind !== 'file' || (want && !want.has(it.id))) continue;
          if (entry.deks.length >= MAX_DEKS) break;
          try {
            const dek = await openDek0(x.id, keys, it);
            entry.deks.push({ id: it.id, dek: b64urlFromBytes(dek) });
            dek.fill(0);
          } catch { /* a DEK that does not open is left out */ }
        }
        after = page.next && page.next.kind === 'n' ? page.next : null;
      } while (after && entry.deks.length < MAX_DEKS);
      deks += entry.deks.length;
    }
    doc.users.push(entry);
    await dir.driveAdminAction(me, x.id, 'drive.keys_viewed', `exported:${entry.keks ? ` KEKs ${entry.keks.length}` : ''}${entry.deks ? ` DEKs ${entry.deks.length}` : ''}`);
  }
  await dir.adminLog({ action: 'keys.exported', detail: `root MEK ${doc.root ? 'yes' : 'no'}; sub-MEKs ${doc.subs?.length ?? 0}; user salts ${Object.keys(doc.salts ?? {}).length}; users ${doc.users.length}; DEKs ${deks}` }, { id: me, adm: true });
  return json({ document: doc });
}

async function openDek0(uid, keys, it) {
  let last;
  for (const kek of keys ? keksOf(keys, it.mek) : []) {
    try { return await openDek(kek, { userId: uid, mekId: it.mek, salt: it.ks }, it.dek); } catch (e) { last = e; }
  }
  throw last || new Error('no key');
}

/**
 * Import the keys parts of a `secbin-keys-export/1` document (a dry run
 * first). Imports never replace working keys: the root MEK, sub-MEKs and
 * salts as a key-kit restore (only what is missing or broken here); a KEK is
 * derived, so importing one only verifies it; a DEK restores an item's DEK
 * seal only when it is missing or does not open, and only after it opened
 * the file's first chunk (a GCM check).
 */
async function keysImport(env, dir, me, body, dryRun) {
  const doc = body.document;
  if (!isObj(doc) || doc.format !== KEYS_EXPORT_FORMAT) return invalid(`Not a ${KEYS_EXPORT_FORMAT} document.`);
  const take = isObj(body.take) ? body.take : { root: true, subs: true, salts: true, keks: true, deks: true };
  const out = { dryRun, keys: null, users: [] };
  if ((take.root && doc.root) || (take.subs && doc.subs) || (take.salts && doc.salts)) {
    const parts = restoreParts({ root: take.root ? doc.root : undefined, subs: take.subs ? doc.subs : undefined, salts: take.salts ? doc.salts : undefined, useRoot: body.useRoot === true });
    if (parts.useRoot) {
      const u = await usage(env, dir);
      if (Object.values(u.counts).some((n) => n > 0) || u.v1) return err(409, 'in_use', 'Items are sealed under the keys here: an imported root MEK replaces the root only on an empty instance.');
    }
    const r = await dir.keyRestore(me, { ...parts, dryRun, checks: await restoreChecks(env, dir, me, parts) });
    if (!r.ok) return fromDir(r);
    out.keys = { root: r.root, rootOld: r.rootOld, subs: r.subs, salts: r.salts };
  }
  if (FILES_NEEDED(take, doc)) binding(env, 'FILES');
  for (const x of Array.isArray(doc.users) ? doc.users.slice(0, 5000) : []) {
    if (!isObj(x) || !UID_RE.test(x.id ?? '')) { out.users.push({ id: String(x?.id ?? '').slice(0, 20), error: 'invalid' }); continue; }
    const res = { id: x.id, username: await dir.userName(x.id) };
    if (!res.username) { out.users.push({ ...res, error: 'unknown user' }); continue; }
    let keys = null;
    try { keys = await userKeys(env, x.id, { all: true }); } catch (e) { if (!(e instanceof HttpError)) throw e; res.error = e.message; }
    if (take.keks && Array.isArray(x.keks) && keys) {
      res.keks = { match: 0, mismatch: 0, unknown: 0 };
      for (const k of x.keks.slice(0, 500)) {
        const here = MEK_ID_RE.test(k?.mekId ?? '') && KEY_RE.test(k?.kek ?? '') ? keys.keks.get(k.mekId) : null;
        if (!here) res.keks.unknown++;
        else if (sameCheck(await keyCheckValue(keyBytes(k.kek), 'kek'), await keyCheckValue(here.kek, 'kek'))) res.keks.match++;
        else res.keks.mismatch++;
      }
    }
    if (take.deks && Array.isArray(x.deks) && keys) {
      res.deks = { restored: 0, working: 0, failed: 0, missing: 0 };
      for (const d of x.deks.slice(0, MAX_DEKS)) {
        const r = await restoreDek(env, x.id, keys, d, dryRun);
        res.deks[r]++;
      }
      if (!dryRun && res.deks.restored) await dir.driveAdminAction(me, x.id, 'drive.keys_imported', `DEKs restored: ${res.deks.restored}`);
    }
    out.users.push(res);
  }
  if (!dryRun) await dir.adminLog({ action: 'keys.imported', detail: `keyring ${out.keys ? 'yes' : 'no'}; users ${out.users.length}` }, { id: me, adm: true });
  return json({ ok: true, ...out });
}
const FILES_NEEDED = (take, doc) => take.deks && Array.isArray(doc.users) && doc.users.some((u) => Array.isArray(u?.deks) && u.deks.length);

/**
 * One imported DEK → 'working' (the item's own seal opens: nothing to do) |
 * 'restored' (its seal was missing or broken, the DEK opened the first chunk,
 * and the item is sealed again under the current KEK; names that no longer
 * open become a placeholder) | 'failed' | 'missing' (no such file).
 */
async function restoreDek(env, uid, keys, d, dryRun) {
  if (!isObj(d) || !NODE_ID_RE.test(d.id ?? '') || !KEY_RE.test(d.dek ?? '')) return 'failed';
  const drive = driveStub(env, uid);
  const it = await drive.itemKeys(uid, d.id);
  if (!it.ok || it.item.kind !== 'file' || it.item.state !== 'ready') return 'missing';
  const item = it.item;
  if (item.mek && item.dek) {
    try { (await openDek0(uid, keys, item)).fill(0); return 'working'; } catch { /* broken: restore */ }
  }
  const dek = keyBytes(d.dek);
  // The DEK must open the file's first chunk (an empty file has none: it cannot be checked).
  if (!item.chunks) return 'failed';
  const obj = await env.FILES.get(driveChunkKey(uid, d.id, 0));
  if (!obj) return 'failed';
  try {
    const key = await importFileKey(d.dek);
    await decryptChunk(key, 0, item.chunks, new Uint8Array(await obj.arrayBuffer()));
  } catch {
    return 'failed';
  }
  if (dryRun) return 'restored';
  // Its name and metadata, when they still open; else placeholders (the content is back).
  let name = null;
  let meta = null;
  if (item.mek) {
    try {
      const got = await openItem(uid, keksOf(keys, item.mek), { ...item, kind: 'dir' });
      name = got.name;
      meta = got.meta;
    } catch { /* lost with the key */ }
  }
  name ??= new TextEncoder().encode(`restored-${d.id}`);
  meta ??= new TextEncoder().encode(JSON.stringify({ type: 'application/octet-stream', mtime: 0, size: item.size }));
  const s = await sealItem(uid, currentKek(keys), { name, meta, dek });
  dek.fill(0);
  const w = await drive.restoreItem(uid, { id: d.id, ...s, fromMek: item.mek ?? null, fromKs: item.ks ?? null, from: item.from });
  return w.ok ? 'restored' : 'failed';
}

/**
 * One user's keys for the owner (step-up; masked in the page until "Show"):
 * `{ what: 'keks' }` → their salt and KEKs; `{ what: 'deks', after? }` → a
 * page of their files: node id, name (opened here), DEK. Admin audit: ids
 * and counts only.
 */
async function userView(env, dir, me, uid, body) {
  const username = await dir.userName(uid);
  if (!username) return err(404, 'not_found', 'User not found.');
  const keys = await userKeys(env, uid, { all: true });
  if (body.what === 'deks') {
    const after = typeof body.after === 'string' && NODE_ID_RE.test(body.after) ? { kind: 'n', id: body.after } : null;
    const page = await driveStub(env, uid).sealedPage(uid, { after, limit: 100 });
    const files = [];
    for (const it of page.items) {
      if (it.kind !== 'file') continue;
      try {
        const got = await openItem(uid, keksOf(keys, it.mek), it);
        files.push({ id: it.id, name: new TextDecoder().decode(got.name), dek: b64urlFromBytes(got.dek) });
        got.dek.fill(0);
      } catch {
        files.push({ id: it.id, name: null, dek: null });
      }
    }
    await dir.driveAdminAction(me, uid, 'drive.keys_viewed', `DEKs: ${files.length}`);
    return json({ userId: uid, username, files, next: page.next && page.next.kind === 'n' ? page.next.id : null });
  }
  const s = await driveStub(env, uid).summary(uid);
  await dir.driveAdminAction(me, uid, 'drive.keys_viewed', `KEKs: ${keys.keks.size}`);
  return json({
    userId: uid, username, salt: keys.salt, current: keys.current, items: s.items,
    keks: [...keys.keks].map(([mekId, v]) => ({ mekId, fp: v.fp, from: v.from, until: v.until, kek: b64urlFromBytes(v.kek), inUse: s.meks.includes(mekId) })),
  });
}
