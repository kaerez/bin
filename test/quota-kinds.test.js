// quota-kinds.test.js — what each role quota kind counts (public/js/
// quotakinds.js) in workerd: every action is counted by exactly the kinds that
// cover it (all outgoing shares, and each type; the Drive's uploads; Receive's
// new links and upload sessions of every kind — files, notes, links and
// credentials, with a kind each —, counted for the link's user), the API-only
// channel, the public account's anonymous subjects and restricted kinds, the
// refunds (refused after counting, a Drive upload that never completes, a
// Receive session that sends nothing), the uploader's neutral 429, the
// validation of kinds, and the Drive's bytes (drive-bytes: each upload's size,
// counted with its file at the reservation, atomically, given back as it is).
import { runDurableObjectAlarm, runInDurableObject } from 'cloudflare:test';
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import { owner, makeUser, fetchJson, createNote, freshIp, proofFor, USER_PW } from './helpers.js';
import { enableDrive, createFile, uploadFile, del, putChunk, drive } from './drive-helpers.js';
import { receiver, newReverse, begin, grantOf, send, rv, reserve, driveOf, dirStub, takeInAny, received, itemSession } from './reverse-helpers.js';
import { encryptPaste } from '../public/js/crypto.js';
import { buildSecret } from '../public/js/sharetypes.js';
import { b64urlFromBytes, randomBytes } from '../public/js/bytes.js';
import { invalidateGuardCaches } from '../src/lib/guard.js';
import { validateExport, PortableError, EXPORT_FORMAT } from '../src/lib/portable.js';

const PUBLIC_ID = 'public-user-0000';
let oc;
beforeAll(async () => { oc = await owner(); });
afterEach(() => { vi.useRealTimers(); invalidateGuardCaches(); });

// Every kind, and which kinds each action must count (and no other).
const KINDS = ['all', 'text', 'note', 'url', 'secret', 'files', 'file', 'drive', 'drive-upload', 'drive-bytes', 'receive', 'receive-link', 'receive-upload',
  'receive-file', 'receive-note', 'receive-url', 'receive-secret'];
const COUNTED_BY = {
  note: ['all', 'text', 'note'],
  url: ['all', 'text', 'url'],
  secret: ['all', 'text', 'secret'],
  file: ['all', 'files', 'file'],
  drive: ['all', 'files', 'drive'],
  'drive-upload': ['drive-upload'], // and its bytes: BYTES_OF
  'receive-link': ['receive', 'receive-link'],
  // An upload session through a Receive link: "receive", "receive-upload" (any kind) and its own kind.
  'receive-file': ['receive', 'receive-upload', 'receive-file'],
  'receive-note': ['receive', 'receive-upload', 'receive-note'],
  'receive-url': ['receive', 'receive-upload', 'receive-url'],
  'receive-secret': ['receive', 'receive-upload', 'receive-secret'],
};
// What an action adds to the quotas counted in bytes (the matrix's Drive upload is 10 bytes).
const BYTES_OF = { 'drive-upload': 10 };
// A window long enough that no test crosses into the next one (a fixed window: 100 calendar years).
const q = (kind, max = 100, channel = 'all') => ({ channel, kind, n: 100, unit: 'y', max });
const setQuotas = (scope, list) => fetchJson('/api/private/admin/quotas', { method: 'PUT', cookie: oc, body: { scope, list } });
const setLimits = (scope, patch, channel = 'all') => fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope, channel, patch } });
/** The account's quotas as /me reports them → { "<kind>:<channel>": used }. */
const used = async (cookie) => Object.fromEntries((await (await fetchJson('/api/private/me', { cookie })).json()).quotas.map((x) => [`${x.kind}:${x.channel}`, x.used]));
const errorBody = async (r) => ({ status: r.status, ...(await r.json()) });

/** A Drive share of `nodes` (its manifest is never read by the server). */
async function driveShare(cookie, nodes) {
  const manifest = { v: 3, kind: 'refs', entries: nodes.map((id, ref) => ({ path: `f${ref}`, size: 0, type: 'application/octet-stream', mtime: 0, ref, fk: b64urlFromBytes(randomBytes(32)) })), dirs: [] };
  const { body } = await encryptPaste({ text: JSON.stringify(manifest), fmt: 'files', expire: '1h' });
  return fetchJson('/api/private/drive/shares', { method: 'POST', cookie, body: { nodes, views: null, expire: '1h', paste: body } });
}
const fileInit = (cookie, headers) => fetchJson('/api/private/file', { method: 'POST', cookie, headers, body: { views: 1, expire: '1h', padded: 65536, files: 1, maxFile: 10 } });
/** One upload session through link `r` that sends a file, then says it is done. */
async function uploadSession(r, ip = freshIp()) {
  const grant = await grantOf(r, { ip });
  await send(r, grant, { ip });
  const done = await rv(r.id, '/done', { headers: { 'x-reverse-grant': grant }, ip });
  expect(done.status).toBe(200);
}
const done = (r, grant, ip) => rv(r.id, '/done', { headers: { 'x-reverse-grant': grant }, ip });

describe('every kind is counted by its actions, and only by them', () => {
  it('outgoing shares, Drive uploads and Receive each count under the kinds that cover them', async () => {
    const u = await receiver('qk-matrix');
    await setLimits(u.id, { url: true, secret: true, reverseUrl: true, reverseSecret: true });
    // Fixtures first: saving the quotas starts every count from zero.
    const f = await uploadFile(u.cookie, 'root', 10);
    const link = await newReverse(u.cookie, { accept: ['files', 'note', 'url', 'secret'] });
    expect(link.res.status).toBe(201);
    expect((await setQuotas(u.id, KINDS.map((k) => q(k)))).status).toBe(200);
    expect(Object.values(await used(u.cookie)).every((n) => n === 0)).toBe(true);

    const actions = {
      note: async () => expect((await createNote(u.cookie, { text: 'plain' })).res.status).toBe(201),
      url: async () => expect((await createNote(u.cookie, { text: 'https://example.com/doc', fmt: 'url' })).res.status).toBe(201),
      secret: async () => expect((await createNote(u.cookie, { text: buildSecret({ username: 'a', password: 'b' }), fmt: 'secret' })).res.status).toBe(201),
      file: async () => expect((await fileInit(u.cookie)).status).toBe(201),
      drive: async () => expect((await driveShare(u.cookie, [f.id])).status).toBe(201),
      'drive-upload': async () => expect((await createFile(u.cookie, 'root', 10)).res.status).toBe(201),
      'receive-link': async () => expect((await newReverse(u.cookie)).res.status).toBe(201),
      'receive-file': () => uploadSession(link),
      'receive-note': () => itemSession(link, 'note', { text: '# hello', fmt: 'markdown' }, { ip: freshIp() }),
      'receive-url': () => itemSession(link, 'url', { url: 'https://example.com/doc' }, { ip: freshIp() }),
      'receive-secret': () => itemSession(link, 'secret', { username: 'synthetic', password: 'not-a-real-one' }, { ip: freshIp() }),
    };
    const expected = Object.fromEntries(KINDS.map((k) => [`${k}:all`, 0]));
    for (const [action, run] of Object.entries(actions)) {
      await run();
      for (const k of COUNTED_BY[action]) expected[`${k}:all`]++;
      expected['drive-bytes:all'] += BYTES_OF[action] ?? 0;
      expect(await used(u.cookie), action).toEqual(expected);
    }
    // In sum: "all" counted the five outgoing shares (not the Drive upload or Receive); "receive" every Receive action;
    // "receive-upload" the four upload sessions, whatever they sent.
    expect(expected).toMatchObject({ 'all:all': 5, 'text:all': 3, 'files:all': 2, 'drive-upload:all': 1, 'drive-bytes:all': 10, 'receive:all': 5, 'receive-upload:all': 4 });
    // Markdown and code notes are notes.
    await createNote(u.cookie, { text: '# md', fmt: 'markdown' });
    await createNote(u.cookie, { text: 'x = 1', fmt: 'code' });
    expect(await used(u.cookie)).toMatchObject({ 'note:all': 3, 'text:all': 5, 'url:all': 1, 'secret:all': 1, 'all:all': 7 });
  });

  it('each kind refuses at its maximum with a message naming what it counts; other kinds go on', async () => {
    const u = await receiver('qk-refuse');
    await setLimits(u.id, { url: true, secret: true });
    const f = await uploadFile(u.cookie, 'root', 10);
    await setQuotas(u.id, [q('note', 1), q('url', 1), q('secret', 1), q('file', 1), q('drive', 1), q('drive-upload', 1), q('receive-link', 1)]);
    const over = async (res, what, kind) => {
      expect(await errorBody(res)).toEqual({ status: 429, error: 'quota_exceeded', message: `Quota reached: 1 ${what} per 100y.`, quota: { channel: 'all', kind, n: 100, unit: 'y', max: 1 } });
    };
    expect((await createNote(u.cookie, { text: 'a' })).res.status).toBe(201);
    await over((await createNote(u.cookie, { text: 'b' })).res, 'notes', 'note');
    expect((await createNote(u.cookie, { text: 'https://example.com/', fmt: 'url' })).res.status).toBe(201);
    await over((await createNote(u.cookie, { text: 'https://example.com/2', fmt: 'url' })).res, 'links', 'url');
    expect((await createNote(u.cookie, { text: buildSecret({ password: 'p' }), fmt: 'secret' })).res.status).toBe(201);
    await over((await createNote(u.cookie, { text: buildSecret({ password: 'q' }), fmt: 'secret' })).res, 'credentials', 'secret');
    expect((await fileInit(u.cookie)).status).toBe(201);
    await over(await fileInit(u.cookie), 'file shares', 'file');
    expect((await driveShare(u.cookie, [f.id])).status).toBe(201);
    await over(await driveShare(u.cookie, [f.id]), 'Drive shares', 'drive');
    expect((await createFile(u.cookie, 'root', 5)).res.status).toBe(201);
    await over((await createFile(u.cookie, 'root', 5)).res, 'files uploaded to the Drive', 'drive-upload');
    expect((await newReverse(u.cookie)).res.status).toBe(201);
    await over((await newReverse(u.cookie)).res, 'new Receive links', 'receive-link');
    // The group kinds name their groups.
    await setQuotas(u.id, [q('all', 0)]);
    await over2((await createNote(u.cookie, { text: 'c' })).res, 'outgoing shares', 'all');
    await setQuotas(u.id, [q('text', 0)]);
    await over2((await createNote(u.cookie, { text: 'c' })).res, 'notes, links and credentials', 'text');
    await setQuotas(u.id, [q('files', 0)]);
    await over2(await fileInit(u.cookie), 'file and Drive shares', 'files');
    await setQuotas(u.id, [q('receive', 0)]);
    await over2((await newReverse(u.cookie)).res, 'Receive links and uploads received', 'receive');
    async function over2(res, what, kind) {
      expect(await errorBody(res)).toEqual({ status: 429, error: 'quota_exceeded', message: `Quota reached: 0 ${what} per 100y.`, quota: { channel: 'all', kind, n: 100, unit: 'y', max: 0 } });
    }
  });

  it('the owner is never counted', async () => {
    expect((await setQuotas('global', KINDS.map((k) => q(k, 0)))).status).toBe(200);
    try {
      expect((await createNote(oc, { text: 'owner' })).res.status).toBe(201);
      expect((await createFile(oc, 'root', 5)).res.status).toBe(201);
      expect((await newReverse(oc, { confirm: false, current: proofFor('owner-password') })).res.status).toBe(201);
      expect((await (await fetchJson('/api/private/me', { cookie: oc })).json()).quotas).toEqual([]);
    } finally {
      await setQuotas('global', []);
    }
  });
});

describe('the API-only channel', () => {
  it('counts only API creations, per kind; kinds used only in the web app take no API-only quota', async () => {
    const u = await makeUser('qk-api');
    await setLimits(u.id, { apiEnabled: true, url: true });
    const key = (await (await fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body: { current: proofFor(USER_PW), name: 'k' } })).json()).key;
    const bearer = { authorization: `Bearer ${key}` };
    expect((await setQuotas(u.id, [q('note', 1, 'api'), q('file', 1, 'api')])).status).toBe(200);
    expect((await createNote(null, { text: '1' }, { headers: bearer })).res.status).toBe(201);
    const over = await createNote(null, { text: '2' }, { headers: bearer });
    expect(over.res.status).toBe(429);
    expect((await over.res.json()).message).toBe('Quota reached: 1 notes per 100y via the API.');
    expect((await createNote(u.cookie, { text: 'GUI is not counted' })).res.status).toBe(201);
    expect((await createNote(null, { text: 'https://example.com/', fmt: 'url' }, { headers: bearer })).res.status).toBe(201); // a link is not a note
    expect((await fileInit(null, bearer)).status).toBe(201);
    expect((await fileInit(null, bearer)).status).toBe(429);
    expect((await fileInit(u.cookie)).status).toBe(201);
    expect(await used(u.cookie)).toEqual({ 'note:api': 1, 'file:api': 1 });
    for (const kind of ['drive', 'drive-upload', 'drive-bytes', 'receive', 'receive-link', 'receive-upload', 'receive-file', 'receive-note', 'receive-url', 'receive-secret']) {
      const r = await setQuotas(u.id, [q(kind, 1, 'api')]);
      expect(await errorBody(r)).toEqual({ status: 400, error: 'invalid_quota', message: `quota kind ${kind} is only ever counted in the web app: its channel must be all` });
    }
    for (const kind of ['all', 'text', 'note', 'url', 'secret', 'files', 'file']) expect((await setQuotas(u.id, [q(kind, 1, 'api')])).status).toBe(200);
  });
});

describe('the public account', () => {
  it('counts each kind per anonymous subject, and takes only the kinds it can use', async () => {
    await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'public.enabled': true, 'public.tracking': 'ip' } });
    expect((await setLimits(PUBLIC_ID, { url: true })).status).toBe(200);
    expect((await setQuotas(PUBLIC_ID, [q('note', 1), q('url', 2)])).status).toBe(200);
    const publicNote = async (ip, extra = {}) => {
      const { body } = await encryptPaste({ text: 'anonymous', bar: true, views: 1, expire: '1h', ...extra });
      return fetchJson('/api/public/paste', { method: 'POST', ip, body: { paste: body } });
    };
    const ip = freshIp();
    expect((await publicNote(ip)).status).toBe(201);
    const over = await publicNote(ip);
    expect(await errorBody(over)).toMatchObject({ status: 429, error: 'quota_exceeded', message: 'Quota reached: 1 notes per 100y.' });
    expect((await publicNote(ip, { text: 'https://example.com/', fmt: 'url' })).status).toBe(201); // a link is not a note
    expect((await publicNote(ip, { text: 'https://example.com/', fmt: 'url' })).status).toBe(201);
    expect((await publicNote(ip, { text: 'https://example.com/', fmt: 'url' })).status).toBe(429);
    expect((await publicNote(freshIp())).status).toBe(201); // another network has its own count
    // No Drive, no Receive: the public list refuses those kinds (and Drive shares), in the API and in an import.
    for (const kind of ['drive', 'drive-upload', 'drive-bytes', 'receive', 'receive-link', 'receive-upload', 'receive-file', 'receive-note', 'receive-url', 'receive-secret']) {
      const r = await setQuotas(PUBLIC_ID, [q(kind)]);
      expect(r.status).toBe(400);
      expect((await r.json()).message).toMatch(/^the public account has no Drive or Receive/);
    }
    for (const kind of ['all', 'text', 'note', 'url', 'secret', 'files', 'file']) expect((await setQuotas(PUBLIC_ID, [q(kind)])).status).toBe(200);
    // The Default role (which the public account's list adds to) takes every kind.
    expect((await setQuotas('global', [q('receive-upload')])).status).toBe(200);
    await setQuotas('global', []);
    await setQuotas(PUBLIC_ID, []);
    await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'public.enabled': false } });
  });

  it('an import refuses a Drive or Receive kind in the public account\'s quotas (the roles take every kind)', () => {
    const doc = (system) => ({ format: EXPORT_FORMAT, created: 1, users: [], system });
    const pub = (quotas) => doc({ public: { limits: { all: {}, api: {} }, quotas, viewerRules: [] } });
    expect(() => validateExport(pub([q('drive-upload')]))).toThrow(/^system\.public\.quotas\[0\]: the public account has no Drive or Receive/);
    expect(() => validateExport(pub([q('receive-link')]))).toThrow(PortableError);
    expect(() => validateExport(pub([q('drive-bytes')]))).toThrow(/^system\.public\.quotas\[0\]: the public account has no Drive or Receive/);
    expect(validateExport(pub([q('url'), q('file')])).system.public.quotas.map((x) => x.kind)).toEqual(['url', 'file']);
    const roles = validateExport(doc({ limits: { all: {}, api: {} }, quotas: KINDS.map((k) => q(k)), viewerRules: [],
      roles: [{ name: 'Receivers', ownQuotas: true, limits: { all: {}, api: {} }, quotas: [q('receive-upload', 5)], viewerRules: [] }] }));
    expect(roles.system.quotas.map((x) => x.kind)).toEqual(KINDS);
    expect(roles.system.roles[0].quotas).toEqual([q('receive-upload', 5)]);
    expect(() => validateExport(doc({ limits: { all: {}, api: {} }, quotas: [q('uploads')], viewerRules: [] }))).toThrow(/^system\.quotas\[0\]: quota kind must be one of/);
  });
});

describe('validation', () => {
  it('rejects unknown kinds and names the valid ones', async () => {
    const u = await makeUser('qk-valid');
    for (const kind of ['notes', 'links', 'upload', 'receive-uploads', '', null]) {
      const r = await setQuotas(u.id, [{ channel: 'all', kind, n: 1, unit: 'd', max: 1 }]);
      expect(await errorBody(r)).toEqual({ status: 400, error: 'invalid_quota', message: `quota kind must be one of ${KINDS.join(', ')}` });
    }
  });
});

describe('Drive uploads', () => {
  it('are refused at the quota before anything is reserved; files taken in from Receive links are not counted', async () => {
    const u = await receiver('qk-drive');
    await setQuotas(u.id, [q('drive-upload', 2)]);
    await uploadFile(u.cookie, 'root', 10);
    await uploadFile(u.cookie, 'root', 10);
    const before = await drive(u.cookie);
    const over = await createFile(u.cookie, 'root', 10);
    expect(over.res.status).toBe(429);
    expect((await over.res.json()).error).toBe('quota_exceeded');
    expect(await drive(u.cookie)).toEqual(before); // nothing reserved
    // A file received through a link and taken in: counted under Receive, not here.
    const link = await newReverse(u.cookie);
    await uploadSession(link);
    const [it0] = (await received(u.cookie)).items;
    expect((await takeInAny(u.cookie, it0.id)).status).toBe(200);
    expect(await used(u.cookie)).toEqual({ 'drive-upload:all': 2 });
  });

  it('give the quota back when the Drive refuses the file, when an unfinished upload is deleted or purged; never for a finished one', async () => {
    const u = await makeUser('qk-drive-refund');
    await enableDrive(u.id, { filePendingSec: 600 });
    await setQuotas(u.id, [q('drive-upload', 5)]);
    // Refused by the Drive (larger than its capacity) after counting.
    const full = await createFile(u.cookie, 'root', 99 * 1024 ** 3);
    expect(full.res.status).toBe(413);
    expect(await used(u.cookie)).toEqual({ 'drive-upload:all': 0 });
    // Cancelled: the browser deletes the unfinished file.
    const cancelled = await createFile(u.cookie, 'root', 10);
    expect(await used(u.cookie)).toEqual({ 'drive-upload:all': 1 });
    expect((await del(u.cookie, cancelled.id)).status).toBe(200);
    expect(await used(u.cookie)).toEqual({ 'drive-upload:all': 0 });
    // A finished file stays counted when deleted.
    const kept = await uploadFile(u.cookie, 'root', 10);
    expect((await del(u.cookie, kept.id)).status).toBe(200);
    expect(await used(u.cookie)).toEqual({ 'drive-upload:all': 1 });
    // Abandoned: purged by the alarm.
    const left = await createFile(u.cookie, 'root', 50);
    expect((await putChunk(u.cookie, left.id, 0, randomBytes(66), left.uploadToken)).status).toBe(200);
    expect(await used(u.cookie)).toEqual({ 'drive-upload:all': 2 });
    vi.useFakeTimers({ now: Date.now() + 601 * 1000, toFake: ['Date'] });
    await runDurableObjectAlarm(driveOf(u.id));
    vi.useRealTimers();
    expect(await used(u.cookie)).toEqual({ 'drive-upload:all': 1 });
  });
});

describe('Drive bytes (drive-bytes)', () => {
  const GiB = 1024 ** 3;
  it('count each upload\'s size at its reservation; refused (naming the size) when a file would go past the max; the file quota counts on', async () => {
    const u = await makeUser('qk-bytes');
    await enableDrive(u.id);
    await setQuotas(u.id, [q('drive-bytes', 100), q('drive-upload', 100)]);
    expect((await createFile(u.cookie, 'root', 60)).res.status).toBe(201);
    expect(await used(u.cookie)).toEqual({ 'drive-bytes:all': 60, 'drive-upload:all': 1 });
    const before = await drive(u.cookie);
    const over = await createFile(u.cookie, 'root', 41);
    expect(await errorBody(over.res)).toEqual({ status: 429, error: 'quota_exceeded', message: 'Quota reached: 100 B uploaded to the Drive per 100y.', quota: { channel: 'all', kind: 'drive-bytes', n: 100, unit: 'y', max: 100 } });
    // Refused as a whole: neither its bytes nor the file counted, nothing reserved.
    expect(await used(u.cookie)).toEqual({ 'drive-bytes:all': 60, 'drive-upload:all': 1 });
    expect(await drive(u.cookie)).toEqual(before);
    // Up to the max exactly, and an empty file even then.
    expect((await createFile(u.cookie, 'root', 40)).res.status).toBe(201);
    expect((await createFile(u.cookie, 'root', 0)).res.status).toBe(201);
    expect(await used(u.cookie)).toEqual({ 'drive-bytes:all': 100, 'drive-upload:all': 3 });
    expect((await createFile(u.cookie, 'root', 1)).res.status).toBe(429);
    // The size in the refusal and on Account: in KB / MB / GB (1024-based, as the pages).
    await setQuotas(u.id, [q('drive-bytes', GiB)]);
    expect((await createFile(u.cookie, 'root', GiB + 1)).res.status).toBe(429);
    expect((await (await createFile(u.cookie, 'root', GiB + 1)).res.json()).message).toBe('Quota reached: 1.0 GB uploaded to the Drive per 100y.');
  });

  it('are checked and counted atomically: uploads at once never go past the max together', async () => {
    const u = await makeUser('qk-bytes-race');
    await enableDrive(u.id);
    await setQuotas(u.id, [q('drive-bytes', 100)]);
    const all = await Promise.all(Array.from({ length: 10 }, () => createFile(u.cookie, 'root', 30)));
    expect(all.map((f) => f.res.status).sort()).toEqual([201, 201, 201, 429, 429, 429, 429, 429, 429, 429]);
    expect(await used(u.cookie)).toEqual({ 'drive-bytes:all': 90 });
    // The file quota and the bytes quota are one check: at the file quota, no bytes are counted either.
    await setQuotas(u.id, [q('drive-upload', 2), q('drive-bytes', 1000)]);
    const both = await Promise.all(Array.from({ length: 5 }, () => createFile(u.cookie, 'root', 30)));
    expect(both.filter((f) => f.res.status === 201)).toHaveLength(2);
    expect(await used(u.cookie)).toEqual({ 'drive-upload:all': 2, 'drive-bytes:all': 60 });
  });

  it('give the bytes back when the Drive refuses the file, when an unfinished upload is deleted or purged; never for a finished one', async () => {
    const u = await makeUser('qk-bytes-refund');
    await enableDrive(u.id, { filePendingSec: 600, driveMaxBytes: 10 * 1024 * 1024 });
    await setQuotas(u.id, [q('drive-bytes', GiB), q('drive-upload', 100)]);
    // Refused by the Drive (past its capacity) after counting.
    expect((await createFile(u.cookie, 'root', 11 * 1024 * 1024)).res.status).toBe(413);
    expect(await used(u.cookie)).toEqual({ 'drive-bytes:all': 0, 'drive-upload:all': 0 });
    // Refused by the Drive for another reason (a folder that does not exist).
    expect((await createFile(u.cookie, 'A'.repeat(22), 70)).res.status).toBe(404);
    expect(await used(u.cookie)).toEqual({ 'drive-bytes:all': 0, 'drive-upload:all': 0 });
    // Cancelled: the browser deletes the unfinished file.
    const cancelled = await createFile(u.cookie, 'root', 70);
    expect(await used(u.cookie)).toEqual({ 'drive-bytes:all': 70, 'drive-upload:all': 1 });
    expect((await del(u.cookie, cancelled.id)).status).toBe(200);
    expect(await used(u.cookie)).toEqual({ 'drive-bytes:all': 0, 'drive-upload:all': 0 });
    // A finished file stays counted when deleted.
    const kept = await uploadFile(u.cookie, 'root', 25);
    expect((await del(u.cookie, kept.id)).status).toBe(200);
    expect(await used(u.cookie)).toEqual({ 'drive-bytes:all': 25, 'drive-upload:all': 1 });
    // Abandoned: purged by the alarm (a folder deleted with an unfinished file in it gives it back as well).
    const left = await createFile(u.cookie, 'root', 50);
    expect((await putChunk(u.cookie, left.id, 0, randomBytes(66), left.uploadToken)).status).toBe(200);
    expect(await used(u.cookie)).toEqual({ 'drive-bytes:all': 75, 'drive-upload:all': 2 });
    vi.useFakeTimers({ now: Date.now() + 601 * 1000, toFake: ['Date'] });
    await runDurableObjectAlarm(driveOf(u.id));
    vi.useRealTimers();
    expect(await used(u.cookie)).toEqual({ 'drive-bytes:all': 25, 'drive-upload:all': 1 });
    // A refund never goes below zero, and a hit gives back only what it counted.
    await runInDurableObject(dirStub(), (inst) => inst.refundDriveUploads(u.id, [{ t: Math.floor(Date.now() / 1000), size: 10 ** 9 }]));
    expect(await used(u.cookie)).toEqual({ 'drive-bytes:all': 0, 'drive-upload:all': 0 });
  });

  it('files taken in from a Receive link are not counted; the max may be past 10 000 000 (bytes), up to 1 PiB', async () => {
    const u = await receiver('qk-bytes-recv');
    await setQuotas(u.id, [q('drive-bytes', 5 * GiB)]);
    const link = await newReverse(u.cookie);
    await uploadSession(link);
    const [it0] = (await received(u.cookie)).items;
    expect((await takeInAny(u.cookie, it0.id)).status).toBe(200);
    expect(await used(u.cookie)).toEqual({ 'drive-bytes:all': 0 });
    expect((await setQuotas(u.id, [q('drive-bytes', 2 ** 50)])).status).toBe(200);
    expect(await errorBody(await setQuotas(u.id, [q('drive-bytes', 2 ** 50 + 1)]))).toEqual({ status: 400, error: 'invalid_quota', message: `quota max of kind drive-bytes must be 0–${2 ** 50} bytes` });
    expect((await setQuotas(u.id, [q('drive-upload', 10000001)])).status).toBe(400); // other kinds: as before
  });
});

describe('Receive', () => {
  it('upload sessions count for the link\'s user; at the quota the uploader gets a neutral 429 with nothing of the quota', async () => {
    const u = await receiver('qk-recv');
    const link = await newReverse(u.cookie);
    await setQuotas(u.id, [q('receive-upload', 1)]);
    await uploadSession(link);
    expect(await used(u.cookie)).toEqual({ 'receive-upload:all': 1 });
    const ip = freshIp();
    const r = await begin(link, { ip });
    const text = await r.text();
    expect(r.status).toBe(429);
    expect(JSON.parse(text)).toEqual({ error: 'not_accepting', message: 'This link can’t accept more uploads right now. Try again later.' });
    expect(text).not.toMatch(/quota|100y|receive/i);
    expect(r.headers.get('retry-after')).toBeNull();
    // The quota is the user's: another user's link is not affected, and neither is the user's own Drive.
    const other = await receiver('qk-recv-other');
    await uploadSession(await newReverse(other.cookie));
    expect((await createFile(u.cookie, 'root', 5)).res.status).toBe(201);
    // "All receive" covers both: one new link and one upload session.
    const v = await receiver('qk-recv-all');
    await setQuotas(v.id, [q('receive', 2)]);
    const l2 = await newReverse(v.cookie);
    expect(l2.res.status).toBe(201);
    await uploadSession(l2);
    expect((await begin(l2, { ip: freshIp() })).status).toBe(429);
    expect((await newReverse(v.cookie)).res.status).toBe(429);
    expect(await used(v.cookie)).toEqual({ 'receive:all': 2 });
  });

  it('a session gives its count back when it does not start, or ends having sent nothing', async () => {
    const u = await receiver('qk-recv-refund', { filePendingSec: 600 });
    const link = await newReverse(u.cookie, { password: 'open sesame' });
    await setQuotas(u.id, [q('receive-upload', 10)]);
    const n = async () => (await used(u.cookie))['receive-upload:all'];
    // A wrong password: no session.
    const bad = await begin(link, { password: 'wrong', ip: freshIp() });
    expect(bad.status).toBe(403);
    expect(await n()).toBe(0);
    // Done with nothing sent.
    const ip = freshIp();
    const g1 = await grantOf(link, { password: 'open sesame', ip });
    expect(await n()).toBe(1);
    expect(await (await done(link, g1, ip)).json()).toEqual({ files: 0, bytes: 0 });
    expect(await n()).toBe(0);
    // A file reserved but never finished, then cancelled, then done: nothing was sent.
    const g2 = await grantOf(link, { password: 'open sesame', ip });
    const f = await reserve(link, g2, { ip });
    expect((await rv(link.id, `/files/${f.node}`, { method: 'DELETE', headers: { 'x-reverse-grant': g2, 'x-upload-token': f.data.uploadToken }, ip })).status).toBe(200);
    await done(link, g2, ip);
    expect(await n()).toBe(0);
    // Sent a file: counted, and stays counted.
    const g3 = await grantOf(link, { password: 'open sesame', ip });
    await send(link, g3, { ip });
    await done(link, g3, ip);
    expect(await n()).toBe(1);
    // Lapsed with nothing sent (no "done"): given back by the Drive's alarm…
    await grantOf(link, { password: 'open sesame', ip });
    expect(await n()).toBe(2);
    vi.useFakeTimers({ now: Date.now() + 601 * 1000, toFake: ['Date'] });
    await runDurableObjectAlarm(driveOf(u.id));
    expect(await n()).toBe(1);
    // …or by the next session start, whichever comes first.
    await grantOf(link, { password: 'open sesame', ip });
    expect(await n()).toBe(2);
    vi.setSystemTime(Date.now() + 601 * 1000);
    await grantOf(link, { password: 'open sesame', ip: freshIp() }); // forgets the lapsed one (given back), counts itself
    vi.useRealTimers();
    expect(await n()).toBe(2);
  });

  it('a new link gives its count back when its creation does not complete', async () => {
    const u = await receiver('qk-link-refund');
    await setQuotas(u.id, [q('receive-link', 1)]);
    const wrong = await newReverse(u.cookie, { confirm: false, current: proofFor('not the password') });
    expect(wrong.res.status).toBe(403);
    expect(await used(u.cookie)).toEqual({ 'receive-link:all': 0 });
    const missing = await newReverse(u.cookie, { folder: 'AAAAAAAAAAAAAAAAAAAAAA' }); // no such folder: the Drive refuses
    expect(missing.res.status).toBe(404);
    expect(await used(u.cookie)).toEqual({ 'receive-link:all': 0 });
    expect((await newReverse(u.cookie)).res.status).toBe(201);
    expect(await used(u.cookie)).toEqual({ 'receive-link:all': 1 });
  });
});
