// receive-types.test.js — "Receive" links (reverse shares, docs/REVERSE.md
// §3.1) that accept what regular shares carry — files, notes, links and
// credentials — in workerd: the role options (Default, Owner, Public, the API
// channel, migration 18), what a link accepts on create and edit (the role
// checked for what is added; widening needs the step-up, a note does not; an
// API key cannot widen), the kind of each send declared at `begin` and
// checked against the link and the link user's role as it is then, again at
// every reservation; one item per note / link / credential session, of
// bounded size, the file types for files only; views and quotas per send of
// each kind, with their refunds; links made before accepting files only; and
// nothing of an item's kind or content in plain text at rest. Synthetic data
// only.
import { runInDurableObject } from 'cloudflare:test';
import { describe, it, expect, beforeAll, vi } from 'vitest';
import { owner, makeUser, fetchJson, intent, freshIp, proofFor, USER_PW, proofHeaders } from './helpers.js';
import { driveLimits, uploadFile, mkdir } from './drive-helpers.js';
import { encryptPaste } from '../public/js/crypto.js';
import { b64urlFromBytes, randomBytes } from '../public/js/bytes.js';
import { PUBLIC_ID, SCHEMA_VERSION } from '../src/directory-do.js';
import { LIMITS, UNLIMITED, API_LIMIT_KEYS, REVERSE_KEYS } from '../src/lib/settings.js';
import { weakening } from '../src/routes/reverse.js';
import { ITEM_MAX_BYTES, encodeItem, RECEIVE_KINDS } from '../public/js/receivekinds.js';
import { linkProof } from '../public/js/reversekeys.js';
import { utf8 } from '../public/js/bytes.js';
import { validateExport, EXPORT_FORMAT } from '../src/lib/portable.js';
import {
  dirStub, driveOf, errorOf, receiver, newReverse, rv, openLink, begin, reserve, send, sendItem, itemSession, received, takeInAny,
} from './reverse-helpers.js';

vi.setConfig({ testTimeout: 60000 });

let oc;
beforeAll(async () => { oc = await owner(); });

const KIND_KEYS = ['reverseFiles', 'reverseText', 'reverseUrl', 'reverseSecret'];
const ALL = ['files', 'note', 'url', 'secret'];
const CONFIRM = { current: proofFor(USER_PW) };
const patch = (cookie, id, body, headers = {}) => fetchJson(`/api/private/shares/${id}`, { method: 'PATCH', cookie, body, headers });
const limits = (scope, p, channel = 'all') => fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope, channel, patch: p } });
const setQuotas = (scope, list) => fetchJson('/api/private/admin/quotas', { method: 'PUT', cookie: oc, body: { scope, list } });
const q = (kind, max = 100) => ({ channel: 'all', kind, n: 100, unit: 'y', max });
const me = async (cookie) => (await fetchJson('/api/private/me', { cookie })).json();
const used = async (cookie) => Object.fromEntries((await me(cookie)).quotas.map((x) => [x.kind, x.used]));
const listed = async (cookie, id) => (await (await fetchJson('/api/private/drive/reverse', { cookie })).json()).reverse.find((x) => x.id === id);
const driveRow = (uid, id) => runInDurableObject(driveOf(uid), (i, s) => s.storage.sql.exec('SELECT * FROM reverse WHERE id = ?', id).toArray()[0]);
const beginAs = async (r, type, ip = freshIp()) => begin(r, { ip, type });
const grantAs = async (r, type, ip) => {
  const b = await beginAs(r, type, ip);
  if (b.status !== 200) throw new Error(`begin ${type}: ${b.status} ${await b.text()}`);
  return (await b.json()).grant;
};
/** A receiver whose role lets links accept everything. */
const everything = (name, extra = {}) => receiver(name, { reverseUrl: true, reverseSecret: true, ...extra });

describe('the role options', () => {
  it('Default: files and notes on, links and credentials off; the owner: all; the public account: none; the API channel can restrict them', async () => {
    expect(Object.fromEntries(KIND_KEYS.map((k) => [k, LIMITS[k].def]))).toEqual({ reverseFiles: true, reverseText: true, reverseUrl: false, reverseSecret: false });
    expect(Object.fromEntries(KIND_KEYS.map((k) => [k, UNLIMITED[k]]))).toEqual({ reverseFiles: true, reverseText: true, reverseUrl: true, reverseSecret: true });
    expect((await me(oc)).limits).toMatchObject({ reverseFiles: true, reverseText: true, reverseUrl: true, reverseSecret: true });
    const u = await makeUser('rt-defaults');
    expect((await me(u.cookie)).limits).toMatchObject({ reverseFiles: true, reverseText: true, reverseUrl: false, reverseSecret: false });
    for (const k of KIND_KEYS) {
      expect(REVERSE_KEYS, k).toContain(k);
      expect(API_LIMIT_KEYS, k).toContain(k);
      expect((await limits(PUBLIC_ID, { [k]: true })).status, k).toBe(400); // not for the public account
      expect((await limits(u.id, { [k]: 'yes' })).status, k).toBe(400);
      expect((await limits('global', { [k]: 'inherit' })).status, k).toBe(400); // the Default role holds a value
    }
    expect((await limits(u.id, { reverseUrl: false }, 'api')).status).toBe(200);
  });

  it('export / import carries them (and the new quota kinds) like every role option; a bad value is refused', () => {
    const doc = (system) => ({ format: EXPORT_FORMAT, created: 1, users: [], system });
    const limits = { all: { reverseFiles: false, reverseText: true, reverseUrl: true, reverseSecret: false }, api: { reverseUrl: false } };
    const quotas = ['receive-file', 'receive-note', 'receive-url', 'receive-secret'].map((k) => q(k, 3));
    const v = validateExport(doc({ limits: { all: {}, api: {} }, quotas: [], viewerRules: [], roles: [{ name: 'Receivers', ownQuotas: true, limits, quotas, viewerRules: [] }] }));
    expect(v.system.roles[0].limits).toEqual(limits);
    expect(v.system.roles[0].quotas).toEqual(quotas);
    expect(() => validateExport(doc({ limits: { all: { reverseSecret: 'yes' }, api: {} }, quotas: [], viewerRules: [] }))).toThrow(/reverseSecret/);
  });

  it('migration 18 gives the Default role a value for each (a Directory the release before left)', async () => {
    expect(SCHEMA_VERSION).toBe(20); // 19: sign-in records sealed (records.test.js), 20: failed sign-ins logged (audit-w3a.test.js), after 18
    await runInDurableObject(dirStub(), (i, s) => {
      s.storage.sql.exec(`DELETE FROM limits WHERE user_id = '' AND key IN (${KIND_KEYS.map(() => '?').join(', ')})`, ...KIND_KEYS);
      s.storage.sql.exec("UPDATE meta SET v = '17' WHERE k = 'schema_version'");
    });
    await runInDurableObject(dirStub(), (i, s) => { try { s.abort('restart'); } catch { /* the instance ends here */ } }).catch(() => {});
    const after = await runInDurableObject(dirStub(), (i, s) => ({
      version: s.storage.sql.exec("SELECT v FROM meta WHERE k = 'schema_version'").one().v,
      rows: Object.fromEntries(s.storage.sql.exec("SELECT key, value FROM limits WHERE user_id = '' AND channel = 'all' AND key IN ('reverseFiles', 'reverseText', 'reverseUrl', 'reverseSecret')").toArray().map((x) => [x.key, JSON.parse(x.value)])),
    }));
    expect(after).toEqual({ version: '20', rows: { reverseFiles: true, reverseText: true, reverseUrl: false, reverseSecret: false } });
  });
});

describe('what a link accepts, on create', () => {
  it('files only unless it says otherwise; a list of known kinds; each one the role allows', async () => {
    const u = await receiver('rt-create');
    const plain = await newReverse(u.cookie);
    expect(plain.res.status).toBe(201);
    expect((await plain.res.json()).accept).toEqual(['files']);
    expect((await listed(u.cookie, plain.id)).accept).toEqual(['files']);
    for (const accept of [[], ['photos'], 'files', ['files', 7], null]) {
      const r = await newReverse(u.cookie, { accept });
      if (accept === null) { expect(r.res.status).toBe(201); continue; } // null: files only, as not sent
      expect(r.res.status, JSON.stringify(accept)).toBe(400);
    }
    // Links and credentials: off in the Default role.
    for (const accept of [['url'], ['files', 'secret']]) {
      const r = await newReverse(u.cookie, { accept });
      expect(r.res.status, JSON.stringify(accept)).toBe(403);
      expect(await errorOf(r.res)).toBe('receive_kind_disabled');
    }
    const notes = await newReverse(u.cookie, { accept: ['note', 'files'] });
    expect(notes.res.status).toBe(201);
    expect((await listed(u.cookie, notes.id)).accept).toEqual(['files', 'note']); // stored in the pages' order
    await driveLimits(u.id, { reverseFiles: false });
    expect(await errorOf((await newReverse(u.cookie)).res)).toBe('receive_kind_disabled'); // files only, and files are off
    await driveLimits(u.id, { reverseUrl: true, reverseSecret: true, reverseFiles: true });
    const all = await newReverse(u.cookie, { accept: ALL });
    expect(all.res.status).toBe(201);
    const head = await (await openLink(all, freshIp())).json();
    expect(head.accept).toEqual(ALL);
  });
});

describe('a link made before these kinds', () => {
  it('accepts files only: its limits have no `accept`', async () => {
    const u = await everything('rt-old');
    const r = await newReverse(u.cookie);
    // As the release before stored it.
    await runInDurableObject(driveOf(u.id), (i, s) => {
      const row = s.storage.sql.exec('SELECT opts FROM reverse WHERE id = ?', r.id).one();
      const o = JSON.parse(row.opts);
      delete o.accept;
      s.storage.sql.exec('UPDATE reverse SET opts = ? WHERE id = ?', JSON.stringify(o), r.id);
    });
    expect((await listed(u.cookie, r.id)).accept).toEqual(['files']);
    const ip = freshIp();
    expect((await (await openLink(r, ip)).json()).accept).toEqual(['files']);
    for (const kind of ['note', 'url', 'secret']) {
      const b = await beginAs(r, kind, ip);
      expect(b.status, kind).toBe(403);
      expect(await errorOf(b)).toBe('kind_not_accepted');
    }
    // An old client (no body): files, as before.
    const g = await begin(r, { ip });
    expect(g.status).toBe(200);
    await send(r, (await g.json()).grant, { ip });
    expect((await driveRow(u.id, r.id)).used).toBe(1); // the refused starts spent no view
  });
});

describe('each send declares its kind; the link and the role decide', () => {
  it('a link that accepts notes only: a note goes through, files and the others are refused before any view, CAPTCHA or password', async () => {
    const u = await everything('rt-notes');
    const r = await newReverse(u.cookie, { accept: ['note'], views: 5, password: 'gate words' });
    const ip = freshIp();
    for (const kind of ['files', 'url', 'secret']) {
      const b = await beginAs(r, kind, ip);
      expect(await errorOf(b), kind).toBe('kind_not_accepted');
    }
    expect((await begin(r, { ip })).status).toBe(403); // no body: files, which it does not accept
    expect((await beginAs(r, 'photos', ip)).status).toBe(400);
    expect((await driveRow(u.id, r.id)).used).toBe(0);
    // A note (with the password): one view.
    const { sent } = await itemSession(r, 'note', { text: '# Minutes\n\n- synthetic', fmt: 'markdown', title: 'Minutes' }, { ip, password: 'gate words' });
    expect((await driveRow(u.id, r.id)).used).toBe(1);
    // It waits in the Drive like a received file, its kind only in what the uploader sealed.
    const got = await received(u.cookie);
    const it = got.items.find((x) => x.id === sent.node);
    expect(it).toMatchObject({ rs: r.id, size: utf8('# Minutes\n\n- synthetic').length, chunks: 1 });
    const stored = await runInDurableObject(driveOf(u.id), (i, s) => s.storage.sql.exec('SELECT name, meta, fk FROM nodes WHERE id = ?', sent.node).one());
    for (const v of Object.values(stored)) expect(v).not.toMatch(/note|markdown|Minutes|"kind"/i);
    expect(JSON.stringify(it)).not.toMatch(/markdown|Minutes|"kind":"note"/);
  });

  it('one item per note, link or credential session, of bounded size; the file types and the largest file are for files only', async () => {
    const u = await everything('rt-item-limits');
    const r = await newReverse(u.cookie, { accept: ALL, maxFileBytes: 4, types: { mode: 'allow', rules: ['ext:pdf'] } });
    const ip = freshIp();
    // A note: no type declaration, and more than the largest file's 4 bytes.
    let grant = await grantAs(r, 'note', ip);
    await sendItem(r, grant, 'note', { text: 'longer than four bytes' }, { ip });
    // A second item in the same session: refused.
    const again = await reserve(r, grant, { path: 'Note', bytes: utf8('second'), item: { kind: 'note', fmt: 'plaintext' }, ip });
    expect(again.res.status).toBe(409);
    expect(await errorOf(again.res)).toBe('one_item');
    // Past the kind's size (checked on the declared size; the chunks must match it).
    grant = await grantAs(r, 'url', ip);
    const big = await reserve(r, grant, { path: 'Link', bytes: utf8('https://example.com/'), size: ITEM_MAX_BYTES.url + 1, item: { kind: 'url' }, ip });
    expect(big.res.status).toBe(413);
    expect(await errorOf(big.res)).toBe('item_too_large');
    // …and a cancelled reservation gives the session its item back.
    const ok = await reserve(r, grant, { path: 'Link', bytes: encodeItem('url', { url: 'https://example.com/doc' }).bytes, item: { kind: 'url' }, ip });
    expect(ok.res.status).toBe(201);
    expect((await rv(r.id, `/files/${ok.node}`, { method: 'DELETE', headers: { 'x-reverse-grant': grant, 'x-upload-token': ok.data.uploadToken }, ip })).status).toBe(200);
    await sendItem(r, grant, 'url', { url: 'https://example.com/doc' }, { ip });
    grant = await grantAs(r, 'secret', ip);
    const huge = await reserve(r, grant, { path: 'Credential', bytes: utf8('{}'), size: ITEM_MAX_BYTES.secret + 1, item: { kind: 'secret' }, ip });
    expect(await errorOf(huge.res)).toBe('item_too_large');
    // Files: still held to the types and the largest file.
    grant = await grantAs(r, 'files', ip);
    expect(await errorOf((await reserve(r, grant, { path: 'a.pdf', bytes: utf8('%PDF'), type: 'application/pdf', ip })).res)).toBe('declaration_required');
    expect(await errorOf((await reserve(r, grant, { path: 'a.pdf', bytes: utf8('%PDF-1'), type: 'application/pdf', types: [{ ext: 'pdf', mime: 'application/pdf' }], ip })).res)).toBe('file_too_large');
    // Every item counts towards the link's most files (and its bytes).
    const r2 = await newReverse(u.cookie, { accept: ['note', 'files'], maxFiles: 1 });
    await itemSession(r2, 'note', { text: 'one' }, { ip });
    const g2 = await grantAs(r2, 'files', ip);
    expect(await errorOf((await reserve(r2, g2, { ip })).res)).toBe('too_many_files');
  });

  it('the link user\'s role is checked at every send: open, begin and each reservation', async () => {
    const u = await everything('rt-role-now');
    const r = await newReverse(u.cookie, { accept: ['files', 'url'] });
    const onlyUrl = await newReverse(u.cookie, { accept: ['url'] });
    const ip = freshIp();
    const grant = await grantAs(r, 'url', ip); // begun while links were allowed
    await driveLimits(u.id, { reverseUrl: false });
    // The page offers what the role allows now; a link left with nothing is gone.
    expect((await (await openLink(r, ip)).json()).accept).toEqual(['files']);
    expect((await openLink(onlyUrl, ip)).status).toBe(410);
    expect((await beginAs(onlyUrl, 'url', ip)).status).toBe(410);
    expect(await errorOf(await beginAs(r, 'url', ip))).toBe('kind_not_accepted');
    // The session begun before cannot reserve its link any more.
    const late = await reserve(r, grant, { path: 'Link', bytes: utf8('https://example.com/'), item: { kind: 'url' }, ip });
    expect(late.res.status).toBe(403);
    expect(await errorOf(late.res)).toBe('kind_not_accepted');
    // Files still go.
    const fg = await grantAs(r, 'files', ip);
    await send(r, fg, { ip });
    await driveLimits(u.id, { reverseUrl: true });
    expect((await (await openLink(onlyUrl, ip)).json()).accept).toEqual(['url']);
  });
});

describe('views and quotas: one per send, whatever it sends', () => {
  it('each kind spends one view and counts under receive, receive-upload and its own kind; a session that sends nothing gives them back', async () => {
    const u = await everything('rt-quota');
    const r = await newReverse(u.cookie, { accept: ALL, views: 10 });
    expect((await setQuotas(u.id, ['receive', 'receive-upload', 'receive-file', 'receive-note', 'receive-url', 'receive-secret'].map((k) => q(k)))).status).toBe(200);
    const ip = freshIp();
    const g = await grantAs(r, 'files', ip);
    await send(r, g, { ip });
    await rv(r.id, '/done', { headers: { 'x-reverse-grant': g }, ip });
    await itemSession(r, 'note', { text: 'hello' }, { ip });
    await itemSession(r, 'url', { url: 'https://example.com/' }, { ip });
    await itemSession(r, 'secret', { username: 'synthetic', password: 'not-real' }, { ip });
    expect((await driveRow(u.id, r.id)).used).toBe(4);
    expect(await used(u.cookie)).toEqual({ receive: 4, 'receive-upload': 4, 'receive-file': 1, 'receive-note': 1, 'receive-url': 1, 'receive-secret': 1 });
    // A credential session that sends nothing: done gives its counts back (the view stays spent).
    const idle = await grantAs(r, 'secret', ip);
    expect((await used(u.cookie))['receive-secret']).toBe(2);
    expect((await rv(r.id, '/done', { headers: { 'x-reverse-grant': idle }, ip })).status).toBe(200);
    expect(await used(u.cookie)).toMatchObject({ receive: 4, 'receive-upload': 4, 'receive-secret': 1 });
    expect((await driveRow(u.id, r.id)).used).toBe(5);
    // A kind's own quota refuses only that kind: the uploader learns only that the link cannot take uploads now.
    expect((await setQuotas(u.id, [q('receive-note', 1)])).status).toBe(200);
    await itemSession(r, 'note', { text: 'first' }, { ip });
    const over = await beginAs(r, 'note', ip);
    expect(over.status).toBe(429);
    expect(await over.json()).toEqual({ error: 'not_accepting', message: 'This link can’t accept more uploads right now. Try again later.' });
    await itemSession(r, 'url', { url: 'https://example.com/other' }, { ip });
    // A lapsed note session that sent nothing gives back its own kind (at the next start).
    expect((await setQuotas(u.id, [q('receive-note', 5), q('receive-upload', 50)])).status).toBe(200);
    await grantAs(r, 'note', ip);
    expect(await used(u.cookie)).toEqual({ 'receive-note': 1, 'receive-upload': 1 });
    await runInDurableObject(driveOf(u.id), (i, s) => s.storage.sql.exec('UPDATE rsessions SET expires = 1 WHERE rid = ? AND files = 0', r.id));
    await grantAs(r, 'url', ip);
    expect(await used(u.cookie)).toEqual({ 'receive-note': 0, 'receive-upload': 1 });
  });
});

describe('what a link accepts, on edit', () => {
  it('adding files, links or credentials weakens it (the step-up; never an API key); adding a note or removing any does not', async () => {
    const u = await everything('rt-edit', { apiEnabled: true });
    const r = await newReverse(u.cookie, { accept: ['note'] });
    // A note → files: weakening.
    let res = await patch(u.cookie, r.id, { accept: ['files', 'note'] });
    expect(res.status).toBe(400);
    expect(await errorOf(res)).toBe('reauth_required');
    expect((await listed(u.cookie, r.id)).accept).toEqual(['note']);
    res = await patch(u.cookie, r.id, { accept: ['files', 'note'], ...CONFIRM });
    expect(res.status, await res.clone().text()).toBe(200);
    expect((await res.json()).accept).toEqual(['files', 'note']);
    // Removing: no step-up.
    expect((await patch(u.cookie, r.id, { accept: ['files'] })).status).toBe(200);
    // Adding a note: no step-up either.
    expect((await patch(u.cookie, r.id, { accept: ['files', 'note'] })).status).toBe(200);
    // Links and credentials: the step-up.
    for (const k of ['url', 'secret']) {
      expect(await errorOf(await patch(u.cookie, r.id, { accept: ['files', 'note', k] })), k).toBe('reauth_required');
      expect(await errorOf(await patch(u.cookie, r.id, { accept: ['files', 'note', k], current: proofFor('wrong password') })), k).toBe('wrong_password');
    }
    expect((await patch(u.cookie, r.id, { accept: ALL, ...CONFIRM })).status).toBe(200);
    expect((await (await openLink(r, freshIp())).json()).accept).toEqual(ALL);
    // Empty or unknown: refused.
    expect((await patch(u.cookie, r.id, { accept: [] })).status).toBe(400);
    expect((await patch(u.cookie, r.id, { accept: ['photos'] })).status).toBe(400);
    // An API key with "manage": may narrow, may add a note, never widen.
    const key = (await (await fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body: { name: 'm', scopes: ['manage'], current: proofFor(USER_PW) } })).json()).key;
    const api = (body) => fetchJson(`/api/private/shares/${r.id}`, { method: 'PATCH', body, headers: { authorization: `Bearer ${key}` } });
    expect((await api({ accept: ['note'] })).status).toBe(200);
    expect((await api({ accept: ['note'] })).status).toBe(200);
    const w = await api({ accept: ['note', 'secret'] });
    expect(w.status).toBe(403);
    expect(await w.json()).toMatchObject({ error: 'step_up_required', weakens: ['accept'] });
    // The API limits hold too: a kind the API channel does not allow is not added through it.
    expect((await limits(u.id, { reverseText: false }, 'api')).status).toBe(200);
    expect((await patch(u.cookie, r.id, { accept: ['url'], ...CONFIRM })).status).toBe(200);
    expect(await errorOf(await api({ accept: ['url', 'note'] }))).toBe('receive_kind_disabled');
    // The change is in the activity log, with what it accepts (never any content).
    const audit = (await (await fetchJson(`/api/private/admin/audit?user=${u.id}`, { cookie: oc })).json()).rows;
    expect(audit.some((e) => e.action === 'share.updated' && e.detail.includes('accept=url'))).toBe(true);
  });

  it('a kind the role does not allow is never added; one the link has may stay while the others change', async () => {
    const u = await everything('rt-edit-role');
    const r = await newReverse(u.cookie, { accept: ['files', 'url'] });
    await driveLimits(u.id, { reverseUrl: false, reverseSecret: false });
    expect(await errorOf(await patch(u.cookie, r.id, { accept: ['files', 'url', 'secret'], ...CONFIRM }))).toBe('receive_kind_disabled');
    // Keeping the link while adding a note: allowed (its uploads stay refused while the role says so).
    expect((await patch(u.cookie, r.id, { accept: ['files', 'note', 'url'] })).status).toBe(200);
    expect((await listed(u.cookie, r.id)).accept).toEqual(['files', 'note', 'url']);
    expect((await (await openLink(r, freshIp())).json()).accept).toEqual(['files', 'note']);
    // The owner changing it directly: never what it accepts.
    expect(await errorOf(await fetchJson(`/api/private/admin/shares/${r.id}`, { method: 'PATCH', cookie: oc, body: { accept: ['files'] } }))).toBe('user_only');
  });

  it('weakening() names "accept" only for what adds files, links or credentials', () => {
    const cur = { expires: 1, views: 1, password: false, captcha: false, accept: ['note'] };
    expect(weakening({ accept: ['note'] }, cur)).toEqual([]);
    expect(weakening({ accept: ['files', 'note'] }, cur)).toEqual(['accept']);
    expect(weakening({ accept: ['url'] }, cur)).toEqual(['accept']);
    expect(weakening({ accept: ['secret'] }, { ...cur, accept: undefined })).toEqual(['accept']); // a link from before: files only
    expect(weakening({ accept: ['note'] }, { ...cur, accept: ['files'] })).toEqual([]);
    expect(weakening({ accept: RECEIVE_KINDS }, { ...cur, accept: RECEIVE_KINDS })).toEqual([]);
  });
});

describe('take-in failures: the reasons for what breaks the link\'s rules', () => {
  it('the user\'s browser may record type, size and kind (audit A-3), listed with the reason; others are refused', async () => {
    const u = await everything('rt-fail');
    const r = await newReverse(u.cookie, { accept: ['note'] });
    const ip = freshIp();
    const nodes = [];
    for (let i = 0; i < 3; i++) nodes.push((await itemSession(r, 'note', { text: `n${i}` }, { ip })).sent.node);
    const mark = (id, reason) => fetchJson(`/api/private/drive/received/${id}/failed`, { method: 'POST', cookie: u.cookie, headers: intent, body: { reason } });
    expect((await mark(nodes[0], 'bogus')).status).toBe(400);
    for (const [i, reason] of ['type', 'size', 'kind'].entries()) expect((await mark(nodes[i], reason)).status, reason).toBe(200);
    const failed = (await received(u.cookie, '?failed=1')).items;
    expect(failed.map((x) => x.reason).sort()).toEqual(['kind', 'size', 'type']);
    // The rules come with each link's key for the browser to hold what it opens to them.
    const r2 = await newReverse(u.cookie, { accept: ['files', 'note'], maxFileBytes: 10, types: { mode: 'allow', rules: ['ext:pdf'] } });
    await itemSession(r2, 'note', { text: 'x' }, { ip });
    const k = (await received(u.cookie)).keys.find((x) => x.id === r2.id);
    expect(k).toMatchObject({ accept: ['files', 'note'], maxFileBytes: 10, types: { mode: 'allow', rules: ['ext:pdf'] } });
  });
});

describe('audit RT-1: each item carries its session\'s declared kind; take-in gets the link\'s kinds as the role allows now', () => {
  it('a modified uploader declaring one kind and sending another: the item carries the declared kind (sealed at rest), for the browser to refuse', async () => {
    const u = await everything('rt1-declared');
    const r = await newReverse(u.cookie, { accept: ALL });
    const ip = freshIp();
    // PoC A1: declares files, sends an item marked "note" (a note bigger than a note may be is only refused at take-in).
    const g1 = await grantAs(r, 'files', ip);
    const a1 = await send(r, g1, { ip, path: 'Note', bytes: utf8('x'.repeat(4096)), item: { kind: 'note', fmt: 'plaintext' } });
    // PoC A3: declares a note, sends a plain file.
    const g3 = await grantAs(r, 'note', ip);
    const a3 = await send(r, g3, { ip, path: 'smuggled.bin', bytes: utf8('MZ binary'), type: 'application/octet-stream' });
    const got = await received(u.cookie);
    const byId = new Map(got.items.map((x) => [x.id, x]));
    expect(byId.get(a1.node).declared).toBe('files');
    expect(byId.get(a3.node).declared).toBe('note');
    // At rest: sealed with the wrap under the user's field layer (no plaintext kind).
    const stored = await runInDurableObject(driveOf(u.id), (i, st) => st.storage.sql.exec('SELECT fk FROM nodes WHERE id = ?', a3.node).one().fk);
    expect(stored).not.toMatch(/declared|note/);
  });

  it('PoC B2: once the role drops credentials, the link\'s kinds as take-in gets them no longer include them', async () => {
    const u = await everything('rt1-role');
    const r = await newReverse(u.cookie, { accept: ['note', 'secret'] });
    const ip = freshIp();
    await itemSession(r, 'note', { text: 'kept' }, { ip });
    expect((await received(u.cookie)).keys.find((k) => k.id === r.id).accept).toEqual(['note', 'secret']);
    await driveLimits(u.id, { reverseSecret: false });
    // A "note" session carrying a credential: the server cannot tell; the browser refuses it (kind), as the role now says.
    const g = await grantAs(r, 'note', ip);
    await sendItem(r, g, 'secret', { username: 'synthetic' }, { ip });
    expect((await received(u.cookie)).keys.find((k) => k.id === r.id).accept).toEqual(['note']);
  });
});

describe('audit RT-3: a Drive share records what its sender\'s role allowed', () => {
  async function driveShare(cookie, node) {
    const manifest = { v: 3, kind: 'refs', entries: [{ path: 'n.md', size: 10, type: 'text/markdown', mtime: 0, ref: 0, fk: b64urlFromBytes(randomBytes(32)), item: { kind: 'note', fmt: 'markdown' } }], dirs: [] };
    const { body, fragment } = await encryptPaste({ text: JSON.stringify(manifest), fmt: 'files', expire: '1h' });
    const res = await fetchJson('/api/private/drive/shares', { method: 'POST', cookie, body: { nodes: [node], views: null, expire: '1h', paste: body } });
    expect(res.status, await res.clone().text()).toBe(201);
    const { id } = await res.json();
    const ip = freshIp();
    const head = await (await fetchJson(`/api/file/${id}`, { ip })).json();
    const { headers } = await proofHeaders(head.adata, fragment, '');
    return (await (await fetchJson(`/api/file/${id}/open`, { method: 'POST', headers, ip })).json()).kinds;
  }
  it('open returns { note, url, secret } as the role was when the share was made (the markers are the sender\'s own)', async () => {
    const u = await receiver('rt3-kinds');
    const f = await uploadFile(u.cookie, 'root', 10);
    expect(await driveShare(u.cookie, f.id)).toEqual({ note: true, url: false, secret: false }); // Default: links and credentials off
    await driveLimits(u.id, { url: true, secret: true });
    expect(await driveShare(u.cookie, f.id)).toEqual({ note: true, url: true, secret: true });
    await driveLimits(u.id, { text: false });
    expect(await driveShare(u.cookie, f.id)).toEqual({ note: false, url: false, secret: false });
  });
});

describe('the uploader page reads what the link accepts', () => {
  it('open sends the kinds, in the pages\' order, and nothing about the role', async () => {
    const u = await everything('rt-open');
    const r = await newReverse(u.cookie, { accept: ['secret', 'files'] });
    const head = await (await rv(r.id, '/open', { headers: { 'x-link-proof': await linkProof(r.pub) }, ip: freshIp() })).json();
    expect(head.accept).toEqual(['files', 'secret']);
    expect(JSON.stringify(head)).not.toMatch(/reverseUrl|reverseSecret|kinds/);
    // Taking one in: the take-in route does not care what it is (the browser seals its kind).
    const { sent } = await itemSession(r, 'secret', { username: 'synthetic' }, { ip: freshIp() });
    expect((await received(u.cookie)).items.some((x) => x.id === sent.node)).toBe(true);
    const take = await fetchJson(`/api/private/drive/received/${sent.node}`, { method: 'POST', cookie: u.cookie, headers: intent, body: {} });
    expect(take.status).toBe(400);
  });
});

describe('a Receive link on a folder deeper than the role allows', () => {
  it('is refused (403 folder_too_deep, with the limit); a folder within it, and the root, take one; the id stays free', async () => {
    const u = await receiver('rt-deep');
    // Folders first, with no limit (the Drive may already hold deeper ones than a later limit allows).
    const a = await mkdir(u.cookie, 'root');
    const b = await mkdir(u.cookie, a.id);
    expect([a.res.status, b.res.status]).toEqual([201, 201]);
    await driveLimits(u.id, { driveEnabled: true, reverseEnabled: true, maxFolderDepth: 1 });
    const deep = await newReverse(u.cookie, { folder: b.id });
    expect(deep.res.status).toBe(403);
    expect(await deep.res.json()).toMatchObject({ error: 'folder_too_deep', max: 1 });
    expect(await listed(u.cookie, deep.id)).toBeUndefined();
    // Level 1 and the root are within the limit; the refused link's id can be used again.
    expect((await newReverse(u.cookie, { folder: a.id, id: deep.id })).res.status).toBe(201);
    expect((await newReverse(u.cookie, { folder: 'root' })).res.status).toBe(201);
    // No limit: any folder.
    await driveLimits(u.id, { driveEnabled: true, reverseEnabled: true, maxFolderDepth: null });
    expect((await newReverse(u.cookie, { folder: b.id })).res.status).toBe(201);
  });
});

describe('audit RT2: the take-in, held to the declared kind by the server too', () => {
  const take = async (cookie, node, parent = 'root') => {
    const res = await takeInAny(cookie, node, parent);
    return { status: res.status, error: res.status === 200 ? null : (await res.json()).error };
  };

  it('RT2-1: the role drops every kind a files-only link accepts — its waiting file is listed with accept [] and refused (409 kind_not_accepted); allowed again, it goes in', async () => {
    const u = await everything('rt2-none');
    const r = await newReverse(u.cookie, { accept: ['files'] });
    const ip = freshIp();
    const sent = await send(r, await grantAs(r, 'files', ip), { ip });
    await driveLimits(u.id, { reverseFiles: false });
    expect((await received(u.cookie)).keys.find((k) => k.id === r.id).accept).toEqual([]);
    expect(await take(u.cookie, sent.node)).toEqual({ status: 409, error: 'kind_not_accepted' });
    await driveLimits(u.id, { reverseFiles: true });
    expect(await take(u.cookie, sent.node)).toEqual({ status: 200, error: null });
  });

  it('the declared kind must be one the link accepts and the role allows now (a note once notes are off; a kind the link dropped)', async () => {
    const u = await everything('rt2-kind');
    const r = await newReverse(u.cookie, { accept: ['note', 'url'] });
    const ip = freshIp();
    const { sent: note } = await itemSession(r, 'note', { text: 'synthetic' }, { ip });
    const { sent: link } = await itemSession(r, 'url', { url: 'https://example.com/' }, { ip });
    await driveLimits(u.id, { reverseText: false });
    expect(await take(u.cookie, note.node)).toEqual({ status: 409, error: 'kind_not_accepted' });
    expect((await patch(u.cookie, r.id, { accept: ['note'] })).status).toBe(200);
    expect(await take(u.cookie, link.node)).toEqual({ status: 409, error: 'kind_not_accepted' });
    await driveLimits(u.id, { reverseText: true });
    expect(await take(u.cookie, note.node)).toEqual({ status: 200, error: null });
  });

  it('RT2-4: a wrap stored in plain text (not sealed at rest) is never trusted: listed as unsealed with no declared kind, and refused', async () => {
    const u = await everything('rt2-plain');
    const r = await newReverse(u.cookie, { accept: ['files'] });
    const ip = freshIp();
    const sent = await send(r, await grantAs(r, 'files', ip), { ip });
    // Someone with write access to the Drive's storage swaps the sealed wrap for plain JSON.
    await runInDurableObject(driveOf(u.id), (i, st) => st.storage.sql.exec('UPDATE nodes SET fk = ? WHERE id = ?', JSON.stringify({ kind: 'rs', data: 'x', declared: 'files' }), sent.node));
    const it = (await received(u.cookie)).items.find((x) => x.id === sent.node);
    expect(it).toMatchObject({ unsealed: true, unreadable: true, declared: null, fk: null });
    expect(await take(u.cookie, sent.node)).toEqual({ status: 409, error: 'kind_not_accepted' });
  });

  it('RT2-2: a link\'s folder moved deeper than the role allows takes nothing in (403 folder_too_deep); a new link there is refused', async () => {
    const u = await everything('rt2-moved');
    const a = await mkdir(u.cookie, 'root');
    const b = await mkdir(u.cookie, 'root');
    const c = await mkdir(u.cookie, b.id);
    const r = await newReverse(u.cookie, { folder: a.id, accept: ['files'] });
    expect(r.res.status).toBe(201);
    const ip = freshIp();
    const sent = await send(r, await grantAs(r, 'files', ip), { ip });
    // The folder moves to level 3 (no limit yet), then the role allows 2.
    expect((await fetchJson(`/api/private/drive/nodes/${a.id}`, { method: 'PATCH', cookie: u.cookie, headers: intent, body: { parent: c.id } })).status).toBe(200);
    await driveLimits(u.id, { maxFolderDepth: 2 });
    const res = await takeInAny(u.cookie, sent.node, a.id);
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: 'folder_too_deep', max: 2 });
    expect((await newReverse(u.cookie, { folder: a.id })).res.status).toBe(403);
  });
});
