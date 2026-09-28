// receive-types.test.js (DOM) — a "Receive" link that accepts notes, links
// and credentials as well as files (docs/REVERSE.md §3.1, §8): the uploader
// page (public/js/reverse.js) offers only what the link accepts, as tabs,
// with the composer's note editor and format, the link field and the
// credential form (with its warning), encrypts each to the link's key and
// declares only its kind; the Drive (public/dashboard/js/drive-app.js) takes
// them in with a kind of their own, lists them with an icon and a label, and
// opens each in the regular shares' viewers (the link under the user's URL
// rules, the credential masked); downloads as text; the Receive dialog and
// Edit choose what a link accepts (widening asks the step-up; a note does
// not); no stray "null" / "undefined" text. Synthetic data only.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mountUploader, limitsText, sendTitle, CREDENTIAL_WARNING } from '../public/js/reverse.js';
import { startDrive, reverseOptions, acceptWords } from '../public/dashboard/js/drive-app.js';
import { reverseEditForm, reverseEditPatch, weakensLink, acceptChoice } from '../public/dashboard/js/reverse-edit.js';
import * as drive from '../public/js/driveclient.js';
import { setReverseStretcher, createReverseKey, linkProof, passwordGate, openUpload, fragmentOf, newReverseId } from '../public/js/reversekeys.js';
import { clearSessionKey, clearImpersonationKeys, sealLinkKey, openName as openSealedName, sealName, sealDek, newSalt } from '../public/js/drivekeys.js';
import { hkdf32 } from '../public/js/crypto.js';
import { utf8, fromUtf8, bytesFromB64url, b64urlFromBytes } from '../public/js/bytes.js';
import { CHUNK, decryptChunk, importFileKey } from '../public/js/files.js';
import { buildSecret } from '../public/js/sharetypes.js';
import { nameDate, SECRET_EXPORT_WARNING, encodeItem, ITEM_MAX_BYTES } from '../public/js/receivekinds.js';
import { refChunks } from '../public/js/refsmanifest.js';
import { revokeShare } from '../public/js/api.js';
import { fakeServer, seedTree, seedReceived } from './drive-fake-server.js';

setReverseStretcher(async (pw, salt) => hkdf32(pw, salt, utf8('dom-stretch')));

const until = async (fn, ms = 5000) => {
  const t0 = Date.now();
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 10));
  }
};
const $ = (s) => document.querySelector(s);
const sha = async (b64) => {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', bytesFromB64url(b64)));
  return btoa(String.fromCharCode(...d)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const type = (el, v) => { el.value = v; el.dispatchEvent(new Event('input', { bubbles: true })); };
/** Text nodes reading "null" or "undefined" (a nullish child passed to append / replaceChildren). */
function strayText(root = document.body) {
  const out = [];
  const walk = (n) => {
    for (const c of n.childNodes) {
      if (c.nodeType === 3 && ['null', 'undefined'].includes(c.textContent.trim())) out.push(`${c.textContent.trim()} in <${n.nodeName.toLowerCase()}${n.id ? `#${n.id}` : ''}>`);
      else if (c.nodeType === 1) walk(c);
    }
  };
  walk(root);
  return out;
}
/** Every form control with no label (a <label for>, a wrapping label, aria-label or aria-labelledby). */
const unlabelled = (root = document.body) => [...root.querySelectorAll('input:not([type="file"]):not([hidden]), select, textarea')]
  .filter((el) => !el.getAttribute('aria-label') && !el.getAttribute('aria-labelledby') && !el.closest('label') && !(el.id && root.querySelector(`label[for="${el.id}"]`)))
  .map((el) => el.id || el.outerHTML.slice(0, 60));

beforeEach(() => { document.body.replaceChildren(); clearSessionKey(); clearImpersonationKeys(); });
afterEach(() => { vi.restoreAllMocks(); });

// ── the uploader page ─────────────────────────────────────────────────────────

/** A stand-in for /api/reverse/<id>/… that knows what the link accepts. */
async function reverseServer({ accept = ['files', 'note', 'url', 'secret'], password = null, limits = {} } = {}) {
  const id = newReverseId();
  const { pub, privateKey } = await createReverseKey();
  const gate = password ? await passwordGate(password, pub) : null;
  const S = { id, pub, privateKey, files: new Map(), chunks: new Map(), begins: [], done: 0, requests: [] };
  const ok = (data, st = 200) => ({ ok: st < 400, status: st, type: 'basic', json: async () => data });
  const fail = (st, error, extra = {}) => ok({ error, message: error, ...extra }, st);
  globalThis.fetch = vi.fn(async (url, init = {}) => {
    const p = new URL(url, 'https://bin.example').pathname;
    const h = init.headers || {};
    const body = typeof init.body === 'string' ? JSON.parse(init.body) : init.body;
    S.requests.push({ p, method: init.method || 'GET', headers: h, body });
    let m;
    if ((m = p.match(/^\/api\/reverse\/([^/]+)\/(open|begin|done|files)(?:\/([^/]+)(?:\/(chunk|finalize)(?:\/(\d+))?)?)?$/))) {
      if (m[1] !== id) return fail(404, 'not_found');
      if ((m[2] === 'open' || m[2] === 'begin') && h['x-link-proof'] !== await linkProof(pub)) return fail(403, 'bad_link');
      if (m[2] === 'open') {
        return ok({ note: null, password: gate ? { salt: gate.salt, t: gate.t } : null, expires: 2000000000, captcha: false, accept: S.accept ?? accept,
          limits: { maxFiles: null, maxBytes: null, maxFileBytes: null, types: null, filesLeft: null, bytesLeft: null, ...limits } });
      }
      if (m[2] === 'begin') {
        S.begins.push({ headers: h, body });
        if (S.refuse) return fail(403, 'kind_not_accepted', { kind: body?.type });
        if (!accept.includes(body?.type ?? 'files')) return fail(403, 'kind_not_accepted', { kind: body?.type });
        if (gate && !h['x-key-proof']) return fail(401, 'password_required');
        if (gate && await sha(h['x-key-proof']) !== gate.ph) return fail(403, 'bad_password');
        return ok({ grant: 'G'.repeat(43), expires: 2000000000 });
      }
      if (m[2] === 'done') { S.done++; return ok({ files: S.files.size, bytes: 0 }); }
      if (m[2] === 'files' && !m[3]) {
        S.files.set(body.id, { ...body, finalized: false });
        return ok({ id: body.id, uploadToken: 'T'.repeat(43), chunks: Math.ceil(body.size / CHUNK) }, 201);
      }
      if (m[4] === 'chunk') { S.chunks.set(`${m[3]}/${m[5]}`, new Uint8Array(await new Response(init.body).arrayBuffer())); return ok({ ok: true }); }
      if (m[4] === 'finalize') { S.files.get(m[3]).finalized = true; return ok({ ok: true }); }
    }
    return fail(404, `unrouted ${p}`);
  });
  S.location = { pathname: `/r/${id}`, hash: `#${fragmentOf(pub)}` };
  /** The one item sent: opened with the link's private key, its content decrypted. */
  S.item = async () => {
    const f = [...S.files.values()].at(-1);
    const got = await openUpload(privateKey, id, { id: f.id, name: f.name, meta: f.meta, fk: { kind: 'rs', data: f.wrap } });
    const key = await importFileKey(btoa(String.fromCharCode(...got.fk)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''));
    const n = Math.ceil(f.size / CHUNK);
    let text = '';
    for (let i = 0; i < n; i++) text += fromUtf8(await decryptChunk(key, i, n, S.chunks.get(`${f.id}/${i}`)));
    return { ...got, text, body: f };
  };
  return S;
}
function page() {
  const main = document.createElement('main');
  main.id = 'main';
  const root = document.createElement('div');
  root.id = 'reverse-app';
  main.appendChild(root);
  document.body.replaceChildren(main);
  return root;
}
const tabs = () => [...document.querySelectorAll('#reverse-tabs [role="tab"]')];
const panelShown = (k) => !$(`#reverse-panel-${k}`).hidden;

describe('the uploader page: what the link accepts', () => {
  it('only the accepted kinds, as a tablist (one Tab stop, arrow keys); the heading and the title say what can be sent', async () => {
    let S = await reverseServer({ accept: ['note', 'secret'] });
    await mountUploader(page(), { location: S.location });
    expect(tabs().map((t) => t.textContent)).toEqual(['Note', 'Credential']);
    expect($('#reverse-tabs').getAttribute('aria-label')).toBe('What to send');
    expect($('h1').textContent).toBe('Send a note or a credential');
    expect(document.title).toBe('Send a note or a credential · secbin');
    expect(panelShown('note')).toBe(true);
    expect($('#reverse-panel-files')).toBeNull();
    expect($('#reverse-panel-url')).toBeNull();
    expect(tabs().map((t) => t.tabIndex)).toEqual([0, -1]);
    tabs()[0].focus();
    tabs()[0].dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true }));
    expect(document.activeElement).toBe(tabs()[1]);
    expect(panelShown('secret')).toBe(true);
    expect(panelShown('note')).toBe(false);
    expect(tabs()[1].getAttribute('aria-selected')).toBe('true');
    expect($('#reverse-panel-secret').getAttribute('role')).toBe('tabpanel');
    expect($('#reverse-send').textContent).toBe('Send credential');
    expect(unlabelled()).toEqual([]);
    expect(strayText()).toEqual([]);
    // Files only (every link from before): no tabs, as before.
    S = await reverseServer({ accept: ['files'] });
    await mountUploader(page(), { location: S.location });
    expect($('#reverse-tabs')).toBeNull();
    expect($('h1').textContent).toBe('Send files');
    expect($('#reverse-send').textContent).toBe('Send files');
    expect($('#reverse-limits').textContent).toMatch(/^This link accepts any files\./);
    // Everything: four tabs, and the limits count items.
    S = await reverseServer({ limits: { filesLeft: 3, maxFileBytes: 1024 } });
    await mountUploader(page(), { location: S.location });
    expect(tabs().map((t) => t.textContent)).toEqual(['Files', 'Note', 'Link', 'Credential']);
    expect($('#reverse-limits').textContent).toMatch(/^This link accepts 3 more items at most · 1\.0 KB per file\./);
    expect(unlabelled()).toEqual([]);
    expect(strayText()).toEqual([]);
  });

  it('a note: the composer\'s formats and an optional title; encrypted to the link, declared only as "note"', async () => {
    const S = await reverseServer();
    await mountUploader(page(), { location: S.location });
    tabs()[1].click();
    expect([...$('#reverse-note-fmt').options].map((o) => [o.value, o.textContent])).toEqual([['plaintext', 'Plain text'], ['markdown', 'Markdown'], ['code', 'Code']]);
    expect($('label[for="reverse-note-text"]').textContent).toBe('Note');
    expect($('#reverse-send').disabled).toBe(true);
    type($('#reverse-note-title'), 'Meeting minutes');
    $('#reverse-note-fmt').value = 'markdown';
    type($('#reverse-note-text'), '# Minutes\n\n- **synthetic** item');
    expect($('#reverse-send').disabled).toBe(false);
    $('#reverse-send').click();
    await until(() => !$('#reverse-done').hidden);
    expect($('#reverse-done').textContent).toMatch(/^Sent the note, encrypted\. The person who shared this link will find it in their Drive\./);
    expect(S.begins).toHaveLength(1);
    expect(S.begins[0].body).toEqual({ type: 'note' });
    const got = await S.item();
    expect(got.text).toBe('# Minutes\n\n- **synthetic** item');
    expect(got.item).toEqual({ kind: 'note', fmt: 'markdown', title: 'Meeting minutes' });
    expect(got.type).toBe('text/markdown');
    expect(got.body.types).toBeUndefined(); // no file-type declaration for a note
    // Nothing on the wire says what it is or holds.
    const wire = JSON.stringify(S.requests.filter((x) => !x.p.endsWith('/begin')).map((x) => x.body ?? null));
    for (const w of ['Minutes', 'markdown', 'synthetic', '"note"']) expect(wire).not.toContain(w);
    // The form is empty again; focus on its first field.
    expect($('#reverse-note-text').value).toBe('');
    expect($('#reverse-note-title').value).toBe('');
    expect(document.activeElement).toBe($('#reverse-note-title'));
    expect(S.done).toBe(1);
  });

  it('a link: checked as a recipient checks it, the destination spelled out; a bad one refused with its field marked', async () => {
    const S = await reverseServer({ accept: ['url'] });
    await mountUploader(page(), { location: S.location });
    expect($('#reverse-tabs')).toBeNull();
    type($('#reverse-link-in'), 'javascript:alert(1)');
    expect($('#reverse-link-in').getAttribute('aria-invalid')).toBe('true');
    expect($('#reverse-link-host').textContent).toMatch(/can never be shared/);
    $('#reverse-send').click();
    await until(() => !$('#reverse-msg').hidden);
    expect($('#reverse-msg').textContent).toMatch(/can never be shared/);
    expect($('#reverse-link-in').getAttribute('aria-describedby')).toContain('reverse-msg');
    expect(S.begins).toHaveLength(0);
    type($('#reverse-link-in'), 'https://xn--80ak6aa92e.com/path?q=1');
    expect($('#reverse-link-host').textContent).toMatch(/Destination: .*international characters/);
    type($('#reverse-link-in'), 'https://example.com/doc');
    $('#reverse-send').click();
    await until(() => !$('#reverse-done').hidden);
    const got = await S.item();
    expect(got.text).toBe('https://example.com/doc');
    expect(got.item).toEqual({ kind: 'url' });
    expect(S.begins[0].body).toEqual({ type: 'url' });
  });

  it('a credential: the regular fields, masked with Show; the warning that the server can decrypt it; cleared after sending', async () => {
    const S = await reverseServer({ accept: ['secret'] });
    await mountUploader(page(), { location: S.location });
    const warn = $('#reverse-sec-warning');
    expect(warn.textContent).toBe(CREDENTIAL_WARNING);
    expect(warn.textContent).toMatch(/^The recipient’s server can decrypt this\./);
    expect(warn.getAttribute('role')).toBe('note');
    expect([...document.querySelectorAll('#reverse-panel-secret label.field-label')].map((l) => l.textContent)).toEqual(['Title', 'User name', 'Password', 'Sign-in URL', 'One-time-code seed', 'Notes']);
    expect($('#reverse-sec-password').type).toBe('password');
    $('#reverse-sec-password-show').click();
    expect($('#reverse-sec-password').type).toBe('text');
    expect($('#reverse-sec-password-show').getAttribute('aria-pressed')).toBe('true');
    type($('#reverse-sec-title'), 'Staging database');
    type($('#reverse-sec-username'), 'synthetic-user');
    type($('#reverse-sec-password'), 'not-a-real-password');
    $('#reverse-send').click();
    await until(() => !$('#reverse-done').hidden);
    const got = await S.item();
    expect(JSON.parse(got.text)).toEqual({ v: 1, title: 'Staging database', username: 'synthetic-user', password: 'not-a-real-password' });
    expect(got.item).toEqual({ kind: 'secret' });
    for (const k of ['title', 'username', 'password']) expect($(`#reverse-sec-${k}`).value).toBe('');
    expect($('#reverse-sec-password').type).toBe('password');
    expect($('#reverse-sec-password-show').getAttribute('aria-pressed')).toBe('false');
    const wire = JSON.stringify(S.requests.map((x) => x.body ?? null));
    for (const w of ['synthetic-user', 'not-a-real-password', 'Staging']) expect(wire).not.toContain(w);
  });

  it('the password gates every kind; the limits apply before anything is sent; the file types are for files only', async () => {
    let S = await reverseServer({ password: 'gate words', limits: { types: { mode: 'allow', rules: ['ext:pdf'] } } });
    await mountUploader(page(), { location: S.location });
    tabs()[1].click();
    type($('#reverse-note-text'), 'plain words');
    $('#reverse-send').click();
    await until(() => !$('#reverse-msg').hidden);
    expect($('#reverse-msg').textContent).toMatch(/Enter the password/);
    expect(S.begins).toHaveLength(0);
    $('#reverse-password').value = 'gate words';
    $('#reverse-send').click();
    await until(() => !$('#reverse-done').hidden);
    expect(S.begins[0].headers['x-key-proof']).toBeTruthy();
    expect((await S.item()).body.types).toBeUndefined(); // "only .pdf files" does not apply to a note
    // Too large for what the link has left: refused before a session starts.
    S = await reverseServer({ limits: { bytesLeft: 3000 } });
    await mountUploader(page(), { location: S.location });
    tabs()[1].click();
    type($('#reverse-note-text'), 'x'.repeat(1000));
    $('#reverse-send').click();
    await until(() => !$('#reverse-msg').hidden);
    expect($('#reverse-msg').textContent).toMatch(/too large for what this link has left/);
    expect($('#reverse-note-text').getAttribute('aria-invalid')).toBe('true');
    expect(S.begins).toHaveLength(0);
  });

  it('a kind the link stopped accepting (its user\'s role changed) is refused with a plain reason', async () => {
    const S = await reverseServer();
    S.refuse = true;
    await mountUploader(page(), { location: S.location });
    tabs()[2].click();
    type($('#reverse-link-in'), 'https://example.com/');
    $('#reverse-send').click();
    await until(() => !$('#reverse-msg').hidden);
    expect($('#reverse-msg').textContent).toBe('This link does not accept links now. Ask the person who shared it.');
    expect($('#reverse-link-in').value).toBe('https://example.com/'); // kept, to send another way
    expect(strayText()).toEqual([]);
  });

  it('the pure helpers', () => {
    expect(sendTitle(['files'])).toBe('Send files');
    expect(sendTitle(['files', 'note', 'url'])).toBe('Send files, a note or a link');
    expect(limitsText({ filesLeft: 1 }, ['note'])).toBe('This link accepts 1 more item at most.');
    expect(limitsText({ maxFileBytes: 10, types: { mode: 'allow', rules: ['ext:pdf'] } }, ['note'])).toBe('This link sets no limits on what you send.');
    expect(acceptWords(['files', 'note', 'secret'])).toBe('files, notes or credentials');
  });
});

// ── the Drive ────────────────────────────────────────────────────────────────

let S;
let ids;
async function server() {
  S = fakeServer({ capacity: 50 * 1024 * 1024 });
  globalThis.fetch = S.fetch;
  ids = await seedTree(S, { Inbox: {}, 'readme.txt': utf8('hi') });
  return S;
}
const PROFILE = {
  limits: { maxViews: 100, allowUnlimitedViews: true, maxExpireSec: null, files: true, text: true, url: true, secret: true, reverseMaxBytes: 1024 ** 3,
    reverseFiles: true, reverseText: true, reverseUrl: true, reverseSecret: true, urlRules: ['scheme:https://'] },
  caps: { driveEnabled: true, reverseEnabled: true }, viewer: { enabled: false },
};
function mountPoint() {
  const mount = document.createElement('div');
  document.body.replaceChildren(document.createElement('main'), mount);
  document.body.firstChild.id = 'main';
  const t = document.createElement('div');
  t.id = 'toast';
  document.body.appendChild(t);
  return mount;
}
const confirm = async (input) => {
  const v = input.value;
  input.value = '';
  if (!v) throw new Error('Enter your current password.');
  return { current: `proof:${v}` };
};
const deps = (profile = PROFILE) => ({ drive, profile, user: S.user, confirm, canUsePasskey: async () => false, revoke: revokeShare });
const dialog = () => document.querySelector('.drive-dialog [role="dialog"]');
const button = (root, text) => [...root.querySelectorAll('button')].find((b) => b.textContent.trim() === text);
const rowOf = (name) => [...document.querySelectorAll('#drive-rows tr')].find((tr) => tr.children[1].textContent.includes(name));
async function existingReverse(folder = 'root', accept = ['files', 'note', 'url', 'secret']) {
  const id = newReverseId();
  const { pub, privateKey } = await createReverseKey();
  const mek = S.current().id;
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey));
  const priv = await sealLinkKey(await S.kekOf(mek), { userId: S.user.id, mekId: mek, linkId: id }, pkcs8);
  S.reverse.push({ id, folder, label: 'inbox', priv, mek, status: 'active', files: 0, bytes: 0, created: 1700000000, expires: 2000000000, accept });
  return { id, pub };
}
async function fieldOf(id, field) {
  const n = S.nodes.get(id);
  const at = { userId: S.user.id, mekId: n.mek, salt: n.ks };
  const v = field === 'name' ? n.name : n.meta;
  return fromUtf8(await openSealedName(await S.kekOf(n.mek), at, field, typeof v === 'string' ? JSON.parse(v) : v));
}
/** Seed a received note, link and credential (and a file) through link `r`. */
async function seedKinds(r, folder) {
  const note = encodeItem('note', { text: '# Hello\n\nSome **bold** words.', fmt: 'markdown', title: 'Weekly: plan / notes' });
  const link = encodeItem('url', { url: 'ssh://example.com/repo' });
  const web = encodeItem('url', { url: 'https://example.com/doc' });
  const secret = encodeItem('secret', { title: 'DB', username: 'synthetic', password: 'not-real-pw' });
  return {
    note: await seedReceived(S, { rid: r.id, pub: r.pub, folder, path: 'Note', bytes: note.bytes, type: note.type, item: note.meta, created: 1700000100 }),
    link: await seedReceived(S, { rid: r.id, pub: r.pub, folder, path: 'Link', bytes: link.bytes, item: link.meta, created: 1700000200 }),
    web: await seedReceived(S, { rid: r.id, pub: r.pub, folder, path: 'Link', bytes: web.bytes, item: web.meta, created: 1700000250 }),
    secret: await seedReceived(S, { rid: r.id, pub: r.pub, folder, path: 'Credential', bytes: secret.bytes, type: secret.type, item: secret.meta, created: 1700000300 }),
    file: await seedReceived(S, { rid: r.id, pub: r.pub, folder, path: 'deep/a.txt', bytes: utf8('file body'), created: 1700000400 }),
  };
}

describe('the Drive: received notes, links and credentials', () => {
  it('takes them in as items of their own kind (sealed), in the link\'s folder, named from the title or kind and date; says what arrived', async () => {
    await server();
    const r = await existingReverse(ids.get('Inbox'));
    const seeded = await seedKinds(r, ids.get('Inbox'));
    const app = await startDrive(mountPoint(), deps());
    await app.app.received;
    expect($('#drive-received').textContent).toMatch(/New items you received were added to your folders: 1 file, 1 note, 2 links and 1 credential\./);
    // Each in the link's folder (the file keeps its folders), named as said; its kind in the sealed metadata only.
    for (const k of ['note', 'link', 'web', 'secret']) expect(S.nodes.get(seeded[k]).parent, k).toBe(ids.get('Inbox'));
    expect(await fieldOf(seeded.note, 'name')).toBe('Weekly: plan - notes'); // "/" cannot be in a name
    expect(await fieldOf(seeded.link, 'name')).toBe(`Link from ${nameDate(1700000200)}`);
    expect(await fieldOf(seeded.secret, 'name')).toBe(`Credential from ${nameDate(1700000300)}`);
    expect(JSON.parse(await fieldOf(seeded.note, 'meta'))).toMatchObject({ kind: 'note', fmt: 'markdown', type: 'text/markdown' });
    expect(JSON.parse(await fieldOf(seeded.secret, 'meta'))).toMatchObject({ kind: 'secret' });
    expect(JSON.parse(await fieldOf(seeded.file, 'meta')).kind).toBeUndefined();
    // Nothing of what they are in plain text in what the browser sent to take them in.
    const taken = JSON.stringify(S.accepted.map((x) => x.body));
    for (const w of ['note', 'secret', 'Weekly', 'markdown', 'Credential']) expect(taken).not.toContain(w);
    // Listed with an icon and a label each.
    await app.app.open(ids.get('Inbox'), { focus: true });
    const kinds = [...document.querySelectorAll('#drive-rows tr[data-item]')].map((tr) => [tr.dataset.item, tr.querySelector('.drive-kind').textContent]);
    expect(kinds.sort()).toEqual([['note', 'Note'], ['secret', 'Credential'], ['url', 'Link'], ['url', 'Link']]);
    for (const tr of document.querySelectorAll('#drive-rows tr[data-item]')) expect(tr.querySelector('.drive-kind-icon').getAttribute('aria-hidden')).toBe('true');
    expect(rowOf('deep').dataset.item).toBeUndefined();
    expect(strayText()).toEqual([]);
  });

  it('opens each with the viewer of regular shares: Markdown rendered (Raw), the link under the user\'s URL rules, the credential masked', async () => {
    await server();
    const r = await existingReverse(ids.get('Inbox'));
    const seeded = await seedKinds(r, ids.get('Inbox'));
    const app = await startDrive(mountPoint(), deps());
    await app.app.received;
    await app.app.open(ids.get('Inbox'), { focus: true });
    // The note.
    rowOf('Weekly').querySelector('button.drive-open').click();
    await until(() => dialog()?.querySelector('#drive-item-note .md'));
    expect(dialog().querySelector('.modal-title').textContent).toBe('Weekly: plan - notes');
    expect(dialog().querySelector('.modal-sub').textContent).toMatch(/not end-to-end encrypted/);
    expect(dialog().querySelector('#drive-item-note h1').textContent).toBe('Hello');
    expect(dialog().querySelector('#drive-item-note strong').textContent).toBe('bold');
    expect(dialog().querySelector('script, iframe, img')).toBeNull();
    $('#drive-item-raw').click();
    expect(dialog().querySelector('#drive-item-note pre').textContent).toBe('# Hello\n\nSome **bold** words.');
    expect($('#drive-item-raw').getAttribute('aria-pressed')).toBe('true');
    expect(strayText()).toEqual([]);
    button(dialog(), 'Close').click();
    // An ssh: link: the user's rules allow https only: spelled out, Copy only, and why.
    const sshName = `Link from ${nameDate(1700000200)}`;
    rowOf(sshName).querySelector('button.drive-open').click();
    await until(() => dialog()?.querySelector('.link-card'));
    const card = dialog().querySelector('.link-card');
    // The host is compared as a parsed URL's, never matched as a substring.
    const shown = new URL(card.querySelector('.link-full').textContent);
    expect(shown.href).toBe(new URL('ssh://example.com/repo').href);
    expect(card.querySelector('.link-host').textContent).toBe(shown.hostname);
    expect(shown.hostname).toBe('example.com');
    expect(button(card, 'Open link')).toBeUndefined();
    expect(button(card, 'Copy link')).toBeDefined();
    expect(card.textContent).toMatch(/Your account’s URL rules allow https:\/\/ links; this link is not one of them/);
    button(dialog(), 'Close').click();
    // An https link: Open, behind a confirmation; never followed on its own.
    const open = vi.spyOn(window, 'open').mockImplementation(() => null);
    rowOf(`Link from ${nameDate(1700000250)}`).querySelector('button.drive-open').click();
    await until(() => dialog()?.querySelector('.link-card'));
    const openBtn = button(dialog().querySelector('.link-card'), 'Open link');
    expect(openBtn).toBeDefined();
    expect(open).not.toHaveBeenCalled();
    openBtn.click();
    expect(open).not.toHaveBeenCalled(); // armed: a second click opens
    openBtn.click();
    expect(open).toHaveBeenCalledWith('https://example.com/doc', '_blank', 'noopener,noreferrer');
    button(dialog(), 'Close').click();
    // The credential: masked until revealed.
    rowOf('Credential from').querySelector('button.drive-open').click();
    await until(() => dialog()?.querySelector('.secret-card'));
    const pwRow = [...dialog().querySelectorAll('.secret-row')].find((x) => x.querySelector('.field-label').textContent === 'Password');
    expect(pwRow.querySelector('.secret-val').textContent).toBe('••••••••');
    expect(dialog().textContent).not.toContain('not-real-pw');
    button(pwRow, 'Reveal').click();
    expect(pwRow.querySelector('.secret-val').textContent).toBe('not-real-pw');
    expect(strayText()).toEqual([]);
    button(dialog(), 'Close').click();
    expect(seeded).toBeTruthy();
  });

  it('downloads as text: a note as .md, a link as .txt with its URL, a credential as a plain-text export after a confirmation', async () => {
    await server();
    const r = await existingReverse(ids.get('Inbox'));
    await seedKinds(r, ids.get('Inbox'));
    const app = await startDrive(mountPoint(), deps());
    await app.app.received;
    await app.app.open(ids.get('Inbox'), { focus: true });
    const saved = [];
    let blob = null;
    vi.spyOn(URL, 'createObjectURL').mockImplementation((b) => { blob = b; return 'blob:x'; });
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function click() { saved.push({ name: this.download, blob }); });
    const select = (name) => { const cb = rowOf(name).querySelector('input[type="checkbox"]'); cb.checked = true; cb.dispatchEvent(new Event('change')); };
    const unselect = (name) => { const cb = rowOf(name).querySelector('input[type="checkbox"]'); cb.checked = false; cb.dispatchEvent(new Event('change')); };
    select('Weekly');
    $('#drive-download').click();
    await until(() => saved.length === 1);
    expect(saved[0].name).toBe('Weekly: plan - notes.md');
    expect(await saved[0].blob.text()).toBe('# Hello\n\nSome **bold** words.');
    unselect('Weekly');
    select(`Link from ${nameDate(1700000250)}`);
    $('#drive-download').click();
    await until(() => saved.length === 2);
    expect(saved[1].name).toBe(`Link from ${nameDate(1700000250)}.txt`);
    expect(await saved[1].blob.text()).toBe('https://example.com/doc\n');
    unselect(`Link from ${nameDate(1700000250)}`);
    select('Credential from');
    $('#drive-download').click();
    await until(() => dialog());
    expect(dialog().querySelector('.modal-title').textContent).toMatch(/in plain text\?$/);
    expect(dialog().querySelector('.modal-sub').textContent).toContain(SECRET_EXPORT_WARNING);
    expect(saved).toHaveLength(2); // nothing yet
    $('#drive-item-download-confirm').click();
    await until(() => saved.length === 3);
    const text = await saved[2].blob.text();
    expect(text.startsWith(SECRET_EXPORT_WARNING)).toBe(true);
    expect(text).toContain('User name: synthetic');
    expect(text).toContain('Password: not-real-pw');
  });

  it('a Drive share carries them as what they are (the recipient sees the same viewers); only where the account may share links and credentials', async () => {
    await server();
    const r = await existingReverse(ids.get('Inbox'));
    const seeded = await seedKinds(r, ids.get('Inbox'));
    const app = await startDrive(mountPoint(), deps());
    await app.app.received;
    const c = app.app.client;
    await c.share([seeded.note, seeded.secret], { views: 1, expire: '1h', limits: PROFILE.limits });
    const body = S.shares.at(-1);
    expect(body).toBeTruthy();
    await expect(c.share([seeded.secret], { views: 1, expire: '1h', limits: { ...PROFILE.limits, secret: false } })).rejects.toThrow(/not allowed to share credentials/);
    await expect(c.share([seeded.web], { views: 1, expire: '1h', limits: { ...PROFILE.limits, url: false } })).rejects.toThrow(/not allowed to share links/);
    await expect(c.share([seeded.note], { views: 1, expire: '1h', limits: { ...PROFILE.limits, text: false } })).rejects.toThrow(/not allowed to share notes/);
    // No limits given (a caller that skips them): none of them is shared (RT-3; the server records the role too).
    await expect(c.share([seeded.web], { views: 1, expire: '1h' })).rejects.toThrow(/not allowed to share links/);
    await expect(c.share([seeded.note], { views: 1, expire: '1h' })).rejects.toThrow(/not allowed to share notes/);
  });
});

describe('take-in holds what arrives to the link\'s rules (audit A-3: the uploader\'s browser only declares them)', () => {
  it('a file whose real type, size or kind breaks the rules fails (listed with why, to delete); it never enters the Drive', async () => {
    await server();
    const pdfOnly = await existingReverse(ids.get('Inbox'), ['files', 'note']);
    Object.assign(S.reverse.at(-1), { types: { mode: 'allow', rules: ['ext:pdf'] }, maxFileBytes: 8 });
    const notesOnly = await existingReverse(ids.get('Inbox'), ['note']);
    const filesOnly = await existingReverse(ids.get('Inbox'), ['files']);
    const note = encodeItem('note', { text: 'a note' });
    const seeded = {
      pdf: await seedReceived(S, { rid: pdfOnly.id, pub: pdfOnly.pub, folder: ids.get('Inbox'), path: 'ok.pdf', bytes: utf8('%PDF-1'), type: 'application/pdf' }),
      exe: await seedReceived(S, { rid: pdfOnly.id, pub: pdfOnly.pub, folder: ids.get('Inbox'), path: 'payload.exe', bytes: utf8('MZ'), type: 'application/x-msdownload' }),
      html: await seedReceived(S, { rid: pdfOnly.id, pub: pdfOnly.pub, folder: ids.get('Inbox'), path: 'page.html', bytes: utf8('<b>'), type: 'application/pdf' }), // declared pdf, named .html
      big: await seedReceived(S, { rid: pdfOnly.id, pub: pdfOnly.pub, folder: ids.get('Inbox'), path: 'big.pdf', bytes: utf8('%PDF-1.7 long'), type: 'application/pdf' }),
      noteOk: await seedReceived(S, { rid: pdfOnly.id, pub: pdfOnly.pub, folder: ids.get('Inbox'), path: 'Note', bytes: note.bytes, item: note.meta }), // types are for files only
      fileToNotes: await seedReceived(S, { rid: notesOnly.id, pub: notesOnly.pub, folder: ids.get('Inbox'), path: 'sneaky.txt', bytes: utf8('x') }),
      noteToFiles: await seedReceived(S, { rid: filesOnly.id, pub: filesOnly.pub, folder: ids.get('Inbox'), path: 'Note', bytes: note.bytes, item: note.meta }),
    };
    const app = await startDrive(mountPoint(), deps());
    await app.app.received;
    const why = (k) => S.nodes.get(seeded[k]).rwhy ?? null;
    expect(Object.fromEntries(Object.keys(seeded).map((k) => [k, why(k)]))).toEqual({
      pdf: null, exe: 'type', html: 'type', big: 'size', noteOk: null, fileToNotes: 'kind', noteToFiles: 'kind',
    });
    // Only the ones that fit were taken in.
    expect((S.accepted || []).map((x) => x.id).sort()).toEqual([seeded.pdf, seeded.noteOk].sort());
    for (const k of ['exe', 'html', 'big', 'fileToNotes', 'noteToFiles']) expect(S.nodes.get(seeded[k]).rs, k).toBeTruthy();
    expect($('#drive-received').textContent).toMatch(/5 received files could not be added/);
    $('#drive-received-review').click();
    await until(() => dialog()?.querySelector('#drive-failed-table'));
    const reasons = [...dialog().querySelectorAll('#drive-failed-table td[data-label="Why"]')].map((td) => td.textContent);
    expect(reasons).toEqual(expect.arrayContaining(['its file type is one this link does not accept, or your account does not allow in the Drive', 'it is larger than this link’s largest file, or than a note, link or credential can be',
      'it is not what its sender declared, or a kind this link (or your role, now) does not accept (a file, note, link or credential)']));
    expect(strayText()).toEqual([]);
  });
});

describe('take-in holds each item to the kind its session declared, its kind\'s cap and the role now (audit RT-1)', () => {
  it('A1: declared a file, sealed as a note (past a note\'s cap): fails; a note past its cap fails even when declared', async () => {
    await server();
    const r = await existingReverse(ids.get('Inbox'), ['files', 'note']);
    const big = encodeItem('note', { text: 'x' });
    const bytes = new Uint8Array(ITEM_MAX_BYTES.note + 1).fill(0x61); // a "note" of 2 MiB + 1
    const seeded = {
      a1: await seedReceived(S, { rid: r.id, pub: r.pub, folder: ids.get('Inbox'), path: 'Note', bytes, item: big.meta, declared: 'files' }),
      over: await seedReceived(S, { rid: r.id, pub: r.pub, folder: ids.get('Inbox'), path: 'Note', bytes, item: big.meta, declared: 'note' }),
      ok: await seedReceived(S, { rid: r.id, pub: r.pub, folder: ids.get('Inbox'), path: 'Note', bytes: big.bytes, item: big.meta, declared: 'note' }),
    };
    const app = await startDrive(mountPoint(), deps());
    await app.app.received;
    expect(Object.fromEntries(Object.keys(seeded).map((k) => [k, S.nodes.get(seeded[k]).rwhy ?? null]))).toEqual({ a1: 'kind', over: 'size', ok: null });
    expect((S.accepted || []).map((x) => x.id)).toEqual([seeded.ok]);
  });

  it('A3: declared a note (no file limits), sealed as a plain file: fails; a link or credential declared as a file fails too', async () => {
    await server();
    const r = await existingReverse(ids.get('Inbox'), ['files', 'note', 'url', 'secret']);
    Object.assign(S.reverse.at(-1), { types: { mode: 'allow', rules: ['ext:pdf'] }, maxFileBytes: 4 });
    const link = encodeItem('url', { url: 'https://example.com/' });
    const secret = encodeItem('secret', { password: 'not-real-pw' });
    const seeded = {
      a3: await seedReceived(S, { rid: r.id, pub: r.pub, folder: ids.get('Inbox'), path: 'payload.exe', bytes: utf8('MZ-long-payload'), type: 'application/pdf', declared: 'note' }),
      linkAsFile: await seedReceived(S, { rid: r.id, pub: r.pub, folder: ids.get('Inbox'), path: 'Link', bytes: link.bytes, item: link.meta, declared: 'files' }),
      secretAsNote: await seedReceived(S, { rid: r.id, pub: r.pub, folder: ids.get('Inbox'), path: 'Credential', bytes: secret.bytes, item: secret.meta, declared: 'note' }),
      linkOk: await seedReceived(S, { rid: r.id, pub: r.pub, folder: ids.get('Inbox'), path: 'Link', bytes: link.bytes, item: link.meta }),
    };
    const app = await startDrive(mountPoint(), deps());
    await app.app.received;
    expect(Object.fromEntries(Object.keys(seeded).map((k) => [k, S.nodes.get(seeded[k]).rwhy ?? null]))).toEqual({ a3: 'kind', linkAsFile: 'kind', secretAsNote: 'kind', linkOk: null });
    expect((S.accepted || []).map((x) => x.id)).toEqual([seeded.linkOk]);
  });

  it('B2: a kind the user\'s role no longer allows (the server filters the link\'s accept) fails at take-in', async () => {
    await server();
    S.roleKinds = ['files', 'note', 'url']; // the role dropped credentials after the link was made
    const r = await existingReverse(ids.get('Inbox'), ['files', 'note', 'url', 'secret']);
    const secret = encodeItem('secret', { password: 'not-real-pw' });
    const note = encodeItem('note', { text: 'hello' });
    const seeded = {
      secret: await seedReceived(S, { rid: r.id, pub: r.pub, folder: ids.get('Inbox'), path: 'Credential', bytes: secret.bytes, item: secret.meta }),
      note: await seedReceived(S, { rid: r.id, pub: r.pub, folder: ids.get('Inbox'), path: 'Note', bytes: note.bytes, item: note.meta }),
    };
    const app = await startDrive(mountPoint(), deps());
    await app.app.received;
    expect(S.nodes.get(seeded.secret).rwhy).toBe('kind');
    expect(S.nodes.get(seeded.note).rwhy ?? null).toBeNull();
    expect((S.accepted || []).map((x) => x.id)).toEqual([seeded.note]);
  });
});

describe('take-in after the re-audit (RT2)', () => {
  it('RT2-1: the role allows none of a files-only link\'s kinds now (accept []): its waiting file fails (kind), never "files" by default', async () => {
    await server();
    S.roleKinds = []; // reverseFiles (and the rest) turned off after the file arrived
    const r = await existingReverse(ids.get('Inbox'), ['files']);
    const f = await seedReceived(S, { rid: r.id, pub: r.pub, folder: ids.get('Inbox'), path: 'waiting.txt', bytes: utf8('synthetic') });
    const app = await startDrive(mountPoint(), deps());
    await app.app.received;
    expect(S.nodes.get(f).rwhy).toBe('kind');
    expect(S.accepted || []).toEqual([]);
  });

  it('RT2-4: an item the server lists as unsealed (plain text at rest), or with no declared kind, fails (kind)', async () => {
    await server();
    const r = await existingReverse(ids.get('Inbox'), ['files']);
    const plain = await seedReceived(S, { rid: r.id, pub: r.pub, folder: ids.get('Inbox'), path: 'a.txt', bytes: utf8('a'), unsealed: true });
    const none = await seedReceived(S, { rid: r.id, pub: r.pub, folder: ids.get('Inbox'), path: 'b.txt', bytes: utf8('b'), declared: null });
    const app = await startDrive(mountPoint(), deps());
    await app.app.received;
    expect([S.nodes.get(plain).rwhy, S.nodes.get(none).rwhy]).toEqual(['kind', 'kind']);
    expect(S.accepted || []).toEqual([]);
  });

  it('RT2-2: a link whose folder was moved deeper than the role allows takes nothing in (place)', async () => {
    S = fakeServer({ capacity: 50 * 1024 * 1024 });
    globalThis.fetch = S.fetch;
    ids = await seedTree(S, { B: { C: { A: {} } } }); // the link's folder A, now at level 3
    const r = await existingReverse(ids.get('B/C/A'), ['files']);
    const f = await seedReceived(S, { rid: r.id, pub: r.pub, folder: ids.get('B/C/A'), path: 'moved.txt', bytes: utf8('synthetic') });
    const app = await startDrive(mountPoint(), deps({ ...PROFILE, limits: { ...PROFILE.limits, maxFolderDepth: 2 } }));
    await app.app.received;
    expect(S.nodes.get(f).rwhy).toBe('place');
    expect(S.accepted || []).toEqual([]);
  });
});

/** A Drive item (sealed as the take-in writes it) of `size` bytes whose content is never served. */
async function oversizeItem(parent, name, item, size) {
  await S.ready;
  const cur = S.current();
  const kek = await S.kekOf(cur.id);
  const id = b64urlFromBytes(crypto.getRandomValues(new Uint8Array(16)));
  const ks = newSalt();
  const at = { userId: S.user.id, mekId: cur.id, salt: ks };
  S.nodes.set(id, {
    id, parent, kind: 'file', size, chunks: refChunks(size), state: 'ready', created: 1700000000, updated: 1700000000, ks, mek: cur.id,
    name: JSON.stringify(await sealName(kek, at, 'name', utf8(name))),
    meta: JSON.stringify(await sealName(kek, at, 'meta', utf8(JSON.stringify({ type: 'text/plain', mtime: 0, size, ...item })))),
    dek: JSON.stringify(await sealDek(kek, at, crypto.getRandomValues(new Uint8Array(32)))),
  });
  return id;
}

describe('the Drive\'s viewers and ZIPs (audit RT-2, RT-4)', () => {
  it('an item larger than its kind can be is not read or shown: Download only', async () => {
    await server();
    const id = await oversizeItem(ids.get('Inbox'), 'Huge note', { kind: 'note', fmt: 'markdown' }, ITEM_MAX_BYTES.note + 1);
    const app = await startDrive(mountPoint(), deps());
    await app.app.received;
    await app.app.open(ids.get('Inbox'), { focus: true });
    const before = S.requests.filter((q) => q.path.includes(`/${id}/`) && /chunk/.test(q.path)).length;
    await expect(app.app.client.readItem(id)).rejects.toThrow(/larger than one can be .* so it is not shown\. Download it instead\./);
    rowOf('Huge note').querySelector('button.drive-open').click();
    await until(() => dialog()?.textContent.includes('larger than one can be'));
    expect(dialog().querySelector('#drive-item-note .md, #drive-item-note pre')).toBeNull();
    expect(S.requests.filter((q) => q.path.includes(`/${id}/`) && /chunk/.test(q.path)).length).toBe(before);
  });

  it('a folder ZIP leaves credentials out and says how many', async () => {
    await server();
    const r = await existingReverse(ids.get('Inbox'));
    await seedKinds(r, ids.get('Inbox'));
    const app = await startDrive(mountPoint(), deps());
    await app.app.received;
    const blobs = [];
    vi.spyOn(URL, 'createObjectURL').mockImplementation((b) => { blobs.push(b); return 'blob:x'; });
    vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    const out = await app.app.client.downloadFolder(ids.get('Inbox'));
    expect(out).toEqual({ left: 1 });
    expect(blobs).toHaveLength(1);
    const zip = new TextDecoder('utf-8', { fatal: false }).decode(await blobs[0].arrayBuffer());
    expect(zip).toContain('Weekly: plan - notes.md');
    expect(zip).not.toContain('Credential from');
    expect(zip).not.toContain('not-real-pw');
  });
});

describe('choosing what a link accepts', () => {
  it('the Receive dialog: a box per kind the role allows (files by default), each with its hint; the link is made with them', async () => {
    await server();
    const app = await startDrive(mountPoint(), deps({ ...PROFILE, limits: { ...PROFILE.limits, reverseSecret: false } }));
    await app.app.ready;
    $('#drive-receive').click();
    await until(() => $('#drive-rev-none'));
    const boxes = [...document.querySelectorAll('#drive-rev-accept input[type="checkbox"]')];
    expect(boxes.map((b) => [b.value, b.checked])).toEqual([['files', true], ['note', false], ['url', false]]);
    expect($('#drive-rev-accept legend').textContent).toBe('What senders can send');
    for (const b of boxes) expect($(`#${b.getAttribute('aria-describedby')}`).textContent.length).toBeGreaterThan(10);
    expect(unlabelled(dialog())).toEqual([]);
    boxes[0].click(); // files off
    boxes[1].click(); // a note on
    $('#drive-rev-confirm').value = 'my password';
    button(dialog(), 'Create link').click();
    await until(() => $('#drive-rev-url'));
    expect(S.reverse[0].accept).toEqual(['note']);
    expect(dialog().querySelector('.modal-sub').textContent).toMatch(/^Anyone with this link can send notes into/);
    expect(strayText()).toEqual([]);
    // None chosen: refused, nothing sent.
    button(dialog(), 'Done').click();
    $('#drive-receive').click();
    await until(() => $('#drive-rev-list table, #drive-rev-none'));
    document.querySelector('#drive-rev-accept input[value="files"]').click();
    $('#drive-rev-confirm').value = 'my password';
    button(dialog(), 'Create link').click();
    await until(() => !dialog().querySelector('.modal-msg').hidden);
    expect(dialog().querySelector('.modal-msg').textContent).toBe('Choose at least one thing senders can send.');
    expect(S.reverse).toHaveLength(1);
    // The folder's links say what each accepts.
    expect(document.querySelector('#drive-rev-table tbody tr').textContent).toMatch(/accepts notes/);
  });

  it('reverseOptions and acceptChoice follow the role', () => {
    expect(acceptChoice({})).toEqual(['files', 'note']);
    expect(acceptChoice({ reverseUrl: true, reverseText: false })).toEqual(['files', 'url']);
    const base = { n: '7', unit: 'd' };
    expect(reverseOptions({ ...base, accept: ['url'] }, {})).toMatchObject({ field: 'accept' });
    expect(reverseOptions({ ...base, accept: ['url'] }, { reverseUrl: true })).toMatchObject({ accept: ['url'] });
    expect(reverseOptions(base, {})).toMatchObject({ accept: ['files'] });
  });

  it('Edit: what it accepts; adding files, links or credentials asks the step-up, a note does not; a kind the role dropped can only go', async () => {
    const cur = { id: 'r'.padEnd(23, 'x'), expires: Math.floor(Date.now() / 1000) + 3600, views: null, used: 0, accept: ['note', 'url'], captcha: false, password: false, note: false };
    const L = { reverseUrl: false, reverseSecret: true };
    const mount = document.createElement('div');
    document.body.replaceChildren(mount);
    const f = reverseEditForm(cur, { limits: L }, { passkey: false, confirm: async () => ({ current: 'p' }) });
    mount.appendChild(f.el);
    const box = (k) => document.querySelector(`fieldset.accept-group input[value="${k}"]`);
    expect([...document.querySelectorAll('fieldset.accept-group input')].map((b) => [b.value, b.checked, b.disabled])).toEqual([['files', false, false], ['note', true, false], ['url', true, false], ['secret', false, false]]);
    expect(box('url').closest('.accept-opt').textContent).toMatch(/Your role no longer allows it: it can only be turned off\./);
    const confirmBox = () => document.getElementById(document.querySelector('[id$="-confirm"]').id).closest('.dfield');
    expect(confirmBox().hidden).toBe(true);
    box('url').click(); // off: it cannot come back
    box('url').dispatchEvent(new Event('change', { bubbles: true }));
    expect(box('url').disabled).toBe(true);
    expect(f.read().patch).toEqual({ accept: ['note'] });
    expect(confirmBox().hidden).toBe(true); // narrowing
    box('secret').click();
    box('secret').dispatchEvent(new Event('change', { bubbles: true }));
    expect(f.read().patch).toEqual({ accept: ['note', 'secret'] });
    expect(confirmBox().hidden).toBe(false); // widening
    expect(unlabelled(mount)).toEqual([]);
    expect(strayText(mount)).toEqual([]);
    // The pure rules.
    expect(weakensLink({ accept: ['note', 'url'] }, { accept: ['url'] })).toBe(false);
    expect(weakensLink({ accept: ['files'] }, { accept: ['note'] })).toBe(true);
    expect(weakensLink({ accept: ['secret'] }, {})).toBe(true); // a link from before: files only
    const same = { expiry: 'keep', unlimited: true, maxFiles: '', maxMb: '', fileMb: '', typeMode: 'any' };
    expect(reverseEditPatch({ ...same, accept: [] }, cur, L).field).toBe('accept');
    expect(reverseEditPatch({ ...same, accept: ['note', 'url', 'files'] }, cur, L).patch).toEqual({ accept: ['note', 'url', 'files'] });
    expect(reverseEditPatch({ ...same, accept: ['note', 'url', 'files'] }, { ...cur, accept: ['note'] }, L).field).toBe('accept'); // url cannot be added
  });
});

describe('the secret builder the uploader reuses', () => {
  it('builds the regular credential payload', () => {
    expect(JSON.parse(buildSecret({ username: 'a' }))).toEqual({ v: 1, username: 'a' });
  });
});
