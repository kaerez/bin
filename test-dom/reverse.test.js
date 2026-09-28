// reverse.test.js (DOM) — reverse shares in the browser (docs/REVERSE.md §8):
// the uploader page (/r/<id>#<key>, public/js/reverse.js) against a stand-in
// of the anonymous API — the note shown as text, the limits, the password
// field, the file list, drag and drop of files and folders, progress,
// errors, and a bad or ended link (the CAPTCHA of a link that has one is on
// its check page: test-dom/captcha.test.js) — and the Drive's "Receive…" action (create a link with
// its options, the link with copy, the folder's links with revoke) plus the
// received files being taken in when the Drive opens (sealed under the
// user's KEK), and the owner acting as the user.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mountUploader, limitsText } from '../public/js/reverse.js';
import { startDrive, reverseOptions } from '../public/dashboard/js/drive-app.js';
import * as drive from '../public/js/driveclient.js';
import {
  setReverseStretcher, createReverseKey, linkProof, passwordGate, sealNote, openUpload, fragmentOf,
  newReverseId, pubFromFragment, pubOfPrivate,
} from '../public/js/reversekeys.js';
import {
  clearSessionKey, clearImpersonationKeys, sealLinkKey, openLinkKey, openName as openSealedName, openDek,
} from '../public/js/drivekeys.js';
import { hkdf32 } from '../public/js/crypto.js';
import { utf8, fromUtf8, bytesFromB64url } from '../public/js/bytes.js';
import { formatDate } from '../public/js/common.js';
import { CHUNK, TAG } from '../public/js/files.js';
import { revokeShare } from '../public/js/api.js';
import { fakeServer, seedTree, seedReceived, FAKE_CSRF } from './drive-fake-server.js';

// Argon2id stand-in: the DOM suites never run WebAssembly.
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

beforeEach(() => { document.body.replaceChildren(); delete globalThis.turnstile; clearSessionKey(); clearImpersonationKeys(); });
afterEach(() => { vi.restoreAllMocks(); });

// ── the uploader page ─────────────────────────────────────────────────────────

/** A stand-in for /api/reverse/<id>/… and /api/config behind fetch. */
async function reverseServer({ password = null, note = null, limits = {}, turnstile = null, status = 200, paused = null } = {}) {
  const id = newReverseId();
  const { pub, privateKey } = await createReverseKey();
  const gate = password ? await passwordGate(password, pub) : null;
  const S = { id, pub, privateKey, files: new Map(), chunks: new Map(), begins: [], done: 0, requests: [] };
  const sealedNote = note ? await sealNote(pub, id, note) : null;
  const ok = (data, st = 200) => ({ ok: st < 400, status: st, type: 'basic', json: async () => data });
  const fail = (st, error, extra = {}) => ok({ error, message: error, ...extra }, st);
  globalThis.fetch = vi.fn(async (url, init = {}) => {
    const p = new URL(url, 'https://bin.example').pathname;
    const h = init.headers || {};
    const body = typeof init.body === 'string' ? JSON.parse(init.body) : init.body;
    S.requests.push({ p, method: init.method || 'GET', headers: h, body });
    if (p === '/api/config') return ok({ turnstile });
    let m;
    if ((m = p.match(/^\/api\/reverse\/([^/]+)\/(open|begin|done|files)(?:\/([^/]+)(?:\/(chunk|finalize)(?:\/(\d+))?)?)?$/))) {
      if (m[1] !== id) return fail(404, 'not_found');
      if (status !== 200) return fail(status, 'gone');
      if (m[2] === 'open' || m[2] === 'begin') {
        if (h['x-link-proof'] !== await linkProof(pub)) return fail(403, 'bad_link');
        // Paused (the owner started over): refused once the link proof matched, as the server does.
        if (paused === 'open' || (paused === 'begin' && m[2] === 'begin') || S.paused) return fail(409, 'paused');
      }
      if (m[2] === 'open') {
        return ok({ note: sealedNote, password: gate ? { salt: gate.salt, t: gate.t } : null, expires: 2000000000,
          limits: { maxFiles: null, maxBytes: null, maxFileBytes: null, types: null, filesLeft: null, bytesLeft: null, ...limits } });
      }
      if (m[2] === 'begin') {
        S.begins.push(h);
        if (gate && !h['x-key-proof']) return fail(401, 'password_required');
        if (S.lockedUntil) return fail(429, 'password_locked', { until: S.lockedUntil });
        if (gate && await sha(h['x-key-proof']) !== gate.ph) return fail(403, 'bad_password');
        return ok({ grant: 'G'.repeat(43), expires: 2000000000 });
      }
      if (m[2] === 'done') { S.done++; return ok({ files: S.files.size, bytes: 0 }); }
      if (m[2] === 'files' && !m[3]) {
        S.files.set(body.id, { ...body, finalized: false });
        return ok({ id: body.id, uploadToken: 'T'.repeat(43), chunks: Math.ceil(body.size / CHUNK) }, 201);
      }
      if (m[4] === 'chunk') { S.chunks.set(`${m[3]}/${m[5]}`, init.body); return ok({ ok: true }); }
      if (m[4] === 'finalize') { S.files.get(m[3]).finalized = true; return ok({ ok: true }); }
      if (!m[4] && init.method === 'DELETE') return ok({ ok: true });
    }
    return fail(404, `unrouted ${p}`);
  });
  S.location = { pathname: `/r/${id}`, hash: `#${fragmentOf(pub)}` };
  return S;
}

function fakeTurnstile() {
  const w = { renders: [], resets: 0 };
  globalThis.turnstile = { render(el, opts) { w.renders.push({ el, opts }); return 'w1'; }, reset() { w.resets += 1; } };
  w.solve = (t) => w.renders.at(-1).opts.callback(t);
  return w;
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
const fileOf = (name, text, type = 'text/plain') => new File([utf8(text)], name, { type, lastModified: 1700000000000 });
const pick = (input, files) => { Object.defineProperty(input, 'files', { configurable: true, get: () => files }); input.dispatchEvent(new Event('change')); };

describe('the uploader page', () => {
  it('says that a send is recorded for the recipient, as a share page says an opening is', async () => {
    const S = await reverseServer();
    const r = await mountUploader(page(), { location: S.location });
    expect(r.state).toBe('ready');
    const note = $('#reverse-receipt-note');
    expect(note.textContent).toBe('Sending is recorded for the recipient and the administrator: the time, and possibly your network address, approximate location, browser, system and languages.');
    expect(note.classList.contains('receipt-note')).toBe(true);
  });

  it('shows the note as text, the limits, and sends encrypted files (no Turnstile script on this page, even with the server\'s keys)', async () => {
    const S = await reverseServer({ note: 'Send the <b>contract</b>, please.\nThanks!', limits: { filesLeft: 5, bytesLeft: 1 << 20, maxFileBytes: 1 << 19 }, turnstile: '0x4AAAAAAAsitekey' });
    const w = fakeTurnstile();
    const root = page();
    const r = await mountUploader(root, { location: S.location });
    expect(r.state).toBe('ready');
    const noteEl = $('#reverse-note .reverse-note-text');
    expect(noteEl.textContent).toBe('Send the <b>contract</b>, please.\nThanks!');
    expect(noteEl.querySelector('b')).toBeNull(); // text, never HTML
    expect($('#reverse-limits').textContent).toMatch(/5 more files at most · 1\.0 MB in total · 512 KB per file/);
    expect($('#reverse-password')).toBeNull();
    const send = $('#reverse-send');
    expect(send.disabled).toBe(true);
    pick($('#reverse-file-input'), [fileOf('a.txt', 'alpha'), fileOf('b.txt', 'bravo!')]);
    expect([...document.querySelectorAll('#reverse-list li')].map((li) => li.textContent)).toEqual(['a.txt — 5 B', 'b.txt — 6 B']);
    expect($('#reverse-total').textContent).toBe('2 files, 11 B');
    // A link without the CAPTCHA: no widget, no Turnstile script, nothing asked for.
    expect($('#reverse-human')).toBeNull();
    expect([...document.querySelectorAll('script[src]')].filter((s) => new URL(s.src, location.href).origin !== location.origin)).toEqual([]);
    expect(send.disabled).toBe(false);
    send.click();
    await until(() => !$('#reverse-done').hidden);
    expect($('#reverse-done').textContent).toMatch(/Sent 2 files \(11 B\), encrypted/);
    expect(w.renders).toHaveLength(0);
    expect(S.begins[0]['x-secbin-turnstile']).toBeUndefined();
    expect(S.begins[0]['x-secbin-human']).toBeUndefined();
    expect(S.done).toBe(1);
    expect([...S.files.values()].every((f) => f.finalized)).toBe(true);
    // Nothing on the wire names or types a file.
    const wire = JSON.stringify(S.requests.map((x) => x.body ?? null));
    for (const w2 of ['a.txt', 'b.txt', 'text/plain', 'alpha']) expect(wire).not.toContain(w2);
    // The user's key opens what was sent.
    const f = [...S.files.values()][0];
    const got = await openUpload(S.privateKey, S.id, { id: f.id, name: f.name, meta: f.meta, fk: { kind: 'rs', data: f.wrap } });
    expect(['a.txt', 'b.txt']).toContain(got.path);
    // The limits shown are updated; the list is empty again; the next send needs nothing more.
    expect($('#reverse-limits').textContent).toMatch(/3 more files at most/);
    expect(document.querySelectorAll('#reverse-list li')).toHaveLength(0);
    expect($('#reverse-recheck').hidden).toBe(true);
    pick($('#reverse-file-input'), [fileOf('c.txt', 'c')]);
    expect(send.disabled).toBe(false);
  });

  it('drops files and folders (paths kept, empty folders not sent), with progress', async () => {
    const S = await reverseServer();
    const root = page();
    await mountUploader(root, { location: S.location });
    const fileEntry = (path, file) => ({ isFile: true, isDirectory: false, fullPath: `/${path}`, file: (ok) => ok(file) });
    const dirEntry = (path, children) => {
      let given = false;
      return { isFile: false, isDirectory: true, fullPath: `/${path}`, createReader: () => ({ readEntries: (ok) => { ok(given ? [] : children); given = true; } }) };
    };
    const big = new File([new Uint8Array(CHUNK + 10)], 'big.bin');
    const items = [
      { webkitGetAsEntry: () => dirEntry('Project', [fileEntry('Project/readme.md', fileOf('readme.md', '# hi')), dirEntry('Project/empty', []), fileEntry('Project/big.bin', big)]) },
      { webkitGetAsEntry: () => fileEntry('loose.txt', fileOf('loose.txt', 'x')) },
    ];
    const drop = $('#reverse-drop');
    await until(() => document.querySelector('.human-wait')?.hidden !== false);
    const ev = new Event('drop', { bubbles: true, cancelable: true });
    ev.dataTransfer = { items, files: [] };
    drop.dispatchEvent(ev);
    await until(() => document.querySelectorAll('#reverse-list li').length === 3);
    expect([...document.querySelectorAll('#reverse-list li')].map((li) => li.textContent.split(' — ')[0])).toEqual(['Project/readme.md', 'Project/big.bin', 'loose.txt']);
    const values = [];
    const bar = document.querySelector('progress.progress-bar');
    const obs = new MutationObserver(() => values.push(bar.value));
    obs.observe(bar, { attributes: true });
    $('#reverse-send').click();
    await until(() => !$('#reverse-done').hidden);
    obs.disconnect();
    expect(S.files.size).toBe(3);
    expect([...S.chunks.keys()].filter((k) => k.endsWith('/1'))).toHaveLength(1); // the big file: two chunks
    expect(S.chunks.get([...S.chunks.keys()].find((k) => k.endsWith('/1'))).byteLength).toBe(10 + TAG);
    const paths = await Promise.all([...S.files.values()].map(async (f) => (await openUpload(S.privateKey, S.id, { id: f.id, name: f.name, meta: f.meta, fk: { kind: 'rs', data: f.wrap } })).path));
    expect(paths.sort()).toEqual(['Project/big.bin', 'Project/readme.md', 'loose.txt']);
    expect(document.querySelector('.progress-block').classList.contains('done')).toBe(true);
  });

  it('asks for the password; a wrong one is refused and marked; the right one sends', async () => {
    const S = await reverseServer({ password: 'letmein' });
    const root = page();
    await mountUploader(root, { location: S.location });
    const pw = $('#reverse-password');
    expect(pw).not.toBeNull();
    expect($('label[for="reverse-password"]').textContent).toMatch(/Password/);
    pick($('#reverse-file-input'), [fileOf('a.txt', 'alpha')]);
    const send = $('#reverse-send');
    await until(() => !send.disabled); // no human check on this server
    send.click();
    await until(() => !$('#reverse-msg').hidden);
    expect($('#reverse-msg').textContent).toMatch(/Enter the password/);
    pw.value = 'nope';
    send.click();
    await until(() => /not right/.test($('#reverse-msg').textContent));
    expect(pw.getAttribute('aria-invalid')).toBe('true');
    expect(S.files.size).toBe(0);
    pw.value = 'letmein';
    send.click();
    await until(() => !$('#reverse-done').hidden);
    expect(S.files.size).toBe(1);
    expect(pw.value).toBe('');
  });

  it('a link whose password is locked (too many wrong ones) says when to try again', async () => {
    const S = await reverseServer({ password: 'letmein' });
    S.lockedUntil = 2000000000;
    await mountUploader(page(), { location: S.location });
    pick($('#reverse-file-input'), [fileOf('a.txt', 'alpha')]);
    await until(() => !$('#reverse-send').disabled);
    $('#reverse-password').value = 'letmein';
    $('#reverse-send').click();
    await until(() => /Too many wrong passwords/.test($('#reverse-msg').textContent));
    expect($('#reverse-msg').textContent).toContain(formatDate(2000000000));
    expect(S.files.size).toBe(0);
  });

  it('refuses files over the link\'s limits before sending anything', async () => {
    const S = await reverseServer({ limits: { filesLeft: 1, types: { mode: 'allow', rules: ['ext:pdf'] } } });
    await mountUploader(page(), { location: S.location });
    expect($('#reverse-limits').textContent).toMatch(/1 more file at most · only \.pdf/);
    pick($('#reverse-file-input'), [fileOf('a.txt', 'x')]);
    await until(() => !$('#reverse-send').disabled);
    $('#reverse-send').click();
    await until(() => !$('#reverse-msg').hidden);
    expect($('#reverse-msg').textContent).toMatch(/does not accept .*\.txt/);
    expect(S.begins).toHaveLength(0);
  });

  it('a link without its key, a wrong key, an ended link', async () => {
    let S = await reverseServer();
    await mountUploader(page(), { location: { pathname: S.location.pathname, hash: '' } });
    expect($('#reverse-error').textContent).toMatch(/incomplete/);
    expect(S.requests.filter((x) => x.p.startsWith('/api/reverse'))).toHaveLength(0);
    await mountUploader(page(), { location: { pathname: S.location.pathname, hash: `#${fragmentOf((await createReverseKey()).pub)}` } });
    expect($('#reverse-error').textContent).toMatch(/not valid/);
    S = await reverseServer({ status: 410 });
    await mountUploader(page(), { location: S.location });
    expect($('#reverse-error').textContent).toMatch(/no longer accepts files/);
    expect($('#reverse-error [role="alert"]')).not.toBeNull();
  });

  it('a paused link (its owner started over) says it is not accepting files right now, on opening or when sending', async () => {
    let S = await reverseServer({ paused: 'open' });
    let r = await mountUploader(page(), { location: S.location });
    expect(r.state).toBe('error');
    expect($('#reverse-error h1').textContent).toBe('This link is not accepting files right now');
    expect($('#reverse-error [role="alert"]').textContent).toMatch(/Try again later/);
    expect($('#reverse-send')).toBeNull();
    expect(S.requests.filter((x) => x.p.endsWith('/begin'))).toHaveLength(0);
    // Paused while the page is open: sending is refused with the same words, nothing is sent.
    S = await reverseServer({ paused: 'begin' });
    r = await mountUploader(page(), { location: S.location });
    expect(r.state).toBe('ready');
    pick($('#reverse-file-input'), [fileOf('a.txt', 'alpha')]);
    await until(() => !$('#reverse-send').disabled);
    $('#reverse-send').click();
    await until(() => !$('#reverse-msg').hidden);
    expect($('#reverse-msg').textContent).toMatch(/^This link is not accepting files right now\./);
    expect(S.files.size).toBe(0);
    expect(document.querySelectorAll('#reverse-list li')).toHaveLength(1); // kept, to try again later
  });

  it('limitsText', () => {
    expect(limitsText({})).toBe('This link accepts any files.');
    expect(limitsText({ filesLeft: 1, types: { mode: 'block', rules: ['ext:exe', 'mime:video/*'] } })).toBe('This link accepts 1 more file at most · no .exe, video/*.');
  });
});

// ── the Drive: Receive… and received files ─────────────────────────────

let S;
let ids;
async function server() {
  S = fakeServer({ capacity: 50 * 1024 * 1024 });
  globalThis.fetch = S.fetch;
  ids = await seedTree(S, { Documents: { 'notes.md': utf8('# notes') }, 'readme.txt': utf8('hi') });
  return S;
}
/** A stored item's field, opened with the user's KEK of its sub-MEK (a check in tests). */
async function fieldOf(id, field = 'name') {
  const n = S.nodes.get(id);
  const at = { userId: S.user.id, mekId: n.mek, salt: n.ks };
  const kek = await S.kekOf(n.mek);
  if (field === 'dek') return openDek(kek, at, typeof n.dek === 'string' ? JSON.parse(n.dek) : n.dek);
  const v = field === 'name' ? n.name : n.meta;
  return fromUtf8(await openSealedName(kek, at, field, typeof v === 'string' ? JSON.parse(v) : v));
}
const PROFILE = { limits: { maxViews: 100, allowUnlimitedViews: true, maxExpireSec: null, files: true, reverseMaxBytes: 1024 ** 3 }, caps: { driveEnabled: true, reverseEnabled: true }, viewer: { enabled: false } };
function mountPoint() {
  const mount = document.createElement('div');
  document.body.replaceChildren(document.createElement('main'), mount);
  document.body.firstChild.id = 'main';
  return mount;
}
/** "Confirm it's you" (confirm.js) stand-in: the typed password becomes a { current } proof; an empty field is refused. */
const confirm = async (input) => {
  const v = input.value;
  input.value = '';
  if (!v) throw new Error('Enter your current password.'); // as confirmStep: a plain Error
  return { current: `proof:${v}` };
};
const deps = (profile = PROFILE, extra = {}) => ({ drive, profile, user: S.user, confirm, canUsePasskey: async () => false, revoke: revokeShare, ...extra }); // as the Drive page wires it (public/dashboard/js/drive.js)
const names = () => [...document.querySelectorAll('#drive-rows tr')].map((tr) => tr.children[1].textContent.trim());
const dialog = () => document.querySelector('.drive-dialog [role="dialog"]');
const button = (root, text) => [...root.querySelectorAll('button')].find((b) => b.textContent.trim() === text);
/** A reverse share the Drive already has (its key sealed under the current KEK), as the server lists it. */
async function existingReverse(folder = 'root') {
  const id = newReverseId();
  const { pub, privateKey } = await createReverseKey();
  const mek = S.current().id;
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey));
  const priv = await sealLinkKey(await S.kekOf(mek), { userId: S.user.id, mekId: mek, linkId: id }, pkcs8);
  S.reverse.push({ id, folder, label: 'old', priv, mek, status: 'active', files: 0, bytes: 0, created: 1700000000, expires: 2000000000 });
  return { id, pub };
}

describe('Drive: Receive…', () => {
  it('is shown only when the role allows it', async () => {
    await server();
    let r = await startDrive(mountPoint(), deps({ ...PROFILE, caps: { driveEnabled: true } }));
    await r.app.ready;
    expect($('#drive-receive').hidden).toBe(true);
    r = await startDrive(mountPoint(), deps());
    await r.app.ready;
    expect($('#drive-receive').hidden).toBe(false);
  });

  it('creates a link for the open (or selected) folder with its options; the server gets only sealed values', async () => {
    await server();
    const r = await startDrive(mountPoint(), deps());
    await r.app.ready;
    // Select the Documents folder: the action applies to it.
    const tr = [...document.querySelectorAll('#drive-rows tr')].find((x) => x.children[1].textContent.trim() === 'Documents');
    tr.querySelector('input[type="checkbox"]').click();
    $('#drive-receive').click();
    await until(() => dialog());
    expect(dialog().querySelector('.modal-title').textContent).toBe('Receive into “Documents”');
    await until(() => $('#drive-rev-none'));
    $('#drive-rev-label').value = 'Contracts';
    $('#drive-rev-note').value = 'Signed copies, please.';
    $('#drive-rev-expire').value = '3';
    $('#drive-rev-files').value = '4';
    $('#drive-rev-bytes').value = '5';
    $('#drive-rev-filesize').value = '2.5';
    $('#drive-rev-types').value = 'allow';
    $('#drive-rev-types').dispatchEvent(new Event('change'));
    $('#drive-rev-rules').value = 'ext:pdf\next:docx';
    $('#drive-rev-pw-on').click();
    $('#drive-rev-pw').value = 'uploader-pass';
    $('#drive-rev-pw2').value = 'uploader-pass';
    // Without the account password (the link adds key material): refused and marked, nothing sent.
    expect($('#drive-rev-confirm').closest('.dfield').hidden).toBe(false);
    button(dialog(), 'Create link').click();
    await until(() => dialog().querySelector('#drive-rev-confirm[aria-invalid="true"]'));
    expect(dialog().textContent).toContain('Enter your current password.');
    expect(S.reverse).toHaveLength(0);
    $('#drive-rev-confirm').value = 'my account password';
    button(dialog(), 'Create link').click();
    await until(() => $('#drive-rev-url'));
    const url = $('#drive-rev-url').textContent;
    const m = /\/r\/(r[A-Za-z0-9_-]{22})#([A-Za-z0-9_-]{87})$/.exec(url);
    expect(m).not.toBeNull();
    const b = S.reverse[0];
    expect(b).toMatchObject({ id: m[1], folder: ids.get('Documents'), label: 'Contracts', expire: '3d', maxFiles: 4, maxBytes: 5 * 1024 * 1024, maxFileBytes: 2.5 * 1024 * 1024, types: { mode: 'allow', rules: ['ext:pdf', 'ext:docx'] } });
    const raw = JSON.stringify(b);
    expect(raw).not.toContain('uploader-pass');
    expect(raw).not.toContain('Signed copies');
    expect(Object.keys(b.password).sort()).toEqual(['ph', 'salt', 't']);
    expect(b.current).toBe('proof:my account password');
    // The link's key is not sent; the private key is sealed under the user's current KEK.
    expect(raw).not.toContain(m[2]);
    expect(b.mek).toBe(S.current().id);
    const pk = await openLinkKey(await S.kekOf(b.mek), { userId: S.user.id, mekId: b.mek, linkId: b.id }, b.priv);
    expect(fragmentOf((await pubOfPrivate(pk)).pub)).toBe(m[2]);
    expect(b.lh).toBe(await sha(await linkProof(pubFromFragment(m[2]))));
    expect(dialog().querySelector('.modal-sub').textContent).toMatch(/into “Documents” for 3 days/);
    expect($('#drive-rev-copy')).not.toBeNull();
  });

  it('a folder\'s "Shares" lists its upload links too, with Copy link and Revoke', async () => {
    await server();
    const { id } = await existingReverse(ids.get('Documents'));
    await existingReverse('root'); // another folder's link: not listed
    const r = await startDrive(mountPoint(), deps());
    await r.app.ready;
    const tr = [...document.querySelectorAll('#drive-rows tr')].find((x) => x.children[1].textContent.trim() === 'Documents');
    button(tr, 'Shares').click();
    await until(() => dialog()?.querySelector('#drive-shares-table'));
    const rows = [...dialog().querySelectorAll('#drive-shares-table tbody tr')];
    expect(rows).toHaveLength(1);
    expect(rows[0].dataset.kind).toBe('reverse');
    expect(rows[0].textContent).toMatch(/old/);
    expect(rows[0].textContent).toMatch(/receive/);
    expect(rows[0].textContent).toMatch(/0 files received/);
    expect(button(rows[0], 'Copy link')).toBeDefined();
    const rv = button(rows[0], 'Revoke');
    rv.click(); // arms
    rv.click();
    await until(() => /revoked/.test(dialog().querySelector('#drive-shares-table tbody tr').textContent));
    expect(S.reverse.find((x) => x.id === id).status).toBe('revoked');
  });

  it('a folder with no shares or upload links says how to make one', async () => {
    await server();
    const r = await startDrive(mountPoint(), deps());
    await r.app.ready;
    const tr = [...document.querySelectorAll('#drive-rows tr')].find((x) => x.children[1].textContent.trim() === 'Documents');
    button(tr, 'Shares').click();
    await until(() => dialog()?.querySelector('#drive-shares-empty'));
    expect(dialog().querySelector('#drive-shares-empty').textContent).toMatch(/Share… or Receive…/);
  });

  it('the owner acting as the user is not asked to confirm (the server asks for nothing then)', async () => {
    await server();
    S.impersonatedBy = 'owner';
    const r = await startDrive(mountPoint(), deps(PROFILE, { user: { ...S.user, impersonating: true } }));
    await r.app.ready;
    $('#drive-receive').click();
    await until(() => dialog());
    expect($('#drive-rev-confirm').closest('.dfield').hidden).toBe(true);
    button(dialog(), 'Create link').click();
    await until(() => $('#drive-rev-url'));
    expect(S.reverse).toHaveLength(1);
    expect(S.reverse[0].current).toBeUndefined();
    expect(S.reverse[0].reauth).toBeUndefined();
  });

  it('validates the options (reverseOptions)', () => {
    expect(reverseOptions({ n: '2', unit: 'h', maxFiles: '', maxMb: '', fileMb: '', typeMode: 'any' }, {})).toMatchObject({ expire: '2h', maxFiles: null, maxBytes: null, maxFileBytes: null, types: null });
    expect(reverseOptions({ n: '0', unit: 'h' }, {}).field).toBe('expire');
    // A Receive link's expiry has its own role option (reverseMaxExpireSec), not the regular maxExpireSec.
    expect(reverseOptions({ n: '2', unit: 'h' }, { reverseMaxExpireSec: 3600 }).field).toBe('expire');
    expect(reverseOptions({ n: '2', unit: 'h' }, { maxExpireSec: 3600 }).error).toBeUndefined();
    expect(reverseOptions({ n: '1', unit: 'd', maxFiles: '0' }, {}).field).toBe('files');
    expect(reverseOptions({ n: '1', unit: 'd', maxMb: 'lots' }, {}).field).toBe('bytes');
    expect(reverseOptions({ n: '1', unit: 'd', maxMb: '2' }, { reverseMaxBytes: 1024 * 1024 }).field).toBe('bytes');
    expect(reverseOptions({ n: '1', unit: 'd', maxMb: '' }, { reverseMaxBytes: 1024 }).maxBytes).toBe(1024);
    expect(reverseOptions({ n: '1', unit: 'd', typeMode: 'allow', typeRules: '' }, {}).field).toBe('types');
    expect(reverseOptions({ n: '1', unit: 'd', typeMode: 'block', typeRules: 'exe' }, {}).field).toBe('types');
  });

  it('lists the folder\'s links (the link rebuilt from its key) and revokes one', async () => {
    await server();
    const old = await existingReverse('root');
    const r = await startDrive(mountPoint(), deps());
    await r.app.ready;
    $('#drive-receive').click();
    await until(() => $('#drive-rev-table'));
    const rowEl = $('#drive-rev-table tbody tr');
    expect(rowEl.children[0].textContent).toBe('old');
    expect(rowEl.children[3].textContent).toBe('0 files, 0 B');
    expect(button(rowEl, 'Copy link')).not.toBeUndefined();
    const rv = button(rowEl, 'Revoke');
    rv.click(); // arm
    button(rowEl, 'Revoke now').click();
    await until(() => S.revoked.includes(old.id));
    await until(() => $('#drive-rev-table tbody tr').dataset.status === 'revoked');
    // Through api.js: the page's recorded CSRF token and the intent header (the server refuses it otherwise).
    const sent = S.requests.find((x) => x.method === 'POST' && x.path === `/api/private/shares/${old.id}/revoke`);
    expect(sent.headers).toMatchObject({ 'x-secbin-csrf': FAKE_CSRF, 'x-secbin-intent': '1' });
  });
});

describe('Drive: received files', () => {
  it('an item whose link moved since the listing (409 folder_moved) waits for the next take-in, never marked failed', async () => {
    await server();
    const rs = await existingReverse(ids.get('Documents'));
    await seedReceived(S, { rid: rs.id, pub: rs.pub, folder: ids.get('Documents'), path: 'moved.txt', bytes: utf8('moved') });
    const real = S.fetch;
    let refusals = 0;
    globalThis.fetch = async (url, init = {}) => {
      if (refusals === 0 && init.method === 'POST' && /^\/api\/private\/drive\/received\/[^/]+$/.test(new URL(url, 'https://x').pathname)) {
        refusals++;
        return { ok: false, status: 409, type: 'basic', json: async () => ({ error: 'folder_moved', message: 'moved', folder: 'root' }) };
      }
      return real(url, init);
    };
    const client = await drive.openDrive({ user: S.user });
    const first = await client.receivePending();
    expect(first).toMatchObject({ added: 0, failed: 0, deferred: 1 });
    expect(S.requests.some((x) => /\/failed$/.test(x.path))).toBe(false);
    const again = await client.receivePending();
    expect(again).toMatchObject({ added: 1, failed: 0, deferred: 0 });
  });

  it('are taken into the Drive when it opens: folders made from their paths, sealed under the KEK, unreadable ones counted', async () => {
    await server();
    const rs = await existingReverse(ids.get('Documents'));
    await seedReceived(S, { rid: rs.id, pub: rs.pub, folder: ids.get('Documents'), path: 'inbox/sub/a.txt', bytes: utf8('alpha') });
    await seedReceived(S, { rid: rs.id, pub: rs.pub, folder: ids.get('Documents'), path: 'b.txt', bytes: utf8('bravo') });
    await seedReceived(S, { rid: rs.id, pub: rs.pub, folder: ids.get('Documents'), path: 'c.txt', bytes: utf8('x'), bad: true });
    // A name the folder already has gets " (2)", as for the user's own uploads.
    await seedReceived(S, { rid: rs.id, pub: rs.pub, folder: ids.get('Documents'), path: 'notes.md', bytes: utf8('other notes') });
    const r = await startDrive(mountPoint(), deps());
    await r.app.ready;
    await r.app.received;
    expect(S.accepted).toHaveLength(3);
    expect($('#drive-received').textContent).toMatch(/1 received file could not be added/);
    // The taken-in fields are the Drive's own: sealed under the user's current KEK, each with its salt.
    const inDocs = S.accepted.filter((x) => x.body.parent === ids.get('Documents'));
    expect(inDocs.every((x) => x.body.mek === S.current().id && typeof x.body.ks === 'string')).toBe(true);
    const leaves = await Promise.all(inDocs.map((x) => fieldOf(x.id)));
    expect([...leaves].sort()).toEqual(['b.txt', 'notes (2).md']);
    const { id } = inDocs[leaves.indexOf('b.txt')];
    expect(JSON.parse(await fieldOf(id, 'meta'))).toMatchObject({ type: 'text/plain', size: 5 });
    expect((await fieldOf(id, 'dek')).length).toBe(32);
    // The folder shows them like any file; the path's folders exist.
    await r.app.open(ids.get('Documents'));
    expect(names()).toEqual(['inbox', 'b.txt', 'notes (2).md', 'notes.md']);
    const inbox = [...S.nodes.values()].find((n) => n.kind === 'dir' && n.parent === ids.get('Documents') && !n.rs);
    await r.app.open(inbox.id);
    expect(names()).toEqual(['sub']);
    // And downloads decrypt with the re-wrapped key (the chunks were never touched).
    const sub = [...S.nodes.values()].find((n) => n.kind === 'dir' && n.parent === inbox.id);
    const client = await drive.openDrive({ user: S.user });
    const a = [...S.nodes.values()].find((n) => n.parent === sub.id);
    const blob = await (await client.download(a.id)).blob();
    expect(new TextDecoder().decode(new Uint8Array(await blob.arrayBuffer()))).toBe('alpha');
  });
});

// ── security audit round 3 (M-1, L-5): the take-in ─────────────────────────
describe('audit round 3: taking received files in', () => {
  const dirs = () => [...S.nodes.values()].filter((n) => n.kind === 'dir' && !n.rs).length;
  const openName = (id) => fieldOf(id);
  const openMeta = async (id) => JSON.parse(await fieldOf(id, 'meta'));

  it(`L-5: a received path creates at most ${drive.RECEIVED_MAX_DEPTH} folder levels; deeper files land in the deepest one`, async () => {
    await server();
    const rs = await existingReverse(ids.get('Documents'));
    const before = dirs();
    const deep = Array.from({ length: 60 }, (_, i) => `d${i}`).join('/');
    const id = await seedReceived(S, { rid: rs.id, pub: rs.pub, folder: ids.get('Documents'), path: `${deep}/x.txt`, bytes: utf8('x') });
    const r = await startDrive(mountPoint(), deps());
    await r.app.ready;
    await r.app.received;
    expect(dirs() - before).toBe(drive.RECEIVED_MAX_DEPTH);
    expect(await openName(id)).toBe('x.txt');
    expect(await openName(S.nodes.get(id).parent)).toBe(`d${drive.RECEIVED_MAX_DEPTH - 1}`);
    expect($('#drive-received').textContent).toMatch(/1 file was in folders nested too deeply/);
  });

  it('L-5: never past the Drive\'s 64 levels in all; and at most a set number of new folders per take-in', async () => {
    await server();
    // A link on a folder 62 levels down: only 2 more levels fit.
    let chain = {};
    const top = chain;
    for (let i = 0; i < 61; i++) { chain[`c${i}`] = {}; chain = chain[`c${i}`]; }
    const deepIds = await seedTree(S, { deep: top });
    const leafPath = ['deep', ...Array.from({ length: 61 }, (_, i) => `c${i}`)].join('/');
    const target = deepIds.get(leafPath);
    const rs = await existingReverse(target);
    const a = await seedReceived(S, { rid: rs.id, pub: rs.pub, folder: target, path: 'p/q/r/s/a.txt', bytes: utf8('a') });
    const r = await startDrive(mountPoint(), deps());
    await r.app.ready;
    await r.app.received;
    expect(await openName(S.nodes.get(a).parent)).toBe('q');
    expect(await openName(S.nodes.get(S.nodes.get(a).parent).parent)).toBe('p');
    // Many new folders at once: the budget, then the link's folder itself.
    await server();
    const rs2 = await existingReverse(ids.get('Documents'));
    const n = drive.RECEIVED_MAX_NEW_FOLDERS + 5;
    const got = [];
    for (let i = 0; i < n; i++) got.push(await seedReceived(S, { rid: rs2.id, pub: rs2.pub, folder: ids.get('Documents'), path: `f${i}/x.txt`, bytes: utf8('x') }));
    const before = dirs();
    const r2 = await startDrive(mountPoint(), deps());
    await r2.app.ready;
    await r2.app.received;
    expect(dirs() - before).toBe(drive.RECEIVED_MAX_NEW_FOLDERS);
    expect(got.filter((x) => S.nodes.get(x).parent === ids.get('Documents'))).toHaveLength(5);
    expect(got.every((x) => !S.nodes.get(x).rs)).toBe(true);
  }, 60000);

  it('L-5: names in every script stay as they are; direction overrides are removed (and the file marked renamed); names are shown isolated', async () => {
    await server();
    const rs = await existingReverse(ids.get('Documents'));
    const keep = ['דוח שנתי 2026.pdf', 'שָׁלוֹם.txt', 'report-דוח.docx', 'تقرير.pdf', 'می‌خواهم.txt', '👨‍👩‍👧 family.jpg'];
    const kept = [];
    for (const name of keep) kept.push([name, await seedReceived(S, { rid: rs.id, pub: rs.pub, folder: ids.get('Documents'), path: name, bytes: utf8(name) })]);
    const hebrewPath = await seedReceived(S, { rid: rs.id, pub: rs.pub, folder: ids.get('Documents'), path: 'מסמכים/דוחות 2026/סיכום.pdf', bytes: utf8('pdf') });
    const spoof = await seedReceived(S, { rid: rs.id, pub: rs.pub, folder: ids.get('Documents'), path: 'invoice\u202efdp.exe', bytes: utf8('MZ'), type: 'application/pdf' });
    const r = await startDrive(mountPoint(), deps());
    await r.app.ready;
    await r.app.received;
    for (const [name, id] of kept) {
      expect(await openName(id)).toBe(name);
      expect((await openMeta(id)).renamed).toBeUndefined();
    }
    expect(await openName(hebrewPath)).toBe('סיכום.pdf');
    const sub = S.nodes.get(hebrewPath).parent;
    expect(await openName(sub)).toBe('דוחות 2026');
    expect(await openName(S.nodes.get(sub).parent)).toBe('מסמכים');
    expect(await openName(spoof)).toBe('invoicefdp.exe');
    expect(await openMeta(spoof)).toMatchObject({ renamed: true, type: 'application/pdf' });
    expect($('#drive-received').textContent).toMatch(/1 name had hidden direction or spacing characters, removed/);
    // The folder shows each name in an isolate, the extension as its own left-to-right one; the renamed file says so.
    await r.app.open(ids.get('Documents'));
    const rowOf = (text) => [...document.querySelectorAll('#drive-rows tr')].find((tr) => tr.querySelector('.fname')?.textContent === text);
    const inv = rowOf('invoicefdp.exe');
    expect(inv.querySelector('.fname').getAttribute('dir')).toBe('auto');
    expect(inv.querySelector('.fext')).toMatchObject({ textContent: '.exe' });
    expect(inv.querySelector('.fext').getAttribute('dir')).toBe('ltr');
    expect(inv.querySelector('.renamed-note').textContent).toMatch(/renamed/);
    const heb = rowOf('דוח שנתי 2026.pdf');
    expect(heb.querySelector('.fstem').textContent).toBe('דוח שנתי 2026');
    expect(heb.querySelector('.fext').textContent).toBe('.pdf');
    expect(heb.querySelector('.renamed-note')).toBeNull();
  }, 60000);

  it('M-1: items that cannot be taken in leave the queue (recorded on the server), never hide later ones, and can be reviewed, retried or deleted', async () => {
    await server();
    S.receivedPage = 2;
    const rs = await existingReverse(ids.get('Documents'));
    rs.label = 'Contracts';
    S.reverse.find((x) => x.id === rs.id).label = 'Contracts';
    const bad = [];
    for (let i = 0; i < 3; i++) {
      const id = await seedReceived(S, { rid: rs.id, pub: rs.pub, folder: ids.get('Documents'), path: `bad${i}.txt`, bytes: utf8('x'), bad: true });
      S.nodes.get(id).created = 1690000000 + i; // the oldest: first in the queue
      bad.push(id);
    }
    const good = [];
    for (let i = 0; i < 3; i++) good.push(await seedReceived(S, { rid: rs.id, pub: rs.pub, folder: ids.get('Documents'), path: `good${i}.txt`, bytes: utf8('ok') }));
    const r = await startDrive(mountPoint(), deps());
    await r.app.ready;
    await r.app.received;
    expect(good.every((id) => !S.nodes.get(id).rs)).toBe(true);
    for (const id of bad) expect(S.nodes.get(id)).toMatchObject({ rs: rs.id, rfail: expect.any(Number), rwhy: 'unreadable' });
    const marks = S.requests.filter((q) => q.method === 'POST' && /\/received\/[^/]+\/failed$/.test(q.path));
    expect(marks).toHaveLength(3);
    expect($('#drive-received').textContent).toMatch(/3 new received files were added.*3 received files could not be added/);
    // Review: link, size, time, why; try one again, delete another.
    $('#drive-received-review').click();
    await until(() => $('#drive-failed-table'));
    const rows = () => [...document.querySelectorAll('#drive-failed-table tbody tr')];
    expect(rows()).toHaveLength(2); // one page of 2…
    expect(rows()[0].children[0].textContent).toBe('Contracts');
    expect(rows()[0].children[3].textContent).toMatch(/does not open/);
    $('#drive-failed-more').click(); // …and the next
    await until(() => rows().length === 3);
    const first = rows()[0];
    button(first, 'Try again').click();
    await until(() => S.requests.some((q) => q.method === 'DELETE' && q.path.endsWith(`/received/${bad[0]}/failed`)));
    // Tried again at once: it still does not open, so it is recorded again.
    await until(() => S.requests.filter((q) => q.method === 'POST' && q.path.endsWith(`/received/${bad[0]}/failed`)).length === 2);
    const second = rows().find((tr) => tr.dataset.id === bad[1]);
    button(second, 'Delete').click();
    button(second, 'Delete now').click();
    await until(() => !S.nodes.has(bad[1]));
    await until(() => !rows().some((tr) => tr.dataset.id === bad[1]));
  }, 60000);
});

// The role's Drive rules on a take-in (on top of the link's own type rules, which the uploader's page applied).
describe('taking received files in: the role\'s Drive rules apply too', () => {
  const withLimits = (extra) => ({ ...PROFILE, limits: { ...PROFILE.limits, ...extra } });

  it('a type the role refuses in the Drive is not taken in (failed: "type"); the others declare their type', async () => {
    await server();
    const rs = await existingReverse(ids.get('Documents'));
    const exe = await seedReceived(S, { rid: rs.id, pub: rs.pub, folder: ids.get('Documents'), path: 'setup.exe', bytes: utf8('MZ'), type: 'application/x-msdownload' });
    const txt = await seedReceived(S, { rid: rs.id, pub: rs.pub, folder: ids.get('Documents'), path: 'notes.txt', bytes: utf8('ok') });
    const r = await startDrive(mountPoint(), deps(withLimits({ fileTypeMode: 'block', fileTypeRules: ['ext:exe'] })));
    await r.app.ready;
    await r.app.received;
    expect(S.nodes.get(exe)).toMatchObject({ rs: rs.id, rfail: expect.any(Number), rwhy: 'type' });
    expect(S.accepted.map((x) => x.id)).toEqual([txt]);
    expect(S.accepted[0].body.types).toEqual([{ ext: 'txt', mime: 'text/plain' }]);
    expect($('#drive-received').textContent).toMatch(/1 received file could not be added/);
    // The review says why.
    $('#drive-received-review').click();
    await until(() => $('#drive-failed-table'));
    expect(document.querySelector('#drive-failed-table tbody tr').children[3].textContent).toBe('its file type is one this link does not accept, or your account does not allow in the Drive');
  }, 60000);

  it('the server refusing the type (a policy the page did not know of) fails the item as "type", and the take-in goes on', async () => {
    await server();
    const rs = await existingReverse(ids.get('Documents'));
    const a = await seedReceived(S, { rid: rs.id, pub: rs.pub, folder: ids.get('Documents'), path: 'a.bin', bytes: utf8('a') });
    S.refusals.push({ method: 'POST', path: new RegExp(`/received/${a}$`), status: 403, error: 'file_type_not_allowed', message: 'This file type may not be added to your Drive: .bin (text/plain).' });
    const b = await seedReceived(S, { rid: rs.id, pub: rs.pub, folder: ids.get('Documents'), path: 'b.txt', bytes: utf8('b') });
    const r = await startDrive(mountPoint(), deps());
    await r.app.ready;
    await r.app.received;
    expect(S.nodes.get(a)).toMatchObject({ rs: rs.id, rwhy: 'type' });
    expect(S.nodes.get(b).rs).toBeNull();
  }, 60000);

  it('the depth limit: a path makes folders only down to the role\'s limit (the rest flattened); a link folder deeper than it takes nothing in', async () => {
    await server();
    const rs = await existingReverse(ids.get('Documents')); // Documents: level 1
    const deep = await seedReceived(S, { rid: rs.id, pub: rs.pub, folder: ids.get('Documents'), path: 'x/y/z/a.txt', bytes: utf8('a') });
    const r = await startDrive(mountPoint(), deps(withLimits({ maxFolderDepth: 2 })));
    await r.app.ready;
    await r.app.received;
    // One folder level fits under Documents: x (level 2); the file lands in it.
    const parent = S.nodes.get(deep).parent;
    expect(await fieldOf(parent)).toBe('x');
    expect(S.nodes.get(parent).parent).toBe(ids.get('Documents'));
    expect($('#drive-received').textContent).toMatch(/1 file was in folders nested too deeply/);
    // The role now allows no folders at all: the link's folder (level 1) takes nothing in.
    await server();
    const rs2 = await existingReverse(ids.get('Documents'));
    const late = await seedReceived(S, { rid: rs2.id, pub: rs2.pub, folder: ids.get('Documents'), path: 'late.txt', bytes: utf8('l') });
    const r2 = await startDrive(mountPoint(), deps(withLimits({ maxFolderDepth: 0 })));
    await r2.app.ready;
    await r2.app.received;
    expect(S.nodes.get(late)).toMatchObject({ rs: rs2.id, rwhy: 'place' });
    expect(S.requests.filter((q) => q.method === 'POST' && q.path === `/api/private/drive/received/${late}`)).toHaveLength(0);
  }, 60000);
});

describe('the owner acting as the user: received files', () => {
  it('opens the user\'s Drive with the user\'s keys (in the page\'s memory only), takes a received file in and downloads it', async () => {
    S = fakeServer({ capacity: 50 * 1024 * 1024 });
    globalThis.fetch = S.fetch;
    ids = await seedTree(S, { Inbox: {} });
    const rs = await existingReverse(ids.get('Inbox'));
    const got = await seedReceived(S, { rid: rs.id, pub: rs.pub, folder: ids.get('Inbox'), path: 'from a client/contract.pdf', bytes: utf8('signed contract'), type: 'application/pdf' });
    S.impersonatedBy = 'owner';
    const user = { ...S.user, impersonating: true };
    const r = await startDrive(mountPoint(), deps(PROFILE, { user }));
    expect(r.state).toBe('open');
    await r.app.ready;
    await r.app.received;
    expect(S.audit.some((x) => x.action === 'drive.keys_used')).toBe(true);
    expect(sessionStorage.length).toBe(0); // the user's keys in the page's memory only
    expect(S.nodes.get(got).rs).toBeNull();
    const folder = S.nodes.get(got).parent;
    expect(await fieldOf(folder)).toBe('from a client');
    // Readable with the user's own keys (nothing was sealed for the owner), and downloadable here.
    expect(await fieldOf(got)).toBe('contract.pdf');
    const client = await drive.openDrive({ user });
    const blob = await (await client.download(got)).blob();
    expect(new TextDecoder().decode(new Uint8Array(await blob.arrayBuffer()))).toBe('signed contract');
  }, 60000);
});
// ── WCAG 2.2 (docs/WCAG22.md): the uploader and the Drive's reverse-share states ──
describe('WCAG 2.2: reverse shares', () => {
  it('the uploader: the drop zone is a named group, not a Tab stop; "Sent …" is said by a status line there from the start; focus goes to "Choose files" after a send', async () => {
    const S = await reverseServer();
    await mountUploader(page(), { location: S.location });
    const drop = $('#reverse-drop');
    expect(drop.getAttribute('role')).toBe('group');
    expect(drop.hasAttribute('tabindex')).toBe(false);
    const live = $('#reverse-done').parentElement;
    expect(live.getAttribute('role')).toBe('status');
    expect($('#reverse-done').hasAttribute('role')).toBe(false);
    pick($('#reverse-file-input'), [fileOf('a.txt', 'alpha')]);
    await until(() => !$('#reverse-send').disabled);
    $('#reverse-send').focus();
    $('#reverse-send').click();
    await until(() => !$('#reverse-done').hidden);
    expect($('#reverse-done').parentElement).toBe(live);
    expect(document.activeElement.id).toBe('reverse-pick-files');
  });

  it('the uploader: an error state names itself in the page title', async () => {
    const S = await reverseServer({ status: 410 });
    await mountUploader(page(), { location: S.location });
    expect(document.title).toBe('This link no longer accepts files · secbin');
  });

  it('Receive…: the file types list has a visible label, "Copy link" keeps its visible words in its name', async () => {
    await server();
    await existingReverse('root');
    const r = await startDrive(mountPoint(), deps());
    await r.app.ready;
    $('#drive-receive').click();
    await until(() => $('#drive-rev-table'));
    const rules = $('#drive-rev-rules');
    expect(rules.hasAttribute('aria-label')).toBe(false);
    expect(document.querySelector('label[for="drive-rev-rules"]').textContent).toMatch(/^The file types/);
    expect(rules.closest('.dfield').hidden).toBe(true);
    $('#drive-rev-types').value = 'allow';
    $('#drive-rev-types').dispatchEvent(new Event('change'));
    expect(rules.closest('.dfield').hidden).toBe(false);
    expect($('#drive-rev-unit').getAttribute('aria-label')).toBe('Accept files for: unit');
    const copy = button($('#drive-rev-table tbody tr'), 'Copy link');
    expect(copy.getAttribute('aria-label')).toBe('Copy link old');
  });

  it('a dialog opening puts away a toast from before it (nothing shown or read outside the modal); a toast raised while it is open still shows', async () => {
    await server();
    const r = await startDrive(mountPoint(), deps());
    await r.app.ready;
    const t = document.body.appendChild(Object.assign(document.createElement('div'), { id: 'toast' }));
    t.setAttribute('role', 'status');
    t.textContent = 'Added 1 received file.';
    t.classList.add('show');
    $('#drive-receive').click();
    await until(() => dialog());
    expect(t.classList.contains('show')).toBe(false);
    expect(t.textContent).toBe('');
    expect(t.inert).toBe(false);
  });

  // Security audit F6 (#67) and audit B L4: when the session ends (session-timeout.js), or the
  // browser is now signed in as someone else (api.js), an open Drive closes: its KEKs are zeroed
  // and leave the client, its dialogs close (the page behind them no longer inert on their
  // account) and what it showed (decrypted names) leaves the page.
  for (const [what, event, why] of [['the session ended', 'secbin:session-ended', 'ended'], ['another session is signed in', 'secbin:session-changed', 'changed']]) {
    it(`${what}: the Drive forgets its keys, closes its dialogs and its contents, and offers a reload`, async () => {
      await server();
      const r = await startDrive(mountPoint(), deps());
      await r.app.ready;
      const forget = vi.spyOn(drive.DriveClient.prototype, 'forget');
      const held = [...r.app.client.keys.keks.values()].flat();
      expect(held.length).toBeGreaterThan(0);
      $('#drive-receive').click();
      await until(() => dialog());
      expect(document.getElementById('main').inert).toBe(true);
      window.dispatchEvent(new CustomEvent(event));
      // Every client on the page forgets (earlier tests' Drives are still listening, too).
      expect(forget).toHaveBeenCalled();
      for (const client of forget.mock.contexts) { expect(client.keys.keks.size).toBe(0); expect(client.legacy).toBeNull(); expect(client.forgotten).toBe(true); }
      for (const k of held) expect(k.every((b) => b === 0)).toBe(true); // overwritten, not only dropped
      forget.mockRestore();
      expect($('#drive-closed').dataset.why).toBe(why);
    expect(dialog()).toBeNull();
      expect(document.getElementById('main').inert).toBe(false);
      expect($('#drive-app')).toBeNull();
      expect($('#drive-rows')).toBeNull();
      expect($('#drive-closed h2').textContent).toBe('Your Drive was closed');
      expect($('#drive-closed-reload')).not.toBeNull();
    });
  }

  it('received files taken in while a dialog is open: no toast outside the modal; the status line says it', async () => {
    await server();
    const rs = await existingReverse('root');
    await seedReceived(S, { rid: rs.id, pub: rs.pub, path: 'late.txt', bytes: utf8('late') });
    const mount = mountPoint(); // (resets the body)
    const t = document.body.appendChild(Object.assign(document.createElement('div'), { id: 'toast' }));
    t.setAttribute('role', 'status');
    // The take-in (in the background) finishes only after the dialog has opened.
    let release;
    const gate = new Promise((resolve) => { release = resolve; });
    const real = drive.DriveClient.prototype.receivePending;
    const spy = vi.spyOn(drive.DriveClient.prototype, 'receivePending').mockImplementation(async function (...a) { await gate; return real.apply(this, a); });
    try {
      const r = await startDrive(mount, deps());
      await r.app.ready;
      expect(document.getElementById('toast')).toBe(t);
      $('#drive-receive').click();
      await until(() => dialog());
      release();
      await r.app.received;
      expect(t.classList.contains('show')).toBe(false);
      expect(t.textContent).toBe('');
      expect($('#drive-received').textContent).toMatch(/1 new received file was added/);
    } finally { spy.mockRestore(); }
  });

  it('a refresh in the background (received files taken in) while a folder opens: the Drive ends in that folder, with focus on its heading', async () => {
    await server();
    const r = await startDrive(mountPoint(), deps());
    await r.app.ready;
    const opening = r.app.open(ids.get('Documents'), { focus: true });
    await r.app.refresh(); // as takeInReceived does after adding files
    await opening;
    expect(r.app.current).toBe(ids.get('Documents'));
    expect($('#drive-pane-title').textContent).toBe('Documents');
    expect(document.activeElement.id).toBe('drive-pane-title');
  });

  it('received files: the Drive\'s status line is there before it says anything', async () => {
    await server();
    const rs = await existingReverse('root');
    await seedReceived(S, { rid: rs.id, pub: rs.pub, path: 'a.txt', bytes: utf8('a') });
    const r = await startDrive(mountPoint(), deps());
    await r.app.ready;
    const live = $('#drive-received-live');
    expect(live.getAttribute('role')).toBe('status');
    expect($('#drive-received').hasAttribute('role')).toBe(false);
    await r.app.received;
    expect($('#drive-received').parentElement).toBe(live);
    expect($('#drive-received').textContent).toMatch(/1 new received file was added/);
  });
});
