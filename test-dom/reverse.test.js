// reverse.test.js (DOM) — reverse shares in the browser (docs/REVERSE.md §8):
// the uploader page (/r/<id>#<key>, public/js/reverse.js) against a stand-in
// of the anonymous API — the note shown as text, the limits, the password
// field, the human check keeping Send disabled until it passes, the file
// list, drag and drop of files and folders, progress, errors, and a bad or
// ended link — and the Drive's "Receive files…" action (create a link with
// its options, the link with copy, the folder's links with revoke) plus the
// received files being re-wrapped when the Drive opens (and counted on the
// unlock prompt while it is locked).
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mountUploader, limitsText } from '../public/js/reverse.js';
import { startDrive, reverseOptions } from '../public/dashboard/js/drive-app.js';
import * as drive from '../public/js/driveclient.js';
import {
  setReverseStretcher, createReverseKey, sealReversePriv, openReversePriv, linkProof, passwordGate, sealNote, openUpload, fragmentOf,
  newReverseId, pubFromFragment,
} from '../public/js/reversekeys.js';
import { createDriveKey, saveSessionKey, clearSessionKey, saveImpersonationKey, clearImpersonationKey, wrapRecovery, recoveryRef, deriveSubkeys, openField } from '../public/js/drivekeys.js';
import { hkdf32 } from '../public/js/crypto.js';
import { utf8, fromUtf8, bytesFromB64url } from '../public/js/bytes.js';
import { formatDate } from '../public/js/common.js';
import { CHUNK, TAG } from '../public/js/files.js';
import { fakeServer, seedTree, seedReceived } from './drive-fake-server.js';

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

beforeEach(() => { document.body.replaceChildren(); delete globalThis.turnstile; clearSessionKey(); clearImpersonationKey(); });
afterEach(() => { vi.restoreAllMocks(); });

// ── the uploader page ─────────────────────────────────────────────────────────

/** A stand-in for /api/reverse/<id>/… and /api/config behind fetch. */
async function reverseServer({ password = null, note = null, limits = {}, turnstile = null, status = 200 } = {}) {
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
  it('shows the note as text, the limits, and sends encrypted files after the human check passes', async () => {
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
    // The widget is shown; Send stays disabled until the check passes.
    await until(() => w.renders.length);
    expect($('#reverse-human').hidden).toBe(false);
    expect(w.renders[0].opts).toMatchObject({ action: 'reverse-upload', appearance: 'always' });
    expect(send.disabled).toBe(true);
    send.disabled = false; // the page cannot force it either
    expect(send.disabled).toBe(true);
    w.solve('tok-1');
    expect(send.disabled).toBe(false);
    send.click();
    await until(() => !$('#reverse-done').hidden);
    expect($('#reverse-done').textContent).toMatch(/Sent 2 files \(11 B\), encrypted/);
    expect(S.begins[0]['x-secbin-turnstile']).toBe('tok-1');
    expect(S.done).toBe(1);
    expect([...S.files.values()].every((f) => f.finalized)).toBe(true);
    // Nothing on the wire names or types a file.
    const wire = JSON.stringify(S.requests.map((x) => x.body ?? null));
    for (const w2 of ['a.txt', 'b.txt', 'text/plain', 'alpha']) expect(wire).not.toContain(w2);
    // The user's key opens what was sent.
    const f = [...S.files.values()][0];
    const got = await openUpload(S.privateKey, S.id, { id: f.id, name: f.name, meta: f.meta, fk: { kind: 'rs', data: f.wrap } });
    expect(['a.txt', 'b.txt']).toContain(got.path);
    // The limits shown are updated; the list is empty again; the next send needs a new check.
    expect($('#reverse-limits').textContent).toMatch(/3 more files at most/);
    expect(document.querySelectorAll('#reverse-list li')).toHaveLength(0);
    pick($('#reverse-file-input'), [fileOf('c.txt', 'c')]);
    expect(send.disabled).toBe(true);
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

  it('limitsText', () => {
    expect(limitsText({})).toBe('This link accepts any files.');
    expect(limitsText({ filesLeft: 1, types: { mode: 'block', rules: ['ext:exe', 'mime:video/*'] } })).toBe('This link accepts 1 more file at most · no .exe, video/*.');
  });
});

// ── the Drive: Receive files… and received files ─────────────────────────────

const CODE = 'ABCD-EFGH-JKMN-PQRS';
let S;
let dk;
let ids;
async function server({ locked = false } = {}) {
  S = fakeServer({ capacity: 50 * 1024 * 1024 });
  globalThis.fetch = S.fetch;
  dk = createDriveKey();
  const w = await wrapRecovery(dk, CODE, await recoveryRef(CODE));
  S.wraps.set(`${w.kind}|${w.ref}`, w);
  ids = await seedTree(S, dk, { Documents: { 'notes.md': utf8('# notes') }, 'readme.txt': utf8('hi') });
  if (!locked) saveSessionKey(dk, S.user.id);
  return S;
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
const deps = (profile = PROFILE, extra = {}) => ({ drive, profile, user: S.user, confirm, canUsePasskey: async () => false, revoke: (id) => fetch(`/api/private/shares/${id}/revoke`, { method: 'POST' }), ...extra });
const names = () => [...document.querySelectorAll('#drive-rows tr')].map((tr) => tr.children[1].textContent.trim());
const dialog = () => document.querySelector('.drive-dialog [role="dialog"]');
const button = (root, text) => [...root.querySelectorAll('button')].find((b) => b.textContent.trim() === text);
/** A reverse share the Drive already has (its key sealed with DK), as the server lists it. */
async function existingReverse(folder = 'root') {
  const id = newReverseId();
  const { pub, privateKey } = await createReverseKey();
  S.reverse.push({ id, folder, label: 'old', priv: await sealReversePriv(dk, id, privateKey), status: 'active', files: 0, bytes: 0, created: 1700000000, expires: 2000000000 });
  return { id, pub };
}

describe('Drive: Receive files…', () => {
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
    expect(dialog().querySelector('.modal-title').textContent).toBe('Receive files into “Documents”');
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
    // The link's key is not sent; the private key is sealed with this Drive's key.
    expect(raw).not.toContain(m[2]);
    expect(fragmentOf((await openReversePriv(dk, b.id, b.priv)).pub)).toBe(m[2]);
    expect(b.lh).toBe(await sha(await linkProof(pubFromFragment(m[2]))));
    expect(dialog().querySelector('.modal-sub').textContent).toMatch(/into “Documents” for 3 days/);
    expect($('#drive-rev-copy')).not.toBeNull();
  });

  it('the owner acting as the user is not asked to confirm (the server asks for nothing then)', async () => {
    await server({ locked: true });
    // The owner's tab already opened this user's Drive through the escrow (docs/DRIVE.md §3).
    S.impersonatedBy = 'owner';
    saveImpersonationKey(dk, S.user.id);
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
    expect(reverseOptions({ n: '2', unit: 'h' }, { maxExpireSec: 3600 }).field).toBe('expire');
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
  });
});

describe('Drive: received files', () => {
  it('are re-wrapped into the Drive when it opens: folders made from their paths, names readable, unreadable ones counted', async () => {
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
    // The re-wrapped fields are the Drive's own: sealed with DK's keys, bound to the node.
    const keys = await deriveSubkeys(dk);
    const inDocs = S.accepted.filter((x) => x.body.parent === ids.get('Documents'));
    const leaves = await Promise.all(inDocs.map(async (x) => fromUtf8(await openField(keys.names, 'name', x.id, x.body.name))));
    expect([...leaves].sort()).toEqual(['b.txt', 'notes (2).md']);
    const { id, body: b } = inDocs[leaves.indexOf('b.txt')];
    expect(JSON.parse(fromUtf8(await openField(keys.names, 'meta', id, b.meta)))).toMatchObject({ type: 'text/plain', size: 5 });
    expect((await openField(keys.files, 'fk', id, b.fk)).length).toBe(32);
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

  it('while the Drive is locked, the unlock prompt says how many are waiting', async () => {
    await server({ locked: true });
    const rs = await existingReverse('root');
    await seedReceived(S, { rid: rs.id, pub: rs.pub, path: 'a.txt', bytes: utf8('a') });
    await seedReceived(S, { rid: rs.id, pub: rs.pub, path: 'b.txt', bytes: utf8('b') });
    const r = await startDrive(mountPoint(), deps());
    expect(r.state).toBe('locked');
    expect($('#drive-received-waiting').textContent).toBe('2 new received files: unlock your Drive to add them to your folders.');
  });
});

// ── security audit round 3 (M-1, L-5): the take-in ─────────────────────────
describe('audit round 3: taking received files in', () => {
  const dirs = () => [...S.nodes.values()].filter((n) => n.kind === 'dir' && !n.rs).length;
  const keysOf = async () => deriveSubkeys(dk);
  const openName = async (id) => fromUtf8(await openField((await keysOf()).names, 'name', id, S.nodes.get(id).name));
  const openMeta = async (id) => JSON.parse(fromUtf8(await openField((await keysOf()).names, 'meta', id, S.nodes.get(id).meta)));

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
    const deepIds = await seedTree(S, dk, { deep: top });
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
