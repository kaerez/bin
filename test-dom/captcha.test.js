// captcha.test.js (DOM) — CAPTCHA on shares in the browser:
//   - the per-share box (public/js/captcha.js) for "allow" (pre-set from the
//     role's default), "require" (ticked, disabled) and "off" (hidden), in the
//     composer, the Drive's Share dialog and its Receive files dialog, and
//     what each sends;
//   - the recipient's viewer (public/js/view.js) with a share that has the
//     CAPTCHA: the key leaves the address bar at once and is kept only sealed
//     (with the tab's Drive keys) for the check page; the check page
//     (public/js/check.js) keeps Continue disabled until the CAPTCHA passes and
//     never holds the key; back on the strict page the key is opened, put back
//     in the address bar, and the share opens with the grant — and that
//     document never has Turnstile's script;
//   - fail closed without sessionStorage or without a page key;
//   - the uploader page (public/js/reverse.js) of a link with the CAPTCHA: the
//     same round trip, one grant per session start, "Complete the CAPTCHA
//     again" after a send or a wrong password.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { captchaChoice, captchaBox, captchaValue, captchaHint } from '../public/js/captcha.js';
import { stashKey, stashedNonce, takeKey, saveGrant, loadGrant, DRIVE_SLOTS } from '../public/js/pagekey.js';
import { encryptPaste } from '../public/js/crypto.js';
import { b64urlFromBytes, randomBytes, utf8 } from '../public/js/bytes.js';
import { createReverseKey, fragmentOf, newReverseId, linkProof, setReverseStretcher, passwordGate } from '../public/js/reversekeys.js';
import { hkdf32 } from '../public/js/crypto.js';
import { startDrive } from '../public/dashboard/js/drive-app.js';
import * as drive from '../public/js/driveclient.js';
import { createDriveKey, saveSessionKey, clearSessionKey, wrapRecovery, recoveryRef } from '../public/js/drivekeys.js';
import { fakeServer, seedTree } from './drive-fake-server.js';

setReverseStretcher(async (pw, salt) => hkdf32(pw, salt, utf8('dom-stretch')));

const T = 30000;
const until = async (fn, ms = 10000) => {
  const t0 = Date.now();
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 10));
  }
};
const $ = (s) => document.querySelector(s);
const read = (p) => readFileSync(join(process.cwd(), p), 'utf8');
const mainOf = (p) => `${read(p).match(/<main[\s\S]*<\/main>/)[0]}<div id="toast" role="status"></div>`;
const reply = (data, status = 200, headers = {}) => ({ ok: status < 400, status, type: 'basic', headers: new Headers(headers), json: async () => data, arrayBuffer: async () => new ArrayBuffer(0) });
const allStorage = () => { const o = {}; for (let i = 0; i < sessionStorage.length; i++) { const k = sessionStorage.key(i); o[k] = sessionStorage.getItem(k); } return JSON.stringify(o); };
const pageKey = () => ({ n: b64urlFromBytes(randomBytes(16)), key: b64urlFromBytes(randomBytes(32)) });
function addPageKey(pk) {
  const m = document.createElement('meta');
  m.name = 'secbin-page-key';
  m.content = `${pk.n}.${pk.key}`;
  document.head.appendChild(m);
}
const turnstileScripts = () => [...document.querySelectorAll('script')].filter((s) => /challenges\.cloudflare\.com/.test(s.src));
function fakeTurnstile() {
  const w = { renders: [] };
  globalThis.turnstile = { render(el, opts) { w.renders.push({ el, opts }); return 'w1'; }, reset() {} };
  w.solve = (t) => w.renders.at(-1).opts.callback(t);
  return w;
}

beforeEach(() => {
  sessionStorage.clear();
  document.head.replaceChildren();
  document.body.replaceChildren();
  delete globalThis.turnstile;
  clearSessionKey();
});
afterEach(() => { vi.restoreAllMocks(); });

// ── the per-share box ─────────────────────────────────────────────────────
describe('the per-share box follows the role', () => {
  const prof = (limits, active = true) => ({ limits, captchaActive: active });
  it('allow: shown, pre-set from the default, the user decides; require: ticked and disabled; off: hidden and never sent', () => {
    let c = captchaChoice(prof({ shareCaptcha: 'allow', shareCaptchaDefault: 'off' }), 'share');
    expect(c).toMatchObject({ show: true, checked: false, disabled: false });
    c = captchaChoice(prof({ shareCaptcha: 'allow', shareCaptchaDefault: 'on' }), 'share');
    expect(c).toMatchObject({ show: true, checked: true, disabled: false });
    expect(captchaValue(c, { checked: false })).toBe(false);
    expect(captchaValue(c, { checked: true })).toBe(true);
    c = captchaChoice(prof({ shareCaptcha: 'require', shareCaptchaDefault: 'off' }), 'share');
    expect(c).toMatchObject({ show: true, checked: true, disabled: true });
    expect(captchaValue(c, { checked: false })).toBe(true);
    c = captchaChoice(prof({ shareCaptcha: 'off', shareCaptchaDefault: 'on' }), 'share');
    expect(c).toMatchObject({ show: false });
    expect(captchaValue(c, { checked: true })).toBeUndefined();
    // The reverse options are separate.
    expect(captchaChoice(prof({ shareCaptcha: 'off', reverseCaptcha: 'require' }), 'reverse')).toMatchObject({ show: true, disabled: true });
    // A profile without the options (the public composer): hidden.
    expect(captchaChoice(null, 'share').show).toBe(false);
  });

  it('as DOM: a labelled checkbox with its explanation (and whether the server enforces it yet)', () => {
    const b = captchaBox({ id: 'x-cap', profile: prof({ shareCaptcha: 'require' }, false), which: 'share' });
    document.body.append(b.el);
    const input = $('#x-cap');
    expect(input.closest('label').textContent.trim()).toBe('Require CAPTCHA to open');
    expect(input.checked).toBe(true);
    expect(input.disabled).toBe(true);
    const hint = document.getElementById(input.getAttribute('aria-describedby'));
    expect(hint.textContent).toMatch(/requires it on every share/);
    expect(hint.textContent).toMatch(/not active on this server yet/);
    expect(hint.classList.contains('warn')).toBe(true);
    const r = captchaBox({ id: 'y-cap', profile: prof({ reverseCaptcha: 'allow', reverseCaptchaDefault: 'off' }), which: 'reverse' });
    document.body.append(r.el);
    expect($('#y-cap').closest('label').textContent.trim()).toBe('Require CAPTCHA to send files');
    expect($('#y-cap').checked).toBe(false);
    expect(captchaHint(r.choice, 'reverse')).toMatch(/Senders complete a CAPTCHA/);
    $('#y-cap').click();
    expect(r.value()).toBe(true);
    expect(captchaBox({ id: 'z-cap', profile: prof({ shareCaptcha: 'off' }), which: 'share' }).el.hidden).toBe(true);
  });
});

describe('the composer', () => {
  it('shows the box as the role says and sends the choice', async () => {
    document.body.innerHTML = mainOf('public/dashboard/index.html');
    const calls = [];
    const api = { createNote: async (paste, label, extra) => { calls.push(extra); return { id: `k${'A'.repeat(22)}`, deletetoken: 'D'.repeat(43) }; } };
    const { startComposer } = await import('../public/js/composer.js');
    const L = { text: true, files: false, url: false, secret: false, openerDelete: false, maxViews: null, allowUnlimitedViews: true, maxExpireSec: null, urlRules: [], fileTypeMode: 'any', maxFolderDepth: null, shareCaptcha: 'allow', shareCaptchaDefault: 'on' };
    startComposer({ limits: L, caps: { maxShareBytes: 100 * 1024 * 1024 }, viewer: { enabled: false }, captchaActive: true }, api);
    const box = $('#captcha');
    expect($('#captcha-opt').hidden).toBe(false);
    expect(box.checked).toBe(true);
    expect(box.disabled).toBe(false);
    expect($('#captcha-hint').textContent).toMatch(/^Recipients complete a CAPTCHA/);
    box.click(); // the user turns it off for this note
    $('#editor').value = 'hello';
    $('#create').click();
    await until(() => calls.length, T);
    expect(calls[0]).toEqual({ captcha: false });
  }, T);
});

// ── the Drive's dialogs ────────────────────────────────────────────────────
describe('the Drive: Share and Receive files', () => {
  let S;
  const CODE = 'ABCD-EFGH-JKMN-PQRS';
  async function openDrive(limits) {
    S = fakeServer();
    globalThis.fetch = S.fetch;
    const dk = createDriveKey();
    const w = await wrapRecovery(dk, CODE, await recoveryRef(CODE));
    S.wraps.set(`${w.kind}|${w.ref}`, w);
    await seedTree(S, dk, { 'readme.txt': utf8('hi') });
    saveSessionKey(dk, S.user.id);
    const mount = document.createElement('div');
    document.body.replaceChildren(document.createElement('main'), mount);
    document.body.firstChild.id = 'main';
    const profile = { limits: { maxViews: 100, allowUnlimitedViews: true, maxExpireSec: null, files: true, reverseMaxBytes: null, ...limits }, caps: { driveEnabled: true, reverseEnabled: true }, viewer: { enabled: false }, captchaActive: true };
    const r = await startDrive(mount, { drive, profile, user: S.user, confirm: async () => ({ current: 'proof' }), canUsePasskey: async () => false, revoke: async () => {} });
    await r.app.ready;
  }
  const dialog = () => $('.drive-dialog [role="dialog"]');
  const button = (root, text) => [...root.querySelectorAll('button')].find((b) => b.textContent.trim() === text);
  const shareReadme = () => {
    [...document.querySelectorAll('#drive-rows tr')].find((tr) => tr.children[1].textContent.trim() === 'readme.txt').querySelector('input[type="checkbox"]').click();
    $('#drive-share').click();
    return dialog();
  };

  it('Share: "allow" pre-set from the default and sent as chosen; "require" ticked and disabled; "off" hidden and not sent', async () => {
    await openDrive({ shareCaptcha: 'allow', shareCaptchaDefault: 'off' });
    let d = shareReadme();
    const box = d.querySelector('#drive-share-captcha');
    expect(box.checked).toBe(false);
    expect(box.disabled).toBe(false);
    box.click();
    button(d, 'Create link').click();
    await until(() => d.querySelector('#drive-share-url'));
    expect(S.shareBodies[0].captcha).toBe(true);
    await openDrive({ shareCaptcha: 'require', shareCaptchaDefault: 'off' });
    d = shareReadme();
    expect(d.querySelector('#drive-share-captcha').checked).toBe(true);
    expect(d.querySelector('#drive-share-captcha').disabled).toBe(true);
    button(d, 'Create link').click();
    await until(() => d.querySelector('#drive-share-url'));
    expect(S.shareBodies[0].captcha).toBe(true);
    await openDrive({ shareCaptcha: 'off' });
    d = shareReadme();
    expect(d.querySelector('#drive-share-captcha').closest('.captcha-opt').hidden).toBe(true);
    button(d, 'Create link').click();
    await until(() => d.querySelector('#drive-share-url'));
    expect('captcha' in S.shareBodies[0]).toBe(false);
  }, T);

  it('Receive files: the reverse options; the folder\'s links show the CAPTCHA', async () => {
    await openDrive({ reverseCaptcha: 'allow', reverseCaptchaDefault: 'on' });
    $('#drive-receive').click();
    const d = await until(() => dialog());
    await until(() => $('#drive-rev-none'));
    const box = $('#drive-rev-captcha');
    expect(box.closest('label').textContent.trim()).toBe('Require CAPTCHA to send files');
    expect(box.checked).toBe(true);
    $('#drive-rev-confirm').value = 'pw';
    button(d, 'Create link').click();
    await until(() => $('#drive-rev-url'));
    expect(S.reverse[0].captcha).toBe(true);
    button(d, 'Done').click();
    $('#drive-receive').click();
    await until(() => $('#drive-rev-list tbody tr'));
    expect($('#drive-rev-list tbody tr').textContent).toMatch(/active · CAPTCHA/);
  }, T);
});

// ── the recipient's viewer ────────────────────────────────────────────────
describe('the viewer: a share with the CAPTCHA', () => {
  const ID = `k${b64urlFromBytes(randomBytes(16))}`;
  const GRANT = `h1.${b64urlFromBytes(utf8('{"k":"s"}'))}.${'M'.repeat(43)}`;
  const DK_B64 = b64urlFromBytes(randomBytes(32));
  let note;
  let requests;
  const shareFetch = vi.fn(async (url, init = {}) => {
    const u = new URL(url, 'https://bin.example');
    const h = init.headers || {};
    requests.push({ path: u.pathname, method: init.method || 'GET', headers: h });
    const human = h['x-secbin-human'] === GRANT;
    if (u.pathname === '/api/config') return reply({ turnstile: '0x4AAAAAAAsitekey' });
    if (u.pathname === `/api/paste/${ID}/human`) return h['x-secbin-turnstile'] === 'tok-1' ? reply({ grant: GRANT, expires: 2000000000 }) : reply({ error: 'turnstile_failed', message: 'x' }, 403);
    if (!human) return reply({ error: 'captcha_required', message: 'This share requires a CAPTCHA; open it in a browser.' }, 403);
    if (u.pathname === `/api/paste/${ID}`) return reply({ v: note.body.v, adata: note.body.adata, meta: note.meta });
    if (u.pathname === `/api/paste/${ID}/open`) return reply({ v: note.body.v, ct: note.body.ct, wk: note.body.wk, adata: note.body.adata, meta: note.meta });
    return reply({ error: 'not_found' }, 404);
  });

  async function loadViewer(url, pk) {
    window.happyDOM.setURL(url);
    document.head.replaceChildren();
    document.body.innerHTML = mainOf('public/index.html');
    if (pk) addPageKey(pk);
    vi.resetModules();
    await import('../public/js/view.js');
  }

  it('strips the key, seals it for the check page, passes the check there, and opens back on the strict page — Turnstile never in the decrypting document', async () => {
    const t = Math.floor(Date.now() / 1000);
    const enc = await encryptPaste({ text: 'the protected note', bar: false, expire: '1h' });
    note = { body: enc.body, meta: { expire: '1h', created: t, expires: t + 3600 } };
    const K = enc.fragment;
    requests = [];
    globalThis.fetch = shareFetch;
    const replace = vi.spyOn(window.location, 'replace').mockImplementation(() => {});
    // The tab also holds a Drive key (the user is signed in here).
    sessionStorage.setItem('secbin_dk', DK_B64);
    sessionStorage.setItem('secbin_dk_uid', 'u1');
    const pk = pageKey();

    // 1. The strict page with the key: refused → the key leaves the URL and storage holds it sealed only.
    await loadViewer(`https://bin.example/p/${ID}#${K}`, pk);
    await until(() => replace.mock.calls.length);
    expect(replace.mock.calls[0][0]).toBe(`/p/${ID}?check`);
    expect(location.hash).toBe('');
    expect(location.href).not.toContain(K);
    expect(allStorage()).not.toContain(K);
    expect(allStorage()).not.toContain(DK_B64);
    for (const k of DRIVE_SLOTS) expect(sessionStorage.getItem(k)).toBeNull();
    expect(stashedNonce({ kind: 'p', id: ID, storage: sessionStorage })).toBe(pk.n);
    expect($('meta[name="secbin-page-key"]')).toBeNull(); // read once, then gone
    expect(turnstileScripts()).toHaveLength(0);

    // 2. The check page (Turnstile's CSP in real life): Continue waits for the CAPTCHA; the key is nowhere here.
    window.happyDOM.setURL(`https://bin.example/p/${ID}?check`);
    document.body.innerHTML = mainOf('public/check/index.html');
    const w = fakeTurnstile();
    vi.resetModules();
    await import('../public/js/check.js');
    const go = await until(() => $('#check-continue'));
    expect($('#check-title').textContent).toBe('Complete the CAPTCHA to open this share');
    await until(() => w.renders.length);
    expect(w.renders[0].opts).toMatchObject({ action: 'share-open' });
    expect(go.disabled).toBe(true);
    expect($('.human-wait').textContent).toBe('Waiting for the CAPTCHA…');
    w.solve('tok-1'); // enabled by the check alone (nothing else on the page enables it)
    expect(go.disabled).toBe(false);
    go.click();
    await until(() => replace.mock.calls.length === 2);
    expect(replace.mock.calls[1][0]).toBe(`/p/${ID}?n=${encodeURIComponent(pk.n)}`);
    expect(loadGrant({ kind: 'p', id: ID, storage: sessionStorage })).toBe(GRANT);
    expect(allStorage()).not.toContain(K);
    expect(document.documentElement.outerHTML).not.toContain(K);
    delete globalThis.turnstile;

    // 3. Back on the strict page (?n=…): the page key for n opens the key; the share opens with the grant.
    requests = [];
    await loadViewer(`https://bin.example/p/${ID}?n=${pk.n}`, pk);
    await until(() => $('#paste-content') && $('#paste-content').textContent.includes('the protected note'));
    expect(location.hash).toBe(`#${K}`);
    expect(location.search).toBe('');
    expect(stashedNonce({ kind: 'p', id: ID, storage: sessionStorage })).toBeNull();
    expect(sessionStorage.getItem('secbin_dk')).toBe(DK_B64); // the Drive key is back
    expect(sessionStorage.getItem('secbin_dk_uid')).toBe('u1');
    expect(requests.filter((r) => r.path.startsWith(`/api/paste/${ID}`)).every((r) => r.headers['x-secbin-human'] === GRANT)).toBe(true);
    // The decrypting document never had Turnstile's script (nor asked for its site key).
    expect(turnstileScripts()).toHaveLength(0);
    expect(globalThis.turnstile).toBeUndefined();
    expect(requests.some((r) => r.path === '/api/config')).toBe(false);
  }, T);

  it('fails closed without sessionStorage, and without a page key (the key still leaves the address bar)', async () => {
    const t = Math.floor(Date.now() / 1000);
    const enc = await encryptPaste({ text: 'x', bar: false, expire: '1h' });
    note = { body: enc.body, meta: { expire: '1h', created: t, expires: t + 3600 } };
    requests = [];
    globalThis.fetch = shareFetch;
    const replace = vi.spyOn(window.location, 'replace').mockImplementation(() => {});
    await loadViewer(`https://bin.example/p/${ID}#${enc.fragment}`, null);
    await until(() => /cannot complete safely/.test($('#status-msg').textContent));
    expect(location.hash).toBe('');
    expect(replace).not.toHaveBeenCalled();
    expect(allStorage()).not.toContain(enc.fragment);
    // No storage at all.
    const getter = vi.spyOn(window, 'sessionStorage', 'get').mockImplementation(() => { throw new Error('denied'); });
    await loadViewer(`https://bin.example/p/${ID}#${enc.fragment}`, pageKey());
    await until(() => /site storage is off/.test($('#status-msg').textContent));
    expect(replace).not.toHaveBeenCalled();
    getter.mockRestore();
    // A sealed record opens only with the page key of its own nonce.
    const pk = pageKey();
    await stashKey({ kind: 'p', id: ID, fragment: 'K'.repeat(43), pageKey: pk, storage: sessionStorage });
    expect(await takeKey({ kind: 'p', id: ID, pageKey: { ...pageKey(), n: pk.n }, storage: sessionStorage })).toBeNull();
    await stashKey({ kind: 'p', id: ID, fragment: 'K'.repeat(43), pageKey: pk, storage: sessionStorage });
    expect(await takeKey({ kind: 'p', id: ID, pageKey: pageKey(), storage: sessionStorage })).toBeNull();
    await stashKey({ kind: 'p', id: ID, fragment: 'K'.repeat(43), pageKey: pk, storage: sessionStorage });
    expect(await takeKey({ kind: 'p', id: ID, pageKey: pk, storage: sessionStorage })).toBe('K'.repeat(43));
  }, T);
});

// ── the uploader ──────────────────────────────────────────────────────────
describe('the uploader: a link with the CAPTCHA', () => {
  async function linkServer({ password = null } = {}) {
    const id = newReverseId();
    const { pub } = await createReverseKey();
    const gate = password ? await passwordGate(password, pub) : null;
    const S = { id, pub, begins: [], spent: new Set(), grants: 0 };
    globalThis.fetch = vi.fn(async (url, init = {}) => {
      const p = new URL(url, 'https://bin.example').pathname;
      const h = init.headers || {};
      const body = typeof init.body === 'string' ? JSON.parse(init.body) : null;
      if (p === `/api/reverse/${id}/open`) {
        if (h['x-link-proof'] !== await linkProof(pub)) return reply({ error: 'bad_link' }, 403);
        return reply({ note: null, password: gate ? { salt: gate.salt, t: gate.t } : null, expires: 2000000000, captcha: true,
          limits: { maxFiles: null, maxBytes: null, maxFileBytes: null, types: null, filesLeft: null, bytesLeft: null } });
      }
      if (p === `/api/reverse/${id}/begin`) {
        S.begins.push(h);
        const g = h['x-secbin-human'];
        if (!g || S.spent.has(g)) return reply({ error: 'captcha_required', message: 'x' }, 403);
        S.spent.add(g);
        if (gate && h['x-key-proof'] === undefined) return reply({ error: 'password_required' }, 401);
        if (S.wrongPassword) return reply({ error: 'bad_password', message: 'x' }, 403);
        return reply({ grant: 'G'.repeat(43), expires: 2000000000 });
      }
      if (p === `/api/reverse/${id}/files`) return reply({ id: body.id, uploadToken: 'T'.repeat(43), chunks: 1 }, 201);
      if (/\/chunk\/0$/.test(p)) return reply({ ok: true });
      if (/\/finalize$/.test(p)) return reply({ ok: true });
      if (p === `/api/reverse/${id}/done`) return reply({ files: 1, bytes: 1 });
      return reply({ error: 'not_found' }, 404);
    });
    return S;
  }
  const page = () => {
    const main = document.createElement('main');
    main.id = 'main';
    const root = document.createElement('div');
    root.id = 'reverse-app';
    main.appendChild(root);
    document.body.replaceChildren(main);
    return root;
  };
  const fileOf = (name) => new File([utf8('abc')], name, { type: 'text/plain' });
  const pick = (files) => { const input = $('#reverse-file-input'); Object.defineProperty(input, 'files', { configurable: true, get: () => files }); input.dispatchEvent(new Event('change')); };

  it('goes to the check page first (key out of the address bar, sealed); back with a grant, one send per CAPTCHA', async () => {
    const S = await linkServer();
    const { mountUploader } = await import('../public/js/reverse.js');
    const K = fragmentOf(S.pub);
    const pk = pageKey();
    const replace = vi.fn();
    const replaceState = vi.fn();
    const loc = { pathname: `/r/${S.id}`, hash: `#${K}`, search: '', replace };
    let r = await mountUploader(page(), { location: loc, history: { replaceState }, storage: sessionStorage, pageKey: pk });
    expect(r.state).toBe('check');
    expect(replaceState).toHaveBeenCalledWith(null, '', `/r/${S.id}`);
    expect(replace).toHaveBeenCalledWith(`/r/${S.id}?check`);
    expect(allStorage()).not.toContain(K);
    expect(S.begins).toHaveLength(0);
    // The check page stored a grant; back with ?n=…
    saveGrant({ kind: 'r', id: S.id, storage: sessionStorage, grant: 'h1.a.first' });
    replaceState.mockClear();
    r = await mountUploader(page(), { location: { pathname: `/r/${S.id}`, hash: '', search: `?n=${pk.n}`, replace }, history: { replaceState }, storage: sessionStorage, pageKey: pk });
    expect(r.state).toBe('ready');
    expect(replaceState).toHaveBeenCalledWith(null, '', `/r/${S.id}#${K}`);
    expect(turnstileScripts()).toHaveLength(0);
    expect($('#reverse-recheck').hidden).toBe(true);
    pick([fileOf('a.txt')]);
    $('#reverse-send').click();
    await until(() => !$('#reverse-done').hidden);
    expect(S.begins[0]['x-secbin-human']).toBe('h1.a.first');
    expect(loadGrant({ kind: 'r', id: S.id, storage: sessionStorage })).toBeNull(); // spent
    expect($('#reverse-done').textContent).toMatch(/To send more, complete the CAPTCHA again/);
    expect($('#reverse-recheck').hidden).toBe(false);
    // A second batch needs the CAPTCHA again: nothing is sent.
    pick([fileOf('b.txt')]);
    $('#reverse-send').click();
    await until(() => !$('#reverse-msg').hidden);
    expect($('#reverse-msg').textContent).toMatch(/needs the CAPTCHA again/);
    expect(S.begins).toHaveLength(1);
    replace.mockClear();
    $('#reverse-recheck').click();
    await until(() => replace.mock.calls.length);
    expect(replace).toHaveBeenCalledWith(`/r/${S.id}?check`);
  }, T);

  it('a wrong password spends the grant: "Complete the CAPTCHA again"', async () => {
    const S = await linkServer({ password: 'right' });
    S.wrongPassword = true;
    const { mountUploader } = await import('../public/js/reverse.js');
    const pk = pageKey();
    await stashKey({ kind: 'r', id: S.id, fragment: fragmentOf(S.pub), pageKey: pk, storage: sessionStorage });
    saveGrant({ kind: 'r', id: S.id, storage: sessionStorage, grant: 'h1.b.one' });
    const r = await mountUploader(page(), { location: { pathname: `/r/${S.id}`, hash: '', search: `?n=${pk.n}`, replace: vi.fn() }, history: { replaceState: vi.fn() }, storage: sessionStorage, pageKey: pk });
    expect(r.state).toBe('ready');
    pick([fileOf('a.txt')]);
    $('#reverse-password').value = 'wrong';
    $('#reverse-send').click();
    await until(() => !$('#reverse-msg').hidden);
    expect($('#reverse-msg').textContent).toMatch(/That password is not right. Complete the CAPTCHA again/);
    expect($('#reverse-recheck').hidden).toBe(false);
    expect($('#reverse-password').getAttribute('aria-invalid')).toBe('true');
    expect(loadGrant({ kind: 'r', id: S.id, storage: sessionStorage })).toBeNull();
  }, T);

  it('the check page for a link says "…to send files" and asks for the reverse action', async () => {
    const id = newReverseId();
    window.happyDOM.setURL(`https://bin.example/r/${id}?check`);
    document.body.innerHTML = mainOf('public/check/index.html');
    globalThis.fetch = vi.fn(async (url) => (new URL(url, 'https://bin.example').pathname === '/api/config' ? reply({ turnstile: '0x4AAAAAAAsitekey' }) : reply({ grant: 'h1.x.y' })));
    const w = fakeTurnstile();
    vi.resetModules();
    await import('../public/js/check.js');
    await until(() => w.renders.length);
    expect($('#check-title').textContent).toBe('Complete the CAPTCHA to send files');
    expect(w.renders[0].opts.action).toBe('reverse-upload');
    // No sealed record in this tab: it says to open the whole link again.
    expect($('#check-page').textContent).toMatch(/does not hold the link any more/);
  }, T);
});
