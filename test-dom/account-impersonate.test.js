// account-impersonate.test.js (DOM) — the account page while the owner acts
// as a user ("Log in as"): every form is there (username, password, passkeys,
// recovery codes, the sign-in steps, API keys), the "confirm it's you" fields
// are hidden and no change sends a confirmation, the password is not held to
// the user's policy, new recovery codes are shown to the owner, the page says
// plainly whose account it is, and each card keeps its human check. The page
// is the real public/dashboard/account/index.html and account.js; the
// network, the WebAuthn prompts and the password stretching are stand-ins.
import { describe, it, expect, vi, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const calls = [];
const config = { turnstile: '0x4AAAAAAAsitekey' };
const record = (name, ret = {}) => async (...args) => { calls.push({ name, args }); return typeof ret === 'function' ? ret(...args) : ret; };
const PASSKEY = { id: 'pk1', name: 'Laptop', created: 1, lastUsed: null, synced: false };
const KEY = { id: 'AAAAAAAAAAAAAAAA', name: 'cli', created: 1, last_used: null, expires: null, scopes: ['notes'] };
const CODES = Array.from({ length: 20 }, (_, i) => `AAAA-BBBB-CCCC-${String(i).padStart(4, '0')}`);
const policyChecks = { user: 0, owner: 0 };

vi.mock('../public/js/api.js', () => {
  class ApiError extends Error {}
  return {
    ApiError,
    fetchConfig: async () => config,
    changePassword: record('changePassword', { ok: true, passkeys: 1, recoveryLeft: 20 }),
    listKeys: async () => ({ keys: [KEY] }),
    createKey: record('createKey', { key: 'sbk_x' }),
    updateKey: record('updateKey'),
    revokeKey: record('revokeKey'),
    myActivity: async () => ({ rows: [] }),
    myPasskeys: async () => ({ passkeys: [PASSKEY], mode: 'any', mfa: false, required: false, recoveryLeft: 20, max: 10 }),
    passkeyRegisterOptions: async () => ({ challengeId: 'c1', publicKey: {} }),
    addPasskey: record('addPasskey', { codes: null }),
    removePasskey: record('removePasskey'),
    regenerateRecoveryCodes: record('regenerateRecoveryCodes', { codes: CODES }),
    setSecondFactor: record('setSecondFactor'),
    changeUsername: record('changeUsername', (name) => ({ username: name })),
  };
});
vi.mock('../public/js/kdf-progress.js', () => ({}));
// createPasskeyPrf: the Drive's account page asks for the PRF output at registration (no PRF here).
vi.mock('../public/js/passkeys.js', () => ({ passkeysSupported: () => true, createPasskey: async () => ({ id: 'new' }), createPasskeyPrf: async () => ({ credential: { id: 'new' }, prf: null }) }));
vi.mock('../public/js/pwauth.js', () => ({
  newCredential: async () => ({ salt: 's', t: 3, proof: 'p' }),
  checkNewPassword: () => { policyChecks.user += 1; return 'too short'; },
  checkOwnerPassword: () => { policyChecks.owner += 1; return null; },
  describePolicy: () => 'At least 20 characters.',
}));
// A real confirmation would be asked for here: it must never be while impersonating.
const confirmStep = vi.fn(async () => ({ current: 'proof' }));
vi.mock('../public/dashboard/js/confirm.js', () => ({ confirmLabel: (t) => t, confirmStep: (...a) => confirmStep(...a) }));
vi.mock('../public/dashboard/js/nav.js', () => ({
  ready: Promise.resolve({
    user: { username: 'carol', role: 'user' },
    impersonatedBy: 'boss',
    limits: { text: true, files: true, maxViews: null, allowUnlimitedViews: true, maxExpireSec: null, maxFileBytes: null, maxFilesPerShare: null },
    caps: { maxShareBytes: 1 },
    viewer: { enabled: false },
    apiKeys: { enabled: true, max: 5 },
    quotas: [],
    passwordPolicy: { minLength: 20 },
    passkeys: { mode: 'any' },
  }),
}));

const widgets = new Map();
globalThis.turnstile = {
  render(el, opts) { const id = `w${widgets.size + 1}`; widgets.set(el.id, { id, opts }); return id; },
  reset() {},
};
let seq = 0;
const solve = (el) => { const t = `tok-${++seq}`; widgets.get(el).opts.callback(t); return t; };

const $ = (s) => document.querySelector(s);
const tick = async (n = 10) => { for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 0)); };
const last = (name) => calls.filter((c) => c.name === name).at(-1);
/** Shown: neither the element nor any ancestor is hidden. */
const shown = (el) => { for (let e = el; e; e = e.parentElement) if (e.hidden) return false; return true; };

async function mountPage() {
  const html = readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '../public/dashboard/account/index.html'), 'utf8');
  const body = html.slice(html.indexOf('<body'), html.indexOf('</body>') + '</body>'.length);
  const doc = new DOMParser().parseFromString(`<!doctype html><html>${body}</html>`, 'text/html');
  for (const s of doc.querySelectorAll('script')) s.remove();
  document.body.replaceChildren(...[...doc.body.childNodes].map((n) => document.importNode(n, true)));
  vi.resetModules();
  await import('../public/dashboard/js/account.js');
  await tick();
}

describe('the account page while the owner acts as the user', () => {
  beforeAll(mountPage);

  it('shows every form: username, password, passkeys, recovery codes, sign-in steps and API keys', () => {
    for (const sel of ['#name-form', '#name-new', '#name-btn', '#pw-form', '#pw-new', '#pw-new2', '#pw-btn',
      '#passkeys-actions', '#passkey-form', '#passkey-add', '#recovery-regen', '#mfa-row', '#mfa-on', '#mfa-off',
      '#key-form', '#key-create']) {
      expect(shown($(sel)), sel).toBe(true);
    }
    const buttons = [...document.querySelectorAll('#keys-body button')].map((b) => b.textContent);
    expect(buttons).toEqual(['Edit', 'Revoke']);
    expect([...document.querySelectorAll('#passkeys-body button')].map((b) => b.textContent)).toEqual(['Remove']);
  });

  it('hides every "confirm it\'s you" field', () => {
    for (const sel of ['#name-current', '#pw-current', '#passkey-current', '#key-current']) {
      expect(shown($(sel)), sel).toBe(false);
      expect(shown($(`${sel}-label`)), `${sel}-label`).toBe(false);
    }
  });

  it('says plainly whose account this is', () => {
    expect($('#acct-title').textContent).toBe('carol’s account.');
    expect($('#acct-sub').textContent).toMatch(/^You \(boss\) are acting as carol: every change here is made to carol’s account/);
    expect($('#pw-policy').textContent).toBe('As the owner, you choose any password for carol.');
  });

  it('keeps a human check on every card', () => {
    expect([...widgets.keys()].sort()).toEqual(['key-turnstile', 'name-turnstile', 'passkey-turnstile', 'pw-turnstile']);
    expect($('#name-btn').disabled).toBe(true);
    solve('name-turnstile');
    expect($('#name-btn').disabled).toBe(false);
  });

  it('sends every change with no confirmation, and the password without the user\'s policy', async () => {
    solve('name-turnstile');
    $('#name-new').value = 'carol2';
    $('#name-form').requestSubmit();
    await tick();
    expect(last('changeUsername').args.slice(0, 2)).toEqual(['carol2', {}]);
    expect($('#acct-title').textContent).toBe('carol2’s account.');

    solve('pw-turnstile');
    $('#pw-new').value = 'x';
    $('#pw-new2').value = 'x';
    $('#pw-form').requestSubmit();
    await tick();
    expect(policyChecks).toEqual({ user: 0, owner: 1 });
    // "Also revoke my API keys" is ticked by default (audit W3 A-8).
    expect(last('changePassword').args[0]).toEqual({ salt: 's', t: 3, proof: 'p', revokeKeys: true });
    expect($('#pw-msg').textContent).toMatch(/carol2’s sessions were signed out/);
    expect($('#pw-revoke-keys').checked).toBe(true); // ticked again after the change
    solve('pw-turnstile');
    $('#pw-new').value = 'x';
    $('#pw-new2').value = 'x';
    $('#pw-revoke-keys').checked = false;
    $('#pw-form').requestSubmit();
    await tick();
    expect(last('changePassword').args[0]).toEqual({ salt: 's', t: 3, proof: 'p', revokeKeys: false });

    solve('passkey-turnstile');
    $('#passkey-form').requestSubmit();
    await tick();
    expect(last('addPasskey').args[0]).toEqual({ challengeId: 'c1', credential: { id: 'new' }, name: 'Passkey' });

    solve('passkey-turnstile');
    $('#mfa-on').checked = true;
    $('#mfa-on').dispatchEvent(new Event('change'));
    await tick();
    expect(last('setSecondFactor').args.slice(0, 2)).toEqual([true, {}]);

    solve('passkey-turnstile');
    $('#recovery-regen').click();
    $('#recovery-regen').click();
    await tick();
    expect(last('regenerateRecoveryCodes').args[0]).toEqual({});
    // The new codes are shown to the owner.
    expect(shown($('#recovery-new'))).toBe(true);
    expect([...document.querySelectorAll('#recovery-list li')].map((li) => li.textContent)).toEqual(CODES);

    solve('passkey-turnstile');
    const rm = $('#passkeys-body button');
    rm.click();
    rm.click();
    await tick();
    expect(last('removePasskey').args.slice(0, 2)).toEqual(['pk1', {}]);

    solve('key-turnstile');
    $('#key-name').value = 'laptop';
    $('#key-form').requestSubmit();
    await tick();
    expect(last('createKey').args.slice(0, 4)).toEqual(['laptop', null, ['notes', 'files', 'policy'], {}]);
    expect($('#key-new-val').textContent).toBe('sbk_x');

    solve('key-turnstile');
    [...document.querySelectorAll('#keys-body button')].find((b) => b.textContent === 'Edit').click();
    [...document.querySelectorAll('#keys-body button')].find((b) => b.textContent === 'Save').click();
    await tick();
    expect(last('updateKey').args.slice(0, 3)).toEqual([KEY.id, { name: 'cli', scopes: ['notes'] }, {}]);

    solve('key-turnstile');
    const rv = $('#keys-body button.danger');
    rv.click();
    rv.click();
    await tick();
    expect(last('revokeKey').args.slice(0, 2)).toEqual([KEY.id, {}]);

    expect(confirmStep).not.toHaveBeenCalled();
  });
});
