// account-turnstile.test.js (DOM) — the account page with the human check on:
// every card that changes the account has its own widget, every button that
// sends a change stays disabled until that card's check has passed (again
// after each use), and each request carries its own fresh token in
// X-Secbin-Turnstile (here: the api.js call's token argument). With the
// check off, nothing is gated and no token is sent. The page itself is the
// real public/dashboard/account/index.html and account.js; the network,
// the WebAuthn prompts and the password stretching are stand-ins.
import { describe, it, expect, vi, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const calls = [];
let config = { turnstile: '0x4AAAAAAAsitekey' };
const record = (name) => async (...args) => { calls.push({ name, args }); return {}; };
const PASSKEY = { id: 'pk1', name: 'Laptop', created: 1, lastUsed: null, synced: false };
const KEY = { id: 'AAAAAAAAAAAAAAAA', name: 'cli', created: 1, last_used: null, expires: null, scopes: ['notes'] };

vi.mock('../public/js/api.js', () => {
  class ApiError extends Error {}
  return {
    ApiError,
    fetchConfig: async () => config,
    changePassword: record('changePassword'),
    listKeys: async () => ({ keys: [KEY] }),
    createKey: async (...args) => { calls.push({ name: 'createKey', args }); return { key: 'sbk_x' }; },
    updateKey: record('updateKey'),
    revokeKey: record('revokeKey'),
    myActivity: async () => ({ rows: [] }),
    myPasskeys: async () => ({ passkeys: [PASSKEY], mode: 'any', mfa: false, required: false, recoveryLeft: 20, max: 10 }),
    passkeyRegisterOptions: async () => ({ challengeId: 'c1', publicKey: {} }),
    addPasskey: record('addPasskey'),
    removePasskey: record('removePasskey'),
    regenerateRecoveryCodes: async (...args) => { calls.push({ name: 'regenerateRecoveryCodes', args }); return { codes: [] }; },
    setSecondFactor: record('setSecondFactor'),
    changeUsername: async (...args) => { calls.push({ name: 'changeUsername', args }); return { username: args[0] }; },
  };
});
vi.mock('../public/js/kdf-progress.js', () => ({}));
// Account adds passkeys with the PRF extension (the Drive's passkey wraps): no PRF output here.
vi.mock('../public/js/passkeys.js', () => ({ passkeysSupported: () => true, createPasskey: async () => ({ id: 'new' }), createPasskeyPrf: async () => ({ credential: { id: 'new' }, prf: null }) }));
vi.mock('../public/js/pwauth.js', () => ({
  newCredential: async () => ({ salt: 's', t: 3, proof: 'p' }),
  checkNewPassword: () => null,
  checkOwnerPassword: () => null,
  describePolicy: () => '',
}));
vi.mock('../public/dashboard/js/confirm.js', () => ({
  confirmLabel: (t) => t,
  confirmStep: async (input) => { input.value = ''; return { current: 'proof' }; },
}));
vi.mock('../public/dashboard/js/nav.js', () => ({
  ready: Promise.resolve({
    user: { username: 'alice', role: 'user' },
    impersonatedBy: null,
    limits: { text: true, files: true, maxViews: null, allowUnlimitedViews: true, maxExpireSec: null, maxFileBytes: null, maxFilesPerShare: null },
    caps: { maxShareBytes: 1 },
    viewer: { enabled: false },
    apiKeys: { enabled: true, max: 5 },
    quotas: [],
    passwordPolicy: null,
    passkeys: { mode: 'any' },
  }),
}));

/** Cloudflare's window.turnstile, one entry per rendered widget. */
const widgets = new Map();
globalThis.turnstile = {
  render(el, opts) { const id = `w${widgets.size + 1}`; widgets.set(el.id, { id, opts, resets: 0 }); return id; },
  reset(id) { for (const w of widgets.values()) if (w.id === id) w.resets += 1; },
};
let seq = 0;
/** Pass the check of widget `el` with a new token; returns it. */
const solve = (el) => { const t = `tok-${++seq}`; widgets.get(el).opts.callback(t); return t; };

const $ = (s) => document.querySelector(s);
const tick = async (n = 10) => { for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 0)); };
const tokenOf = (name) => calls.filter((c) => c.name === name).at(-1)?.args.at(-1);

// The card each widget serves, and the controls it gates.
const CARDS = {
  'name-turnstile': ['#name-btn'],
  'pw-turnstile': ['#pw-btn'],
  'passkey-turnstile': ['#passkey-add', '#recovery-regen', '#mfa-off', '#mfa-on', '#passkeys-body button'],
  'key-turnstile': ['#key-create', '#keys-body button.danger'],
};

/** Mount a fresh copy of the account page and run account.js on it. */
async function mountPage() {
  const html = readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '../public/dashboard/account/index.html'), 'utf8');
  // Only the body: the head's stylesheet and scripts are not needed here.
  const body = html.slice(html.indexOf('<body'), html.indexOf('</body>') + '</body>'.length);
  const doc = new DOMParser().parseFromString(`<!doctype html><html>${body}</html>`, 'text/html');
  for (const s of doc.querySelectorAll('script')) s.remove();
  document.body.replaceChildren(...[...doc.body.childNodes].map((n) => document.importNode(n, true)));
  vi.resetModules();
  await import('../public/dashboard/js/account.js');
  await tick();
}
beforeAll(mountPage);

describe('the account page with the human check on', () => {
  it('shows a widget on every card that changes the account', () => {
    expect([...widgets.keys()].sort()).toEqual(Object.keys(CARDS).sort());
    for (const [el, w] of widgets) {
      expect($(`#${el}`).hidden, el).toBe(false);
      expect(w.opts, el).toMatchObject({ appearance: 'always', action: el === 'pw-turnstile' ? 'password' : 'account' });
    }
  });

  it('keeps every protected control disabled until its card\'s check passes', () => {
    for (const [el, sels] of Object.entries(CARDS)) {
      for (const sel of sels) {
        const found = [...document.querySelectorAll(sel)];
        expect(found.length, sel).toBeGreaterThan(0);
        for (const b of found) expect(b.disabled, sel).toBe(true);
      }
      // The reason sits right under the card's first button.
      const first = $(sels[0]);
      expect(first.nextElementSibling.textContent, el).toMatch(/Waiting for the human check/);
      expect(first.nextElementSibling.hidden, el).toBe(false);
      solve(el);
      for (const sel of sels) for (const b of document.querySelectorAll(sel)) expect(b.disabled, sel).toBe(false);
      expect(first.nextElementSibling.hidden, el).toBe(true);
    }
  });

  it('sends a fresh token with each change and starts a new check after it', async () => {
    const used = new Set();
    const expectFresh = (name, token) => {
      expect(tokenOf(name), name).toBe(token);
      expect(used.has(token), name).toBe(false);
      used.add(token);
    };

    // Username.
    let t = solve('name-turnstile');
    $('#name-new').value = 'alice2';
    $('#name-current').value = 'pw';
    $('#name-form').requestSubmit();
    await tick();
    expectFresh('changeUsername', t);
    expect($('#name-btn').disabled).toBe(true); // the token is spent
    expect(widgets.get('name-turnstile').resets).toBe(1);

    // Password.
    t = solve('pw-turnstile');
    $('#pw-current').value = 'old';
    $('#pw-new').value = 'new-password-1';
    $('#pw-new2').value = 'new-password-1';
    $('#pw-form').requestSubmit();
    await tick();
    expectFresh('changePassword', t);

    // Passkeys card: add, the sign-in choice, new codes and remove, one token each.
    const pk = 'passkey-turnstile';
    t = solve(pk);
    $('#passkey-form').requestSubmit();
    await tick();
    expectFresh('addPasskey', t);
    expect($('#recovery-regen').disabled).toBe(true); // one widget: every button waits again

    t = solve(pk);
    $('#mfa-on').checked = true;
    $('#mfa-on').dispatchEvent(new Event('change'));
    await tick();
    expectFresh('setSecondFactor', t);

    t = solve(pk);
    $('#recovery-regen').click();
    $('#recovery-regen').click(); // armed, then confirmed
    await tick();
    expectFresh('regenerateRecoveryCodes', t);

    t = solve(pk);
    // The table was drawn again: the new Remove button is gated too.
    const rm = $('#passkeys-body button');
    rm.click();
    rm.click();
    await tick();
    expectFresh('removePasskey', t);
    expect($('#passkeys-body button').disabled).toBe(true);

    // API keys card: create, change and revoke.
    const kc = 'key-turnstile';
    t = solve(kc);
    $('#key-name').value = 'laptop';
    $('#key-form').requestSubmit();
    await tick();
    expectFresh('createKey', t);

    t = solve(kc);
    [...document.querySelectorAll('#keys-body button')].find((b) => b.textContent === 'Edit').click();
    const save = [...document.querySelectorAll('#keys-body button')].find((b) => b.textContent === 'Save');
    expect(save.disabled).toBe(false);
    save.click();
    await tick();
    expectFresh('updateKey', t);

    // The table was drawn again after the change; the check has no token yet.
    const rv = $('#keys-body button.danger');
    expect(rv.disabled).toBe(true);
    [...document.querySelectorAll('#keys-body button')].find((b) => b.textContent === 'Edit').click();
    expect([...document.querySelectorAll('#keys-body button')].find((b) => b.textContent === 'Save').disabled).toBe(true);
    t = solve(kc);
    rv.click();
    rv.click();
    await tick();
    expectFresh('revokeKey', t);

    expect(used.size).toBe(9);
  });
});

describe('the account page with the human check off', () => {
  beforeAll(async () => {
    config = { turnstile: null };
    widgets.clear();
    calls.length = 0;
    await mountPage();
  });

  it('shows no widget, gates nothing and sends no token', async () => {
    expect(widgets.size).toBe(0);
    for (const el of Object.keys(CARDS)) expect($(`#${el}`).hidden, el).toBe(true);
    for (const sels of Object.values(CARDS)) for (const sel of sels) for (const b of document.querySelectorAll(sel)) expect(b.disabled, sel).toBe(false);
    expect(document.querySelector('.human-wait:not([hidden])')).toBeNull();
    $('#name-new').value = 'alice3';
    $('#name-current').value = 'pw';
    $('#name-form').requestSubmit();
    await tick();
    expect(tokenOf('changeUsername')).toBeNull();
    $('#recovery-regen').click();
    $('#recovery-regen').click();
    await tick();
    expect(tokenOf('regenerateRecoveryCodes')).toBeNull();
    expect($('#recovery-regen').disabled).toBe(false);
  });
});
