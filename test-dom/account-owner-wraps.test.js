// account-owner-wraps.test.js (DOM) — the owner's Account → Passkeys while
// Drives still wait for their upgrade: removing a passkey or creating new
// recovery codes drops that credential's old Drive wrap at once (docs/
// DRIVE.md §3.3), so the card says, before either, that the waiting Drives
// can still be upgraded with the owner's other sign-in methods and the escrow.
// Without Drives waiting (and for any other account) the note is not shown.
// The page is the real public/dashboard/account/index.html and account.js;
// the network is a stand-in.
import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

let waiting = 0;
const PASSKEY = { id: 'pk1', name: 'Laptop', created: 1, lastUsed: null, synced: false };
const NOTE = 'Drives still waiting for their upgrade can still be upgraded with your other sign-in methods and the escrow.';

vi.mock('../public/js/api.js', () => {
  class ApiError extends Error {}
  const none = async () => ({});
  return {
    ApiError,
    fetchConfig: async () => ({}),
    changePassword: none, createKey: none, updateKey: none, revokeKey: none, changeUsername: none,
    listKeys: async () => ({ keys: [] }),
    myActivity: async () => ({ rows: [] }),
    myPasskeys: async () => ({ passkeys: [PASSKEY], mode: 'any', mfa: false, required: false, recoveryLeft: 20, max: 10, drivesWaiting: waiting }),
    passkeyRegisterOptions: none, addPasskey: none, removePasskey: none, setSecondFactor: none,
    regenerateRecoveryCodes: async () => ({ codes: [] }),
  };
});
vi.mock('../public/js/kdf-progress.js', () => ({}));
vi.mock('../public/js/passkeys.js', () => ({ passkeysSupported: () => true, createPasskey: async () => ({ id: 'new' }) }));
vi.mock('../public/js/pwauth.js', () => ({ newCredential: async () => ({}), checkNewPassword: () => null, checkOwnerPassword: () => null, describePolicy: () => '' }));
vi.mock('../public/dashboard/js/confirm.js', () => ({ confirmLabel: (t) => t, confirmStep: async () => ({ current: 'proof' }) }));
vi.mock('../public/dashboard/js/nav.js', () => ({
  ready: Promise.resolve({
    user: { username: 'owner', role: 'owner' },
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

const $ = (s) => document.querySelector(s);
const tick = async (n = 10) => { for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 0)); };

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

describe('Account → Passkeys, the owner with Drives waiting for their upgrade', () => {
  it('says, before a passkey is removed or new codes are made, that the waiting Drives stay upgradable', async () => {
    waiting = 2;
    await mountPage();
    const note = $('#passkeys-drive-note');
    expect(note.hidden).toBe(false);
    expect(note.textContent).toContain(NOTE);
    expect(note.textContent).toMatch(/removes its copy of your old Drive key at once/);
    // It sits before the controls it is about: the Remove buttons' table comes first, then the note, then "New recovery codes".
    const order = (a, b) => a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING;
    expect(order(note, $('#recovery-regen'))).toBeTruthy();
    expect(order($('#passkeys-body'), note)).toBeTruthy();
  });

  it('shows no note when no Drive waits', async () => {
    waiting = 0;
    await mountPage();
    expect($('#passkeys-drive-note').hidden).toBe(true);
  });
});
