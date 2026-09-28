// setup-keys.test.js — the set-up page's Drive keys step (docs/DRIVE.md §3,
// public/dashboard/setup/index.html + public/js/setup.js): generated on the
// server by default; entered by hand (hex or base64, 32 bytes, checked here
// first, with the out-of-band help); hidden when an owner is recovered (the
// keyring is kept); after the set-up, the page says to download the key kit.
import { describe, it, expect, afterEach, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// The Argon2id stretch is not what is tested here.
vi.mock('../public/js/pwauth.js', async (importOriginal) => ({
  ...(await importOriginal()),
  newCredential: async () => ({ salt: 'AAAAAAAAAAAAAAAAAAAAAA', t: 3, proof: 'P'.repeat(43) }),
}));

const $ = (s) => document.querySelector(s);
const tick = () => new Promise((r) => setTimeout(r, 0));
const until = async (fn, ms = 5000) => {
  const t0 = Date.now();
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 10));
  }
};

let requests;
async function mountPage({ ownerExists = false, keys = 'created' } = {}) {
  requests = [];
  globalThis.fetch = vi.fn(async (url, init = {}) => {
    const body = typeof init.body === 'string' ? JSON.parse(init.body) : undefined;
    requests.push({ url, method: init.method || 'GET', body });
    const json = (d) => ({ ok: true, status: 200, type: 'basic', json: async () => d });
    if (url === '/api/auth/setup' && (init.method || 'GET') === 'GET') return json({ enabled: true, configured: true, ownerExists });
    if (url === '/api/auth/setup') return json({ ok: true, recovered: ownerExists, keys });
    return { ok: false, status: 404, type: 'basic', json: async () => ({ error: 'not_found' }) };
  });
  const html = readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '../public/dashboard/setup/index.html'), 'utf8');
  const body = html.slice(html.indexOf('<body'), html.indexOf('</body>') + '</body>'.length);
  const doc = new DOMParser().parseFromString(`<!doctype html><html>${body}</html>`, 'text/html');
  for (const s of doc.querySelectorAll('script')) s.remove();
  document.body.replaceChildren(...[...doc.body.childNodes].map((n) => document.importNode(n, true)));
  vi.resetModules();
  await import('../public/js/setup.js');
  await until(() => !$('#setup-form').hidden);
  await tick();
}
const fill = () => {
  $('#setup-token').value = 'a-setup-token';
  $('#setup-user').value = 'owner';
  $('#setup-pass').value = 'a long owner password';
  $('#setup-pass2').value = 'a long owner password';
};
const submit = () => $('#setup-form').dispatchEvent(new Event('submit', { cancelable: true }));
afterEach(() => { vi.useRealTimers(); });

describe('the set-up page: Drive keys', () => {
  it('generated on the server by default, with plain-language help; the page then says to download the key kit', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout'], shouldAdvanceTime: true });
    await mountPage();
    expect($('#setup-keys-generate').checked).toBe(true);
    expect($('#setup-keys-fields').hidden).toBe(true);
    expect($('#setup-keys-help').textContent.replace(/\s+/g, ' ')).toMatch(/losing them loses every Drive file.*key kit/s);
    fill();
    submit();
    await until(() => requests.some((r) => r.method === 'POST'));
    expect(requests.find((r) => r.method === 'POST').body.keys).toBeUndefined();
    await until(() => !$('#setup-msg').hidden);
    expect($('#setup-msg').textContent).toMatch(/Drive keys were created.*download the key kit \(Admin → Security → Keys\)/);
  });

  it('entered by hand: 32 bytes as hex or base64, checked in the page first (the field says what is wrong)', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout'], shouldAdvanceTime: true });
    await mountPage();
    $('#setup-keys-manual').checked = true;
    $('#setup-keys-manual').dispatchEvent(new Event('change'));
    expect($('#setup-keys-fields').hidden).toBe(false);
    expect($('#setup-keys-manual-help').textContent.replace(/\s+/g, ' ')).toMatch(/openssl rand -base64 32.*RandomNumberGenerator.*not Get-Random/s);
    expect($('#setup-root').type).toBe('password');
    fill();
    $('#setup-root').value = 'not a key';
    $('#setup-sub').value = 'x';
    submit();
    await until(() => !$('#setup-msg').hidden);
    expect($('#setup-msg').textContent).toMatch(/Root MEK: .*32 bytes/);
    expect($('#setup-root').getAttribute('aria-invalid')).toBe('true');
    expect(requests.some((r) => r.method === 'POST')).toBe(false);
    const hex = Array.from(crypto.getRandomValues(new Uint8Array(32)), (b) => b.toString(16).padStart(2, '0')).join('');
    const b64 = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
    $('#setup-root').value = hex;
    $('#setup-sub').value = b64;
    submit();
    await until(() => requests.some((r) => r.method === 'POST'));
    expect(requests.find((r) => r.method === 'POST').body.keys).toEqual({ mode: 'manual', root: hex, sub: b64 });
  });

  it('an owner recovery keeps the keys: the step is hidden and nothing is sent for them', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout'], shouldAdvanceTime: true });
    await mountPage({ ownerExists: true, keys: 'kept' });
    expect($('#setup-keys').hidden).toBe(true);
    expect($('#setup-keys-kept').hidden).toBe(false);
    fill();
    submit();
    await until(() => requests.some((r) => r.method === 'POST'));
    expect(requests.find((r) => r.method === 'POST').body.keys).toBeUndefined();
    await until(() => !$('#setup-msg').hidden);
    expect($('#setup-msg').textContent).toMatch(/^Owner account recovered\. Now delete/);
  });
});
