// setup-keys.test.js — the set-up page's Drive keys step (docs/DRIVE.md §3,
// public/dashboard/setup/index.html + public/js/setup.js): the server
// proposes a root MEK and a first sub-MEK (for the setup token's holder),
// shown masked until Show, with "Use these", "Generate again" and "Enter
// manually" (as Admin → Security → Keys does); the set-up sends only the
// chosen pair's ids, and not before "Use these"; entered by hand (hex or
// base64, 32 bytes, checked here first, with the out-of-band help); hidden
// when an owner is recovered (the keyring is kept); after the set-up, the
// page says to download the key kit.
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
let proposals; // every pair the fake server proposed
let setupAnswer; // null, or the error the set-up answers with
const b64 = (n) => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(n)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
async function mountPage({ ownerExists = false, keys = 'created' } = {}) {
  requests = [];
  proposals = [];
  setupAnswer = null;
  globalThis.fetch = vi.fn(async (url, init = {}) => {
    const body = typeof init.body === 'string' ? JSON.parse(init.body) : undefined;
    requests.push({ url, method: init.method || 'GET', body, headers: init.headers || {} });
    const json = (d, status = 200) => ({ ok: status < 400, status, type: 'basic', json: async () => d });
    if (url === '/api/auth/setup' && (init.method || 'GET') === 'GET') return json({ enabled: true, configured: true, ownerExists });
    if (url === '/api/auth/setup/candidate') {
      const one = () => ({ id: b64(12), key: b64(32), fp: b64(8).slice(0, 11) });
      const pair = { root: one(), sub: one(), expires: 1 };
      proposals.push(pair);
      return json(pair);
    }
    if (url === '/api/auth/setup' && setupAnswer) return json(setupAnswer, 410);
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
  it('generated on the server: proposed, masked until Show, "Generate again", then "Use these"; the page then says to download the key kit', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout'], shouldAdvanceTime: true });
    await mountPage();
    const setups = () => requests.filter((r) => r.url === '/api/auth/setup' && r.method === 'POST');
    expect($('#setup-keys-generate').checked).toBe(true);
    expect($('#setup-keys-fields').hidden).toBe(true);
    expect($('#setup-keys-gen-box').hidden).toBe(false);
    expect($('#setup-keys-cand').hidden).toBe(true);
    expect($('#setup-keys-choice').hidden).toBe(true);
    expect($('#setup-keys-help').textContent.replace(/\s+/g, ' ')).toMatch(/losing them loses every Drive file.*key kit/s);
    expect($('#setup-keys-gen-help').textContent.replace(/\s+/g, ' ')).toMatch(/Nothing is stored until you choose “Use these”/);
    // Without the setup token, nothing is asked of the server.
    $('#setup-keys-gen').click();
    await until(() => !$('#setup-msg').hidden);
    expect($('#setup-msg').textContent).toMatch(/setup token first/);
    expect(proposals).toHaveLength(0);
    // Nothing is chosen yet: the set-up is refused in the page.
    fill();
    submit();
    await until(() => /Generate the Drive keys/.test($('#setup-msg').textContent));
    expect(setups()).toHaveLength(0);
    // Proposed: both keys masked until Show (the value is never in the page's text before).
    $('#setup-keys-gen').click();
    await until(() => !$('#setup-keys-cand').hidden);
    const cand = requests.find((r) => r.url === '/api/auth/setup/candidate');
    expect(cand).toMatchObject({ method: 'POST', body: { token: 'a-setup-token' } });
    expect(cand.headers['x-secbin-intent']).toBe('1');
    const [p1] = proposals;
    expect($('#setup-cand-root-value').textContent).not.toContain(p1.root.key);
    expect($('#setup-cand-sub-value').textContent).not.toContain(p1.sub.key);
    expect(document.body.textContent).not.toContain(p1.root.key);
    expect($('#setup-keys-gen').hidden).toBe(true);
    expect([...$('#setup-keys-choice').querySelectorAll('button')].map((b) => b.textContent)).toEqual(['Use these', 'Generate again', 'Enter manually']);
    $('#setup-cand-root-show').click();
    expect($('#setup-cand-root-value').textContent).toBe(p1.root.key);
    expect($('#setup-cand-root-show').textContent).toBe('Hide');
    $('#setup-cand-root-show').click();
    expect($('#setup-cand-root-value').textContent).not.toContain(p1.root.key);
    // Still not chosen: refused in the page.
    submit();
    await until(() => /Choose “Use these”/.test($('#setup-msg').textContent));
    expect(setups()).toHaveLength(0);
    // Generate again: a new pair replaces the first.
    $('#setup-keys-again').click();
    await until(() => proposals.length === 2 && $('#setup-cand-sub').dataset.fp === proposals[1].sub.fp);
    const p2 = proposals[1];
    $('#setup-cand-sub-show').click();
    expect($('#setup-cand-sub-value').textContent).toBe(p2.sub.key);
    $('#setup-keys-use').click();
    expect($('#setup-keys-use').hidden).toBe(true);
    expect($('#setup-keys-chosen').textContent).toMatch(/These keys will be used/);
    // The set-up sends the chosen pair's ids, never a key.
    submit();
    await until(() => setups().length === 1);
    expect(setups()[0].body.keys).toEqual({ mode: 'generated', root: p2.root.id, sub: p2.sub.id });
    expect(JSON.stringify(setups()[0].body)).not.toContain(p2.root.key);
    await until(() => /Owner account created/.test($('#setup-msg').textContent));
    expect($('#setup-msg').textContent).toMatch(/Drive keys were created.*download the key kit \(Admin → Security → Keys\)/);
  });

  it('a proposal the server no longer has (10 minutes): the set-up says so and the keys are generated again', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout'], shouldAdvanceTime: true });
    await mountPage();
    fill();
    $('#setup-keys-gen').click();
    await until(() => !$('#setup-keys-cand').hidden);
    $('#setup-keys-use').click();
    setupAnswer = { error: 'candidate_expired', message: 'The generated Drive keys are no longer available (they are kept for 10 minutes): generate them again.' };
    submit();
    await until(() => /no longer available/.test($('#setup-msg').textContent));
    expect($('#setup-keys-cand').hidden).toBe(true);
    expect($('#setup-keys-gen').hidden).toBe(false);
  });

  it('"Enter manually" from a proposal switches to the two fields', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout'], shouldAdvanceTime: true });
    await mountPage();
    fill();
    $('#setup-keys-gen').click();
    await until(() => !$('#setup-keys-cand').hidden);
    $('#setup-keys-to-manual').click();
    expect($('#setup-keys-manual').checked).toBe(true);
    expect($('#setup-keys-fields').hidden).toBe(false);
    expect($('#setup-keys-gen-box').hidden).toBe(true);
    expect(document.activeElement).toBe($('#setup-root'));
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
