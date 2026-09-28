// kit-fresh.mjs — the Drive kits' freshness end to end (docs/DRIVE.md §3,
// §3.1, §3.2) against the REAL server, pages and Cloudflare Turnstile widget
// (Cloudflare's testing keys, which always pass):
//  - the set-up page proposes a root MEK and a first sub-MEK, masked until
//    Show; "Generate again" replaces them, "Use these" chooses them, and the
//    keyring is then exactly that pair (key version 1);
//  - alice's Account → Drive personal kit: its CAPTCHA (Download and Verify
//    wait for it; each request carries a token), "Version N, <date>",
//    "Last downloaded: never", then a download recorded with its version;
//  - the owner rotates a sub-MEK in Security → Keys (the key kit card shows
//    the new version); alice's Account page and Drive page then show the
//    calm "download a new kit" notice, with no key detail; the owner acting as
//    alice sees none and cannot clear it;
//  - alice downloads again and the notices go; her first kit verifies with
//    an older key version (a warning), the new one with the current one;
//  - axe (WCAG 2.2 A/AA) on every new state; no page errors or CSP / Trusted
//    Types violations. Synthetic data only.
// A manual test, not run in CI: see test-e2e/README.md. A fresh server with
// Turnstile's testing keys, on http://localhost:
//   npx wrangler dev --port 9220 --persist-to <fresh dir> \
//     --var TURNSTILE_SITEKEY:1x00000000000000000000AA --var TURNSTILE_SECRET:1x0000000000000000000000000000000AA
//   WT=$PWD BASE=http://localhost:9220 [CHROMIUM=<path>] [OUT=<dir>] [PROXY_SPKI=<the egress proxy CA's SPKI>] node test-e2e/kit-fresh.mjs
import { chromium } from 'playwright-core';
import { readFileSync, mkdirSync, mkdtempSync } from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';

const require = createRequire(import.meta.url);
const AXE = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const BASE = process.env.BASE;
const WT = process.env.WT;
if (!BASE || !WT) { console.error('usage: WT=<repo checkout> BASE=http://localhost:9220 node test-e2e/kit-fresh.mjs'); process.exit(2); }
const TOKEN = /^AUTHN=(.*)$/m.exec(readFileSync(path.join(WT, '.dev.vars'), 'utf8'))[1].trim();
const OUT = process.env.OUT || mkdtempSync(path.join(os.tmpdir(), 'secbin-kitfresh-'));
mkdirSync(OUT, { recursive: true });
const PW = 'owner-password-123';
const ALICE_PW = 'alice-password-123';
const KIT_PASS = 'a kit passphrase for the test';
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22a', 'wcag22aa'];
const STALE = 'Your Drive’s keys were updated. Download a new personal kit and keep it safe.';
const results = [];
const check = (n, ok, x = '') => { results.push(!!ok); console.log(`${ok ? 'PASS' : 'FAIL'} ${n}${x && !ok ? ` — ${x}` : ''}`); };
const b = await chromium.launch({
  ...(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {}),
  ...(process.env.HTTPS_PROXY ? { proxy: { server: process.env.HTTPS_PROXY, bypass: '127.0.0.1,localhost' } } : {}),
  ...(process.env.PROXY_SPKI ? { args: [`--ignore-certificate-errors-spki-list=${process.env.PROXY_SPKI}`] } : {}),
});
const errors = [];
const watch = (p) => {
  p.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  p.on('console', (m) => {
    const t = m.text();
    if (/^Potential permissions policy violation/.test(t)) return; // Turnstile's frame asks for features the policy denies
    if (m.type() === 'error' && /Content Security Policy|Trusted Type/i.test(t)) errors.push(`console: ${t}`);
  });
};
async function audit(p, label) {
  await p.evaluate(AXE);
  const v = await p.evaluate(async (tags) => {
    // eslint-disable-next-line no-undef
    const r = await axe.run(document, { runOnly: { type: 'tag', values: tags }, resultTypes: ['violations'] });
    return r.violations.map((x) => `${x.id} (${x.impact}): ${x.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')}`);
  }, TAGS);
  check(`axe: ${label}`, v.length === 0, v.join('; '));
}
const api = (p, url, init = {}) => p.evaluate(async ([u, i]) => {
  const csrf = (document.cookie.match(/(?:^|;\s*)__Host-secbin_csrf=([^;]+)/) || [])[1] || '';
  const r = await fetch(u, { cache: 'no-store', ...i, headers: { 'content-type': 'application/json', 'x-secbin-intent': '1', ...(i.method && i.method !== 'GET' ? { 'x-secbin-csrf': csrf } : {}), ...(i.headers || {}) } });
  return { status: r.status, body: await r.json().catch(() => null) };
}, [url, init]);
async function login(p, user, pw) {
  await p.goto(`${BASE}/dashboard/login/`);
  await p.fill('#login-user', user); await p.fill('#login-pass', pw);
  await p.waitForFunction(() => !document.querySelector('#login-btn').disabled, null, { timeout: 60000 });
  await p.click('#login-btn');
  await p.waitForURL(/\/dashboard\/(\?.*)?$/, { timeout: 60000 });
  await p.waitForSelector('#dash-nav:not([hidden])');
}
const saveDownload = async (p, click, name) => {
  const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 180000 }), click()]);
  const f = path.join(OUT, name);
  await dl.saveAs(f);
  return f;
};
const accountKit = async (p) => {
  await p.goto(`${BASE}/dashboard/account/?load=${Date.now()}#drive-kit`);
  await p.waitForFunction(() => /^Version \d/.test(document.querySelector('#ukit-version')?.textContent || ''), null, { timeout: 60000 });
};
/** The personal kit downloaded on Account (the CAPTCHA passes first) → { file, turnstile header sent }. */
async function downloadKit(p, name) {
  await p.fill('#ukit-pass', KIT_PASS); await p.fill('#ukit-pass2', KIT_PASS); await p.fill('#ukit-confirm', ALICE_PW);
  await p.waitForFunction(() => !document.querySelector('#ukit-download').disabled, null, { timeout: 60000 });
  const sent = p.waitForRequest((r) => r.url().endsWith('/api/private/drive/kit') && r.method() === 'POST', { timeout: 60000 });
  const file = await saveDownload(p, () => p.click('#ukit-download'), name);
  return { file, token: (await sent).headers()['x-secbin-turnstile'] || null };
}
/** Verify a saved kit on Account → { verdict, version (the version check's status and text) }. */
async function verifyKit(p, file) {
  await p.setInputFiles('#ukit-verify-file', file);
  await p.fill('#ukit-verify-pass', KIT_PASS);
  await p.waitForFunction(() => !document.querySelector('#ukit-verify').disabled, null, { timeout: 60000 });
  const sent = p.waitForRequest((r) => r.url().endsWith('/api/private/drive/kit/verify'), { timeout: 120000 });
  await p.click('#ukit-verify');
  const req = await sent;
  await p.waitForSelector('#ukit-verify-verdict', { timeout: 120000 });
  const v = await p.$eval('#ukit-verify-results [data-check="version"]', (li) => ({ status: li.dataset.status, text: li.textContent }));
  return { verdict: await p.getAttribute('#ukit-verify-verdict', 'data-verdict'), version: v, token: req.headers()['x-secbin-turnstile'] || null };
}

try {
  // ── set-up: the proposed keys, "Generate again", then "Use these" ──
  const oc = await b.newContext({ acceptDownloads: true, reducedMotion: 'reduce', viewport: { width: 1280, height: 900 } });
  const p = await oc.newPage();
  watch(p);
  await p.goto(`${BASE}/dashboard/setup/`);
  await p.waitForSelector('#setup-form:not([hidden])');
  check('set-up: generating on the server is the default; nothing proposed yet', await p.isChecked('#setup-keys-generate') && await p.isVisible('#setup-keys-gen') && await p.isHidden('#setup-keys-cand'));
  await p.fill('#setup-token', TOKEN); await p.fill('#setup-user', 'owner'); await p.fill('#setup-pass', PW); await p.fill('#setup-pass2', PW);
  await p.click('#setup-btn');
  await p.waitForFunction(() => /Generate the Drive keys/.test(document.querySelector('#setup-msg').textContent), null, { timeout: 30000 });
  check('set-up: refused in the page until the keys are chosen', /Generate the Drive keys and choose “Use these”/.test(await p.textContent('#setup-msg')));
  await p.click('#setup-keys-gen');
  await p.waitForSelector('#setup-cand-root-show', { timeout: 30000 });
  const fp1 = await p.getAttribute('#setup-cand-root', 'data-fp');
  const masked = await p.textContent('#setup-cand-root-value');
  check('set-up: the proposal is masked (no key in the page\'s text)', /^•+$/.test(masked) && !/[A-Za-z0-9_-]{43}/.test(await p.textContent('#setup-keys')));
  await audit(p, 'set-up (the keys proposed, masked)');
  await p.click('#setup-cand-root-show');
  const key1 = await p.textContent('#setup-cand-root-value');
  check('set-up: Show reveals the proposed root MEK (32 bytes)', /^[A-Za-z0-9_-]{43}$/.test(key1));
  await p.click('#setup-keys-again');
  await p.waitForFunction((f) => document.querySelector('#setup-cand-root')?.dataset.fp !== f, fp1, { timeout: 30000 });
  const fpRoot = await p.getAttribute('#setup-cand-root', 'data-fp');
  const fpSub = await p.getAttribute('#setup-cand-sub', 'data-fp');
  await p.click('#setup-cand-root-show');
  const key2 = await p.textContent('#setup-cand-root-value');
  check('set-up: "Generate again" proposes another pair', key2 !== key1 && fpRoot !== fp1);
  await p.click('#setup-keys-use');
  check('set-up: "Use these" says which keys will be used', /These keys will be used/.test(await p.textContent('#setup-keys-chosen')));
  await audit(p, 'set-up (the keys chosen)');
  await p.click('#setup-btn');
  await p.waitForFunction(() => /created/.test(document.querySelector('#setup-msg').textContent), null, { timeout: 60000 });
  check('set-up: done with the keys created', /Drive keys were created.*key kit/.test(await p.textContent('#setup-msg')));
  await login(p, 'owner', PW);
  let st = (await api(p, '/api/private/admin/keys')).body;
  check('keyring: exactly the pair chosen (the second one), version 1', st.root.fp === fpRoot && st.subs.length === 1 && st.subs[0].fp === fpSub && st.version.n === 1, JSON.stringify({ root: st.root.fp, fpRoot, subs: st.subs.map((s) => s.fp), fpSub, v: st.version }));

  // ── alice, with a Drive and a file ──
  check('Default role: Drive on', (await api(p, '/api/private/admin/limits', { method: 'PATCH', body: JSON.stringify({ scope: 'global', channel: 'all', patch: { driveEnabled: true } }) })).status === 200);
  await p.goto(`${BASE}/dashboard/admin/`);
  await p.click('.tab[data-tab="users"]');
  const up = p.locator('.admin-panel[data-panel="users"]');
  await up.locator('input[aria-label="New username"]').first().fill('alice');
  await up.locator('input[aria-label="New user password"]').first().fill(ALICE_PW);
  await up.locator('input[aria-label="Repeat password"]').first().fill(ALICE_PW);
  await up.locator('button:has-text("Create user")').first().click();
  await p.waitForFunction(() => document.getElementById('toast').textContent === 'User created.', null, { timeout: 30000 });
  const aliceId = (await api(p, '/api/private/admin/users')).body.users.find((u) => u.username === 'alice').id;
  const ac = await b.newContext({ acceptDownloads: true, reducedMotion: 'reduce', viewport: { width: 1280, height: 900 } });
  const a = await ac.newPage();
  watch(a);
  await login(a, 'alice', ALICE_PW);
  await a.goto(`${BASE}/dashboard/drive/`);
  await a.waitForSelector('#drive-app', { timeout: 60000 });
  await a.setInputFiles('#drive-file-input', [{ name: 'alice.txt', mimeType: 'text/plain', buffer: Buffer.from('alice\n') }]);
  await a.waitForFunction(() => [...document.querySelectorAll('#drive-rows tr')].some((tr) => tr.children[1].textContent.trim() === 'alice.txt'), null, { timeout: 60000 });
  check('Drive page: no kit notice before any key change', (await a.$('#drive-kit-notice')) === null);

  // ── alice's personal kit: the CAPTCHA, the version, the first download ──
  await accountKit(a);
  check('Account kit card: "Version 1, <date>"', /^Version 1, \S/.test(await a.textContent('#ukit-version')), await a.textContent('#ukit-version'));
  check('Account kit card: last downloaded: never; no notice', /^Never/.test(await a.textContent('#ukit-last')) && await a.isHidden('#ukit-stale') && (await a.$('#acct-kit-notice')) === null);
  await a.waitForSelector('#ukit-turnstile:not([hidden]) iframe', { state: 'attached', timeout: 60000 }).catch(() => {});
  check('Account kit card: its own CAPTCHA widget', await a.isVisible('#ukit-turnstile'));
  await audit(a, 'Account → personal kit (never downloaded)');
  const first = await downloadKit(a, 'kit-v1.json');
  check('download: carries a CAPTCHA token', !!first.token);
  await a.waitForFunction(() => /\(version 1\)$/.test(document.querySelector('#ukit-last').textContent), null, { timeout: 30000 });
  check('download: "Last downloaded: <date> (version 1)", no notice', await a.isHidden('#ukit-stale'));
  const v1 = await verifyKit(a, first.file);
  // (Cloudflare's testing keys hand out the same dummy token each time: each request still needs one.)
  check('verify: complete, version 1 is the current one, with a CAPTCHA token', v1.verdict === 'complete' && v1.version.status === 'pass' && !!v1.token, JSON.stringify(v1));

  // ── the owner rotates a sub-MEK ──
  await p.goto(`${BASE}/dashboard/admin/?load=${Date.now()}#keys`);
  await p.waitForSelector('#keys-subs-table tbody tr', { timeout: 60000 });
  check('key kit card: "Current keys: Version 1, <date>"', /^Current keys: Version 1, /.test(await p.textContent('#keys-kit-version')));
  await p.click('button:has-text("Rotate now…")');
  await p.waitForSelector('.key-chooser');
  await p.fill('#keys-confirm', PW);
  await p.click('.key-chooser button:has-text("Generate securely")');
  await p.waitForSelector('.key-chooser .key-value', { timeout: 60000 });
  await p.fill('#keys-confirm', PW);
  await p.click('.key-chooser button:has-text("Use this key")');
  await p.waitForFunction(() => /current from now on/.test(document.getElementById('toast').textContent), null, { timeout: 120000 });
  await p.goto(`${BASE}/dashboard/admin/?load=${Date.now()}#keys`);
  await p.waitForSelector('#keys-kit-version', { timeout: 60000 });
  check('key kit card: "Current keys: Version 2, <date>" after the rotation', /^Current keys: Version 2, /.test(await p.textContent('#keys-kit-version')));
  st = (await api(p, '/api/private/admin/keys')).body;

  // ── alice sees the notice, on Account and on the Drive page ──
  await accountKit(a);
  check('Account: the notice near the top and in the card', (await a.textContent('#acct-kit-notice')).startsWith(STALE) && await a.isVisible('#ukit-stale') && (await a.textContent('#ukit-stale')) === STALE);
  check('Account kit card: "Version 2", last download still version 1', /^Version 2, /.test(await a.textContent('#ukit-version')) && /\(version 1\)$/.test(await a.textContent('#ukit-last')));
  const noDetail = (t) => !st.subs.some((s) => t.includes(s.fp) || t.includes(`${s.fp.slice(0, 4)}-${s.fp.slice(4, 8)}`)) && !/MEK|KEK/.test(t);
  check('Account: the notices hold no key detail', noDetail(await a.textContent('#acct-kit-notice')) && noDetail(await a.textContent('#ukit-stale')));
  await audit(a, 'Account → personal kit (out of date)');
  await a.goto(`${BASE}/dashboard/drive/`);
  await a.waitForSelector('#drive-kit-notice', { timeout: 60000 });
  check('Drive page: the notice, with a link to Account', (await a.textContent('#drive-kit-notice')).startsWith(STALE) && (await a.getAttribute('#drive-kit-notice a', 'href')) === '/dashboard/account/#drive-kit' && noDetail(await a.textContent('#drive-kit-notice')));
  await audit(a, 'Drive page (kit notice)');

  // ── the owner acting as alice: no notice, and it cannot be cleared ──
  const ic = await b.newContext({ reducedMotion: 'reduce', viewport: { width: 1280, height: 900 } });
  const ip = await ic.newPage();
  watch(ip);
  await login(ip, 'owner', PW);
  const imp = await api(ip, `/api/private/admin/users/${aliceId}/impersonate`, { method: 'POST', body: '{}' });
  check('impersonate alice', imp.status === 200, JSON.stringify(imp));
  await ip.goto(`${BASE}/dashboard/drive/`);
  await ip.waitForSelector('#drive-imp-note', { timeout: 60000 });
  check('acting as alice: no kit notice on the Drive page', (await ip.$('#drive-kit-notice')) === null);
  const tried = await api(ip, '/api/private/drive/kit', { method: 'POST', body: '{}' });
  check('acting as alice: the kit download is refused (403 impersonating)', tried.status === 403 && tried.body.error === 'impersonating');
  await ic.close();
  check('alice\'s notice is still hers', (await api(a, '/api/private/drive/kit')).body.stale === true);

  // ── alice downloads again: the notices go ──
  await accountKit(a);
  const second = await downloadKit(a, 'kit-v2.json');
  await a.waitForFunction(() => /\(version 2\)$/.test(document.querySelector('#ukit-last').textContent), null, { timeout: 30000 });
  check('download again: the notices go at once (card and top)', await a.isHidden('#ukit-stale') && (await a.$('#acct-kit-notice')) === null && !!second.token);
  await accountKit(a);
  check('Account, loaded again: no notice', await a.isHidden('#ukit-stale') && (await a.$('#acct-kit-notice')) === null);
  await a.goto(`${BASE}/dashboard/drive/`);
  await a.waitForSelector('#drive-app', { timeout: 60000 });
  await a.waitForFunction(() => document.querySelectorAll('#drive-rows tr').length > 0, null, { timeout: 60000 });
  check('Drive page: no notice after the new download', (await a.$('#drive-kit-notice')) === null);
  await accountKit(a);
  const old = await verifyKit(a, first.file);
  check('verify the first kit: an older key version (a warning)', old.version.status === 'warn' && /Version 1; the keys are now version 2/.test(old.version.text), JSON.stringify(old));
  await accountKit(a);
  const cur = await verifyKit(a, second.file);
  check('verify the new kit: complete, the current version', cur.verdict === 'complete' && cur.version.status === 'pass', JSON.stringify(cur));
  await audit(a, 'Account → personal kit (verify results)');
  await ac.close();
  await oc.close();
} catch (e) {
  console.log('ERROR', e);
  results.push(false);
} finally {
  check('no page errors or CSP / Trusted Types violations', errors.length === 0, errors.slice(0, 5).join(' | '));
  console.log(`output: ${OUT}`);
  await b.close();
  const failed = results.filter((x) => !x).length;
  console.log(`\n${results.length - failed}/${results.length} passed`);
  process.exit(failed ? 1 : 0);
}
