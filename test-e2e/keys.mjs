// keys.mjs — the Drive key model v2 end to end (docs/DRIVE.md §3, §3.1, §3.2)
// against the REAL server and pages: the set-up page with keys entered by hand
// (hex and base64), Admin → Security → Keys (Show with the step-up, a
// generated sub-MEK used only on "Use this key", rotation, a scheduled
// sub-MEK entered by hand, a re-seal with progress, deleting a sub-MEK, a
// root change), the key kit (download with the step-up, verify with a date,
// a wrong passphrase, a restore preview that replaces nothing), the personal
// kit on Account (download, verify, restore), Import / export → Drive keys
// (parts, the user picker, the masked view, the sealed file; an import
// previewed, then applied, that replaces nothing), a user's keys (masked,
// Show), every Drive file still opening after each change, the admin audit
// holding fingerprints and never a key, axe (WCAG 2.2 A/AA) on every state,
// and no page errors or CSP / Trusted Types violations. Synthetic data only.
// A manual test, not run in CI: see test-e2e/README.md. Needs a fresh
// `wrangler dev` (no owner yet), playwright-core and axe-core, and a Chromium.
//   WT=<repo checkout> BASE=http://localhost:8787 [CHROMIUM=<path>] [OUT=<dir>] node test-e2e/keys.mjs
import { chromium } from 'playwright-core';
import { readFileSync, mkdirSync, mkdtempSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';

const require = createRequire(import.meta.url);
const AXE = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const BASE = process.env.BASE;
const WT = process.env.WT;
if (!BASE || !WT) { console.error('usage: WT=<repo checkout> BASE=http://localhost:8787 node test-e2e/keys.mjs'); process.exit(2); }
const TOKEN = /^AUTHN=(.*)$/m.exec(readFileSync(path.join(WT, '.dev.vars'), 'utf8'))[1].trim();
const OUT = process.env.OUT || mkdtempSync(path.join(os.tmpdir(), 'secbin-keys-'));
mkdirSync(OUT, { recursive: true });
const PW = 'owner-password-123';
const ALICE_PW = 'alice-password-123';
const KIT_PASS = 'a kit passphrase for the test';
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22a', 'wcag22aa'];
// The keys entered by hand at set-up (synthetic, random for this run).
const ROOT = randomBytes(32);
const SUB = randomBytes(32);
const b64url = (b) => Buffer.from(b).toString('base64url');
const results = [];
const check = (n, ok, x = '') => { results.push(!!ok); console.log(`${ok ? 'PASS' : 'FAIL'} ${n}${x ? ' — ' + x : ''}`); };
const b = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
const errors = [];
const watch = (p) => {
  p.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  p.on('console', (m) => { if (m.type() === 'error' && /Content Security Policy|Trusted Type/i.test(m.text())) errors.push(`console: ${m.text()}`); });
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
  await p.fill('#login-user', user); await p.fill('#login-pass', pw); await p.click('#login-btn');
  await p.waitForURL(/\/dashboard\/(\?.*)?$/, { timeout: 60000 });
  await p.waitForSelector('#dash-nav:not([hidden])');
}
const exact = (name) => new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`);
const rowOf = (p, name) => p.locator('#drive-rows tr', { has: p.locator('td:nth-child(2) bdi.fname', { hasText: exact(name) }) });
const hasRow = (n) => [...document.querySelectorAll('#drive-rows tr')].some((tr) => tr.children[1].textContent.trim() === n);
async function driveUpload(p, name, text) {
  await p.goto(`${BASE}/dashboard/drive/`);
  await p.waitForSelector('#drive-app', { timeout: 60000 });
  await p.setInputFiles('#drive-file-input', [{ name, mimeType: 'text/plain', buffer: Buffer.from(text) }]);
  await p.waitForFunction(hasRow, name, { timeout: 60000 });
}
/** The file `name` in the root folder downloads and decrypts to `text` (a fresh page load: the keys from the server). */
async function driveReads(p, name, text) {
  await p.goto(`${BASE}/dashboard/drive/`);
  await p.waitForSelector('#drive-app', { timeout: 60000 });
  await p.waitForFunction(hasRow, name, { timeout: 60000 });
  await rowOf(p, name).locator('input[type="checkbox"]').check();
  const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 60000 }), p.click('#drive-download')]);
  const f = path.join(OUT, `read-${Date.now()}-${name}`);
  await dl.saveAs(f);
  return readFileSync(f, 'utf8') === text;
}
const keysPage = async (p) => {
  await p.goto(`${BASE}/dashboard/admin/?load=${Date.now()}#keys`); // a new load each time (not only a new #fragment)
  await p.waitForSelector('#keys-subs-table tbody tr', { timeout: 60000 });
  await p.waitForFunction(() => [...document.querySelectorAll('#keys-subs-table tbody tr td[data-label="Items"]')].every((td) => td.textContent !== '…'), null, { timeout: 30000 });
};
const subRows = (p) => p.$$eval('#keys-subs-table tbody tr', (trs) => trs.map((tr) => ({ id: tr.dataset.id, status: tr.dataset.status, items: tr.querySelector('td[data-label="Items"]').textContent, fp: tr.querySelector('td[data-label="Fingerprint"]').textContent })));
const status = async (p) => (await api(p, '/api/private/admin/keys')).body;
const confirmPw = (p) => p.fill('#keys-confirm', PW);
const waitToast = (p, re) => p.waitForFunction((s) => new RegExp(s).test(document.getElementById('toast').textContent), re.source, { timeout: 120000 });
const saveDownload = async (p, click, name) => {
  const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 180000 }), click()]);
  const f = path.join(OUT, name);
  await dl.saveAs(f);
  return f;
};
const shown = new Set(); // every key value this run saw (none may reach the admin audit)

try {
  // ── set-up: the Drive keys entered by hand (hex and base64) ──
  const oc = await b.newContext({ acceptDownloads: true, reducedMotion: 'reduce', viewport: { width: 1280, height: 900 } });
  const p = await oc.newPage();
  watch(p);
  await p.goto(`${BASE}/dashboard/setup/`);
  await p.waitForSelector('#setup-form:not([hidden])');
  check('set-up: the keys are generated by default, with plain-language help', await p.isChecked('#setup-keys-generate') && await p.isHidden('#setup-keys-fields') && /key kit/.test(await p.textContent('#setup-keys-help')));
  await p.check('#setup-keys-manual');
  check('set-up: entering by hand shows two password-type fields and the out-of-band help', await p.isVisible('#setup-root') && (await p.getAttribute('#setup-root', 'type')) === 'password' && /openssl rand -base64 32/.test(await p.textContent('#setup-keys-manual-help')));
  await audit(p, 'set-up (keys entered by hand)');
  await p.fill('#setup-token', TOKEN); await p.fill('#setup-user', 'owner'); await p.fill('#setup-pass', PW); await p.fill('#setup-pass2', PW);
  await p.fill('#setup-root', 'not a key'); await p.fill('#setup-sub', 'x');
  await p.click('#setup-btn');
  await p.waitForFunction(() => /32 bytes/.test(document.querySelector('#setup-msg').textContent), null, { timeout: 30000 });
  check('set-up: a malformed key is refused in the page (the field marked)', (await p.getAttribute('#setup-root', 'aria-invalid')) === 'true');
  await p.fill('#setup-root', ROOT.toString('hex'));
  await p.fill('#setup-sub', SUB.toString('base64'));
  await p.click('#setup-btn');
  await p.waitForFunction(() => /created/.test(document.querySelector('#setup-msg').textContent), null, { timeout: 30000 });
  check('set-up: done, and the page says to download the key kit', /Drive keys were created.*key kit/.test(await p.textContent('#setup-msg')));
  await login(p, 'owner', PW);
  const ownerId = (await api(p, '/api/private/me')).body.user.id;
  const lim = await api(p, '/api/private/admin/limits', { method: 'PATCH', body: JSON.stringify({ scope: 'global', channel: 'all', patch: { driveEnabled: true } }) });
  check('Default role: Drive on', lim.status === 200);
  await p.goto(`${BASE}/dashboard/admin/`);
  await p.click('.tab[data-tab="users"]');
  const up = p.locator('.admin-panel[data-panel="users"]');
  await up.locator('input[aria-label="New username"]').first().fill('alice');
  await up.locator('input[aria-label="New user password"]').first().fill(ALICE_PW);
  await up.locator('input[aria-label="Repeat password"]').first().fill(ALICE_PW);
  await up.locator('button:has-text("Create user")').first().click();
  await p.waitForFunction(() => document.getElementById('toast').textContent === 'User created.', null, { timeout: 30000 });
  const aliceId = (await api(p, '/api/private/admin/users')).body.users.find((u) => u.username === 'alice').id;

  // Content under the first sub-MEK: the owner's and alice's.
  await driveUpload(p, 'owner-first.txt', 'owner, before any change\n');
  const ac = await b.newContext({ acceptDownloads: true, reducedMotion: 'reduce', viewport: { width: 1280, height: 900 } });
  const a = await ac.newPage();
  watch(a);
  await login(a, 'alice', ALICE_PW);
  await driveUpload(a, 'alice-first.txt', 'alice, before any change\n');

  // ── Security → Keys: the keyring ──
  await keysPage(p);
  let rows = await subRows(p);
  const sub1 = rows[0].id;
  check('keys: one sub-MEK, current, holding the two files', rows.length === 1 && rows[0].status === 'current' && rows[0].items === '2', JSON.stringify(rows));
  check('keys: plain-language help (the server can open every Drive; what the root is; rotation)', /server can open every Drive/.test(await p.textContent('#keys-ring')) && /re-seals every item/.test(await p.textContent('#keys-root-help')) && /new data uses a new sub-MEK/.test(await p.textContent('#keys-rotate-help')));
  check('keys: the fresh-kit notice (no kit yet)', /No key kit has been downloaded yet/.test(await p.textContent('#keys-kit-notice')));
  await audit(p, 'Security → Keys');
  await p.click('#keys-root button:has-text("Show")');
  await p.waitForFunction(() => !document.querySelector('#keys-msg').hidden, null, { timeout: 30000 });
  check('keys: Show without the password is refused', (await p.$('#keys-shown .key-value')) === null);
  await confirmPw(p);
  await p.click('#keys-root button:has-text("Show")');
  await p.waitForSelector('#keys-shown .key-value', { timeout: 60000 });
  const rootShown = await p.textContent('#keys-shown .key-value');
  shown.add(rootShown);
  check('keys: Show (with the step-up) gives the root entered at set-up, hidden again later', rootShown === b64url(ROOT) && /hidden again in 60 seconds/.test(await p.textContent('#keys-shown')));
  await audit(p, 'Security → Keys (a key shown)');
  await p.click('#keys-shown button:has-text("Hide")');
  await confirmPw(p);
  await p.click(`#keys-subs-table tr[data-id="${sub1}"] button:has-text("Show")`);
  await p.waitForSelector('#keys-shown .key-value', { timeout: 60000 });
  check('keys: the sub-MEK is the one entered at set-up', (await p.textContent('#keys-shown .key-value')) === b64url(SUB));
  shown.add(b64url(SUB));
  await p.click('#keys-shown button:has-text("Hide")');

  // Rotate: a generated key, used only on "Use this key" (another first).
  await p.click('button:has-text("Rotate now…")');
  await p.waitForSelector('.key-chooser');
  await confirmPw(p);
  await p.click('.key-chooser button:has-text("Generate securely")');
  await p.waitForSelector('.key-chooser .key-value', { timeout: 60000 });
  const cand1 = await p.textContent('.key-chooser .key-value');
  check('rotate: a generated candidate is shown; nothing is stored yet', (await status(p)).subs.length === 1);
  await audit(p, 'Security → Keys (a generated key)');
  await confirmPw(p);
  await p.click('.key-chooser button:has-text("Generate another")');
  await p.waitForFunction((c) => { const v = document.querySelector('.key-chooser .key-value'); return v && v.textContent !== c; }, cand1, { timeout: 60000 });
  const cand2 = await p.textContent('.key-chooser .key-value');
  shown.add(cand1); shown.add(cand2);
  await confirmPw(p);
  await p.click('.key-chooser button:has-text("Use this key")');
  await waitToast(p, /current from now on/);
  await keysPage(p);
  rows = await subRows(p);
  const sub2 = rows.find((r) => r.status === 'current').id;
  check('rotate: two sub-MEKs; the new one current, the old one retired with its items', rows.length === 2 && sub2 !== sub1 && rows.find((r) => r.id === sub1).status === 'retired' && rows.find((r) => r.id === sub1).items === '2', JSON.stringify(rows));
  await confirmPw(p);
  await p.click(`#keys-subs-table tr[data-id="${sub2}"] button:has-text("Show")`);
  await p.waitForSelector('#keys-shown .key-value', { timeout: 60000 });
  check('rotate: the key used is the second candidate (the first was thrown away)', (await p.textContent('#keys-shown .key-value')) === cand2);
  await p.click('#keys-shown button:has-text("Hide")');
  check('rotate: every file still opens (alice)', await driveReads(a, 'alice-first.txt', 'alice, before any change\n'));
  await driveUpload(a, 'alice-second.txt', 'alice, after the rotation\n');

  // A scheduled sub-MEK, entered by hand, from tomorrow.
  await keysPage(p);
  const tomorrow = new Date(Date.now() + 36 * 3600 * 1000);
  const pad = (n) => String(n).padStart(2, '0');
  await p.fill('#keys-add-from', `${tomorrow.getFullYear()}-${pad(tomorrow.getMonth() + 1)}-${pad(tomorrow.getDate())}T09:00`);
  await p.fill('#keys-add-note', 'scheduled by hand');
  await p.click('button:has-text("Add a sub-MEK…")');
  await p.waitForSelector('.key-chooser');
  await p.click('.key-chooser summary:has-text("Enter manually")');
  const SUB3 = randomBytes(32);
  shown.add(b64url(SUB3));
  await p.fill('#sub-manual', SUB3.toString('hex'));
  await audit(p, 'Security → Keys (a key entered by hand)');
  await confirmPw(p);
  await p.click('.key-chooser button:has-text("Use the key I entered")');
  await waitToast(p, /Sub-MEK added/);
  await keysPage(p);
  rows = await subRows(p);
  const sub3 = rows.find((r) => r.status === 'scheduled')?.id;
  check('add: a sub-MEK scheduled from tomorrow; the current one unchanged', !!sub3 && rows.find((r) => r.id === sub2).status === 'current', JSON.stringify(rows));

  // Re-seal the retired sub-MEK, then delete it.
  await confirmPw(p);
  // The job's progress box may come and go quickly: watched for while it runs.
  await p.evaluate(() => { window.sawJob = false; new MutationObserver(() => { if (/Re-sealing/.test(document.querySelector('#keys-job')?.textContent || '')) window.sawJob = true; }).observe(document.body, { subtree: true, childList: true, characterData: true }); });
  await p.click(`#keys-subs-table tr[data-id="${sub1}"] button:has-text("Re-seal")`);
  await waitToast(p, new RegExp(`Nothing is sealed under ${sub1} any more`));
  check('re-seal: the job showed its progress, and its end is announced', await p.evaluate(() => window.sawJob));
  await audit(p, 'Security → Keys (a re-seal done)');
  await keysPage(p);
  rows = await subRows(p);
  check('re-seal: nothing is left under the retired sub-MEK', rows.find((r) => r.id === sub1).items === '0', JSON.stringify(rows));
  check('re-seal: every file still opens (the owner)', await driveReads(p, 'owner-first.txt', 'owner, before any change\n'));
  await keysPage(p);
  await confirmPw(p); // first: leaving the armed button disarms it
  await p.click(`#keys-subs-table tr[data-id="${sub1}"] button:has-text("Delete")`);
  check('delete: two steps (the button asks to confirm)', /then delete\?/.test(await p.textContent(`#keys-subs-table tr[data-id="${sub1}"] button.danger`)));
  await p.click(`#keys-subs-table tr[data-id="${sub1}"] button.danger`);
  await waitToast(p, /was deleted/);
  await keysPage(p);
  rows = await subRows(p);
  check('delete: the retired sub-MEK is gone', !rows.some((r) => r.id === sub1) && rows.length === 2, JSON.stringify(rows));
  check('delete: alice\'s files still open (a new page: the keys from the server)', await driveReads(a, 'alice-first.txt', 'alice, before any change\n') && await driveReads(a, 'alice-second.txt', 'alice, after the rotation\n'));

  // ── the key kit ──
  await keysPage(p);
  await p.fill('#kkit-pass', KIT_PASS); await p.fill('#kkit-pass2', KIT_PASS); await p.fill('#kkit-confirm', PW);
  const kit = await saveDownload(p, () => p.click('#kkit-download'), 'key-kit.json');
  const kitText = readFileSync(kit, 'utf8');
  check('key kit: downloaded after the step-up; the file holds no key in the clear', /secbin-key-kit\/1/.test(kitText) && ![...shown].some((k) => kitText.includes(k)) && !kitText.includes(ROOT.toString('hex')));
  await keysPage(p);
  check('key kit: the notice is gone and the date shown', (await p.$('#keys-kit-notice')) === null && /Latest key kit/.test(await p.textContent('#keys-kit-last')));
  await p.setInputFiles('#kkit-verify-file', kit);
  await p.fill('#kkit-verify-pass', KIT_PASS);
  await p.click('#kkit-verify');
  await p.waitForSelector('#kkit-verify-verdict', { timeout: 120000 });
  check('key kit: verify (today) — complete', (await p.getAttribute('#kkit-verify-verdict', 'data-verdict')) === 'complete', await p.textContent('#kkit-verify-out'));
  await audit(p, 'Security → Keys (key kit verified)');
  const later = new Date(Date.now() + 4 * 86400 * 1000);
  await p.fill('#kkit-verify-date', `${later.getFullYear()}-${pad(later.getMonth() + 1)}-${pad(later.getDate())}`);
  await p.setInputFiles('#kkit-verify-file', kit);
  await p.fill('#kkit-verify-pass', KIT_PASS);
  await p.click('#kkit-verify');
  await p.waitForSelector('#kkit-verify-verdict', { timeout: 120000 });
  check('key kit: verify on a later date — the scheduled sub-MEK is in effect then, and in the kit', (await p.getAttribute('#kkit-verify-verdict', 'data-verdict')) === 'complete' && (await p.textContent('#kkit-verify-out')).includes(sub3), await p.textContent('#kkit-verify-out'));
  await p.setInputFiles('#kkit-verify-file', kit);
  await p.fill('#kkit-verify-pass', 'not the passphrase');
  await p.click('#kkit-verify');
  await p.waitForFunction(() => { const m = document.querySelector('#kkit-verify-msg'); const v = document.querySelector('#kkit-verify-verdict'); return (m && !m.hidden && !/Checking/.test(m.textContent)) || (v && v.dataset.verdict === 'failed'); }, null, { timeout: 120000 });
  check('key kit: a wrong passphrase does not open it', !(await p.$('#kkit-verify-verdict[data-verdict="complete"]')));
  await p.waitForTimeout(3000); // the throttle after a failed opening
  await p.setInputFiles('#kkit-restore-file', kit);
  await p.fill('#kkit-restore-pass', KIT_PASS);
  await p.fill('#kkit-restore-confirm', PW); // the preview asks for the step-up too (it opens the kit)
  await p.click('#kkit-preview');
  await p.waitForFunction(() => /restore/i.test(document.querySelector('#kkit-restore-plan').textContent), null, { timeout: 120000 });
  check('key kit: a restore preview on a working server replaces nothing', /Nothing to restore/.test(await p.textContent('#kkit-restore-plan')) && await p.isDisabled('#kkit-restore'), await p.textContent('#kkit-restore-plan'));
  await audit(p, 'Security → Keys (restore preview)');

  // ── a user's keys (read-only, masked) ──
  await p.selectOption('#keys-user', aliceId);
  await p.fill('#keys-user-confirm', PW);
  await p.click('#keys-user-view');
  await p.waitForSelector('#keys-user-out li', { timeout: 60000 });
  check('a user\'s keys: salt and KEKs listed, masked', /User salt/.test(await p.textContent('#keys-user-out')) && /••••••••/.test(await p.textContent('#keys-user-out')) && (await p.$('#keys-user-out .key-value')) === null);
  await p.locator('#keys-user-out button:has-text("Show")').first().click();
  check('a user\'s keys: Show reveals one value', (await p.$$('#keys-user-out .key-value')).length === 1);
  shown.add(await p.textContent('#keys-user-out .key-value'));
  await audit(p, 'Security → Keys (a user\'s keys)');

  // ── the personal kit (alice, on Account) ──
  await a.goto(`${BASE}/dashboard/account/#drive-kit`);
  await a.waitForSelector('#ukit-download', { timeout: 60000 });
  await audit(a, 'Account (personal kit)');
  await a.fill('#ukit-pass', KIT_PASS); await a.fill('#ukit-pass2', KIT_PASS); await a.fill('#ukit-confirm', ALICE_PW);
  const ukit = await saveDownload(a, () => a.click('#ukit-download'), 'personal-kit.json');
  check('personal kit: downloaded after the step-up', /secbin-user-kit\/2/.test(readFileSync(ukit, 'utf8')));
  await a.setInputFiles('#ukit-verify-file', ukit);
  await a.fill('#ukit-verify-pass', KIT_PASS);
  await a.click('#ukit-verify');
  await a.waitForSelector('#ukit-verify-verdict', { timeout: 120000 });
  check('personal kit: verify — complete', (await a.getAttribute('#ukit-verify-verdict', 'data-verdict')) === 'complete', await a.textContent('#ukit-verify-out'));
  await audit(a, 'Account (personal kit verified)');
  await a.setInputFiles('#ukit-restore-file', ukit);
  await a.fill('#ukit-restore-pass', KIT_PASS); await a.fill('#ukit-restore-confirm', ALICE_PW);
  await a.click('#ukit-restore');
  await a.waitForFunction(() => /Restore done|cannot|wrong|not/.test(document.querySelector('#ukit-restore-msg').textContent) && !/Opening/.test(document.querySelector('#ukit-restore-msg').textContent), null, { timeout: 120000 });
  check('personal kit: a restore on a working server changes nothing', /Restore done: your user salt was already there; nothing else was missing/.test(await a.textContent('#ukit-restore-msg')), await a.textContent('#ukit-restore-msg'));

  // ── Import / export → Drive keys ──
  const before = await status(p);
  await p.goto(`${BASE}/dashboard/admin/?load=${Date.now()}#portable`);
  await p.waitForSelector('#kx-build', { timeout: 60000 });
  await p.check('#kx-root');
  await p.selectOption('#kx-subs', 'all');
  await p.fill('#kx-search', 'ali');
  check('export: the user search filters the list', await p.isVisible(`#kx-users li[data-id="${aliceId}"]`) && await p.isHidden(`#kx-users li[data-id="${ownerId}"]`));
  await p.click('#drive-keys-port button:has-text("Select all")');
  await p.fill('#kx-search', '');
  await p.check('#kx-salts'); await p.check('#kx-keks');
  await p.selectOption('#kx-deks', 'all');
  await p.fill('#kx-confirm', PW);
  await p.click('#kx-build');
  await p.waitForSelector('#kx-view li', { timeout: 60000 });
  const view = await p.textContent('#kx-view');
  check('export: built after the step-up, shown masked (root, sub-MEKs, alice\'s salt, KEKs and DEKs)', /Root MEK/.test(view) && /User salts: 1/.test(view) && /File keys \(DEKs\): 2/.test(view) && (await p.$('#kx-view .key-value')) === null, view.slice(0, 300));
  await audit(p, 'Import / export (Drive keys built)');
  await p.fill('#kx-pass', KIT_PASS); await p.fill('#kx-pass2', KIT_PASS);
  const exp = await saveDownload(p, () => p.click('#kx-save'), 'drive-keys.json');
  const expText = readFileSync(exp, 'utf8');
  check('export: the file is sealed (no key in the clear)', ![...shown].some((k) => expText.includes(k)) && !expText.includes(ROOT.toString('hex')));
  await p.setInputFiles('#ki-file', exp);
  await p.fill('#ki-pass', KIT_PASS);
  await p.click('#ki-open');
  await p.waitForSelector('#ki-preview', { timeout: 60000 });
  await p.fill('#ki-confirm', PW); // the preview asks for the step-up too (it opens the file's keys)
  await p.click('#ki-preview');
  await p.waitForSelector('#ki-plan li', { timeout: 60000 });
  const plan = await p.textContent('#ki-plan');
  check('import: the preview replaces nothing (KEKs checked and matching; DEKs already working)', /Preview/.test(plan) && /match/.test(plan) && /0 to restore/.test(plan) && !/0 match/.test(plan), plan);
  await audit(p, 'Import / export (import preview)');
  await p.fill('#ki-confirm', PW);
  await p.click('#ki-apply');
  await p.waitForFunction(() => /Imported/.test(document.querySelector('#ki-plan-msg').textContent), null, { timeout: 60000 });
  const after = await status(p);
  check('import: applied; the keyring is as it was', JSON.stringify(after.subs.map((s) => [s.id, s.fp])) === JSON.stringify(before.subs.map((s) => [s.id, s.fp])) && after.root.fp === before.root.fp);

  // ── a root change (a key entered by hand) ──
  await keysPage(p);
  const ROOT2 = randomBytes(32);
  shown.add(b64url(ROOT2));
  await p.click('#keys-root button:has-text("Change root…")');
  await p.waitForSelector('.key-chooser');
  await p.click('.key-chooser summary:has-text("Enter manually")');
  await p.fill('#root-manual', ROOT2.toString('base64'));
  await confirmPw(p);
  await p.click('.key-chooser button:has-text("Use the key I entered")');
  await waitToast(p, /Every item is re-sealed under the new root MEK and was checked; the old one was removed/);
  const st2 = await status(p);
  check('root change: a new root; every item re-sealed; the old root gone', st2.root.fp !== before.root.fp && !st2.root.changing, JSON.stringify(st2.root));
  await keysPage(p);
  await confirmPw(p);
  await p.click('#keys-root button:has-text("Show")');
  await p.waitForSelector('#keys-shown .key-value', { timeout: 60000 });
  check('root change: the root is the one entered', (await p.textContent('#keys-shown .key-value')) === b64url(ROOT2));
  check('root change: every file still opens (alice and the owner)', await driveReads(a, 'alice-first.txt', 'alice, before any change\n') && await driveReads(a, 'alice-second.txt', 'alice, after the rotation\n') && await driveReads(p, 'owner-first.txt', 'owner, before any change\n'));

  // ── the admin audit: key actions by fingerprint, never a key ──
  const rowsAudit = [];
  for (let before = null, n = 0; n < 20; n++) {
    const r = (await api(p, `/api/private/admin/audit${before ? `?before=${before}` : ''}`)).body;
    rowsAudit.push(...(r.rows || []));
    if (!r.rows || r.rows.length < 100) break;
    before = r.rows[r.rows.length - 1].id;
  }
  const keyActs = new Set(rowsAudit.filter((x) => /^(keys|drive)\./.test(x.action)).map((x) => x.action));
  info(`key actions in the admin audit: ${[...keyActs].sort().join(', ')}`);
  const auditText = JSON.stringify(rowsAudit);
  const vals = [...shown, ROOT.toString('hex'), SUB.toString('base64'), SUB3.toString('hex'), ROOT2.toString('base64')];
  check('admin audit: the key actions are there', ['keys.created', 'keys.viewed', 'keys.rotated', 'keys.added', 'keys.removed', 'keys.kit_exported', 'keys.kit_verified', 'keys.exported', 'keys.imported', 'keys.root_changed'].every((x) => keyActs.has(x)), [...keyActs].join(','));
  check('admin audit: no key value anywhere in it', !vals.some((v) => auditText.includes(v)));
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
function info(n) { console.log(`INFO ${n}`); }
