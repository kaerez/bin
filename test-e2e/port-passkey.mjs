// port-passkey.mjs — Admin → Import / export confirmed with a passkey, and a
// Drive keys export verified, end to end against the REAL server and pages,
// with Chromium's virtual WebAuthn authenticator (CDP): the owner adds a
// passkey on Account; the account and system export and the import (its
// preview and its apply) each confirm with the passkey when the password
// field is left empty (POST /api/private/me/reauth, then { reauth }, never a
// password proof), and a wrong password is still refused; Import / export →
// Drive keys: an export of the root MEK, the sub-MEKs and the owner's own
// salt, KEKs and DEKs (the labels saying what the id list and the build
// hold), then Verify of the saved file (the passkey again) — everything
// matches this server — and of a tampered copy (another root MEK, a wrong
// KEK, a broken DEK, a sub-MEK unknown here) that says what does not match;
// only check values (and the DEKs) sent, nothing changed (the keyring, the
// file still opening), the admin audit with fingerprints and counts only;
// axe (WCAG 2.2 A/AA) on every new state; no page errors or CSP / Trusted
// Types violations. Synthetic data only. A manual test, not run in CI: see
// test-e2e/README.md. Needs a fresh `wrangler dev` (no owner yet) on
// "localhost" (an RP ID cannot be an IP address), playwright-core and
// axe-core, and a Chromium.
//   WT=<repo checkout> BASE=http://localhost:8787 [CHROMIUM=<path>] [OUT=<dir>] node test-e2e/port-passkey.mjs
import { chromium } from 'playwright-core';
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync } from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';

const require = createRequire(import.meta.url);
const AXE = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const BASE = process.env.BASE;
const WT = process.env.WT;
if (!BASE || !WT) { console.error('usage: WT=<repo checkout> BASE=http://localhost:8787 node test-e2e/port-passkey.mjs'); process.exit(2); }
const TOKEN = /^AUTHN=(.*)$/m.exec(readFileSync(path.join(WT, '.dev.vars'), 'utf8'))[1].trim();
const OUT = process.env.OUT || mkdtempSync(path.join(os.tmpdir(), 'secbin-port-passkey-'));
mkdirSync(OUT, { recursive: true });
const PW = 'owner-password-123';
const ALICE_PW = 'alice-password-123';
const PASS = 'an export passphrase for the test';
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22a', 'wcag22aa'];
const MINE = 'Your password (or leave it empty to confirm with a passkey)';
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
const saveDownload = async (p, click, name) => {
  const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 180000 }), click()]);
  const f = path.join(OUT, name);
  await dl.saveAs(f);
  return f;
};
const hasRow = (n) => [...document.querySelectorAll('#drive-rows tr')].some((tr) => tr.children[1].textContent.trim() === n);
const portable = async (p) => {
  await p.goto(`${BASE}/dashboard/admin/?load=${Date.now()}#portable`);
  await p.waitForSelector('#kx-build', { timeout: 60000 });
};
const msgOf = (p, sel) => p.evaluate((s) => document.querySelector(s)?.textContent || '', sel);

try {
  const ctx = await b.newContext({ acceptDownloads: true, reducedMotion: 'reduce', viewport: { width: 1280, height: 900 } });
  const p = await ctx.newPage();
  watch(p);
  const cdp = await ctx.newCDPSession(p);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  // What the pages send: the step-up of each export, import and verify.
  const sent = [];
  p.on('request', (r) => {
    if (r.method() !== 'POST' || !/\/api\/private\/(admin\/(export|import|keys\/export(\/verify)?)|me\/reauth)$/.test(new URL(r.url()).pathname)) return;
    let body = null;
    try { body = r.postDataJSON(); } catch { /* not JSON */ }
    sent.push({ path: new URL(r.url()).pathname, body });
  });
  const since = (n, pathname) => sent.slice(n).filter((x) => x.path === pathname);
  const passkeyOnly = (x) => !!x && !!x.body && typeof x.body.reauth?.challengeId === 'string' && !!x.body.reauth.credential && x.body.current === undefined;

  // ── set-up, a user, the owner's passkey, a Drive file ──
  await p.goto(`${BASE}/dashboard/setup/`);
  await p.waitForSelector('#setup-form:not([hidden])');
  await p.fill('#setup-token', TOKEN); await p.fill('#setup-user', 'owner'); await p.fill('#setup-pass', PW); await p.fill('#setup-pass2', PW);
  await p.click('#setup-btn');
  await p.waitForFunction(() => /created/.test(document.querySelector('#setup-msg').textContent), null, { timeout: 30000 });
  await p.goto(`${BASE}/dashboard/login/`);
  await p.fill('#login-user', 'owner'); await p.fill('#login-pass', PW); await p.click('#login-btn');
  await p.waitForURL(/\/dashboard\/(\?.*)?$/, { timeout: 60000 });
  const ownerId = (await api(p, '/api/private/me')).body.user.id;
  check('Default role: Drive on', (await api(p, '/api/private/admin/limits', { method: 'PATCH', body: JSON.stringify({ scope: 'global', channel: 'all', patch: { driveEnabled: true } }) })).status === 200);
  await p.goto(`${BASE}/dashboard/admin/`);
  await p.click('.tab[data-tab="users"]');
  const up = p.locator('.admin-panel[data-panel="users"]');
  await up.locator('input[aria-label="New username"]').first().fill('alice');
  await up.locator('input[aria-label="New user password"]').first().fill(ALICE_PW);
  await up.locator('input[aria-label="Repeat password"]').first().fill(ALICE_PW);
  await up.locator('button:has-text("Create user")').first().click();
  await p.waitForFunction(() => document.getElementById('toast').textContent === 'User created.', null, { timeout: 30000 });
  await p.goto(`${BASE}/dashboard/account/`);
  await p.waitForSelector('#passkeys-body td');
  await p.fill('#passkey-current', PW);
  await p.fill('#passkey-name', 'Virtual laptop');
  await p.click('#passkey-add');
  await p.waitForSelector('#recovery-new:not([hidden])', { timeout: 60000 });
  check('the owner has a passkey (on the virtual authenticator)', (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials.length === 1);
  await p.goto(`${BASE}/dashboard/drive/`);
  await p.waitForSelector('#drive-app', { timeout: 60000 });
  await p.setInputFiles('#drive-file-input', [{ name: 'figures.txt', mimeType: 'text/plain', buffer: Buffer.from('synthetic quarterly figures\n') }]);
  await p.waitForFunction(hasRow, 'figures.txt', { timeout: 60000 });

  // ── the account and system export, confirmed with the passkey ──
  await portable(p);
  const panel = p.locator('.admin-panel[data-panel="portable"]');
  const exp = panel.locator('.card').nth(0);
  check('export: the step-up field says an empty field uses a passkey', (await exp.locator(`input[aria-label="${MINE}"]`).count()) === 1
    && (await exp.locator('label.field', { has: p.locator(`input[aria-label="${MINE}"]`) }).locator('.field-label').textContent()) === MINE);
  await exp.locator('input[aria-label="Export alice"]').check();
  await exp.locator('input[aria-label="Export passphrase"]').fill(PASS);
  await exp.locator('input[aria-label="Repeat export passphrase"]').fill(PASS);
  // A wrong password is still refused.
  await exp.locator(`input[aria-label="${MINE}"]`).fill('not-the-owner-password');
  await exp.locator('button:has-text("Encrypt and download")').click();
  await p.waitForFunction(() => /incorrect/.test(document.querySelector('.admin-panel[data-panel="portable"] .card p.msg')?.textContent || ''), null, { timeout: 30000 });
  check('export: a wrong password is refused', true);
  check('export: the field is cleared after each try', (await exp.locator(`input[aria-label="${MINE}"]`).inputValue()) === '');
  let n = sent.length;
  const accountFile = await saveDownload(p, () => exp.locator('button:has-text("Encrypt and download")').click(), 'account-export.json');
  const ex = since(n, '/api/private/admin/export');
  check('export: confirmed with the passkey (a reauth challenge, then { reauth }, no password proof)', since(n, '/api/private/me/reauth').length === 1 && ex.length === 1 && passkeyOnly(ex[0]), ex[0] ? `sent: ${Object.keys(ex[0].body || {}).join(', ')}` : 'nothing sent');
  check('export: the file is the encrypted envelope', JSON.parse(readFileSync(accountFile, 'utf8')).format === 'secbin-export-enc/v1');
  await audit(p, 'Import / export (exported with a passkey)');

  // ── the import: its preview and its apply, each confirmed with the passkey ──
  const imp = panel.locator('.card').nth(1);
  await imp.locator('input[aria-label="Export file"]').setInputFiles(accountFile);
  await imp.locator('input[aria-label="Export passphrase"]').fill(PASS);
  await imp.locator('button:has-text("Decrypt")').click();
  await imp.locator('select[aria-label="Action for alice"]').waitFor({ timeout: 60000 });
  await imp.locator('label.part-opt', { hasText: 'Settings' }).locator('input').check();
  check('import: the step-up field says the same, for the preview and again for the import', (await imp.locator(`input[aria-label="${MINE}"]`).count()) === 1 && /for the preview and again for the import/.test(await imp.textContent()));
  n = sent.length;
  await imp.locator('button:has-text("Preview")').click();
  await imp.locator('text=Preview ready').waitFor({ timeout: 60000 });
  const pv = since(n, '/api/private/admin/import');
  check('import: the preview confirmed with the passkey', since(n, '/api/private/me/reauth').length === 1 && pv.length === 1 && passkeyOnly(pv[0]) && pv[0].body.dryRun === true);
  await audit(p, 'Import / export (import previewed with a passkey)');
  n = sent.length;
  await p.waitForFunction(() => { const x = [...document.querySelectorAll('.admin-panel[data-panel="portable"] .card:nth-child(2) button')].find((y) => y.textContent === 'Import'); return x && !x.disabled; }, null, { timeout: 30000 });
  await imp.locator('button:has-text("Import")').click();
  await imp.locator('p.msg:text-is("Imported.")').waitFor({ timeout: 60000 });
  const ap = since(n, '/api/private/admin/import');
  check('import: applied, confirmed with the passkey again (a new challenge)', since(n, '/api/private/me/reauth').length === 1 && ap.length === 1 && passkeyOnly(ap[0]) && ap[0].body.dryRun === false && ap[0].body.reauth.challengeId !== pv[0].body.reauth.challengeId);

  // ── Drive keys: the labels, an export, Verify ──
  await portable(p);
  check('Drive keys: "Download the chosen ids" says it is a list of user ids with no keys', await p.isVisible('#drive-keys-port button:has-text("Download the chosen ids (a list of user ids, no keys)")')
    && /plain text file of the chosen user ids, one per line, with no keys/.test(await p.textContent('#drive-keys-port')));
  check('Drive keys: next to "Build the export", what goes in and when it is encrypted', (await p.getAttribute('#kx-build', 'aria-describedby')) === 'kx-build-hint'
    && /chosen users’ salts, KEKs and DEKs \(as ticked\)/.test(await p.textContent('#kx-build-hint')) && /“Encrypt and download” then encrypts it with the export passphrase/.test(await p.textContent('#kx-build-hint')));
  const before = (await api(p, '/api/private/admin/keys')).body;
  await p.check('#kx-root');
  await p.selectOption('#kx-subs', 'all');
  await p.check(`#kx-users li[data-id="${ownerId}"] input`);
  await p.check('#kx-salts'); await p.check('#kx-keks');
  await p.selectOption('#kx-deks', 'all');
  n = sent.length;
  await p.click('#kx-build'); // the field left empty: the passkey
  await p.waitForSelector('#kx-view li', { timeout: 60000 });
  check('Drive keys export: built after a passkey confirmation', passkeyOnly(since(n, '/api/private/admin/keys/export')[0]));
  await p.fill('#kx-pass', PASS); await p.fill('#kx-pass2', PASS);
  const keysFile = await saveDownload(p, () => p.click('#kx-save'), 'drive-keys.json');
  // The file's keys, opened in the page (for the checks below; never logged).
  const doc = await p.evaluate(async ([text, pass]) => (await import('/js/exportcrypt.js')).openExport(text, pass), [readFileSync(keysFile, 'utf8'), PASS]);
  check('the export holds the root, the sub-MEKs, the owner\'s salt, KEKs and DEK', !!doc.root && doc.subs.length >= 1 && !!doc.salts[ownerId] && doc.users[0].keks.length >= 1 && doc.users[0].deks.length === 1);
  const secrets = [doc.root.key, ...doc.subs.map((s) => s.key), doc.salts[ownerId], ...doc.users[0].keks.map((k) => k.kek)];

  const verify = async (file) => {
    await p.setInputFiles('#kv-file', file);
    await p.fill('#kv-pass', PASS);
    await p.click('#kv-verify');
    await p.waitForFunction(() => document.querySelector('#kv-verdict') || !document.querySelector('#kv-msg').hidden && !/…/.test(document.querySelector('#kv-msg').textContent), null, { timeout: 180000 });
  };
  await audit(p, 'Import / export (Drive keys: the Verify form)');
  n = sent.length;
  await verify(keysFile);
  const v1 = since(n, '/api/private/admin/keys/export/verify');
  check('verify: the file matches this server', (await p.getAttribute('#kv-verdict', 'data-verdict')) === 'complete' && (await p.textContent('#kv-verdict')) === 'Everything in this file matches this server', await msgOf(p, '#kv-out') || await msgOf(p, '#kv-msg'));
  check('verify: the summary says so', /^Everything in this file matches this server\./.test(await p.textContent('#kv-summary')));
  const statusOf = (id) => p.getAttribute(`#kv-results [data-check="${id}"]`, 'data-status');
  check('verify: root MEK, every sub-MEK, the owner\'s salt, KEKs and DEK pass', (await statusOf('root')) === 'pass' && (await Promise.all(doc.subs.map((s) => statusOf(`sub:${s.id}`)))).every((x) => x === 'pass')
    && (await statusOf(`user:${ownerId}`)) === 'pass' && /the user salt matches; KEKs: \d+ of \d+ match; DEKs: 1 of 1 open their file’s first chunk/.test(await p.textContent(`#kv-results [data-check="user:${ownerId}"]`)));
  check('verify: the sub-MEK in effect today is in the file', (await statusOf('date')) === 'pass');
  check('verify: confirmed with the passkey; only check values (and the DEK) sent', v1.length === 1 && passkeyOnly(v1[0]) && !secrets.some((k) => JSON.stringify(v1[0].body).includes(k)) && v1[0].body.users[0].deks[0].dek === doc.users[0].deks[0].dek);
  check('verify: the file and passphrase fields are cleared', (await p.inputValue('#kv-pass')) === '' && (await p.evaluate(() => document.querySelector('#kv-file').files.length)) === 0);
  check('verify: focus on the verdict', await p.evaluate(() => document.activeElement?.id === 'kv-verdict'));
  await audit(p, 'Import / export (Drive keys verified: matches)');

  // A tampered copy: another root MEK, a wrong KEK, a broken DEK, a sub-MEK unknown here.
  const tamperedText = await p.evaluate(async ([text, pass]) => {
    const { openExport, sealExport } = await import('/js/exportcrypt.js');
    const { b64urlFromBytes, randomBytes } = await import('/js/bytes.js');
    const d = await openExport(text, pass);
    const other = () => b64urlFromBytes(randomBytes(32));
    d.root.key = other();
    d.subs.push({ id: 'mZZZZZZZZZZZ', key: other(), fp: 'x', from: 0, until: 0 });
    d.users[0].keks[0].kek = other();
    d.users[0].deks[0].dek = other();
    return sealExport(d, pass);
  }, [readFileSync(keysFile, 'utf8'), PASS]);
  const tampered = path.join(OUT, 'drive-keys-tampered.json');
  writeFileSync(tampered, tamperedText);
  await verify(tampered);
  check('verify (tampered): does not match', (await p.getAttribute('#kv-verdict', 'data-verdict')) === 'incomplete' && (await p.textContent('#kv-verdict')) === 'Not everything in this file matches this server');
  check('verify (tampered): the root MEK, the unknown sub-MEK and the owner\'s keys fail, in words', (await statusOf('root')) === 'fail' && (await statusOf('sub:mZZZZZZZZZZZ')) === 'fail' && (await statusOf(`user:${ownerId}`)) === 'fail'
    && (await p.textContent('#kv-results [data-check="root"] strong')) === 'Fail: ');
  const userLine = await p.textContent(`#kv-results [data-check="user:${ownerId}"]`);
  check('verify (tampered): the KEK differs and the DEK does not open its file', /1 differ/.test(userLine) && /DEKs: 0 of 1 open their file’s first chunk; 1 do not open it/.test(userLine), userLine);
  check('verify (tampered): the summary names what does not match', /^What does not match: Root MEK; Sub-MEK mZZZZZZZZZZZ; owner \(/.test(await p.textContent('#kv-summary')), await p.textContent('#kv-summary'));
  await audit(p, 'Import / export (Drive keys verified: a tampered copy)');
  // A wrong passphrase: said so, nothing sent.
  n = sent.length;
  await p.setInputFiles('#kv-file', keysFile);
  await p.fill('#kv-pass', 'not the passphrase');
  await p.click('#kv-verify');
  await p.waitForFunction(() => !document.querySelector('#kv-msg').hidden && !/…/.test(document.querySelector('#kv-msg').textContent), null, { timeout: 120000 });
  check('verify: a wrong passphrase is refused in the page, nothing sent', since(n, '/api/private/admin/keys/export/verify').length === 0 && since(n, '/api/private/me/reauth').length === 0, await msgOf(p, '#kv-msg'));

  // Nothing changed: the keyring, the file still opening; the audit has counts and fingerprints only.
  const after = (await api(p, '/api/private/admin/keys')).body;
  check('verify changed nothing: the keyring is as it was', JSON.stringify(after.subs.map((s) => [s.id, s.fp, s.from, s.until])) === JSON.stringify(before.subs.map((s) => [s.id, s.fp, s.from, s.until])) && after.root.fp === before.root.fp);
  await p.goto(`${BASE}/dashboard/drive/`);
  await p.waitForSelector('#drive-app', { timeout: 60000 });
  await p.waitForFunction(hasRow, 'figures.txt', { timeout: 60000 });
  await p.locator('#drive-rows tr', { has: p.locator('td:nth-child(2) bdi.fname', { hasText: /^figures\.txt$/ }) }).locator('input[type="checkbox"]').check();
  const got = await saveDownload(p, () => p.click('#drive-download'), 'figures.txt');
  check('verify changed nothing: the file still opens', readFileSync(got, 'utf8') === 'synthetic quarterly figures\n');
  const rows = (await api(p, '/api/private/admin/audit')).body.rows;
  const vr = rows.filter((r) => r.action === 'keys.export_verified');
  check('admin audit: each verify recorded, with the root fingerprint and counts, never a key', vr.length === 2 && vr.some((r) => r.detail.startsWith('matches:') && r.detail.includes(before.root.fp)) && vr.some((r) => r.detail.startsWith('does not match:'))
    && !rows.some((r) => secrets.some((k) => String(r.detail).includes(k))), vr.map((r) => r.detail).join(' | '));
  check('admin audit: the export and the import recorded', rows.some((r) => r.action === 'export.created') && rows.some((r) => r.action === 'import.system'));
} catch (e) {
  check('no exception', false, e.message.split('\n')[0]);
}
check('no page errors or CSP / Trusted Types violations', errors.length === 0, errors.slice(0, 3).join(' | '));
await b.close();
console.log(`${results.filter(Boolean).length}/${results.length} passed`);
process.exit(results.every(Boolean) ? 0 : 1);
