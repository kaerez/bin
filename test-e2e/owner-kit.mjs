// owner-kit.mjs — the owner recovery kit end to end (docs/DRIVE.md §3,
// "Recovery kits"), against a real `wrangler dev` and the real pages, in two
// phases on the same server state:
//
//   PHASE=1 (a fresh server, no owner yet): the kit status and the fresh-kit
//     notice on the Drive page; Download kit on the export screen (the step-up;
//     again and again), the file saved to disk; after a reload, Verify kit with
//     that saved file (setInputFiles; no file → the button stays disabled with a
//     hint), a tampered file, an older kit after a rotation (the notice appears,
//     announced, and survives a reload); Restore from kit; the create-user form
//     setting up the new user's Drive now, or deferring it; axe on every state.
//   PHASE=2 (the same state, the server restarted with a NEW AUTHN value, set as
//     AUTHN2): AUTHN owner recovery; the Drive page's unlock screen (restore
//     from kit, start over); starting over (the typed username; the old Drive
//     archived; the fresh-kit notice); restoring the archive with the phase-1
//     kit; axe on every state.
//
// A manual test, not in CI (test-e2e/README.md). Usage:
//   WT=<repo> BASE=http://localhost:8787 OUT=<dir> PHASE=1 [CHROMIUM=…] node test-e2e/owner-kit.mjs
//   (restart wrangler dev with the same --persist-to and a new AUTHN, e.g. --var AUTHN:<new>)
//   WT=<repo> BASE=http://localhost:8787 OUT=<same dir> PHASE=2 AUTHN2=<new> node test-e2e/owner-kit.mjs
import { chromium } from 'playwright-core';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';

const require = createRequire(import.meta.url);
const AXE = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const { BASE, WT, OUT } = process.env;
const PHASE = process.env.PHASE || '1';
if (!BASE || !WT || !OUT) { console.error('usage: WT=… BASE=… OUT=… PHASE=1|2 node test-e2e/owner-kit.mjs'); process.exit(2); }
mkdirSync(OUT, { recursive: true });
const TOKEN = /^AUTHN=(.*)$/m.exec(readFileSync(path.join(WT, '.dev.vars'), 'utf8'))[1].trim();
const PW = 'owner-password-123';
const PW2 = 'owner-password-after-recovery';
const KITPASS = 'a long kit passphrase 1';
const KIT = path.join(OUT, 'owner-kit.json');
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22a', 'wcag22aa'];
const results = [];
const check = (n, ok, x = '') => { results.push(!!ok); console.log(`${ok ? 'PASS' : 'FAIL'} ${n}${x ? ` — ${x}` : ''}`); };
const b = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
const errors = [];
const watch = (p) => {
  p.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  p.on('console', (m) => { if (m.type() === 'error' && !/status of (40[0134]|409|410|429)/.test(m.text())) errors.push(`console: ${m.text()}`); });
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
async function login(p, user, pw) {
  await p.goto(`${BASE}/dashboard/login/`);
  await p.fill('#login-user', user); await p.fill('#login-pass', pw); await p.click('#login-btn');
  await p.waitForURL(/\/dashboard\/(account\/)?(\?.*)?$/, { timeout: 60000 });
}
// A raw request as the page's own client sends it (public/js/api.js): a change carries the session's CSRF token.
const api = (p, url, init) => p.evaluate(async ([u, i]) => {
  const csrf = (document.cookie.match(/(?:^|;\s*)__Host-secbin_csrf=([^;]+)/) || [])[1] || '';
  const x = i || {};
  const r = await fetch(u, { cache: 'no-store', ...x, headers: { ...(x.method && x.method !== 'GET' ? { 'x-secbin-csrf': csrf } : {}), ...(x.headers || {}) } });
  return { status: r.status, body: await r.json().catch(() => null) };
}, [url, init]);
const drivePage = async (p) => {
  await p.goto(`${BASE}/dashboard/drive/`);
  await p.waitForSelector('#drive-app, #drive-unlock', { timeout: 60000 });
};
const exportScreen = async (p) => {
  await p.goto(`${BASE}/dashboard/admin/#owner-kit`);
  await p.waitForSelector('#owner-kit #kit-status-slot [data-kit], #owner-kit #kit-status-slot p', { timeout: 60000 });
};
const text = (p, sel) => p.textContent(sel);
async function download(p, passphrase = KITPASS, to = KIT) {
  await p.fill('#kit-pass', passphrase); await p.fill('#kit-pass2', passphrase); await p.fill('#kit-confirm', PW);
  const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 60000 }), p.click('#kit-download')]);
  await dl.saveAs(to);
  await p.waitForFunction(() => /downloaded/.test(document.querySelector('#kit-download-msg').textContent), null, { timeout: 60000 });
  return JSON.parse(readFileSync(to, 'utf8'));
}
async function verify(p, file, passphrase = KITPASS) {
  await p.setInputFiles('#kit-verify-file', file);
  await p.fill('#kit-verify-pass', passphrase);
  await p.click('#kit-verify');
  await p.waitForSelector('#kit-verify-verdict', { timeout: 120000 });
  return p.$$eval('#kit-verify-results li', (l) => Object.fromEntries(l.map((x) => [x.dataset.check, x.dataset.status])));
}

try {
  const ctx = await b.newContext({ acceptDownloads: true, reducedMotion: 'reduce', viewport: { width: 1280, height: 900 } });
  const p = await ctx.newPage();
  watch(p);
  if (PHASE === '1') {
    await p.goto(`${BASE}/dashboard/setup/`);
    await p.fill('#setup-token', TOKEN); await p.fill('#setup-user', 'owner'); await p.fill('#setup-pass', PW); await p.fill('#setup-pass2', PW);
    await p.click('#setup-btn');
    await p.waitForFunction(() => /created/.test(document.querySelector('#setup-msg').textContent), null, { timeout: 30000 });
    await login(p, 'owner', PW);
    // Content in the owner's Drive (it comes back from the archive in phase 2).
    await drivePage(p);
    await p.setInputFiles('#drive-file-input', [{ name: 'owner-notes.txt', mimeType: 'text/plain', buffer: Buffer.from('owner notes\n') }]);
    await p.waitForFunction(() => [...document.querySelectorAll('#drive-rows tr')].some((tr) => tr.textContent.includes('owner-notes.txt')), null, { timeout: 60000 });
    check('drive: the kit status (version 1, a fingerprint, created) and "never"', /version 1 · fingerprint [A-Za-z0-9_-]{4}-[A-Za-z0-9_-]{4} · created /.test(await text(p, '[data-kit="escrow"]')) && /never/.test(await text(p, '[data-kit="latest"]')));
    check('drive: the "no kit yet" notice (a static note)', (await p.getAttribute('#kit-status-notice', 'role')) === 'note' && (await p.getAttribute('#kit-status-notice', 'data-state')) === 'none');
    await audit(p, 'drive page, with the notice');

    // The export screen.
    await exportScreen(p);
    check('export screen: the kit card, the same status', /version 1/.test(await text(p, '#owner-kit [data-kit="escrow"]')));
    check('export screen: an empty passphrase is warned about', /No passphrase/.test(await text(p, '#kit-pass-warn')) && await p.isVisible('#kit-pass-warn'));
    check('export screen: Verify and Restore stay disabled without a file, with a hint', await p.isDisabled('#kit-verify') && await p.isDisabled('#kit-restore') && /Choose the kit file you saved/.test(await text(p, '#kit-verify-hint')));
    await audit(p, 'export screen');
    await p.fill('#kit-pass', KITPASS); await p.fill('#kit-pass2', KITPASS);
    await p.click('#kit-download');
    await p.waitForFunction(() => !document.querySelector('#kit-download-msg').hidden && /password|passkey/i.test(document.querySelector('#kit-download-msg').textContent), null, { timeout: 30000 });
    check('download: refused without the step-up', (await api(p, '/api/private/drive')).body.kit === null);
    const env1 = await download(p);
    check('download: the file is an owner kit, sealed (format, ownerId, salt, t, m, iv, ct)', env1.format === 'secbin-owner-kit/1' && Object.keys(env1).sort().join() === 'ct,format,iv,m,ownerId,salt,t');
    check('download: recorded (version 1)', (await api(p, '/api/private/drive')).body.kit?.version === 1);
    const env2 = await download(p, KITPASS, path.join(OUT, 'owner-kit-2.json'));
    check('download: always available, a new file each time', env2.ct !== env1.ct);
    // Verify the file saved to disk, from a reloaded page (nothing kept in the page).
    await p.reload();
    await p.waitForSelector('#owner-kit #kit-status-slot [data-kit]', { timeout: 60000 });
    check('verify: after a reload, no file → disabled', await p.isDisabled('#kit-verify'));
    let v = await verify(p, KIT);
    check('verify: the saved kit is a complete backup', (await text(p, '#kit-verify-verdict')) === 'Complete backup' && Object.values(v).every((s) => s === 'pass' || s === 'skip'), JSON.stringify(v));
    check('verify: the file and passphrase are cleared', (await p.inputValue('#kit-verify-pass')) === '' && (await p.$eval('#kit-verify-file', (i) => i.files.length)) === 0 && await p.isDisabled('#kit-verify'));
    await audit(p, 'export screen: verify results (complete)');
    const tampered = path.join(OUT, 'tampered.json');
    writeFileSync(tampered, JSON.stringify({ ...env1, ct: `${env1.ct.slice(0, 10)}${env1.ct[10] === 'A' ? 'B' : 'A'}${env1.ct.slice(11)}` }));
    v = await verify(p, tampered);
    check('verify: a tampered file fails the authentication check', v.auth === 'fail' && (await text(p, '#kit-verify-verdict')) === 'This kit cannot be used');
    await audit(p, 'export screen: verify results (failed)');
    const log = (await api(p, `/api/private/admin/audit?user=${(await api(p, '/api/private/me')).body.user.id}&limit=200`)).body.rows;
    check('audit: kit_exported ×2 and kit_verified', log.filter((x) => x.action === 'drive.kit_exported').length === 2 && log.some((x) => x.action === 'drive.kit_verified'));

    // The Drive page without the notice; a rotation brings it back.
    await drivePage(p);
    check('drive: no notice after a download', !(await p.$('#kit-status-notice')));
    await audit(p, 'drive page, no notice');
    await p.click('#drive-escrow-tools summary');
    await p.fill('#drive-rotate-pw', PW);
    await p.click('#drive-rotate-btn');
    await p.waitForSelector('#kit-status-notice', { timeout: 60000 });
    check('rotation: the notice appears, announced (role=alert)', (await p.getAttribute('#kit-status-notice', 'role')) === 'alert' && /The escrow key was replaced\. Download a fresh owner recovery kit/.test(await text(p, '#kit-status-notice')));
    await audit(p, 'drive page, the notice after a rotation');
    await drivePage(p);
    check('rotation: the notice survives a reload (a static note), version 2', (await p.getAttribute('#kit-status-notice', 'role')) === 'note' && /version 2/.test(await text(p, '[data-kit="escrow"]')));
    // The older kit: still works, not complete.
    await exportScreen(p);
    v = await verify(p, KIT);
    check('verify: the kit from before the rotation is "older version, still works"', v.version === 'warn' && (await text(p, '#kit-verify-verdict')) === 'Incomplete backup' && /Older version 1 .*still works through the Drive key/.test(await text(p, '#kit-verify-results [data-check="version"]')));
    await audit(p, 'export screen: verify results (incomplete)');
    // Restore from the kit in normal times: the same Drive, a new password key.
    await p.setInputFiles('#kit-restore-file', KIT);
    await p.fill('#kit-restore-pass', KITPASS); await p.fill('#kit-restore-pw', PW);
    await p.click('#kit-restore');
    await p.waitForFunction(() => /Restored/.test(document.querySelector('#kit-restore-msg').textContent), null, { timeout: 120000 });
    check('restore: from the export screen', true);
    await audit(p, 'export screen: after a restore');

    // Create user: the Drive set up now (the owner's Drive unlocked), or deferred.
    await api(p, '/api/private/admin/limits', { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ scope: 'global', channel: 'all', patch: { driveEnabled: true } }) });
    await p.goto(`${BASE}/dashboard/admin/`);
    const create = async (name) => {
      await p.click('.tab[data-tab="users"]');
      const u = p.locator('.admin-panel[data-panel="users"]');
      await u.locator('input[aria-label="New username"]').first().fill(name);
      await u.locator('input[aria-label="New user password"]').first().fill(`${name}-password-1`);
      await u.locator('input[aria-label="Repeat password"]').first().fill(`${name}-password-1`);
      await u.locator('button:has-text("Create user")').first().click();
      await p.waitForFunction((n) => (document.querySelector('#user-create-drive')?.textContent || '').startsWith(`${n}:`), name, { timeout: 60000 });
      return text(p, '#user-create-drive');
    };
    check('create user: the Drive is set up now', /set up now/.test(await create('carol')));
    await audit(p, 'admin users: Drive set up now');
    const held = await p.evaluate(() => { const v = [sessionStorage.getItem('secbin_dk'), sessionStorage.getItem('secbin_dk_uid')]; sessionStorage.removeItem('secbin_dk'); return v; });
    check('create user (owner\'s Drive locked): deferred to the first sign-in', /first sign-in/.test(await create('dave')));
    await audit(p, 'admin users: Drive deferred');
    await p.evaluate((v) => { sessionStorage.setItem('secbin_dk', v[0]); sessionStorage.setItem('secbin_dk_uid', v[1]); }, held);
    const c = await (await b.newContext()).newPage();
    await login(c, 'carol', 'carol-password-1');
    const cst = await api(c, '/api/private/drive');
    check('carol: her Drive was there before her first sign-in, and opens with the starting password', cst.body.wraps.map((w) => w.kind).sort().join() === 'escrow,pw' && !!(await c.evaluate(() => sessionStorage.getItem('secbin_dk'))));
    await c.context().close();
  } else {
    // ── phase 2: AUTHN recovery, the unlock screen, start over, the archive back ──
    if (!process.env.AUTHN2 || !existsSync(KIT)) throw new Error('phase 2 needs AUTHN2 and the phase-1 kit in OUT');
    await p.goto(`${BASE}/dashboard/setup/`);
    await p.fill('#setup-token', process.env.AUTHN2); await p.fill('#setup-user', 'owner'); await p.fill('#setup-pass', PW2); await p.fill('#setup-pass2', PW2);
    await p.click('#setup-btn');
    await p.waitForFunction(() => /recover|reset|created|updated/i.test(document.querySelector('#setup-msg').textContent), null, { timeout: 30000 });
    await login(p, 'owner', PW2);
    const st = await api(p, '/api/private/drive');
    check('recovery: the owner\'s Drive is marked pwStale, only the old pw wrap left', st.body.pwStale === true && st.body.wraps.map((w) => w.kind).join() === 'pw');
    await drivePage(p);
    check('unlock screen: restore from kit and start over offered', await p.isVisible('#drive-owner-recovery') && await p.isVisible('#kit-restore-file'));
    await audit(p, 'drive unlock screen (owner recovery)');
    await p.click('#drive-reset summary');
    await audit(p, 'drive unlock screen: start over opened');
    await p.fill('#drive-reset-user', 'nobody'); await p.fill('#drive-reset-pw', PW2);
    await p.click('#drive-reset-btn');
    await p.waitForSelector('#drive-reset-msg:not([hidden])');
    check('start over: refused without the typed username', /Type your username/.test(await text(p, '#drive-reset-msg')));
    await audit(p, 'drive unlock screen: start over error');
    await p.fill('#drive-reset-user', 'owner'); await p.fill('#drive-reset-pw', PW2);
    await p.click('#drive-reset-btn');
    await p.waitForSelector('#drive-app', { timeout: 120000 });
    check('start over: the Drive opens (new keys), the fresh-kit notice announced, the archive shown', (await p.getAttribute('#kit-status-notice', 'role')) === 'alert' && await p.isVisible('#drive-archive'));
    await audit(p, 'drive page after start over (notice, archive)');
    // The phase-1 kit (the old DK) brings the archive back.
    await exportScreen(p);
    await p.setInputFiles('#kit-restore-file', KIT);
    await p.fill('#kit-restore-pass', KITPASS); await p.fill('#kit-restore-pw', PW2);
    await p.click('#kit-restore');
    await p.waitForFunction(() => /Restored/.test(document.querySelector('#kit-restore-msg').textContent), null, { timeout: 120000 });
    check('restore: the archive is back', /before you started over/.test(await text(p, '#kit-restore-msg')));
    await drivePage(p);
    await p.waitForFunction(() => [...document.querySelectorAll('#drive-rows tr')].some((tr) => tr.textContent.includes('owner-notes.txt')), null, { timeout: 60000 });
    check('restore: the old file is in the Drive again; no archive left', !(await p.$('#drive-archive')));
    await audit(p, 'drive page after the archive restore');
  }
} catch (e) {
  console.log('ERROR', e);
  results.push(false);
} finally {
  check('no page errors or CSP / Trusted Types violations', errors.length === 0, errors.slice(0, 5).join(' | '));
  await b.close();
  const failed = results.filter((x) => !x).length;
  console.log(`\n${results.length - failed}/${results.length} passed`);
  process.exit(failed ? 1 : 0);
}
