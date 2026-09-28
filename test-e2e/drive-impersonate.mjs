// drive-impersonate.mjs — e2e: the owner logs in as a user ("Log in as") and
// has that user's whole Drive with the key model v2 (docs/DRIVE.md §3, §9):
// the server hands the owner's session the user's KEKs (drive.keys_used in
// the admin audit), in the page's memory only (never in the tab's storage);
// the owner reads and downloads the user's file, uploads one, shares it (the
// recipient opens the link); the personal kit and the upgrade are the user's
// own (403 impersonating). A user who has never signed in has a Drive too
// (made on first need), so the owner can use it at once. The user's activity
// lists what was done as them, as their own, with no trace of the
// impersonation; the admin audit shows the owner as the real actor. Also:
// Hebrew and spoofing names in the Drive page.
// A manual test, not run in CI: see test-e2e/README.md.
// Usage: WT=<repo checkout> BASE=http://127.0.0.1:8787 [CHROMIUM=<path>] node test-e2e/drive-impersonate.mjs
import { chromium } from 'playwright-core';
import { readFileSync, mkdtempSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const BASE = process.env.BASE;
const WT = process.env.WT;
if (!BASE || !WT) { console.error('usage: WT=<repo checkout> BASE=http://127.0.0.1:8787 node drive-impersonate.mjs'); process.exit(2); }
const TOKEN = /^AUTHN=(.*)$/m.exec(readFileSync(path.join(WT, '.dev.vars'), 'utf8'))[1].trim();
const OUT = mkdtempSync(path.join(os.tmpdir(), 'secbin-drive-imp-'));
const PW = 'owner-password-123';
const ALICE_PW = 'alice-password-123';
const BOB_PW = 'bob-password-12345';
const results = [];
const check = (n, ok, x = '') => { results.push(!!ok); console.log(`${ok ? 'PASS' : 'FAIL'} ${n}${x ? ' — ' + x : ''}`); };
const b = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
const errors = [];
const watch = (p) => {
  p.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  p.on('console', (m) => { if (m.type() === 'error' && /Content Security Policy|Trusted Type/i.test(m.text())) errors.push(`console: ${m.text()}`); });
};
// A raw request as the page's own client sends it (public/js/api.js): a
// change carries the session's CSRF token (the readable __Host-secbin_csrf cookie).
const api = (p, url, init = {}) => p.evaluate(async ([u, i]) => {
  const csrf = (document.cookie.match(/(?:^|;\s*)__Host-secbin_csrf=([^;]+)/) || [])[1] || '';
  const r = await fetch(u, { cache: 'no-store', ...i, headers: { 'content-type': 'application/json', 'x-secbin-intent': '1', ...(i.method && i.method !== 'GET' ? { 'x-secbin-csrf': csrf } : {}), ...(i.headers || {}) } });
  return { status: r.status, body: await r.json().catch(() => null) };
}, [url, init]);
const rowNames = (p) => p.$$eval('#drive-rows tr', (trs) => trs.map((tr) => tr.children[1].textContent.trim()));
// Names are shown as a bidi isolate with the extension in its own element (common.js nameEl).
const exact = (name) => new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`);
const rowOf = (p, name) => p.locator('#drive-rows tr', { has: p.locator('td:nth-child(2) bdi.fname', { hasText: exact(name) }) });
const hasRow = (n) => [...document.querySelectorAll('#drive-rows tr')].some((tr) => tr.children[1].textContent.trim() === n);
const waitRow = (p, n) => p.waitForFunction(hasRow, n, { timeout: 30000 });
// Every Drive key the tab's storage holds (the KEKs must never be there).
const stored = (p) => p.evaluate(() => [...Object.keys(sessionStorage), ...Object.keys(localStorage)].filter((k) => /^secbin_(kek|dk)/.test(k)));
async function login(p, user, pw) {
  await p.goto(`${BASE}/dashboard/login/`);
  await p.fill('#login-user', user); await p.fill('#login-pass', pw); await p.click('#login-btn');
  await p.waitForURL(/\/dashboard\/(\?.*)?$/, { timeout: 60000 });
  await p.waitForSelector('#dash-nav:not([hidden])');
}
async function createUser(p, name, pw) {
  await p.goto(`${BASE}/dashboard/admin/`);
  await p.click('.tab[data-tab="users"]');
  const u = p.locator('.admin-panel[data-panel="users"]');
  await u.locator('input[aria-label="New username"]').first().fill(name);
  await u.locator('input[aria-label="New user password"]').first().fill(pw);
  await u.locator('input[aria-label="Repeat password"]').first().fill(pw);
  await u.locator('button:has-text("Create user")').first().click();
  await p.waitForFunction(() => document.getElementById('toast').textContent === 'User created.', null, { timeout: 30000 });
}
async function logInAs(p, name) {
  await p.goto(`${BASE}/dashboard/admin/`);
  await p.click('.tab[data-tab="users"]');
  await p.locator('.admin-panel[data-panel="users"] tr', { has: p.locator(`td:text-is("${name}")`) }).locator('button:has-text("Log in as")').click();
  await p.waitForURL(`${BASE}/dashboard/`, { timeout: 30000 });
  await p.waitForSelector('#imp-banner:not([hidden])');
}
async function returnToAdmin(p) {
  await p.click('#imp-return');
  await p.waitForURL(`${BASE}/dashboard/admin/`, { timeout: 30000 });
}
const openDrivePage = async (p) => {
  await p.goto(`${BASE}/dashboard/drive/`);
  await p.waitForSelector('#drive-app, #drive-unavailable, #drive-disabled', { timeout: 60000 });
};

try {
  // ── the owner: set up (the Drive keys are made), signed in ──
  const oc = await b.newContext({ acceptDownloads: true, reducedMotion: 'reduce' });
  const p = await oc.newPage();
  watch(p);
  await p.goto(`${BASE}/dashboard/setup/`);
  await p.fill('#setup-token', TOKEN); await p.fill('#setup-user', 'owner'); await p.fill('#setup-pass', PW); await p.fill('#setup-pass2', PW);
  // The Drive keys the server proposes: generated, then "Use these" (the release before has no such step).
  if (await p.$('#setup-keys-gen')) { await p.click('#setup-keys-gen'); await p.click('#setup-keys-use'); }
  await p.click('#setup-btn');
  await p.waitForFunction(() => /created/.test(document.querySelector('#setup-msg').textContent), null, { timeout: 30000 });
  await login(p, 'owner', PW);
  const own = (await api(p, '/api/private/drive')).body;
  check('owner: the Drive is there at once (a current sub-MEK, no wraps)', own.enabled === true && /^m/.test(own.current || '') && own.wraps === undefined);
  check('owner: no Drive key in the tab\'s storage', (await stored(p)).length === 0);
  // Every account gets a Drive (the Default role).
  const lim = await api(p, '/api/private/admin/limits', { method: 'PATCH', body: JSON.stringify({ scope: 'global', channel: 'all', patch: { driveEnabled: true } }) });
  check('Default role: Drive on', lim.status === 200, JSON.stringify(lim.body));
  await createUser(p, 'alice', ALICE_PW);
  await createUser(p, 'bob', BOB_PW);
  const users = (await api(p, '/api/private/admin/users')).body.users;
  const aliceId = users.find((x) => x.username === 'alice').id;
  const bobId = users.find((x) => x.username === 'bob').id;

  // ── alice uses her Drive ──
  const ac = await b.newContext({ acceptDownloads: true, reducedMotion: 'reduce' });
  const a = await ac.newPage();
  watch(a);
  await login(a, 'alice', ALICE_PW);
  await openDrivePage(a);
  check('alice: her Drive opens (no prompt)', await a.isVisible('#drive-app'));
  await a.setInputFiles('#drive-file-input', [{ name: 'alice-notes.txt', mimeType: 'text/plain', buffer: Buffer.from('alice private notes\n') }]);
  await waitRow(a, 'alice-notes.txt');
  // Names in every script stay as they are; a spoofing one is cleaned (and the user told).
  await a.setInputFiles('#drive-file-input', [{ name: 'דוח שנתי 2026.pdf', mimeType: 'application/pdf', buffer: Buffer.from('%PDF-1.4\n') }]);
  await waitRow(a, 'דוח שנתי 2026.pdf');
  await a.setInputFiles('#drive-file-input', [{ name: 'invoice\u202efdp.exe', mimeType: 'application/octet-stream', buffer: Buffer.from('MZ') }]);
  await waitRow(a, 'invoicefdp.exe');
  const shown = await a.$$eval('#drive-rows tr', (trs) => trs.map((tr) => {
    const n = tr.querySelector('bdi.fname');
    return n ? { text: n.textContent, dir: n.getAttribute('dir'), ext: n.querySelector('bdi.fext')?.textContent, extDir: n.querySelector('bdi.fext')?.getAttribute('dir') } : null;
  }).filter(Boolean));
  const heb = shown.find((x) => x.text === 'דוח שנתי 2026.pdf');
  const inv = shown.find((x) => x.text === 'invoicefdp.exe');
  check('names: a Hebrew name kept unchanged, isolated, its extension ".pdf" its own LTR isolate', !!heb && heb.dir === 'auto' && heb.ext === '.pdf' && heb.extDir === 'ltr', JSON.stringify(heb));
  check('names: "invoice<RLO>fdp.exe" is stored as invoicefdp.exe and shows ".exe"', !!inv && inv.ext === '.exe' && !shown.some((x) => /\u202e/.test(x.text)), JSON.stringify(inv));
  check('names: the user is told it was renamed', /renamed/.test(await a.textContent('#toast')), await a.textContent('#toast'));
  const aliceBefore = (await api(a, '/api/private/me/activity')).body.rows.map((r) => r.id);

  // ── the owner logs in as alice: her whole Drive ──
  await logInAs(p, 'alice');
  await openDrivePage(p);
  check('as alice: the Drive opens (no prompt, no notice in its place)', await p.isVisible('#drive-app') && (await p.$('#drive-unavailable')) === null);
  const note = await p.textContent('#drive-imp-note');
  check('as alice: the page says it is her Drive, that the keys use is in the admin audit, and that her activity shows the actions as hers', /alice’s Drive/.test(note) && /admin audit/.test(note) && /in their activity as their own/.test(note), note);
  await waitRow(p, 'alice-notes.txt');
  check('as alice: her file is listed (names decrypted)', (await rowNames(p)).includes('alice-notes.txt'));
  check('as alice: no Drive key in the tab\'s storage (her KEKs are in the page\'s memory only)', (await stored(p)).length === 0, (await stored(p)).join(','));
  await rowOf(p, 'alice-notes.txt').locator('input[type="checkbox"]').check();
  const [dl] = await Promise.all([p.waitForEvent('download'), p.click('#drive-download')]);
  const f = path.join(OUT, 'alice-notes.txt');
  await dl.saveAs(f);
  check('as alice: download decrypts her file', readFileSync(f, 'utf8') === 'alice private notes\n');
  await rowOf(p, 'alice-notes.txt').locator('input[type="checkbox"]').uncheck();
  await p.setInputFiles('#drive-file-input', [{ name: 'from-admin.txt', mimeType: 'text/plain', buffer: Buffer.from('left by the admin\n') }]);
  await waitRow(p, 'from-admin.txt');
  check('as alice: upload works', true);
  await rowOf(p, 'from-admin.txt').locator('input[type="checkbox"]').check();
  await p.click('#drive-share');
  await p.waitForSelector('#drive-share-views');
  await p.click('.drive-dialog button:has-text("Create link")');
  await p.waitForSelector('#drive-share-url', { timeout: 60000 });
  const url = await p.textContent('#drive-share-url');
  check('as alice: share creates a link', /\/p\/f[A-Za-z0-9_-]+#/.test(url), url);
  await p.click('.drive-dialog button:has-text("Done")');
  // Her personal kit and the upgrade are hers alone.
  const kitTry = await api(p, '/api/private/drive/kit', { method: 'POST', body: JSON.stringify({ current: 'x'.repeat(43) }) });
  check('as alice: her personal kit is refused (impersonating)', kitTry.status === 403 && kitTry.body.error === 'impersonating', JSON.stringify(kitTry));
  const upTry = await api(p, '/api/private/drive/migrate', { method: 'PUT', body: JSON.stringify({ items: [] }) });
  check('as alice: the upgrade route is refused (impersonating)', upTry.status === 403 && upTry.body.error === 'impersonating', JSON.stringify(upTry));
  const oldKeys = await api(p, '/api/private/drive/keys', { method: 'PUT', body: JSON.stringify({ remove: [{ kind: 'pw', ref: 'pw' }] }) });
  check('as alice: the old key-wrap route is gone (405)', oldKeys.status === 405, String(oldKeys.status));
  // A reload asks the server for her keys again.
  await p.reload();
  await p.waitForSelector('#drive-app', { timeout: 60000 });
  await waitRow(p, 'from-admin.txt');
  check('as alice: a reload opens it again (the keys from the server)', true);

  // The recipient opens the owner's share of alice's file.
  const rc = await b.newContext({ reducedMotion: 'reduce' });
  const r = await rc.newPage();
  watch(r);
  await r.goto(url);
  // A limited share asks before spending its view.
  await r.waitForSelector('#view-files:not([hidden]), #reveal-burn:not([disabled])', { timeout: 60000 });
  if (await r.isVisible('#reveal-burn')) await r.click('#reveal-burn');
  await r.waitForSelector('#view-files:not([hidden])', { timeout: 60000 });
  check('recipient: the share opens and lists the file', /from-admin\.txt/.test(await r.textContent('#view-files')));
  await rc.close();

  await returnToAdmin(p);
  check('back as the owner: still no Drive key in the tab\'s storage', (await stored(p)).length === 0);

  // ── bob has never signed in: his Drive is there anyway (made on first need) ──
  await logInAs(p, 'bob');
  await openDrivePage(p);
  check('as bob (never signed in): his Drive opens at once', await p.isVisible('#drive-app'));
  await p.setInputFiles('#drive-file-input', [{ name: 'for-bob.txt', mimeType: 'text/plain', buffer: Buffer.from('waiting for bob\n') }]);
  await waitRow(p, 'for-bob.txt');
  await returnToAdmin(p);
  const bc = await b.newContext({ reducedMotion: 'reduce' });
  const bp = await bc.newPage();
  watch(bp);
  await login(bp, 'bob', BOB_PW);
  await openDrivePage(bp);
  await waitRow(bp, 'for-bob.txt');
  check('bob: his first sign-in opens the Drive with no prompt, the owner\'s file readable', await bp.isVisible('#drive-app'));
  const bobLog = (await api(bp, '/api/private/me/activity')).body.rows;
  check('bob: his activity shows the upload as his, with nothing of the owner\'s visit', bobLog.some((x) => x.action === 'drive.file_uploaded')
    && !bobLog.some((x) => /imperson|keys_used|escrow|acting as/i.test(`${x.action} ${x.detail}`)), bobLog.map((x) => x.action).join(','));
  await bc.close();

  // ── alice's activity lists what was done as her, as hers; the admin audit has the truth ──
  const aliceAfter = (await api(a, '/api/private/me/activity')).body.rows.filter((x) => !aliceBefore.includes(x.id));
  const newActs = new Set(aliceAfter.map((x) => x.action));
  check('alice: the Drive actions done as her are in her own activity', ['drive.file_read', 'drive.file_uploaded', 'share.created'].every((x) => newActs.has(x)), [...newActs].join(','));
  check('alice: with no trace of the impersonation (no start or end, no keys use, no actor)', !aliceAfter.some((x) => /imperson|keys_used|escrow|owner/i.test(`${x.action} ${x.detail}`) || 'actor' in x || 'imp' in x));
  await a.goto(`${BASE}/dashboard/account/`);
  await a.waitForSelector('#activity-body td');
  const seen = await a.textContent('#activity-body');
  check('alice: her activity view never mentions the impersonation or the keys use', !/imperson|keys_used|acting as/i.test(seen));
  await openDrivePage(a);
  await waitRow(a, 'from-admin.txt');
  check('alice: she sees the file the owner uploaded', (await rowNames(a)).includes('from-admin.txt'));
  const audit = (await api(p, `/api/private/admin/audit?user=${aliceId}`)).body.rows;
  const mine = audit.filter((x) => x.actor === 'owner');
  const acts = new Set(mine.map((x) => x.action));
  const want = ['impersonate.start', 'impersonate.end', 'drive.keys_used', 'drive.file_read', 'drive.file_uploaded', 'share.created'];
  check('admin audit: the owner as the real actor of each', want.every((x) => acts.has(x)), [...acts].join(','));
  check('admin audit: Drive rows marked as done acting as alice (the keys use as the owner\'s own)',
    mine.filter((x) => /^drive\.|^share\./.test(x.action)).every((x) => x.imp === 1 && x.adm === (x.action === 'drive.keys_used' ? 1 : 0)), JSON.stringify(mine.map((x) => [x.action, x.imp, x.adm])));
  const bobAudit = (await api(p, `/api/private/admin/audit?user=${bobId}`)).body.rows;
  check('admin audit: the owner\'s use of bob\'s keys and upload, as the owner', ['drive.keys_used', 'drive.file_uploaded'].every((x) => bobAudit.some((y) => y.actor === 'owner' && y.action === x)), bobAudit.map((x) => `${x.actor}:${x.action}`).join(','));
  await ac.close();
  await oc.close();
} catch (e) {
  check('no exception', false, e.message.split('\n').slice(0, 3).join(' / '));
} finally {
  check('no page errors or CSP / Trusted Types violations', errors.length === 0, errors.slice(0, 5).join(' | '));
  await b.close();
  const failed = results.filter((x) => !x).length;
  console.log(`\n${results.length - failed}/${results.length} passed`);
  process.exit(failed ? 1 : 0);
}
