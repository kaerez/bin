// drive-impersonate.mjs — e2e: the owner logs in as a user ("Log in as") and
// has that user's whole Drive, through the owner escrow (docs/DRIVE.md §3):
// opens it (the owner's own Drive key is in the tab), reads and downloads the
// user's file, uploads one, shares it (the recipient opens the link) and
// revokes nothing of theirs; the user's key sits in its own tab slot, never
// over the owner's, and goes when the impersonation ends. The user's own
// keys cannot be removed or replaced (the page says why). A user who has not
// signed in since the Drive was enabled has no Drive: the owner sees a notice
// and nothing is created; the user's first sign-in sets it up by itself
// (password and escrow wraps). The user's activity lists what was done as
// them, as their own, with no trace of the impersonation; the admin audit
// shows the owner as the real actor. Also: the notice when the owner's own
// Drive is not unlocked in the tab.
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
const api = (p, url, init = {}) => p.evaluate(async ([u, i]) => {
  const r = await fetch(u, { cache: 'no-store', ...i, headers: { 'content-type': 'application/json', 'x-secbin-intent': '1', ...(i.headers || {}) } });
  return { status: r.status, body: await r.json().catch(() => null) };
}, [url, init]);
const rowNames = (p) => p.$$eval('#drive-rows tr', (trs) => trs.map((tr) => tr.children[1].textContent.trim()));
// Names are shown as a bidi isolate with the extension in its own element (common.js nameEl).
const exact = (name) => new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`);
const rowOf = (p, name) => p.locator('#drive-rows tr', { has: p.locator('td:nth-child(2) bdi.fname', { hasText: exact(name) }) });
const hasRow = (n) => [...document.querySelectorAll('#drive-rows tr')].some((tr) => tr.children[1].textContent.trim() === n);
const waitRow = (p, n) => p.waitForFunction(hasRow, n, { timeout: 30000 });
const slots = (p) => p.evaluate(() => ({ dk: sessionStorage.getItem('secbin_dk'), uid: sessionStorage.getItem('secbin_dk_uid'), imp: sessionStorage.getItem('secbin_dk_imp'), impUid: sessionStorage.getItem('secbin_dk_imp_uid') }));
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
  await p.waitForSelector('#drive-app, #drive-unlock, #drive-impersonating, #drive-disabled', { timeout: 60000 });
};

try {
  // ── the owner: set up, signed in (their Drive and escrow key are made) ──
  const oc = await b.newContext({ acceptDownloads: true, reducedMotion: 'reduce' });
  const p = await oc.newPage();
  watch(p);
  await p.goto(`${BASE}/dashboard/setup/`);
  await p.fill('#setup-token', TOKEN); await p.fill('#setup-user', 'owner'); await p.fill('#setup-pass', PW); await p.fill('#setup-pass2', PW);
  await p.click('#setup-btn');
  await p.waitForFunction(() => /created/.test(document.querySelector('#setup-msg').textContent), null, { timeout: 30000 });
  await login(p, 'owner', PW);
  const ownerId = (await api(p, '/api/private/me')).body.user.id;
  const own = (await api(p, '/api/private/drive')).body;
  check('owner: Drive set up at sign-in, with the escrow key pair', own.wraps.some((w) => w.kind === 'pw') && !!own.escrowPub && typeof own.escrowPriv === 'string');
  const ownerSlot = (await slots(p)).dk;
  check('owner: the tab holds the owner\'s Drive key', !!ownerSlot && (await slots(p)).uid === ownerId);
  // Every account gets a Drive (the Default role).
  const lim = await api(p, '/api/private/admin/limits', { method: 'PATCH', body: JSON.stringify({ scope: 'global', channel: 'all', patch: { driveEnabled: true } }) });
  check('Default role: Drive on', lim.status === 200, JSON.stringify(lim.body));
  // alice: created with the owner's Drive unlocked in the tab, so her Drive is set up now (the owner knows her password).
  const createNote = async (name) => {
    await p.waitForFunction((n) => (document.querySelector('#user-create-drive')?.textContent || '').startsWith(`${n}:`), name, { timeout: 60000 });
    return p.textContent('#user-create-drive');
  };
  await createUser(p, 'alice', ALICE_PW);
  check('create alice: the form says her Drive is set up now', /alice: their Drive is set up now/.test(await createNote('alice')));
  // bob: created with the owner's Drive locked in the tab: his Drive waits for his first sign-in.
  const held = await p.evaluate(() => { const v = { dk: sessionStorage.getItem('secbin_dk'), uid: sessionStorage.getItem('secbin_dk_uid') }; sessionStorage.removeItem('secbin_dk'); sessionStorage.removeItem('secbin_dk_uid'); return v; });
  await createUser(p, 'bob', BOB_PW);
  check('create bob (the owner\'s Drive locked): the form says his Drive is set up at his first sign-in', /bob: their Drive is set up at their first sign-in \(your own Drive is not unlocked/.test(await createNote('bob')));
  await p.evaluate((v) => { sessionStorage.setItem('secbin_dk', v.dk); sessionStorage.setItem('secbin_dk_uid', v.uid); }, held);
  const users = (await api(p, '/api/private/admin/users')).body.users;
  const aliceId = users.find((x) => x.username === 'alice').id;
  const bobId = users.find((x) => x.username === 'bob').id;

  // ── alice uses her Drive (password + escrow wrap, pinned) ──
  const ac = await b.newContext({ acceptDownloads: true, reducedMotion: 'reduce' });
  const a = await ac.newPage();
  watch(a);
  await login(a, 'alice', ALICE_PW);
  await openDrivePage(a);
  check('alice: her Drive opens (unlocked at sign-in)', await a.isVisible('#drive-app'));
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
  const ast = (await api(a, '/api/private/drive')).body;
  check('alice: wraps pw + escrow, the escrow key pinned', ['escrow', 'pw'].every((k) => ast.wraps.some((w) => w.kind === k)) && !!ast.escrowPin);
  const aliceBefore = (await api(a, '/api/private/me/activity')).body.rows.map((r) => r.id);

  // ── the owner logs in as alice: her whole Drive ──
  await logInAs(p, 'alice');
  await openDrivePage(p);
  check('as alice: the Drive opens (no unlock prompt, no notice)', await p.isVisible('#drive-app') && await p.isHidden('#drive-unlock'));
  check('as alice: the page says it is her Drive opened with the escrow key', /alice’s Drive, opened with your escrow key/.test(await p.textContent('#drive-imp-note')));
  check('as alice: and why her own keys cannot be changed', /cannot be removed or replaced while you act as alice/.test(await p.textContent('#drive-imp-note')));
  await waitRow(p, 'alice-notes.txt');
  check('as alice: her file is listed (names decrypted)', (await rowNames(p)).includes('alice-notes.txt'));
  let s = await slots(p);
  check('as alice: the owner\'s key slot is untouched; alice\'s key in its own slot', s.dk === ownerSlot && s.uid === ownerId && !!s.imp && s.impUid === aliceId && s.imp !== ownerSlot);
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
  const keysTry = await api(p, '/api/private/drive/keys', { method: 'PUT', body: JSON.stringify({ remove: [{ kind: 'pw', ref: 'pw' }] }) });
  check('as alice: removing her password wrap is refused (impersonating)', keysTry.status === 403 && keysTry.body.error === 'impersonating');
  // A reload keeps using alice's key (no second escrow use needed).
  await p.reload();
  await p.waitForSelector('#drive-app', { timeout: 60000 });
  await waitRow(p, 'from-admin.txt');
  check('as alice: a reload opens it again from the tab', true);

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
  s = await slots(p);
  check('back as the owner: alice\'s key is gone from the tab, the owner\'s stays', !s.imp && !s.impUid && s.dk === ownerSlot);

  // ── bob has not signed in since the Drive was enabled: nothing is created ──
  await logInAs(p, 'bob');
  await openDrivePage(p);
  check('as bob: the notice says he has not signed in since the Drive was enabled',
    await p.isVisible('#drive-impersonating') && (await p.getAttribute('#drive-impersonating', 'data-reason')) === 'no_drive'
      && /The user hasn’t signed in since the Drive was enabled/.test(await p.textContent('#drive-impersonating')) && await p.isHidden('#drive-app'));
  const bst = (await api(p, '/api/private/drive')).body;
  check('as bob: nothing is created (no wraps, no salt)', bst.wraps.length === 0 && bst.driveSalt === null, JSON.stringify(bst.wraps));
  s = await slots(p);
  check('as bob: no key for bob in the tab', !s.imp && !s.impUid && s.dk === ownerSlot);
  await returnToAdmin(p);
  // His first sign-in sets it up by itself: password and escrow wraps, no prompt.
  const bc = await b.newContext({ reducedMotion: 'reduce' });
  const bp = await bc.newPage();
  watch(bp);
  await login(bp, 'bob', BOB_PW);
  const bst2 = (await api(bp, '/api/private/drive')).body;
  check('bob: his first sign-in set up his Drive (pw + escrow wraps, the escrow key pinned)', bst2.wraps.map((w) => w.kind).sort().join(',') === 'escrow,pw' && !!bst2.escrowPin && !('handoffKey' in bst2), JSON.stringify(bst2.wraps.map((w) => w.kind)));
  await openDrivePage(bp);
  check('bob: the Drive opens without a prompt', await bp.isVisible('#drive-app') && await bp.isHidden('#drive-unlock'));
  const bobLog = (await api(bp, '/api/private/me/activity')).body.rows;
  check('bob: his activity shows his own set-up and nothing of the owner\'s visit', bobLog.some((x) => x.action === 'drive.keys_changed')
    && !bobLog.some((x) => /imperson|escrow_used|acting as/i.test(`${x.action} ${x.detail}`)), bobLog.map((x) => x.action).join(','));
  await bc.close();
  // And now the owner opens it through the escrow.
  await logInAs(p, 'bob');
  await openDrivePage(p);
  check('as bob, after his sign-in: his Drive opens through the escrow', await p.isVisible('#drive-app'));
  await returnToAdmin(p);

  // ── the owner's own Drive locked in a fresh tab: a notice, not a prompt ──
  const lc = await b.newContext({ reducedMotion: 'reduce' });
  const l = await lc.newPage();
  watch(l);
  await login(l, 'owner', PW);
  await l.evaluate(() => { sessionStorage.removeItem('secbin_dk'); sessionStorage.removeItem('secbin_dk_uid'); });
  await logInAs(l, 'alice');
  await openDrivePage(l);
  check('owner Drive locked: the notice says to unlock it first', await l.isVisible('#drive-impersonating') && /Unlock your own Drive first/.test(await l.textContent('#drive-impersonating')) && await l.isHidden('#drive-unlock'));
  await returnToAdmin(l);
  await lc.close();

  // ── alice's activity lists what was done as her, as hers; the admin audit has the truth ──
  const aliceAfter = (await api(a, '/api/private/me/activity')).body.rows.filter((x) => !aliceBefore.includes(x.id));
  const newActs = new Set(aliceAfter.map((x) => x.action));
  check('alice: the Drive actions done as her are in her own activity', ['drive.file_read', 'drive.file_uploaded', 'share.created'].every((x) => newActs.has(x)), [...newActs].join(','));
  check('alice: with no trace of the impersonation (no start or end, no escrow use, no actor)', !aliceAfter.some((x) => /imperson|escrow|owner/i.test(`${x.action} ${x.detail}`) || 'actor' in x || 'imp' in x));
  await a.goto(`${BASE}/dashboard/account/`);
  await a.waitForSelector('#activity-body td');
  const seen = await a.textContent('#activity-body');
  check('alice: her activity view never mentions the impersonation or the owner\'s escrow use', !/imperson|escrow_used|acting as/i.test(seen));
  await openDrivePage(a);
  await waitRow(a, 'from-admin.txt');
  check('alice: she sees the file the owner uploaded', (await rowNames(a)).includes('from-admin.txt'));
  const audit = (await api(p, `/api/private/admin/audit?user=${aliceId}`)).body.rows;
  const mine = audit.filter((x) => x.actor === 'owner');
  const acts = new Set(mine.map((x) => x.action));
  const want = ['impersonate.start', 'impersonate.end', 'drive.escrow_used', 'drive.file_read', 'drive.file_uploaded', 'share.created'];
  check('admin audit: the owner as the real actor of each', want.every((x) => acts.has(x)), [...acts].join(','));
  check('admin audit: Drive rows marked as done acting as alice (the escrow use as the owner\'s own)',
    mine.filter((x) => /^drive\.|^share\./.test(x.action) && x.action !== 'drive.created_by_owner').every((x) => x.imp === 1 && x.adm === (x.action === 'drive.escrow_used' ? 1 : 0)));
  check('admin audit: alice\'s Drive set up by the owner at her creation (an admin action)', audit.some((x) => x.action === 'drive.created_by_owner' && x.adm === 1));
  const bobAudit = (await api(p, `/api/private/admin/audit?user=${bobId}`)).body.rows;
  check('admin audit: nothing was created in bob\'s Drive by the owner', !bobAudit.some((x) => x.actor === 'owner' && /^drive\./.test(x.action) && x.action !== 'drive.escrow_used'), bobAudit.map((x) => x.action).join(','));
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
