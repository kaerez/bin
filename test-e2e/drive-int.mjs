// drive-int.mjs — Dashboard → Drive end to end against the REAL server (shard A)
// and the real client (public/js/driveclient.js), with the key model v2
// (docs/DRIVE.md §3): the set-up page making the Drive keys, the Drive opening
// right after any sign-in (password, passkey, recovery code) with no prompt,
// the KEKs in the page's memory only (never in browser storage; a key planted
// there is ignored), the tree (collapsed by default, + expands, selecting shows the right pane,
// keyboard), upload (files, folder), new folder, rename, move, delete,
// download (file, folder zip), Share… with the link, the recipient's view of a
// drive share, an item's shares with revoke, the disabled notice for a role
// without a Drive, the mobile tree toggle, no names or contents on the wire, CSP
// cleanliness and axe (WCAG 2.2 A/AA) on every state in both themes.
// A manual test, not run in CI: see test-e2e/README.md. Needs a fresh
// `wrangler dev` (no owner yet), playwright-core and axe-core, a Chromium and
// `unzip`. Usage (localhost, not an IP: the passkey steps need an RP ID):
//   WT=<repo checkout> BASE=http://localhost:8787 [CHROMIUM=<path>] node test-e2e/drive-int.mjs
import { chromium } from 'playwright-core';
import { readFileSync, mkdirSync, writeFileSync, mkdtempSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';

const require = createRequire(import.meta.url);
const AXE = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const BASE = process.env.BASE;
const WT = process.env.WT;
if (!BASE || !WT) { console.error('usage: WT=<repo checkout> BASE=http://localhost:8787 node test-e2e/drive-int.mjs'); process.exit(2); }
const TOKEN = /^AUTHN=(.*)$/m.exec(readFileSync(path.join(WT, '.dev.vars'), 'utf8'))[1].trim();
const OUT = process.env.OUT || mkdtempSync(path.join(os.tmpdir(), 'secbin-drive-int-'));
mkdirSync(OUT, { recursive: true });
// A folder to upload: tree/{readme.md, doc.pdf, empty/, sub/{blob.bin, pic.png}}.
const TREE = path.join(OUT, 'tree');
mkdirSync(path.join(TREE, 'sub'), { recursive: true });
mkdirSync(path.join(TREE, 'empty'), { recursive: true });
writeFileSync(path.join(TREE, 'readme.md'), '# Tree\nhello\n');
writeFileSync(path.join(TREE, 'doc.pdf'), '%PDF-1.4\n%%EOF\n');
writeFileSync(path.join(TREE, 'sub', 'blob.bin'), Buffer.alloc(300000, 3));
writeFileSync(path.join(TREE, 'sub', 'pic.png'), Buffer.from('89504e470d0a1a0a', 'hex'));
const PW = 'owner-password-123';
const ALICE_PW = 'alice-password-123';
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22a', 'wcag22aa'];
const results = [];
const check = (n, ok, x = '') => { results.push(!!ok); console.log(`${ok ? 'PASS' : 'FAIL'} ${n}${x ? ' — ' + x : ''}`); };
const info = (n) => console.log(`INFO ${n}`);
const b = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
const errors = [];
const wire = []; // request bodies sent to the Drive API (must never hold names, contents or secrets)
const watch = (p) => {
  p.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  p.on('console', (m) => { if (m.type() === 'error' && !/status of (40[134]|409|410|429)/.test(m.text())) errors.push(`console: ${m.text()}`); });
  p.on('request', (r) => { if (/\/api\/private\/drive/.test(r.url())) { const d = r.postDataBuffer(); if (d) wire.push(d.toString('latin1')); } });
  // Every Drive change (the chunk uploads included) with the session's CSRF token (src/lib/csrf.js).
  p.on('response', (r) => {
    const q = r.request();
    if (!/\/api\/private\/(admin\/)?drive(\/|$|\?)/.test(new URL(r.url()).pathname + '/') || q.method() === 'GET') return;
    changes.push({ what: `${q.method()} ${new URL(r.url()).pathname}`, token: /^[A-Za-z0-9_-]{43}$/.test(q.headers()['x-secbin-csrf'] || ''), status: r.status() });
  });
};
const changes = []; // the Drive's state-changing requests: { what, token, status }
const axeFails = [];
async function audit(p, label) {
  await p.evaluate(AXE);
  const v = await p.evaluate(async (tags) => {
    // eslint-disable-next-line no-undef
    const r = await axe.run(document, { runOnly: { type: 'tag', values: tags }, resultTypes: ['violations'] });
    return r.violations.map((x) => `${x.id} (${x.impact}): ${x.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')}`);
  }, TAGS);
  if (v.length) axeFails.push(`${label}: ${v.join('; ')}`);
  check(`axe: ${label}`, v.length === 0, v.join('; '));
}
const rowNames = (p) => p.$$eval('#drive-rows tr', (trs) => trs.map((tr) => tr.children[1].textContent.trim()));
// A name is shown as a bidi isolate with its extension in its own element
// (common.js nameEl), so it is matched by its whole text, exactly.
const exact = (name) => new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`);
const treeItem = (p, name) => p.locator('#drive-tree-pane .tree-item', { has: p.locator(':scope > .tree-label .tree-text', { hasText: exact(name) }) });
const rowOf = (p, name) => p.locator('#drive-rows tr', { has: p.locator('td:nth-child(2) bdi.fname', { hasText: exact(name) }) });
const selectRow = async (p, name) => { await rowOf(p, name).locator('input[type="checkbox"]').check(); };
const waitRows = (p, fn, arg) => p.waitForFunction(fn, arg, { timeout: 30000 });
const hasRow = (n) => [...document.querySelectorAll('#drive-rows tr')].some((tr) => tr.children[1].textContent.trim() === n);
const titleIs = (n) => document.querySelector('#drive-pane-title').textContent === n;
const driveState = (p) => p.evaluate(async () => (await fetch('/api/private/drive', { cache: 'no-store' })).json());
// Every key the tab's storage holds (the KEKs must never be there).
const stored = (p) => p.evaluate(() => [...Object.keys(sessionStorage), ...Object.keys(localStorage)].filter((k) => /^secbin_(kek|dk)/.test(k)));

async function mkdirUI(p, name) {
  await p.click('#drive-mkdir');
  await p.waitForSelector('.drive-dialog input');
  await p.fill('.drive-dialog input', name);
  await p.keyboard.press('Enter');
  await waitRows(p, hasRow, name);
}
async function openUI(p, name) {
  await rowOf(p, name).locator('button.drive-open').click();
  await waitRows(p, titleIs, name);
}
async function uploadUI(p, name, content, mimeType = 'text/plain') {
  await p.setInputFiles('#drive-file-input', [{ name, mimeType, buffer: Buffer.isBuffer(content) ? content : Buffer.from(content) }]);
  await waitRows(p, hasRow, name);
}
async function login(p, user, pw) {
  await p.goto(`${BASE}/dashboard/login/`);
  await p.fill('#login-user', user); await p.fill('#login-pass', pw); await p.click('#login-btn');
  await p.waitForURL(/\/dashboard\/(\?.*)?$/, { timeout: 60000 });
  await p.waitForSelector('#dash-nav:not([hidden])');
}

let codes;
let st;
try {
  // ── the set-up makes the Drive keys; the owner signs in ─────────────────
  const ctx = await b.newContext({ acceptDownloads: true, reducedMotion: 'reduce', viewport: { width: 1280, height: 900 } });
  await ctx.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: BASE });
  const p = await ctx.newPage();
  watch(p);
  const cdp = await ctx.newCDPSession(p);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true },
  });
  await p.goto(`${BASE}/dashboard/setup/`);
  await p.fill('#setup-token', TOKEN); await p.fill('#setup-user', 'owner'); await p.fill('#setup-pass', PW); await p.fill('#setup-pass2', PW);
  // The Drive keys the server proposes: generated, then "Use these" (the release before has no such step).
  if (await p.$('#setup-keys-gen')) { await p.click('#setup-keys-gen'); await p.click('#setup-keys-use'); }
  await p.click('#setup-btn');
  await p.waitForFunction(() => /created/.test(document.querySelector('#setup-msg').textContent), null, { timeout: 30000 });
  check('set-up: the Drive keys were made; the page says to download the key kit', /Drive keys were created.*key kit/.test(await p.textContent('#setup-msg')));
  await login(p, 'owner', PW);
  check('sign-in: no Drive key in the tab\'s storage', (await stored(p)).length === 0, (await stored(p)).join(','));
  st = await driveState(p);
  check('drive state: a current sub-MEK, and no key, wrap or salt', st.enabled === true && /^m[A-Za-z0-9_-]{11}$/.test(st.current || '') && ['wraps', 'driveSalt', 'escrowPub', 'escrowPriv', 'kcv', 'keys'].every((k) => st[k] === undefined), JSON.stringify(Object.keys(st)));
  check('nav: the owner sees the Drive link (caps.driveEnabled)', await p.isVisible('#nav-drive'));

  // A user whose role (Default) has no Drive.
  await p.goto(`${BASE}/dashboard/admin/`);
  await p.click('.tab[data-tab="users"]');
  const u = p.locator('.admin-panel[data-panel="users"]');
  await u.locator('input[aria-label="New username"]').first().fill('alice');
  await u.locator('input[aria-label="New user password"]').first().fill(ALICE_PW);
  await u.locator('input[aria-label="Repeat password"]').first().fill(ALICE_PW);
  await u.locator('button:has-text("Create user")').first().click();
  await p.waitForFunction(() => document.getElementById('toast').textContent === 'User created.', null, { timeout: 30000 });

  // A passkey and recovery codes: the Drive does not depend on them (nothing about the Drive changes).
  await p.goto(`${BASE}/dashboard/account/`);
  await p.waitForSelector('#passkeys-body td');
  await p.fill('#passkey-current', PW);
  await p.fill('#passkey-name', 'Virtual laptop');
  await p.click('#passkey-add');
  await p.waitForSelector('#recovery-new:not([hidden])', { timeout: 60000 });
  codes = await p.$$eval('#recovery-list li', (l) => l.map((x) => x.textContent));
  check('account: 20 recovery codes', codes.length === 20, String(codes.length));
  const st0 = await driveState(p);
  check('account: the Drive keeps no wrap for a passkey or the codes', st0.wraps === undefined && st0.current === st.current);

  // ── any sign-in (a passkey, a recovery code): the Drive opens with no prompt ──
  // Signing out is a change: the session's CSRF token too, as the page's own client sends it (api.js).
  const logout = () => p.evaluate(() => fetch('/api/auth/logout', { method: 'POST', headers: { 'x-secbin-intent': '1', 'x-secbin-csrf': (document.cookie.match(/(?:^|;\s*)__Host-secbin_csrf=([^;]+)/) || [])[1] || '' } }));
  const opensWithNoPrompt = async (label) => {
    await p.goto(`${BASE}/dashboard/drive/`);
    await p.waitForSelector('#drive-app, #drive-unavailable, #drive-disabled', { timeout: 30000 });
    check(`${label}: the Drive opens with no prompt`, await p.isVisible('#drive-app') && await p.isHidden('input[type="password"]'));
    check(`${label}: no Drive key in the tab's storage`, (await stored(p)).length === 0, (await stored(p)).join(','));
  };
  await logout();
  await p.goto(`${BASE}/dashboard/login/`);
  await p.click('#passkey-btn');
  await p.waitForURL(`${BASE}/dashboard/`, { timeout: 60000 });
  await opensWithNoPrompt('sign-in with a passkey alone');
  await logout();
  await p.goto(`${BASE}/dashboard/login/`);
  await p.click('#recovery-toggle');
  await p.fill('#login-user', 'owner'); await p.fill('#login-code', codes[1]); await p.click('#login-btn');
  await p.waitForURL(/\/dashboard\/account\/\?recovery=19/, { timeout: 60000 });
  await opensWithNoPrompt('sign-in with a recovery code');

  // ── the Drive page in the same tab: no prompt ──
  await p.goto(`${BASE}/dashboard/drive/`);
  await p.waitForSelector('#drive-app', { timeout: 30000 });
  check('drive: open (no set-up, unlock or recovery screen)', await p.isVisible('#drive-app') && (await p.$('#drive-unlock')) === null);
  check('drive: the page says the Drive is not end-to-end encrypted', /not end-to-end encrypted/.test(await p.textContent('main')));
  check('nav: Drive link current on the Drive page', (await p.getAttribute('#nav-drive', 'aria-current')) === 'page');
  await waitRows(p, () => !document.getElementById('drive-empty').hidden);
  check('drive: a new Drive is empty', true);
  await audit(p, 'drive (empty)');

  // Content through the page itself.
  await mkdirUI(p, 'Documents'); await mkdirUI(p, 'Photos'); await mkdirUI(p, 'Empty');
  await uploadUI(p, 'readme.txt', 'Welcome to the Drive.\n');
  await openUI(p, 'Documents'); await mkdirUI(p, 'Reports'); await uploadUI(p, 'notes.md', '# Notes\nhello\n', 'text/markdown');
  await openUI(p, 'Reports'); await mkdirUI(p, 'Archive'); await uploadUI(p, 'q1.txt', 'Q1 numbers\n');
  await p.click('#drive-pane .crumbs button:has-text("My Drive")');
  await waitRows(p, titleIs, 'My Drive');
  await openUI(p, 'Photos'); await uploadUI(p, 'cat.png', Buffer.alloc(2048), 'image/png');
  await p.goto(`${BASE}/dashboard/drive/`);
  await p.waitForSelector('#drive-app');

  // ── tree: collapsed by default, right pane ────────────────────────────
  await waitRows(p, () => document.querySelectorAll('#drive-rows tr').length >= 4);
  check('pane: the root folder\'s content', JSON.stringify(await rowNames(p)) === JSON.stringify(['Documents', 'Empty', 'Photos', 'readme.txt']), (await rowNames(p)).join(','));
  const treeInfo = await p.$$eval('#drive-tree-pane .tree-item', (lis) => lis.map((li) => ({ name: li.querySelector('.tree-text').textContent, exp: li.getAttribute('aria-expanded'), vis: !li.parentElement.closest('.tree-group[hidden]') })));
  check('tree: root open, every folder under it closed', treeInfo[0].exp === 'true' && treeInfo.slice(1).every((t) => t.exp !== 'true'), JSON.stringify(treeInfo));
  check('tree: only top-level folders visible (no files, no sub-folders)', treeInfo.filter((t) => t.vis).map((t) => t.name).join(',') === 'My Drive,Documents,Empty,Photos');
  check('tree: role=tree, named', (await p.getAttribute('#drive-tree-pane [role="tree"]', 'aria-label')) === 'Drive folders');
  check('tree: exactly one tab stop', (await p.$$eval('#drive-tree-pane .tree-item', (l) => l.filter((x) => x.tabIndex === 0).length)) === 1);
  await audit(p, 'drive (root)');
  await treeItem(p, 'Documents').locator(':scope > .tree-label .tree-twisty').click();
  await p.waitForFunction(() => [...document.querySelectorAll('#drive-tree-pane .tree-text')].some((t) => t.textContent === 'Reports' && t.closest('.tree-item').parentElement.closest('.tree-item').getAttribute('aria-expanded') === 'true'));
  check('tree: + expands Documents (aria-expanded, − shown)', (await treeItem(p, 'Documents').getAttribute('aria-expanded')) === 'true' && (await treeItem(p, 'Documents').locator(':scope > .tree-label .tree-twisty').textContent()) === '−');
  check('tree: + does not change the right pane', (await rowNames(p)).includes('readme.txt'));
  await treeItem(p, 'Documents').locator(':scope > .tree-label .tree-twisty').click();
  check('tree: − collapses', (await treeItem(p, 'Documents').getAttribute('aria-expanded')) === 'false');
  await treeItem(p, 'Photos').locator(':scope > .tree-label .tree-text').click();
  await waitRows(p, titleIs, 'Photos');
  check('tree: selecting Photos shows its content on the right', JSON.stringify(await rowNames(p)) === '["cat.png"]' && (await treeItem(p, 'Photos').getAttribute('aria-selected')) === 'true');
  check('pane: breadcrumb My Drive / Photos', (await p.$$eval('#drive-pane .crumbs .crumb', (c) => c.map((x) => x.textContent))).join('/') === 'My Drive/Photos');
  await p.keyboard.press('ArrowUp');
  await p.keyboard.press('Enter');
  await waitRows(p, titleIs, 'Empty');
  check('keyboard: ↑ + Enter selects Empty; empty-folder message', await p.isVisible('#drive-empty'));
  await p.keyboard.press('ArrowUp');
  await p.keyboard.press('ArrowRight');
  await p.waitForFunction(() => document.activeElement.getAttribute('aria-expanded') === 'true');
  await p.keyboard.press('ArrowDown');
  const f1 = await p.evaluate(() => document.activeElement.querySelector('.tree-text').textContent);
  await p.keyboard.press(' ');
  await waitRows(p, titleIs, 'Reports');
  check('keyboard: → expands, ↓ moves into it, Space selects Reports', f1 === 'Reports' && JSON.stringify(await rowNames(p)) === '["Archive","q1.txt"]', f1);
  await p.keyboard.press('Home');
  check('keyboard: Home → My Drive', await p.evaluate(() => document.activeElement.querySelector('.tree-text').textContent === 'My Drive'));
  await p.click('#drive-pane .crumbs button:has-text("Documents")');
  await waitRows(p, titleIs, 'Documents');
  check('pane: breadcrumb back to Documents', JSON.stringify(await rowNames(p)) === '["Reports","notes.md"]');

  // ── upload ────────────────────────────────────────────────────────────
  await p.setInputFiles('#drive-file-input', [{ name: 'hello.txt', mimeType: 'text/plain', buffer: Buffer.from('hello drive\n') }, { name: 'two.bin', mimeType: 'application/octet-stream', buffer: Buffer.alloc(9000, 7) }]);
  await waitRows(p, hasRow, 'two.bin');
  check('upload files: both appear in the open folder', (await rowNames(p)).includes('hello.txt') && (await rowNames(p)).includes('two.bin'));
  check('upload: progress bar reports done', /done/.test(await p.textContent('.drive-transfer .progress-label')));
  await p.setInputFiles('#drive-file-input', [{ name: 'hello.txt', mimeType: 'text/plain', buffer: Buffer.from('hello again\n') }]);
  await waitRows(p, hasRow, 'hello (2).txt');
  check('upload: a name already in the folder gets " (2)"', (await rowNames(p)).filter((n) => n.startsWith('hello')).join(',') === 'hello (2).txt,hello.txt', (await rowNames(p)).join(','));
  await p.setInputFiles('#drive-folder-input', TREE);
  await waitRows(p, () => [...document.querySelectorAll('#drive-rows tr')].some((tr) => tr.dataset.kind === 'dir' && tr.textContent.includes('tree')));
  check('upload folder: the folder appears', true);
  await openUI(p, 'tree');
  const inTree = await rowNames(p);
  check('upload folder: tree/ holds sub, doc.pdf, readme.md', ['sub', 'doc.pdf', 'readme.md'].every((n) => inTree.includes(n)), inTree.join(','));
  check('tree: the opened folder is revealed and selected in the tree', (await treeItem(p, 'tree').getAttribute('aria-selected')) === 'true');
  await p.click('#drive-pane .crumbs button:has-text("Documents")');
  await waitRows(p, titleIs, 'Documents');
  const capText = await p.textContent('#drive-cap-text');
  check('capacity: "of … used" with the meter, or "no limit" (the owner) without it',
    (/of .* used/.test(capText) && await p.isVisible('#drive-cap-meter')) || (/used · no limit/.test(capText) && await p.isHidden('#drive-cap-meter')), capText);

  // ── new folder, rename ────────────────────────────────────────────────
  await p.click('#drive-mkdir');
  await p.waitForSelector('.drive-dialog [role="dialog"]');
  check('new folder: a named modal dialog with focus in the field', (await p.evaluate(() => { const d = document.querySelector('.drive-dialog [role="dialog"]'); return d.getAttribute('aria-modal') === 'true' && document.getElementById(d.getAttribute('aria-labelledby')).textContent === 'New folder' && d.contains(document.activeElement) && document.activeElement.tagName === 'INPUT'; })));
  check('dialog: the page behind is inert', await p.evaluate(() => document.getElementById('main').inert === true));
  await audit(p, 'dialog: new folder');
  await p.keyboard.type('bad/name');
  await p.keyboard.press('Enter');
  check('new folder: a name with / is refused', /cannot contain/.test(await p.textContent('.drive-dialog .modal-msg')));
  await p.fill('.drive-dialog input', 'Reports');
  await p.keyboard.press('Enter');
  await p.waitForFunction(() => /already exists/.test(document.querySelector('.drive-dialog .modal-msg').textContent));
  check('new folder: a duplicate name is refused', true);
  await p.fill('.drive-dialog input', 'New stuff');
  await p.keyboard.press('Enter');
  await waitRows(p, hasRow, 'New stuff');
  check('new folder: created, dialog closed, focus back on the button', await p.isHidden('.drive-dialog') && await p.evaluate(() => document.activeElement.id === 'drive-mkdir') && await p.evaluate(() => !document.getElementById('main').inert));
  check('new folder: it shows in the tree too', await treeItem(p, 'New stuff').count() === 1);
  check('toolbar: Rename/Move/Delete/Share disabled with nothing selected', await p.isDisabled('#drive-rename') && await p.isDisabled('#drive-move') && await p.isDisabled('#drive-del') && await p.isDisabled('#drive-share'));
  await selectRow(p, 'New stuff');
  check('toolbar: enabled for one selection; Download names the zip', await p.isEnabled('#drive-rename') && (await p.textContent('#drive-download')) === 'Download (.zip)');
  await p.click('#drive-rename');
  await p.waitForSelector('.drive-dialog input');
  await p.fill('.drive-dialog input', 'Renamed stuff');
  await p.keyboard.press('Enter');
  await waitRows(p, hasRow, 'Renamed stuff');
  check('rename: the new name in the pane and the tree', !(await rowNames(p)).includes('New stuff') && await treeItem(p, 'Renamed stuff').count() === 1);

  // ── move ──────────────────────────────────────────────────────────────
  await selectRow(p, 'Renamed stuff');
  await p.click('#drive-move');
  await p.waitForSelector('.drive-dialog .drive-picker [role="tree"]');
  await p.waitForFunction(() => document.querySelectorAll('.drive-picker .tree-item').length >= 4);
  const pickNames = await p.$$eval('.drive-picker .tree-item', (l) => l.filter((x) => !x.parentElement.closest('.tree-group[hidden]')).map((x) => x.querySelector('.tree-text').textContent));
  check('move: picker tree collapsed by default (root open)', pickNames.join(',') === 'My Drive,Documents,Empty,Photos', pickNames.join(','));
  await audit(p, 'dialog: move');
  await p.locator('.drive-picker .tree-item', { has: p.locator(':scope > .tree-label .tree-text', { hasText: exact('Documents') }) }).locator(':scope > .tree-label .tree-twisty').click();
  await p.waitForFunction(() => [...document.querySelectorAll('.drive-picker .tree-text')].some((t) => t.textContent === 'Reports'));
  check('move: the folder being moved is not a target', !(await p.$$eval('.drive-picker .tree-text', (l) => l.map((x) => x.textContent))).includes('Renamed stuff'));
  await p.locator('.drive-picker .tree-text', { hasText: exact('Photos') }).click();
  check('move: target shown', /Move to: My Drive \/ Photos/.test(await p.textContent('#drive-move-target')));
  await p.click('.drive-dialog button:has-text("Move here")');
  await waitRows(p, (n) => ![...document.querySelectorAll('#drive-rows tr')].some((tr) => tr.children[1].textContent.trim() === n), 'Renamed stuff');
  check('move: gone from Documents', true);
  await treeItem(p, 'Photos').locator(':scope > .tree-label .tree-text').click();
  await waitRows(p, () => document.querySelector('#drive-pane-title').textContent === 'Photos' && [...document.querySelectorAll('#drive-rows tr')].some((tr) => tr.textContent.includes('Renamed stuff')));
  check('move: now in Photos', true);

  // ── delete ────────────────────────────────────────────────────────────
  await selectRow(p, 'Renamed stuff');
  await p.click('#drive-del');
  await p.waitForSelector('#drive-delete-confirm');
  check('delete: confirm dialog names the item and focuses Cancel', /Delete “Renamed stuff”\?/.test(await p.textContent('.drive-dialog .modal-title')) && await p.evaluate(() => document.activeElement.textContent === 'Cancel'));
  await audit(p, 'dialog: delete');
  await p.keyboard.press('Escape');
  check('delete: Escape cancels', await p.isHidden('.drive-dialog') && (await rowNames(p)).includes('Renamed stuff'));
  await p.click('#drive-del');
  await p.click('#drive-delete-confirm');
  await waitRows(p, (n) => ![...document.querySelectorAll('#drive-rows tr')].some((tr) => tr.children[1].textContent.trim() === n), 'Renamed stuff');
  check('delete: removed from the pane and the tree', await treeItem(p, 'Renamed stuff').count() === 0);

  // ── download ──────────────────────────────────────────────────────────
  await treeItem(p, 'My Drive').locator(':scope > .tree-label .tree-text').click();
  await waitRows(p, titleIs, 'My Drive');
  await selectRow(p, 'readme.txt');
  const [dl1] = await Promise.all([p.waitForEvent('download'), p.click('#drive-download')]);
  const f = path.join(OUT, 'readme.txt');
  await dl1.saveAs(f);
  check('download: a file, decrypted in the browser', readFileSync(f, 'utf8') === 'Welcome to the Drive.\n' && dl1.suggestedFilename() === 'readme.txt');
  await rowOf(p, 'readme.txt').locator('input[type="checkbox"]').uncheck();
  await selectRow(p, 'Documents');
  const [dl2] = await Promise.all([p.waitForEvent('download'), p.click('#drive-download')]);
  const z = path.join(OUT, 'Documents.zip');
  await dl2.saveAs(z);
  const zl = execFileSync('unzip', ['-Z1', z]).toString().trim().split('\n').sort();
  check('download: a folder as .zip with its tree', ['Reports/', 'Reports/q1.txt', 'notes.md', 'tree/sub/'].every((n) => zl.includes(n)), zl.join(','));
  check('download: the zip holds the right bytes', execFileSync('unzip', ['-p', z, 'Reports/q1.txt']).toString() === 'Q1 numbers\n');
  await rowOf(p, 'Documents').locator('input[type="checkbox"]').uncheck();

  // ── share ─────────────────────────────────────────────────────────────
  await openUI(p, 'Documents');
  await selectRow(p, 'notes.md');
  await p.click('#drive-share');
  await p.waitForSelector('#drive-share-views');
  check('share: the composer\'s options (views, ∞, expiry, password, label)', await p.isVisible('#drive-share-unlimited') && await p.isVisible('#drive-share-expire') && await p.isVisible('#drive-share-unit') && await p.isVisible('#drive-share-pw-on') && await p.isVisible('#drive-share-label'));
  check('share: label carries the "not encrypted" hint', /drive-share-label-hint/.test(await p.getAttribute('#drive-share-label', 'aria-describedby')));
  await audit(p, 'dialog: share');
  await p.fill('#drive-share-views', '0');
  await p.click('.drive-dialog button:has-text("Create link")');
  check('share: invalid views refused', /Views must be/.test(await p.textContent('.drive-dialog .modal-msg')) && (await p.getAttribute('#drive-share-views', 'aria-invalid')) === 'true');
  await p.fill('#drive-share-views', '3');
  await p.check('#drive-share-pw-on');
  await p.fill('#drive-share-pw', 'pw-one');
  await p.fill('#drive-share-pw2', 'pw-two');
  await p.click('.drive-dialog button:has-text("Create link")');
  check('share: mismatched passwords refused', /do not match/.test(await p.textContent('.drive-dialog .modal-msg')));
  await p.fill('#drive-share-pw2', 'pw-one');
  await p.fill('#drive-share-label', 'for Alice');
  await p.click('.drive-dialog button:has-text("Create link")');
  await p.waitForSelector('#drive-share-url', { timeout: 60000 });
  const url = await p.textContent('#drive-share-url');
  check('share: the link is shown', /\/p\/f[A-Za-z0-9_-]+#/.test(url), url);
  check('share: note says 3 views', /up to 3 times/.test(await p.textContent('.drive-dialog .modal-sub')));
  await p.click('#drive-share-copy');
  await p.waitForFunction(() => document.querySelector('#drive-share-copy').textContent === 'copied');
  check('share: copy link (clipboard write succeeded)', (await p.textContent('#drive-share-copy')) === 'copied');
  check('share: QR code', await p.isVisible('.drive-qr img'));
  await audit(p, 'dialog: share link');
  await p.click('.drive-dialog button:has-text("Done")');
  check('share: Done closes', await p.isHidden('.drive-dialog'));

  // ── the recipient opens the drive share (manifest v3, per-file keys) ──
  const r = await (await b.newContext({ reducedMotion: 'reduce', acceptDownloads: true })).newPage();
  watch(r);
  await r.goto(url);
  await r.waitForSelector('#view-password:not([hidden])', { timeout: 30000 });
  await r.fill('#decrypt-password', 'pw-one');
  await r.click('#decrypt-btn');
  await r.waitForSelector('#view-files:not([hidden])', { timeout: 60000 });
  check('recipient: the drive share opens with its password and lists notes.md', /notes\.md/.test(await r.textContent('#view-files')));
  await audit(r, 'recipient (drive share)');

  // ── an item's shares, revoke ──────────────────────────────────────────
  await rowOf(p, 'notes.md').locator('button:has-text("Shares")').click();
  await p.waitForSelector('#drive-shares-table');
  const shareRow = p.locator('#drive-shares-table tbody tr').first();
  check('shares: lists the new share', /for Alice/.test(await shareRow.textContent()) && /active/.test(await shareRow.textContent()) && /drive/.test(await shareRow.textContent()));
  await audit(p, 'dialog: shares');
  await shareRow.locator('button:has-text("Revoke")').click();
  check('shares: revoke is two-step', /irreversible/.test(await shareRow.locator('button.danger').textContent()));
  await shareRow.locator('button.danger').click();
  await p.waitForFunction(() => /revoked/.test(document.querySelector('#drive-shares-table tbody tr').textContent));
  check('shares: revoked', true);
  await p.keyboard.press('Escape');
  check('shares: revoking keeps the file', (await rowNames(p)).includes('notes.md'));
  await rowOf(p, 'Reports').locator('button:has-text("Shares")').click();
  await p.waitForSelector('#drive-shares-empty');
  check('shares: an item without shares says so', true);
  await p.keyboard.press('Escape');
  check('shares: focus back on the Shares button', await p.evaluate(() => /Shares of Reports/.test(document.activeElement.getAttribute('aria-label') || '')));
  const r2 = await (await b.newContext({ reducedMotion: 'reduce' })).newPage();
  await r2.goto(url);
  await r2.waitForSelector('#view-status:not([hidden])', { timeout: 30000 });
  check('recipient: a revoked drive share is gone', true);
  await r2.context().close();
  await r.context().close();

  // ── light theme, mobile ───────────────────────────────────────────────
  await p.evaluate(() => { document.documentElement.classList.remove('dark'); });
  await audit(p, 'drive (light)');
  await p.setViewportSize({ width: 390, height: 844 });
  await p.evaluate(() => { document.documentElement.classList.add('dark'); });
  await p.waitForTimeout(200);
  check('mobile: tree collapses into a Folders toggle', await p.isVisible('#drive-tree-toggle') && await p.isHidden('#drive-tree-pane') && (await p.getAttribute('#drive-tree-toggle', 'aria-expanded')) === 'false');
  await audit(p, 'drive (phone)');
  await p.click('#drive-tree-toggle');
  check('mobile: the toggle shows the tree', await p.isVisible('#drive-tree-pane') && (await p.getAttribute('#drive-tree-toggle', 'aria-expanded')) === 'true');
  check('mobile: no horizontal scroll at 390 px', !(await p.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1)));
  await p.setViewportSize({ width: 320, height: 700 });
  check('mobile: no horizontal scroll at 320 px', !(await p.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1)));
  await audit(p, 'drive (320px, tree open)');
  await p.screenshot({ path: path.join(OUT, 'drive-phone.png'), fullPage: true });
  await p.setViewportSize({ width: 1280, height: 900 });
  await p.screenshot({ path: path.join(OUT, 'drive-desktop.png'), fullPage: true });

  // ── reload and a new tab: the keys come from the server each time; a planted key is ignored ──
  await p.reload();
  await p.waitForSelector('#drive-app');
  check('reload: open again (no prompt), nothing in the tab\'s storage', await p.isVisible('#drive-app') && (await stored(p)).length === 0);
  const state = await ctx.storageState();
  const p2ctx = await b.newContext({ storageState: state, reducedMotion: 'reduce' });
  // Any script on the origin could write these slots: a KEK of its own, and an old Drive key.
  const junk = Buffer.alloc(32, 9).toString('base64url');
  const me = await p.evaluate(async () => (await (await fetch('/api/private/me', { cache: 'no-store' })).json()).user.id);
  await p2ctx.addInitScript(([uid, cur, k]) => {
    if (sessionStorage.getItem('planted')) return;
    sessionStorage.setItem('planted', '1');
    const slot = JSON.stringify({ u: uid, c: cur, k: { [cur]: k } });
    sessionStorage.setItem('secbin_kek', slot);
    sessionStorage.setItem('secbin_kek_imp', slot);
    sessionStorage.setItem('secbin_dk', k);
    sessionStorage.setItem('secbin_dk_uid', uid);
    localStorage.setItem('secbin_kek', slot);
  }, [me, st.current, junk]);
  const p2 = await p2ctx.newPage();
  watch(p2);
  await p2.goto(`${BASE}/dashboard/drive/`);
  await p2.waitForSelector('#drive-app', { timeout: 30000 });
  await waitRows(p2, hasRow, 'Documents');
  check('new tab with keys planted in storage: the Drive opens with the server\'s keys (names decrypt)', true);
  check('new tab: the planted KEK slots are removed', await p2.evaluate(() => ['secbin_kek', 'secbin_kek_imp'].every((k) => sessionStorage.getItem(k) === null)));
  await mkdirUI(p2, 'Made after a plant');
  await p2ctx.close();
  // A clean tab reads what the planted tab made: it was sealed under the server's KEK, not the planted one.
  const p3 = await (await b.newContext({ storageState: state, reducedMotion: 'reduce' })).newPage();
  watch(p3);
  await p3.goto(`${BASE}/dashboard/drive/`);
  await p3.waitForSelector('#drive-app', { timeout: 30000 });
  await waitRows(p3, hasRow, 'Made after a plant');
  check('a clean tab opens the folder the planted tab made (sealed under the server\'s KEK)', true);
  await p3.context().close();

  // ── a role without a Drive ────────────────────────────────────────────
  const a = await (await b.newContext({ reducedMotion: 'reduce' })).newPage();
  watch(a);
  await login(a, 'alice', ALICE_PW);
  check('nav: no Drive link when the role has none', await a.isHidden('#nav-drive'));
  check('sign-in: no Drive key in storage for a role without a Drive', (await stored(a)).length === 0);
  await a.goto(`${BASE}/dashboard/drive/`);
  await a.waitForSelector('#drive-disabled');
  check('disabled: "Drive is not enabled for your account"', /Drive is not enabled for your account/.test(await a.textContent('#drive-disabled')));
  await audit(a, 'disabled');
  await a.context().close();

  // ── zero knowledge on the wire ────────────────────────────────────────
  const leaks = ['Documents', 'readme.txt', 'notes.md', 'Welcome to the Drive', 'Q1 numbers', PW, 'pw-one'].filter((s) => wire.some((w) => w.includes(s)));
  check('wire: no names, contents or passwords in any Drive request (sealed in the browser)', leaks.length === 0 && wire.length > 0, leaks.join(','));
  const noToken = changes.filter((c) => !c.token).map((c) => c.what);
  const refused = changes.filter((c) => c.status === 403 && c.token).length;
  check('wire: every Drive change carries the session’s CSRF token (chunk uploads included)', changes.length > 0 && changes.some((c) => /\/chunk\//.test(c.what)) && noToken.length === 0, `${changes.length} changes; without: ${[...new Set(noToken)].join(', ')}`);
  info(`Drive changes seen: ${changes.length}; 403s: ${refused}`);
} catch (e) {
  console.log('ERROR', e);
  results.push(false);
} finally {
  check('no page errors or CSP / Trusted Types violations', errors.length === 0, errors.slice(0, 5).join(' | '));
  writeFileSync(path.join(OUT, 'axe.json'), JSON.stringify(axeFails, null, 1));
  console.log(`output (downloads, screenshots, axe.json): ${OUT}`);
  await b.close();
  const failed = results.filter((x) => !x).length;
  console.log(`\n${results.length - failed}/${results.length} passed`);
  process.exit(failed ? 1 : 0);
}
