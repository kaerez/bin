// drive-upgrade.mjs — the one-time upgrade of Drives made by the release
// before the key model v2 (docs/DRIVE.md §3.3), end to end on one server
// state, in two phases:
//   PHASE=1, against a server running the release before (a checkout of it):
//     the owner and two users (alice, carol) with Drives made the old way —
//     files, a folder with a file in it, and alice's reverse link with one
//     received file taken in and one still waiting;
//   PHASE=2, against this release on the same state (the Directory's
//     migration marks those accounts as waiting): the owner's sign-in and
//     Drive page upgrade the owner's own Drive; Admin → Security → Keys lists
//     the Drives waiting and upgrades carol's through the escrow of the
//     release before; alice's sign-in and Drive page upgrade hers; every file
//     reads back with the same bytes, the waiting received file is taken in,
//     the reverse link still receives; once every Drive is upgraded the old
//     wraps and escrow records are gone and nothing is left waiting.
// A manual test, not run in CI: see test-e2e/README.md. Synthetic data only.
//   PHASE=1 WT=<checkout of the release before> BASE=http://localhost:8787 OUT=<dir> node test-e2e/drive-upgrade.mjs
//   (stop that server; start this release's `wrangler dev` on the same --persist-to state)
//   PHASE=2 WT=<this checkout> BASE=http://localhost:8787 OUT=<same dir> node test-e2e/drive-upgrade.mjs
import { chromium } from 'playwright-core';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';

const BASE = process.env.BASE;
const WT = process.env.WT;
const OUT = process.env.OUT;
const PHASE = process.env.PHASE;
if (!BASE || !WT || !OUT || !['1', '2'].includes(PHASE)) { console.error('usage: PHASE=1|2 WT=<checkout> BASE=<url> OUT=<dir> node test-e2e/drive-upgrade.mjs'); process.exit(2); }
mkdirSync(OUT, { recursive: true });
const STATE = path.join(OUT, 'drive-upgrade.json');
const TOKEN = /^AUTHN=(.*)$/m.exec(readFileSync(path.join(WT, '.dev.vars'), 'utf8'))[1].trim();
const PW = 'owner-password-123';
const USERS = { alice: 'alice-password-123', carol: 'carol-password-123' };
const FILES = {
  owner: [['owner-old.txt', 'the owner, in the release before\n']],
  alice: [['alice-old.txt', 'alice, in the release before\n'], ['Alice docs/nested.md', '# nested\nalice again\n']],
  carol: [['carol-old.txt', 'carol, in the release before\n']],
};
const results = [];
const check = (n, ok, x = '') => { results.push(!!ok); console.log(`${ok ? 'PASS' : 'FAIL'} ${n}${x ? ' — ' + x : ''}`); };
const b = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
const errors = [];
const watch = (p) => {
  p.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  p.on('console', (m) => { if (m.type() === 'error' && /Content Security Policy|Trusted Type/i.test(m.text())) errors.push(`console: ${m.text()}`); });
};
const api = (p, url, init = {}) => p.evaluate(async ([u, i]) => {
  const csrf = (document.cookie.match(/(?:^|;\s*)__Host-secbin_csrf=([^;]+)/) || [])[1] || '';
  const r = await fetch(u, { cache: 'no-store', ...i, headers: { 'content-type': 'application/json', 'x-secbin-intent': '1', ...(i.method && i.method !== 'GET' ? { 'x-secbin-csrf': csrf } : {}), ...(i.headers || {}) } });
  return { status: r.status, body: await r.json().catch(() => null) };
}, [url, init]);
async function login(p, user, pw) {
  await p.goto(`${BASE}/dashboard/login/`);
  await p.fill('#login-user', user); await p.fill('#login-pass', pw); await p.click('#login-btn');
  await p.waitForURL(/\/dashboard\/(\?.*)?$/, { timeout: 90000 });
  await p.waitForSelector('#dash-nav:not([hidden])');
}
const exact = (name) => new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`);
const rowOf = (p, name) => p.locator('#drive-rows tr', { has: p.locator('td:nth-child(2) bdi.fname', { hasText: exact(name) }) });
const hasRow = (n) => [...document.querySelectorAll('#drive-rows tr')].some((tr) => tr.children[1].textContent.trim() === n);
const waitRow = (p, n, timeout = 60000) => p.waitForFunction(hasRow, n, { timeout });
async function drivePage(p) {
  await p.goto(`${BASE}/dashboard/drive/`);
  await p.waitForSelector('#drive-app', { timeout: 90000 });
  await p.waitForSelector('#drive-rows tr, #drive-empty:not([hidden])', { timeout: 60000 });
}
async function openFolder(p, name) {
  await rowOf(p, name).locator('button.drive-open').click();
  await p.waitForFunction((n) => document.querySelector('#drive-pane-title').textContent === n, name, { timeout: 30000 });
}
async function upload(p, name, text) {
  await p.setInputFiles('#drive-file-input', [{ name, mimeType: 'text/plain', buffer: Buffer.from(text) }]);
  await waitRow(p, name);
}
/** Put `files` ([path, text], one folder level at most) into the Drive open on `p`. */
async function putFiles(p, files) {
  for (const [f, text] of files) {
    const [dir, name] = f.includes('/') ? f.split('/') : [null, f];
    await drivePage(p);
    if (dir) {
      if (!(await rowOf(p, dir).count())) {
        await p.click('#drive-mkdir'); await p.fill('.drive-dialog input', dir); await p.keyboard.press('Enter');
        await waitRow(p, dir);
      }
      await openFolder(p, dir);
    }
    await upload(p, name, text);
  }
}
/** Every file in `files` downloads and decrypts to its text. */
async function reads(p, files) {
  const bad = [];
  for (const [f, text] of files) {
    const [dir, name] = f.includes('/') ? f.split('/') : [null, f];
    await drivePage(p);
    if (dir) await openFolder(p, dir);
    await waitRow(p, name);
    await rowOf(p, name).locator('input[type="checkbox"]').check();
    const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 60000 }), p.click('#drive-download')]);
    const out = path.join(OUT, `p${PHASE}-${Date.now()}-${name}`);
    await dl.saveAs(out);
    if (readFileSync(out, 'utf8') !== text) bad.push(f);
  }
  return bad;
}
/** The anonymous uploader sends one file through `url`. */
async function send(url, name, text) {
  const c = await b.newContext({ viewport: { width: 1280, height: 900 } });
  const u = await c.newPage();
  watch(u);
  await u.goto(url);
  await u.waitForSelector('#reverse-page', { timeout: 60000 });
  await u.setInputFiles('#reverse-file-input', [{ name, mimeType: 'text/plain', buffer: Buffer.from(text) }]);
  await u.waitForFunction(() => !document.querySelector('#reverse-send').disabled, null, { timeout: 60000 });
  await u.click('#reverse-send');
  await u.waitForSelector('#reverse-done:not([hidden])', { timeout: 120000 });
  await c.close();
}
const ctx = () => b.newContext({ acceptDownloads: true, reducedMotion: 'reduce', viewport: { width: 1280, height: 900 } });

try {
  if (PHASE === '1') {
    // ── the release before: Drives made the old way ──
    const oc = await ctx();
    const p = await oc.newPage();
    watch(p);
    await p.goto(`${BASE}/dashboard/setup/`);
    await p.fill('#setup-token', TOKEN); await p.fill('#setup-user', 'owner'); await p.fill('#setup-pass', PW); await p.fill('#setup-pass2', PW);
    await p.click('#setup-btn');
    await p.waitForFunction(() => /created/.test(document.querySelector('#setup-msg').textContent), null, { timeout: 30000 });
    await login(p, 'owner', PW);
    const own = (await api(p, '/api/private/drive')).body;
    check('release before: the owner\'s Drive has its old key wraps and escrow key', Array.isArray(own.wraps) && own.wraps.some((w) => w.kind === 'pw') && !!own.escrowPub, JSON.stringify(Object.keys(own)));
    const lim = await api(p, '/api/private/admin/limits', { method: 'PATCH', body: JSON.stringify({ scope: 'global', channel: 'all', patch: { driveEnabled: true, reverseEnabled: true } }) });
    check('release before: Drive and reverse shares on for the Default role', lim.status === 200, JSON.stringify(lim.body));
    for (const [name, pw] of Object.entries(USERS)) {
      await p.goto(`${BASE}/dashboard/admin/`);
      await p.click('.tab[data-tab="users"]');
      const up = p.locator('.admin-panel[data-panel="users"]');
      await up.locator('input[aria-label="New username"]').first().fill(name);
      await up.locator('input[aria-label="New user password"]').first().fill(pw);
      await up.locator('input[aria-label="Repeat password"]').first().fill(pw);
      await up.locator('button:has-text("Create user")').first().click();
      await p.waitForFunction(() => document.getElementById('toast').textContent === 'User created.', null, { timeout: 30000 });
    }
    await putFiles(p, FILES.owner);
    const ac = await ctx();
    const a = await ac.newPage();
    watch(a);
    await login(a, 'alice', USERS.alice);
    await putFiles(a, FILES.alice);
    // alice's reverse link on her root folder: one upload taken in, one left waiting.
    await drivePage(a);
    await a.click('#drive-receive');
    await a.waitForSelector('#drive-rev-form');
    await a.fill('#drive-rev-label', 'Old link');
    await a.fill('#drive-rev-confirm', USERS.alice);
    await a.click('.drive-dialog button:has-text("Create link")');
    await a.waitForSelector('#drive-rev-url', { timeout: 60000 });
    const link = (await a.textContent('#drive-rev-url')).trim();
    await a.click('.drive-dialog button:has-text("Done")');
    await send(link, 'received-before.txt', 'received in the release before\n');
    await drivePage(a);
    await waitRow(a, 'received-before.txt', 90000);
    check('release before: alice took a received file in', true);
    await send(link, 'waiting.txt', 'received, still waiting at the upgrade\n');
    const cc = await ctx();
    const c = await cc.newPage();
    watch(c);
    await login(c, 'carol', USERS.carol);
    await putFiles(c, FILES.carol);
    check('release before: every file reads back', (await reads(p, FILES.owner)).length === 0 && (await reads(a, FILES.alice)).length === 0 && (await reads(c, FILES.carol)).length === 0);
    const users = (await api(p, '/api/private/admin/users')).body.users;
    writeFileSync(STATE, JSON.stringify({ link, ids: Object.fromEntries(users.map((u) => [u.username, u.id])) }));
    await ac.close(); await cc.close(); await oc.close();
  } else {
    // ── this release on the same state ──
    const { link, ids } = JSON.parse(readFileSync(STATE, 'utf8'));
    const oc = await ctx();
    const p = await oc.newPage();
    watch(p);
    await login(p, 'owner', PW);
    let mig = (await api(p, '/api/private/admin/drive/migration')).body;
    const waiting = (mig.drives || []).filter((d) => d.state !== 'done').map((d) => d.username).sort();
    check('upgrade: the owner, alice and carol are waiting', JSON.stringify(waiting) === '["alice","carol","owner"]' && mig.legacyEscrow === true, JSON.stringify(mig));
    // The owner's own Drive page upgrades it (the sign-in opened the old key).
    await p.goto(`${BASE}/dashboard/drive/`);
    await p.waitForSelector('#drive-upgrade', { timeout: 90000 });
    check('upgrade: the owner\'s Drive page shows the upgrade with its progress', /being upgraded|is upgraded/.test(await p.textContent('#drive-upgrade')));
    await p.waitForFunction(() => /Your Drive is upgraded/.test(document.querySelector('#drive-upgrade')?.textContent || '') || !document.querySelector('#drive-upgrade-msg')?.hidden, null, { timeout: 180000 });
    check('upgrade: the owner\'s Drive is upgraded', /Your Drive is upgraded/.test(await p.textContent('#drive-upgrade')), await p.textContent('#drive-upgrade'));
    check('upgrade: the owner\'s files read back with the same bytes', (await reads(p, FILES.owner)).length === 0);
    // Admin → Security → Keys: carol's Drive through the escrow of the release before.
    await p.goto(`${BASE}/dashboard/admin/#keys`);
    await p.waitForSelector('#keys-upgrade:not([hidden]) #keys-upgrade-table', { timeout: 60000 });
    const rows = await p.$$eval('#keys-upgrade-table tbody tr', (trs) => trs.map((tr) => `${tr.children[0].textContent}:${tr.dataset.state}`));
    check('upgrade: Admin lists the Drives and their state', rows.some((r) => r.startsWith('carol:')) && rows.some((r) => r.startsWith('alice:')), rows.join(', '));
    await p.fill('#keys-upgrade-confirm', PW); // the escrow opens a user's old key: the step-up
    await p.click(`#keys-upgrade-table tr[data-id="${ids.carol}"] button`);
    await p.waitForFunction(() => /carol’s Drive is upgraded/.test(document.getElementById('toast').textContent), null, { timeout: 180000 });
    check('upgrade: carol\'s Drive upgraded from Admin (she has not signed in)', true);
    const audit = (await api(p, `/api/private/admin/audit?user=${ids.carol}`)).body.rows.map((r) => r.action);
    check('upgrade: the escrow use and the upgrade in the admin audit', audit.includes('drive.escrow_used') && audit.some((x) => /drive\.migrat/.test(x)), audit.join(','));
    // alice: her sign-in and Drive page.
    const ac = await ctx();
    const a = await ac.newPage();
    watch(a);
    await login(a, 'alice', USERS.alice);
    await a.goto(`${BASE}/dashboard/drive/`);
    await a.waitForSelector('#drive-upgrade', { timeout: 90000 });
    await a.waitForFunction(() => /Your Drive is upgraded/.test(document.querySelector('#drive-upgrade')?.textContent || '') || !document.querySelector('#drive-upgrade-msg')?.hidden, null, { timeout: 180000 });
    check('upgrade: alice\'s Drive page upgraded it at her sign-in', /Your Drive is upgraded/.test(await a.textContent('#drive-upgrade')), await a.textContent('#drive-upgrade'));
    check('upgrade: alice\'s files (a folder included) read back with the same bytes', (await reads(a, [...FILES.alice, ['received-before.txt', 'received in the release before\n']])).length === 0);
    await drivePage(a);
    await waitRow(a, 'waiting.txt', 90000);
    check('upgrade: the file waiting at the upgrade is taken in and reads back', (await reads(a, [['waiting.txt', 'received, still waiting at the upgrade\n']])).length === 0);
    await send(link, 'after-upgrade.txt', 'received after the upgrade\n');
    await drivePage(a);
    await waitRow(a, 'after-upgrade.txt', 90000);
    check('upgrade: the old reverse link still receives (its key re-sealed)', (await reads(a, [['after-upgrade.txt', 'received after the upgrade\n']])).length === 0);
    check('upgrade: alice\'s old key is gone from the tab', await a.evaluate(() => !sessionStorage.getItem('secbin_dk')));
    const cc = await ctx();
    const c = await cc.newPage();
    watch(c);
    await login(c, 'carol', USERS.carol);
    await drivePage(c);
    check('upgrade: carol\'s Drive opens with no upgrade left to do', (await c.$('#drive-upgrade')) === null);
    check('upgrade: carol\'s files read back with the same bytes', (await reads(c, FILES.carol)).length === 0);
    mig = (await api(p, '/api/private/admin/drive/migration')).body;
    check('upgrade: nothing is left waiting, the escrow records are gone', (mig.drives || []).every((d) => d.state === 'done') && !mig.left && mig.legacyEscrow === false, JSON.stringify(mig));
    for (const [who, page] of [['owner', p], ['alice', a], ['carol', c]]) {
      const m = (await api(page, '/api/private/drive/migrate')).body;
      check(`upgrade: ${who}'s old key wraps, salt and check value are removed`, m.legacy === false && !m.kcv && (m.v1Items || 0) === 0 && (m.v1Links || 0) === 0, JSON.stringify(m));
    }
    await p.goto(`${BASE}/dashboard/admin/?load=${Date.now()}#keys`); // a new load (not only the same #fragment)
    await p.waitForSelector('#keys-subs-table tbody tr', { timeout: 60000 });
    await p.waitForTimeout(1500);
    check('upgrade: the Admin upgrade card is gone', await p.isHidden('#keys-upgrade'));
    await ac.close(); await cc.close(); await oc.close();
  }
} catch (e) {
  console.log('ERROR', e);
  results.push(false);
} finally {
  check('no page errors or CSP / Trusted Types violations', errors.length === 0, errors.slice(0, 5).join(' | '));
  await b.close();
  const failed = results.filter((x) => !x).length;
  console.log(`\n${results.length - failed}/${results.length} passed (phase ${PHASE})`);
  process.exit(failed ? 1 : 0);
}
