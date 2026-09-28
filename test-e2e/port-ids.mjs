// port-ids.mjs — Admin → Import / export: the user id lists of the account
// export and import, end to end against the REAL server and pages. Export:
// each row shows its user id; the search finds by name or id; Select all /
// Deselect all take the rows shown; an uploaded id list chooses exactly the
// users it names; "Download the chosen ids" saves them as a plain text list
// (user ids only); the export sent is the users chosen from the list, and the
// file holds their ids. Import: the ids in the file are shown and downloaded;
// an uploaded list takes over the accounts it names (a deleted one created,
// an existing one updated) and skips the others; the preview and the import
// send only those; the existing account keeps its password (it still signs
// in with it) and takes only its role, whichever way it was chosen; the
// created account gets a new id. The labels say the lists hold user ids only.
// axe (WCAG 2.2 A/AA) on every new state; no page errors or CSP / Trusted
// Types violations. Synthetic data only. A manual test, not run in CI: see
// test-e2e/README.md. Needs a fresh `wrangler dev` (no owner yet),
// playwright-core and axe-core, and a Chromium.
//   WT=<repo checkout> BASE=http://localhost:9230 [CHROMIUM=<path>] [OUT=<dir>] node test-e2e/port-ids.mjs
import { chromium } from 'playwright-core';
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync } from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';

const require = createRequire(import.meta.url);
const AXE = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const BASE = process.env.BASE;
const WT = process.env.WT;
if (!BASE || !WT) { console.error('usage: WT=<repo checkout> BASE=http://localhost:9230 node test-e2e/port-ids.mjs'); process.exit(2); }
const TOKEN = /^AUTHN=(.*)$/m.exec(readFileSync(path.join(WT, '.dev.vars'), 'utf8'))[1].trim();
const OUT = process.env.OUT || mkdtempSync(path.join(os.tmpdir(), 'secbin-port-ids-'));
mkdirSync(OUT, { recursive: true });
const PW = 'owner-password-123';
const USER_PW = { alice: 'alice-password-123', bob: 'bob-password-123', carol: 'carol-password-123' };
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
const login = async (p, user, pw) => {
  await p.goto(`${BASE}/dashboard/login/`);
  await p.fill('#login-user', user); await p.fill('#login-pass', pw); await p.click('#login-btn');
  await p.waitForURL(/\/dashboard\/(\?.*)?$/, { timeout: 60000 });
};
const portable = async (p) => {
  await p.goto(`${BASE}/dashboard/admin/?load=${Date.now()}#portable`);
  await p.waitForSelector('#ax-ids-file', { state: 'attached', timeout: 60000 });
};

try {
  const ctx = await b.newContext({ acceptDownloads: true, reducedMotion: 'reduce', viewport: { width: 1280, height: 900 } });
  const p = await ctx.newPage();
  watch(p);
  // What the page sends to the export and import routes.
  const sent = [];
  p.on('request', (r) => {
    if (r.method() !== 'POST' || !/\/api\/private\/admin\/(export|import)$/.test(new URL(r.url()).pathname)) return;
    let body = null;
    try { body = r.postDataJSON(); } catch { /* not JSON */ }
    sent.push({ path: new URL(r.url()).pathname, body });
  });
  const since = (n, pathname) => sent.slice(n).filter((x) => x.path === pathname);

  // ── set-up: the owner, and alice, bob and carol ──
  await p.goto(`${BASE}/dashboard/setup/`);
  await p.waitForSelector('#setup-form:not([hidden])');
  await p.fill('#setup-token', TOKEN); await p.fill('#setup-user', 'owner'); await p.fill('#setup-pass', PW); await p.fill('#setup-pass2', PW);
  await p.click('#setup-btn');
  await p.waitForFunction(() => /created/.test(document.querySelector('#setup-msg').textContent), null, { timeout: 30000 });
  await login(p, 'owner', PW);
  for (const [name, pw] of Object.entries(USER_PW)) {
    await p.evaluate(async ([n, w]) => {
      const { newCredential } = await import('/js/pwauth.js');
      const { admin } = await import('/js/api.js');
      await admin.createUser({ username: n, ...(await newCredential(w)) });
    }, [name, pw]);
  }
  const ids = {};
  const users = (await api(p, '/api/private/admin/users')).body.users;
  for (const n of Object.keys(USER_PW)) ids[n] = users.find((u) => u.username === n).id;
  const ownerId = users.find((u) => u.role === 'owner').id;
  check('set-up: three users', Object.values(ids).every((id) => /^[A-Za-z0-9_-]{16}$/.test(id)));

  // ── export: ids shown, search, Select all / Deselect all of those shown ──
  await portable(p);
  const exp = p.locator('.admin-panel[data-panel="portable"] .card').nth(0);
  const rowIds = () => p.$$eval('#ax-users tr', (trs) => trs.map((tr) => tr.dataset.id));
  const picked = () => p.$$eval('#ax-users tr', (trs) => trs.filter((tr) => tr.querySelector('td[data-label="Export"] input').checked).map((tr) => tr.dataset.id));
  const shown = () => p.$$eval('#ax-users tr', (trs) => trs.filter((tr) => !tr.hidden && tr.offsetParent !== null).map((tr) => tr.dataset.id));
  check('export: a row per account, each showing its user id', JSON.stringify(await rowIds()) === JSON.stringify([ownerId, ids.alice, ids.bob, ids.carol])
    && (await exp.locator(`#ax-users tr[data-id="${ids.bob}"] td[data-label="User"]`).textContent()) === `bob${ids.bob}`);
  check('export: the labels say the lists hold user ids only', (await exp.locator('#ax-ids-save').textContent()) === 'Download the chosen ids (a list of user ids, no keys or credentials)'
    && (await exp.locator('label.field', { has: p.locator('#ax-ids-file') }).locator('.field-label').textContent()) === 'Choose from an id list (user ids only: one per line, or a JSON array)'
    && /one per line, with no keys, passwords or other credentials/.test(await exp.textContent()));
  await p.fill('#ax-search', 'car');
  check('export: the search by name shows only the matches', JSON.stringify(await shown()) === JSON.stringify([ids.carol]));
  await exp.locator('button[aria-label="Select all: users to export (those shown)"]').click();
  check('export: Select all takes only the rows shown', JSON.stringify(await picked()) === JSON.stringify([ids.carol]) && (await p.textContent('#ax-count')) === '1 of 4 chosen');
  await p.fill('#ax-search', ids.alice.slice(0, 8));
  check('export: the search by id', JSON.stringify(await shown()) === JSON.stringify([ids.alice]));
  await audit(p, 'Import / export (export: a search)');
  await p.fill('#ax-search', '');
  await exp.locator('button[aria-label="Deselect all: users to export (those shown)"]').click();
  check('export: Deselect all of every row shown', (await picked()).length === 0);

  // ── export: an uploaded id list, the chosen ids downloaded, the export ──
  const listFile = path.join(OUT, 'chosen-ids.txt');
  writeFileSync(listFile, `${ids.alice}\n${ids.carol}\nnot-a-user-id\n${'z'.repeat(16)}\n`);
  await p.setInputFiles('#ax-ids-file', listFile);
  await p.waitForFunction(() => !document.querySelector('#ax-ids-file-msg').hidden, null, { timeout: 30000 });
  check('export: the list chooses exactly the users it names', JSON.stringify(await picked()) === JSON.stringify([ids.alice, ids.carol]));
  check('export: the status line says how many matched', (await p.textContent('#ax-ids-file-msg')) === '2 of 3 ids in the list are accounts here and are now chosen; the others are not on this server.'
    && await p.evaluate(() => document.querySelector('#ax-ids-file-msg').parentElement.getAttribute('role') === 'status'));
  await audit(p, 'Import / export (export: chosen from an id list)');
  const downIds = await saveDownload(p, () => p.click('#ax-ids-save'), 'downloaded-ids.txt');
  check('export: "Download the chosen ids" saves them, one per line, nothing else', readFileSync(downIds, 'utf8') === `${ids.alice}\n${ids.carol}\n`);
  await exp.locator(`input[aria-label="Credentials for alice"]`).check();
  await exp.locator(`input[aria-label="Credentials for carol"]`).check();
  await exp.locator('input[aria-label="Export passphrase"]').fill(PASS);
  await exp.locator('input[aria-label="Repeat export passphrase"]').fill(PASS);
  await exp.locator(`input[aria-label="${MINE}"]`).fill(PW);
  let n = sent.length;
  const accountFile = await saveDownload(p, () => exp.locator('button:has-text("Encrypt and download")').click(), 'account-export.json');
  const ex = since(n, '/api/private/admin/export');
  check('export: sent the users chosen from the list, with their parts', ex.length === 1
    && JSON.stringify(ex[0].body.users) === JSON.stringify([{ id: ids.alice, parts: ['credentials', 'role'] }, { id: ids.carol, parts: ['credentials', 'role'] }]), JSON.stringify(ex[0]?.body?.users));
  const doc = await p.evaluate(async ([text, pass]) => (await import('/js/exportcrypt.js')).openExport(text, pass), [readFileSync(accountFile, 'utf8'), PASS]);
  check('export: the file holds each user\'s id', JSON.stringify(doc.users.map((u) => [u.id, u.username])) === JSON.stringify([[ids.alice, 'alice'], [ids.carol, 'carol']]));

  // carol is deleted (the import will create her again); alice stays (an update).
  check('carol deleted', (await api(p, `/api/private/admin/users/${ids.carol}`, { method: 'DELETE' })).status === 200);

  // ── import: the ids in the file, shown and downloaded; a list takes over the accounts it names ──
  await portable(p);
  const imp = p.locator('.admin-panel[data-panel="portable"] .card').nth(1);
  await imp.locator('input[aria-label="Export file"]').setInputFiles(accountFile);
  await imp.locator('input[aria-label="Export passphrase"]').fill(PASS);
  await imp.locator('button:has-text("Decrypt")').click();
  await imp.locator('select[aria-label="Action for alice"]').waitFor({ timeout: 60000 });
  const action = (name) => imp.locator(`select[aria-label="Action for ${name}"]`).inputValue();
  check('import: each row shows the id in the file', (await imp.locator('tbody td[data-label="User"]').allTextContents()).join('|') === `alice${ids.alice}|carol${ids.carol}`);
  check('import: before a list, alice (here) is skipped and carol (new) created', (await action('alice')) === 'skip' && (await action('carol')) === 'create');
  check('import: the labels say the lists hold user ids only, and that a list only chooses', (await p.textContent('#ai-ids-save')) === 'Download the ids in the file (a list of user ids, no keys or credentials)'
    && /An existing account keeps its password, recovery codes, API keys and passkeys whichever way it was chosen/.test(await imp.textContent()));
  const fileIds = await saveDownload(p, () => p.click('#ai-ids-save'), 'file-ids.txt');
  check('import: "Download the ids in the file" saves the file\'s ids', readFileSync(fileIds, 'utf8') === `${ids.alice}\n${ids.carol}\n`);
  const takeList = async (name, text, done) => {
    const f = path.join(OUT, name);
    writeFileSync(f, text);
    await p.setInputFiles('#ai-ids-file', f);
    await p.waitForFunction((re) => new RegExp(re).test(document.querySelector('#ai-ids-file-msg').textContent), done, { timeout: 30000 });
  };
  await takeList('only-alice.txt', `${ids.alice}\n`, '^1 of 1 id in the list');
  check('import: a list naming alice updates her and skips carol', (await action('alice')) === 'update' && (await action('carol')) === 'skip');
  await takeList('only-carol.txt', `${ids.carol}\n${'z'.repeat(16)}\n`, '^1 of 2 ids in the list');
  check('import: a list naming carol creates her and skips alice', (await action('carol')) === 'create' && (await action('alice')) === 'skip');
  await takeList('both.json', JSON.stringify([ids.alice, ids.carol]), '^2 of 2 ids in the list');
  check('import: a list naming both: alice updated (her role and passkeys only), carol created', (await action('alice')) === 'update' && (await action('carol')) === 'create'
    && await imp.locator('input[aria-label="Import Credentials for alice"]').isDisabled() && !(await imp.locator('input[aria-label="Import Credentials for alice"]').isChecked()));
  await audit(p, 'Import / export (import: chosen from an id list)');
  await imp.locator(`input[aria-label="${MINE}"]`).fill(PW);
  n = sent.length;
  await imp.locator('button:has-text("Preview")').click();
  await imp.locator('text=Preview ready').waitFor({ timeout: 60000 });
  const pv = since(n, '/api/private/admin/import');
  check('import: the preview sends only the accounts from the list, with the parts that apply', pv.length === 1
    && JSON.stringify(pv[0].body.decisions.users) === JSON.stringify({ alice: { as: 'alice', action: 'update', parts: ['role'] }, carol: { as: 'carol', action: 'create', parts: ['credentials', 'role'] } }), JSON.stringify(pv[0]?.body?.decisions));
  await audit(p, 'Import / export (import previewed)');
  await p.waitForFunction(() => { const x = [...document.querySelectorAll('.admin-panel[data-panel="portable"] .card:nth-child(2) button')].find((y) => y.textContent === 'Import'); return x && !x.disabled; }, null, { timeout: 30000 });
  await imp.locator(`input[aria-label="${MINE}"]`).fill(PW);
  await imp.locator('button:has-text("Import")').click();
  await imp.locator('p.msg:text-is("Imported.")').waitFor({ timeout: 60000 });
  const after = (await api(p, '/api/private/admin/users')).body.users;
  const carolNow = after.find((u) => u.username === 'carol');
  check('import: carol created again, with a new id (the file\'s id is not used)', !!carolNow && carolNow.id !== ids.carol);
  check('import: alice is the same account', after.find((u) => u.username === 'alice')?.id === ids.alice);

  // The existing account kept its password; the created one has the file's.
  const c2 = await b.newContext();
  const p2 = await c2.newPage();
  watch(p2);
  await login(p2, 'alice', USER_PW.alice);
  check('alice still signs in with her own password', (await api(p2, '/api/private/me')).body.user.id === ids.alice);
  await c2.clearCookies();
  await login(p2, 'carol', USER_PW.carol);
  check('carol signs in with the password from the file', (await api(p2, '/api/private/me')).body.user.username === 'carol');
  await c2.close();
} catch (e) {
  check('no exception', false, e.message.split('\n')[0]);
}
check('no page errors or CSP / Trusted Types violations', errors.length === 0, errors.slice(0, 3).join(' | '));
await b.close();
console.log(`${results.filter(Boolean).length}/${results.length} passed`);
process.exit(results.every(Boolean) ? 0 : 1);
