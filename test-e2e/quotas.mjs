// quotas.mjs — role quota kinds end to end (public/js/quotakinds.js; README
// "Quotas") in real Chromium against `wrangler dev`, synthetic data only:
//   • Admin → Roles → a custom role → Quotas: the kind select's groups
//     (Outgoing shares, Drive, Receive) and labels; "API only" disabled for a
//     web-only kind; a quota of each group set and saved through the editor;
//     the Public role offering only the outgoing kinds it can use; axe
//     (WCAG 2.2 A/AA) on both editors;
//   • the user, at each quota, through the UI: the composer refusing a second
//     note, the Drive refusing a second upload, the Receive dialog
//     refusing a second link, and the anonymous uploader's page refusing a
//     second upload session with the neutral message (nothing of the quota);
//     axe on each refusal; the Account page listing the quotas;
//   • no page errors and no CSP / Trusted Types violations.
//
// A manual test, not run in CI. Needs a fresh `wrangler dev` (no owner yet),
// playwright-core and axe-core, and a Chromium:
//   npx wrangler dev --port 9190 --persist-to <fresh dir>
//   WT=$PWD BASE=http://localhost:9190 [CHROMIUM=<path to chrome>] node test-e2e/quotas.mjs
import { chromium } from 'playwright-core';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';

const require = createRequire(import.meta.url);
const AXE = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const BASE = process.env.BASE;
const WT = process.env.WT;
if (!BASE || !WT) { console.error('usage: WT=<worktree> BASE=http://localhost:9190 node test-e2e/quotas.mjs'); process.exit(2); }
const TOKEN = /^AUTHN=(.*)$/m.exec(readFileSync(path.join(WT, '.dev.vars'), 'utf8'))[1].trim();
const PW = 'owner-password-123';
const QUINN_PW = 'quinn-password-123';
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22a', 'wcag22aa'];
const NOT_ACCEPTING = 'This link can’t accept more uploads right now. Try again later.';

const results = [];
const check = (n, ok, x = '') => { results.push(!!ok); console.log(`${ok ? 'PASS' : 'FAIL'} ${n}${x && !ok ? ` — ${x}` : ''}`); };
const b = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
const errors = [];
const watch = (p, tag) => {
  p.on('pageerror', (e) => errors.push(`${tag} pageerror: ${e.message}`));
  p.on('console', (m) => {
    if (m.type() !== 'error') return;
    if (/Content Security Policy|Trusted Type/i.test(m.text()) || !/status of (40[0-9]|41[0-9]|42[0-9])/.test(m.text())) errors.push(`${tag} console: ${m.text()}`);
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
async function login(p, user, pw) {
  await p.goto(`${BASE}/dashboard/login/`);
  await p.fill('#login-user', user); await p.fill('#login-pass', pw);
  await p.click('#login-btn');
  await p.waitForURL(/\/dashboard\/(\?.*)?$/, { timeout: 60000 });
}
async function openTab(p, name) {
  await p.waitForSelector('.admin-panel[data-panel="users"] input[aria-label="New username"]', { state: 'attached', timeout: 30000 });
  await p.waitForSelector(`.tab[data-tab="${name}"][aria-controls]`, { timeout: 30000 });
  await p.click(`.tab[data-tab="${name}"]`);
  await p.waitForSelector(`.admin-panel[data-panel="${name}"]:not([hidden])`, { timeout: 30000 });
}
async function editRole(p, name) {
  const row = p.locator('.admin-panel[data-panel="roles"] tbody tr', { hasText: name }).first();
  await row.waitFor({ timeout: 30000 });
  await row.locator('button', { hasText: 'Edit' }).click();
  await p.waitForSelector('#role-detail h2', { timeout: 30000 });
}
/** A same-origin admin call from the page, with the session's CSRF token (setup only). */
const api = (p, method, url, body) => p.evaluate(async ([m, u, bd]) => {
  const t = /(?:^|; )__Host-secbin_csrf=([^;]+)/.exec(document.cookie)?.[1];
  const r = await fetch(u, { method: m, headers: { 'content-type': 'application/json', 'x-secbin-intent': '1', ...(t ? { 'x-secbin-csrf': t } : {}) }, body: bd === undefined ? undefined : JSON.stringify(bd) });
  return { status: r.status, body: await r.json().catch(() => null) };
}, [method, url, body]);
const toast = (p, want) => p.waitForFunction((w) => (document.getElementById('toast')?.textContent || '').includes(w), want, { timeout: 30000 }).then(() => true, () => false);
const textOf = (p, sel, want) => p.waitForFunction(([s, w]) => { const el = document.querySelector(s); return el && !el.hidden && el.textContent.includes(w); }, [sel, want], { timeout: 60000 }).then(() => true, () => false);
/** The kind select's groups: [[label, [option text…]]…]. */
const groupsOf = (sel) => sel.evaluate((s) => [...s.children].map((g) => [g.label, [...g.children].map((o) => o.textContent)]));
const dialogButton = (p, text) => p.locator('.drive-dialog [role="dialog"] button', { hasText: text }).first();

try {
  // ── the owner, a role and a user ─────────────────────────────────────────
  const octx = await b.newContext({ viewport: { width: 1280, height: 900 }, reducedMotion: 'reduce' });
  const op = await octx.newPage();
  watch(op, 'owner');
  await op.goto(`${BASE}/dashboard/setup/`);
  await op.fill('#setup-token', TOKEN); await op.fill('#setup-user', 'owner'); await op.fill('#setup-pass', PW); await op.fill('#setup-pass2', PW);
  await op.click('#setup-btn');
  await op.waitForFunction(() => /created/.test(document.querySelector('#setup-msg').textContent), null, { timeout: 60000 });
  await login(op, 'owner', PW);
  await op.goto(`${BASE}/dashboard/admin/`);
  const users = op.locator('.admin-panel[data-panel="users"]');
  await users.locator('input[aria-label="New username"]').fill('quinn');
  await users.locator('input[aria-label="New user password"]').fill(QUINN_PW);
  await users.locator('input[aria-label="Repeat password"]').fill(QUINN_PW);
  await users.locator('button:has-text("Create user")').click();
  check('setup: user created', await toast(op, 'User created'));
  const role = await api(op, 'POST', '/api/private/admin/roles', { name: 'Limited' });
  const quinn = (await api(op, 'GET', '/api/private/admin/users')).body.users.find((u) => u.username === 'quinn');
  const assigned = await api(op, 'PUT', `/api/private/admin/users/${quinn.id}/role`, { roleId: role.body.id });
  // Turning the Receive CAPTCHA off widens what the role's links may be: the owner's password confirms it.
  const current = await op.evaluate(async (pw) => {
    const { stretch } = await import('/js/pwauth.js');
    const { salt, t } = await (await fetch('/api/auth/prelogin', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'owner' }) })).json();
    return stretch(pw, salt, t);
  }, PW);
  const opts = await api(op, 'PATCH', '/api/private/admin/limits', { scope: `role:${role.body.id}`, channel: 'all', patch: { driveEnabled: true, reverseEnabled: true, reverseCaptcha: 'off' }, current });
  check('setup: role "Limited" with the Drive and Receive, given to quinn', role.status === 201 && assigned.status === 200 && opts.status === 200, JSON.stringify([role, assigned, opts]));

  // ── Admin → Roles → Limited → Quotas ─────────────────────────────────────
  await op.goto(`${BASE}/dashboard/admin/`);
  await openTab(op, 'roles');
  await editRole(op, 'Limited');
  await op.getByLabel('This role\'s own list (instead of Default\'s)').check();
  check('roles: "This role\'s own list" chosen', await toast(op, 'own quota list'));
  const box = op.locator('#role-detail');
  for (let i = 0; i < 4; i++) await box.locator('button', { hasText: 'Add quota' }).click();
  const rows = box.locator('.quota-row');
  const kind = (i) => rows.nth(i).getByLabel('Kind', { exact: true });
  const channel = (i) => rows.nth(i).getByLabel('Via (channel)', { exact: true });
  check('roles: the kind select has the groups Outgoing shares, Drive and Receive, every kind labelled', JSON.stringify(await groupsOf(kind(0))) === JSON.stringify([
    ['Outgoing shares', ['All outgoing shares', 'Notes, links and credentials', 'Notes', 'Links', 'Credentials', 'File and Drive shares', 'File shares', 'Drive shares']],
    ['Drive', ['Files uploaded']],
    ['Receive', ['All receive', 'New links', 'Uploads received']],
  ]), JSON.stringify(await groupsOf(kind(0))));
  const plan = [['note', 'Notes'], ['drive-upload', 'Files uploaded'], ['receive-link', 'New links'], ['receive-upload', 'Uploads received']];
  for (const [i, [, label]] of plan.entries()) {
    await rows.nth(i).getByLabel('Max', { exact: true }).fill('1');
    await kind(i).selectOption({ label });
  }
  const apiOff = async (i) => channel(i).evaluate((s) => s.querySelector('option[value="api"]').disabled);
  const offs = [await apiOff(0), await apiOff(1), await apiOff(2), await apiOff(3)];
  check('roles: "API only" is disabled for a Drive or Receive kind, allowed for notes', JSON.stringify(offs) === '[false,true,true,true]', JSON.stringify(offs));
  await kind(0).focus();
  check('roles: the kind select takes keyboard focus', await kind(0).evaluate((el) => document.activeElement === el));
  await audit(op, 'Admin → Roles → Limited (the quota editor)');
  await box.locator('button', { hasText: 'Save quotas' }).click();
  check('roles: quotas saved', await toast(op, 'Quotas saved.'));
  const saved = (await api(op, 'GET', `/api/private/admin/roles/${role.body.id}`)).body.quotas.map((q) => `${q.max} ${q.kind} ${q.channel} ${q.n}${q.unit}`);
  check('roles: the server has one quota of each group as chosen', JSON.stringify(saved) === JSON.stringify(plan.map(([k]) => `1 ${k} all 1d`)), JSON.stringify(saved));

  await openTab(op, 'roles');
  await editRole(op, 'Public');
  await box.locator('button', { hasText: 'Add quota' }).click();
  check('roles: the Public role offers only the outgoing kinds it can use', JSON.stringify(await groupsOf(box.locator('.quota-row').first().getByLabel('Kind', { exact: true }))) === JSON.stringify([
    ['Outgoing shares', ['All outgoing shares', 'Notes, links and credentials', 'Notes', 'Links', 'Credentials', 'File and Drive shares', 'File shares']],
  ]));
  await audit(op, 'Admin → Roles → Public (the quota editor)');

  // ── the user at each quota ────────────────────────────────────────────────
  const uctx = await b.newContext({ viewport: { width: 1280, height: 900 }, reducedMotion: 'reduce' });
  const up = await uctx.newPage();
  watch(up, 'quinn');
  await login(up, 'quinn', QUINN_PW);
  // Outgoing: a second note.
  await up.fill('#editor', 'the first note');
  await up.click('#create');
  await up.waitForFunction(() => /\/p\//.test(document.querySelector('#paste-url')?.textContent || ''), null, { timeout: 60000 });
  check('outgoing: the first note is created', true);
  await up.goto(`${BASE}/dashboard/`);
  await up.fill('#editor', 'the second note');
  await up.click('#create');
  check('outgoing: the second note is refused — "Quota reached: 1 notes per 1d."', await textOf(up, '#create-msg', 'Quota reached: 1 notes per 1d.'), await up.textContent('#create-msg'));
  await audit(up, 'the composer, refused at the notes quota');

  // Drive: a second upload.
  await up.goto(`${BASE}/dashboard/drive/`);
  await up.waitForSelector('#drive-app', { timeout: 60000 });
  await up.setInputFiles('#drive-file-input', [{ name: 'first.txt', mimeType: 'text/plain', buffer: Buffer.from('synthetic file one') }]);
  await up.waitForFunction(() => [...document.querySelectorAll('#drive-rows tr')].some((tr) => tr.textContent.includes('first.txt')), null, { timeout: 60000 });
  check('Drive: the first upload is stored', true);
  await up.setInputFiles('#drive-file-input', [{ name: 'second.txt', mimeType: 'text/plain', buffer: Buffer.from('synthetic file two') }]);
  check('Drive: the second upload is refused — "Quota reached: 1 files uploaded to the Drive per 1d."', await textOf(up, '#drive-msg', 'Quota reached: 1 files uploaded to the Drive per 1d.'), await up.textContent('#drive-msg'));
  check('Drive: nothing of the refused file is listed', !(await up.locator('#drive-rows tr', { hasText: 'second.txt' }).count()));
  await audit(up, 'the Drive, refused at the uploads quota');

  // Receive: a second link, then a second upload session.
  await up.click('#drive-receive');
  await up.waitForSelector('#drive-rev-confirm');
  await up.fill('#drive-rev-label', 'synthetic inbox');
  await up.fill('#drive-rev-confirm', QUINN_PW);
  await dialogButton(up, 'Create link').click();
  await up.waitForSelector('#drive-rev-url', { timeout: 60000 });
  const revUrl = await up.textContent('#drive-rev-url');
  await dialogButton(up, 'Done').click();
  check('Receive: the first link is created', /\/r\/r/.test(revUrl), revUrl);
  await up.click('#drive-receive');
  await up.waitForSelector('#drive-rev-confirm');
  await up.fill('#drive-rev-label', 'a second inbox');
  await up.fill('#drive-rev-confirm', QUINN_PW);
  await dialogButton(up, 'Create link').click();
  const refusedLink = await up.waitForFunction(() => [...document.querySelectorAll('.drive-dialog [role="dialog"] .modal-msg')].some((m) => !m.hidden && m.textContent.includes('Quota reached: 1 new Receive links per 1d.')), null, { timeout: 60000 }).then(() => true, () => false);
  check('Receive: the second link is refused — "Quota reached: 1 new Receive links per 1d."', refusedLink, await up.locator('.drive-dialog [role="dialog"] .modal-msg').allTextContents().then((t) => t.join(' | ')));
  await audit(up, 'the Receive dialog, refused at the links quota');
  await up.keyboard.press('Escape');

  const sctx = await b.newContext({ viewport: { width: 1280, height: 900 }, reducedMotion: 'reduce' });
  const sp = await sctx.newPage();
  watch(sp, 'sender');
  await sp.goto(revUrl);
  await sp.waitForSelector('#reverse-page', { timeout: 60000 });
  await sp.setInputFiles('#reverse-file-input', [{ name: 'sent.txt', mimeType: 'text/plain', buffer: Buffer.from('synthetic upload') }]);
  await sp.click('#reverse-send');
  check('Receive: the first upload session sends its file', await textOf(sp, '#reverse-done', 'Sent 1 file'));
  await sp.setInputFiles('#reverse-file-input', [{ name: 'more.txt', mimeType: 'text/plain', buffer: Buffer.from('synthetic upload two') }]);
  await sp.click('#reverse-send');
  check(`Receive: the second session is refused — "${NOT_ACCEPTING}"`, await textOf(sp, '#reverse-msg', NOT_ACCEPTING), await sp.textContent('#reverse-msg'));
  const page = await sp.evaluate(() => document.body.innerText);
  check('Receive: the uploader sees nothing of the user\'s quota', !/quota|per 1d|Uploads received/i.test(page));
  await audit(sp, 'the uploader page, refused at the uploads-received quota');

  // The Account page lists them, used and allowed.
  await up.goto(`${BASE}/dashboard/account/`);
  await up.waitForSelector('#acct-quotas p', { timeout: 60000 });
  const listed = await up.locator('#acct-quotas p').allTextContents();
  check('Account: every quota listed with its use', JSON.stringify(listed) === JSON.stringify(['1 / 1 notes per 1d', '1 / 1 files uploaded to the Drive per 1d', '1 / 1 new Receive links per 1d', '1 / 1 uploads received per 1d']), JSON.stringify(listed));

  check('no page errors and no CSP / Trusted Types violations', errors.length === 0, errors.join(' | '));
} catch (e) {
  check('suite ran to the end', false, e && e.stack ? e.stack : String(e));
} finally {
  await b.close();
}
const passed = results.filter(Boolean).length;
console.log(`${passed}/${results.length} passed`);
process.exit(passed === results.length ? 0 : 1);
