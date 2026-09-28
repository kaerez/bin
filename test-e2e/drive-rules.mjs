// drive-rules.mjs — the Drive's bytes quota and the role's file rules in the
// Drive, and the one footer, end to end in real Chromium against `wrangler
// dev`, synthetic data only:
//   • Admin → Roles → a custom role → Quotas: "Bytes uploaded" in the Drive
//     group, its max in MiB or GiB (the unit select shown for it only), saved
//     in bytes; then, as the user, an upload past it refused with the size
//     ("Quota reached: 1.0 KB uploaded to the Drive per 1d.") and nothing of
//     it listed; the Account page listing it as a size;
//   • the role's limits: a blocked file type and a folder-depth limit set in
//     the role editor; as the user, a Drive upload of that type refused before
//     anything is sent (the reason on the page), a folder nested past the limit
//     refused in its dialog, one within it made;
//   • the footer: the same on every page, "Encrypted in your browser"; the
//     viewer saying a note is end-to-end and a Drive share is not;
//   • axe (WCAG 2.2 A/AA) on every state above; no page errors and no CSP /
//     Trusted Types violations.
//
// A manual test, not run in CI. Needs a fresh `wrangler dev` (no owner yet),
// playwright-core and axe-core, and a Chromium:
//   npx wrangler dev --port 9241 --persist-to <fresh dir>
//   WT=$PWD BASE=http://localhost:9241 [CHROMIUM=<path to chrome>] node test-e2e/drive-rules.mjs
import { chromium } from 'playwright-core';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';

const require = createRequire(import.meta.url);
const AXE = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const BASE = process.env.BASE;
const WT = process.env.WT;
if (!BASE || !WT) { console.error('usage: WT=<worktree> BASE=http://localhost:9241 node test-e2e/drive-rules.mjs'); process.exit(2); }
const TOKEN = /^AUTHN=(.*)$/m.exec(readFileSync(path.join(WT, '.dev.vars'), 'utf8'))[1].trim();
const PW = 'owner-password-123';
const RITA_PW = 'rita-password-123';
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22a', 'wcag22aa'];

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
/** A same-origin admin call from the page, with the session's CSRF token (setup and checks only). */
const api = (p, method, url, body) => p.evaluate(async ([m, u, bd]) => {
  const t = /(?:^|; )__Host-secbin_csrf=([^;]+)/.exec(document.cookie)?.[1];
  const r = await fetch(u, { method: m, headers: { 'content-type': 'application/json', 'x-secbin-intent': '1', ...(t ? { 'x-secbin-csrf': t } : {}) }, body: bd === undefined ? undefined : JSON.stringify(bd) });
  return { status: r.status, body: await r.json().catch(() => null) };
}, [method, url, body]);
const toast = (p, want) => p.waitForFunction((w) => (document.getElementById('toast')?.textContent || '').includes(w), want, { timeout: 30000 }).then(() => true, () => false);
const textOf = (p, sel, want) => p.waitForFunction(([s, w]) => { const el = document.querySelector(s); return el && !el.hidden && el.textContent.includes(w); }, [sel, want], { timeout: 60000 }).then(() => true, () => false);
const hasRow = (p, name) => p.waitForFunction((n) => [...document.querySelectorAll('#drive-rows tr')].some((tr) => tr.textContent.includes(n)), name, { timeout: 60000 }).then(() => true, () => false);
/** The page's footer as HTML, the current page's mark left out. */
const footerOf = (p) => p.evaluate(() => { const f = document.querySelector('footer').cloneNode(true); f.querySelectorAll('[aria-current]').forEach((a) => a.removeAttribute('aria-current')); return f.outerHTML.replace(/\s+/g, ' '); });
const synthetic = (n, c = 'x') => Buffer.from(c.repeat(n));
/** Open a share link: past the "reveal" step of a share with a view limit, to `view` (#view-paste / #view-files). */
async function openShare(p, url, view) {
  await p.goto(url);
  await p.waitForSelector(`#reveal-burn:visible, ${view}:not([hidden])`, { timeout: 60000 });
  if (await p.isVisible('#reveal-burn')) await p.click('#reveal-burn');
  await p.waitForSelector(`${view}:not([hidden])`, { timeout: 60000 });
}

try {
  // ── the owner, a role and a user ─────────────────────────────────────────
  const octx = await b.newContext({ viewport: { width: 1280, height: 900 }, reducedMotion: 'reduce' });
  const op = await octx.newPage();
  watch(op, 'owner');
  await op.goto(`${BASE}/dashboard/setup/`);
  await op.fill('#setup-token', TOKEN); await op.fill('#setup-user', 'owner'); await op.fill('#setup-pass', PW); await op.fill('#setup-pass2', PW);
  // The Drive keys the server proposes: generated, then "Use these".
  await op.click('#setup-keys-gen'); await op.click('#setup-keys-use');
  await op.click('#setup-btn');
  await op.waitForFunction(() => /created/.test(document.querySelector('#setup-msg').textContent), null, { timeout: 60000 });
  await login(op, 'owner', PW);
  await op.goto(`${BASE}/dashboard/admin/`);
  const users = op.locator('.admin-panel[data-panel="users"]');
  await users.locator('input[aria-label="New username"]').fill('rita');
  await users.locator('input[aria-label="New user password"]').fill(RITA_PW);
  await users.locator('input[aria-label="Repeat password"]').fill(RITA_PW);
  await users.locator('button:has-text("Create user")').click();
  check('setup: user created', await toast(op, 'User created'));
  const role = await api(op, 'POST', '/api/private/admin/roles', { name: 'Rules' });
  const rita = (await api(op, 'GET', '/api/private/admin/users')).body.users.find((u) => u.username === 'rita');
  const assigned = await api(op, 'PUT', `/api/private/admin/users/${rita.id}/role`, { roleId: role.body.id });
  const opts = await api(op, 'PATCH', '/api/private/admin/limits', { scope: `role:${role.body.id}`, channel: 'all', patch: { driveEnabled: true } });
  check('setup: role "Rules" with the Drive, given to rita', role.status === 201 && assigned.status === 200 && opts.status === 200, JSON.stringify([role, assigned, opts]));

  // ── Admin → Roles → Rules → Quotas: "Bytes uploaded" in MiB ──────────────
  await op.goto(`${BASE}/dashboard/admin/`);
  await openTab(op, 'roles');
  await editRole(op, 'Rules');
  await op.getByLabel('This role\'s own list (instead of Default\'s)').check();
  check('quotas: "This role\'s own list" chosen', await toast(op, 'own quota list'));
  const box = op.locator('#role-detail');
  await box.locator('button', { hasText: 'Add quota' }).click();
  const qrow = box.locator('.quota-row').first();
  const unitLabel = qrow.locator('label', { has: op.getByLabel('Max unit', { exact: true }) });
  check('quotas: a count kind shows no unit', await unitLabel.isHidden());
  await qrow.getByLabel('Kind', { exact: true }).selectOption({ label: 'Bytes uploaded' });
  check('quotas: "Bytes uploaded" shows its unit select (MiB, GiB), in a visible label', await unitLabel.isVisible()
    && JSON.stringify(await qrow.getByLabel('Max unit', { exact: true }).evaluate((s) => [...s.options].map((o) => o.value))) === '["MiB","GiB"]');
  check('quotas: "Bytes uploaded" takes no "API only" channel', await qrow.getByLabel('Via (channel)', { exact: true }).evaluate((s) => s.querySelector('option[value="api"]').disabled));
  await qrow.getByLabel('Max', { exact: true }).fill('0.001');
  await qrow.getByLabel('Max unit', { exact: true }).selectOption('MiB');
  await audit(op, 'Admin → Roles → Rules (a bytes quota in the editor)');
  await box.locator('button', { hasText: 'Save quotas' }).click();
  check('quotas: saved', await toast(op, 'Quotas saved.'));
  const saved = (await api(op, 'GET', `/api/private/admin/roles/${role.body.id}`)).body.quotas.map((q) => `${q.max} ${q.kind} ${q.channel} ${q.n}${q.unit}`);
  check('quotas: the server has the max in bytes (0.001 MiB = 1049 bytes)', JSON.stringify(saved) === JSON.stringify(['1049 drive-bytes all 1d']), JSON.stringify(saved));

  // ── the role's limits: a blocked type and a folder-depth limit ───────────
  const limit = (label) => box.getByLabel(label, { exact: true }).first();
  await limit('File types mode').selectOption('enum:block');
  await limit('File type list mode').selectOption('value');
  await limit('File type list').fill('ext:exe');
  await limit('Max folder depth mode').selectOption('value');
  await limit('Max folder depth').fill('1');
  await audit(op, 'Admin → Roles → Rules (the file rules set)');
  await box.locator('button', { hasText: /^Save\s+limits$/ }).first().click();
  check('limits: saved', await toast(op, 'Limits saved.'));
  const lim = (await api(op, 'GET', `/api/private/admin/roles/${role.body.id}`)).body.limits.all;
  check('limits: the server has the file rules', lim.fileTypeMode === 'block' && JSON.stringify(lim.fileTypeRules) === '["ext:exe"]' && lim.maxFolderDepth === 1, JSON.stringify(lim));

  // ── rita in the Drive ─────────────────────────────────────────────────────
  const uctx = await b.newContext({ viewport: { width: 1280, height: 900 }, reducedMotion: 'reduce' });
  const up = await uctx.newPage();
  watch(up, 'rita');
  const sent = [];
  up.on('request', (r) => { if (r.method() === 'POST' && /\/api\/private\/drive\/(files|folders)$/.test(r.url())) sent.push({ url: r.url(), body: r.postDataJSON() }); });
  await login(up, 'rita', RITA_PW);
  await up.goto(`${BASE}/dashboard/drive/`);
  await up.waitForSelector('#drive-app', { timeout: 60000 });

  // The bytes quota: 600 bytes fit, 600 more do not.
  await up.setInputFiles('#drive-file-input', [{ name: 'first.txt', mimeType: 'text/plain', buffer: synthetic(600, 'a') }]);
  check('bytes: the first 600 bytes are stored', await hasRow(up, 'first.txt'));
  check('bytes: the upload declared its type (a type policy applies)', JSON.stringify(sent.at(-1)?.body?.types) === '[{"ext":"txt","mime":"text/plain"}]', JSON.stringify(sent.at(-1)?.body?.types));
  await up.setInputFiles('#drive-file-input', [{ name: 'second.txt', mimeType: 'text/plain', buffer: synthetic(600, 'b') }]);
  check('bytes: 600 more are refused — "Quota reached: 1.0 KB uploaded to the Drive per 1d."', await textOf(up, '#drive-msg', 'Quota reached: 1.0 KB uploaded to the Drive per 1d.'), await up.textContent('#drive-msg'));
  check('bytes: nothing of the refused file is listed', !(await up.locator('#drive-rows tr', { hasText: 'second.txt' }).count()));
  await audit(up, 'the Drive, refused at the bytes quota');

  // A blocked type: refused before anything is sent.
  const before = sent.length;
  await up.setInputFiles('#drive-file-input', [{ name: 'tool.exe', mimeType: 'application/x-msdownload', buffer: synthetic(10, 'M') }]);
  check('types: an .exe upload is refused with the reason', await textOf(up, '#drive-msg', 'Your administrator does not allow .exe'), await up.textContent('#drive-msg'));
  check('types: nothing was sent for it', sent.length === before, JSON.stringify(sent.slice(before)));
  await audit(up, 'the Drive, an upload refused by the file-type rule');

  // The depth limit: a folder at level 1 is made; one inside it is refused in its dialog.
  await up.click('#drive-mkdir');
  await up.waitForSelector('.drive-dialog [role="dialog"]');
  await up.fill('.drive-dialog input', 'Level one');
  await up.keyboard.press('Enter');
  check('depth: a folder at level 1 is made', await hasRow(up, 'Level one'));
  await up.locator('#drive-rows tr', { hasText: 'Level one' }).locator('button.drive-open').click();
  await up.waitForFunction(() => document.getElementById('drive-pane-title')?.textContent === 'Level one', null, { timeout: 30000 });
  const folders = sent.filter((x) => /folders$/.test(x.url)).length;
  await up.click('#drive-mkdir');
  await up.waitForSelector('.drive-dialog [role="dialog"]');
  await up.fill('.drive-dialog input', 'Level two');
  await up.keyboard.press('Enter');
  const why = 'Folders may nest at most 1 level deep in your Drive for your account; the new folder would be at level 2.';
  check('depth: a folder at level 2 is refused in its dialog, with the reason', await textOf(up, '.drive-dialog .modal-msg', why), await up.textContent('.drive-dialog .modal-msg'));
  check('depth: nothing was sent for it', sent.filter((x) => /folders$/.test(x.url)).length === folders);
  await audit(up, 'the new-folder dialog, refused by the depth limit');
  await up.keyboard.press('Escape');

  // The server refuses the same when asked directly (a page that does not check first).
  // A well-formed body whose seals are never opened: the type is checked first.
  const current = (await api(up, 'GET', '/api/private/drive')).body.current;
  const field = { iv: 'A'.repeat(16), ct: 'A'.repeat(64) };
  const direct = await api(up, 'POST', '/api/private/drive/files', { parent: 'root', size: 1, name: field, meta: field, dek: field, ks: 'A'.repeat(43), mek: current });
  check('types: the server asks a direct upload for its declaration (the policy with it)', direct.status === 400 && direct.body.error === 'declaration_required' && direct.body.policy?.mode === 'block', JSON.stringify(direct));

  // Account: the bytes quota as a size.
  await up.goto(`${BASE}/dashboard/account/`);
  await up.waitForSelector('#acct-quotas p', { timeout: 60000 });
  const listed = await up.locator('#acct-quotas p').allTextContents();
  check('Account: the bytes quota listed as sizes', JSON.stringify(listed) === JSON.stringify(['600 B / 1.0 KB uploaded to the Drive per 1d']), JSON.stringify(listed));

  // ── the footer, the viewer ────────────────────────────────────────────────
  // A Drive share of first.txt.
  await up.goto(`${BASE}/dashboard/drive/`);
  await up.waitForSelector('#drive-app', { timeout: 60000 });
  await hasRow(up, 'first.txt');
  await up.locator('#drive-rows tr', { hasText: 'first.txt' }).locator('input[type="checkbox"]').check();
  await up.click('#drive-share');
  await up.waitForSelector('#drive-share-views');
  await up.click('.drive-dialog button:has-text("Create link")');
  await up.waitForSelector('#drive-share-url', { timeout: 60000 });
  const driveShare = await up.textContent('#drive-share-url');
  await up.click('.drive-dialog button:has-text("Done")');
  // A note.
  await up.goto(`${BASE}/dashboard/`);
  await up.waitForSelector('#editor');
  await up.fill('#editor', 'a synthetic note');
  await up.click('#create');
  await up.waitForFunction(() => /\/p\//.test(document.querySelector('#paste-url')?.textContent || ''), null, { timeout: 60000 });
  const note = await up.textContent('#paste-url');

  const vctx = await b.newContext({ viewport: { width: 1280, height: 900 }, reducedMotion: 'reduce' });
  const vp = await vctx.newPage();
  watch(vp, 'recipient');
  await openShare(vp, note, '#view-paste');
  check('viewer: a note says it is end-to-end', /End-to-end encrypted: this note was decrypted in your browser/.test(await vp.textContent('#view-paste')));
  await audit(vp, 'the viewer: a note');
  const foots = new Set([await footerOf(vp)]);
  const vp2 = await vctx.newPage();
  watch(vp2, 'recipient 2');
  await openShare(vp2, driveShare, '#view-files');
  check('viewer: a Drive share says it is not end-to-end, and that the server can decrypt it', /Shared from the sender’s Drive: encrypted in the sender’s browser, but not end-to-end\. The server holds the keys to the sender’s Drive and can decrypt these files\./.test(await vp2.textContent('#files-e2e')));
  await audit(vp2, 'the viewer: a Drive share');
  foots.add(await footerOf(vp2));

  for (const [p, url, label] of [[vp, '/', 'the landing page'], [vp, '/accessibility/', 'the accessibility statement and glossary'], [vp, '/r/rAAAAAAAAAAAAAAAAAAAAAA#x', 'the uploader page'],
    [up, '/dashboard/', 'the composer'], [up, '/dashboard/drive/', 'the Drive'], [up, '/dashboard/shares/', 'My shares'], [up, '/dashboard/account/', 'Account'], [op, '/dashboard/admin/', 'Admin']]) {
    await p.goto(`${BASE}${url}`);
    await p.waitForSelector('footer .foot-feats', { timeout: 60000 });
    await p.waitForTimeout(500);
    foots.add(await footerOf(p));
    check(`footer: "Private · Encrypted in your browser · Notes & files" on ${label}`, (await p.textContent('footer .foot-feats')).replace(/\s+/g, ' ').trim() === 'Private Encrypted in your browser Notes & files');
    const main = (await p.textContent('main')).replace(/\s+/g, ' ');
    if (url === '/') check('the landing page: notes and file shares are end-to-end, in its text', /End-to-end encrypted notes and file shares that self-destruct/.test(main));
    if (url === '/dashboard/') check('the composer: notes and file shares are end-to-end, in its introduction', /Notes and file shares are end-to-end encrypted: encrypted in your browser, with the key only in the link\./.test(main));
    if (url === '/accessibility/') check('the glossary: "Encrypted in your browser" and "End-to-end encrypted"', /Encrypted in your browser What every page’s footer says/.test(main) && /End-to-end encrypted Encrypted on the sender’s device/.test(main));
    if (['/', '/accessibility/', '/r/rAAAAAAAAAAAAAAAAAAAAAA#x', '/dashboard/'].includes(url)) await audit(p, label);
  }
  check('footer: the same HTML on every page', foots.size === 1, [...foots].join('\n'));

  check('no page errors and no CSP / Trusted Types violations', errors.length === 0, errors.join(' | '));
} catch (e) {
  check('suite ran to the end', false, e && e.stack ? e.stack : String(e));
} finally {
  await b.close();
}
const passed = results.filter(Boolean).length;
console.log(`${passed}/${results.length} passed`);
process.exit(passed === results.length ? 0 : 1);
