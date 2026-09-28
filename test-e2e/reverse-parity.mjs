// reverse-parity.mjs — "Receive" links (reverse shares) with the options of
// regular shares, end to end against the REAL server and pages
// (docs/REVERSE.md §5, §6.1, §8): a user whose role allows links with no
// expiry makes one with an uploader password and 2 views in the Drive's
// Receive… dialog; an anonymous uploader sends files twice; the third visit
// is refused (its views are used up); in My shares the user filters by "no
// expiry", edits the link (a new password, more views) and the uploader
// sends again with the new password (the old one refused); then the link is
// given an expiry, which the uploader page shows. axe (WCAG 2.2 A/AA, and
// the AAA contrast rule) on the Receive dialog with its new options, on My
// shares' Edit and on the uploader page; nothing on the wire names a file or
// carries a password; no page errors or CSP / Trusted Types violations.
// Synthetic data only. A manual test, not run in CI: see test-e2e/README.md.
// Needs a fresh `wrangler dev` (no owner yet), playwright-core and axe-core,
// and a Chromium.
//   WT=<repo checkout> BASE=http://localhost:9170 [CHROMIUM=<path>] node test-e2e/reverse-parity.mjs
import { chromium } from 'playwright-core';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';

const require = createRequire(import.meta.url);
const AXE = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const BASE = process.env.BASE;
const WT = process.env.WT;
if (!BASE || !WT) { console.error('usage: WT=<repo checkout> BASE=http://localhost:9170 node test-e2e/reverse-parity.mjs'); process.exit(2); }
const TOKEN = /^AUTHN=(.*)$/m.exec(readFileSync(path.join(WT, '.dev.vars'), 'utf8'))[1].trim();
const PW = 'owner-password-123';
const ALICE_PW = 'alice-password-123';
const GATE1 = 'first-gate-words';
const GATE2 = 'second-gate-words';
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22a', 'wcag22aa'];
const results = [];
const check = (n, ok, x = '') => { results.push(!!ok); console.log(`${ok ? 'PASS' : 'FAIL'} ${n}${x ? ' — ' + x : ''}`); };
const b = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
const errors = [];
const wire = []; // what the uploader's and the user's browsers sent to the API
const watch = (p, { record = false } = {}) => {
  p.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  p.on('console', (m) => {
    const t = m.text();
    if (m.type() === 'error' && (/Content Security Policy|Trusted Type/i.test(t) || !/status of (40[0-9]|41[0-9]|42[0-9])/.test(t))) errors.push(`console: ${t}`);
  });
  if (record) p.on('request', (r) => { if (/\/api\//.test(r.url())) { wire.push(r.url()); const d = r.postDataBuffer(); if (d) wire.push(d.toString('latin1')); } });
};
async function audit(p, label, { aaa = true } = {}) {
  await p.evaluate(AXE);
  const v = await p.evaluate(async ({ tags, aaa }) => {
    // eslint-disable-next-line no-undef
    const r = await axe.run(document, { runOnly: { type: 'tag', values: aaa ? [...tags, 'wcag2aaa'] : tags }, resultTypes: ['violations'] });
    return r.violations.map((x) => `${x.id} (${x.impact}): ${x.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')}`);
  }, { tags: TAGS, aaa });
  check(`axe${aaa ? ' (A/AA + AAA)' : ''}: ${label}`, v.length === 0, v.join('; '));
}
async function login(p, user, pw) {
  await p.goto(`${BASE}/dashboard/login/`);
  await p.fill('#login-user', user); await p.fill('#login-pass', pw);
  await p.click('#login-btn');
  await p.waitForURL(/\/dashboard\/(\?.*)?$/, { timeout: 60000 });
  await p.waitForSelector('#dash-nav:not([hidden])');
}
/** The uploader: open the link in a fresh context, send one file with `password` → the page's final text. */
async function upload(link, name, password, { ctx } = {}) {
  const c = ctx || await b.newContext({ viewport: { width: 1280, height: 900 } });
  const u = await c.newPage();
  watch(u, { record: true });
  await u.goto(link);
  await u.waitForSelector('#reverse-page, #reverse-error', { timeout: 60000 });
  if (await u.locator('#reverse-error').count()) {
    const t = await u.textContent('#reverse-error');
    if (!ctx) await c.close();
    return { refused: t };
  }
  await u.setInputFiles('#reverse-file-input', [{ name, mimeType: 'text/plain', buffer: Buffer.from(`content of ${name}\n`) }]);
  if (password) await u.fill('#reverse-password', password);
  await u.click('#reverse-send');
  await u.waitForFunction(() => !document.querySelector('#reverse-done').hidden || /not right|no longer|cannot/.test(document.querySelector('#reverse-msg')?.textContent || ''), null, { timeout: 60000 });
  const done = await u.evaluate(() => (document.querySelector('#reverse-done').hidden ? null : document.querySelector('#reverse-done').textContent));
  const msg = await u.evaluate(() => document.querySelector('#reverse-msg')?.textContent || '');
  const limits = await u.evaluate(() => document.querySelector('#reverse-limits')?.textContent || '');
  if (!ctx) await c.close();
  return { done, msg, limits };
}
const receiveRow = (p) => p.locator('#shares-body tr', { has: p.locator('td[data-label="Type"]:text-is("receive")') }).first();

try {
  // ── the owner; alice, whose role allows links with no expiry ──
  const octx = await b.newContext({ viewport: { width: 1280, height: 900 } });
  const op = await octx.newPage();
  watch(op);
  await op.goto(`${BASE}/dashboard/setup/`);
  await op.fill('#setup-token', TOKEN); await op.fill('#setup-user', 'owner'); await op.fill('#setup-pass', PW); await op.fill('#setup-pass2', PW);
  await op.click('#setup-btn');
  await op.waitForFunction(() => /created/.test(document.querySelector('#setup-msg').textContent), null, { timeout: 30000 });
  await login(op, 'owner', PW);
  await op.goto(`${BASE}/dashboard/admin/`);
  await op.click('.tab[data-tab="users"]');
  const up = op.locator('.admin-panel[data-panel="users"]');
  await up.locator('input[aria-label="New username"]').first().fill('alice');
  await up.locator('input[aria-label="New user password"]').first().fill(ALICE_PW);
  await up.locator('input[aria-label="Repeat password"]').first().fill(ALICE_PW);
  await up.locator('button:has-text("Create user")').first().click();
  await op.waitForFunction(() => document.getElementById('toast').textContent === 'User created.', null, { timeout: 30000 });
  // The Default role: no link without an expiry, and its default hint in the role editor.
  await op.click('.tab[data-tab="roles"]');
  const defRow = await op.waitForSelector('.admin-panel[data-panel="roles"] tbody tr:has-text("Default")');
  await (await defRow.$('button:has-text("Edit")')).click();
  const noExpSel = op.locator('select[aria-label="Receive: links with no expiry allowed (they take files until revoked) mode"]').first();
  await noExpSel.waitFor();
  check('admin: the Default role has "no expiry" off, with its default hint', (await noExpSel.inputValue()) === 'false'
    && /default: no/.test(await noExpSel.locator('xpath=..').textContent()));
  const roleSet = await op.evaluate(async () => {
    const H = { 'content-type': 'application/json', 'x-secbin-intent': '1', 'x-secbin-csrf': (document.cookie.match(/__Host-secbin_csrf=([^;]+)/) || [])[1] || '' };
    const role = await (await fetch('/api/private/admin/roles', { method: 'POST', headers: H, body: JSON.stringify({ name: 'Receivers' }) })).json();
    const lim = await fetch('/api/private/admin/limits', { method: 'PATCH', headers: H, body: JSON.stringify({ scope: `role:${role.id}`, channel: 'all',
      patch: { driveEnabled: true, reverseEnabled: true, reverseNoExpiry: true, reverseMaxViews: 10, reverseCaptcha: 'off' } }) });
    const users = (await (await fetch('/api/private/admin/users')).json()).users;
    const alice = users.find((u) => u.username === 'alice');
    const set = await fetch(`/api/private/admin/users/${alice.id}/role`, { method: 'PUT', headers: H, body: JSON.stringify({ roleId: role.id }) });
    return lim.status === 200 && set.status === 200;
  });
  check('admin: a role with Receive links, no expiry allowed, at most 10 views, given to alice', roleSet);

  // ── alice: a link with no expiry, a password and 2 views ──
  const actx = await b.newContext({ viewport: { width: 1280, height: 900 } });
  const ap = await actx.newPage();
  watch(ap, { record: true });
  await login(ap, 'alice', ALICE_PW);
  await ap.goto(`${BASE}/dashboard/drive/`);
  await ap.waitForSelector('#drive-app', { timeout: 60000 });
  check('drive: the toolbar says "Receive…"', (await ap.textContent('#drive-receive')).trim() === 'Receive…');
  await ap.click('#drive-receive');
  await ap.waitForSelector('#drive-rev-none');
  check('receive dialog: titled "Receive into …"', (await ap.textContent('.drive-dialog .modal-title')) === 'Receive into “My Drive”');
  check('receive dialog: "No expiry" is offered (the role allows it); unlimited views pre-set', await ap.isVisible('#drive-rev-noexpire')
    && (await ap.getAttribute('#drive-rev-unlimited', 'aria-pressed')) === 'true');
  await ap.fill('#drive-rev-label', 'Forever inbox');
  await ap.check('#drive-rev-noexpire');
  check('receive dialog: "No expiry" disables the duration', await ap.isDisabled('#drive-rev-expire'));
  await ap.click('#drive-rev-unlimited');
  await ap.fill('#drive-rev-views', '2');
  await ap.check('#drive-rev-pw-on');
  await ap.fill('#drive-rev-pw', GATE1);
  await ap.fill('#drive-rev-pw2', GATE1);
  await ap.fill('#drive-rev-confirm', ALICE_PW);
  await audit(ap, 'Receive dialog with no expiry, views and a password');
  await ap.click('.drive-dialog button:has-text("Create link")');
  await ap.waitForSelector('#drive-rev-url', { timeout: 60000 });
  const link = (await ap.textContent('#drive-rev-url')).trim();
  check('link: made', /\/r\/r[A-Za-z0-9_-]{22}#[A-Za-z0-9_-]{87}$/.test(link), link);
  check('link: the dialog says it has no expiry and 2 views', /as long as the link is not revoked \(2 views\)/.test(await ap.textContent('.drive-dialog .modal-sub')));
  await ap.click('.drive-dialog button:has-text("Done")');

  // ── the uploader: twice, then refused ──
  const first = await upload(link, 'one.txt', GATE1);
  check('uploader: the page says the link has no expiry', /no expiry: it takes files until it is revoked/.test(first.limits), first.limits);
  check('uploader: the first upload', /^Sent 1 file/.test(first.done || ''), first.done || first.msg);
  const second = await upload(link, 'two.txt', GATE1);
  check('uploader: the second upload', /^Sent 1 file/.test(second.done || ''), second.done || second.msg);
  const third = await upload(link, 'three.txt', GATE1);
  check('uploader: the third visit is refused (its views are used up)', /no longer accepts files/.test(third.refused || ''), JSON.stringify(third));

  // ── alice: My shares — "No expiry", the filter, the Edit ──
  await ap.goto(`${BASE}/dashboard/shares/`);
  await ap.waitForSelector('#shares-body tr');
  let row = receiveRow(ap);
  check('My shares: the link says "No expiry"', (await row.locator('td[data-label="Expires"]').textContent()) === 'No expiry');
  check('My shares: its views are used up', /0 left of 2 views/.test(await row.locator('td[data-label="Views"]').textContent()), await row.locator('td[data-label="Views"]').textContent());
  await ap.selectOption('#shares-expiry', 'none');
  await ap.waitForFunction(() => [...document.querySelectorAll('#shares-body tr')].every((tr) => tr.querySelector('td[data-label="Expires"]')?.textContent === 'No expiry'), null, { timeout: 30000 });
  check('My shares: the "no expiry" filter', (await ap.locator('#shares-body tr').count()) === 1);
  row = receiveRow(ap);
  await row.locator('button:has-text("Edit")').click();
  await ap.waitForSelector('.extend-row .rev-edit', { timeout: 60000 });
  await audit(ap, 'My shares: Edit of a Receive link');
  const edit = ap.locator('.extend-row .rev-edit');
  await edit.locator('label.radio-opt:has-text("Change it") input').check();
  await edit.locator('input[id$="-pw"]').fill(GATE2);
  await edit.locator('input[id$="-pw2"]').fill(GATE2);
  await edit.locator('input[id$="-views"]').fill('4');
  await audit(ap, 'My shares: Edit with a new password', { aaa: false });
  await ap.click('.extend-row button:has-text("Save changes")');
  await ap.waitForFunction(() => /Upload link updated/.test(document.getElementById('toast').textContent), null, { timeout: 60000 });
  await ap.waitForFunction(() => [...document.querySelectorAll('#shares-body tr td[data-label="Views"]')].some((td) => /2 left of 4 views/.test(td.textContent)), null, { timeout: 30000 });
  check('My shares: saved (2 left of 4 views)', true);

  // ── the uploader: the old password refused, the new one sends ──
  const old = await upload(link, 'four.txt', GATE1);
  check('uploader: the old password is refused', !old.done && /not right/.test(old.msg), JSON.stringify(old));
  const fresh = await upload(link, 'five.txt', GATE2);
  check('uploader: the new password sends', /^Sent 1 file/.test(fresh.done || ''), fresh.done || fresh.msg);

  // ── alice: give it an expiry ──
  await ap.selectOption('#shares-expiry', '');
  await ap.waitForSelector('#shares-body tr');
  row = receiveRow(ap);
  await row.locator('button:has-text("Edit")').click();
  await ap.waitForSelector('.extend-row .rev-edit', { timeout: 60000 });
  check('Edit: a link with no expiry offers "Give it an expiry"', await ap.locator('.extend-row label.radio-opt:has-text("Give it an expiry")').count() === 1);
  await ap.locator('.extend-row label.radio-opt:has-text("Give it an expiry") input').check();
  await ap.locator('.extend-row input[id$="-expire"]').fill('3');
  await ap.click('.extend-row button:has-text("Save changes")');
  await ap.waitForFunction(() => /Upload link updated/.test(document.getElementById('toast').textContent), null, { timeout: 60000 });
  await ap.waitForFunction(() => [...document.querySelectorAll('#shares-body tr td[data-label="Expires"]')].some((td) => /^in (2d 23h|3d)/.test(td.textContent)), null, { timeout: 30000 });
  check('My shares: it now expires in 3 days', true);
  const after = await upload(link, 'six.txt', GATE2);
  check('uploader: the page shows the expiry; files still arrive', /The link expires /.test(after.limits) && /^Sent 1 file/.test(after.done || ''), JSON.stringify(after));
  // Given an expiry, it can no longer be shortened: only extended (as regular shares) — or made indefinite again.
  const shorter = await ap.evaluate(async () => {
    const rows = (await (await fetch('/api/private/shares')).json()).rows;
    const r = rows.find((x) => x.kind === 'reverse');
    const H = { 'content-type': 'application/json', 'x-secbin-csrf': (document.cookie.match(/__Host-secbin_csrf=([^;]+)/) || [])[1] || '' };
    const res = await fetch(`/api/private/shares/${r.id}`, { method: 'PATCH', headers: H, body: JSON.stringify({ expires: r.expires - 3600 }) });
    return res.status;
  });
  check('server: a shorter expiry is refused (400)', shorter === 400, String(shorter));

  // ── the Drive: the files arrived; nothing named or secret on the wire ──
  await ap.goto(`${BASE}/dashboard/drive/`);
  await ap.waitForSelector('#drive-app');
  await ap.waitForFunction(() => ['one.txt', 'two.txt', 'five.txt', 'six.txt'].every((n) => [...document.querySelectorAll('#drive-rows tr')].some((tr) => tr.children[1].textContent.trim() === n)), null, { timeout: 60000 });
  check('drive: the four accepted uploads are in the Drive (three.txt and four.txt never arrived)', await ap.evaluate(() => ![...document.querySelectorAll('#drive-rows tr')].some((tr) => /three|four/.test(tr.children[1].textContent))));
  const leaked = ['one.txt', 'two.txt', 'five.txt', 'content of', GATE1, GATE2, link.split('#')[1]].filter((w) => wire.some((x) => x.includes(w)));
  check('wire: no file name, content, password or link key was sent', leaked.length === 0, leaked.join(','));
  const log = await op.evaluate(async () => (await (await fetch('/api/private/admin/audit')).json()).rows.map((r) => `${r.action} ${r.detail}`));
  check('audit: created with no expiry and 2 views; the edit names what changed, never a value', log.some((x) => /^share\.created id=r\S+ kind=reverse.* expires=none views=2/.test(x))
    && log.some((x) => /^share\.updated id=r\S+ .*views=4.*password=set/.test(x)) && !log.some((x) => x.includes(GATE2)), log.filter((x) => /share\./.test(x)).slice(0, 6).join(' | '));

  check('no page errors, CSP or Trusted Types violations', errors.length === 0, errors.slice(0, 5).join(' | '));
} catch (e) {
  console.log(`E2E ERROR ${e.stack || e}`);
  results.push(false);
} finally {
  await b.close();
}
const passed = results.filter(Boolean).length;
console.log(`\n${passed}/${results.length} passed`);
process.exit(passed === results.length ? 0 : 1);
