// receive-api.mjs — "Receive" links through their API, with receipts, pause /
// resume and a change of folder, end to end against the REAL server and pages
// (docs/REVERSE.md §5, §6.1, §8; docs/API.md "Receive links"): the Drive's
// "Receive…" stays disabled until the open folder has listed; alice makes a
// link on a folder; an uploader sends (the page says a send is recorded);
// an API key with read / manage lists the link, reads its receipts (the
// details the owner lets alice see), is refused a weakening change (403
// step_up_required) and pauses it — the uploader page then says it is not
// accepting files — and My shares resumes it; a file waits (not taken in),
// the link moves to another folder in My shares' Edit (the folder tree), the
// waiting file and a new one land there, the folders' Shares dialogs follow
// the move; a folder past the role's depth is refused; the owner sees the
// receipts in Admin → Shares; the log names the changes. axe (WCAG 2.2 A/AA,
// and the AAA contrast rule) on each new state; nothing on the wire names a
// file; no page errors or CSP / Trusted Types violations. Synthetic data
// only. A manual test, not run in CI: see test-e2e/README.md. Needs a fresh
// `wrangler dev` (no owner yet), playwright-core and axe-core, and a Chromium.
//   WT=<repo checkout> BASE=http://localhost:9390 [CHROMIUM=<path>] node test-e2e/receive-api.mjs
import { chromium } from 'playwright-core';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';

const require = createRequire(import.meta.url);
const AXE = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const BASE = process.env.BASE;
const WT = process.env.WT;
if (!BASE || !WT) { console.error('usage: WT=<repo checkout> BASE=http://localhost:9390 node test-e2e/receive-api.mjs'); process.exit(2); }
const TOKEN = /^AUTHN=(.*)$/m.exec(readFileSync(path.join(WT, '.dev.vars'), 'utf8'))[1].trim();
const PW = 'owner-password-123';
const ALICE_PW = 'alice-password-123';
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22a', 'wcag22aa'];
const results = [];
const check = (n, ok, x = '') => { results.push(!!ok); console.log(`${ok ? 'PASS' : 'FAIL'} ${n}${x ? ' — ' + x : ''}`); };
const b = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
const errors = [];
const wire = [];
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
const exact = (s) => new RegExp(`^${s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`);
const rowOf = (p, name) => p.locator('#drive-rows tr', { has: p.locator('td:nth-child(2) bdi.fname', { hasText: exact(name) }) });
const hasRow = (n) => [...document.querySelectorAll('#drive-rows tr')].some((tr) => tr.children[1].textContent.trim() === n);
const titleIs = (n) => document.querySelector('#drive-pane-title')?.textContent === n;
async function mkdirUI(p, name) {
  await p.click('#drive-mkdir');
  await p.waitForSelector('.drive-dialog input');
  await p.fill('.drive-dialog input', name);
  await p.keyboard.press('Enter');
  await p.waitForFunction(hasRow, name, { timeout: 30000 });
}
async function openUI(p, name) {
  await rowOf(p, name).locator('button.drive-open').click();
  await p.waitForFunction(titleIs, name, { timeout: 30000 });
}
/** The uploader: open the link in a fresh context and send one file → { done, msg, refused, note }. */
async function upload(link, name) {
  const c = await b.newContext({ viewport: { width: 1280, height: 900 }, userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36', locale: 'he-IL' });
  const u = await c.newPage();
  watch(u, { record: true });
  await u.goto(link);
  await u.waitForSelector('#reverse-page, #reverse-error', { timeout: 60000 });
  if (await u.locator('#reverse-error').count()) {
    const t = await u.textContent('#reverse-error');
    await c.close();
    return { refused: t };
  }
  const note = await u.textContent('#reverse-receipt-note');
  await u.setInputFiles('#reverse-file-input', [{ name, mimeType: 'text/plain', buffer: Buffer.from(`content of ${name}\n`) }]);
  await u.click('#reverse-send');
  await u.waitForFunction(() => !document.querySelector('#reverse-done').hidden || (document.querySelector('#reverse-msg') && !document.querySelector('#reverse-msg').hidden), null, { timeout: 60000 });
  const done = await u.evaluate(() => (document.querySelector('#reverse-done').hidden ? null : document.querySelector('#reverse-done').textContent));
  const msg = await u.evaluate(() => document.querySelector('#reverse-msg')?.textContent || '');
  await c.close();
  return { done, msg, note };
}
/** A request with the API key, from Node (no browser, no cookie). */
async function api(key, pathname, { method = 'GET', body, headers = {} } = {}) {
  const res = await fetch(`${BASE}${pathname}`, { method, headers: { authorization: `Bearer ${key}`, ...(body ? { 'content-type': 'application/json' } : {}), ...headers }, body: body ? JSON.stringify(body) : undefined });
  return { status: res.status, body: await res.json().catch(() => null) };
}
const csrfHeaders = `({ 'content-type': 'application/json', 'x-secbin-intent': '1', 'x-secbin-csrf': (document.cookie.match(/__Host-secbin_csrf=([^;]+)/) || [])[1] || '' })`;
const receiveRow = (p) => p.locator('#shares-body tr', { has: p.locator('td[data-label="Type"]:text-is("receive")') }).first();

try {
  // ── the owner; alice, whose role has Receive links, API keys, receipt details and a folder depth of 1 ──
  const octx = await b.newContext({ viewport: { width: 1280, height: 900 } });
  const op = await octx.newPage();
  watch(op);
  await op.goto(`${BASE}/dashboard/setup/`);
  await op.fill('#setup-token', TOKEN); await op.fill('#setup-user', 'owner'); await op.fill('#setup-pass', PW); await op.fill('#setup-pass2', PW);
  if (await op.$('#setup-keys-gen')) { await op.click('#setup-keys-gen'); await op.click('#setup-keys-use'); }
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
  const setRole = (patch) => op.evaluate(async ({ pw, patch, H }) => {
    const headers = new Function(`return ${H}`)();
    let role = (await (await fetch('/api/private/admin/roles')).json()).roles?.find((r) => r.name === 'Receivers');
    if (!role) role = await (await fetch('/api/private/admin/roles', { method: 'POST', headers, body: JSON.stringify({ name: 'Receivers' }) })).json();
    const { stretch } = await import('/js/pwauth.js');
    const { salt, t } = await (await fetch('/api/auth/prelogin', { method: 'POST', headers, body: JSON.stringify({ username: 'owner' }) })).json();
    const lim = await fetch('/api/private/admin/limits', { method: 'PATCH', headers, body: JSON.stringify({ scope: `role:${role.id}`, channel: 'all', patch, current: await stretch(pw, salt, t) }) });
    const users = (await (await fetch('/api/private/admin/users')).json()).users;
    const alice = users.find((u) => u.username === 'alice');
    const set = await fetch(`/api/private/admin/users/${alice.id}/role`, { method: 'PUT', headers, body: JSON.stringify({ roleId: role.id }) });
    return lim.status === 200 && set.status === 200;
  }, { pw: PW, patch, H: csrfHeaders });
  check('admin: a role with Receive links, API keys, receipt details and folders 1 level deep, given to alice',
    await setRole({ driveEnabled: true, reverseEnabled: true, reverseCaptcha: 'off', apiEnabled: true, receiptIp: true, receiptBrowser: true, maxFolderDepth: 1 }));

  // ── alice: "Receive…" waits for the listing; two folders; a link on "Inbox" ──
  const actx = await b.newContext({ viewport: { width: 1280, height: 900 } });
  const ap = await actx.newPage();
  watch(ap, { record: true });
  await login(ap, 'alice', ALICE_PW);
  let release;
  const held = new Promise((r) => { release = r; });
  await ap.route('**/api/private/drive/nodes/root', async (route) => { await held; await route.continue(); });
  await ap.goto(`${BASE}/dashboard/drive/`);
  await ap.waitForSelector('#drive-receive', { timeout: 60000 });
  check('drive: "Receive…" is disabled while the open folder lists', await ap.isDisabled('#drive-receive'));
  release();
  await ap.waitForFunction(titleIs, 'My Drive', { timeout: 60000 });
  await ap.unroute('**/api/private/drive/nodes/root');
  check('drive: "Receive…" is enabled once it has listed', await ap.isEnabled('#drive-receive'));
  await mkdirUI(ap, 'Inbox');
  await mkdirUI(ap, 'Archive');
  await openUI(ap, 'Archive');
  // The role's depth (1) is lifted a moment to make a folder at level 2, then put back.
  await setRole({ maxFolderDepth: null });
  await ap.reload();
  await ap.waitForFunction(titleIs, 'My Drive', { timeout: 60000 });
  await openUI(ap, 'Archive');
  await mkdirUI(ap, 'Deep');
  await setRole({ maxFolderDepth: 1 });
  await ap.goto(`${BASE}/dashboard/drive/`);
  await ap.waitForFunction(titleIs, 'My Drive', { timeout: 60000 });
  await openUI(ap, 'Inbox');
  await ap.click('#drive-receive');
  await ap.waitForSelector('#drive-rev-none');
  check('receive dialog: names the open folder', (await ap.textContent('.drive-dialog .modal-title')) === 'Receive into “Inbox”');
  await ap.fill('#drive-rev-label', 'Scans');
  await ap.fill('#drive-rev-confirm', ALICE_PW);
  await ap.click('.drive-dialog button:has-text("Create link")');
  await ap.waitForSelector('#drive-rev-url', { timeout: 60000 });
  const link = (await ap.textContent('#drive-rev-url')).trim();
  const linkId = /\/r\/(r[A-Za-z0-9_-]{22})#/.exec(link)?.[1];
  check('link: made on Inbox', !!linkId, link);
  await ap.click('.drive-dialog button:has-text("Done")');

  // ── an uploader sends: the page says a send is recorded ──
  const first = await upload(link, 'first.txt');
  check('uploader: the page says a send is recorded for the recipient', /^Sending is recorded for the recipient and the administrator/.test(first.note || ''), first.note);
  check('uploader: the first file is sent', /^Sent 1 file/.test(first.done || ''), first.done || first.msg);
  // The Drive takes it in when it opens: into Inbox.
  await ap.goto(`${BASE}/dashboard/drive/`);
  await ap.waitForFunction(titleIs, 'My Drive', { timeout: 60000 });
  await ap.waitForFunction(() => /added/.test(document.querySelector('#drive-received')?.textContent || ''), null, { timeout: 60000 });
  await openUI(ap, 'Inbox');
  await ap.waitForFunction(hasRow, 'first.txt', { timeout: 60000 });
  check('drive: the first file was taken into Inbox', true);

  // ── an API key with read and manage (made in the page, confirmed with the password) ──
  const key = await ap.evaluate(async ({ pw, H }) => {
    const headers = new Function(`return ${H}`)();
    const { stretch } = await import('/js/pwauth.js');
    const { salt, t } = await (await fetch('/api/auth/prelogin', { method: 'POST', headers, body: JSON.stringify({ username: 'alice' }) })).json();
    const r = await fetch('/api/private/me/keys', { method: 'POST', headers, body: JSON.stringify({ name: 'receive tool', scopes: ['read', 'manage'], current: await stretch(pw, salt, t) }) });
    return (await r.json()).key;
  }, { pw: ALICE_PW, H: csrfHeaders });
  check('API key: made with read and manage', /^sbk_/.test(key || ''));
  const list = await api(key, '/api/private/receive');
  const l = list.body?.rows?.[0];
  check('API: lists the link with its folder, what it accepts and one session', list.status === 200 && l?.id === linkId && l.label === 'Scans' && l.accept.join() === 'files' && l.opens === 1 && l.paused === false && /^[A-Za-z0-9_-]{22}$/.test(l.folder), JSON.stringify(l));
  check('API: never the link\'s key', !JSON.stringify(list.body).includes(link.split('#')[1]) && !('priv' in (l || {})));
  const inboxId = l?.folder;
  const receipts = await api(key, `/api/private/receive/${linkId}/opens`);
  check('API: the receipt of the session, with the details the owner lets alice see', receipts.status === 200 && receipts.body.total === 1
    && receipts.body.fields.join() === 'receiptIp,receiptBrowser' && receipts.body.rows[0].browser === 'Chrome' && 'ip' in receipts.body.rows[0] && !('langs' in receipts.body.rows[0]), JSON.stringify(receipts.body));
  const weak = await api(key, `/api/private/receive/${linkId}`, { method: 'PATCH', body: { views: 5 } });
  check('API: a tightening change works (5 views)', weak.status === 200 && weak.body.views === 5, JSON.stringify(weak.body));
  const weaker = await api(key, `/api/private/receive/${linkId}`, { method: 'PATCH', body: { views: null } });
  check('API: a weakening change is refused (403 step_up_required)', weaker.status === 403 && weaker.body.error === 'step_up_required' && weaker.body.weakens.join() === 'views', JSON.stringify(weaker.body));
  const create = await api(key, '/api/private/drive/reverse', { method: 'POST', body: {}, headers: { 'x-secbin-intent': '1' } });
  check('API: a key cannot create a link', create.status === 403 && create.body.error === 'api_key_not_allowed');

  // ── paused through the API: the uploader is told; My shares resumes it ──
  const paused = await api(key, `/api/private/receive/${linkId}/pause`, { method: 'POST', headers: { 'x-secbin-intent': '1' } });
  check('API: paused', paused.status === 200 && paused.body.paused === true, JSON.stringify(paused.body));
  const refused = await upload(link, 'while-paused.txt');
  check('uploader: a paused link says it is not accepting files', /not accepting files right now/.test(refused.refused || ''), JSON.stringify(refused));
  await ap.goto(`${BASE}/dashboard/shares/`);
  await ap.waitForSelector('#shares-body tr');
  let row = receiveRow(ap);
  check('My shares: a "paused" badge (paused by you) and Resume', await row.locator('span.pill:text-is("paused")').count() === 1
    && /Paused by you/.test(await row.locator('span.pill:text-is("paused")').getAttribute('title')) && await row.locator('button:text-is("Resume")').count() === 1);
  check('My shares: its receipts count the session', (await row.locator('td[data-label="Opened"] button').textContent()) === '1 upload session');
  await row.locator('td[data-label="Opened"] button').click();
  await ap.waitForSelector('.opens-row table');
  check('My shares: the receipts table (started at, address, browser)', (await ap.locator('.opens-row thead th').allTextContents()).join('|') === 'Started at|Address|Browser');
  await audit(ap, 'My shares: a paused Receive link with its receipts');
  await row.locator('button:text-is("Resume")').click();
  await ap.waitForFunction(() => /resumed/.test(document.getElementById('toast').textContent), null, { timeout: 30000 });
  row = receiveRow(ap);
  await row.locator('button:text-is("Pause")').waitFor({ timeout: 30000 });
  check('My shares: resumed (Pause offered again, no badge)', await row.locator('span.pill:text-is("paused")').count() === 0);

  // ── a file waits (the Drive not opened), the link moves to "Archive" in My shares' Edit ──
  const waiting = await upload(link, 'waiting.txt');
  check('uploader: sends again once resumed', /^Sent 1 file/.test(waiting.done || ''), waiting.done || waiting.msg);
  row = receiveRow(ap);
  await row.locator('button:has-text("Edit")').click();
  await ap.waitForSelector('.extend-row .rev-edit', { timeout: 60000 });
  const box = ap.locator('.extend-row fieldset.rev-edit-folder');
  await box.locator('button:text-is("Choose another folder…")').click();
  await box.locator('[role="tree"]').waitFor({ timeout: 60000 });
  await ap.waitForFunction(() => /^Uploads go to: My Drive \/ Inbox\.$/.test(document.querySelector('.extend-row [id$="-folder-now"]')?.textContent || ''), null, { timeout: 30000 });
  check('Edit: the folder group says where uploads go now', true);
  // A folder past the role's depth (Archive / Deep): refused before anything is sent.
  const archiveItem = box.locator('[role="treeitem"]', { has: ap.locator(':scope > .tree-label .tree-text', { hasText: exact('Archive') }) });
  await archiveItem.locator(':scope > .tree-label .tree-twisty').click();
  const deepItem = box.locator('[role="treeitem"]', { has: ap.locator(':scope > .tree-label .tree-text', { hasText: exact('Deep') }) });
  await deepItem.waitFor({ timeout: 30000 });
  await deepItem.locator(':scope > .tree-label').click();
  await ap.click('.extend-row button:has-text("Save changes")');
  await ap.waitForFunction(() => /at most 1 level deep/.test(document.querySelector('.extend-row p.msg.error')?.textContent || ''), null, { timeout: 30000 });
  check('Edit: a folder deeper than the role allows is refused in the form', true);
  const deepApi = await ap.evaluate(async ({ id, H }) => {
    const headers = new Function(`return ${H}`)();
    const nodes = (await (await fetch('/api/private/drive/nodes/root')).json()).children.filter((c) => c.kind === 'dir');
    const out = [];
    for (const n of nodes) {
      const kids = (await (await fetch(`/api/private/drive/nodes/${n.id}`)).json()).children.filter((c) => c.kind === 'dir');
      for (const k of kids) out.push((await fetch(`/api/private/receive/${id}`, { method: 'PATCH', headers, body: JSON.stringify({ folder: k.id }) })).json());
    }
    return Promise.all(out);
  }, { id: linkId, H: csrfHeaders });
  check('server: that folder is refused too (403 folder_too_deep)', deepApi.length === 1 && deepApi[0].error === 'folder_too_deep' && deepApi[0].max === 1, JSON.stringify(deepApi));
  await archiveItem.locator(':scope > .tree-label').click();
  check('Edit: the new folder is announced', (await box.locator('[id$="-folder-new"]').textContent()) === 'New folder: My Drive / Archive');
  await audit(ap, 'My shares: Edit with the folder tree open');
  await ap.click('.extend-row button:has-text("Save changes")');
  await ap.waitForFunction(() => /Upload link updated/.test(document.getElementById('toast').textContent), null, { timeout: 60000 });
  const moved = await api(key, `/api/private/receive/${linkId}`);
  check('API: the link receives into another folder now', moved.body?.link?.folder && moved.body.link.folder !== inboxId, JSON.stringify(moved.body?.link));
  const later = await upload(link, 'later.txt');
  check('uploader: sends into the new folder', /^Sent 1 file/.test(later.done || ''), later.done || later.msg);

  // ── the Drive: the waiting and the new file are in Archive; the folders' Shares follow the move ──
  await ap.goto(`${BASE}/dashboard/drive/`);
  await ap.waitForFunction(titleIs, 'My Drive', { timeout: 60000 });
  await openUI(ap, 'Archive');
  await ap.waitForFunction(() => ['waiting.txt', 'later.txt'].every((n) => [...document.querySelectorAll('#drive-rows tr')].some((tr) => tr.children[1].textContent.trim() === n)), null, { timeout: 60000 });
  check('drive: the file that waited and the new one are in Archive', true);
  await ap.goto(`${BASE}/dashboard/drive/`);
  await ap.waitForFunction(titleIs, 'My Drive', { timeout: 60000 });
  await openUI(ap, 'Inbox');
  check('drive: Inbox holds only what was taken in before the move', await ap.evaluate(() => [...document.querySelectorAll('#drive-rows tr')].map((tr) => tr.children[1].textContent.trim()).join() === 'first.txt'));
  await ap.goto(`${BASE}/dashboard/drive/`);
  await ap.waitForFunction(titleIs, 'My Drive', { timeout: 60000 });
  const sharesOf = async (name) => {
    await rowOf(ap, name).locator('button:has-text("Shares")').click();
    await ap.waitForSelector('.drive-dialog #drive-shares-table, .drive-dialog #drive-shares-empty', { timeout: 30000 });
    const kinds = await ap.locator('.drive-dialog #drive-shares-table tbody tr').evaluateAll((rs) => rs.map((r) => r.dataset.kind));
    return kinds;
  };
  const inboxShares = await sharesOf('Inbox');
  check('drive: Inbox\'s Shares no longer list the link', inboxShares.length === 0, inboxShares.join());
  await ap.keyboard.press('Escape');
  await ap.waitForSelector('.drive-dialog', { state: 'detached' });
  const archiveShares = await sharesOf('Archive');
  check('drive: Archive\'s Shares list it, with Pause', archiveShares.join() === 'reverse' && await ap.locator('.drive-dialog button:text-is("Pause")').count() === 1, archiveShares.join());
  await audit(ap, 'the Drive: a folder\'s Shares with Pause');
  await ap.click('.drive-dialog button:text-is("Pause")');
  await ap.waitForSelector('.drive-dialog button:text-is("Resume")', { timeout: 30000 });
  check('drive: paused from the Shares dialog (Resume offered)', (await api(key, `/api/private/receive/${linkId}`)).body.link.paused === true);
  await ap.click('.drive-dialog button:text-is("Resume")');
  await ap.waitForSelector('.drive-dialog button:text-is("Pause")', { timeout: 30000 });
  await ap.keyboard.press('Escape');

  // ── the owner: the receipts in Admin → Shares; the log ──
  await op.goto(`${BASE}/dashboard/admin/`);
  await op.click('.tab[data-tab="shares"]');
  const orow = op.locator('.admin-panel[data-panel="shares"] tbody tr', { has: op.locator('td[data-label="Type"]:text-is("receive")') }).first();
  await orow.waitFor({ timeout: 30000 });
  const sessions = await orow.locator('td[data-label="Opened"] button').textContent();
  check('admin: Admin → Shares counts the link\'s upload sessions', sessions === '3 upload sessions', sessions);
  await orow.locator('td[data-label="Opened"] button').click();
  await op.waitForSelector('.opens-row table');
  check('admin: the owner sees every detail (languages too)', (await op.locator('.opens-row thead th').allTextContents()).includes('Languages'));
  await audit(op, 'Admin → Shares: a Receive link\'s receipts');
  const log = await op.evaluate(async () => (await (await fetch('/api/private/admin/audit')).json()).rows.map((r) => `${r.action} ${r.detail}`));
  const mine = log.filter((x) => x.includes(linkId || '-'));
  check('audit: paused (with the key), resumed, moved (by the folder id), the views change', mine.some((x) => /^share\.updated .* paused .*apikey=/.test(`${x} `))
    && mine.some((x) => /^share\.updated .* resumed/.test(x)) && mine.some((x) => /^share\.updated .*folder=[A-Za-z0-9_-]{22}/.test(x)) && mine.some((x) => /views=5 .*apikey=/.test(x)), mine.slice(0, 8).join(' | '));
  check('audit: never the API key', !log.some((x) => x.includes(key)));

  const leaked = ['first.txt', 'waiting.txt', 'later.txt', 'content of', link.split('#')[1]].filter((w) => wire.some((x) => x.includes(w)));
  check('wire: no file name, content or link key was sent', leaked.length === 0, leaked.join(','));
  check('no page errors, CSP or Trusted Types violations', errors.length === 0, errors.slice(0, 5).join(' | '));
} catch (e) {
  console.log(`E2E ERROR ${e.stack || e}`);
  if (errors.length) console.log(`page errors: ${errors.slice(0, 5).join(' | ')}`);
  results.push(false);
} finally {
  await b.close();
}
const passed = results.filter(Boolean).length;
console.log(`\n${passed}/${results.length} passed`);
process.exit(passed === results.length ? 0 : 1);
