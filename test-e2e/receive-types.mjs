// receive-types.mjs — "Receive" links (reverse shares) that accept notes,
// links and credentials as well as files, end to end against the REAL server
// and pages (docs/REVERSE.md §3.1, §8): the owner gives alice a role whose
// links may accept every kind; alice makes a link that accepts a note, a
// link and a credential (and one that takes files only) in the Drive's
// Receive… dialog; an anonymous uploader sends a Markdown note with a title,
// a link and a credential through the uploader page's tabs (axe on each tab);
// a disallowed kind is refused (the files-only link; and once the role drops
// credentials, the credential tab is gone and a direct `begin` refused); alice
// opens her Drive, which takes them in and lists them with their kinds; each
// opens in its viewer (the note rendered, the link spelled out, the
// credential masked, then revealed; axe on each); and nothing on the wire
// carries a note's text, a link or a credential's fields. No page errors or
// CSP / Trusted Types violations. Synthetic data only. A manual test, not run
// in CI: see test-e2e/README.md. Needs a fresh `wrangler dev` (no owner yet),
// playwright-core and axe-core, and a Chromium.
//   WT=<repo checkout> BASE=http://localhost:9210 [CHROMIUM=<path>] node test-e2e/receive-types.mjs
import { chromium } from 'playwright-core';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';

const require = createRequire(import.meta.url);
const AXE = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const BASE = process.env.BASE;
const WT = process.env.WT;
if (!BASE || !WT) { console.error('usage: WT=<repo checkout> BASE=http://localhost:9210 node test-e2e/receive-types.mjs'); process.exit(2); }
const TOKEN = /^AUTHN=(.*)$/m.exec(readFileSync(path.join(WT, '.dev.vars'), 'utf8'))[1].trim();
const PW = 'owner-password-123';
const ALICE_PW = 'alice-password-123';
const NOTE_TITLE = 'Synthetic minutes';
const NOTE_TEXT = '# Minutes\n\n- **first** synthetic point\n- second point';
const LINK = 'https://example.com/synthetic/doc';
const CRED_USER = 'synthetic-operator';
const CRED_PW = 'synthetic-Pa55-not-real';
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22a', 'wcag22aa'];
const results = [];
const check = (n, ok, x = '') => { results.push(!!ok); console.log(`${ok ? 'PASS' : 'FAIL'} ${n}${x ? ' — ' + x : ''}`); };
const b = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
const errors = [];
const wire = []; // what the uploader's and the user's browsers sent to the API: [url, body]
const watch = (p, { record = false } = {}) => {
  p.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  p.on('console', (m) => {
    const t = m.text();
    if (m.type() === 'error' && (/Content Security Policy|Trusted Type/i.test(t) || !/status of (40[0-9]|41[0-9]|42[0-9])/.test(t))) errors.push(`console: ${t}`);
  });
  if (record) p.on('request', (r) => { if (/\/api\//.test(r.url())) { const d = r.postDataBuffer(); wire.push([r.url(), d ? d.toString('latin1') : '']); } });
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
const csrfFetch = (p, url, method, body) => p.evaluate(async ({ url, method, body }) => {
  const H = { 'content-type': 'application/json', 'x-secbin-intent': '1', 'x-secbin-csrf': (document.cookie.match(/__Host-secbin_csrf=([^;]+)/) || [])[1] || '' };
  const r = await fetch(url, { method, headers: H, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json().catch(() => null) };
}, { url, method, body });
/** A link made in the Drive's Receive… dialog accepting `kinds` → its URL. */
async function makeLink(ap, kinds, label) {
  await ap.click('#drive-receive');
  await ap.waitForSelector('#drive-rev-accept');
  for (const k of ['files', 'note', 'url', 'secret']) {
    const box = ap.locator(`#drive-rev-accept-${k}`);
    if (await box.count()) await box.setChecked(kinds.includes(k));
  }
  await ap.fill('#drive-rev-label', label);
  await ap.fill('#drive-rev-confirm', ALICE_PW);
  await ap.click('.drive-dialog button:has-text("Create link")');
  await ap.waitForSelector('#drive-rev-url', { timeout: 60000 });
  const url = (await ap.textContent('#drive-rev-url')).trim();
  const sub = await ap.textContent('.drive-dialog .modal-sub');
  await ap.click('.drive-dialog button:has-text("Done")');
  return { url, sub };
}
async function uploaderPage(link) {
  const c = await b.newContext({ viewport: { width: 1280, height: 900 } });
  const u = await c.newPage();
  watch(u, { record: true });
  await u.goto(link);
  await u.waitForSelector('#reverse-page, #reverse-error', { timeout: 60000 });
  return { c, u };
}
const sent = (u) => u.waitForFunction(() => !document.querySelector('#reverse-done').hidden || !document.querySelector('#reverse-msg').hidden, null, { timeout: 60000 });

try {
  // ── the owner; alice, whose role's links may accept every kind ──
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
  // The Default role: files and notes on, links and credentials off (Admin → Roles shows the four options).
  await op.click('.tab[data-tab="roles"]');
  const defRow = await op.waitForSelector('.admin-panel[data-panel="roles"] tbody tr:has-text("Default")');
  await (await defRow.$('button:has-text("Edit")')).click();
  const kindSel = (label) => op.locator(`select[aria-label="${label} mode"]`).first();
  await kindSel('Receive: links may accept notes (plain text, Markdown, code)').waitFor();
  const vals = [
    await kindSel('Receive: links may accept files and folders').inputValue(),
    await kindSel('Receive: links may accept notes (plain text, Markdown, code)').inputValue(),
    await kindSel('Receive: links may accept links (shown spelled out; the user’s URL rules decide what opens)').inputValue(),
    await kindSel('Receive: links may accept credentials (not end-to-end: the server can decrypt them, as all Drive content)').inputValue(),
  ];
  check('admin: the Default role — files and notes on, links and credentials off', vals.join() === 'true,true,false,false', vals.join());
  const made = await op.evaluate(async (pw) => {
    const H = { 'content-type': 'application/json', 'x-secbin-intent': '1', 'x-secbin-csrf': (document.cookie.match(/__Host-secbin_csrf=([^;]+)/) || [])[1] || '' };
    const role = await (await fetch('/api/private/admin/roles', { method: 'POST', headers: H, body: JSON.stringify({ name: 'Receivers' }) })).json();
    const patch = { driveEnabled: true, reverseEnabled: true, reverseUrl: true, reverseSecret: true, reverseCaptcha: 'off' };
    // Allowing links and credentials (and no CAPTCHA) weakens a control: refused without the owner's step-up…
    const bare = await fetch('/api/private/admin/limits', { method: 'PATCH', headers: H, body: JSON.stringify({ scope: `role:${role.id}`, channel: 'all', patch }) });
    const refused = { status: bare.status, ...(await bare.json()) };
    // …and saved with it (the password stretched as the admin page's confirm.js does).
    const { prelogin } = await import('/js/api.js');
    const { stretch } = await import('/js/pwauth.js');
    const { salt, t } = await prelogin('owner');
    const lim = await fetch('/api/private/admin/limits', { method: 'PATCH', headers: H, body: JSON.stringify({ scope: `role:${role.id}`, channel: 'all', patch, current: await stretch(pw, salt, t) }) });
    const users = (await (await fetch('/api/private/admin/users')).json()).users;
    const alice = users.find((u) => u.username === 'alice');
    const set = await fetch(`/api/private/admin/users/${alice.id}/role`, { method: 'PUT', headers: H, body: JSON.stringify({ roleId: role.id }) });
    return { refused, roleId: lim.status === 200 && set.status === 200 ? role.id : null };
  }, PW);
  check('admin: allowing links and credentials needs the step-up (400 reauth_required naming reverseUrl, reverseSecret)', made.refused.status === 400 && made.refused.error === 'reauth_required'
    && ['reverseUrl', 'reverseSecret'].every((k) => (made.refused.weakens || []).includes(k)), JSON.stringify(made.refused));
  const roleId = made.roleId;
  check('admin: a role whose links may accept links and credentials too, given to alice', !!roleId);

  // ── alice: a link for a note, a link and a credential; and one for files only ──
  const actx = await b.newContext({ viewport: { width: 1280, height: 900 } });
  const ap = await actx.newPage();
  watch(ap, { record: true });
  await login(ap, 'alice', ALICE_PW);
  await ap.goto(`${BASE}/dashboard/drive/`);
  await ap.waitForSelector('#drive-app', { timeout: 60000 });
  await ap.click('#drive-receive');
  await ap.waitForSelector('#drive-rev-accept');
  const offered = await ap.$$eval('#drive-rev-accept input[type="checkbox"]', (els) => els.map((e) => `${e.value}:${e.checked}`));
  check('Receive dialog: a box per kind the role allows, files ticked', offered.join() === 'files:true,note:false,url:false,secret:false', offered.join());
  await audit(ap, 'Receive dialog with "What senders can send"');
  await ap.click('.drive-dialog button:has-text("Cancel")');
  const typed = await makeLink(ap, ['note', 'url', 'secret'], 'Typed inbox');
  check('link: made, accepting notes, links and credentials', /\/r\/r[A-Za-z0-9_-]{22}#[A-Za-z0-9_-]{87}$/.test(typed.url) && /can send notes, links or credentials into/.test(typed.sub), typed.sub);
  const filesOnly = await makeLink(ap, ['files'], 'Files only');

  // ── the uploader: a note, a link and a credential, through the tabs ──
  const { c: uc, u } = await uploaderPage(typed.url);
  const tabs = await u.$$eval('#reverse-tabs [role="tab"]', (els) => els.map((e) => e.textContent));
  check('uploader: one tab per accepted kind', tabs.join() === 'Note,Link,Credential', tabs.join());
  check('uploader: the heading says what can be sent', (await u.textContent('h1')) === 'Send a note, a link or a credential');
  await audit(u, 'uploader: the Note tab');
  await u.fill('#reverse-note-title', NOTE_TITLE);
  await u.selectOption('#reverse-note-fmt', 'markdown');
  await u.fill('#reverse-note-text', NOTE_TEXT);
  await u.click('#reverse-send');
  await sent(u);
  check('uploader: the note is sent', /^Sent the note, encrypted/.test(await u.textContent('#reverse-done')), await u.textContent('#reverse-done'));
  await u.click('#reverse-tab-url');
  await audit(u, 'uploader: the Link tab');
  await u.fill('#reverse-link-in', LINK);
  check('uploader: the link\'s destination is spelled out', (await u.textContent('#reverse-link-host')) === `Destination: ${new URL(LINK).hostname}`);
  await u.click('#reverse-send');
  await sent(u);
  check('uploader: the link is sent', /^Sent the link, encrypted/.test(await u.textContent('#reverse-done')), await u.textContent('#reverse-done'));
  await u.click('#reverse-tab-secret');
  check('uploader: the credential form warns that the server can decrypt it', /^The recipient’s server can decrypt this\./.test(await u.textContent('#reverse-sec-warning')));
  await audit(u, 'uploader: the Credential tab');
  await u.fill('#reverse-sec-title', 'Synthetic staging');
  await u.fill('#reverse-sec-username', CRED_USER);
  await u.fill('#reverse-sec-password', CRED_PW);
  await u.click('#reverse-send');
  await sent(u);
  check('uploader: the credential is sent', /^Sent the credential, encrypted/.test(await u.textContent('#reverse-done')), await u.textContent('#reverse-done'));
  check('uploader: the credential fields are cleared', (await u.inputValue('#reverse-sec-password')) === '' && (await u.inputValue('#reverse-sec-username')) === '');
  await audit(u, 'uploader: after sending');
  await uc.close();

  // ── a kind the link does not accept is refused ──
  const { c: fc, u: fu } = await uploaderPage(filesOnly.url);
  check('files-only link: no tabs, "Send files"', (await fu.locator('#reverse-tabs').count()) === 0 && (await fu.textContent('h1')) === 'Send files');
  await audit(fu, 'uploader: a files-only link');
  const refused = await fu.evaluate(async () => {
    const { openLink } = await import('/js/reverseclient.js');
    const upl = await openLink({ pathname: location.pathname, hash: location.hash });
    try { await upl.begin({ type: 'note' }); return 'started'; } catch (e) { return `${e.status} ${e.code}`; }
  });
  check('server: a note to a files-only link is refused (403 kind_not_accepted)', refused === '403 kind_not_accepted', refused);
  await fc.close();
  // The role drops credentials: the tab is gone, and a direct start is refused.
  const drop = await csrfFetch(op, '/api/private/admin/limits', 'PATCH', { scope: `role:${roleId}`, channel: 'all', patch: { reverseSecret: false } });
  check('admin: credentials turned off for the role', drop.status === 200, JSON.stringify(drop));
  const { c: dc, u: du } = await uploaderPage(typed.url);
  const tabs2 = await du.$$eval('#reverse-tabs [role="tab"]', (els) => els.map((e) => e.textContent));
  check('uploader: the role now allows no credentials — no Credential tab', tabs2.join() === 'Note,Link', tabs2.join());
  const refused2 = await du.evaluate(async () => {
    const { openLink } = await import('/js/reverseclient.js');
    const upl = await openLink({ pathname: location.pathname, hash: location.hash });
    try { await upl.begin({ type: 'secret' }); return 'started'; } catch (e) { return `${e.status} ${e.code}`; }
  });
  check('server: a credential is refused at send time once the role drops it', refused2 === '403 kind_not_accepted', refused2);
  await dc.close();
  // Back on before the take-in: a kind the role no longer allows fails there too (audit RT-1; the DOM and
  // workerd suites cover that), and the credential sent above is taken in below.
  const ownerProof = await op.evaluate(async (pw) => {
    const { prelogin } = await import('/js/api.js');
    const { stretch } = await import('/js/pwauth.js');
    const { salt, t } = await prelogin('owner');
    return stretch(pw, salt, t);
  }, PW);
  const back = await csrfFetch(op, '/api/private/admin/limits', 'PATCH', { scope: `role:${roleId}`, channel: 'all', patch: { reverseSecret: true }, current: ownerProof });
  check('admin: credentials turned back on for the role', back.status === 200, JSON.stringify(back));

  // ── alice: the Drive takes them in; each opens in its viewer ──
  await ap.goto(`${BASE}/dashboard/drive/`);
  await ap.waitForSelector('#drive-app', { timeout: 60000 });
  await ap.waitForFunction(() => /New items you received were added to your folders: 1 note, 1 link and 1 credential/.test(document.querySelector('#drive-received')?.textContent || ''), null, { timeout: 60000 });
  check('drive: the take-in says what arrived', true);
  await ap.waitForFunction(() => document.querySelectorAll('#drive-rows tr[data-item]').length === 3, null, { timeout: 60000 });
  const listed = await ap.$$eval('#drive-rows tr[data-item]', (trs) => trs.map((tr) => `${tr.dataset.item}:${tr.querySelector('.drive-kind').textContent}:${tr.children[1].textContent.includes('from') || tr.children[1].textContent.includes('Synthetic minutes')}`).sort());
  check('drive: listed with their kinds and names', listed.join() === 'note:Note:true,secret:Credential:true,url:Link:true', listed.join());
  await audit(ap, 'drive: the folder with a note, a link and a credential');
  const openRow = async (kind) => ap.locator(`#drive-rows tr[data-item="${kind}"] button.drive-open`).click();
  await openRow('note');
  await ap.waitForSelector('#drive-item-note .md h1');
  check('viewer: the note, Markdown rendered', (await ap.textContent('#drive-item-note h1')) === 'Minutes' && (await ap.textContent('#drive-item-note strong')) === 'first');
  check('viewer: the note is titled by its title', (await ap.textContent('.drive-dialog .modal-title')) === NOTE_TITLE);
  await audit(ap, 'drive viewer: a note');
  await ap.click('.drive-dialog button:has-text("Close")');
  await openRow('url');
  await ap.waitForSelector('.drive-dialog .link-card');
  // Hosts compared as parsed URLs' (never a substring match).
  const shownHost = new URL((await ap.textContent('.drive-dialog .link-full')).trim()).hostname;
  check('viewer: the link spelled out, with Open (https, allowed by the rules)', shownHost === new URL(LINK).hostname && (await ap.textContent('.drive-dialog .link-host')) === shownHost
    && (await ap.locator('.drive-dialog .link-card button:has-text("Open link")').count()) === 1);
  await audit(ap, 'drive viewer: a link');
  await ap.click('.drive-dialog button:has-text("Close")');
  await openRow('secret');
  await ap.waitForSelector('.drive-dialog .secret-card');
  const masked = await ap.textContent('.drive-dialog .secret-card');
  check('viewer: the credential masked', !masked.includes(CRED_PW) && masked.includes(CRED_USER));
  await audit(ap, 'drive viewer: a credential');
  await ap.click('.drive-dialog button[aria-label="Reveal password"]');
  check('viewer: Reveal shows the password', (await ap.textContent('.drive-dialog .secret-card')).includes(CRED_PW));
  await ap.click('.drive-dialog button:has-text("Close")');

  // ── nothing of what was sent on the wire (only the kind, declared at begin) ──
  const bodies = wire.map((x) => x[1]).join('\n');
  const leaked = [NOTE_TITLE, 'first** synthetic', LINK, 'example.com/synthetic', CRED_USER, CRED_PW, 'Synthetic staging', typed.url.split('#')[1]].filter((w) => bodies.includes(w));
  check('wire: no note text or title, link, credential field or link key was sent', leaked.length === 0, leaked.join(','));
  const declared = wire.filter((x) => /\/begin$/.test(x[0])).map((x) => x[1]);
  check('wire: each start declared only its kind', declared.join('|') === '{"type":"note"}|{"type":"url"}|{"type":"secret"}|{"type":"note"}|{"type":"secret"}', declared.join('|'));
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
