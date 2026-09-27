// csrf.mjs — end to end: CSRF tokens (src/lib/csrf.js, public/js/api.js) in
// real Chromium against `wrangler dev`. A page acts for the session it was
// loaded for and sends that session's token; after a refusal it retries once
// only when the browser is still signed in as the same user, in the same
// impersonation state. So the user is never stuck, and a tab loaded for one
// user never changes another user's account:
//   • sign in and act;
//   • back and forward, including a restore from the back-forward cache, then act;
//   • two tabs: sign out and in again as the same user in one, act in the other
//     (it succeeds through the one retry); a token refused twice shows "Your
//     session changed in another tab; reload the page." with a Reload button;
//     sign out only, and the other tab gets the normal "session ended" message;
//     sign in as another user in one, and the other tab's change is refused
//     without a retry (the other user's account is untouched);
//   • a reload in the middle of a flow;
//   • impersonation start and end in another tab: a tab loaded before the
//     change is refused the same way, and acts again after Reload;
//   • Admin → Settings → CSRF tokens off and on again (the server really stops
//     and starts requiring the header), with axe (WCAG 2.2 A/AA) on the page
//     and on the "session changed" banner.
// Also: no CSP / Trusted Types violations and no page errors.
//
// A manual test, not run in CI. Needs a fresh `wrangler dev` (no owner yet),
// playwright-core and axe-core, and a Chromium. Usage:
//   BASE=http://localhost:9090 [WT=<repo checkout>] [E2E_DEPS=<dir with node_modules>] \
//     [CHROMIUM=<path to chrome>] node test-e2e/csrf.mjs
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WT = process.env.WT || path.resolve(HERE, '..');
const req = createRequire(process.env.E2E_DEPS ? path.join(process.env.E2E_DEPS, 'noop.js') : import.meta.url);
const { chromium } = req('playwright-core');
const AXE = readFileSync(req.resolve('axe-core/axe.min.js'), 'utf8');
const BASE = process.env.BASE;
if (!BASE) { console.error('usage: BASE=http://localhost:9090 node test-e2e/csrf.mjs'); process.exit(2); }
const TOKEN = /^AUTHN=(.*)$/m.exec(readFileSync(path.join(WT, '.dev.vars'), 'utf8'))[1].trim();
const PW = 'owner-password-123';
const DANA_PW = 'dana-password-123';
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22a', 'wcag22aa'];
const SESSION_CHANGED = 'Your session changed in another tab; reload the page.';

const results = [];
const check = (n, ok, x = '') => { results.push(!!ok); console.log(`${ok ? 'PASS' : 'FAIL'} ${n}${x ? ` — ${x}` : ''}`); };
const info = (n) => console.log(`INFO ${n}`);

// Pages without no-store are the usual bfcache candidates; the dashboard is
// no-store, so let Chromium keep such pages too (as current Chrome does for
// pages without an unload handler when the feature is on).
const b = await chromium.launch({
  ...(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {}),
  // Playwright turns the back-forward cache off by default; this suite needs it.
  ignoreDefaultArgs: ['--disable-back-forward-cache'],
  args: ['--enable-features=BackForwardCache,CacheControlNoStoreEnterBackForwardCache'],
});
const errors = [];
const violations = [];
const log = []; // "METHOD path status csrf=<header?>" for every API call
const watch = (p, tag) => {
  p.on('pageerror', (e) => errors.push(`${tag} pageerror: ${e.message}`));
  p.on('console', (m) => {
    if (m.type() !== 'error') return;
    if (/Content Security Policy|Trusted Type/i.test(m.text())) violations.push(`${tag}: ${m.text()}`);
    else if (!/status of (40[0-9]|410|429)/.test(m.text())) errors.push(`${tag} console: ${m.text()}`);
  });
  p.on('response', (r) => {
    const u = new URL(r.url());
    if (!u.pathname.startsWith('/api/')) return;
    log.push({ tag, method: r.request().method(), path: u.pathname, status: r.status(), csrf: r.request().headers()['x-secbin-csrf'] || '' });
  });
};
// Remember whether the page came back from the back-forward cache.
const initScript = () => { addEventListener('pageshow', (e) => { window.__restored = e.persisted; }); };
const newCtx = async () => { const c = await b.newContext(); await c.addInitScript(initScript); return c; };

const toast = (p, want) => p.waitForFunction((w) => { const t = document.getElementById('toast'); return t && t.textContent.includes(w); }, want, { timeout: 30000 }).then(() => true, () => false);
/** Empty the toast before an action, so that only the action's own message counts. */
const clearToast = (p) => p.evaluate(() => { const t = document.getElementById('toast'); if (t) t.textContent = ''; });
/** Change the first share's label on My shares (already open) and wait for the toast. */
async function relabel(p, label, want = 'Label saved') {
  const input = p.locator('input.label-in').first();
  await clearToast(p);
  await input.fill(label); await input.press('Tab');
  return toast(p, want);
}
const toastText = (p) => p.evaluate(() => document.getElementById('toast')?.textContent || '');
const csrfCookie = async (ctx) => (await ctx.cookies(BASE)).find((c) => c.name === '__Host-secbin_csrf');
/** Put `value` in the token cookie (or remove it), as page script could: a stale or missing token. */
const setCsrfCookie = (p, value) => p.evaluate((v) => {
  document.cookie = v ? `__Host-secbin_csrf=${v}; Path=/; Secure; SameSite=Strict` : '__Host-secbin_csrf=; Path=/; Secure; SameSite=Strict; Max-Age=0';
}, value);
/** A raw same-origin call from the page, with the given CSRF header (or none) — not through api.js. */
const raw = (p, method, url, body, token) => p.evaluate(async ([m, u, bd, t]) => {
  const headers = { 'content-type': 'application/json', ...(t ? { 'x-secbin-csrf': t } : {}) };
  const r = await fetch(u, { method: m, headers, body: bd === undefined ? undefined : JSON.stringify(bd) });
  return { status: r.status, error: (await r.json().catch(() => ({}))).error };
}, [method, url, body, token]);
/** An empty settings change through the page's own client (public/js/api.js). */
const settingsViaApi = (p) => p.evaluate(async () => {
  const { admin } = await import('/js/api.js');
  try { await admin.settings({}); return true; } catch { return false; }
});

async function signIn(p, user, pw) {
  await p.goto(`${BASE}/dashboard/login/`);
  await p.fill('#login-user', user); await p.fill('#login-pass', pw); await p.click('#login-btn');
  await p.waitForURL(`${BASE}/dashboard/`, { timeout: 60000 });
  await p.waitForSelector('#view-create:not([hidden])');
}
/** The composer, ready: "Create another" after a success, or the page itself. */
async function openComposer(p) {
  if (await p.isVisible('#view-success')) await p.click('#another');
  else if (!/^\/dashboard\/$/.test(new URL(p.url()).pathname)) await p.goto(`${BASE}/dashboard/`);
  await p.waitForSelector('#view-create:not([hidden])');
}
async function createNote(p, text, { open = true } = {}) {
  if (open) await openComposer(p);
  await p.fill('#editor', text);
  await p.click('#create');
  return p.waitForSelector('#view-success:not([hidden])', { timeout: 60000 }).then(() => true, () => false);
}
/** Try to create a note that must be refused: true when the "session changed" banner (with its Reload button) comes up. */
async function createNoteRefused(p, text) {
  await p.fill('#editor', text);
  await p.click('#create');
  return p.waitForSelector('#session-changed:not([hidden]) #session-reload', { timeout: 30000 }).then(() => true, () => false);
}
/** The labels of the shares of whoever `p`'s browser is signed in as now. */
const shareLabels = (p) => p.evaluate(async () => (await (await fetch('/api/private/shares')).json()).rows.map((x) => x.label ?? ''));
/** The API calls of tab `tag` since `mark`, share ids shortened. */
const seqOf = (tag, mark) => log.slice(mark).filter((x) => x.tag === tag).map((x) => `${x.method} ${x.path.replace(/[A-Za-z0-9_-]{23}$/, '<id>')} ${x.status}`).join(', ');
const bannerUp = (p) => p.isVisible('#session-changed').catch(() => false);
async function axe(p, label) {
  await p.evaluate(AXE);
  const v = await p.evaluate(async (tags) => {
    const r = await axe.run(document, { runOnly: { type: 'tag', values: tags }, resultTypes: ['violations'] });
    return r.violations.map((x) => `${x.id} (${x.impact}): ${x.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')}`);
  }, TAGS);
  check(`axe: ${label} has 0 violations`, v.length === 0, v.join('; '));
}

try {
  // ── setup: the owner, and a user for impersonation ──────────────────────
  const ctx = await newCtx();
  const p = await ctx.newPage();
  watch(p, 'A');
  await p.goto(`${BASE}/dashboard/setup/`);
  await p.fill('#setup-token', TOKEN); await p.fill('#setup-user', 'owner'); await p.fill('#setup-pass', PW); await p.fill('#setup-pass2', PW);
  await p.click('#setup-btn');
  await p.waitForFunction(() => /created|recovered/.test(document.querySelector('#setup-msg').textContent), null, { timeout: 60000 });

  // ── 1. sign in and act ──────────────────────────────────────────────────
  await signIn(p, 'owner', PW);
  const c1 = await csrfCookie(ctx);
  check('sign-in sets the readable __Host-secbin_csrf cookie', c1 && /^[A-Za-z0-9_-]{43}$/.test(c1.value) && c1.secure && !c1.httpOnly && c1.sameSite === 'Strict' && c1.path === '/', JSON.stringify(c1 && { ...c1, value: '…' }));
  const sess = (await ctx.cookies(BASE)).find((c) => c.name === '__Host-secbin_sess');
  check('the session cookie is still HttpOnly, Secure, SameSite=Strict', sess && sess.httpOnly && sess.secure && sess.sameSite === 'Strict');
  check('a note from the composer', await createNote(p, 'first note'));
  const created = log.filter((x) => x.method === 'POST' && x.path === '/api/private/paste').at(-1);
  check('…sent with the session’s token', created && created.status === 201 && created.csrf === c1.value);
  check('without the header the server refuses (403 csrf_mismatch)', (await raw(p, 'PATCH', '/api/private/admin/settings', {})).error === 'csrf_mismatch');

  // Create a user (dana) through the admin panel.
  await p.goto(`${BASE}/dashboard/admin/`);
  const users = p.locator('.admin-panel[data-panel="users"]');
  await users.locator('input[aria-label="New username"]').fill('dana');
  await users.locator('input[aria-label="New user password"]').fill(DANA_PW);
  await users.locator('input[aria-label="Repeat password"]').fill(DANA_PW);
  await users.locator('button:has-text("Create user")').click();
  check('admin: user created', await toast(p, 'User created'));

  // ── 2. back / forward, bfcache ─────────────────────────────────────────
  await p.goto(`${BASE}/dashboard/shares/`);
  await p.locator('input.label-in').first().waitFor();
  await p.goto(`${BASE}/dashboard/account/`);
  await p.waitForSelector('#name-form');
  await p.goBack();
  await p.locator('input.label-in').first().waitFor();
  const restoredBack = await p.evaluate(() => window.__restored === true);
  info(`back: ${restoredBack ? 'restored from the back-forward cache' : 'loaded again (not from the back-forward cache)'}`);
  check('after Back, an action on the page succeeds', await relabel(p, 'after back'));
  await p.goForward();
  await p.waitForSelector('#name-form');
  const restoredFwd = await p.evaluate(() => window.__restored === true);
  info(`forward: ${restoredFwd ? 'restored from the back-forward cache' : 'loaded again'}`);
  await p.fill('#name-new', 'owner2'); await p.fill('#name-current', PW); await p.click('#name-btn');
  check('after Forward, an action on the page succeeds (username change)', await p.waitForFunction(() => /changed|saved/i.test(document.querySelector('#name-msg')?.textContent || '') || /changed|saved/i.test(document.getElementById('toast')?.textContent || ''), null, { timeout: 60000 }).then(() => true, () => false), await toastText(p));
  // The dashboard is no-store, so Chromium reloads it on Back/Forward (above).
  // A real restore from the back-forward cache: a signed-in static page that
  // has loaded api.js, left while the session changes (sign out, sign in
  // again: a new token), then restored with all its JavaScript state.
  await p.goto(`${BASE}/accessibility/`);
  await p.evaluate(async () => { window.__api = await import('/js/api.js'); });
  const depth = await p.evaluate(() => history.length);
  const oldToken = (await csrfCookie(ctx)).value;
  await p.goto(`${BASE}/dashboard/`);
  await p.waitForSelector('#nav-logout');
  await p.click('#nav-logout');
  await p.waitForURL(/\/dashboard\/login\//);
  await signIn(p, 'owner2', PW);
  const newToken = (await csrfCookie(ctx)).value;
  check('the session changed while the page was away (new token)', newToken && newToken !== oldToken);
  const steps = (await p.evaluate(() => history.length)) - depth;
  await p.evaluate((n) => history.go(-n), steps);
  await p.waitForURL(`${BASE}/accessibility/`, { waitUntil: 'commit' });
  await p.waitForFunction(() => document.readyState === 'complete');
  const restored = await p.evaluate(() => window.__restored === true && !!window.__api);
  check('the back-forward cache restored the page with its state (pageshow persisted)', restored);
  let mark = log.length;
  const bf = await p.evaluate(async () => {
    try {
      const { rows } = await window.__api.listShares();
      await window.__api.updateShare(rows[0].id, { label: 'after bfcache restore' });
      return 'ok';
    } catch (e) { return `${e.status} ${e.code} ${e.message}`; }
  });
  check('after the restore, an action succeeds', bf === 'ok', bf);
  const bfPatch = log.slice(mark).filter((x) => x.method === 'PATCH');
  // (A page that recorded no session records the current one before its first change.)
  check('…on the first attempt, with the current session’s token (nothing stale was kept)', bfPatch.length === 1 && bfPatch[0].status === 200 && bfPatch[0].csrf === newToken, JSON.stringify(bfPatch.map((x) => x.status)));

  // ── 3. two tabs ─────────────────────────────────────────────────────────
  await p.goto(`${BASE}/dashboard/`);
  await p.waitForSelector('#nav-logout');
  const q = await ctx.newPage();
  watch(q, 'B');
  await q.goto(`${BASE}/dashboard/shares/`);
  await q.locator('input.label-in').first().waitFor();
  // Tab A signs out and in again: a new session, a new token.
  const before = (await csrfCookie(ctx)).value;
  await p.click('#nav-logout');
  await p.waitForURL(/\/dashboard\/login\//);
  check('sign-out clears the token cookie', !(await csrfCookie(ctx)));
  await signIn(p, 'owner2', PW);
  const after = (await csrfCookie(ctx)).value;
  check('a new sign-in has a new token', after && after !== before);
  // Tab B was loaded for the same user's old session and never reloaded.
  mark = log.length;
  check('tab B: acting after tab A signed out and in again as the same user succeeds', await relabel(q, 'from tab B'));
  check('…refused for the page’s old token, then /me (the same user), then retried once', seqOf('B', mark) === 'PATCH /api/private/shares/<id> 403, GET /api/private/me 200, PATCH /api/private/shares/<id> 200', seqOf('B', mark));
  check('…the retry carries the new token', log.slice(mark).some((x) => x.tag === 'B' && x.method === 'PATCH' && x.status === 200 && x.csrf === after));
  check('…and /me re-set the cookie to the current token', (await csrfCookie(ctx)).value === after);
  // The page sends its own session's token, whatever the cookie holds.
  await setCsrfCookie(q, before);
  check('…the cookie now holds the old token', (await csrfCookie(ctx))?.value === before);
  mark = log.length;
  check('tab B: a different value in the cookie changes nothing', await relabel(q, 'own token'));
  check('…first attempt, with the page’s session’s token', seqOf('B', mark) === 'PATCH /api/private/shares/<id> 200' && log.slice(mark).some((x) => x.tag === 'B' && x.csrf === after), seqOf('B', mark));
  // A token refused twice (a session that keeps changing): the reload message, with a Reload button.
  await q.route('**/api/private/shares/*', (route) => (route.request().method() === 'PATCH'
    ? route.continue({ headers: { ...route.request().headers(), 'x-secbin-csrf': 'Z'.repeat(43) } })
    : route.continue()));
  check('tab B: refused twice → “Your session changed in another tab; reload the page.”', await relabel(q, 'refused twice', SESSION_CHANGED), await toastText(q));
  await q.unroute('**/api/private/shares/*');
  check('…and the banner says so, with a Reload button', await bannerUp(q) && (await q.textContent('#session-changed')).includes(SESSION_CHANGED) && (await q.textContent('#session-reload')) === 'Reload');
  await axe(q, 'My shares with the “session changed” banner');
  await q.click('#session-reload');
  await q.locator('input.label-in').first().waitFor();
  check('Reload: the page acts again (the banner is gone)', !(await bannerUp(q)) && await relabel(q, 'after Reload'));
  // Tab A signs out only: in tab B the session really ended → the normal message, not a CSRF error.
  await p.click('#nav-logout');
  await p.waitForURL(/\/dashboard\/login\//);
  const ended = await relabel(q, 'signed out', 'Your session has ended');
  check('tab B after sign-out elsewhere: the normal “session has ended” message', ended, await toastText(q));
  check('…not a CSRF error', !(await toastText(q)).includes('reload the page'));
  // Another user: tab B is loaded for owner2, then tab A signs out and signs in as dana.
  await signIn(p, 'owner2', PW);
  await q.reload();
  await q.locator('input.label-in').first().waitFor();
  await p.click('#nav-logout');
  await p.waitForURL(/\/dashboard\/login\//);
  await signIn(p, 'dana', DANA_PW);
  const danaBefore = await shareLabels(p);
  mark = log.length;
  check('tab B (loaded for owner2) after tab A signed in as dana: the change is refused with “session changed”', await relabel(q, 'written on owner2’s page', SESSION_CHANGED), await toastText(q));
  check('…not retried: one refused change and one /me, nothing else', seqOf('B', mark) === 'PATCH /api/private/shares/<id> 403, GET /api/private/me 200', seqOf('B', mark));
  check('…dana’s account is unchanged', JSON.stringify(await shareLabels(p)) === JSON.stringify(danaBefore));
  check('…the banner with Reload is up', await bannerUp(q));
  // The page now acts for no one: a further change is not even sent.
  mark = log.length;
  await relabel(q, 'second try', SESSION_CHANGED);
  check('…a further change from that page is not sent at all', seqOf('B', mark) === '', seqOf('B', mark));
  // Its log-out does not end dana's session either.
  await q.click('#nav-logout');
  await q.waitForTimeout(1000);
  check('…and its log-out leaves dana signed in', (await p.evaluate(async () => (await (await fetch('/api/private/me')).json()).user?.username)) === 'dana');
  await q.click('#session-reload');
  await q.waitForSelector('#nav-logout');
  check('Reload: the page is now dana’s', (await q.evaluate(async () => (await (await fetch('/api/private/me')).json()).user?.username)) === 'dana' && !(await bannerUp(q)));
  await q.close();
  await p.goto(`${BASE}/dashboard/`);
  await p.waitForSelector('#nav-logout');
  await p.click('#nav-logout');
  await p.waitForURL(/\/dashboard\/login\//);

  // ── 4. a reload in the middle of a flow ─────────────────────────────────
  await signIn(p, 'owner2', PW);
  await p.fill('#editor', 'typed before the reload');
  // (the draft itself is not kept across a reload; the flow is started again)
  // The token cookie goes missing (e.g. storage cleared) mid-flow; the reload brings it back.
  await setCsrfCookie(p, null);
  check('…the token cookie is gone', !(await csrfCookie(ctx)));
  await p.reload();
  await p.waitForSelector('#view-create:not([hidden])');
  check('the reload re-set the token cookie', (await csrfCookie(ctx))?.value === after || /^[A-Za-z0-9_-]{43}$/.test((await csrfCookie(ctx))?.value || ''));
  mark = log.length;
  check('after the reload the flow completes (note created)', await createNote(p, 'after the reload'));
  check('…on the first attempt (no retry needed)', log.slice(mark).filter((x) => x.method === 'POST' && x.path === '/api/private/paste').map((x) => x.status).join() === '201');

  // ── 5. impersonation start / end with another tab open ──────────────────
  const r = await ctx.newPage();
  watch(r, 'C');
  await r.goto(`${BASE}/dashboard/`); // the owner's composer, left open
  await r.waitForSelector('#view-create:not([hidden])');
  const ownerToken = (await csrfCookie(ctx)).value;
  await p.goto(`${BASE}/dashboard/admin/`);
  await p.locator('.admin-panel[data-panel="users"] tr', { hasText: 'dana' }).locator('button', { hasText: 'Log in as' }).click();
  await p.waitForURL(`${BASE}/dashboard/`);
  await p.waitForSelector('#imp-banner:not([hidden])');
  const impToken = (await csrfCookie(ctx)).value;
  check('impersonation start changes the token', impToken && impToken !== ownerToken);
  // Tab C still shows the owner's page: it must not create a share in dana's account.
  const danaShares = await shareLabels(p);
  mark = log.length;
  check('tab C (loaded for the owner, impersonation started in another tab): its change is refused with “session changed”', await createNoteRefused(r, 'from tab C while impersonating'));
  check('…not retried', seqOf('C', mark) === 'POST /api/private/paste 403, GET /api/private/me 200', seqOf('C', mark));
  check('…dana’s account is unchanged', (await shareLabels(p)).length === danaShares.length);
  // Tab D is loaded while acting as dana; then impersonation ends in tab A.
  const d = await ctx.newPage();
  watch(d, 'D');
  await d.goto(`${BASE}/dashboard/`);
  await d.waitForSelector('#imp-banner:not([hidden])');
  await p.click('#imp-return');
  await p.waitForURL(`${BASE}/dashboard/admin/`);
  const endToken = (await csrfCookie(ctx)).value;
  check('impersonation end changes the token', endToken !== impToken && endToken !== ownerToken);
  const ownerShares = await shareLabels(p);
  mark = log.length;
  check('tab D (loaded while acting as dana, impersonation ended in another tab): its change is refused with “session changed”', await createNoteRefused(d, 'from tab D after impersonation ended'));
  check('…not retried', seqOf('D', mark) === 'POST /api/private/paste 403, GET /api/private/me 200', seqOf('D', mark));
  check('…the owner’s account is unchanged', (await shareLabels(p)).length === ownerShares.length);
  check('…the stale impersonation banner is hidden', !(await d.isVisible('#imp-banner')));
  await d.close();
  // Tab C, loaded for the owner: after Reload it acts for the owner again.
  await r.click('#session-reload');
  await r.waitForSelector('#view-create:not([hidden])');
  check('tab C after Reload: an action succeeds', await createNote(r, 'from tab C after returning'));
  check('…in the owner’s account', (await shareLabels(p)).length === ownerShares.length + 1);
  await r.close();

  // ── 6. Admin → Settings → CSRF tokens ───────────────────────────────────
  await p.click('.tab[data-tab="settings"]');
  await p.waitForSelector('#set-csrf');
  check('the switch is on by default', await p.isChecked('#set-csrf'));
  check('its help text is linked to it', (await p.getAttribute('#set-csrf', 'aria-describedby')) === 'set-csrf-help'
    && /SameSite cookies, the cross-site check, and the required JSON or intent header/.test(await p.textContent('#set-csrf-help')));
  await axe(p, 'Admin → Settings (CSRF tokens on)');
  await p.uncheck('#set-csrf');
  await p.click('#set-csrf-save');
  check('turning it off: toast', await toast(p, 'CSRF tokens are off.'));
  check('off: a change without the header is accepted', (await raw(p, 'PATCH', '/api/private/admin/settings', {})).status === 200);
  // (A page cannot forge Sec-Fetch-Site; test/csrf.test.js covers the cross-site refusal with the setting off.)
  check('off: the intent header is still required', (await p.evaluate(async () => (await (await fetch('/api/private/admin/ip-rules/AAAAAAAAAAAAAAAA', { method: 'DELETE' })).json()).error)) === 'missing_intent');
  await axe(p, 'Admin → Settings (CSRF tokens off)');
  await p.reload();
  await p.click('.tab[data-tab="settings"]');
  await p.waitForSelector('#set-csrf');
  check('the page shows it off after a reload', !(await p.isChecked('#set-csrf')));
  await p.check('#set-csrf');
  await p.click('#set-csrf-save');
  check('turning it back on: toast', await toast(p, 'CSRF tokens are on.'));
  check('on again: a change without the header is refused at once', (await raw(p, 'PATCH', '/api/private/admin/settings', {})).error === 'csrf_mismatch');
  check('on again: the page’s own client still works', await settingsViaApi(p));
  await p.click('.tab[data-tab="audit"]');
  const audited = await p.waitForFunction(() => document.querySelectorAll('.admin-panel[data-panel="audit"] tr').length > 1 && [...document.querySelectorAll('.admin-panel[data-panel="audit"] tr')].filter((tr) => tr.textContent.includes('settings.csrf')).length >= 2, null, { timeout: 30000 }).then(() => true, () => false);
  check('the admin audit shows both settings.csrf changes', audited);
} catch (e) {
  check('suite ran to the end', false, e.stack || String(e));
} finally {
  check('no CSP / Trusted Types violations', violations.length === 0, violations.slice(0, 3).join(' | '));
  check('no page errors', errors.length === 0, errors.slice(0, 5).join(' | '));
  await b.close();
  const failed = results.filter((x) => !x).length;
  console.log(`\n${results.length - failed}/${results.length} passed`);
  process.exit(failed ? 1 : 0);
}
