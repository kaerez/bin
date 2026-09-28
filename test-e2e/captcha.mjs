// captcha.mjs — CAPTCHA on shares end to end (the shareCaptcha / reverseCaptcha
// role options; SECURITY.md "CAPTCHA on shares") against the REAL server,
// client and Cloudflare Turnstile widget (Cloudflare's testing keys, which
// always pass): the role editor's radios; the per-share boxes of the
// composer, the Drive's Share and Receive files dialogs; a protected note, a
// protected file share, a protected Drive share and a protected reverse link,
// each through its check page (the Turnstile CSP, no key there) and back on
// its strict page (the key back, no Turnstile script); an unprotected note and
// an unprotected link with no check at all; an API recipient refused; My
// shares and Admin → Shares badges; a user whose role requires it; axe
// (WCAG 2.2 A/AA) on the new states; no page errors or CSP / Trusted Types
// violations.
//
// A fresh server with Turnstile's testing keys, on http://localhost:
//   npx wrangler dev --port 9140 --persist-to <fresh dir> \
//     --var TURNSTILE_SITEKEY:1x00000000000000000000AA --var TURNSTILE_SECRET:1x0000000000000000000000000000000AA
//   WT=$PWD BASE=http://localhost:9140 PROXY_SPKI=<the egress proxy CA's SPKI, when there is one> node test-e2e/captcha.mjs
// (CHROMIUM=/path/to/chrome to use that browser; npm install --no-save playwright-core axe-core first.)
import { chromium } from 'playwright-core';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { webcrypto } from 'node:crypto';
import http from 'node:http';
import path from 'node:path';

const require = createRequire(import.meta.url);
const AXE = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');
const BASE = process.env.BASE;
const WT = process.env.WT;
if (!BASE || !WT) { console.error('usage: WT=<worktree> BASE=http://localhost:9140 node captcha.mjs'); process.exit(2); }
const TOKEN = /^AUTHN=(.*)$/m.exec(readFileSync(path.join(WT, '.dev.vars'), 'utf8'))[1].trim();
const PW = 'owner-password-123';
const NORA_PW = 'nora-password-123';
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22a', 'wcag22aa'];
const TS_ORIGIN = 'https://challenges.cloudflare.com';
const results = [];
const check = (n, ok, x = '') => { results.push(!!ok); console.log(`${ok ? 'PASS' : 'FAIL'} ${n}${x && !ok ? ` — ${x}` : ''}`); };
const launch = {
  ...(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {}),
  ...(process.env.HTTPS_PROXY ? { proxy: { server: process.env.HTTPS_PROXY, bypass: '127.0.0.1,localhost' } } : {}),
  ...(process.env.PROXY_SPKI ? { args: [`--ignore-certificate-errors-spki-list=${process.env.PROXY_SPKI}`] } : {}),
};
const b = await chromium.launch(launch);
const errors = [];
const watch = (p) => {
  p.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  p.on('console', (m) => {
    const t = m.text();
    // Turnstile's iframe asks for features the Permissions-Policy denies (on every Turnstile page): not ours.
    if (/^Potential permissions policy violation/.test(t)) return;
    if (m.type() === 'error' && (/Content Security Policy|Trusted Type/i.test(t) || !/status of (40[0-9]|41[0-9]|42[0-9])/.test(t))) errors.push(`console: ${t}`);
  });
};
/** Every main-frame document response of `p`: { url, csp, coep }. */
const navs = (p) => {
  const list = [];
  p.on('response', (r) => {
    if (r.request().isNavigationRequest() && r.frame() === p.mainFrame()) list.push({ url: r.url(), status: r.status(), csp: r.headers()['content-security-policy'] || '', coep: r.headers()['cross-origin-embedder-policy'] || null });
  });
  return list;
};
/** A CSP header as { directive: [source, …] } (exact tokens, never substrings). */
const cspOf = (csp) => Object.fromEntries(String(csp || '').split(';').map((d) => d.trim().split(/\s+/)).filter((t) => t[0]).map(([k, ...v]) => [k.toLowerCase(), v]));
/** The strict CSP: no directive allows any other origin, and nothing may be framed. */
const strict = (csp) => {
  const d = cspOf(csp);
  return Object.keys(d).length > 0 && Object.values(d).every((v) => !v.some((t) => /^https?:/i.test(t))) && d['frame-src']?.join(' ') === "'none'";
};
/** The Turnstile CSP: Cloudflare's origin (and no other) added to script-src, and frame-src exactly it. */
const tsCsp = (csp) => {
  const d = cspOf(csp);
  return d['script-src']?.join(' ') === `'self' 'wasm-unsafe-eval' ${TS_ORIGIN}` && d['frame-src']?.join(' ') === TS_ORIGIN;
};
/** A URL's query and fragment, parsed. */
const hasParam = (u, k) => new URL(u).searchParams.has(k);
const isCheck = (u) => new URL(u).search === '?check';
async function axeOf(p) {
  await p.evaluate(AXE);
  return p.evaluate(async (tags) => {
    // eslint-disable-next-line no-undef
    const r = await axe.run(document, { runOnly: { type: 'tag', values: tags }, resultTypes: ['violations'] });
    return r.violations.map((x) => `${x.id} (${x.impact}): ${x.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')}`);
  }, TAGS);
}
async function audit(p, label) {
  const v = await axeOf(p);
  check(`axe: ${label}`, v.length === 0, v.join('; '));
}
const storageText = (p) => p.evaluate(() => { const o = {}; for (let i = 0; i < sessionStorage.length; i++) { const k = sessionStorage.key(i); o[k] = sessionStorage.getItem(k); } return JSON.stringify(o); });
// No Turnstile object and no script from any origin but the page's own (parsed origins, not substrings).
const noTurnstileHere = (p) => p.evaluate(() => typeof window.turnstile === 'undefined' && ![...document.scripts].some((s) => s.src && new URL(s.src, location.href).origin !== location.origin));
async function login(p, user, pw) {
  await p.goto(`${BASE}/dashboard/login/`);
  await p.fill('#login-user', user); await p.fill('#login-pass', pw);
  await p.waitForFunction(() => !document.querySelector('#login-btn').disabled, null, { timeout: 60000 });
  await p.click('#login-btn');
  await p.waitForURL(/\/dashboard\/(\?.*)?$/, { timeout: 60000 });
}
/** An admin tab, once the page has wired its tabs (admin.js sets aria-controls when ready). */
async function openTab(p, name) {
  // The page opens Users first (after its overview): wait for that before choosing a tab.
  await p.waitForSelector('.admin-panel[data-panel="users"] input[aria-label="New username"]', { state: 'attached', timeout: 30000 });
  await p.waitForSelector(`.tab[data-tab="${name}"][aria-controls]`, { timeout: 30000 });
  await p.click(`.tab[data-tab="${name}"]`);
  await p.waitForSelector(`.admin-panel[data-panel="${name}"]:not([hidden])`, { timeout: 30000 });
}
async function editRole(p, name) {
  const row = p.locator('.admin-panel[data-panel="roles"] tbody tr', { hasText: name }).first();
  await row.waitFor({ timeout: 30000 });
  await row.locator('button', { hasText: 'Edit' }).click();
}
/** Pass a check page: Continue enabled once the widget has a token, then back on the share's page. */
async function passCheck(p) {
  await p.waitForSelector('#check-continue');
  await p.waitForFunction(() => !document.querySelector('#check-continue').disabled, null, { timeout: 60000 });
  await p.click('#check-continue');
}
/** The composer on the dashboard: a note (unlimited views when asked) → its link. */
async function composeNote(p, text, { captcha, unlimited = false } = {}) {
  await p.goto(`${BASE}/dashboard/`);
  await p.waitForSelector('#editor');
  await p.fill('#editor', text);
  if (unlimited) await p.click('#views-unlimited');
  if (captcha !== undefined) await p.setChecked('#captcha', captcha);
  await p.click('#create');
  await p.waitForFunction(() => /\/p\//.test(document.querySelector('#paste-url').textContent), null, { timeout: 60000 });
  return p.textContent('#paste-url');
}
const idOf = (url) => /\/(?:p|r)\/([^#?]+)/.exec(url)[1];
const keyOf = (url) => url.split('#')[1];
async function recipient() {
  const ctx = await b.newContext({ acceptDownloads: true, viewport: { width: 1280, height: 900 }, reducedMotion: 'reduce' });
  const p = await ctx.newPage();
  watch(p);
  return { ctx, p, nav: navs(p) };
}
/** A view-limited share asks before it spends the view ("Open files"): open it. */
async function openFiles(p) {
  await p.waitForSelector('#reveal-burn:not([disabled]), #files-tree .file-card', { timeout: 60000 });
  if (await p.isVisible('#reveal-burn')) await p.click('#reveal-burn');
  await p.waitForSelector('#files-tree .file-card', { timeout: 60000 });
}
async function downloadedText(p) {
  const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 60000 }), p.click('#files-tree .file-card button:has-text("Download")')]);
  return readFileSync(await dl.path(), 'utf8');
}
const dialogButton = (p, text) => p.locator('.drive-dialog [role="dialog"] button', { hasText: text }).first();
const TEXT_FILE = 'the protected file content\n';
const DRIVE_FILE = 'a drive file behind a CAPTCHA\n';

try {
  // ── the owner ─────────────────────────────────────────────────────────────
  const octx = await b.newContext({ viewport: { width: 1280, height: 900 }, reducedMotion: 'reduce' });
  const op = await octx.newPage();
  watch(op);
  await op.goto(`${BASE}/dashboard/setup/`);
  await op.fill('#setup-token', TOKEN); await op.fill('#setup-user', 'owner'); await op.fill('#setup-pass', PW); await op.fill('#setup-pass2', PW);
  await op.click('#setup-btn');
  await op.waitForFunction(() => /created/.test(document.querySelector('#setup-msg').textContent), null, { timeout: 30000 });
  await login(op, 'owner', PW);

  // Admin → Roles → Default: the CAPTCHA options as radios.
  await op.goto(`${BASE}/dashboard/admin/`);
  await openTab(op, 'roles');
  await editRole(op, 'Default');
  const shares = op.locator('fieldset.captcha-role', { has: op.locator(':scope > legend', { hasText: 'CAPTCHA on shares' }) });
  await shares.waitFor({ timeout: 30000 });
  const allow = shares.getByLabel('Allow CAPTCHA (user chooses per share)', { exact: true });
  check('roles: the Default role has the CAPTCHA radios; "Allow" checked, its "Default for new shares" shown',
    await allow.isChecked() && await shares.getByLabel('Require CAPTCHA for all shares').count() === 1 && await shares.getByLabel('Disable CAPTCHA').count() === 1
    && await shares.locator('fieldset.captcha-default').isVisible() && await shares.getByLabel('CAPTCHA off').isChecked());
  check('roles: no "not active" warning (Turnstile is configured)', await shares.locator('p.warn').count() === 0);
  await audit(op, 'Admin → Roles → Default (the CAPTCHA radios)');

  // The composer: the owner may choose; off by default.
  await op.goto(`${BASE}/dashboard/`);
  await op.waitForSelector('#captcha-opt:not([hidden])', { timeout: 30000 });
  check('composer: "Require CAPTCHA to open" shown, off by default for the owner, and explained',
    !(await op.isChecked('#captcha')) && !(await op.isDisabled('#captcha')) && /Recipients complete a CAPTCHA/.test(await op.textContent('#captcha-hint')));
  await audit(op, 'composer with the CAPTCHA box');

  // ── notes ─────────────────────────────────────────────────────────────────
  const plainUrl = await composeNote(op, 'an open note', { captcha: false, unlimited: true });
  const protUrl = await composeNote(op, 'a note behind a CAPTCHA', { captcha: true, unlimited: true });
  let r = await recipient();
  await r.p.goto(plainUrl);
  await r.p.waitForFunction(() => document.querySelector('#paste-content')?.textContent.includes('an open note'), null, { timeout: 60000 });
  check('unprotected note: opens at once, no check page and no Turnstile script', !r.nav.some((n) => hasParam(n.url, 'check')) && await noTurnstileHere(r.p));
  check('unprotected note: its page has the strict CSP (and COEP)', strict(r.nav[0].csp) && r.nav[0].coep === 'require-corp', r.nav[0].csp);
  await r.ctx.close();

  r = await recipient();
  const K = keyOf(protUrl);
  await r.p.goto(protUrl);
  await r.p.waitForURL((u) => u.search === '?check', { timeout: 30000 });
  check('protected note: the page goes to its check page at once', r.p.url() === `${BASE}/p/${idOf(protUrl)}?check`, r.p.url());
  const checkNav = r.nav.find((n) => isCheck(n.url));
  check('protected note: the check page has the Turnstile CSP (no COEP)', checkNav && tsCsp(checkNav.csp) && checkNav.coep === null, checkNav?.csp);
  await r.p.waitForSelector('#check-continue');
  check('check page: Continue disabled until the CAPTCHA passes', await r.p.isDisabled('#check-continue'));
  check('protected note: the key is nowhere on the check page (address, page, sessionStorage)',
    !r.p.url().includes(K) && !(await r.p.content()).includes(K) && !(await storageText(r.p)).includes(K) && (await r.p.textContent('#check-title')) === 'Complete the CAPTCHA to open this share');
  await r.p.waitForSelector('#check-widget iframe, #check-widget input[name="cf-turnstile-response"]', { state: 'attached', timeout: 60000 });
  await audit(r.p, 'the check page (a note)');
  await r.p.waitForFunction(() => !document.querySelector('#check-continue').disabled, null, { timeout: 60000 });
  check('check page: Continue enabled once the CAPTCHA passed (testing key)', !(await r.p.isDisabled('#check-continue')));
  await r.p.click('#check-continue');
  await r.p.waitForFunction(() => document.querySelector('#paste-content')?.textContent.includes('a note behind a CAPTCHA'), null, { timeout: 60000 });
  check('protected note: back on its page, the note decrypts', true);
  check('protected note: the key is back in the address bar, the sealed copy gone from sessionStorage',
    r.p.url() === `${BASE}/p/${idOf(protUrl)}#${K}` && !/secbin_pk:/.test(await storageText(r.p)), r.p.url());
  const back = r.nav.at(-1);
  check('protected note: the decrypting document has the strict CSP and no Turnstile script', hasParam(back.url, 'n') && strict(back.csp) && await noTurnstileHere(r.p), back.url);
  const before = r.nav.length;
  await r.p.reload();
  await r.p.waitForFunction(() => document.querySelector('#paste-content')?.textContent.includes('a note behind a CAPTCHA'), null, { timeout: 60000 });
  check('protected note: a reload in the same tab opens it with the kept grant (no second CAPTCHA)', !r.nav.slice(before).some((n) => hasParam(n.url, 'check')));
  await r.ctx.close();
  r = await recipient();
  await r.p.goto(protUrl);
  await r.p.waitForURL((u) => u.search === '?check', { timeout: 30000 });
  check('protected note: another browser session (no grant) gets the check page again', true);
  await r.ctx.close();

  // An API (or CLI) recipient cannot pass it.
  const api = await fetch(`${BASE}/api/paste/${idOf(protUrl)}`);
  const apiBody = await api.json();
  check('API: a recipient without a grant gets 403 captcha_required, "open it in a browser"', api.status === 403 && apiBody.error === 'captcha_required' && apiBody.message === 'This share requires a CAPTCHA; open it in a browser.', JSON.stringify(apiBody));
  const hr = await fetch(`${BASE}/api/paste/${idOf(protUrl)}/human`, { method: 'POST', headers: { 'x-secbin-intent': '1' } });
  check('API: a grant needs a Turnstile token (403 turnstile_required)', hr.status === 403 && (await hr.json()).error === 'turnstile_required');

  // ── the page key: the audit's proofs of concept, as regressions (F1) ──────
  // A tab that holds Drive keys (synthetic) opens the protected note: on the
  // check page there is no Drive key, the sealed record holds the link's key
  // alone, and the page key is in an HttpOnly cookie a script cannot read.
  {
    const ctx = await b.newContext({ viewport: { width: 1280, height: 900 }, reducedMotion: 'reduce' });
    const p = await ctx.newPage(); // not watched: the probes below provoke CSP refusals on purpose
    await p.goto(`${BASE}/accessibility/`);
    await p.evaluate(() => { sessionStorage.setItem('secbin_dk', 'SYNTHETIC-DRIVE-KEY'); sessionStorage.setItem('secbin_dk_uid', 'u-synthetic'); });
    await p.goto(protUrl);
    await p.waitForURL((u) => u.search === '?check', { timeout: 30000 });
    await p.waitForSelector('#check-continue');
    const id = idOf(protUrl);
    const seen = await p.evaluate((sid) => ({ keys: Object.keys(sessionStorage), rec: sessionStorage.getItem(`secbin_pk:p:${sid}`), cookie: document.cookie }), id);
    check('check page: the tab holds no Drive key (removed, never sealed)', !seen.keys.some((k) => k.startsWith('secbin_dk')) && !JSON.stringify(seen).includes('SYNTHETIC-DRIVE-KEY'), seen.keys.join(','));
    check('check page: the page key is not readable by its scripts (HttpOnly cookie)', !seen.cookie.includes('secbin_pk'), seen.cookie);
    const { n, iv, ct } = JSON.parse(seen.rec);
    // PoC F1: an outside client with the navigation's Fetch Metadata, but no cookie, gets no page key.
    const raw = (u, headers) => new Promise((res, rej) => http.get(u, { headers }, (x) => { let d = ''; x.on('data', (c) => { d += c; }); x.on('end', () => res({ body: d, cookie: x.headers['set-cookie'] || null })); }).on('error', rej));
    const nav = { 'sec-fetch-dest': 'document', 'sec-fetch-mode': 'navigate', 'sec-fetch-site': 'same-origin' };
    const forged = await raw(`${BASE}/p/${id}?n=${n}`, nav);
    check('PoC F1: forged navigation headers without the cookie get no page key (and no cookie)', !/secbin-page-key/.test(forged.body) && forged.cookie === null);
    // PoC F1: a same-origin fetch() from the check document (it sends the cookie) gets no key either.
    const fetched = await p.evaluate(async (u) => (await (await fetch(u, { credentials: 'same-origin' })).text()).includes('secbin-page-key'), `/p/${id}?n=${n}`);
    check('PoC F1: fetch() from the check document gets no page key', fetched === false);
    // What the record holds (opened here with the browser's own cookie, as only the strict page could).
    const pk = (await ctx.cookies(BASE)).find((c) => c.name === '__Secure-secbin_pk');
    check('the page key cookie: HttpOnly, Secure, SameSite=Strict, scoped to the share\'s path, 15 minutes',
      pk && pk.httpOnly && pk.secure && pk.sameSite === 'Strict' && pk.path === `/p/${id}` && pk.expires > Date.now() / 1000 && pk.expires <= Date.now() / 1000 + 900 + 5, JSON.stringify(pk));
    const [cn, ckey] = pk.value.split('.');
    const b64 = (x) => Buffer.from(x.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    const aesKey = await webcrypto.subtle.importKey('raw', b64(ckey), { name: 'AES-GCM' }, false, ['decrypt']);
    const plain = JSON.parse(new TextDecoder().decode(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv: b64(iv), additionalData: new TextEncoder().encode(`secbin-page/v1\np\n${id}\n${n}\n`) }, aesKey, b64(ct))));
    check('the sealed record holds the link\'s key and nothing else', cn === n && JSON.stringify(Object.keys(plain)) === '["k"]' && plain.k === K, JSON.stringify(Object.keys(plain)));
    // Framing and popups from the check document.
    const probe = await p.evaluate(async (sid) => {
      const w = window.open(`/p/${sid}`, '_blank');
      await new Promise((res) => setTimeout(res, 3000));
      let popupReadable;
      try { popupReadable = !!(w && w.document && w.document.body); } catch { popupReadable = false; }
      const f = document.createElement('iframe');
      f.src = `/p/${sid}`;
      document.body.append(f);
      await new Promise((res) => setTimeout(res, 2000));
      let frameReadable;
      try { frameReadable = !!(f.contentDocument && f.contentDocument.querySelector('script[src="/js/view.js"]')); } catch { frameReadable = false; }
      let swRegistered = true;
      try { await navigator.serviceWorker.register('/sw.js'); } catch { swRegistered = false; }
      return { popupHandle: !!w, popupClosed: !w || w.closed, popupReadable, frameReadable, swRegistered };
    }, id);
    check('check page: a popup it opens to the strict page gives it no readable handle (another browsing context group)', probe.popupClosed && !probe.popupReadable, JSON.stringify(probe));
    check('check page: the strict page cannot be framed there', !probe.frameReadable, JSON.stringify(probe));
    check('check page: no service worker can be registered from it (worker-src \'none\')', !probe.swRegistered, JSON.stringify(probe));
    for (const pg of ctx.pages()) if (pg !== p) await pg.close();
    // A cross-origin page cannot frame the strict page either (frame-ancestors 'none').
    const fp = await ctx.newPage();
    await fp.setContent(`<iframe src="${BASE}/p/${id}"></iframe>`);
    await fp.waitForTimeout(2000);
    const child = fp.frames().find((f) => f !== fp.mainFrame());
    let framed = false;
    try { framed = !!child && await child.evaluate(() => !!document.querySelector('script[src="/js/view.js"]')); } catch { framed = false; }
    check('the strict page refuses to be framed (frame-ancestors \'none\')', !framed);
    await ctx.close();
  }
  // The app's own service worker still registers from normal pages.
  {
    const ctx = await b.newContext();
    const p = await ctx.newPage();
    watch(p);
    await p.goto(`${BASE}/`);
    const sw = await p.evaluate(async () => {
      const reg = await Promise.race([navigator.serviceWorker.ready, new Promise((res) => setTimeout(() => res(null), 15000))]);
      return reg && reg.active ? new URL(reg.active.scriptURL).pathname : null;
    });
    check('the app\'s service worker still registers from normal pages (/sw.js)', sw === '/sw.js', String(sw));
    await ctx.close();
  }
  // Opened from another site: that navigation gets no page key, so the page reloads itself once (?pk) and goes on.
  {
    r = await recipient();
    const other = BASE.replace('//localhost', '//127.0.0.1');
    await r.p.goto(`${other}/accessibility/`);
    await r.p.evaluate((u) => { const a = document.createElement('a'); a.href = u; a.id = 'x-link'; a.textContent = 'the link'; document.body.append(a); }, protUrl);
    await r.p.click('#x-link');
    await r.p.waitForURL((u) => u.search === '?check', { timeout: 30000 });
    const first = r.nav.find((x) => new URL(x.url).host === new URL(BASE).host);
    check('opened from another site: the page reloads itself once for a page key, then the check page', !!first && r.nav.some((x) => hasParam(x.url, 'pk')), r.nav.map((x) => x.url).join(' → '));
    await passCheck(r.p);
    await r.p.waitForFunction(() => document.querySelector('#paste-content')?.textContent.includes('a note behind a CAPTCHA'), null, { timeout: 60000 });
    check('opened from another site: the note decrypts after the CAPTCHA', new URL(r.p.url()).hash === `#${K}`);
    await r.ctx.close();
  }

  // ── a file share ──────────────────────────────────────────────────────────
  await op.goto(`${BASE}/dashboard/`);
  await op.click('#tab-files');
  await op.setInputFiles('#file-input', [{ name: 'report.txt', mimeType: 'text/plain', buffer: Buffer.from(TEXT_FILE) }]);
  await op.check('#captcha');
  await op.click('#create');
  await op.waitForFunction(() => /\/p\/f/.test(document.querySelector('#paste-url').textContent), null, { timeout: 60000 });
  const fileUrl = await op.textContent('#paste-url');
  check('protected file share: created from the composer with the box ticked', /\/p\/f/.test(fileUrl));
  r = await recipient();
  await r.p.goto(fileUrl);
  await r.p.waitForURL((u) => u.search === '?check', { timeout: 30000 });
  await passCheck(r.p);
  await openFiles(r.p);
  check('protected file share: through its check page, then the file downloads intact', (await downloadedText(r.p)) === TEXT_FILE && await noTurnstileHere(r.p));
  await r.ctx.close();

  // ── a Drive share ─────────────────────────────────────────────────────────
  await op.goto(`${BASE}/dashboard/drive/`);
  await op.waitForSelector('#drive-app', { timeout: 60000 });
  await op.setInputFiles('#drive-file-input', [{ name: 'plans.txt', mimeType: 'text/plain', buffer: Buffer.from(DRIVE_FILE) }]);
  await op.waitForFunction(() => [...document.querySelectorAll('#drive-rows tr')].some((tr) => tr.textContent.includes('plans.txt')), null, { timeout: 60000 });
  await op.locator('#drive-rows tr', { hasText: 'plans.txt' }).locator('input[type="checkbox"]').check();
  await op.click('#drive-share');
  await op.waitForSelector('#drive-share-captcha');
  check('Drive → Share: the CAPTCHA box, off by default for the owner', !(await op.isChecked('#drive-share-captcha')) && (await op.textContent('label:has(#drive-share-captcha)')).trim() === 'Require CAPTCHA to open');
  await op.check('#drive-share-captcha');
  await dialogButton(op, 'Create link').click();
  await op.waitForSelector('#drive-share-url', { timeout: 60000 });
  const driveUrl = await op.textContent('#drive-share-url');
  await dialogButton(op, 'Done').click();
  r = await recipient();
  await r.p.goto(driveUrl);
  await r.p.waitForURL((u) => u.search === '?check', { timeout: 30000 });
  await passCheck(r.p);
  await openFiles(r.p);
  check('protected Drive share: through its check page, then the file downloads intact', (await downloadedText(r.p)) === DRIVE_FILE);
  await r.ctx.close();

  // ── reverse links ─────────────────────────────────────────────────────────
  await op.locator('#drive-rows tr', { hasText: 'plans.txt' }).locator('input[type="checkbox"]').uncheck(); // for the open folder
  await op.click('#drive-receive');
  await op.waitForSelector('#drive-rev-captcha');
  check('Receive files: "Require CAPTCHA to send files", on by default for the owner', await op.isChecked('#drive-rev-captcha') && (await op.textContent('label:has(#drive-rev-captcha)')).trim() === 'Require CAPTCHA to send files');
  await op.fill('#drive-rev-label', 'with CAPTCHA');
  await op.fill('#drive-rev-confirm', PW);
  await dialogButton(op, 'Create link').click();
  await op.waitForSelector('#drive-rev-url', { timeout: 60000 });
  const revUrl = await op.textContent('#drive-rev-url');
  await dialogButton(op, 'Done').click();
  await op.click('#drive-receive');
  await op.waitForSelector('#drive-rev-captcha');
  await op.uncheck('#drive-rev-captcha');
  await op.fill('#drive-rev-label', 'open link');
  await op.fill('#drive-rev-confirm', PW);
  await dialogButton(op, 'Create link').click();
  await op.waitForSelector('#drive-rev-url', { timeout: 60000 });
  const openRevUrl = await op.textContent('#drive-rev-url');
  await dialogButton(op, 'Done').click();

  r = await recipient();
  const RK = keyOf(revUrl);
  await r.p.goto(revUrl);
  await r.p.waitForURL((u) => u.search === '?check', { timeout: 30000 });
  await r.p.waitForSelector('#check-continue');
  check('protected reverse link: the uploader page goes to its check page; the link key is not there',
    !r.p.url().includes(RK) && !(await r.p.content()).includes(RK) && !(await storageText(r.p)).includes(RK));
  const rcheck = r.nav.find((n) => isCheck(n.url));
  check('protected reverse link: "Complete the CAPTCHA to send files", with the Turnstile CSP', (await r.p.textContent('#check-title')) === 'Complete the CAPTCHA to send files' && tsCsp(rcheck.csp));
  await passCheck(r.p);
  await r.p.waitForSelector('#reverse-page', { timeout: 60000 });
  const rback = r.nav.at(-1);
  check('protected reverse link: back on the uploader page (strict CSP, no Turnstile script, the key back)', strict(rback.csp) && await noTurnstileHere(r.p) && new URL(r.p.url()).hash === `#${RK}`, rback.url);
  await audit(r.p, 'the uploader page after the CAPTCHA');
  await r.p.setInputFiles('#reverse-file-input', [{ name: 'upload.txt', mimeType: 'text/plain', buffer: Buffer.from('sent behind a CAPTCHA') }]);
  await r.p.click('#reverse-send');
  await r.p.waitForFunction(() => !document.querySelector('#reverse-done').hidden, null, { timeout: 60000 });
  check('protected reverse link: a file is sent', /Sent 1 file/.test(await r.p.textContent('#reverse-done')));
  check('protected reverse link: "Complete the CAPTCHA again" is offered for more', await r.p.isVisible('#reverse-recheck') && /complete the CAPTCHA again/.test(await r.p.textContent('#reverse-done')));
  await r.ctx.close();
  r = await recipient();
  await r.p.goto(openRevUrl);
  await r.p.waitForSelector('#reverse-page', { timeout: 60000 });
  await r.p.setInputFiles('#reverse-file-input', [{ name: 'open.txt', mimeType: 'text/plain', buffer: Buffer.from('no CAPTCHA') }]);
  await r.p.click('#reverse-send');
  await r.p.waitForFunction(() => !document.querySelector('#reverse-done').hidden, null, { timeout: 60000 });
  check('unprotected reverse link: no check page, no Turnstile; the file is sent', !r.nav.some((n) => hasParam(n.url, 'check')) && await noTurnstileHere(r.p) && /Sent 1 file/.test(await r.p.textContent('#reverse-done')));
  await r.ctx.close();

  // ── the lists ─────────────────────────────────────────────────────────────
  await op.goto(`${BASE}/dashboard/shares/`);
  await op.waitForFunction(() => document.querySelectorAll('#shares-body tr').length >= 6, null, { timeout: 60000 });
  const badges = await op.$$eval('#shares-body tr', (trs) => trs.map((tr) => [tr.children[0].querySelector('input').value, tr.querySelector('.captcha-badge') ? 'CAPTCHA' : '']));
  const withBadge = badges.filter((x) => x[1]).length;
  check('My shares: the CAPTCHA badge on the 4 protected shares only', withBadge === 4 && badges.find((x) => x[0] === 'with CAPTCHA')?.[1] === 'CAPTCHA' && badges.find((x) => x[0] === 'open link')?.[1] === '', JSON.stringify(badges));
  await audit(op, 'My shares with CAPTCHA badges');
  await op.goto(`${BASE}/dashboard/admin/`);
  await openTab(op, 'shares');
  await op.waitForFunction(() => document.querySelectorAll('.admin-panel[data-panel="shares"] tbody tr').length >= 6, null, { timeout: 60000 });
  check('Admin → Shares: the CAPTCHA badge', (await op.locator('.admin-panel[data-panel="shares"] .captcha-badge').count()) === 4);

  // ── a user whose role requires it ────────────────────────────────────────
  await openTab(op, 'roles');
  await editRole(op, 'Default');
  await shares.waitFor({ timeout: 30000 });
  await shares.getByLabel('Require CAPTCHA for all shares').check();
  const hid = await shares.locator('fieldset.captcha-default').isHidden();
  await op.locator('#role-detail button', { hasText: /^Save\s+limits$/ }).first().click();
  await op.waitForFunction(() => /Limits saved/.test(document.getElementById('toast').textContent), null, { timeout: 30000 });
  const ov = await op.evaluate(async () => (await (await fetch('/api/private/admin/overview')).json()).limits.all.shareCaptcha);
  check('roles: "Require CAPTCHA for all shares" hides the default and is saved', hid && ov === 'require', ov);
  await openTab(op, 'users');
  const users = op.locator('.admin-panel[data-panel="users"]');
  await users.locator('input[aria-label="New username"]').fill('nora');
  await users.locator('input[aria-label="New user password"]').fill(NORA_PW);
  await users.locator('input[aria-label="Repeat password"]').fill(NORA_PW);
  await users.locator('button', { hasText: 'Create user' }).click();
  await op.waitForFunction(() => /User created/.test(document.getElementById('toast').textContent), null, { timeout: 30000 });
  const nctx = await b.newContext({ viewport: { width: 390, height: 844 }, reducedMotion: 'reduce' });
  const np = await nctx.newPage();
  watch(np);
  await login(np, 'nora', NORA_PW);
  await np.goto(`${BASE}/dashboard/`);
  await np.waitForSelector('#captcha-opt:not([hidden])', { timeout: 30000 });
  check('a user under "require": the composer\'s box is ticked and disabled, and says so', await np.isChecked('#captcha') && await np.isDisabled('#captcha') && /requires it on every share/.test(await np.textContent('#captcha-hint')));
  const noraUrl = await composeNote(np, 'nora\'s note');
  const nr = await fetch(`${BASE}/api/paste/${idOf(noraUrl)}`);
  check('a user under "require": the note has the CAPTCHA (an API recipient is refused)', nr.status === 403 && (await nr.json()).error === 'captcha_required');
  await nctx.close();

  check('no page errors, no CSP / Trusted Types violations', errors.length === 0, errors.slice(0, 5).join(' | '));
} catch (e) {
  console.log(`E2E ERROR ${e && e.stack ? e.stack : e}`);
  results.push(false);
} finally {
  await b.close();
}
const passed = results.filter(Boolean).length;
console.log(`${passed}/${results.length} passed`);
process.exit(passed === results.length ? 0 : 1);
