// check.js — the CAPTCHA page of a share that has one: /p/<id>?check (a note,
// file share or Drive share) and /r/<id>?check (a reverse share's upload
// link), served with the Turnstile CSP (src/index.js). It is the only page of
// a share where Cloudflare's script runs, so the link's key is never here: the
// share's own page sealed it in sessionStorage before coming here
// (public/js/pagekey.js) and only that strict page can open it again.
//
// The visitor completes the CAPTCHA; Continue (disabled until then) redeems
// the token for a grant (POST …/<id>/human), keeps it for this tab and goes
// back to the share's page (?n=<nonce>), which opens the share. DOM through
// h() only (Trusted Types).

import { h, clear, showMsg, friendlyError } from './common.js';
import { shareHuman, reverseApi, ApiError } from './api.js';
import { humanCheck as realHumanCheck } from './turnstile.js';
import { tabStorage, stashedNonce, saveGrant } from './pagekey.js';

const ROUTE = /^\/(p|r)\/([^/]+)\/?$/;

/** The share this check page is for → { page: 'p' | 'r', id, path } or null. */
export function checkRoute(pathname) {
  const m = ROUTE.exec(String(pathname || ''));
  if (!m) return null;
  let id;
  try { id = decodeURIComponent(m[2]); } catch { return null; }
  return /^[A-Za-z0-9_-]{8,40}$/.test(id) ? { page: m[1], id, path: `/${m[1]}/${m[2]}` } : null;
}

/**
 * Mount the check page in `root`. deps (tests): { location, humanCheck,
 * shareHuman, reverseHuman, storage }. Resolves to { state, button? }.
 */
export async function mountCheck(root, deps = {}) {
  const loc = deps.location || globalThis.location;
  const humanCheck = deps.humanCheck || realHumanCheck;
  const storage = 'storage' in deps ? deps.storage : tabStorage();
  const route = checkRoute(loc.pathname);
  const reverse = route && route.page === 'r';
  const title = h('h1.title', { id: 'check-title', tabindex: '-1', text: reverse ? 'Complete the CAPTCHA to send files' : 'Complete the CAPTCHA to open this share' });
  if (!route) {
    root.replaceChildren(h('div.card.stack', {}, title, h('p.subtitle', { role: 'alert', text: 'This page is not part of a valid link.' })));
    return { state: 'error' };
  }
  // A link key must never stay where Cloudflare's script runs: opened with one
  // (someone added "?check" to a whole link), hand it to the share's strict
  // page at once, before the widget's script is loaded.
  if (loc.hash && loc.hash.length > 1) {
    loc.replace(`${route.path}${loc.hash}`);
    return { state: 'leaving' };
  }
  if (!storage) {
    root.replaceChildren(h('div.card.stack', {}, title,
      h('p.subtitle', { role: 'alert', text: 'This browser does not let the page keep your place for this tab (site storage is off, or this is a restricted window). Allow site storage for this site, or open the link in another browser.' })));
    return { state: 'error' };
  }
  const nonce = stashedNonce({ kind: route.page, id: route.id, storage });
  const box = h('div.turnstile', { id: 'check-widget', hidden: true });
  // Not created disabled: the gate (humanCheck) keeps it disabled until the CAPTCHA has passed.
  const go = h('button.cta', { type: 'button', id: 'check-continue', text: 'Continue' });
  const msg = h('p.msg.error', { id: 'check-msg', role: 'alert', hidden: true });
  clear(root).append(h('div.card.stack', { id: 'check-page' },
    h('p.eyebrow', { text: 'CAPTCHA' }),
    title,
    h('p.subtitle', { id: 'check-why', text: reverse
      ? 'The person who shared this link asks senders to confirm they are a person first. When the CAPTCHA has passed, Continue takes you back to the upload page.'
      : 'The person who shared this asks recipients to confirm they are a person first. When the CAPTCHA has passed, Continue takes you back to the share, which opens then.' }),
    h('p.mono.muted', { text: 'The CAPTCHA is Cloudflare Turnstile. It usually needs no puzzle. The link\'s key is not on this page.' }),
    ...(nonce ? [] : [h('p.type-hint.warn', { role: 'note', text: 'This tab does not hold the link any more: after the CAPTCHA, open the whole link again (with the part after “#”).' })]),
    box, go, msg));
  go.setAttribute('aria-describedby', 'check-why');
  const check = humanCheck(box, reverse ? 'reverse-upload' : 'share-open', { gate: [go], noun: 'CAPTCHA' });
  const redeem = deps.shareHuman || ((kind, id, token) => shareHuman(kind, id, token));
  const reverseHuman = deps.reverseHuman || ((id, token) => reverseApi.human(id, token));
  go.addEventListener('click', async () => {
    if (go.disabled) return;
    msg.hidden = true;
    go.disabled = true;
    try {
      const token = await (await check).take();
      const kind = route.id[0] === 'f' ? 'file' : 'paste';
      const r = reverse ? await reverseHuman(route.id, token) : await redeem(kind, route.id, token);
      saveGrant({ kind: route.page, id: route.id, storage, grant: typeof r.grant === 'string' ? r.grant : null });
      loc.replace(nonce ? `${route.path}?n=${encodeURIComponent(nonce)}` : route.path);
      return;
    } catch (e) {
      showMsg(msg, e instanceof ApiError && e.code === 'turnstile_failed' ? 'The CAPTCHA failed or expired. Complete it again, then press Continue.' : friendlyError(e));
    }
    go.disabled = false;
  });
  title.focus({ preventScroll: true });
  return { state: 'ready', button: go, check };
}

const mount = typeof document !== 'undefined' ? document.getElementById('check-app') : null;
if (mount) mountCheck(mount);
