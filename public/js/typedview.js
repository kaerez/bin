// typedview.js — the viewers of a note, a link and a credential, shared by the
// regular share page (public/js/view.js), the Drive (a note, link or
// credential received through a "Receive" link: public/dashboard/js/
// drive-app.js) and a Drive share's recipient. DOM through h() only (strict
// CSP, Trusted Types); nothing here follows a link or runs content.
//
//   note       — Markdown through the safe subset renderer (markdown.js), code
//                (and plain text that looks like code) highlighted, else plain
//                text; always textContent.
//   link       — never followed automatically: the destination spelled out
//                (the host as the browser resolves it), warnings (another
//                app, international characters, not HTTPS), and Open only for
//                the schemes a recipient may open, behind a second, confirmed
//                click, with noopener / noreferrer. `rules` (the Drive: the
//                user's own URL rules) also keeps a link those rules do not
//                allow to Copy only, and says so.
//   credential — each field with Copy; the password and the one-time-code seed
//                masked until revealed; a live one-time code.

import { renderMarkdown } from './markdown.js';
import { looksLikeCode, highlightInto } from './highlight.js';
import { toast, copyText, countdownSwitch } from './ui.js';
import { h, armConfirm } from './common.js';
import { describeHost, parseSecret, parseShareUrl, urlAllowed, describeUrlRules, ShareTypeError, totpCode } from './sharetypes.js';

let totpTimer = null;
/** Stop the one-time code's clock (a credential card that is no longer shown). */
export function stopTotp() { clearInterval(totpTimer); totpTimer = null; }

/** How a note of format `fmt` is shown → { markdown, code }. */
export function noteKind(fmt, text) {
  const markdown = fmt === 'markdown';
  return { markdown, code: !markdown && (fmt === 'code' || (fmt === 'plaintext' && looksLikeCode(text))) };
}

/** Draw note `text` into `container` (rendered Markdown unless `raw`, highlighted code, or plain text). */
export function drawNote(container, text, { markdown = false, code = false, raw = false } = {}) {
  container.replaceChildren();
  if (markdown && !raw) {
    const div = h('div.md');
    renderMarkdown(div, text);
    container.appendChild(div);
    return;
  }
  const pre = h('pre.code');
  if (code) { const c = h('code'); highlightInto(c, text); pre.appendChild(c); } else pre.textContent = text;
  container.appendChild(pre);
}

/**
 * A link card. `rules`: URL rules the link must match to be opened here
 * (null: any scheme that is not forbidden, as a recipient who does not know
 * the sender's rules sees it). Throws ShareTypeError for a malformed link.
 */
export function linkCard(text, { rules = null, lead = null } = {}) {
  // Any scheme that is not forbidden (javascript:, data:, file:, …) parses; `rules` decides what opens.
  const u = parseShareUrl(text, { recipient: true });
  const d = describeHost(u);
  const allowed = !rules || urlAllowed(u, rules);
  const openable = d.openable && allowed;
  const warn = [];
  if (!allowed) warn.push([`Your account’s URL rules allow ${describeUrlRules(rules)}; this link is not one of them. For your safety it cannot be opened from here: copy it only if you trust the sender and know what it does.`]);
  else if (d.external && d.openable) warn.push([`This is a ${d.scheme}: link: opening it hands it to another app on your device.`]);
  if (allowed && !d.openable) warn.push([`This is a ${d.scheme}: link for another app. For your safety it cannot be opened from here: copy it only if you trust the sender and know what it does.`]);
  // <bdi> isolates the Unicode form so right-to-left labels cannot reorder the sentence.
  if (d.idn) warn.push(['This address uses international characters and is displayed as “', h('bdi', { dir: 'ltr', text: d.unicode }), '”. Such names can imitate a well-known site — check the real address above.']);
  if (d.insecure) warn.push(['This link is not HTTPS: the connection to it is not encrypted.']);
  let open = null;
  if (openable) {
    open = h('button.send', { type: 'button' }, h('span.send-txt', { text: 'Open link' }));
    armConfirm(open, d.external ? `Open this ${d.scheme}: link?` : `Open ${d.ascii}?`, () => window.open(u.href, '_blank', 'noopener,noreferrer'));
  }
  const copy = h('button.btn', { type: 'button', text: 'Copy link', on: { click: async () => toast((await copyText(u.href)) ? 'link copied' : 'copy failed') } });
  // The full link is always spelled out (for app links the host alone would
  // hide the path and query that carry what the link does).
  return h('div.link-card', {},
    h('p.field-label', { text: lead ?? (d.external ? 'This share is a link' : 'This share is a link to') }),
    h('p.link-host', { text: d.ascii }),
    ...(u.href !== d.ascii ? [h('p.link-full', { text: u.href })] : []),
    ...warn.map((w) => h('p.type-hint.warn', { role: 'note' }, ...w)),
    h('div.btn-row', {}, open, copy));
}

const SECRET_LABELS = [['title', 'Title', false], ['username', 'User name', false], ['password', 'Password', true], ['url', 'Sign-in URL', false], ['totp', 'One-time-code seed', true], ['notes', 'Notes', false]];

/** A credential card. Throws ShareTypeError for a malformed credential. */
export function secretCard(text) {
  const sec = parseSecret(text);
  stopTotp();
  const card = h('div.secret-card');
  for (const [key, label, masked] of SECRET_LABELS) {
    if (sec[key] === undefined) continue;
    const val = h('span.secret-val', { text: masked ? '••••••••' : sec[key] });
    if (masked) val.classList.add('masked');
    const btns = h('div.btn-row');
    if (masked) {
      const reveal = h('button.btn', { type: 'button', text: 'Reveal', 'aria-pressed': 'false', 'aria-label': `Reveal ${label.toLowerCase()}` });
      reveal.onclick = () => {
        const show = reveal.getAttribute('aria-pressed') !== 'true';
        val.textContent = show ? sec[key] : '••••••••';
        val.classList.toggle('masked', !show);
        reveal.textContent = show ? 'Hide' : 'Reveal';
        reveal.setAttribute('aria-pressed', String(show));
      };
      btns.appendChild(reveal);
    }
    btns.appendChild(h('button.btn', { type: 'button', text: 'Copy', 'aria-label': `Copy ${label.toLowerCase()}`, on: { click: async () => toast((await copyText(sec[key])) ? `${label.toLowerCase()} copied` : 'copy failed') } }));
    card.appendChild(h('div.secret-row', {}, h('span.field-label', { text: label }), val, btns));
  }
  if (sec.totp !== undefined) {
    const code = h('span.totp-code', { text: '······' });
    const left = h('span.mono.muted', { 'aria-live': 'off' });
    // The seconds countdown can be stopped (WCAG 2.2.2); the code itself keeps
    // changing when it has to (that is what it is for).
    const totpSwitch = countdownSwitch(() => tick());
    let current = '';
    const copy = h('button.btn', { type: 'button', text: 'Copy code', on: { click: async () => { if (current) toast((await copyText(current)) ? 'code copied' : 'copy failed'); } } });
    const tick = async () => {
      // A card no longer in the page stops its clock.
      if (tick.started && !card.isConnected) { stopTotp(); return; }
      try {
        const r = await totpCode(sec.totp);
        current = r.code;
        code.textContent = r.code;
        left.textContent = totpSwitch.stopped() ? `changes every ${r.period} seconds` : `changes in ${r.remaining}s`;
      } catch (e) {
        stopTotp();
        code.textContent = '—';
        left.textContent = e instanceof ShareTypeError ? e.message : 'The one-time code could not be computed.';
      }
    };
    tick();
    tick.started = true;
    totpTimer = setInterval(tick, 1000);
    card.appendChild(h('div.secret-row', {}, h('span.field-label', { text: 'One-time code' }), h('span', {}, code, ' ', left), h('div.btn-row', {}, copy, totpSwitch.el)));
  }
  return card;
}
