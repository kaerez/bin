// captcha.js — the per-share CAPTCHA choice where a share is created (the
// composer, the Drive's Share and Receive dialogs), from the creator's
// role options (src/lib/settings.js: shareCaptcha / reverseCaptcha and their
// defaults): "allow" shows the box pre-set from the role's default, "require"
// shows it ticked and disabled, "off" hides it. The server applies the role
// again and never trusts this value beyond what the role allows.

import { h } from './common.js';

/**
 * The choice for `which` ('share' | 'reverse') from the profile
 * (/api/private/me) → { show, checked, disabled, mode, active }. `active`:
 * the server has Turnstile keys (else the flag waits for them).
 */
export function captchaChoice(profile, which) {
  const L = (profile && profile.limits) || {};
  const mode = L[`${which}Captcha`];
  const active = !!(profile && profile.captchaActive);
  if (mode === 'require') return { show: true, checked: true, disabled: true, mode, active };
  if (mode === 'allow') return { show: true, checked: L[`${which}CaptchaDefault`] === 'on', disabled: false, mode, active };
  return { show: false, checked: false, disabled: true, mode: 'off', active };
}

/** The line under the box: what it does, and whether the server enforces it yet. */
export function captchaHint(choice, which) {
  const what = which === 'reverse'
    ? 'Senders complete a CAPTCHA (Cloudflare Turnstile) before they can upload.'
    : 'Recipients complete a CAPTCHA (Cloudflare Turnstile) before anything of the share is sent to them; the API and the CLI cannot open it.';
  const req = choice.mode === 'require' ? ` Your role requires it on every ${which === 'reverse' ? 'link' : 'share'}.` : '';
  const off = choice.active ? '' : ' The CAPTCHA is not active on this server yet (no Turnstile keys): until the owner sets them up, it is not asked for.';
  return `${what}${req}${off}`;
}

/** The value to send: the box for "allow", true for "require", nothing for "off". */
export function captchaValue(choice, box) {
  if (!choice.show) return undefined;
  return choice.disabled ? true : !!(box && box.checked);
}

/**
 * The box as DOM (the dialogs): { el, input, value() }. `el` is hidden when
 * the role has the CAPTCHA off.
 */
export function captchaBox({ id, profile, which }) {
  const choice = captchaChoice(profile, which);
  const hintId = `${id}-hint`;
  const input = h('input', { type: 'checkbox', id, checked: choice.checked, disabled: choice.disabled, 'aria-describedby': hintId });
  const label = which === 'reverse' ? 'Require CAPTCHA to send files' : 'Require CAPTCHA to open';
  const el = h('div.captcha-opt', { hidden: !choice.show },
    h('label.inline', {}, input, ` ${label}`),
    h(`p.type-hint${choice.active ? '' : '.warn'}`, { id: hintId, text: captchaHint(choice, which) }));
  return { el, input, choice, value: () => captchaValue(choice, input) };
}
