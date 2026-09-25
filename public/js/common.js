// common.js — shared UI helpers for the viewer and the dashboard: a tiny
// element builder (textContent only — never innerHTML), two-step confirms,
// password reveal toggles, formatting, and friendly error text.

import { ApiError } from './api.js';

/** h('tag.class', { attr: v, on: { click } }, ...children) — DOM construction only. */
export function h(spec, props = {}, ...children) {
  const [tag, ...classes] = spec.split('.');
  const el = document.createElement(tag || 'div');
  if (classes.length) el.className = classes.join(' ');
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'on') { for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn); continue; }
    if (k === 'text') { el.textContent = String(v); continue; }
    if (k === 'dataset') { Object.assign(el.dataset, v); continue; }
    if (k === 'hidden' || k === 'disabled' || k === 'checked' || k === 'selected') { el[k] = !!v; continue; }
    if (k === 'value') { el.value = v; continue; }
    if (/^on/i.test(k) || k === 'style' || k === 'innerHTML' || k === 'srcdoc') throw new Error(`refusing unsafe prop ${k}`);
    el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.appendChild(typeof c === 'string' || typeof c === 'number' ? document.createTextNode(String(c)) : c);
  }
  return el;
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

export function showMsg(el, message, isError = true) {
  if (!el) return;
  el.textContent = message;
  el.classList.toggle('error', isError);
  el.hidden = !message;
}

/**
 * Two-step confirmation for irreversible actions: the first activation arms the
 * button (label names the effect), a second within 5 s confirms; disarms on
 * timeout or blur.
 */
export function armConfirm(btn, armedLabel, onConfirm) {
  const label = btn.textContent;
  let timer = null;
  const disarm = () => {
    if (timer === null) return;
    clearTimeout(timer);
    timer = null;
    btn.textContent = label;
    btn.classList.remove('armed');
  };
  btn.onclick = () => {
    if (timer !== null) { disarm(); onConfirm(); return; }
    btn.textContent = armedLabel;
    btn.classList.add('armed');
    timer = setTimeout(disarm, 5000);
  };
  btn.onblur = disarm;
}

/** Wire [input, button] pairs holding the same secret to one reveal state. */
export function wirePeek(...pairs) {
  const fields = pairs.map(([i, b]) => ({ input: typeof i === 'string' ? document.querySelector(i) : i, btn: typeof b === 'string' ? document.querySelector(b) : b }))
    .filter(({ input, btn }) => input && btn);
  const paint = (show) => {
    for (const { input, btn } of fields) {
      input.type = show ? 'text' : 'password';
      btn.classList.toggle('revealed', show);
      btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      btn.setAttribute('aria-pressed', String(show));
    }
  };
  paint(false);
  for (const { btn } of fields) btn.onclick = () => paint(fields[0].input.type === 'password');
}

export const reducedMotion = () =>
  typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;

export const wait = (ms) => new Promise((r) => setTimeout(r, ms));

/** ms → H:MM:SS (or MM:SS under an hour). */
export function formatDuration(ms) {
  const total = Math.floor(ms / 1000);
  if (total <= 0) return 'expired';
  const d = Math.floor(total / 86400);
  const hh = Math.floor((total % 86400) / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const pad = (n) => String(n).padStart(2, '0');
  if (d > 0) return `${d}d ${pad(hh)}:${pad(m)}:${pad(s)}`;
  return hh > 0 ? `${hh}:${pad(m)}:${pad(s)}` : `${pad(m)}:${pad(s)}`;
}

/** Seconds → coarse "2d 3h" / "3h 12m" / "12m" / "<1m". */
export function formatCoarse(sec) {
  const d = Math.floor(sec / 86400);
  const hh = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return hh > 0 ? `${d}d ${hh}h` : `${d}d`;
  if (hh > 0) return m > 0 ? `${hh}h ${m}m` : `${hh}h`;
  return m > 0 ? `${m}m` : '<1m';
}

export function formatBytes(n) {
  if (!Number.isFinite(n)) return '—';
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${i === 0 ? v : v.toFixed(v < 10 ? 1 : 0)} ${u[i]}`;
}

export const formatDate = (sec) => (sec ? new Date(sec * 1000).toLocaleString() : '—');

/** Duration units shared by every "n minutes/hours/days" control. */
export const DURATION_UNITS = [['s', 'seconds', 1], ['m', 'minutes', 60], ['h', 'hours', 3600], ['d', 'days', 86400]];

/** Seconds → { n, unit } using the largest exact unit. */
export function splitDuration(sec) {
  for (let i = DURATION_UNITS.length - 1; i >= 0; i--) {
    const [u, , f] = DURATION_UNITS[i];
    if (sec % f === 0 && sec >= f) return { n: sec / f, unit: u };
  }
  return { n: sec, unit: 's' };
}

export const unitSeconds = (u) => (DURATION_UNITS.find((x) => x[0] === u) || DURATION_UNITS[0])[2];

export function friendlyError(e) {
  if (e instanceof ApiError) {
    if (e.status === 401 && e.code === 'unauthenticated') return 'Your session has ended — please log in again.';
    if (e.status === 429 && e.code === 'blocked') return 'Too many attempts from your network. Try again later.';
    return e.message || 'Server error. Please try again.';
  }
  if (e && /too large/.test(e.message || '')) return 'That is too large.';
  if (e && e.name === 'TypeError') return 'Could not reach the server — check your connection and try again.';
  return (e && e.message) || 'Something went wrong. Please try again.';
}
