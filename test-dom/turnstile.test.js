// turnstile.test.js (DOM) — the browser side of the Turnstile human check:
// nothing is loaded or shown when the server has it off; when on, the widget
// renders for the form's action and each token is handed out once. The
// Trusted Types policy lets exactly one third-party script URL through.
import { describe, it, expect, vi, beforeEach } from 'vitest';

let config = { turnstile: null };
vi.mock('../public/js/api.js', () => ({ fetchConfig: async () => config }));

const { humanCheck } = await import('../public/js/turnstile.js');
const { scriptURL, TURNSTILE_SCRIPT } = await import('../public/js/tt.js');

/** A stand-in for Cloudflare's window.turnstile. */
function fakeTurnstile() {
  const w = { renders: [], resets: 0 };
  globalThis.turnstile = {
    render(el, opts) { w.renders.push({ el, opts }); return 'w1'; },
    reset() { w.resets += 1; },
  };
  w.solve = (t) => w.renders.at(-1).opts.callback(t);
  return w;
}

beforeEach(() => { delete globalThis.turnstile; document.body.replaceChildren(); });

describe('humanCheck', () => {
  it('does nothing when the server has no human check', async () => {
    config = { turnstile: null };
    const el = document.createElement('div');
    el.hidden = true;
    const c = await humanCheck(el, 'login');
    expect(c.active).toBe(false);
    expect(await c.take()).toBeNull();
    expect(el.hidden).toBe(true);
    expect(document.querySelector('script')).toBeNull();
  });

  it('renders for the action and hands each token out once', async () => {
    config = { turnstile: '0x4AAAAAAAsitekey' };
    const w = fakeTurnstile();
    const el = document.createElement('div');
    el.hidden = true;
    const c = await humanCheck(el, 'password');
    expect(el.hidden).toBe(false);
    expect(w.renders[0].opts).toMatchObject({ sitekey: '0x4AAAAAAAsitekey', action: 'password', appearance: 'always' });
    w.solve('tok-1');
    expect(await c.take()).toBe('tok-1');
    // The next attempt starts a fresh challenge and waits for its token.
    const next = c.take();
    expect(w.resets).toBe(1);
    w.solve('tok-2');
    expect(await next).toBe('tok-2');
  });

  it('waits for a token that is not there yet', async () => {
    config = { turnstile: '0x4AAAAAAAsitekey' };
    const w = fakeTurnstile();
    const c = await humanCheck(document.createElement('div'), 'login');
    const p = c.take();
    setTimeout(() => w.solve('late'), 5);
    expect(await p).toBe('late');
  });
});

describe('gated buttons', () => {
  const button = () => { const b = document.createElement('button'); document.body.append(b); return b; };

  it('stay disabled until the check passes, and again after each token is used', async () => {
    config = { turnstile: '0x4AAAAAAAsitekey' };
    const w = fakeTurnstile();
    const b = button();
    const pending = humanCheck(document.createElement('div'), 'login', { gate: [b] });
    expect(b.disabled).toBe(true); // before the site key is even known
    const c = await pending;
    expect(b.disabled).toBe(true);
    // The reason is shown under the button and linked to it.
    const note = b.nextElementSibling;
    expect(note.textContent).toMatch(/Waiting for the human check/);
    expect(note.hidden).toBe(false);
    expect(b.getAttribute('aria-describedby')).toBe(note.id);
    w.solve('tok-1');
    expect(b.disabled).toBe(false);
    expect(note.hidden).toBe(true);
    // The page disables the button while it works and re-enables it after:
    // the button still waits for the next token.
    b.disabled = true;
    expect(await c.take()).toBe('tok-1');
    b.disabled = false;
    expect(b.disabled).toBe(true);
    w.solve('tok-2');
    expect(b.disabled).toBe(false);
    // The page's own "disabled" wins while the check has a token.
    b.disabled = true;
    expect(b.disabled).toBe(true);
    b.disabled = false;
    expect(b.disabled).toBe(false);
    // An expired token disables them again.
    w.renders.at(-1).opts['expired-callback']();
    expect(b.disabled).toBe(true);
    expect(note.hidden).toBe(false);
  });

  it('can be any form control, and can join after the check is mounted', async () => {
    config = { turnstile: '0x4AAAAAAAsitekey' };
    const w = fakeTurnstile();
    const b = button();
    const radio = document.createElement('input');
    radio.type = 'radio';
    document.body.append(radio);
    const c = await humanCheck(document.createElement('div'), 'account', { gate: [b, radio] });
    expect(radio.disabled).toBe(true);
    // A row's button made after the check was mounted.
    const later = button();
    c.gate(later);
    expect(later.disabled).toBe(true);
    expect(later.getAttribute('aria-describedby')).toBe(b.nextElementSibling.id);
    w.solve('tok-1');
    expect([b.disabled, radio.disabled, later.disabled]).toEqual([false, false, false]);
    // The page's own wish still counts (e.g. a radio that needs a passkey first).
    radio.disabled = true;
    expect(radio.disabled).toBe(true);
    radio.disabled = false;
    // One widget, several buttons: each use spends the token and disables them all.
    expect(await c.take()).toBe('tok-1');
    expect([b.disabled, radio.disabled, later.disabled]).toEqual([true, true, true]);
    const next = c.take();
    w.solve('tok-2');
    expect(await next).toBe('tok-2');
    expect(w.resets).toBe(2);
    expect(() => c.gate(document.createElement('div'))).toThrow(/form controls/);
  });

  it('can join at once, before the check is mounted', async () => {
    config = { turnstile: '0x4AAAAAAAsitekey' };
    const w = fakeTurnstile();
    const b = button();
    const pending = humanCheck(document.createElement('div'), 'account', { gate: [b] });
    // A row's button made while the site key is still being fetched.
    const row = button();
    pending.gate(row);
    expect([b.disabled, row.disabled]).toEqual([true, true]);
    expect(row.getAttribute('aria-describedby')).toBe(b.nextElementSibling.id);
    await pending;
    expect(row.disabled).toBe(true);
    w.solve('tok-1');
    expect([b.disabled, row.disabled]).toEqual([false, false]);
  });

  it('are left alone when the server has no human check', async () => {
    config = { turnstile: null };
    const b = button();
    const c = await humanCheck(document.createElement('div'), 'login', { gate: [b, null] });
    expect(b.disabled).toBe(false);
    const later = button();
    c.gate(later); // a no-op without a human check
    expect(later.disabled).toBe(false);
    expect(b.nextElementSibling.hidden).toBe(true); // no human check: no note
    b.disabled = true;
    expect(b.disabled).toBe(true);
  });

  it('stay disabled, with the reason shown, when the widget cannot load', async () => {
    config = { turnstile: '0x4AAAAAAAsitekey' };
    const b = button();
    const el = document.createElement('div');
    document.body.append(el);
    // No window.turnstile: the script tag is added and fails.
    const p = humanCheck(el, 'login', { gate: [b] });
    await Promise.resolve(); await new Promise((r) => setTimeout(r, 0));
    document.querySelector('script')?.dispatchEvent(new Event('error'));
    const c = await p;
    expect(b.disabled).toBe(true);
    expect(b.nextElementSibling.hidden).toBe(true); // the alert explains instead
    expect(el.querySelector('[role="alert"]').textContent).toMatch(/could not load/);
    await expect(c.take()).rejects.toThrow(/could not load/);
  });
});

describe('Trusted Types policy', () => {
  it('allows the exact Turnstile script and nothing else from that origin', () => {
    expect(String(scriptURL(TURNSTILE_SCRIPT))).toBe(TURNSTILE_SCRIPT);
    for (const bad of [
      'https://challenges.cloudflare.com/turnstile/v0/api.js',
      'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=x',
      'https://challenges.cloudflare.com/evil.js',
      'https://evil.example/turnstile/v0/api.js?render=explicit',
    ]) expect(() => scriptURL(bad), bad).toThrow();
  });
});
