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
    expect(w.renders[0].opts).toMatchObject({ sitekey: '0x4AAAAAAAsitekey', action: 'password', appearance: 'interaction-only' });
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
