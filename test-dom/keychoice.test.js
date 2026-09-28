// keychoice.test.js — copying a generated or shown key (public/js/keychoice.js,
// the set-up page and Admin → Security → Keys): the clipboard is cleared after
// 60 s only where the page may read it back, only while the page has focus and
// only when it still holds that key (nothing else the person copied is
// wiped); where the Permissions-Policy denies clipboard-read (this site's), the
// toast says the page cannot clear it instead of promising a clear.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { copyKey, candidateView, CLEAR_MS } from '../public/js/keychoice.js';

let clip;
let allowRead;
beforeEach(() => {
  document.body.innerHTML = '<div id="toast" role="status"></div>';
  clip = { value: '', writes: [] };
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: { writeText: vi.fn(async (t) => { clip.value = t; clip.writes.push(t); }), readText: vi.fn(async () => clip.value) },
  });
  Object.defineProperty(window, 'isSecureContext', { configurable: true, value: true });
  allowRead = true;
  Object.defineProperty(document, 'featurePolicy', { configurable: true, value: { allowsFeature: (f) => (f === 'clipboard-read' ? allowRead : true) } });
  vi.spyOn(document, 'hasFocus').mockReturnValue(true);
  vi.useFakeTimers({ toFake: ['setTimeout'] });
});
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); delete document.featurePolicy; });

const KEY = 'k'.repeat(43);
const flush = async () => { for (let i = 0; i < 5; i++) await Promise.resolve(); };

describe('copying a key', () => {
  it('clears the clipboard after 60 s while it still holds the key and the page has focus; the toast says so', async () => {
    const btn = document.createElement('button');
    await copyKey(btn, KEY);
    expect(clip.value).toBe(KEY);
    expect(document.getElementById('toast').textContent).toMatch(/Clipboard clears in 60 s/);
    await vi.advanceTimersByTimeAsync(CLEAR_MS - 1000);
    expect(clip.value).toBe(KEY);
    await vi.advanceTimersByTimeAsync(1000);
    await flush();
    expect(clip.value).toBe('');
  });

  it('leaves the clipboard alone when something else was copied meanwhile, or the page has no focus, or reading fails', async () => {
    await copyKey(document.createElement('button'), KEY);
    clip.value = 'something else the person copied';
    await vi.advanceTimersByTimeAsync(CLEAR_MS);
    await flush();
    expect(clip.value).toBe('something else the person copied');
    await copyKey(document.createElement('button'), KEY);
    document.hasFocus.mockReturnValue(false);
    await vi.advanceTimersByTimeAsync(CLEAR_MS);
    await flush();
    expect(clip.value).toBe(KEY);
    document.hasFocus.mockReturnValue(true);
    navigator.clipboard.readText.mockRejectedValue(new Error('denied'));
    await copyKey(document.createElement('button'), KEY);
    await vi.advanceTimersByTimeAsync(CLEAR_MS);
    await flush();
    expect(clip.value).toBe(KEY);
  });

  it('where the Permissions-Policy denies clipboard-read (this site\'s): no clear is scheduled and the toast says to clear it', async () => {
    allowRead = false;
    await copyKey(document.createElement('button'), KEY);
    expect(document.getElementById('toast').textContent).toMatch(/cannot clear the clipboard/);
    await vi.advanceTimersByTimeAsync(CLEAR_MS);
    await flush();
    expect(navigator.clipboard.readText).not.toHaveBeenCalled();
    expect(clip.value).toBe(KEY);
  });

  it('the candidate view\'s copy button copies the key even while it is masked', async () => {
    const v = candidateView({ id: 'c', label: 'root MEK', cand: { key: KEY, fp: 'abcdefghijk' }, masked: true });
    document.body.append(v);
    expect(v.querySelector('#c-value').textContent).not.toContain(KEY);
    v.querySelector('.copy-btn').click();
    await flush();
    expect(clip.writes).toEqual([KEY]);
  });
});
