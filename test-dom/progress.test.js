// progress.test.js — the download / preview progress bar (public/js/progress.js):
// a percentage next to a native <progress> named by its label, a busy
// (indeterminate) state for unmeasurable steps, and a status line for screen
// readers that only changes at each quarter. The status line sits beside the
// visible block (which hides when unused), so the live region is in the page
// before its first update.
import { describe, it, expect } from 'vitest';
import { progressBar } from '../public/js/progress.js';

describe('progressBar', () => {
  it('shows a named bar with a percentage', () => {
    const pb = progressBar();
    document.body.replaceChildren(pb.el);
    expect(pb.block.hidden).toBe(true);
    // The live region is present (and not hidden) before anything is shown.
    expect(pb.live.isConnected && !pb.live.closest('[hidden]')).toBe(true);
    expect(pb.live.getAttribute('role')).toBe('status');
    pb.set('Loading a.txt…', 0.437);
    const bar = pb.el.querySelector('progress');
    expect(pb.block.hidden).toBe(false);
    expect(bar.value).toBe(43);
    expect(bar.max).toBe(100);
    expect(pb.el.querySelector('.progress-pct').textContent).toBe('43%');
    expect(document.getElementById(bar.getAttribute('aria-labelledby')).textContent).toBe('Loading a.txt…');
  });

  it('clamps, goes busy for unmeasurable steps, and finishes', () => {
    const pb = progressBar();
    pb.set('x', 7);
    expect(pb.el.querySelector('progress').value).toBe(100);
    pb.set('Preparing the preview…', null);
    expect(pb.el.querySelector('progress').hasAttribute('value')).toBe(false);
    expect(pb.el.querySelector('.progress-pct').textContent).toBe('');
    pb.done('Downloading a.txt: done');
    expect(pb.block.classList.contains('done')).toBe(true);
    expect(pb.el.querySelector('.progress-pct').textContent).toBe('100%');
    pb.hide();
    expect(pb.block.hidden).toBe(true);
    expect(pb.live.textContent).toBe(''); // nothing stale to re-read
    expect(pb.live.closest('[hidden]')).toBe(null);
  });

  it('announces only quarter steps and phase changes', () => {
    const pb = progressBar();
    const live = pb.el.querySelector('[role="status"]');
    const said = [];
    new MutationObserver(() => said.push(live.textContent)).observe(live, { childList: true, characterData: true, subtree: true });
    for (let i = 0; i <= 100; i += 5) pb.set('Loading…', i / 100);
    return Promise.resolve().then(() => {
      expect(live.textContent).toBe('Loading… 100%');
      expect(said.length).toBeLessThanOrEqual(5); // 0, 25, 50, 75, 100
    });
  });

  it('gives each bar its own label id', () => {
    const a = progressBar();
    const b = progressBar();
    expect(a.el.querySelector('progress').getAttribute('aria-labelledby')).not.toBe(b.el.querySelector('progress').getAttribute('aria-labelledby'));
  });
});
