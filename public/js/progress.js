// progress.js — a labelled progress bar with a percentage, for file downloads
// and previews (fetch + decrypt, then the render step). A native <progress>
// named by its label; screen readers get a separate polite status line that
// changes only at each quarter and at phase changes, so it does not chatter.
// That line sits beside the bar (which stays hidden until used), not inside
// it, so the live region is already in the accessibility tree when the first
// update arrives: a region that appears together with its text is often not
// read. Built with DOM calls only.

let seq = 0;

export function progressBar() {
  const id = `pb-${++seq}`;
  const el = document.createElement('div');
  el.className = 'progress';
  const block = document.createElement('div');
  block.className = 'progress-block';
  block.hidden = true;
  const head = document.createElement('div');
  head.className = 'progress-head';
  const label = document.createElement('span');
  label.className = 'progress-label';
  label.id = `${id}-label`;
  const pct = document.createElement('span');
  pct.className = 'progress-pct';
  pct.setAttribute('aria-hidden', 'true'); // the bar itself carries the value
  head.append(label, pct);
  const bar = document.createElement('progress');
  bar.className = 'progress-bar';
  bar.max = 100;
  bar.setAttribute('aria-labelledby', label.id);
  const live = document.createElement('span');
  live.className = 'sr-only';
  live.setAttribute('role', 'status');
  live.setAttribute('aria-live', 'polite');
  block.append(head, bar);
  el.append(block, live);

  let lastSaid = '';
  const say = (text) => { if (text !== lastSaid) { lastSaid = text; live.textContent = text; } };

  return {
    el,
    block,
    live,
    /**
     * `fraction` in [0, 1] shows a percentage; null shows a busy
     * (indeterminate) bar for steps that cannot be measured.
     */
    set(text, fraction = null) {
      block.hidden = false;
      block.classList.remove('done');
      label.textContent = text;
      if (fraction === null || !Number.isFinite(fraction)) {
        bar.removeAttribute('value'); // indeterminate
        pct.textContent = '';
        say(text);
        return;
      }
      const p = Math.max(0, Math.min(100, Math.floor(fraction * 100)));
      bar.value = p;
      pct.textContent = `${p}%`;
      say(`${text} ${Math.floor(p / 25) * 25}%`);
    },
    done(text) {
      bar.value = 100;
      pct.textContent = '100%';
      label.textContent = text;
      block.classList.add('done');
      say(text);
    },
    hide() { block.hidden = true; lastSaid = ''; live.textContent = ''; },
  };
}
