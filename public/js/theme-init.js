// theme-init.js — blocking, first-party head script (CSP-safe: script-src 'self').
// Runs before the stylesheet paints so the theme is applied with no flash.
// An explicit choice (the topbar toggle, saved as 'secbin:theme') always wins;
// with none saved, follow the OS/browser `prefers-color-scheme` — dark unless
// it asks for light. The HTML ships class="dark", so a no-JS load stays dark.
(function () {
  let saved = null;
  try {
    saved = localStorage.getItem('secbin:theme');
  } catch {
    /* private mode / storage disabled — fall through to the system preference */
  }
  let t = saved === 'light' || saved === 'dark' ? saved : null;
  if (!t) {
    let light = false;
    try {
      light = typeof matchMedia === 'function' && matchMedia('(prefers-color-scheme: light)').matches;
    } catch {
      /* no media queries — keep the dark default */
    }
    t = light ? 'light' : 'dark';
  }
  document.documentElement.classList.toggle('dark', t === 'dark');
  // Keep the browser chrome (mobile address bar) on the actual canvas color.
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.content = t === 'dark' ? '#0d1117' : '#f2f1ec';
})();
