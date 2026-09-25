// theme.js — wires the topbar light/dark toggle (deferred, first-party, CSP-safe).
// theme-init.js already applied the saved preference before paint; this handles
// clicks: flip the class on <html>, persist it, and animate the flip rather than
// snapping between palettes (see "theme flip" in styles.css).
(function () {
  const btn = document.getElementById('themeToggle');
  if (!btn) return;
  const root = document.documentElement;
  // Mirrors the 520ms in styles.css — change them together.
  const FLIP_MS = 520;
  let untheme = null;

  // Reflect the state theme-init.js applied before paint (it runs in <head>,
  // before the button exists, so the a11y state is set here instead).
  btn.setAttribute('aria-pressed', String(root.classList.contains('dark')));

  // The state change itself, shared by all three paths below.
  const apply = function (next) {
    root.classList.toggle('dark', next === 'dark');
    btn.setAttribute('aria-pressed', String(next === 'dark'));
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.content = next === 'dark' ? '#0d1117' : '#f2f1ec';
    try {
      localStorage.setItem('binthere:theme', next);
    } catch {
      /* storage disabled — the toggle still works for this page load */
    }
  };

  btn.addEventListener('click', function () {
    const next = root.classList.contains('dark') ? 'light' : 'dark';

    // Reduced motion: flip outright. The stylesheet has the wave and the
    // fallback transition switched off, so waiting on either would just delay it.
    if (typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches) {
      apply(next);
      return;
    }

    // Snapshot the painted page so the stylesheet can wash the new palette
    // across it. Nothing re-renders, so scroll, focus and an open modal survive.
    if (typeof document.startViewTransition === 'function') {
      const vt = document.startViewTransition(function () { apply(next); });
      // A second click interrupts the running flip and rejects its promises.
      if (vt && vt.finished && typeof vt.finished.catch === 'function') {
        vt.finished.catch(function () { /* superseded by a newer flip */ });
      }
      return;
    }

    // Fallback: interpolate the colours in place. The style flush is what makes
    // the pre-flip palette the value the transition animates *from* — the older
    // engines this path exists for are the ones that otherwise coalesce it away.
    root.classList.add('theming');
    void root.offsetWidth;
    apply(next);
    clearTimeout(untheme);
    untheme = setTimeout(function () { root.classList.remove('theming'); }, FLIP_MS);
  });
})();
