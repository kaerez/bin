// a11y-init.js — blocking, first-party head script (CSP-safe: script-src 'self').
// Applies the saved accessibility preferences (public/js/a11y.js) as classes
// on <html> before the stylesheet paints, so a reload never flashes the
// default look. Keep CLASS in step with FLAGS in a11y.js.
(function () {
  let s = null;
  try {
    s = JSON.parse(localStorage.getItem('secbin:a11y') || 'null');
  } catch {
    /* storage blocked or corrupt: defaults */
  }
  if (!s || typeof s !== 'object' || Array.isArray(s)) return;
  const CLASS = {
    keyboardNav: 'a11y-keyboard', noAnimations: 'a11y-no-anim', highContrast: 'a11y-contrast',
    readableFont: 'a11y-readable', markHeadings: 'a11y-headings', markLinks: 'a11y-links',
  };
  const html = document.documentElement;
  for (const k of Object.keys(CLASS)) if (s[k] === true) html.classList.add(CLASS[k]);
  if (s.fontScale === 'lg') html.classList.add('a11y-font-lg');
  if (s.fontScale === 'sm') html.classList.add('a11y-font-sm');
})();
