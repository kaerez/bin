// statement.js — /accessibility/: fills in the contact details the admin set
// (Settings → Accessibility statement), in both languages. Text only.

import { fetchConfig } from './api.js';

(async () => {
  let a = null;
  try { a = (await fetchConfig()).accessibility; } catch { /* keep the fallback text */ }
  if (!a) return;
  for (const lang of ['en', 'he']) {
    if (a.contact) document.getElementById(`st-contact-${lang}`).textContent = a.contact;
    if (a.coordinator) {
      document.getElementById(`st-coord-${lang}-text`).textContent = a.coordinator;
      document.getElementById(`st-coord-${lang}`).hidden = false;
    }
  }
})();
