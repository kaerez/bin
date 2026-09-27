// a11y-statement.test.js — the accessibility statement is admin-editable
// structured text (#35): English only by default, served publicly by
// /api/config, every field validated (lengths, one line, list items, language
// code, direction, date, the two languages together, the overall size), saved
// by the owner only, logged without dumping long text, and carried by the
// settings part of an export / import (re-validated there).
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, fetchJson, proofFor } from './helpers.js';
import { A11Y_KEYS, A11Y_MAX_TOTAL, A11Y_DEFAULTS, publicStatement } from '../public/js/a11ystatement.js';

let oc;
beforeAll(async () => { oc = await owner(); });
const save = (patch, cookie = oc) => fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie, body: patch });
const config = async () => (await (await fetchJson('/api/config')).json()).accessibility;
const CURRENT = proofFor('owner-password');
const exportDoc = async () => (await (await fetchJson('/api/private/admin/export', { method: 'POST', cookie: oc, body: { current: CURRENT, system: true } })).json()).document;
const importDoc = (document, dryRun = true) =>
  fetchJson('/api/private/admin/import', { method: 'POST', cookie: oc, body: { current: CURRENT, document, decisions: { system: true, users: {} }, dryRun } });

describe('accessibility statement settings', () => {
  it('defaults to one English statement, served publicly', async () => {
    const a = await config();
    expect(a.statements).toHaveLength(1);
    expect(a.statements[0]).toMatchObject({ lang: 'en', dir: 'ltr', title: 'Accessibility statement', doneHeading: 'What we have done' });
    expect(a.statements[0].done.length).toBeGreaterThan(3);
    expect(a.statements[0].standard.join(' ')).toMatch(/partial conformance/);
    expect(a).toMatchObject({ contact: '', coordinator: '', reviewed: '2026-09-25' });
    expect(JSON.stringify(a)).not.toMatch(/[֐-׿]/);
    // Public, and cacheable by nobody's cookie: no session needed.
    expect((await fetchJson('/api/config')).status).toBe(200);
  });

  it('saves the whole statement, normalised, and a second language', async () => {
    const r = await save({
      'a11y.title': '  Access\r\nstatement ',
      'a11y.commitment': 'One.\r\n\r\n  Two.  ',
      'a11y.done': ' first \n\n second\r\n',
      'a11y.reviewed': '2027-01-31',
      'a11y.contact': 'access@example.test',
      'a11y.alt.lang': 'HE', 'a11y.alt.dir': 'rtl', 'a11y.alt.title': 'הצהרת נגישות', 'a11y.alt.done': 'א\nב',
    });
    expect(r.status).toBe(200);
    const s = (await r.json()).settings;
    expect(s['a11y.title']).toBe('Access statement');
    expect(s['a11y.commitment']).toBe('One.\nTwo.');
    expect(s['a11y.done']).toBe('first\nsecond');
    expect(s['a11y.alt.lang']).toBe('he');
    const a = await config();
    expect(a.statements.map((b) => [b.lang, b.dir])).toEqual([['en', 'ltr'], ['he', 'rtl']]);
    expect(a.statements[0].commitment).toEqual(['One.', 'Two.']);
    expect(a.statements[1]).toMatchObject({ title: 'הצהרת נגישות', done: ['א', 'ב'], commitmentHeading: '' });
    expect(a).toMatchObject({ contact: 'access@example.test', reviewed: '2027-01-31' });
    // Turning the second language off keeps its text for later.
    expect((await save({ 'a11y.alt.lang': '' })).status).toBe(200);
    expect((await config()).statements).toHaveLength(1);
    const ov = await (await fetchJson('/api/private/admin/overview', { cookie: oc })).json();
    expect(ov.settings['a11y.alt.title']).toBe('הצהרת נגישות');
    expect(ov.defaults.settings['a11y.title']).toBe('Accessibility statement');
  });

  it('refuses invalid values', async () => {
    const bad = [
      { 'a11y.title': '' },
      { 'a11y.doneHeading': '   ' },
      { 'a11y.title': 'x'.repeat(121) },
      { 'a11y.commitment': 'x'.repeat(2001) },
      { 'a11y.commitment': 42 },
      { 'a11y.done': Array.from({ length: 31 }, (_, i) => `item ${i}`).join('\n') },
      { 'a11y.done': 'x'.repeat(501) },
      { 'a11y.lang': '' },
      { 'a11y.lang': 'english' },
      { 'a11y.lang': 'e<n' },
      { 'a11y.alt.lang': 'he"><b' },
      { 'a11y.dir': 'auto' },
      { 'a11y.reviewed': '2026-02-30' },
      { 'a11y.reviewed': '25/09/2026' },
      { 'a11y.alt.lang': 'fr', 'a11y.alt.title': '' }, // a second language needs a title
      { 'a11y.alt.lang': 'en', 'a11y.alt.title': 'Statement' }, // and must differ from the main one
      { 'a11y.unknown': 'x' },
    ];
    for (const patch of bad) expect([patch, (await save(patch)).status]).toEqual([patch, 400]);
    // The whole statement is capped, even when every field is within its own limit.
    const big = Object.fromEntries(['commitment', 'standard', 'reviewNote'].flatMap((k) => [[`a11y.${k}`, 'x'.repeat(2000)], [`a11y.alt.${k}`, 'x'.repeat(2000)]]));
    for (const k of ['done', 'limits']) { big[`a11y.${k}`] = Array(16).fill('y'.repeat(499)).join('\n'); big[`a11y.alt.${k}`] = big[`a11y.${k}`]; }
    const total = Object.values(big).reduce((n, v) => n + v.length, 0);
    expect(total).toBeGreaterThan(A11Y_MAX_TOTAL);
    const r = await save(big);
    expect(r.status).toBe(400);
    expect((await r.json()).message).toMatch(/at most 32000 characters in all/);
    // Only the owner may edit it.
    const u = await makeUser('a11y-user');
    expect((await save({ 'a11y.title': 'Mine' }, u.cookie)).status).toBe(403);
    expect((await config()).statements[0].title).toBe('Access statement');
  });

  it('a full statement in a non-Latin script fits in one save', async () => {
    const ja = (n) => 'あ'.repeat(n); // three bytes each in UTF-8
    const list = Array(16).fill(ja(499)).join('\n');
    const patch = { 'a11y.alt.lang': 'ja', 'a11y.alt.dir': 'ltr', 'a11y.alt.title': ja(100), 'a11y.alt.commitment': ja(2000), 'a11y.alt.standard': ja(2000), 'a11y.alt.reviewNote': ja(2000), 'a11y.alt.done': list, 'a11y.alt.limits': list };
    expect(new TextEncoder().encode(JSON.stringify(patch)).length).toBeGreaterThan(64 * 1024);
    expect((await save(patch)).status).toBe(200);
    expect((await config()).statements[1].done).toHaveLength(16);
    expect((await save({ 'a11y.alt.lang': '' })).status).toBe(200);
  });

  it('logs changed keys only, long text by its length', async () => {
    const long = 'A commitment that is longer than sixty characters, to be logged by length.';
    expect((await save({ 'a11y.commitment': long, 'a11y.contact': 'access@example.test' })).status).toBe(200);
    const rows = (await (await fetchJson('/api/private/admin/audit', { cookie: oc })).json()).rows.filter((x) => x.action === 'settings.updated');
    expect(rows[0].detail).toBe(`a11y.commitment=(${long.length} characters)`);
  });

  it('travels in the settings part of an export and is re-validated on import', async () => {
    const doc = await exportDoc();
    for (const k of A11Y_KEYS) expect(doc.system.settings, k).toHaveProperty([k]);
    doc.system.settings['a11y.title'] = 'Imported statement';
    doc.system.settings['a11y.alt.lang'] = 'ar';
    doc.system.settings['a11y.alt.dir'] = 'rtl';
    doc.system.settings['a11y.alt.title'] = 'بيان إمكانية الوصول';
    const ok = await importDoc(doc, false);
    expect(ok.status).toBe(200);
    const plan = (await ok.json()).plan;
    expect(plan.system.settings).toEqual(expect.arrayContaining([expect.objectContaining({ key: 'a11y.title', to: 'Imported statement' })]));
    expect((await config()).statements.map((b) => [b.lang, b.title])).toEqual([['en', 'Imported statement'], ['ar', 'بيان إمكانية الوصول']]);
    // Each field is checked as on save…
    for (const mutate of [
      (d) => { d.system.settings['a11y.title'] = ''; },
      (d) => { d.system.settings['a11y.lang'] = 'not a code'; },
      (d) => { d.system.settings['a11y.dir'] = 'up'; },
      (d) => { d.system.settings['a11y.done'] = ['a list', 'is text']; },
      (d) => { d.system.settings['a11y.reviewed'] = 'soon'; },
    ]) {
      const d = structuredClone(doc);
      mutate(d);
      expect((await importDoc(d)).status).toBe(400);
    }
    // …and so are the rules across fields.
    const d = structuredClone(doc);
    d.system.settings['a11y.alt.title'] = '';
    const preview = await importDoc(d);
    expect(preview.status).toBe(200);
    expect((await preview.json()).plan.errors.join(' ')).toMatch(/second language needs a title/);
    const r = await importDoc(d, false);
    expect(r.status).toBe(409);
    expect((await config()).statements[1].title).toBe('بيان إمكانية الوصول');
  });

  it('the owner can restore the default (English only), keeping the contact and coordinator', async () => {
    // What "Restore the default statement" then "Save" sends: every statement
    // field at its default, the second language off and cleared.
    expect((await save({ 'a11y.contact': 'access@example.test', 'a11y.coordinator': 'Dana' })).status).toBe(200);
    expect((await config()).statements).toHaveLength(2); // edited, with a second language (above)
    const restore = Object.fromEntries(A11Y_KEYS.filter((k) => k !== 'a11y.contact' && k !== 'a11y.coordinator').map((k) => [k, A11Y_DEFAULTS[k]]));
    const u = await makeUser('a11y-restorer');
    expect((await save(restore, u.cookie)).status).toBe(403);
    const r = await save(restore);
    expect(r.status).toBe(200);
    const s = (await r.json()).settings;
    for (const k of Object.keys(restore)) expect(s[k], k).toBe(A11Y_DEFAULTS[k]);
    expect(await config()).toEqual(publicStatement({ ...A11Y_DEFAULTS, 'a11y.contact': 'access@example.test', 'a11y.coordinator': 'Dana' }));
    expect(JSON.stringify(await config())).not.toMatch(/[\u0590-\u05ff\u0600-\u06ff]/);
  });
});
