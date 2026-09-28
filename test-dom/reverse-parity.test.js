// reverse-parity.test.js — "Receive" links (reverse shares) with the options
// regular shares have, in the browser: the Drive's Receive… dialog (no
// expiry, views, the uploader password as the role says), the Drive client's
// updateReverse (the note and the password sealed with the link's key, the
// server sent only sealed values), and the Edit form of My shares
// (reverse-edit.js: what it sends, what the role hides or fixes, labels).
// Synthetic data only.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { startDrive, reverseOptions } from '../public/dashboard/js/drive-app.js';
import { reverseViews, reversePasswordChoice, reverseEditPatch, reverseEditForm, saveReverseEdit, weakensLink } from '../public/dashboard/js/reverse-edit.js';
import * as drive from '../public/js/driveclient.js';
import { setReverseStretcher, createReverseKey, newReverseId, openNote, passwordProof } from '../public/js/reversekeys.js';
import { clearSessionKey, clearImpersonationKeys, sealLinkKey } from '../public/js/drivekeys.js';
import { hkdf32 } from '../public/js/crypto.js';
import { utf8, bytesFromB64url, b64urlFromBytes } from '../public/js/bytes.js';
import { expiresText, viewsText } from '../public/js/common.js';
import { revokeShare } from '../public/js/api.js';
import { fakeServer, seedTree } from './drive-fake-server.js';

setReverseStretcher(async (pw, salt) => hkdf32(pw, salt, utf8('dom-stretch')));

const until = async (fn, ms = 5000) => {
  const t0 = Date.now();
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() - t0 > ms) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 10));
  }
};
const $ = (s) => document.querySelector(s);
const button = (root, text) => [...root.querySelectorAll('button')].find((b) => b.textContent.trim() === text);
const dialog = () => document.querySelector('.drive-dialog [role="dialog"]');
const now = () => Math.floor(Date.now() / 1000);

beforeEach(() => { document.body.replaceChildren(); clearSessionKey(); clearImpersonationKeys(); });
afterEach(() => { vi.restoreAllMocks(); });

// ── the pure helpers ─────────────────────────────────────────────────────────
describe('the options as typed', () => {
  it('reverseOptions: no expiry and views, as the role allows', () => {
    const L = { reverseNoExpiry: true, reverseMaxViews: 10, reverseAllowUnlimitedViews: true };
    expect(reverseOptions({ n: '3', unit: 'd', noExpiry: true, unlimited: true }, L)).toMatchObject({ expire: 'never', views: null });
    expect(reverseOptions({ n: '3', unit: 'd', noExpiry: true }, { ...L, reverseNoExpiry: false }).field).toBe('expire');
    expect(reverseOptions({ n: '3', unit: 'd', views: '4', unlimited: false }, L)).toMatchObject({ expire: '3d', views: 4, expiryText: '3 days' });
    expect(reverseOptions({ n: '3', unit: 'd', views: '11', unlimited: false }, L).field).toBe('views');
    expect(reverseOptions({ n: '3', unit: 'd', unlimited: true }, { reverseAllowUnlimitedViews: false }).field).toBe('views');
    expect(reverseOptions({ n: '2', unit: 'd' }, { reverseMaxExpireSec: 86400 }).field).toBe('expire');
  });

  it('reverseViews never goes below the views used; reversePasswordChoice follows reversePassword', () => {
    expect(reverseViews({ views: '2', unlimited: false }, {}, 3).field).toBe('views');
    expect(reverseViews({ views: '3', unlimited: false }, {}, 3)).toEqual({ views: 3 });
    expect(reverseViews({ views: '0', unlimited: false }, {})).toMatchObject({ field: 'views' });
    expect(reversePasswordChoice({ reversePassword: 'require' })).toMatchObject({ show: true, checked: true, disabled: true });
    expect(reversePasswordChoice({ reversePassword: 'off' })).toMatchObject({ show: false });
    expect(reversePasswordChoice({ reversePassword: 'allow', reversePasswordDefault: 'on' })).toMatchObject({ show: true, checked: true, disabled: false });
    expect(reversePasswordChoice({ reversePassword: 'allow', reversePasswordDefault: 'off' })).toMatchObject({ checked: false });
  });

  it('reverseEditPatch sends only what changed, within the role', () => {
    const t = 1_900_000_000;
    const cur = { expires: t + 3600, views: 5, used: 2, maxFiles: 3, maxBytes: 1024 * 1024, maxFileBytes: null, types: null, captcha: false, password: true, note: false };
    const same = { expiry: 'keep', views: '5', unlimited: false, maxFiles: '3', maxMb: '1', fileMb: '', typeMode: 'any', captcha: false, password: 'keep', note: 'keep' };
    const L = { reverseNoExpiry: true, reverseMaxViews: null };
    expect(reverseEditPatch(same, cur, L, t)).toMatchObject({ error: 'Nothing to change.' });
    // Expiry: extended from the current one; none; given one (a link without).
    expect(reverseEditPatch({ ...same, expiry: 'extend', n: '2', unit: 'h' }, cur, L, t).patch).toEqual({ expires: t + 3600 + 7200 });
    expect(reverseEditPatch({ ...same, expiry: 'none' }, cur, L, t).patch).toEqual({ expires: null });
    expect(reverseEditPatch({ ...same, expiry: 'none' }, cur, { reverseNoExpiry: false }, t).field).toBe('expire');
    expect(reverseEditPatch({ ...same, expiry: 'extend', n: '1', unit: 'd' }, { ...cur, expires: null }, L, t).patch).toEqual({ expires: t + 86400 });
    expect(reverseEditPatch({ ...same, expiry: 'extend', n: '400', unit: 'd' }, cur, L, t).field).toBe('expire');
    expect(reverseEditPatch({ ...same, expiry: 'extend', n: '2', unit: 'd' }, cur, { ...L, reverseMaxExpireSec: 86400 }, t).field).toBe('expire');
    // Views: lowered to the used ones, never below; unlimited only where allowed.
    expect(reverseEditPatch({ ...same, views: '2' }, cur, L, t).patch).toEqual({ views: 2 });
    expect(reverseEditPatch({ ...same, views: '1' }, cur, L, t).field).toBe('views');
    expect(reverseEditPatch({ ...same, unlimited: true }, cur, L, t).patch).toEqual({ views: null });
    expect(reverseEditPatch({ ...same, unlimited: true }, cur, { ...L, reverseAllowUnlimitedViews: false }, t).field).toBe('views');
    // Limits, CAPTCHA.
    expect(reverseEditPatch({ ...same, maxFiles: '', maxMb: '2', fileMb: '0.5', typeMode: 'allow', typeRules: 'ext:pdf', captcha: true }, cur, L, t).patch)
      .toEqual({ maxFiles: null, maxBytes: 2 * 1024 * 1024, maxFileBytes: 512 * 1024, types: { mode: 'allow', rules: ['ext:pdf'] }, captcha: true });
    expect(reverseEditPatch({ ...same, maxMb: '2' }, cur, { ...L, reverseMaxBytes: 1024 * 1024 }, t).field).toBe('bytes');
    // "No limit" is the role's limit: unchanged when that is what it has.
    expect(reverseEditPatch({ ...same, maxMb: '' }, cur, { ...L, reverseMaxBytes: 1024 * 1024 }, t)).toMatchObject({ error: 'Nothing to change.' });
    // Password and note.
    expect(reverseEditPatch({ ...same, password: 'change', pw1: 'a', pw2: 'b' }, cur, L, t).field).toBe('pw2');
    expect(reverseEditPatch({ ...same, password: 'change', pw1: 'new one', pw2: 'new one' }, cur, L, t).patch).toEqual({ password: 'new one' });
    expect(reverseEditPatch({ ...same, password: 'remove' }, cur, L, t).patch).toEqual({ removePassword: true });
    expect(reverseEditPatch({ ...same, password: 'remove' }, cur, { ...L, reversePassword: 'require' }, t).field).toBe('pw');
    expect(reverseEditPatch({ ...same, note: 'change', noteText: '  hello  ' }, cur, L, t).patch).toEqual({ note: 'hello' });
    expect(reverseEditPatch({ ...same, note: 'remove' }, cur, L, t).patch).toEqual({ note: '' });
  });

  it('the lists say "No expiry" and a Receive link\'s views', () => {
    expect(expiresText({ expires: null, status: 'active' })).toBe('No expiry');
    expect(expiresText({ expires: now() + 90000, status: 'active' })).toMatch(/^in 1d/);
    expect(viewsText({ kind: 'reverse', views_total: 2, left: 1, received: { files: 3 } })).toBe('3 files received · 1 left of 2 views');
    expect(viewsText({ kind: 'reverse', views_total: null, received: { files: 1 } })).toBe('1 file received · unlimited views');
    expect(viewsText({ kind: 'text', views_total: 2, left: 1 })).toBe('1 left of 2');
  });
});

// ── the Drive: Receive… ──────────────────────────────────────────────────────
let S;
let ids;
async function server() {
  S = fakeServer({ capacity: 50 * 1024 * 1024 });
  globalThis.fetch = S.fetch;
  ids = await seedTree(S, { Documents: {} });
  return S;
}
const BASE = { maxViews: 100, allowUnlimitedViews: true, maxExpireSec: null, files: true, reverseMaxBytes: 1024 ** 3 };
const profileWith = (limits) => ({ limits: { ...BASE, ...limits }, caps: { driveEnabled: true, reverseEnabled: true }, viewer: { enabled: false } });
function mountPoint() {
  const mount = document.createElement('div');
  document.body.replaceChildren(document.createElement('main'), mount);
  document.body.firstChild.id = 'main';
  return mount;
}
const confirm = async (input) => ({ current: `proof:${input.value}` });
const deps = (profile) => ({ drive, profile, user: S.user, confirm, canUsePasskey: async () => false, revoke: revokeShare });
async function openReceive(profile) {
  await server();
  const r = await startDrive(mountPoint(), deps(profile));
  await r.app.ready;
  $('#drive-receive').click();
  await until(() => dialog());
  await until(() => $('#drive-rev-none'));
}

describe('Drive: Receive… with no expiry, views and the password mode', () => {
  it('the Default role: no "No expiry" box, unlimited views pre-set, the password box off', async () => {
    await openReceive(profileWith({ reverseNoExpiry: false, reverseAllowUnlimitedViews: true, reversePassword: 'allow', reversePasswordDefault: 'off' }));
    expect(dialog().querySelector('.modal-title').textContent).toBe('Receive into “My Drive”');
    expect($('#drive-rev-noexpire')).toBeNull();
    expect($('#drive-rev-unlimited').getAttribute('aria-pressed')).toBe('true');
    expect($('#drive-rev-views').disabled).toBe(true);
    expect(document.querySelector('label[for="drive-rev-views"]').textContent).toBe('Views');
    expect($('#drive-rev-views').getAttribute('aria-describedby')).toBe('drive-rev-views-hint');
    expect($('#drive-rev-views-hint').textContent).toMatch(/A view is one visit that starts sending files/);
    expect($('#drive-rev-pw-on').checked).toBe(false);
    expect($('#drive-rev-pw-on').disabled).toBe(false);
  });

  it('creates a link with no expiry, 2 views and the password the role requires; the server gets "never" and 2', async () => {
    await openReceive(profileWith({ reverseNoExpiry: true, reverseMaxViews: 5, reversePassword: 'require' }));
    expect($('#drive-rev-pw-on').checked).toBe(true);
    expect($('#drive-rev-pw-on').disabled).toBe(true);
    expect($('#drive-rev-pw').closest('.drive-share-pw').hidden).toBe(false);
    expect($('#drive-rev-pw-on').closest('label').textContent).toMatch(/your role requires one/);
    const noExp = $('#drive-rev-noexpire');
    expect(noExp.closest('label').textContent).toBe('No expiry');
    expect(noExp.getAttribute('aria-describedby')).toBe('drive-rev-noexpire-hint');
    noExp.click();
    expect($('#drive-rev-expire').disabled).toBe(true);
    $('#drive-rev-unlimited').click();
    expect($('#drive-rev-views').disabled).toBe(false);
    $('#drive-rev-views').value = '9';
    $('#drive-rev-confirm').value = 'account pw';
    // Over the role's views: refused before anything is sent, the field marked.
    button(dialog(), 'Create link').click();
    await until(() => dialog().textContent.includes('Views must be a whole number from 1 to 5'));
    expect(S.reverse).toHaveLength(0);
    $('#drive-rev-views').value = '2';
    // The required password: empty is refused.
    button(dialog(), 'Create link').click();
    await until(() => dialog().textContent.includes('Enter a password'));
    $('#drive-rev-pw').value = 'up-pass';
    $('#drive-rev-pw2').value = 'up-pass';
    button(dialog(), 'Create link').click();
    await until(() => $('#drive-rev-url'));
    expect(S.reverse[0]).toMatchObject({ expire: 'never', views: 2 });
    expect(Object.keys(S.reverse[0].password).sort()).toEqual(['ph', 'salt', 't']);
    expect(JSON.stringify(S.reverse[0])).not.toContain('up-pass');
    expect(dialog().querySelector('.modal-sub').textContent).toMatch(/as long as the link is not revoked \(2 views\)/);
  });

  it('the role without unlimited views: ∞ is off and disabled; "off" hides the password box', async () => {
    await openReceive(profileWith({ reverseAllowUnlimitedViews: false, reversePassword: 'off' }));
    expect($('#drive-rev-unlimited').getAttribute('aria-pressed')).toBe('false');
    expect($('#drive-rev-unlimited').disabled).toBe(true);
    expect($('#drive-rev-views').disabled).toBe(false);
    expect($('#drive-rev-pw-on')).toBeNull();
  });

  it('the folder\'s links: "No expiry" and views', async () => {
    await server();
    const id = newReverseId();
    const { privateKey } = await createReverseKey();
    const mek = S.current().id;
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey));
    const priv = await sealLinkKey(await S.kekOf(mek), { userId: S.user.id, mekId: mek, linkId: id }, pkcs8);
    S.reverse.push({ id, folder: 'root', label: 'forever', priv, mek, status: 'active', files: 1, bytes: 5, created: now() - 60, expires: null, views: 3, used: 1 });
    const r = await startDrive(mountPoint(), deps(profileWith({})));
    await r.app.ready;
    $('#drive-receive').click();
    await until(() => $('#drive-rev-table'));
    const cells = [...$('#drive-rev-table tbody tr').children].map((c) => c.textContent);
    expect(cells[2]).toBe('No expiry');
    expect(cells[4]).toBe('2 left of 3');
    expect([...$('#drive-rev-table thead tr').children].map((c) => c.textContent)).toEqual(['Label', 'Created', 'Expires', 'Received', 'Views', 'Status', 'Actions']);
  });
});

describe('Drive: Edit a link from its lists', () => {
  async function seeded(profile, folder = 'root') {
    await server();
    const id = newReverseId();
    const { pub, privateKey } = await createReverseKey();
    const mek = S.current().id;
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey));
    const priv = await sealLinkKey(await S.kekOf(mek), { userId: S.user.id, mekId: mek, linkId: id }, pkcs8);
    S.reverse.push({ id, folder: folder === 'root' ? 'root' : ids.get(folder), label: 'inbox', priv, mek, status: 'active', files: 0, bytes: 0, created: now() - 60, expires: now() + 86400, views: 2, used: 1 });
    const r = await startDrive(mountPoint(), deps(profile));
    await r.app.ready;
    return { id, pub };
  }

  it('the Receive dialog: Edit turns it into the form; Save sends the change, the note sealed with the link\'s key', async () => {
    const { id, pub } = await seeded(profileWith({ reverseNoExpiry: true }));
    $('#drive-receive').click();
    await until(() => $('#drive-rev-table'));
    button($('#drive-rev-table tbody tr'), 'Edit').click();
    await until(() => dialog().querySelector('.rev-edit'));
    expect(dialog().querySelector('.modal-title').textContent).toBe('Edit “inbox”');
    const groups = dialog().querySelectorAll('fieldset.rev-edit-group');
    const confirmBox = dialog().querySelector('input[id$="-confirm"]').closest('.dfield');
    expect(confirmBox.hidden).toBe(true); // nothing weakens the link yet
    groups[0].querySelectorAll('input')[2].click(); // No expiry
    groups[0].querySelectorAll('input')[2].dispatchEvent(new Event('change', { bubbles: true }));
    // No expiry weakens it: the account password is asked for.
    expect(confirmBox.hidden).toBe(false);
    expect(dialog().querySelector(`label[for="${dialog().querySelector('input[id$="-confirm"]').id}"]`).textContent).toMatch(/Your account password/);
    dialog().querySelector('input[id$="-confirm"]').value = 'my account pw';
    groups[2].querySelectorAll('input')[1].click(); // the note: Add one
    groups[2].querySelectorAll('input')[1].dispatchEvent(new Event('change'));
    dialog().querySelector('textarea[id$="-note"]').value = 'drop the scans here';
    dialog().querySelector('input[id$="-views"]').value = '1'; // lowered to the one used
    button(dialog(), 'Save changes').click();
    await until(() => S.patches?.length);
    const sent = S.patches.at(-1);
    expect(sent).toMatchObject({ id, body: { expires: null, views: 1, current: 'proof:my account pw' } });
    expect(JSON.stringify(sent.body)).not.toContain('drop the scans');
    expect(await openNote(pub, id, sent.body.note)).toBe('drop the scans here');
    await until(() => !dialog());
  });

  it('"Remove it" (the password) is sent, with the confirmation; a tightening change asks for none (audit L1)', async () => {
    const { id } = await seeded(profileWith({}));
    S.reverse[0].password = { salt: 'x', t: 3, ph: 'y' };
    const openEdit = async () => {
      $('#drive-receive').click();
      await until(() => $('#drive-rev-table'));
      button($('#drive-rev-table tbody tr'), 'Edit').click();
      await until(() => dialog().querySelector('.rev-edit'));
    };
    await openEdit();
    const pwGroup = [...dialog().querySelectorAll('fieldset.rev-edit-group')].find((f) => /Uploader password/.test(f.querySelector('legend').textContent));
    const remove = [...pwGroup.querySelectorAll('input')].find((x) => x.closest('label').textContent === 'Remove it');
    remove.click();
    remove.dispatchEvent(new Event('change', { bubbles: true }));
    dialog().querySelector('input[id$="-confirm"]').value = 'acct';
    button(dialog(), 'Save changes').click();
    await until(() => S.patches?.length);
    expect(S.patches.at(-1)).toEqual({ id, body: { password: null, current: 'proof:acct' } });
    await until(() => !dialog());
    // With more views too: both are sent (the removal is never dropped).
    S.reverse[0].password = { salt: 'x', t: 3, ph: 'y' };
    await openEdit();
    const pw2 = [...dialog().querySelectorAll('fieldset.rev-edit-group')].find((f) => /Uploader password/.test(f.querySelector('legend').textContent));
    [...pw2.querySelectorAll('input')].find((x) => x.closest('label').textContent === 'Remove it').click();
    dialog().querySelector('input[id$="-views"]').value = '3';
    button(dialog(), 'Save changes').click();
    await until(() => S.patches.length === 2);
    expect(S.patches.at(-1).body).toMatchObject({ password: null, views: 3 });
    await until(() => !dialog());
    // Raising the views only: tightening nothing away, no confirmation asked or sent.
    await openEdit();
    dialog().querySelector('input[id$="-views"]').value = '4';
    dialog().querySelector('input[id$="-views"]').dispatchEvent(new Event('input', { bubbles: true }));
    expect(dialog().querySelector('input[id$="-confirm"]').closest('.dfield').hidden).toBe(true);
    button(dialog(), 'Save changes').click();
    await until(() => S.patches.length === 3);
    expect(S.patches.at(-1).body).toEqual({ views: 4 });
  });

  it('the Drive client refuses an empty change instead of reporting success', async () => {
    await server();
    const c = await drive.openDrive({ user: S.user });
    await expect(c.updateReverse('rX', {})).rejects.toThrow(/Nothing to change/);
    await expect(c.updateReverse('rX', { current: 'p' })).rejects.toThrow(/Nothing to change/);
    expect(S.patches ?? []).toHaveLength(0);
  });

  it('a folder\'s Shares: its links with "No expiry", views and Edit; no Edit where the role does not allow it', async () => {
    for (const edit of [true, false]) {
      await seeded(profileWith({ reverseEdit: edit }), 'Documents');
      S.reverse[0].expires = null;
      const tr = [...document.querySelectorAll('#drive-rows tr')].find((x) => x.children[1].textContent.trim() === 'Documents');
      button(tr, 'Shares').click();
      await until(() => dialog()?.querySelector('#drive-shares-table'));
      const row = dialog().querySelector('#drive-shares-table tbody tr');
      expect(row.querySelector('td[data-label="Expires"]').textContent).toBe('No expiry');
      expect(row.querySelector('td[data-label="Views"]').textContent).toBe('0 files received · 1 left of 2 views');
      expect(!!button(row, 'Edit'), `reverseEdit ${edit}`).toBe(edit);
      if (edit) {
        button(row, 'Edit').click();
        await until(() => dialog().querySelector('.rev-edit'));
        expect(dialog().querySelector('legend').textContent).toMatch(/It has no expiry now/);
      }
      dialog().dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
      await until(() => !dialog());
    }
  });
});

// ── the Drive client: updateReverse ──────────────────────────────────────────
describe('DriveClient.updateReverse', () => {
  it('seals the note and the password with the link\'s key; the server sees neither', async () => {
    await server();
    const id = newReverseId();
    const { pub, privateKey } = await createReverseKey();
    const mek = S.current().id;
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey));
    const priv = await sealLinkKey(await S.kekOf(mek), { userId: S.user.id, mekId: mek, linkId: id }, pkcs8);
    S.reverse.push({ id, folder: 'root', label: 'x', priv, mek, status: 'active', files: 0, bytes: 0, created: 1, expires: null, views: null, used: 0 });
    const c = await drive.openDrive({ user: S.user });
    await c.updateReverse(id, { note: 'please send the forms', password: 'gate words', views: 4, expires: null });
    const sent = S.patches.at(-1);
    expect(sent.id).toBe(id);
    expect(sent.body.views).toBe(4);
    expect(sent.body.expires).toBeNull();
    const raw = JSON.stringify(sent.body);
    expect(raw).not.toContain('please send the forms');
    expect(raw).not.toContain('gate words');
    // The note opens with the link's key; the password proof matches the gate (as the uploader's browser makes it).
    expect(await openNote(pub, id, sent.body.note)).toBe('please send the forms');
    const proof = await passwordProof('gate words', sent.body.password.salt, sent.body.password.t, pub);
    const h = b64urlFromBytes(new Uint8Array(await crypto.subtle.digest('SHA-256', bytesFromB64url(proof))));
    expect(h).toBe(sent.body.password.ph);
    // Removing both: nulls, and no key needed for a plain change.
    await c.updateReverse(id, { note: '', removePassword: true });
    expect(S.patches.at(-1).body).toEqual({ note: null, password: null });
    await c.updateReverse(id, { label: 'plain' });
    expect(S.patches.at(-1).body).toEqual({ label: 'plain' });
  });

  it('saveReverseEdit uses the Drive client only for the note or the password', async () => {
    const updateShare = vi.fn(async () => ({ ok: true }));
    const client = { updateReverse: vi.fn(async () => ({ ok: true })) };
    const driveClient = vi.fn(async () => client);
    await saveReverseEdit('rX', { views: 3, removePassword: true }, { updateShare, driveClient });
    expect(updateShare).toHaveBeenCalledWith('rX', { views: 3, password: null });
    expect(driveClient).not.toHaveBeenCalled();
    await saveReverseEdit('rX', { note: 'hi' }, { updateShare, driveClient });
    expect(client.updateReverse).toHaveBeenCalledWith('rX', { note: 'hi' });
  });
});

// ── the Edit form (My shares) ────────────────────────────────────────────────
describe('the Edit form of a Receive link', () => {
  const cur = { id: 'r1', expires: now() + 86400, views: 2, used: 2, maxFiles: null, maxBytes: 1024 * 1024, maxFileBytes: null, types: null, captcha: true, password: true, note: true };
  const mount = (form) => { document.body.replaceChildren(form.el); return form; };
  const labelled = (root) => [...root.querySelectorAll('input, select, textarea, button')].filter((el) => {
    if (el.type === 'radio' || el.type === 'checkbox') return !el.closest('label');
    if (el.tagName === 'BUTTON') return !el.getAttribute('aria-label') && !el.textContent.trim();
    return !el.getAttribute('aria-label') && !document.querySelector(`label[for="${el.id}"]`);
  });

  it('every control has a label; the choices follow the role', () => {
    const f = mount(reverseEditForm(cur, { limits: { reverseNoExpiry: true, reversePassword: 'allow', reverseCaptcha: 'allow' } }));
    expect(labelled(document.body)).toEqual([]);
    const legends = [...document.querySelectorAll('legend')].map((l) => l.textContent);
    expect(legends[0]).toMatch(/^Expiry — It expires in/);
    const radios = (i) => [...document.querySelectorAll('fieldset.rev-edit-group')[i].querySelectorAll('label.radio-opt')].map((l) => l.textContent);
    expect(radios(0)).toEqual(['Keep it', 'Extend it', 'No expiry (it accepts files until you revoke it)']);
    expect(radios(1)).toEqual(['Keep it', 'Change it', 'Remove it']);
    expect(radios(2)).toEqual(['Keep it', 'Replace it', 'Remove it']);
    expect(document.querySelector('[id$="views-hint"]').textContent).toMatch(/^2 used so far/);
    // The role requires a password and the CAPTCHA, and has no "no expiry".
    const g = mount(reverseEditForm(cur, { limits: { reverseNoExpiry: false, reversePassword: 'require', reverseCaptcha: 'require' } }));
    expect(radios(0)).toEqual(['Keep it', 'Extend it']);
    expect(radios(1)).toEqual(['Keep it', 'Change it']);
    expect(document.querySelector('input[type="checkbox"]').disabled).toBe(true);
    // Passwords off, the link without one: nothing to choose, no group.
    mount(reverseEditForm({ ...cur, password: false }, { limits: { reversePassword: 'off' } }));
    expect(document.querySelectorAll('fieldset.rev-edit-group')).toHaveLength(2);
    expect(f && g).toBeTruthy();
  });

  it('asks for the account password only when a change weakens the link; never while the owner acts as the user', async () => {
    const link = { ...cur, views: 5, used: 1, captcha: true, password: true };
    // weakensLink: the password removed or changed, the CAPTCHA off, no expiry, unlimited views.
    for (const p of [{ expires: null }, { views: null }, { password: 'x' }, { removePassword: true }, { captcha: false }]) expect(weakensLink(p, link), JSON.stringify(p)).toBe(true);
    for (const p of [{ views: 2 }, { views: 9 }, { expires: now() + 99 }, { captcha: true }, { maxFiles: 1 }, { note: 'n' }]) expect(weakensLink(p, link), JSON.stringify(p)).toBe(false);
    expect(weakensLink({ password: 'x' }, { ...link, password: false })).toBe(false); // adding one tightens
    expect(weakensLink({ views: null }, { ...link, views: null })).toBe(false);
    const seen = [];
    const f = mount(reverseEditForm(link, { limits: { reverseNoExpiry: true }, user: { username: 'u' } }, { confirm: async (input) => { seen.push(input.value); return { current: 'proof' }; }, passkey: false }));
    const box = document.querySelector('input[id$="-confirm"]').closest('.dfield');
    expect(box.hidden).toBe(true);
    const capBox = document.querySelector('input[type="checkbox"][id$="-captcha"]');
    capBox.click(); // CAPTCHA off
    capBox.dispatchEvent(new Event('change', { bubbles: true }));
    expect(box.hidden).toBe(false);
    document.querySelector('input[id$="-confirm"]').value = 'typed';
    const o = f.read();
    expect(o.patch).toEqual({ captcha: false });
    expect(await f.stepUp(o.patch)).toEqual({ current: 'proof' });
    expect(seen).toEqual(['typed']);
    capBox.click(); // back on: nothing weakens it
    capBox.dispatchEvent(new Event('change', { bubbles: true }));
    expect(box.hidden).toBe(true);
    expect(await f.stepUp({ views: 9 })).toEqual({});
    // The owner acting as the user: never asked.
    const g = mount(reverseEditForm(link, { limits: {}, impersonatedBy: 'owner' }, { confirm: async () => { throw new Error('asked'); }, passkey: false }));
    expect(await g.stepUp({ captcha: false })).toEqual({});
    expect(document.querySelector('input[id$="-confirm"]').closest('.dfield').hidden).toBe(true);
  });

  it('a link with no expiry: "Give it an expiry"; the form reads what changed', () => {
    const f = mount(reverseEditForm({ ...cur, expires: null, views: null, used: 3 }, { limits: { reverseNoExpiry: true } }));
    const radios = [...document.querySelectorAll('fieldset.rev-edit-group')[0].querySelectorAll('input')];
    expect(radios.map((r) => r.closest('label').textContent)).toEqual(['Keep it', 'Give it an expiry']);
    expect(document.querySelector('legend').textContent).toMatch(/It has no expiry now/);
    radios[1].click();
    radios[1].dispatchEvent(new Event('change'));
    const expire = document.querySelector('[id$="-expire"]');
    expect(expire.closest('.opt').hidden).toBe(false);
    expire.value = '2';
    // Unlimited now: turning ∞ off gives a number from the used ones up.
    document.querySelector('.opt-toggle').click();
    const views = document.querySelector('[id$="-views"]');
    expect(views.min).toBe('3');
    views.value = '5';
    const o = f.read();
    expect(o.patch).toMatchObject({ views: 5 });
    expect(o.patch.expires).toBeGreaterThan(now() + 2 * 86400 - 10);
  });
});
