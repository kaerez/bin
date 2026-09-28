// admin-portable.test.js — Admin → Import / export, mounted in happy-dom with
// the API mocked: a table of users × parts on export and on import, the owner
// as one of the rows, "Select all" / "Deselect all" per column, and the
// import rule (an existing account takes only its role and passkeys, the owner
// only passkeys: the other parts are shown but disabled and never sent), and
// the step-up of both (confirm.js, real: the typed password stretched into
// `current`, or, the field left empty, a passkey assertion as `reauth`); and
// the user id lists (id-list.js): on export a search, Select all / Deselect
// all of the rows shown, an uploaded id list and a download of the chosen ids;
// on import an uploaded list that only chooses the accounts to take over (the
// import rule unchanged) and a download of the ids in the file.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const calls = { exportData: [], importData: [], reauth: 0, prelogin: [] };
const pk = { supported: true, keys: 1 };
let fileDoc = null;
vi.mock('../public/js/api.js', () => {
  class ApiError extends Error {}
  return {
    ApiError,
    // confirm.js: the password's salt, the reauth challenge, whether the account has a passkey.
    prelogin: async (username) => { calls.prelogin.push(username); return { salt: 'S'.repeat(22), t: 3 }; },
    reauthOptions: async () => { calls.reauth++; return { challengeId: `ch${calls.reauth}`, publicKey: { challenge: 'c' } }; },
    myPasskeys: async () => ({ mode: 'any', passkeys: Array.from({ length: pk.keys }, (_, i) => ({ id: `p${i}` })) }),
    admin: {
      users: async () => ({ users: [
        { id: 'o'.repeat(16), username: 'owner', role: 'owner' },
        { id: 'a'.repeat(16), username: 'alice', role: 'user' },
        { id: 'b'.repeat(16), username: 'bob', role: 'user' },
      ] }),
      exportData: async (body) => { calls.exportData.push(body); return { document: { format: 'secbin-export/v1', created: 1, users: [] } }; },
      importData: async (body) => { calls.importData.push(body); return { ok: true, applied: !body.dryRun, plan: { system: null, owner: null, users: [], errors: [], warnings: [] } }; },
    },
  };
});
vi.mock('../public/js/pwauth.js', () => ({ stretch: async (pw) => `stretched:${pw}` }));
vi.mock('../public/js/passkeys.js', () => ({
  passkeysSupported: () => pk.supported,
  usePasskey: async (publicKey) => ({ id: 'cred1', type: 'public-key', answered: publicKey.challenge }),
  usePasskeyPrf: async () => { throw new Error('not used here'); },
}));
vi.mock('../public/js/exportcrypt.js', () => {
  class ExportCryptError extends Error {}
  return { ExportCryptError, sealExport: async () => '{}', openExport: async () => structuredClone(fileDoc) };
});

const { renderPortable } = await import('../public/dashboard/js/admin-portable.js');
const profile = { user: { username: 'owner', role: 'owner' } };
const MINE = 'Your password (or leave it empty to confirm with a passkey)';
const flush = () => new Promise((r) => setTimeout(r, 0));
const until = async (fn) => { for (let i = 0; i < 50 && !fn(); i++) await flush(); expect(fn()).toBeTruthy(); };
const q = (root, label) => root.querySelector(`[aria-label="${label}"]`);
const click = (root, label) => q(root, label).click();

let panel;
beforeEach(async () => {
  calls.exportData.length = 0;
  calls.importData.length = 0;
  calls.prelogin.length = 0;
  calls.reauth = 0;
  Object.assign(pk, { supported: true, keys: 1 });
  URL.createObjectURL = () => 'blob:x';
  URL.revokeObjectURL = () => {};
  document.body.replaceChildren();
  panel = document.body.appendChild(document.createElement('div'));
  await renderPortable(panel, profile);
});
afterEach(() => { vi.restoreAllMocks(); });
const cards = () => panel.querySelectorAll('.card');
const pick = (input, files) => { Object.defineProperty(input, 'files', { configurable: true, get: () => files }); input.dispatchEvent(new Event('change')); };
/** What a download saves: the Blob and the file name. */
function captureSaves() {
  const saved = [];
  let last = null;
  URL.createObjectURL = (b) => { last = b; return 'blob:x'; };
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function click() { saved.push({ blob: last, name: this.download }); });
  return saved;
}
const A = 'a'.repeat(16);
const B = 'b'.repeat(16);
const O = 'o'.repeat(16);

describe('export', () => {
  it('the owner is the first row, with only passkeys and recovery codes (off by default)', () => {
    const exp = cards()[0];
    const rows = exp.querySelectorAll('table.part-table tbody tr');
    expect(rows).toHaveLength(3);
    expect(rows[0].textContent).toContain('owner (you, owner)');
    expect(q(exp, 'Passkeys for owner').checked).toBe(false);
    expect(q(exp, 'Recovery codes for owner').checked).toBe(false);
    for (const part of ['Credentials', 'Role', 'API keys']) expect(q(exp, `${part} for owner`)).toBeNull();
    expect(rows[0].querySelectorAll('[aria-label="never exported for the owner"]')).toHaveLength(3);
    // Users: a checkbox per part, the role on by default.
    for (const part of ['Credentials', 'Role', 'API keys', 'Passkeys', 'Recovery codes']) expect(q(exp, `${part} for alice`)).not.toBeNull();
    expect(q(exp, 'Role for alice').checked).toBe(true);
    expect(q(exp, 'Passkeys for alice').checked).toBe(false);
    expect(q(exp, 'Export owner').checked).toBe(false);
  });

  it('Select all / Deselect all per column include the owner row; the owner\'s parts go separately', async () => {
    const exp = cards()[0];
    click(exp, 'Select all: users to export (those shown)');
    expect(['owner', 'alice', 'bob'].every((n) => q(exp, `Export ${n}`).checked)).toBe(true);
    click(exp, 'Select all: Passkeys for every user');
    click(exp, 'Select all: Recovery codes for every user');
    expect(['owner', 'alice', 'bob'].every((n) => q(exp, `Passkeys for ${n}`).checked && q(exp, `Recovery codes for ${n}`).checked)).toBe(true);
    click(exp, 'Deselect all: Recovery codes for every user');
    expect(['owner', 'alice', 'bob'].some((n) => q(exp, `Recovery codes for ${n}`).checked)).toBe(false);
    q(exp, 'Recovery codes for bob').click();
    click(exp, 'Deselect all: Role for every user');
    q(exp, MINE).value = 'pw';
    [...exp.querySelectorAll('button')].find((b) => b.textContent === 'Encrypt and download').click();
    await until(() => calls.exportData.length === 1);
    const body = calls.exportData[0];
    expect(body.owner).toEqual(['passkeys']);
    expect(body.users).toEqual([
      { id: 'a'.repeat(16), parts: ['passkeys'] },
      { id: 'b'.repeat(16), parts: ['passkeys', 'recoveryCodes'] },
    ]);
  });

  it('the step-up: the typed password (stretched, the field cleared), or a passkey when the field is empty', async () => {
    const exp = cards()[0];
    const go = () => [...exp.querySelectorAll('button')].find((b) => b.textContent === 'Encrypt and download').click();
    // The field and its label (the label is the control's name).
    const mine = q(exp, MINE);
    expect(mine.type).toBe('password');
    expect(mine.closest('label').querySelector('.field-label').textContent).toBe(MINE);
    q(exp, 'Export alice').click();
    mine.value = 'owner pw';
    go();
    await until(() => calls.exportData.length === 1);
    expect(calls.exportData[0]).toMatchObject({ current: 'stretched:owner pw' });
    expect(calls.exportData[0].reauth).toBeUndefined();
    expect(calls.prelogin).toEqual(['owner']);
    expect(mine.value).toBe('');
    // Empty: a passkey (a fresh reauth challenge), no password proof.
    await until(() => !exp.querySelector('button.btn:not(.mini)').disabled);
    go();
    await until(() => calls.exportData.length === 2);
    expect(calls.exportData[1].reauth).toEqual({ challengeId: 'ch1', credential: { id: 'cred1', type: 'public-key', answered: 'c' } });
    expect(calls.exportData[1].current).toBeUndefined();
    expect(calls.reauth).toBe(1);
  });

  it('an empty field without a passkey (none on the account, or none in this browser) is refused, nothing sent', async () => {
    const exp = cards()[0];
    q(exp, 'Export alice').click();
    for (const state of [{ keys: 0 }, { supported: false }]) {
      Object.assign(pk, { supported: true, keys: 1 }, state);
      [...exp.querySelectorAll('button')].find((b) => b.textContent === 'Encrypt and download').click();
      await until(() => /Enter your current password/.test(exp.querySelector('#ax-msg').textContent));
      exp.querySelector('#ax-msg').textContent = '';
    }
    expect(calls.exportData).toHaveLength(0);
    expect(calls.reauth).toBe(0);
  });

  it('an owner row with no part chosen is refused', async () => {
    const exp = cards()[0];
    q(exp, 'Export owner').click();
    q(exp, MINE).value = 'pw';
    [...exp.querySelectorAll('button')].find((b) => b.textContent === 'Encrypt and download').click();
    await until(() => /Choose what to export for "owner"/.test(exp.querySelector('#ax-msg').textContent));
    expect(calls.exportData).toHaveLength(0);
  });
});


describe('export: the user id lists', () => {
  const exp = () => cards()[0];
  const shownNames = () => [...exp().querySelectorAll('#ax-users tr')].filter((tr) => !tr.hidden).map((tr) => tr.querySelector('td[data-label="User"]').firstChild.textContent);
  const picked = () => ['owner', 'alice', 'bob'].filter((n) => q(exp(), `Export ${n}`).checked);
  const find = (text) => { const s = exp().querySelector('#ax-search'); s.value = text; s.dispatchEvent(new Event('input')); };

  it('shows each user\'s id; the search finds by name or id; Select all / Deselect all take the rows shown', () => {
    expect([...exp().querySelectorAll('#ax-users tr')].map((tr) => tr.dataset.id)).toEqual([O, A, B]);
    expect(exp().querySelector('#ax-users tr[data-id="' + A + '"] td[data-label="User"]').textContent).toBe(`alice${A}`);
    const search = exp().querySelector('#ax-search');
    expect(search.type).toBe('search');
    expect(search.closest('label').querySelector('.field-label').textContent).toBe('Find users');
    expect(exp().querySelector('#ax-count').getAttribute('role')).toBe('status');
    expect(exp().querySelector('#ax-count').textContent).toBe('0 of 3 chosen');
    find('bo');
    expect(shownNames()).toEqual(['bob']);
    click(exp(), 'Select all: users to export (those shown)');
    expect(picked()).toEqual(['bob']);
    expect(exp().querySelector('#ax-count').textContent).toBe('1 of 3 chosen');
    find(A.slice(0, 5));
    expect(shownNames()).toEqual(['alice']);
    click(exp(), 'Select all: users to export (those shown)');
    expect(picked()).toEqual(['alice', 'bob']);
    find('');
    expect(shownNames()).toEqual(['owner (you, owner)', 'alice', 'bob']);
    find('nobody');
    expect(shownNames()).toEqual([]);
    click(exp(), 'Deselect all: users to export (those shown)'); // nothing shown: nothing changes
    expect(picked()).toEqual(['alice', 'bob']);
    find('ali');
    click(exp(), 'Deselect all: users to export (those shown)');
    expect(picked()).toEqual(['bob']);
    // The part checkboxes and their bulk toggles are still there, for every user.
    click(exp(), 'Select all: Passkeys for every user');
    expect(['owner', 'alice', 'bob'].every((n) => q(exp(), `Passkeys for ${n}`).checked)).toBe(true);
  });

  it('an uploaded id list chooses exactly those users (hidden or not), and they are what is exported', async () => {
    q(exp(), 'Export bob').click();
    const s = exp().querySelector('#ax-search');
    s.value = 'bob';
    s.dispatchEvent(new Event('input'));
    const upload = exp().querySelector('#ax-ids-file');
    expect(upload.closest('label').querySelector('.field-label').textContent).toBe('Choose from an id list (user ids only: one per line, or a JSON array)');
    pick(upload, [new File([`${A}\nnot-a-user-id\n${'z'.repeat(16)}\n`], 'ids.txt')]);
    await until(() => !exp().querySelector('#ax-ids-file-msg').hidden);
    expect(picked()).toEqual(['alice']);
    expect(exp().querySelector('#ax-ids-file-msg').textContent).toBe('1 of 2 ids in the list are accounts here and are now chosen; the others are not on this server.');
    expect(exp().querySelector('#ax-ids-file-msg').closest('[role="status"]')).not.toBeNull();
    // A JSON array too, the owner included.
    pick(upload, [new File([JSON.stringify([O, B])], 'ids.json')]);
    await until(() => picked().length === 2);
    expect(picked()).toEqual(['owner', 'bob']);
    q(exp(), 'Passkeys for owner').click();
    q(exp(), MINE).value = 'pw';
    [...exp().querySelectorAll('button')].find((b) => b.textContent === 'Encrypt and download').click();
    await until(() => calls.exportData.length === 1);
    expect(calls.exportData[0].owner).toEqual(['passkeys']);
    expect(calls.exportData[0].users).toEqual([{ id: B, parts: ['role'] }]);
  });

  it('downloads the chosen ids as a plain text list, user ids only', async () => {
    const saves = captureSaves();
    const down = exp().querySelector('#ax-ids-save');
    expect(down.textContent).toBe('Download the chosen ids (a list of user ids, no keys or credentials)');
    expect(exp().textContent).toMatch(/plain text file of the chosen user ids, one per line, with no keys, passwords or other credentials/);
    q(exp(), 'Export owner').click();
    q(exp(), 'Export bob').click();
    down.click();
    expect(saves).toHaveLength(1);
    expect(await saves[0].blob.text()).toBe(`${O}\n${B}\n`);
    expect(saves[0].blob.type).toBe('text/plain');
    expect(saves[0].name).toMatch(/^secbin-user-ids-.*\.txt$/);
    expect(calls.exportData).toHaveLength(0); // nothing sent to the server
  });
});

describe('import', () => {
  const key = (name) => ({ id: name.padEnd(22, 'x'), handle: null, name, publicKey: 'AAAA', alg: -7, signCount: 0, transports: [], backupEligible: false, backedUp: false, created: 1, lastUsed: null });
  const all = (name) => ({ username: name, credentials: { salt: 'A'.repeat(22), t: 3, verifier: 'a'.repeat(64), disabled: false }, role: 'Default', apiKeys: [], passkeys: { mfa: false, keys: [key(name)] }, recoveryCodes: ['c'.repeat(64)] });
  const open = async () => {
    fileDoc = { format: 'secbin-export/v1', created: 1, owner: { passkeys: { keys: [key('ownerkey')] }, recoveryCodes: ['d'.repeat(64)] }, users: [all('bob'), all('carol')] };
    const imp = cards()[1];
    const file = q(imp, 'Export file');
    Object.defineProperty(file, 'files', { value: [{ size: 10, text: async () => '{}' }] });
    [...imp.querySelectorAll('button')].find((b) => b.textContent === 'Decrypt').click();
    await until(() => q(imp, 'Action for the owner'));
    return imp;
  };

  it('the file\'s owner row goes to your account: passkeys only, recovery codes disabled', async () => {
    const imp = await open();
    const rows = imp.querySelectorAll('table.part-table tbody tr');
    expect(rows).toHaveLength(3);
    expect(rows[0].textContent).toContain('owner (in the file)');
    expect(rows[0].textContent).toContain('owner (you)');
    expect(q(imp, 'Action for the owner').value).toBe('skip');
    expect(q(imp, 'Import Passkeys for the owner').disabled).toBe(false);
    expect(q(imp, 'Import Passkeys for the owner').checked).toBe(true);
    expect(q(imp, 'Import Recovery codes for the owner').disabled).toBe(true);
    expect(q(imp, 'Import Recovery codes for the owner').checked).toBe(false);
    expect(rows[0].querySelectorAll('[aria-label="not in the file"]')).toHaveLength(3);
  });

  it('an existing user takes only its role and passkeys; a new one every part; renaming re-enables the parts', async () => {
    const imp = await open();
    expect(q(imp, 'Action for bob').value).toBe('skip');
    expect([...q(imp, 'Action for bob').options].map((o) => o.value)).toEqual(['skip', 'update']);
    for (const part of ['Credentials', 'API keys', 'Recovery codes']) {
      expect(q(imp, `Import ${part} for bob`).disabled).toBe(true);
      expect(q(imp, `Import ${part} for bob`).checked).toBe(false);
    }
    for (const part of ['Role', 'Passkeys']) expect(q(imp, `Import ${part} for bob`).checked).toBe(true);
    expect(q(imp, 'Action for carol').value).toBe('create');
    for (const part of ['Credentials', 'Role', 'API keys', 'Passkeys', 'Recovery codes']) expect(q(imp, `Import ${part} for carol`).disabled).toBe(false);
    // Renamed to the owner: passkeys only. Renamed to a new name: everything again.
    const as = q(imp, 'Import carol as');
    as.value = 'owner';
    as.dispatchEvent(new Event('input'));
    expect(q(imp, 'Import Role for carol').disabled).toBe(true);
    expect(q(imp, 'Import Passkeys for carol').disabled).toBe(false);
    as.value = 'carol2';
    as.dispatchEvent(new Event('input'));
    expect(q(imp, 'Import Recovery codes for carol').disabled).toBe(false);
    expect(q(imp, 'Import Recovery codes for carol').checked).toBe(true);
  });

  it('Select all / Deselect all: users take their usual action, parts skip what cannot apply; only applicable parts are sent', async () => {
    const imp = await open();
    click(imp, 'Select all: users to import');
    expect(q(imp, 'Action for the owner').value).toBe('update');
    expect(q(imp, 'Action for bob').value).toBe('update');
    expect(q(imp, 'Action for carol').value).toBe('create');
    click(imp, 'Deselect all: Recovery codes for every user');
    expect(q(imp, 'Import Recovery codes for carol').checked).toBe(false);
    click(imp, 'Select all: Recovery codes for every user');
    expect(q(imp, 'Import Recovery codes for carol').checked).toBe(true);
    expect(q(imp, 'Import Recovery codes for bob').checked).toBe(false); // disabled: never on an existing account
    expect(q(imp, 'Import Recovery codes for the owner').checked).toBe(false);
    click(imp, 'Deselect all: Role for every user');
    q(imp, MINE).value = 'pw';
    [...imp.querySelectorAll('button')].find((b) => b.textContent === 'Preview').click();
    await until(() => calls.importData.length === 1);
    const d = calls.importData[0].decisions;
    expect(calls.importData[0].dryRun).toBe(true);
    expect(d.owner).toEqual({ passkeys: true });
    expect(d.users.bob).toEqual({ as: 'bob', action: 'update', parts: ['passkeys'] });
    expect(d.users.carol).toEqual({ as: 'carol', action: 'create', parts: ['credentials', 'apiKeys', 'passkeys', 'recoveryCodes'] });
  });

  it('the preview and the import each confirm again: a passkey, or the typed password', async () => {
    const imp = await open();
    const mine = q(imp, MINE);
    expect(mine.closest('label').querySelector('.field-label').textContent).toBe(MINE);
    expect(imp.textContent).toContain('Confirms that it is you, for the preview and again for the import.');
    const button = (t) => [...imp.querySelectorAll('button')].find((b) => b.textContent === t);
    // The preview with a passkey (the field left empty).
    button('Preview').click();
    await until(() => calls.importData.length === 1);
    expect(calls.importData[0]).toMatchObject({ dryRun: true, reauth: { challengeId: 'ch1', credential: { id: 'cred1' } } });
    expect(calls.importData[0].current).toBeUndefined();
    await until(() => !button('Import').disabled);
    // The import with a passkey again (a new challenge), then a preview with the password.
    button('Import').click();
    await until(() => calls.importData.length === 2);
    expect(calls.importData[1]).toMatchObject({ dryRun: false, reauth: { challengeId: 'ch2' } });
    await until(() => !button('Preview').disabled);
    mine.value = 'owner pw';
    button('Preview').click();
    await until(() => calls.importData.length === 3);
    expect(calls.importData[2]).toMatchObject({ dryRun: true, current: 'stretched:owner pw' });
    expect(calls.importData[2].reauth).toBeUndefined();
    expect(mine.value).toBe('');
    // No passkey here: an empty field is refused and nothing is sent.
    await until(() => !button('Preview').disabled);
    pk.keys = 0;
    button('Preview').click();
    await until(() => /Enter your current password/.test(imp.querySelector('p.msg:not([hidden])')?.textContent || ''));
    expect(calls.importData).toHaveLength(3);
  });

  it('an existing row with nothing applicable chosen is refused', async () => {
    const imp = await open();
    q(imp, 'Action for bob').value = 'update';
    q(imp, 'Action for bob').dispatchEvent(new Event('change'));
    q(imp, 'Import Role for bob').click();
    q(imp, 'Import Passkeys for bob').click();
    q(imp, MINE).value = 'pw';
    [...imp.querySelectorAll('button')].find((b) => b.textContent === 'Preview').click();
    await until(() => /Choose what to import for "bob"/.test(imp.querySelector('p.msg:not([hidden])')?.textContent || ''));
    expect(calls.importData).toHaveLength(0);
  });
  describe('the user id lists', () => {
    const withIds = () => {
      fileDoc = { format: 'secbin-export/v1', created: 1, owner: { id: 'O'.repeat(16), passkeys: { keys: [key('ownerkey')] }, recoveryCodes: ['d'.repeat(64)] },
        users: [{ id: 'B'.repeat(16), ...all('bob') }, { id: 'C'.repeat(16), ...all('carol') }, { id: 'D'.repeat(16), username: 'dave', role: 'Default' }] };
    };
    const openIds = async () => {
      const imp = cards()[1];
      Object.defineProperty(q(imp, 'Export file'), 'files', { configurable: true, value: [{ size: 10, text: async () => '{}' }] });
      [...imp.querySelectorAll('button')].find((b) => b.textContent === 'Decrypt').click();
      await until(() => imp.querySelector('#ai-ids-file'));
      return imp;
    };
    const actions = (imp) => ['the owner', 'bob', 'carol', 'dave'].map((n) => q(imp, `Action for ${n}`).value);

    it('shows the ids in the file; an uploaded list takes over the accounts it names and skips the others, the import rule unchanged', async () => {
      withIds();
      const imp = await openIds();
      const cells = [...imp.querySelectorAll('table.part-table tbody td[data-label="User"]')].map((td) => td.textContent);
      expect(cells).toEqual([`owner (in the file)${'O'.repeat(16)}`, `bob${'B'.repeat(16)}`, `carol${'C'.repeat(16)}`, `dave${'D'.repeat(16)}`]);
      expect(actions(imp)).toEqual(['skip', 'skip', 'create', 'skip']);
      const upload = imp.querySelector('#ai-ids-file');
      expect(upload.closest('label').querySelector('.field-label').textContent).toBe('Choose from an id list (user ids only: one per line, or a JSON array)');
      // bob by the id of the account here, dave (no credentials: cannot be created); carol is not listed.
      pick(upload, [new File([`${B}\n${'D'.repeat(16)}\n${'z'.repeat(16)}\n`], 'ids.txt')]);
      await until(() => !imp.querySelector('#ai-ids-file-msg').hidden);
      expect(actions(imp)).toEqual(['skip', 'update', 'skip', 'skip']);
      expect(imp.querySelector('#ai-ids-file-msg').textContent).toBe('1 of 3 ids in the list are accounts in this file and are now taken over; every other account in the file is skipped. 1 account in the list cannot be created (no credentials in the file). Nothing changes until you import.');
      // bob exists here: still only its role and passkeys, whatever the list says.
      for (const part of ['Credentials', 'API keys', 'Recovery codes']) {
        expect(q(imp, `Import ${part} for bob`).disabled).toBe(true);
        expect(q(imp, `Import ${part} for bob`).checked).toBe(false);
      }
      // By the ids in the file: the owner row and carol.
      pick(upload, [new File([JSON.stringify(['O'.repeat(16), 'C'.repeat(16)])], 'ids.json')]);
      await until(() => q(imp, 'Action for carol').value === 'create' && q(imp, 'Action for bob').value === 'skip');
      expect(actions(imp)).toEqual(['update', 'skip', 'create', 'skip']);
      expect(q(imp, 'Import Recovery codes for the owner').disabled).toBe(true);
      pick(upload, [new File([`${B}\n${'C'.repeat(16)}\n`], 'ids.txt')]);
      await until(() => q(imp, 'Action for bob').value === 'update');
      q(imp, MINE).value = 'pw';
      [...imp.querySelectorAll('button')].find((b) => b.textContent === 'Preview').click();
      await until(() => calls.importData.length === 1);
      const d = calls.importData[0].decisions;
      expect(d.owner).toBe(false);
      expect(d.users).toEqual({
        bob: { as: 'bob', action: 'update', parts: ['role', 'passkeys'] },
        carol: { as: 'carol', action: 'create', parts: ['credentials', 'role', 'apiKeys', 'passkeys', 'recoveryCodes'] },
      });
      // A new list after a preview asks for a new preview.
      await until(() => !imp.querySelector('button.btn.danger').disabled);
      pick(upload, [new File([`${B}\n`], 'ids.txt')]);
      await until(() => q(imp, 'Action for carol').value === 'skip');
      expect(imp.querySelector('button.btn.danger').disabled).toBe(true);
    });

    it('downloads the ids in the file as a plain text list, user ids only', async () => {
      withIds();
      const imp = await openIds();
      const saves = captureSaves();
      const down = imp.querySelector('#ai-ids-save');
      expect(down.textContent).toBe('Download the ids in the file (a list of user ids, no keys or credentials)');
      expect(imp.textContent).toMatch(/An id list only chooses the accounts to take over/);
      expect(imp.textContent).toMatch(/An existing account keeps its password, recovery codes, API keys and passkeys whichever way it was chosen/);
      down.click();
      expect(await saves[0].blob.text()).toBe(`${'O'.repeat(16)}\n${'B'.repeat(16)}\n${'C'.repeat(16)}\n${'D'.repeat(16)}\n`);
      expect(saves[0].blob.type).toBe('text/plain');
      expect(calls.importData).toHaveLength(0);
    });

    it('a file without ids: nothing to download', async () => {
      const imp = await open();
      expect(imp.querySelector('#ai-ids-save').disabled).toBe(true);
      expect(imp.querySelectorAll('table.part-table tbody .mono.muted.block')).toHaveLength(0);
    });
  });
});
