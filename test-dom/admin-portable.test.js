// admin-portable.test.js — Admin → Import / export, mounted in happy-dom with
// the API mocked: a table of users × parts on export and on import, the owner
// as one of the rows, "Select all" / "Deselect all" per column, and the
// import rule (an existing account takes only its role and passkeys, the owner
// only passkeys: the other parts are shown but disabled and never sent).
import { describe, it, expect, vi, beforeEach } from 'vitest';

const calls = { exportData: [], importData: [] };
let fileDoc = null;
vi.mock('../public/js/api.js', () => {
  class ApiError extends Error {}
  return {
    ApiError,
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
vi.mock('../public/js/pwauth.js', () => ({ loginProof: async () => 'proof' }));
vi.mock('../public/js/exportcrypt.js', () => {
  class ExportCryptError extends Error {}
  return { ExportCryptError, sealExport: async () => '{}', openExport: async () => structuredClone(fileDoc) };
});

const { renderPortable } = await import('../public/dashboard/js/admin-portable.js');
const profile = { user: { username: 'owner', role: 'owner' } };
const flush = () => new Promise((r) => setTimeout(r, 0));
const until = async (fn) => { for (let i = 0; i < 50 && !fn(); i++) await flush(); expect(fn()).toBeTruthy(); };
const q = (root, label) => root.querySelector(`[aria-label="${label}"]`);
const click = (root, label) => q(root, label).click();

let panel;
beforeEach(async () => {
  calls.exportData.length = 0;
  calls.importData.length = 0;
  URL.createObjectURL = () => 'blob:x';
  URL.revokeObjectURL = () => {};
  document.body.replaceChildren();
  panel = document.body.appendChild(document.createElement('div'));
  await renderPortable(panel, profile);
});
const cards = () => panel.querySelectorAll('.card');

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
    click(exp, 'Select all: users to export');
    expect(['owner', 'alice', 'bob'].every((n) => q(exp, `Export ${n}`).checked)).toBe(true);
    click(exp, 'Select all: Passkeys for every user');
    click(exp, 'Select all: Recovery codes for every user');
    expect(['owner', 'alice', 'bob'].every((n) => q(exp, `Passkeys for ${n}`).checked && q(exp, `Recovery codes for ${n}`).checked)).toBe(true);
    click(exp, 'Deselect all: Recovery codes for every user');
    expect(['owner', 'alice', 'bob'].some((n) => q(exp, `Recovery codes for ${n}`).checked)).toBe(false);
    q(exp, 'Recovery codes for bob').click();
    click(exp, 'Deselect all: Role for every user');
    q(exp, 'Your password').value = 'pw';
    [...exp.querySelectorAll('button')].find((b) => b.textContent === 'Encrypt and download').click();
    await until(() => calls.exportData.length === 1);
    const body = calls.exportData[0];
    expect(body.owner).toEqual(['passkeys']);
    expect(body.users).toEqual([
      { id: 'a'.repeat(16), parts: ['passkeys'] },
      { id: 'b'.repeat(16), parts: ['passkeys', 'recoveryCodes'] },
    ]);
  });

  it('an owner row with no part chosen is refused', async () => {
    const exp = cards()[0];
    q(exp, 'Export owner').click();
    q(exp, 'Your password').value = 'pw';
    [...exp.querySelectorAll('button')].find((b) => b.textContent === 'Encrypt and download').click();
    await until(() => /Choose what to export for "owner"/.test(exp.querySelector('p.msg').textContent));
    expect(calls.exportData).toHaveLength(0);
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
    q(imp, 'Your password').value = 'pw';
    [...imp.querySelectorAll('button')].find((b) => b.textContent === 'Preview').click();
    await until(() => calls.importData.length === 1);
    const d = calls.importData[0].decisions;
    expect(calls.importData[0].dryRun).toBe(true);
    expect(d.owner).toEqual({ passkeys: true });
    expect(d.users.bob).toEqual({ as: 'bob', action: 'update', parts: ['passkeys'] });
    expect(d.users.carol).toEqual({ as: 'carol', action: 'create', parts: ['credentials', 'apiKeys', 'passkeys', 'recoveryCodes'] });
  });

  it('an existing row with nothing applicable chosen is refused', async () => {
    const imp = await open();
    q(imp, 'Action for bob').value = 'update';
    q(imp, 'Action for bob').dispatchEvent(new Event('change'));
    q(imp, 'Import Role for bob').click();
    q(imp, 'Import Passkeys for bob').click();
    q(imp, 'Your password').value = 'pw';
    [...imp.querySelectorAll('button')].find((b) => b.textContent === 'Preview').click();
    await until(() => /Choose what to import for "bob"/.test(imp.querySelector('p.msg:not([hidden])')?.textContent || ''));
    expect(calls.importData).toHaveLength(0);
  });
});
