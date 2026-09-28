// drive-audit.test.js — the browser side of the Drive fixes from security
// audit round 2 (docs/DRIVE.md §3, §8.1), with the real client against the
// in-memory server (drive-fake-server.js):
//   L-1  finalize while a chunk write is in flight: finalized again, not failed;
//   L-6  a file without readable metadata, or whose size disagrees, is
//        unreadable, never an empty file;
//   names in every script kept, spoofing characters removed (round 3, L-5);
//   keys  the pages with third-party script keep the tab's Drive keys out of
//        sessionStorage.
// (H-1 and the escrow blocks covered the owner's escrow key and its pins,
// removed with the key model v2; the impersonated Drive is in
// driveclient.test.js and drive.test.js.)
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { openDrive } from '../public/js/driveclient.js';
import { clearSessionKey, holdSessionKeys, releaseSessionKeys } from '../public/js/drivekeys.js';
import { fakeServer, seedTree } from './drive-fake-server.js';

const enc = (s) => new TextEncoder().encode(s);
let S;
const install = (opts) => { S = fakeServer(opts); globalThis.fetch = S.fetch; return S; };
beforeEach(() => { clearSessionKey(); releaseSessionKeys(); clearSessionKey(); });
afterEach(() => { vi.restoreAllMocks(); });

function fakeFile(name, bytes, type = 'text/plain') {
  return { name, size: bytes.length, type, lastModified: 1700000000000, slice: (a, b) => ({ arrayBuffer: async () => bytes.slice(a, b).buffer }) };
}

describe('L-1: finalize while a chunk write is in flight', () => {
  it('the client finalizes again after "busy" instead of failing the upload', async () => {
    install();
    const c = await openDrive({ user: S.user });
    S.busyFinalize = 2;
    const id = await c.upload('root', fakeFile('late.txt', enc('written late')));
    expect(S.nodes.get(id).state).toBe('ready');
    expect(S.requests.filter((r) => r.path.endsWith('/finalize'))).toHaveLength(3);
  }, 30000);
});

describe('L-6: a file needs its sealed metadata', () => {
  it('missing metadata or a size that disagrees makes it unreadable, never an empty file', async () => {
    install();
    const ids = await seedTree(S, { 'a.txt': enc('hello a'), 'b.txt': enc('hello b'), 'c.txt': enc('hello c') });
    const a = S.nodes.get(ids.get('a.txt'));
    a.meta = null; a.size = 0; a.chunks = 0; // the server drops the metadata and claims an empty file
    const b = S.nodes.get(ids.get('b.txt'));
    b.size = 3; // a size that disagrees with the sealed one
    const c = await openDrive({ user: S.user });
    const { children } = await c.list();
    const by = Object.fromEntries(children.map((x) => [x.id, x]));
    expect(by[a.id]).toMatchObject({ unreadable: true, name: null });
    expect(by[b.id]).toMatchObject({ unreadable: true, name: null });
    expect(by[ids.get('c.txt')].name).toBe('c.txt');
    await expect(c.download(a.id)).rejects.toThrow(/cannot be read/);
    await expect(c.download(b.id)).rejects.toThrow(/cannot be read/);
    // Files whose metadata alone is gone do not make the tab drop its keys.
    S.nodes.get(ids.get('c.txt')).meta = null;
    await c.list();
    expect(c.keys.keks.get(S.current().id)).toBeDefined();
  }, 30000);
});

// Real names in every script stay exactly as they are; only the spoofing
// characters go (files.js cleanName), and display isolates the name and its
// extension (common.js nameEl).
const REAL_NAMES = ['דוח שנתי 2026.pdf', 'שָׁלוֹם.txt', 'report-דוח.docx', 'تقرير.pdf', 'می\u200cخواهم.txt', '👨\u200d👩\u200d👧 family.jpg', 'נקודה\u200f.txt'];

describe('names: real names kept, spoofing characters removed (audit round 3, L-5)', () => {
  it('cleanName, checkPath and both checkName keep Hebrew, niqqud, Arabic, ZWNJ / ZWJ and LRM / RLM unchanged', async () => {
    const { checkPath, cleanName } = await import('../public/js/files.js');
    const { checkName } = await import('../public/js/driveclient.js');
    const page = await import('../public/dashboard/js/drive-app.js');
    for (const n of REAL_NAMES) {
      expect(cleanName(n), n).toBe(n.normalize('NFC'));
      expect(checkPath(n)).toBe(n);
      expect(checkName(n)).toBe(n.normalize('NFC'));
      expect(page.checkName(n)).toEqual({ name: n.normalize('NFC') });
    }
    expect(checkPath('תיקייה/משנה/דוח.pdf')).toBe('תיקייה/משנה/דוח.pdf');
  });

  it('strips overrides, isolates, U+200B, U+FEFF and line separators — "invoice<RLO>fdp.exe" becomes invoicefdp.exe — and says so', async () => {
    const { cleanName } = await import('../public/js/files.js');
    const { checkName } = await import('../public/js/driveclient.js');
    const page = await import('../public/dashboard/js/drive-app.js');
    expect(cleanName('invoice\u202efdp.exe')).toBe('invoicefdp.exe');
    for (const [raw, out] of [['a\u200bb.txt', 'ab.txt'], ['x\u2028y', 'xy'], ['nel\u0085.txt', 'nel.txt'], ['rtl\u2067x\u2069.txt', 'rtlx.txt'], ['b\ufeffom', 'bom'], ['e\u0301.txt', '\u00e9.txt']]) {
      expect(cleanName(raw)).toBe(out);
      expect(checkName(raw)).toBe(out);
    }
    expect(page.checkName('invoice\u202efdp.exe')).toEqual({ name: 'invoicefdp.exe', renamed: true });
  });

  it('shows every name in a bidi isolate with its real extension as its own LTR isolate', async () => {
    const { nameEl } = await import('../public/js/common.js');
    for (const n of [...REAL_NAMES, 'invoice\u202efdp.exe', 'README']) {
      const el = nameEl(n);
      expect(el.tagName).toBe('BDI');
      expect(el.getAttribute('dir')).toBe('auto');
      const clean = n.replace(/\u202e/g, '').normalize('NFC');
      expect(el.textContent).toBe(clean);
      const ext = el.querySelector('bdi.fext');
      const dot = clean.lastIndexOf('.');
      if (dot > 0) {
        expect(ext.getAttribute('dir')).toBe('ltr');
        expect(ext.textContent).toBe(clean.slice(dot));
      } else {
        expect(ext).toBeNull();
      }
    }
    expect(nameEl('invoice\u202efdp.exe').querySelector('.fext').textContent).toBe('.exe');
  });

  it('the Drive stores and lists them unchanged (and cleans a spoofing one, marked renamed)', async () => {
    install();
    const c = await openDrive({ user: S.user });
    const dir = await c.mkdir('root', 'תיקייה');
    for (const n of REAL_NAMES) await c.upload(dir, fakeFile(n, enc(n)));
    await c.upload(dir, fakeFile('invoice\u202efdp.exe', enc('x')));
    const names = (await c.list(dir)).children.map((x) => x.name).sort();
    expect(names).toEqual([...REAL_NAMES.map((n) => n.normalize('NFC')), 'invoicefdp.exe'].sort());
    expect((await c.list('root')).children.map((x) => x.name)).toEqual(['תיקייה']);
  }, 60000);
});

describe('keys exposure: pages with third-party script', () => {
  it('no KEK is ever in sessionStorage; holdSessionKeys moves the old Drive key (the one slot a tab may keep) into memory, release puts it back', () => {
    sessionStorage.setItem('secbin_dk', 'D'.repeat(43));
    sessionStorage.setItem('secbin_dk_uid', 'u1');
    holdSessionKeys();
    expect(sessionStorage.getItem('secbin_dk')).toBeNull();
    releaseSessionKeys();
    expect(sessionStorage.getItem('secbin_dk')).toBe('D'.repeat(43));
    expect(sessionStorage.getItem('secbin_kek')).toBeNull();
  });
});

