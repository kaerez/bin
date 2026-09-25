// extract.js — write a file share's entries under an output directory, safely.
//
// The manifest is attacker-controlled data (the sender writes it), so even
// though files.js already rejects "..", absolute paths, backslashes and control
// characters, every write here is independently confined:
//   • each target is path.resolve(root, …segments) and must stay inside root;
//   • every path component below root is lstat'ed immediately before use and
//     must be a real directory — a symlink planted in the output directory is
//     never followed (no writing through links to ~/.bashrc or /etc);
//   • files are created O_EXCL (or, with --force, O_TRUNC|O_NOFOLLOW over a
//     regular file only) with mode 0600, directories with mode 0700;
//   • nothing existing is overwritten without --force.
// An interrupted file is removed, never left half-written under its real name.
import { constants } from 'node:fs';
import { lstat, mkdir, open, realpath, unlink } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { checkPath } from '../vendor/files.js';
import { UsageError } from './errors.js';

const NOFOLLOW = constants.O_NOFOLLOW ?? 0;
const CREATE_NEW = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW;
const OVERWRITE = constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | NOFOLLOW;
// Windows cannot represent these in a name (and ":" would address an NTFS
// alternate data stream); reserved device names map to devices, not files.
const WIN_BAD = /[<>:"|?*]|[. ]$/;
const WIN_RESERVED = /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\.|$)/i;

/** Refused for safety: a path would escape the output directory or cross a link. */
export class UnsafePathError extends Error {
  constructor(message) { super(message); this.name = 'UnsafePathError'; }
}

/** Existing files would be overwritten (and --force was not given). */
export class OverwriteError extends UsageError {
  constructor(message, paths) { super(message); this.name = 'OverwriteError'; this.paths = paths; }
}

const exists = async (p) => {
  try {
    return await lstat(p);
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw e;
  }
};

/** Absolute target for share-relative `rel`, guaranteed inside `root`. */
export function targetPath(root, rel, platform = process.platform) {
  try {
    checkPath(rel);
  } catch (e) {
    throw new UnsafePathError(`refusing unsafe path in the share (${e.message})`);
  }
  const segs = rel.split('/');
  if (platform === 'win32' && segs.some((s) => WIN_BAD.test(s) || WIN_RESERVED.test(s))) {
    throw new UnsafePathError(`refusing "${rel}": not a valid Windows file name`);
  }
  const t = path.resolve(root, ...segs);
  const r = path.relative(root, t);
  if (r === '' || r === '..' || r.startsWith(`..${path.sep}`) || path.isAbsolute(r)) {
    throw new UnsafePathError(`refusing "${rel}": it would be written outside the output directory`);
  }
  return t;
}

/**
 * Create (0700) or verify each directory component of `relDir` below root,
 * one at a time, refusing symlinks and non-directories.
 */
export async function ensureDir(root, relDir, platform) {
  if (relDir === '') return;
  const segs = relDir.split('/');
  for (let i = 1; i <= segs.length; i++) {
    const rel = segs.slice(0, i).join('/');
    const p = targetPath(root, rel, platform);
    let st = await exists(p);
    if (!st) {
      try {
        await mkdir(p, { mode: 0o700 });
        continue;
      } catch (e) {
        if (e.code !== 'EEXIST') throw e;
        st = await lstat(p); // lost a race: re-check what is there now
      }
    }
    if (st.isSymbolicLink()) throw new UnsafePathError(`refusing to write through the symbolic link ${p}`);
    if (!st.isDirectory()) throw new UnsafePathError(`${p} exists and is not a folder`);
  }
}

const parentOf = (rel) => (rel.includes('/') ? rel.slice(0, rel.lastIndexOf('/')) : '');

/**
 * Resolve (creating if needed, 0700) the output directory. The directory the
 * user named may itself be a symlink (e.g. /tmp on macOS) — that is their
 * choice; only what lies BELOW it is policed.
 */
export async function prepareRoot(outDir) {
  const abs = path.resolve(outDir);
  const st = await exists(abs);
  if (!st) await mkdir(abs, { recursive: true, mode: 0o700 });
  else if (!(await lstat(await realpath(abs))).isDirectory()) throw new UsageError(`--out ${outDir} is not a folder`);
  return realpath(abs);
}

/**
 * Check every planned write before anything is written: unsafe paths abort
 * the whole download, and existing files are refused unless `force`.
 * `items` = [{ rel, dir: boolean }].
 */
export async function preflight(root, items, { force, platform }) {
  const conflicts = [];
  for (const it of items) {
    const segs = it.rel.split('/');
    for (let i = 1; i < segs.length; i++) {
      const p = targetPath(root, segs.slice(0, i).join('/'), platform);
      const st = await exists(p);
      if (!st) break;
      if (st.isSymbolicLink()) throw new UnsafePathError(`refusing to write through the symbolic link ${p}`);
      if (!st.isDirectory()) throw new UnsafePathError(`${p} exists and is not a folder`);
    }
    const t = targetPath(root, it.rel, platform);
    const st = await exists(t);
    if (!st) continue;
    if (st.isSymbolicLink()) throw new UnsafePathError(`refusing to write through the symbolic link ${t}`);
    if (it.dir) {
      if (!st.isDirectory()) throw new UnsafePathError(`${t} exists and is not a folder`);
    } else if (!st.isFile()) {
      throw new UnsafePathError(`${t} exists and is not a regular file`);
    } else if (!force) {
      conflicts.push(t);
    }
  }
  if (conflicts.length) {
    const shown = conflicts.slice(0, 5).join(', ') + (conflicts.length > 5 ? `, … (${conflicts.length} in total)` : '');
    throw new OverwriteError(`refusing to overwrite existing files (use --force): ${shown}`, conflicts);
  }
}

/**
 * Create a new, empty folder `<root>/<base>` (or `<base>-2`, `-3`, …) with
 * mode 0700 and return its path. Used when a view-limited share has already
 * been opened and its files would collide with existing ones: the view is
 * spent, so the download goes somewhere new instead of being abandoned.
 */
export async function freshFolder(root, base, platform) {
  for (let i = 1; i <= 100; i++) {
    const p = targetPath(root, i === 1 ? base : `${base}-${i}`, platform);
    try {
      await mkdir(p, { mode: 0o700 });
      return p;
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
    }
  }
  throw new UsageError(`cannot create a new folder for the download in ${root}`);
}

/** Create an (empty) directory entry. */
export function writeDir(root, rel, platform) {
  return ensureDir(root, rel, platform);
}

/**
 * Stream `chunks` (async iterable of Uint8Array) into root/rel with mode 0600.
 * Returns the number of bytes written.
 */
export async function writeFile(root, rel, chunks, { force, mtime, platform, onBytes }) {
  await ensureDir(root, parentOf(rel), platform);
  const t = targetPath(root, rel, platform);
  const st = await exists(t);
  if (st) {
    if (st.isSymbolicLink()) throw new UnsafePathError(`refusing to write through the symbolic link ${t}`);
    if (!st.isFile()) throw new UnsafePathError(`${t} exists and is not a regular file`);
    if (!force) throw new UsageError(`refusing to overwrite ${t} (use --force)`);
  }
  let fh;
  try {
    fh = await open(t, st ? OVERWRITE : CREATE_NEW, 0o600);
  } catch (e) {
    if (e.code === 'ELOOP' || e.code === 'EEXIST') throw new UnsafePathError(`refusing to write ${t}: it changed while downloading`);
    throw e;
  }
  let n = 0;
  try {
    if (st) await fh.chmod(0o600); // an overwritten file keeps its old mode otherwise
    for await (const slice of chunks) {
      let o = 0;
      while (o < slice.length) {
        const { bytesWritten } = await fh.write(slice, o, slice.length - o);
        o += bytesWritten;
      }
      n += slice.length;
      if (onBytes) onBytes(slice.length);
    }
    if (mtime > 0) await fh.utimes(mtime / 1000, mtime / 1000);
    await fh.close();
    fh = null;
    return n;
  } catch (e) {
    if (fh) await fh.close().catch(() => {});
    await unlink(t).catch(() => {}); // never leave a truncated file under its real name
    throw e;
  }
}
