// walk.js — collect the files and folders `secbin send` shares, without ever
// following a symbolic link (a link could point anywhere — ~/.ssh, /etc — and
// silently sending its target is exactly the surprise a secret-sharing tool
// must not have). Links, sockets, FIFOs and devices are skipped with a warning.
//
// Share paths are relative POSIX paths: a file argument contributes its
// basename, a directory argument `dir` contributes `dir/…` for everything
// beneath it. Empty folders (including ones that are empty only because their
// contents were skipped) become explicit dir entries so they survive the trip.
import { constants } from 'node:fs';
import { lstat, open, readdir } from 'node:fs/promises';
import path from 'node:path';
import { checkPath, HARD_MAX_SHARE_BYTES, MAX_ENTRIES } from '../vendor/files.js';
import { detectMime } from '../vendor/mime.js';
import { UsageError } from './errors.js';

const HEAD_BYTES = 64;
// O_NOFOLLOW: if a walked file is swapped for a symlink before we read it, the
// open fails instead of reading the link's target. (0 where unsupported.)
export const READ_FLAGS = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);

// Print a local path safely: file names may contain control characters.
export const showPath = (p) => JSON.stringify(p).slice(1, -1).replace(/[\u007f-\u009f]/g, '?');

async function readHead(abs) {
  const fh = await open(abs, READ_FLAGS);
  try {
    const buf = new Uint8Array(HEAD_BYTES);
    const { bytesRead } = await fh.read(buf, 0, HEAD_BYTES, 0);
    return buf.subarray(0, bytesRead);
  } finally {
    await fh.close();
  }
}

function sharePath(p) {
  try {
    return checkPath(p);
  } catch (e) {
    throw new UsageError(`cannot share "${showPath(p)}": ${e.message} (rename it or leave it out)`);
  }
}

/**
 * Walk the `send` arguments. Returns
 *   { files: [{ path, abs, size, mtime, type }], dirs: [path], skipped }.
 * Throws UsageError on unreadable arguments, unshareable names, duplicate
 * share paths, or a share over the hard size / entry limits.
 */
export async function collect(args, io) {
  const files = [];
  const dirs = [];
  const seen = new Map(); // share path → the local path it came from
  let skipped = 0;
  let bytes = 0;

  const claim = (p, abs) => {
    if (seen.has(p)) {
      throw new UsageError(`two inputs map to the same path "${showPath(p)}" in the share (${showPath(seen.get(p))} and ${showPath(abs)}) — rename one or send them separately`);
    }
    seen.set(p, abs);
  };
  const tooMany = () => files.length + dirs.length > MAX_ENTRIES;
  const TOO_MANY = `too many entries (${MAX_ENTRIES} files and empty folders max per share)`;
  const skip = (abs, why) => {
    skipped++;
    io.stderr(`warning: skipping ${why} ${showPath(abs)}\n`);
  };

  const addFile = async (p, abs, st) => {
    claim(p, abs);
    bytes += st.size;
    if (bytes > HARD_MAX_SHARE_BYTES) throw new UsageError('the files are too large to share (2 GiB max per share)');
    let head;
    try {
      head = await readHead(abs);
    } catch (e) {
      throw new UsageError(`cannot read ${showPath(abs)}: ${e.code ?? e.message}`);
    }
    files.push({
      path: p, abs, size: st.size, mtime: Math.max(0, Math.floor(st.mtimeMs)),
      type: detectMime({ name: path.posix.basename(p), platformType: '', head }),
    });
    if (tooMany()) throw new UsageError(TOO_MANY);
  };

  const walkDir = async (p, abs) => {
    claim(p, abs);
    let names;
    try {
      names = (await readdir(abs)).sort();
    } catch (e) {
      throw new UsageError(`cannot read directory ${showPath(abs)}: ${e.code ?? e.message}`);
    }
    let contributed = 0;
    for (const name of names) {
      const childAbs = path.join(abs, name);
      const st = await lstat(childAbs);
      if (st.isSymbolicLink()) { skip(childAbs, 'symbolic link'); continue; }
      const childPath = sharePath(`${p}/${name}`);
      if (st.isDirectory()) { await walkDir(childPath, childAbs); contributed++; continue; }
      if (st.isFile()) { await addFile(childPath, childAbs, st); contributed++; continue; }
      skip(childAbs, 'special file');
    }
    if (contributed === 0) {
      dirs.push(p);
      if (tooMany()) throw new UsageError(TOO_MANY);
    }
  };

  for (const arg of args) {
    const abs = path.resolve(arg);
    let st;
    try {
      st = await lstat(abs);
    } catch (e) {
      throw new UsageError(`cannot read ${showPath(arg)}: ${e.code ?? e.message}`);
    }
    if (st.isSymbolicLink()) { skip(arg, 'symbolic link'); continue; }
    const name = path.basename(abs);
    if (name === '') throw new UsageError('cannot share the filesystem root');
    const p = sharePath(name);
    if (st.isDirectory()) await walkDir(p, abs);
    else if (st.isFile()) await addFile(p, abs, st);
    else skip(arg, 'special file');
  }

  if (files.length === 0 && dirs.length === 0) throw new UsageError('nothing to send');
  return { files, dirs, skipped };
}

/**
 * A readStreamChunk() source for a local file: reads [start, end) at an
 * offset, reopening per call (a 10 000-file share must not hold 10 000 fds).
 * A file that shrank since the walk is a "short read" — never padded silently.
 */
export function fileSource(f, off) {
  return {
    off,
    size: f.size,
    read: async (start, end) => {
      const fh = await open(f.abs, READ_FLAGS);
      try {
        const out = new Uint8Array(end - start);
        let got = 0;
        while (got < out.length) {
          const { bytesRead } = await fh.read(out, got, out.length - got, start + got);
          if (bytesRead === 0) break;
          got += bytesRead;
        }
        if (got !== out.length) throw new UsageError(`${showPath(f.abs)} changed while it was being sent (it is now shorter)`);
        return out;
      } finally {
        await fh.close();
      }
    },
  };
}
