// walk.js — recursive walk of dropped folders (File and Directory Entries API).
// `readEntries()` returns directory contents in batches and must be called
// until it returns an empty array; empty folders are reported so they survive
// in the share. Paths are the entry's fullPath without the leading slash.

const entryPath = (entry) => entry.fullPath.replace(/^\/+/, '');

/**
 * Walk `entry`, calling `onFile(path, File)` for every file and
 * `onEmptyDir(path)` for every folder that contains nothing.
 */
export async function walkEntry(entry, onFile, onEmptyDir) {
  if (entry.isFile) {
    const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
    await onFile(entryPath(entry), file);
    return;
  }
  if (!entry.isDirectory) return;
  const reader = entry.createReader();
  let any = false;
  for (;;) {
    const batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
    if (!batch.length) break;
    any = true;
    for (const child of batch) await walkEntry(child, onFile, onEmptyDir);
  }
  if (!any) onEmptyDir(entryPath(entry));
}
