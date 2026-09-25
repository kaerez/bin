// format-bytes.js — human-readable byte counts for progress and listings.
const UNITS = ['B', 'KiB', 'MiB', 'GiB'];

export function formatBytes(n) {
  let v = n;
  let u = 0;
  while (v >= 1024 && u < UNITS.length - 1) { v /= 1024; u++; }
  return u === 0 ? `${v} B` : `${v.toFixed(v < 10 ? 1 : 0)} ${UNITS[u]}`;
}
