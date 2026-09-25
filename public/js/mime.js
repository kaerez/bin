// mime.js — MIME detection for the composer and the CLI: the platform-provided
// type, else magic-byte sniffing of the first bytes, else the file extension,
// else application/octet-stream. The result is only a suggestion the sender can
// change; it travels inside the encrypted manifest. The viewer never trusts it
// for safety — every renderer is safe for arbitrary bytes (see viewer.js).

import { checkMime } from './files.js';

export const OCTET = 'application/octet-stream';

const EXT = {
  txt: 'text/plain', log: 'text/plain', md: 'text/markdown', markdown: 'text/markdown',
  csv: 'text/csv', tsv: 'text/tab-separated-values', json: 'application/json',
  xml: 'application/xml', yaml: 'application/yaml', yml: 'application/yaml', toml: 'application/toml',
  html: 'text/html', htm: 'text/html', css: 'text/css', js: 'text/javascript', mjs: 'text/javascript',
  ts: 'text/x-typescript', py: 'text/x-python', go: 'text/x-go', rs: 'text/x-rust', java: 'text/x-java',
  c: 'text/x-c', h: 'text/x-c', cpp: 'text/x-c++', sh: 'application/x-sh', sql: 'application/sql',
  png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp',
  bmp: 'image/bmp', avif: 'image/avif', svg: 'image/svg+xml', ico: 'image/vnd.microsoft.icon',
  pdf: 'application/pdf', zip: 'application/zip', gz: 'application/gzip', tar: 'application/x-tar',
  '7z': 'application/x-7z-compressed',
  mp3: 'audio/mpeg', ogg: 'audio/ogg', oga: 'audio/ogg', wav: 'audio/wav', flac: 'audio/flac',
  m4a: 'audio/mp4', mp4: 'video/mp4', m4v: 'video/mp4', webm: 'video/webm', mov: 'video/quicktime',
  doc: 'application/msword', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xls: 'application/vnd.ms-excel', xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  ppt: 'application/vnd.ms-powerpoint', pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
};

/** Types offered in the composer's picker (the sender can also type any valid one). */
export const COMMON_TYPES = [...new Set(['text/plain', 'text/markdown', 'text/csv', 'application/json',
  'image/png', 'image/jpeg', 'image/webp', 'image/gif', 'image/bmp', 'image/avif', 'image/svg+xml',
  'application/pdf', 'audio/mpeg', 'audio/ogg', 'audio/wav', 'video/mp4', 'video/webm',
  'application/zip', OCTET])];

const startsWith = (b, sig, at = 0) => sig.every((v, i) => b[at + i] === v);
const ascii = (s) => [...s].map((c) => c.charCodeAt(0));

/** Sniff well-known signatures from the first (≥16) bytes. Returns a type or null. */
export function sniff(b) {
  if (!b || b.length < 4) return null;
  if (startsWith(b, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return 'image/png';
  if (startsWith(b, [0xff, 0xd8, 0xff])) return 'image/jpeg';
  if (startsWith(b, ascii('GIF87a')) || startsWith(b, ascii('GIF89a'))) return 'image/gif';
  if (startsWith(b, ascii('RIFF')) && startsWith(b, ascii('WEBP'), 8)) return 'image/webp';
  if (startsWith(b, ascii('RIFF')) && startsWith(b, ascii('WAVE'), 8)) return 'audio/wav';
  if (startsWith(b, ascii('BM')) && b.length >= 26) return 'image/bmp';
  if (startsWith(b, ascii('ftypavif'), 4) || startsWith(b, ascii('ftypavis'), 4)) return 'image/avif';
  if (startsWith(b, ascii('ftyp'), 4)) return 'video/mp4';
  if (startsWith(b, ascii('%PDF-'))) return 'application/pdf';
  if (startsWith(b, [0x50, 0x4b, 0x03, 0x04])) return 'application/zip';
  if (startsWith(b, [0x1f, 0x8b])) return 'application/gzip';
  if (startsWith(b, ascii('OggS'))) return 'audio/ogg';
  if (startsWith(b, ascii('ID3')) || (b[0] === 0xff && (b[1] & 0xe0) === 0xe0)) return 'audio/mpeg';
  if (startsWith(b, [0x1a, 0x45, 0xdf, 0xa3])) return 'video/webm';
  if (startsWith(b, ascii('fLaC'))) return 'audio/flac';
  return null;
}

export function fromExtension(name) {
  const dot = name.lastIndexOf('.');
  if (dot <= 0 || dot === name.length - 1) return null;
  return EXT[name.slice(dot + 1).toLowerCase()] ?? null;
}

/** Normalize to a valid lowercase type/subtype (drop parameters), or null. */
export function normalizeMime(t) {
  if (typeof t !== 'string') return null;
  const base = t.split(';')[0].trim().toLowerCase();
  try { return checkMime(base); } catch { return null; }
}

/** Best guess: platform type → magic bytes → extension → octet-stream. */
export function detectMime({ name, platformType, head }) {
  return normalizeMime(platformType) || sniff(head) || fromExtension(name) || OCTET;
}

export const extensionOf = (name) => {
  const dot = name.lastIndexOf('.');
  return dot > 0 ? name.slice(dot + 1).toLowerCase() : '';
};
