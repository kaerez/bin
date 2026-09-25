// viewer.js — the safe in-browser file viewer.
//
// Policy: the sender's admin-approved rules travel inside the encrypted
// manifest (a snapshot); the recipient's page intersects them with the current
// global policy from /api/config, so an admin can switch viewing off instantly.
//
// Safety: nothing here executes content. Text/markdown/code go through
// textContent-only renderers; images and media are decoded by the browser from
// blob: URLs whose MIME comes from our own signature sniffing (never from the
// sender's label), after header-level size checks so a decompression bomb
// cannot take the tab down; SVG is never rendered as an image; PDFs are
// rasterized by a hardened pdf.js with scripting and eval disabled.

import { renderMarkdown, MAX_MD_BYTES } from './markdown.js';
import { highlightInto, MAX_HIGHLIGHT_BYTES } from './highlight.js';
import { sniff, extensionOf } from './mime.js';
import { h, clear } from './common.js';

export const MAX_TEXT_BYTES = 2 * 1024 * 1024;
export const MAX_IMAGE_PIXELS = 40_000_000;
const IMAGE_TYPES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/bmp', 'image/avif'];
const MEDIA_TYPES = ['audio/mpeg', 'audio/ogg', 'audio/wav', 'audio/flac', 'video/mp4', 'video/webm'];

// ── policy ────────────────────────────────────────────────────────────────────

function ruleMatches(rule, entry) {
  if (rule.match === 'any') return true;
  if (rule.match === 'ext') return extensionOf(entry.path) === rule.value;
  if (rule.value.endsWith('/*')) return entry.type.startsWith(rule.value.slice(0, -1));
  return entry.type === rule.value;
}

/** First matching rule's renderer, or null. */
export function matchRenderer(entry, rules) {
  for (const r of rules || []) if (ruleMatches(r, entry)) return r.renderer;
  return null;
}

/**
 * Renderer allowed for `entry`, or null: the sender's snapshot must allow it,
 * the live global policy must allow the same renderer, and the file must fit
 * both size caps.
 */
export function allowedRenderer(entry, snapshot, globalViewer) {
  if (!snapshot || !globalViewer || !globalViewer.enabled || entry.dir) return null;
  const r = matchRenderer(entry, snapshot.rules);
  if (!r) return null;
  if (matchRenderer(entry, globalViewer.rules) !== r) return null;
  if (entry.size > Math.min(snapshot.maxBytes, globalViewer.maxBytes)) return null;
  return r;
}

// ── image header parsing (dimensions before decode) ─────────────────────────

const u16be = (b, o) => (b[o] << 8) | b[o + 1];
const u32be = (b, o) => ((b[o] << 24) >>> 0) + (b[o + 1] << 16) + (b[o + 2] << 8) + b[o + 3];
const u16le = (b, o) => b[o] | (b[o + 1] << 8);
const i32le = (b, o) => b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24);

/** { width, height } from the header, or null if unknown/unsupported. */
export function imageSize(b, type) {
  try {
    if (type === 'image/png' && b.length >= 24) return { width: u32be(b, 16), height: u32be(b, 20) };
    if (type === 'image/gif' && b.length >= 10) return { width: u16le(b, 6), height: u16le(b, 8) };
    if (type === 'image/bmp' && b.length >= 26) return { width: Math.abs(i32le(b, 18)), height: Math.abs(i32le(b, 22)) };
    if (type === 'image/jpeg') {
      let o = 2;
      while (o + 9 < b.length) {
        if (b[o] !== 0xff) { o++; continue; }
        const m = b[o + 1];
        if (m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc) return { height: u16be(b, o + 5), width: u16be(b, o + 7) };
        if (m === 0xd8 || m === 0x01 || (m >= 0xd0 && m <= 0xd7)) { o += 2; continue; }
        o += 2 + u16be(b, o + 2);
      }
      return null;
    }
    if (type === 'image/webp' && b.length >= 30) {
      const fourcc = String.fromCharCode(b[12], b[13], b[14], b[15]);
      if (fourcc === 'VP8 ') return { width: u16le(b, 26) & 0x3fff, height: u16le(b, 28) & 0x3fff };
      if (fourcc === 'VP8L') {
        const v = b[21] | (b[22] << 8) | (b[23] << 16) | (b[24] << 24);
        return { width: (v & 0x3fff) + 1, height: ((v >>> 14) & 0x3fff) + 1 };
      }
      if (fourcc === 'VP8X') return { width: 1 + (b[24] | (b[25] << 8) | (b[26] << 16)), height: 1 + (b[27] | (b[28] << 8) | (b[29] << 16)) };
      return null;
    }
    if (type === 'image/avif') {
      for (let o = 0; o + 16 < Math.min(b.length, 1 << 16); o++) {
        if (b[o] === 0x69 && b[o + 1] === 0x73 && b[o + 2] === 0x70 && b[o + 3] === 0x65) return { width: u32be(b, o + 8), height: u32be(b, o + 12) };
      }
      return null;
    }
  } catch { /* fall through */ }
  return null;
}

// ── renderers ────────────────────────────────────────────────────────────────

function decodeText(bytes, max) {
  const truncated = bytes.length > max;
  const text = new TextDecoder('utf-8', { fatal: false }).decode(truncated ? bytes.subarray(0, max) : bytes);
  return { text, truncated };
}

function note(text) {
  return h('p.msg.viewer-note', { text });
}

/**
 * Render `bytes` of `entry` with `renderer` into `container`. Returns a
 * cleanup function (revokes object URLs, stops pdf.js). Throws an Error with a
 * user-facing message when the content is refused.
 */
export async function renderPreview(container, entry, bytes, renderer) {
  clear(container);
  const urls = [];
  let pdfCleanup = null;
  const cleanup = () => {
    for (const u of urls) URL.revokeObjectURL(u);
    if (pdfCleanup) pdfCleanup();
    clear(container);
  };

  if (renderer === 'text' || renderer === 'code' || renderer === 'markdown') {
    const cap = renderer === 'markdown' ? MAX_MD_BYTES : renderer === 'code' ? MAX_HIGHLIGHT_BYTES : MAX_TEXT_BYTES;
    const { text, truncated } = decodeText(bytes, renderer === 'text' ? MAX_TEXT_BYTES : cap);
    if (renderer === 'markdown' && !truncated) {
      const div = h('div.md');
      renderMarkdown(div, text);
      container.appendChild(div);
    } else if (renderer === 'code' && !truncated) {
      const code = h('code');
      highlightInto(code, text);
      container.appendChild(h('pre.code', {}, code));
    } else {
      container.appendChild(h('pre.code', { text }));
    }
    if (truncated) container.appendChild(note('Preview truncated — download the file to see all of it.'));
    return cleanup;
  }

  if (renderer === 'image') {
    const type = sniff(bytes);
    if (!IMAGE_TYPES.includes(type)) throw new Error('This file is not a supported image (PNG, JPEG, GIF, WebP, BMP or AVIF).');
    const dim = imageSize(bytes, type);
    if (!dim || !dim.width || !dim.height) throw new Error('Could not read the image dimensions safely — download it instead.');
    if (dim.width * dim.height > MAX_IMAGE_PIXELS) throw new Error(`The image is too large to preview (${dim.width}×${dim.height}).`);
    const url = URL.createObjectURL(new Blob([bytes], { type }));
    urls.push(url);
    const img = h('img.viewer-img', { alt: entry.path, src: url, decoding: 'async', referrerpolicy: 'no-referrer' });
    await new Promise((resolve, reject) => {
      img.onload = resolve;
      img.onerror = () => reject(new Error('The image could not be decoded.'));
      container.appendChild(h('div.viewer-frame', {}, img));
    });
    return cleanup;
  }

  if (renderer === 'media') {
    const type = sniff(bytes);
    if (!MEDIA_TYPES.includes(type)) throw new Error('This file is not a supported audio/video format.');
    const url = URL.createObjectURL(new Blob([bytes], { type }));
    urls.push(url);
    const el = h(type.startsWith('audio/') ? 'audio.viewer-media' : 'video.viewer-media', { controls: true, preload: 'metadata', src: url });
    container.appendChild(h('div.viewer-frame', {}, el));
    return cleanup;
  }

  if (renderer === 'pdf') {
    if (sniff(bytes) !== 'application/pdf') throw new Error('This file is not a PDF.');
    const { renderPdf } = await import('./pdfview.js');
    pdfCleanup = await renderPdf(container, bytes);
    return cleanup;
  }

  throw new Error('This file type cannot be previewed.');
}
