// pdfview.js — hardened PDF preview on the vendored pdf.js core (display
// layer + worker only). This build contains no eval; we never load pdf.js's
// scripting sandbox, annotation/form layers or XFA, so JavaScript embedded in a
// PDF never runs. Pages are rasterized to a canvas one at a time on demand,
// with page-count and canvas-size caps so a hostile document cannot exhaust
// memory. Parsing happens in pdf.js's Web Worker (worker-src 'self').

import * as pdfjs from './vendor/pdfjs/pdf.min.mjs';
import { h } from './common.js';
import { scriptURL } from './tt.js';

const BASE = '/js/vendor/pdfjs/';
// The CSP enforces Trusted Types, so pdf.js must not construct its worker from
// a plain string: create it here through our policy and hand pdf.js the port.
// One worker is shared by every preview on the page.
let workerPort = null;
// The previous preview's teardown: pdf.js refuses a new document on the shared
// worker while an old one is still being destroyed, so wait for it.
let teardown = Promise.resolve();
function pdfWorker() {
  if (!workerPort) {
    const w = new Worker(scriptURL(`${BASE}pdf.worker.min.mjs`), { type: 'module' });
    // A worker that failed to load is dropped, so the next preview retries.
    w.addEventListener('error', () => {
      if (workerPort === w) { workerPort = null; pdfjs.GlobalWorkerOptions.workerPort = null; }
    });
    workerPort = w;
    pdfjs.GlobalWorkerOptions.workerPort = w;
  }
  return workerPort;
}

export const MAX_PAGES = 500;
export const MAX_CANVAS_PIXELS = 16_000_000;

/** Render `bytes` into `container`; returns a cleanup function. */
export async function renderPdf(container, bytes) {
  await teardown.catch(() => {});
  pdfWorker();
  const task = pdfjs.getDocument({
    data: bytes.slice(), // pdf.js transfers the buffer to its worker
    enableXfa: false,
    disableAutoFetch: true,
    disableStream: true,
    stopAtErrors: false,
    isEvalSupported: false, // no-op on this build (no eval at all); kept as defense in depth
    maxImageSize: MAX_CANVAS_PIXELS,
    standardFontDataUrl: `${BASE}standard_fonts/`,
    cMapUrl: `${BASE}cmaps/`,
    cMapPacked: true,
    wasmUrl: `${BASE}wasm/`,
    useSystemFonts: false,
  });
  let doc;
  try {
    doc = await task.promise;
  } catch (e) {
    await task.destroy();
    throw new Error(e && e.name === 'PasswordException' ? 'This PDF is password-protected — download it instead.' : 'This PDF could not be read.');
  }
  const pages = Math.min(doc.numPages, MAX_PAGES);
  const canvas = h('canvas.viewer-pdf');
  const label = h('span.mono.viewer-page');
  const prev = h('button.btn', { type: 'button', text: '‹ Prev' });
  const next = h('button.btn', { type: 'button', text: 'Next ›' });
  container.appendChild(h('div.viewer-toolbar', {}, prev, label, next));
  container.appendChild(h('div.viewer-frame', {}, canvas));
  if (doc.numPages > MAX_PAGES) container.appendChild(h('p.msg.viewer-note', { text: `Showing the first ${MAX_PAGES} of ${doc.numPages} pages.` }));

  let current = 1;
  let renderTask = null;
  let destroyed = false;

  async function show(n) {
    current = n;
    label.textContent = `page ${n} / ${pages}`;
    prev.disabled = n <= 1;
    next.disabled = n >= pages;
    if (renderTask) { renderTask.cancel(); renderTask = null; }
    const page = await doc.getPage(n);
    if (destroyed) return;
    const base = page.getViewport({ scale: 1 });
    const width = Math.max(320, Math.min(container.clientWidth || 800, 1400));
    let scale = (width / base.width) * Math.min(2, window.devicePixelRatio || 1);
    const px = base.width * base.height * scale * scale;
    if (px > MAX_CANVAS_PIXELS) scale *= Math.sqrt(MAX_CANVAS_PIXELS / px);
    const vp = page.getViewport({ scale });
    canvas.width = Math.floor(vp.width);
    canvas.height = Math.floor(vp.height);
    renderTask = page.render({ canvas, canvasContext: canvas.getContext('2d'), viewport: vp, annotationMode: pdfjs.AnnotationMode.DISABLE });
    try { await renderTask.promise; } catch (e) { if (!(e instanceof pdfjs.RenderingCancelledException)) throw e; }
    page.cleanup();
  }

  prev.onclick = () => { if (current > 1) show(current - 1); };
  next.onclick = () => { if (current < pages) show(current + 1); };
  await show(1);

  return () => {
    destroyed = true;
    if (renderTask) renderTask.cancel();
    teardown = task.destroy();
  };
}
