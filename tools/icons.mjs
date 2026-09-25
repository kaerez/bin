#!/usr/bin/env node
// Render the PWA (web app manifest) icons from the favicon's guilloché rosette.
//
//     node tools/icons.mjs
//
// Writes public/img/icon-192.png, public/img/icon-512.png (purpose "any") and
// public/img/icon-maskable-512.png (purpose "maskable": full-bleed canvas, the
// rosette kept inside the 80% safe zone so any launcher mask shape fits).
//
// The geometry mirrors public/img/favicon.svg, but with the dark "Plate"
// colors written out literally (the favicon switches colors through CSS custom
// properties + prefers-color-scheme, which a rasterizer cannot resolve). Keep
// the colors in step with the html.dark tokens in public/css/styles.css.
//
// Uses sharp (librsvg), which is already in the dev dependency tree; nothing
// here ships to the browser. The output PNGs are committed.
import { writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const OUT = join(ROOT, 'public', 'img');

// html.dark tokens: --paper, --rule-2, --accent.
const PAPER = '#0d1117';
const RULE = '#33404c';
const ACCENT = '#8fb3cc';

/** The rosette on a 32×32 grid, centered at (16,16), radius ≈ 10.2. */
function rosette() {
  return `<g fill="none" stroke="${ACCENT}" stroke-width="1.4">
    <circle cx="16" cy="16" r="10.2"/>
    <ellipse cx="16" cy="16" rx="10.2" ry="4"/>
    <ellipse cx="16" cy="16" rx="10.2" ry="4" transform="rotate(60 16 16)"/>
    <ellipse cx="16" cy="16" rx="10.2" ry="4" transform="rotate(120 16 16)"/>
  </g>
  <circle cx="16" cy="16" r="1.7" fill="${ACCENT}"/>`;
}

/** Purpose "any": the favicon itself — rounded plate, hairline border, rosette. */
function anySvg(size) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="${size}" height="${size}">
  <rect width="32" height="32" rx="7" fill="${PAPER}"/>
  <rect x="0.5" y="0.5" width="31" height="31" rx="6.5" fill="none" stroke="${RULE}"/>
  ${rosette()}
</svg>`;
}

/**
 * Purpose "maskable": square full-bleed plate (the launcher applies its own
 * mask). The safe zone is a centered circle of radius 40% of the icon; the
 * rosette (outer radius ≈ 10.9 incl. stroke) is scaled by 0.9 (≈ 9.8, ~77% of it).
 */
function maskableSvg(size) {
  const scale = 0.9;
  const t = 16 - 16 * scale;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="${size}" height="${size}">
  <rect width="32" height="32" fill="${PAPER}"/>
  <g transform="translate(${t} ${t}) scale(${scale})">${rosette()}</g>
</svg>`;
}

let sharp;
try {
  ({ default: sharp } = await import('sharp'));
} catch {
  console.error('tools/icons.mjs needs sharp (npm install at the repo root).');
  process.exit(1);
}

const jobs = [
  ['icon-192.png', anySvg(192), 192],
  ['icon-512.png', anySvg(512), 512],
  ['icon-maskable-512.png', maskableSvg(512), 512],
];

for (const [name, svg, size] of jobs) {
  const png = await sharp(Buffer.from(svg), { density: 72 * (size / 32) })
    .resize(size, size)
    // Deterministic output: no timestamps/metadata, fixed compression.
    .png({ compressionLevel: 9, adaptiveFiltering: false, palette: false })
    .toBuffer();
  await writeFile(join(OUT, name), png);
  console.log(`wrote public/img/${name} (${size}×${size}, ${png.length} bytes)`);
}
