// screen.js — pure string builders and ANSI constants for the full-screen UI.
// Nothing here writes to a stream; callers compose frames and send them to
// stderr, keeping stdout clean for machine-readable output.
const ESC = String.fromCharCode(0x1b);

// [2J wipes the viewport only: each wizard page starts on a clean screen but
// the user's scrollback survives. ([3J would erase scrollback too — history
// the CLI didn't create is not ours to destroy.) The final result screen
// still persists — nothing clears after it.
export const CLEAR = `${ESC}[2J${ESC}[H`;
export const HOME = `${ESC}[H`;
// Erase from the cursor to end of line — appended per line by frames whose
// shape changes between redraws (e.g. the header slide), so rows the content
// just vacated don't keep stale glyphs.
export const ERASE_EOL = `${ESC}[K`;
export const HIDE_CURSOR = `${ESC}[?25l`;
export const SHOW_CURSOR = `${ESC}[?25h`;

const BEL = String.fromCharCode(0x07);
// OSC 11 sets the terminal background while the wizard runs; OSC 111 restores
// the terminal default. Unsupported terminals ignore both sequences.
export const SET_BG = `${ESC}]11;#24374e${BEL}`;
export const RESET_BG = `${ESC}]111${BEL}`;
export const SAVE_CURSOR = `${ESC}7`;
export const RESTORE_CURSOR = `${ESC}8`;

/** Move the cursor to 1-based viewport `row`, `col`. */
export const moveTo = (row, col) => `${ESC}[${row};${col}H`;

/** Below this many columns the boxes/logo are skipped for plain lines. */
export const MIN_WIDTH = 60;

const ANSI_RE = new RegExp(`${ESC}\\[[0-9;]*m`, 'g');

export const stripAnsi = (s) => s.replace(ANSI_RE, '');

export function center(line, width) {
  const pad = Math.max(0, Math.floor((width - stripAnsi(line).length) / 2));
  return ' '.repeat(pad) + line;
}

// Three-row half-block wordmark: B i N T H E R E (30 columns).
export const LOGO = [
  '█▀▄ █ █▄ █ ▀█▀ █ █ █▀▀ █▀▄ █▀▀',
  '█▀▄ █ █ ▀█  █  █▀█ █▀  █▀▄ █▀ ',
  '▀▀  ▀ ▀  ▀  ▀  ▀ ▀ ▀▀▀ ▀ ▀ ▀▀▀',
];

/** Full-width dim horizontal rule delimiting screen sections. */
export function rule(width, theme) {
  return theme.dim('─'.repeat(width));
}

/**
 * Wrap lines in a rounded hairline box (dim border, one space of padding),
 * sized to the widest visible line.
 */
export function box(lines, theme, { label = '' } = {}) {
  const inner = Math.max(...lines.map((l) => stripAnsi(l).length));
  const side = theme.dim('│');
  const room = inner + 2;
  const labelled = label !== '' && label.length + 4 <= room;
  const top = labelled
    ? theme.dim('╭─ ') + theme.accent(label) + theme.dim(` ${'─'.repeat(room - label.length - 3)}╮`)
    : theme.dim('╭' + '─'.repeat(room) + '╮');
  return [
    top,
    ...lines.map((l) => `${side} ${l}${' '.repeat(inner - stripAnsi(l).length)} ${side}`),
    theme.dim('╰' + '─'.repeat(inner + 2) + '╯'),
  ];
}

// Truecolor logo gradient, light steel blue to iron-gall blue.
const GRADIENT_FROM = [170, 205, 235];
const GRADIENT_TO = [58, 96, 130];

/**
 * The ember row above the wordmark: a wax-red spark dotting the "i" (column 4
 * of the logo), padded to the logo's width so centering keeps it aligned.
 * A numeric `glow` blends its truecolor brightness; basic terminals use two
 * states.
 */
export function logoEmber(theme, glow = true) {
  const strength = typeof glow === 'number' ? Math.min(Math.max(glow, 0), 1) : (glow ? 1 : 0);
  let spark;
  if (theme.on && theme.truecolor) {
    const low = [113, 91, 96];
    const high = [231, 112, 91];
    const rgb = low.map((v, i) => Math.round(v + (high[i] - v) * strength));
    spark = `${ESC}[38;2;${rgb.join(';')}m✦${ESC}[0m`;
  } else {
    spark = strength >= 0.5 ? theme.danger('✦') : theme.dim('✦');
  }
  return '    ' + spark + ' '.repeat(LOGO[0].length - 5);
}

function gradientRgb(i, span) {
  const t = i / span;
  return GRADIENT_FROM.map((f, k) => Math.round(f + (GRADIENT_TO[k] - f) * t));
}

const rgbCode = ([r, g, b]) => `${ESC}[38;2;${r};${g};${b}m`;
const gradientCode = (i, span) => rgbCode(gradientRgb(i, span));
const mixRgb = (from, to, amount) => from.map((v, i) => Math.round(v + (to[i] - v) * amount));

/**
 * The wordmark rows, painted: a horizontal gradient on truecolor terminals,
 * flat accent on 16-color ones, plain text otherwise.
 */
export function paintedLogo(theme) {
  if (!theme.on) return [...LOGO];
  if (!theme.truecolor) return LOGO.map((line) => theme.accent(line));
  const span = LOGO[0].length - 1;
  return LOGO.map((row) => {
    let out = '';
    for (let i = 0; i < row.length; i++) {
      if (row[i] === ' ') { out += ' '; continue; }
      out += gradientCode(i, span) + row[i];
    }
    return `${out}${ESC}[0m`;
  });
}

// Full-cell blocks flicker in through lighter shades; half blocks (▀ ▄) would
// spill outside the letterform if swapped, so they only dim while arriving.
const HALF_BLOCKS = new Set(['▀', '▄']);

function paintCell(theme, ch, i, span) {
  if (!theme.on) return ch;
  return theme.truecolor ? `${gradientCode(i, span)}${ch}${ESC}[0m` : theme.accent(ch);
}

/** Per-cell staggered arrival delays (ms) for the intro, one per logo cell. */
export function introDelays(spreadMs = 550) {
  const rows = LOGO.length;
  const cols = LOGO[0].length;
  return LOGO.map((row, r) => [...row].map((_, i) => {
    // Left-to-right stagger with deterministic coordinate jitter.
    const wave = 0.66 * (i / (cols - 1)) + 0.12 * (r / (rows - 1));
    const noise = (((i + 3) * 37 + (r + 5) * 61 + i * r * 17) % 101) / 101;
    return spreadMs * Math.min(0.999, wave + 0.2 * noise);
  }));
}

/**
 * One frame of the materialise-in intro at elapsed time `t`: each glyph waits
 * its delay, flickers in as ░, sharpens to ▒, then resolves to the painted
 * glyph. Frame shape is constant (unresolved cells are spaces), so redraws
 * can overwrite in place.
 */
export function logoIntroFrame(theme, t, delays) {
  if (delays.every((row) => row.every((d) => t - d >= 220))) return paintedLogo(theme);
  const span = LOGO[0].length - 1;
  return LOGO.map((row, r) => {
    let out = '';
    for (let i = 0; i < row.length; i++) {
      const ch = row[i];
      if (ch === ' ') { out += ' '; continue; }
      const dt = t - delays[r][i];
      if (dt < 0) { out += ' '; continue; }
      if (dt < 220) {
        if (theme.on && theme.truecolor) {
          // Fade from the wizard background without changing the glyph.
          const background = [36, 55, 78];
          const progress = 1 - Math.pow(1 - dt / 220, 3);
          out += `${rgbCode(mixRgb(background, gradientRgb(i, span), progress))}${ch}${ESC}[0m`;
          continue;
        }
        out += theme.dim(HALF_BLOCKS.has(ch) ? ch : (dt < 110 ? '░' : '▒'));
        continue;
      }
      out += paintCell(theme, ch, i, span);
    }
    return out;
  });
}

// Slanted shine with a narrow white core and wider blue halo.
const SWEEP_TILT = 2;
const SWEEP_HALO = 4.8;
const SWEEP_CORE = 1.15;
const SHINE_EDGE = [132, 193, 231];
const SHINE_CORE = [255, 255, 255];
export const SWEEP_MS = 1150;

const smoothstep = (edge0, edge1, x) => {
  const p = Math.min(Math.max((x - edge0) / (edge1 - edge0), 0), 1);
  return p * p * (3 - 2 * p);
};

/**
 * One shine frame at elapsed time `t` ∈ [0, SWEEP_MS]. Truecolor terminals
 * blend the halo into existing glyphs; basic/plain terminals use weight or
 * shade fallbacks without changing half-block silhouettes.
 */
export function logoSweepFrame(theme, t) {
  const rows = LOGO.length;
  const cols = LOGO[0].length;
  const span = cols - 1;
  const pMin = -SWEEP_TILT * rows - SWEEP_HALO;
  const pMax = cols + SWEEP_HALO;
  const progress = Math.min(Math.max(t / SWEEP_MS, 0), 1);
  const p = pMin + progress * (pMax - pMin);
  return LOGO.map((row, r) => {
    let out = '';
    for (let i = 0; i < row.length; i++) {
      const ch = row[i];
      if (ch === ' ') { out += ' '; continue; }
      const d = Math.abs(i - (rows - 1 - r) * SWEEP_TILT - p);
      if (d >= SWEEP_HALO) {
        out += paintCell(theme, ch, i, span);
        continue;
      }
      const halo = 1 - smoothstep(SWEEP_CORE, SWEEP_HALO, d);
      const core = 1 - smoothstep(0, SWEEP_CORE, d);
      if (theme.on && theme.truecolor) {
        const lit = mixRgb(SHINE_EDGE, SHINE_CORE, core);
        out += `${rgbCode(mixRgb(gradientRgb(i, span), lit, Math.min(1, halo * 0.58 + core * 0.62)))}${ch}${ESC}[0m`;
      } else if (theme.on) {
        out += core > 0.25
          ? `${ESC}[1;37m${ch}${ESC}[0m`
          : `${ESC}[1;34m${ch}${ESC}[0m`;
      } else {
        out += HALF_BLOCKS.has(ch) ? ch : (core > 0.25 ? '▓' : '▒');
      }
    }
    return out;
  });
}

/** Key-hint footer line: `↵ select · ↑↓ move · ^c quit`. */
export function footer(hints, theme) {
  return hints
    .map(([key, label]) => `${theme.bold(key)} ${theme.dim(label)}`)
    .join(theme.dim('  ·  '));
}
