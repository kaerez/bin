// anim.js — subtle TTY-only motion. Everything degrades to static output when
// stderr is not a TTY, so scripted runs and tests see the same plain frames.
import { CLEAR, center, HIDE_CURSOR, HOME, SHOW_CURSOR, SWEEP_MS } from './screen.js';

const ESC = String.fromCharCode(0x1b);

/** Carriage return + erase-line: rewrite an animated line in place. */
export const CLEAR_LINE = `\r${ESC}[2K`;

export const SPINNER = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

export const INTRO_MS = 780;

// Monotonic deadlines let slow terminal writes skip frames instead of
// accumulating timer drift.
const FRAME_MS = 1000 / 60;
const SPINNER_MS = 80;
const now = () => performance.now();

/** Whether non-essential TUI motion is disabled. */
export const reducedMotion = (io) => io.env?.BINTHERE_NO_ANIMATION === '1';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Play a short full-screen intro on stderr: `frameFor(t)` builds the frame
 * lines for elapsed ms `t`, redrawn up to 60fps by overwriting in place. The
 * frame shape must stay constant. No-op without a TTY or under reduced motion.
 */
export async function playIntro(io, frameFor, duration = INTRO_MS) {
  if (io.stderrIsTTY !== true || reducedMotion(io)) return;
  const start = now();
  let deadline = start;
  let drawn = false;
  io.stderr(HIDE_CURSOR);
  try {
    for (;;) {
      const t = now() - start;
      if (t >= duration) return;
      io.stderr((drawn ? HOME : CLEAR) + frameFor(t).join('\n') + '\n');
      drawn = true;
      deadline += FRAME_MS;
      const delay = deadline - now();
      if (delay > 0) await sleep(delay);
      else deadline = now();
    }
  } finally {
    io.stderr(SHOW_CURSOR);
  }
}

/** Start-to-start cadence for the looping logo shine. */
export const SHINE_CYCLE_MS = 6000;

const TICK = Symbol('tick');

/** Race `pending` against a cancellable timer, so timers never outlive the wait. */
function raceDelay(pending, ms) {
  let timer;
  return Promise.race([
    pending,
    new Promise((resolve) => { timer = setTimeout(() => resolve(TICK), ms); }),
  ]).finally(() => clearTimeout(timer));
}

/**
 * Wait for `pending` while running a shine immediately and every `cycleMs`.
 * `drawFrame(null)` restores the resting frame. Reuse `schedule` across calls
 * to preserve cadence after handled keys.
 */
export async function shimmerWhile(pending, drawFrame, {
  cycleMs = SHINE_CYCLE_MS,
  sweepMs = SWEEP_MS,
  schedule = { nextAt: now() },
} = {}) {
  for (;;) {
    // Skip missed cycles instead of replaying them back-to-back.
    while (schedule.nextAt + cycleMs <= now()) schedule.nextAt += cycleMs;
    const cycleStart = schedule.nextAt;
    let key = await raceDelay(pending, Math.max(0, cycleStart - now()));
    if (key !== TICK) return key;
    schedule.nextAt += cycleMs;
    let deadline = cycleStart;
    for (;;) {
      const t = now() - cycleStart;
      if (t >= sweepMs) {
        if (drawFrame(null) === false) return pending;
        break;
      }
      // A false return disables repainting, for example after a resize.
      if (drawFrame(t) === false) return pending;
      deadline += FRAME_MS;
      const delay = Math.max(0, deadline - now());
      key = await raceDelay(pending, delay);
      if (key !== TICK) { drawFrame(null); return key; }
      if (delay === 0) deadline = now();
    }
  }
}

/**
 * Run `fn` while a braille spinner ticks next to `label` on stderr, erasing
 * the line when the work settles. The line is centered like the rest of the
 * wizard (io without `columns` gets no pad). Without a TTY the label prints
 * once as a plain dim line instead.
 */
export async function withSpinner(io, theme, label, fn) {
  if (io.stderrIsTTY !== true || reducedMotion(io)) {
    io.stderr(theme.dim(label) + '\n');
    return fn();
  }
  const cols = typeof io.columns === 'function' ? io.columns() : 0;
  const start = now();
  const draw = (frame) => {
    io.stderr(CLEAR_LINE + center(`${theme.accent(SPINNER[frame % SPINNER.length])} ${theme.dim(label)}`, cols));
  };
  draw(0);
  const pending = Promise.resolve().then(fn);
  try {
    for (;;) {
      const result = await raceDelay(pending, SPINNER_MS);
      if (result !== TICK) return result;
      // Derive the frame from elapsed time to skip delayed ticks.
      draw(Math.max(1, Math.floor((now() - start) / SPINNER_MS)));
    }
  } finally {
    io.stderr(CLEAR_LINE);
  }
}
