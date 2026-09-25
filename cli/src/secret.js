// secret.js — resolve a secret (password / delete token) for any command.
// Secrets come from a --*-env variable (scripts: keeps them out of argv/shell
// history/ps) or an interactive hidden prompt — never a bare flag value.
import { UsageError } from './errors.js';

// Parity with the web composer: a longer password could be set here but not
// typed back in the browser's password dialog.
export const MAX_PASSWORD = 128;

export function resolveSecret({ envVar, promptWanted, promptLabel, io }) {
  if (envVar !== undefined) {
    const value = io.env[envVar];
    if (value === undefined || value === '') {
      throw new UsageError(`environment variable ${envVar} is not set (or empty)`);
    }
    return Promise.resolve(value);
  }
  if (promptWanted) {
    if (!io.stdinIsTTY) {
      throw new UsageError('no TTY to prompt on — use --password-env / --token-env instead');
    }
    return io.promptHidden(promptLabel);
  }
  return Promise.resolve('');
}

/**
 * A NEW password for a share being created (--password / --password-env).
 * Prompting asks twice: a typo would make the share permanently unopenable,
 * since the server cannot recover or reset it.
 */
export async function newPassword({ envVar, promptWanted, io }) {
  let password;
  if (envVar === undefined && promptWanted) {
    if (!io.stdinIsTTY) throw new UsageError('no TTY to prompt on — use --password-env instead');
    password = await io.promptHidden('Password: ');
    if (password === '') throw new UsageError('empty password');
    if (await io.promptHidden('Repeat:   ') !== password) throw new UsageError('passwords do not match');
  } else {
    password = await resolveSecret({ envVar, promptWanted: false, io });
  }
  if (password.length > MAX_PASSWORD) { // UTF-16 length, as the web composer counts
    throw new UsageError(`password is too long (${MAX_PASSWORD} characters max)`);
  }
  return password;
}
