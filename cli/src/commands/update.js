import { spawn } from 'node:child_process';
import { lstat, realpath } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { UsageError } from '../errors.js';

const PACKAGE_NAME = 'secbin';
const PACKAGE_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const VERSION = createRequire(import.meta.url)('../../package.json').version;
const VERSION_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

function npmInvocation(args, platform = process.platform, env = process.env) {
  if (platform !== 'win32') return ['npm', args];
  return [env.ComSpec || 'cmd.exe', ['/d', '/s', '/c', 'npm.cmd', ...args]];
}

/** Run npm without a shell and capture bounded output. */
export function runProcess(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    const append = (current, chunk) => (current + chunk).slice(-64 * 1024);
    child.stdout.on('data', (chunk) => { stdout = append(stdout, chunk); });
    child.stderr.on('data', (chunk) => { stderr = append(stderr, chunk); });
    child.once('error', reject);
    child.once('close', (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });
}

// The npm name must actually be this project's: the registry name "secbin" is
// not reserved by this repository, and `update` runs a global install of
// whatever it points at. Only a release whose package metadata names this
// repository is trusted — anything else is refused, never installed.
const REPOSITORY = 'github.com/kaerez/bin';
const REPOSITORY_RE = /^(?:git\+)?(?:https|ssh|git):\/\/(?:git@)?github\.com[/:]kaerez\/bin(?:\.git)?\/?$/i;

/** Parse `npm view <pkg>@latest version repository.url --json` → the verified version. */
function parseLatest(value, source) {
  let data;
  try {
    data = JSON.parse(value);
  } catch {
    data = value.trim();
  }
  const version = data !== null && typeof data === 'object' ? data.version : data;
  if (typeof version !== 'string' || !VERSION_RE.test(version)) {
    throw new Error(`${source} returned an invalid version`);
  }
  const repo = data !== null && typeof data === 'object' ? data['repository.url'] : undefined;
  if (typeof repo !== 'string' || !REPOSITORY_RE.test(repo)) {
    throw new Error(`the npm package "${PACKAGE_NAME}" is not published from ${REPOSITORY} — refusing to use it for updates (install or update from a clone of the repository: npm install -g ./cli)`);
  }
  return version;
}

function compareVersions(a, b) {
  const left = VERSION_RE.exec(a);
  const right = VERSION_RE.exec(b);
  for (let i = 1; i <= 3; i++) {
    const difference = Number(left[i]) - Number(right[i]);
    if (difference !== 0) return Math.sign(difference);
  }
  if (left[4] === right[4]) return 0;
  if (left[4] === undefined) return 1;
  if (right[4] === undefined) return -1;
  const leftPre = left[4].split('.');
  const rightPre = right[4].split('.');
  for (let i = 0; i < Math.max(leftPre.length, rightPre.length); i++) {
    if (leftPre[i] === undefined) return -1;
    if (rightPre[i] === undefined) return 1;
    if (leftPre[i] === rightPre[i]) continue;
    const leftNumber = /^\d+$/.test(leftPre[i]);
    const rightNumber = /^\d+$/.test(rightPre[i]);
    if (leftNumber && rightNumber) return Math.sign(Number(leftPre[i]) - Number(rightPre[i]));
    if (leftNumber !== rightNumber) return leftNumber ? -1 : 1;
    return leftPre[i] < rightPre[i] ? -1 : 1;
  }
  return 0;
}

async function isGlobalInstall(globalRoot, packageRoot = PACKAGE_ROOT) {
  try {
    const globalPath = join(globalRoot, PACKAGE_NAME);
    const [current, globalPackage, globalStat] = await Promise.all([
      realpath(packageRoot),
      realpath(globalPath),
      lstat(globalPath),
    ]);
    return !globalStat.isSymbolicLink() && current === globalPackage;
  } catch {
    return false;
  }
}

function failure(result, action) {
  if (result.code === 0) return;
  throw new Error(`${action} failed (npm exited ${result.code})`);
}

function npmRunner(io) {
  const exec = io.runProcess ?? runProcess;
  return (args) => {
    const [command, commandArgs] = npmInvocation(
      args, io.platform ?? process.platform, io.env ?? process.env,
    );
    return exec(command, commandArgs);
  };
}

async function latestVersion(invoke) {
  const view = await invoke(['view', `${PACKAGE_NAME}@latest`, 'version', 'repository.url', '--json']);
  failure(view, 'checking for updates');
  return parseLatest(view.stdout, 'npm');
}

function reportVersion(latest, io) {
  const comparison = compareVersions(VERSION, latest);

  if (comparison === 0) {
    io.stdout(`${PACKAGE_NAME} ${VERSION} is up to date\n`);
    return 0;
  }
  if (comparison > 0) {
    io.stdout(`${PACKAGE_NAME} ${VERSION} is newer than the published ${latest}\n`);
    return 0;
  }
  io.stdout(`${PACKAGE_NAME} ${VERSION}; update available: ${latest}\n`);
  return 0;
}

export async function cmdVersion(args, io) {
  if (args.length > 0) throw new UsageError(`unknown version option "${args[0]}"`);
  const latest = await latestVersion(npmRunner(io));
  return reportVersion(latest, io);
}

export async function cmdUpdate(args, io) {
  if (args.length > 0) throw new UsageError(`unknown update option "${args[0]}"`);

  const invoke = npmRunner(io);
  const latest = await latestVersion(invoke);
  const comparison = compareVersions(VERSION, latest);

  if (comparison >= 0) return reportVersion(latest, io);

  const root = await invoke(['root', '--global']);
  failure(root, 'locating the global npm installation');
  const globalRoot = root.stdout.trim();
  if (globalRoot === '') throw new Error('npm returned an empty global package path');
  const global = io.isGlobalInstall
    ? await io.isGlobalInstall(globalRoot, PACKAGE_ROOT)
    : await isGlobalInstall(globalRoot);
  if (!global) {
    throw new Error(`automatic update requires a global npm installation; run: npm install -g ${PACKAGE_NAME}@latest`);
  }

  io.stderr(`updating ${PACKAGE_NAME} ${VERSION} → ${latest}…\n`);
  const install = await invoke([
    'install', '--global', '--no-audit', '--no-fund', `${PACKAGE_NAME}@latest`,
  ]);
  failure(install, `updating ${PACKAGE_NAME}`);
  io.stdout(`updated ${PACKAGE_NAME} ${VERSION} → ${latest}\n`);
  return 0;
}
