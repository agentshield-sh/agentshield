import { execFileSync } from 'node:child_process';

const DEFAULT_TIMEOUT_MS = 15_000;

function run(file, args, cwd, options) {
  try {
    return execFileSync(file, args, {
      cwd,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      maxBuffer: options.maxBuffer ?? 32 * 1024 * 1024,
    });
  } catch (error) {
    // npm exits non-zero whenever it reports findings, so a failed exit code
    // still carries the payload we want on stdout.
    return error.stdout?.toString?.() ?? '';
  }
}

export function jsonCommand(file, args = [], cwd = process.cwd(), options = {}) {
  const raw = run(file, args, cwd, options);
  if (!raw.trim()) return null;
  try {
    return JSON.parse(raw);
  } catch {
    // A truncated or non-JSON response must degrade to "no data", never crash
    // the scan that called it.
    return null;
  }
}

export function textCommand(file, args = [], cwd = process.cwd(), options = {}) {
  return run(file, args, cwd, options).trim() || null;
}

export function isValidNpmPackageName(name) {
  return /^(@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/i.test(String(name || ''));
}
