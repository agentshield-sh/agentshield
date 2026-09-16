import { createHash } from 'node:crypto';

// Finding ids must stay stable across runs and unique across sources. Slicing a
// hex-encoded path collides constantly (every absolute path starts with "/Use…",
// every TOML config ends with "toml"), so identity is derived from a digest.
export function shortHash(value, length = 10) {
  return createHash('sha256').update(String(value)).digest('hex').slice(0, length);
}

export function slug(value) {
  return String(value)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}
