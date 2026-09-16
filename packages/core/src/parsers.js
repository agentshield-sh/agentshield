// Shared config readers. Both the secret scanner and the config-risk audit need
// key/value pairs rather than raw text: regexing a whole file produces constant
// false positives against files like ~/.claude.json, which stores conversation
// history alongside real settings.

// Key segments whose values are transcript/output data, never configuration.
const NOISE_SEGMENTS = new Set([
  'history', 'messages', 'transcript', 'conversation', 'pastedcontents',
  'content', 'text', 'display', 'output', 'stdout', 'stderr', 'prompt',
  'completion', 'summary', 'examples', 'changelog',
]);

// A real config value is short. Anything longer is prose, a document, or a blob.
const MAX_VALUE_LENGTH = 512;

function isNoiseKey(keyPath) {
  return keyPath.split('.').some((segment) => NOISE_SEGMENTS.has(segment.toLowerCase()));
}

export function jsonEntries(raw) {
  let root;
  try {
    root = JSON.parse(raw);
  } catch {
    return [];
  }
  const out = [];
  const seen = new WeakSet();

  function walk(prefix, value) {
    if (!value || typeof value !== 'object' || seen.has(value)) return;
    seen.add(value);
    for (const [key, child] of Object.entries(value)) {
      const keyPath = prefix ? `${prefix}.${key}` : key;
      if (isNoiseKey(keyPath)) continue;
      if (child === null) continue;
      if (typeof child === 'object') {
        walk(keyPath, child);
      } else {
        const text = String(child);
        if (text.length <= MAX_VALUE_LENGTH) out.push([keyPath, text]);
      }
    }
  }

  walk('', root);
  return out;
}

function splitAssignment(line) {
  const index = line.indexOf('=');
  if (index === -1) return null;
  return [line.slice(0, index).trim(), line.slice(index + 1).trim()];
}

function assignmentLines(raw) {
  return String(raw)
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'));
}

export function tomlEntries(raw) {
  const out = [];
  let table = '';
  for (const line of assignmentLines(raw)) {
    const heading = line.match(/^\[+([^\]]+)\]+$/);
    if (heading) {
      table = heading[1].trim();
      continue;
    }
    const pair = splitAssignment(line);
    if (!pair) continue;
    const [key, value] = pair;
    if (value.length > MAX_VALUE_LENGTH) continue;
    out.push([table ? `${table}.${key}` : key, value]);
  }
  return out;
}

export function envEntries(raw) {
  return assignmentLines(raw)
    .map(splitAssignment)
    .filter(Boolean)
    .filter(([, value]) => value.length <= MAX_VALUE_LENGTH);
}

export function shellEntries(raw) {
  return assignmentLines(raw)
    .filter((line) => line.startsWith('export ') || line.includes('='))
    .map((line) => splitAssignment(line.replace(/^export\s+/, '')))
    .filter(Boolean)
    .filter(([, value]) => value.length <= MAX_VALUE_LENGTH);
}

export function parseConfigEntries(path, raw) {
  if (path.endsWith('.json')) return jsonEntries(raw);
  if (path.endsWith('.toml')) return tomlEntries(raw);
  if (/\.env(\.|$)|\.env$/.test(path) || path.includes('.env')) return envEntries(raw);
  if (/\.(zshrc|bashrc|bash_profile|profile|zprofile|zshenv)$/.test(path)) return shellEntries(raw);
  return [];
}

export function unquote(value) {
  return String(value ?? '').trim().replace(/^['"]|['"]$/g, '');
}
