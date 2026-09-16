import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createFinding } from '../schema.js';
import { shortHash, slug } from '../id.js';
import { parseConfigEntries, unquote } from '../parsers.js';

// Value shapes, most specific first. `keyed: false` means the prefix alone is
// proof enough and the entry may sit under any key; the rest only count under a
// key that already looks like a credential slot, which keeps ids, hashes, and
// ordinary long strings out of the report.
const VALUE_PATTERNS = [
  { name: 'Anthropic API key', regex: /^sk-ant-[A-Za-z0-9_-]{20,}$/, confidence: 'high', keyed: false },
  { name: 'OpenAI key', regex: /^sk-(proj-)?[A-Za-z0-9_-]{20,}$/i, confidence: 'high', keyed: false },
  { name: 'xAI API key', regex: /^xai-[A-Za-z0-9_-]{20,}$/, confidence: 'high', keyed: false },
  { name: 'GitHub token', regex: /^(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})$/, confidence: 'high', keyed: false },
  { name: 'GitLab token', regex: /^glpat-[A-Za-z0-9_-]{20,}$/, confidence: 'high', keyed: false },
  { name: 'Figma token', regex: /^figd_[A-Za-z0-9_-]{20,}$/i, confidence: 'high', keyed: false },
  { name: 'Linear token', regex: /^lin_api_[A-Za-z0-9_-]{16,}$/i, confidence: 'high', keyed: false },
  { name: 'Slack token', regex: /^xox[abprs]-[A-Za-z0-9-]{10,}$/, confidence: 'high', keyed: false },
  { name: 'AWS access key id', regex: /^(AKIA|ASIA)[0-9A-Z]{16}$/, confidence: 'high', keyed: false },
  { name: 'Google API key', regex: /^AIza[0-9A-Za-z_-]{35}$/, confidence: 'high', keyed: false },
  { name: 'Stripe key', regex: /^(sk|rk|pk)_(live|test)_[A-Za-z0-9]{24,}$/, confidence: 'high', keyed: false },
  { name: 'npm token', regex: /^npm_[A-Za-z0-9]{36,}$/, confidence: 'high', keyed: false },
  { name: 'Hugging Face token', regex: /^hf_[A-Za-z0-9]{20,}$/, confidence: 'high', keyed: false },
  { name: 'DigitalOcean token', regex: /^dop_v1_[a-f0-9]{64}$/, confidence: 'high', keyed: false },
  { name: 'SendGrid key', regex: /^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/, confidence: 'high', keyed: false },
  { name: 'Databricks token', regex: /^dapi[a-f0-9]{32}$/, confidence: 'high', keyed: false },
  { name: 'Sentry token', regex: /^sntrys_[A-Za-z0-9_-]{20,}$/, confidence: 'high', keyed: false },
  { name: 'Shopify token', regex: /^shpat_[a-f0-9]{32}$/, confidence: 'high', keyed: false },
  { name: 'Twilio key', regex: /^SK[a-f0-9]{32}$/, confidence: 'medium', keyed: true },
  { name: 'JSON Web Token', regex: /^eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/, confidence: 'medium', keyed: false },
  { name: 'Database connection string with password', regex: /^(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp):\/\/[^\s:@/]+:[^\s@/]+@/i, confidence: 'high', keyed: false },
  { name: 'Bearer token', regex: /^Bearer\s+[A-Za-z0-9._-]{20,}$/i, confidence: 'medium', keyed: true },
  { name: 'Generic API token', regex: /^[A-Za-z0-9._-]{24,}$/i, confidence: 'low', keyed: true },
];

// Committed placeholder files exist precisely so real values stay out of them.
const PLACEHOLDER_ENV_FILE = /\.(example|sample|template|dist|defaults?)$/i;

const KEY_HINT = /(token|secret|api[_-]?key|access[_-]?key|client[_-]?secret|password|passwd|credential|auth|figma[_-]?api[_-]?key|anthropic[_-]?api[_-]?key|openai[_-]?api[_-]?key|linear[_-]?api[_-]?key|github[_-]?token)/i;

// A reference to another variable, or a value that is visibly not a secret:
// `${API_KEY}`, `<your key here>`, `xxxxxxxx`, `REPLACE_ME`, `sk-...`.
const REFERENCE_VALUE = /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$|^\{\{.*\}\}$|^%[A-Za-z_]+%$/;
const PLACEHOLDER_VALUE = /^(<[^>]*>|\[[^\]]*\]|\.{3,}|x{4,}|\*{3,}|0{8,})$|^(your|my|the|replace|change|insert|placeholder|example|sample|dummy|fake|todo|test|xxx|changeme|redacted|none|null|undefined)[-_a-z0-9 ]*$|\.{3}$|(x{5,}|\*{4,})|<[^>]{2,}>/i;

export function isPlaceholderValue(value) {
  const text = String(value ?? '').trim();
  return !text || REFERENCE_VALUE.test(text) || PLACEHOLDER_VALUE.test(text);
}

function redact(value) {
  if (!value || value.length <= 8) return '***redacted***';
  return `${value.slice(0, 4)}…${value.slice(-4)}`;
}

// Redact the password inside a connection string rather than the ends of the
// whole URL, which would otherwise print most of the credential.
function redactValue(detector, value) {
  if (detector.startsWith('Database')) return value.replace(/(:\/\/[^:@/]+:)[^@/]+@/, '$1***@');
  return redact(value);
}

export function classifyValue(key, value) {
  const normalized = unquote(value);
  if (isPlaceholderValue(normalized)) return null;
  const keyed = KEY_HINT.test(key);
  for (const pattern of VALUE_PATTERNS) {
    if (pattern.keyed && !keyed) continue;
    if (pattern.regex.test(normalized)) {
      return { detector: pattern.name, confidence: pattern.confidence, redactedValue: redactValue(pattern.name, normalized) };
    }
  }
  return null;
}

function checkFile(path) {
  if (!existsSync(path)) return [];
  let raw;
  try {
    raw = readFileSync(path, 'utf8');
  } catch {
    // An unreadable file (permissions, a dangling symlink) should not abort the scan.
    return [];
  }
  const findings = [];
  for (const [key, value] of parseConfigEntries(path, raw)) {
    const classified = classifyValue(key, value);
    if (!classified) continue;
    findings.push(createFinding({
      id: `secret-${slug(key)}-${shortHash(path)}`,
      category: 'secret-exposure',
      severity: path.includes('.env') || path.endsWith('.zshrc') || path.endsWith('.bashrc') ? 'high' : classified.confidence === 'high' ? 'medium' : 'low',
      confidence: classified.confidence,
      title: `${classified.detector} appears to be stored in plaintext`,
      description: `A likely secret was found in ${path}. Key: ${key}. Value redacted: ${classified.redactedValue}.`,
      path,
      recommendation: path.includes('.env') ? 'Move this token to a secret manager or injected runtime env, not a checked-in or long-lived .env file.' : 'Move this secret to a dedicated secret store or safer runtime injection path, then rotate it if the file has been shared or synced.',
      metadata: { key, detector: classified.detector, redactedValue: classified.redactedValue },
    }));
  }
  return findings;
}

function discoverEnvFiles(startDirs, maxDepth = 2) {
  const seen = new Set();
  const results = [];
  const ignoredDirs = new Set(['.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.turbo', '.cache', '.venv', 'venv', 'fixtures', 'test', 'tests', '__tests__']);
  function walk(dir, depth) {
    if (depth > maxDepth || seen.has(dir) || !existsSync(dir)) return;
    seen.add(dir);
    let entries = [];
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);
      const isEnvFile = entry.name.startsWith('.env') || entry.name.endsWith('.env');
      if (entry.isFile() && isEnvFile && !PLACEHOLDER_ENV_FILE.test(entry.name)) {
        results.push(full);
      }
      if (entry.isDirectory() && !ignoredDirs.has(entry.name)) {
        walk(full, depth + 1);
      }
    }
  }
  for (const dir of startDirs) walk(dir, 0);
  return results;
}

export function runSecretExposureScan(extraPaths = [], options = {}) {
  const home = homedir();
  const workspaceDirs = options.workspaceDirs || [process.cwd()];
  const discoveredEnvFiles = discoverEnvFiles(workspaceDirs, options.maxEnvDepth ?? 2);
  const extraFiles = [];
  const extraDirs = [];
  for (const path of extraPaths) {
    try {
      const stats = statSync(path);
      if (stats.isDirectory()) extraDirs.push(path);
      else if (stats.isFile()) extraFiles.push(path);
    } catch {
      // A missing or unreadable explicitly supplied path should not abort a scan.
    }
  }
  const discoveredExtraEnvFiles = discoverEnvFiles(extraDirs, options.maxEnvDepth ?? 2);
  const paths = [
    join(home, '.codex', 'config.toml'),
    join(home, '.claude.json'),
    join(home, '.zshrc'),
    join(home, '.bashrc'),
    join(home, '.bash_profile'),
    join(home, '.profile'),
    join(home, '.zprofile'),
    join(home, '.zshenv'),
    join(home, '.env'),
    join(home, '.config', 'opencode', 'config.json'),
    join(home, '.config', 'cursor', 'mcp.json'),
    join(home, '.cursor', 'mcp.json'),
    join(home, '.claude', 'settings.json'),
    join(home, '.claude', 'settings.local.json'),
    ...workspaceDirs.flatMap((dir) => [join(dir, '.claude', 'settings.json'), join(dir, '.claude', 'settings.local.json'), join(dir, '.mcp.json')]),
    ...discoveredEnvFiles,
    ...discoveredExtraEnvFiles,
    ...extraFiles,
  ];

  return [...new Set(paths)].flatMap(checkFile);
}
