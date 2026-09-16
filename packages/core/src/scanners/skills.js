import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, extname, join, resolve, sep } from 'node:path';
import { createFinding } from '../schema.js';
import { shortHash } from '../id.js';
import { unquote } from '../parsers.js';
import { runSkillSpectorAudit } from './skillspector.js';

// An agent skill is instructions plus bundled files that a coding agent loads
// and acts on, so a skill directory is executable content: it can tell the agent
// to run commands, read credentials, or set aside its own safety rules. This
// scanner reviews every skill on the machine the way it would review a script.

const SKILL_FILE = 'SKILL.md';
// The Agent Skills convention (agentskills.io) names the manifest SKILL.md;
// some publishers ship it as skill.md, and a scanner should not miss a skill
// over case.
const isSkillFile = (name) => name.toLowerCase() === SKILL_FILE.toLowerCase();

// Where agent runtimes keep skills. Each runtime has a per-user home and a
// per-project folder; every one is checked, whichever agents a machine runs.
// Missing folders cost one stat each.
export const USER_SKILL_DIRS = [
  ['.claude', 'skills'],
  ['.config', 'claude', 'skills'],
  ['.codex', 'skills'],
  ['.agents', 'skills'],
  ['.openclaw', 'skills'],
  ['.cursor', 'skills'],
  ['.gemini', 'skills'],
  ['.copilot', 'skills'],
  ['.opencode', 'skills'],
  ['.config', 'opencode', 'skills'],
  ['.codeium', 'windsurf', 'skills'],
  ['.windsurf', 'skills'],
  ['.kiro', 'skills'],
  ['.continue', 'skills'],
];
export const PROJECT_SKILL_DIRS = [
  ['.claude', 'skills'],
  ['.codex', 'skills'],
  ['.agents', 'skills'],
  ['.cursor', 'skills'],
  ['.gemini', 'skills'],
  ['.github', 'skills'],
  ['.opencode', 'skills'],
  ['.windsurf', 'skills'],
  ['.kiro', 'skills'],
  // A plugin or skills repository keeps its skills at the top level.
  ['skills'],
];
// Marketplace-installed plugins: installed copies only. A marketplace clone
// (Claude Code's plugins/marketplaces) holds every catalogued plugin whether
// installed or not, and the installed ones are already covered by the cache.
export const PLUGIN_SKILL_DIRS = [
  ['.claude', 'plugins', 'cache'],
  ['.codex', 'plugins'],
  ['.cursor', 'plugins'],
  ['.gemini', 'extensions'],
  ['.opencode', 'plugins'],
];
const IGNORED_DIRS = new Set(['node_modules', '.git', 'dist', 'build', '.next', '.venv', 'venv', '__pycache__', '.cache']);

const SCANNABLE_EXTENSIONS = new Set([
  '.md', '.markdown', '.txt', '.sh', '.bash', '.zsh', '.fish', '.py', '.js', '.mjs',
  '.cjs', '.ts', '.rb', '.pl', '.ps1', '.json', '.yaml', '.yml', '.toml', '.html',
]);

const MAX_FILE_BYTES = 512 * 1024;
const MAX_FILES_PER_SKILL = 60;
// Reading a skill is cheap (hundreds per second), so the cap only guards against
// a pathological tree. Roots are visited in priority order — explicit paths,
// then the project, then the user's own skills, then plugins — so a machine
// with a large plugin cache never starves the skills a reader asked about.
const MAX_SKILLS = 1500;
// A project registry that has grown to this size is not worth parsing inline.
const MAX_PROJECT_REGISTRY_BYTES = 32 * 1024 * 1024;

// --- pattern library ---------------------------------------------------------

// Fetch a remote payload and hand it straight to an interpreter.
const PIPE_TO_INTERPRETER = /\b(curl|wget|iwr|invoke-webrequest)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|k|da)?sh\b|\b(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(python3?|node|ruby|perl|pwsh)\b|\bi(ex|nvoke-expression)\s*\(\s*i(wr|nvoke-webrequest)/i;
const DECODE_TO_INTERPRETER = /\b(base64\s+(-d|-D|--decode)|openssl\s+enc\s+-d)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b/i;
const EVAL_ENCODED = /\beval\s*\(\s*(atob|Buffer\.from|decodeURIComponent|unescape)\b|\bexec\s*\(\s*(base64\.b64decode|__import__\(\s*['"]base64)/i;

// Download to disk now, execute later. Each half is unremarkable on its own, so
// they are only reported together, and only when the file that is executed is
// the file that was downloaded: `curl --output /dev/null` next to `python3 -c`
// is a health check, not an installer.
const DOWNLOAD_TO_FILE = /\b(curl|wget)\b[^\n]{0,200}?\s(?:-o|-O|--output|--output-document)(?:=|\s+)(?<target>[^\s'"`;|&]+)/;

// Paths that hold credentials. The tight list is reported on its own; the wide
// list only counts when something is also shipping data off the machine.
const CREDENTIAL_PATH = /(\.ssh\/(id_[a-z0-9_]+|authorized_keys)|\bid_rsa\b|\bid_ed25519\b|\.aws\/credentials|\.config\/gcloud|\.kube\/config|\.npmrc|\.netrc|\.pypirc|\.docker\/config\.json|\.gnupg|\.claude\.json|\.codex\/auth\.json|login\.keychain|security\s+find-(generic|internet)-password)/i;
const SENSITIVE_PATH = new RegExp(`${CREDENTIAL_PATH.source}|\\.env\\b|\\.git-credentials|history\\.jsonl`, 'i');
const READ_COMMAND = /(^|[\s`|(])(cat|less|more|head|tail|cp|mv|scp|rsync|open|grep|awk|sed|xargs|source|export|python3?|node|ruby|Read|Bash|Glob|find)\b/;

// Sending data somewhere off this machine.
const NETWORK_SEND = /\bcurl\b[^\n]{0,200}(-X\s*POST|--data|--data-binary|--data-raw|-d\s|--upload-file|\s-T\s|\s-F\s)|\bwget\b[^\n]{0,200}--post|\b(nc|ncat|netcat)\s+-[^\n]{0,40}\d|\brequests\.post\(|\burllib\.request\.urlopen\(|\bfetch\([^\n]{0,200}method\s*:\s*['"]POST|\baxios\.post\(|\bscp\s+\S+\s+\S+@|\bmail\s+-s\b/i;

const DESTRUCTIVE_COMMANDS = [
  // The target has to end right there. `rm -rf /tmp/build` is housekeeping;
  // `rm -rf /` and `rm -rf ~` are not.
  { label: 'a recursive force-delete of a root or home path', regex: /\brm\s+(-[a-zA-Z]*[rR][a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*[rR])[a-zA-Z]*\s+(\/|~|\$HOME|\$\{HOME\}|\*)(?=\s|$|["'`;&|,)])/ },
  { label: 'a privileged delete', regex: /\bsudo\s+rm\b/i },
  { label: 'a filesystem format', regex: /\bmkfs(\.[a-z0-9]+)?\s/i },
  { label: 'a raw device write', regex: /\bdd\s+[^\n]{0,120}\bof=\/dev\//i },
  { label: 'a fork bomb', regex: /:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/ },
  { label: 'a world-writable permission change', regex: /\bchmod\s+(-R\s+)?0?777\b/ },
  { label: 'shell history removal', regex: /\bhistory\s+-c\b|\brm\b[^\n]{0,60}\.(bash|zsh)_history/i },
  { label: 'credential store deletion', regex: /\brm\b[^\n]{0,80}\.ssh\/|\bsecurity\s+delete-(generic|internet)-password/i },
];

// Text that steers the agent instead of describing a task.
const INSTRUCTION_OVERRIDE = [
  /ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|earlier|preceding|above)\s+(instructions|prompts?|rules|directions|guidance)/i,
  /disregard\s+(all\s+|any\s+)?(the\s+)?(previous|prior|earlier|above|system)\s+(instructions|prompts?|rules)/i,
  // "do not tell the user to run X" is advice about phrasing, not concealment.
  /(do\s+not|don'?t|never)\s+(tell|inform|notify|warn)\s+(the\s+)?user\b(?!\s+(to|that\s+they|how)\b)/i,
  // "Do not show this to the user" conceals something. "Do not show the user
  // the JSON output" is a formatting instruction, and skills are full of them,
  // so show/display only count when the object is the thing being hidden.
  /(do\s+not|don'?t|never)\s+(show|display|reveal|surface|expose)\s+(this|that|it|these|them)\s+to\s+(the\s+)?user/i,
  /without\s+(telling|informing|notifying|asking|confirming\s+with)\s+(the\s+)?user/i,
  /(hide|conceal)\s+(this|these|it)\s+from\s+(the\s+)?user/i,
  /you\s+(are|have\s+been)\s+(now\s+)?(fully\s+|pre-?)?(authorized|approved|permitted)\s+to\s+(run|execute|access|read|send|bypass)/i,
  /(bypass|override|ignore|skip)\s+(all\s+|any\s+)?(the\s+)?(safety|security|permission)\s+(checks?|rules|guidelines|restrictions|prompts?)/i,
];

// Characters a reviewer cannot see but a model still reads: zero-width and
// bidi-control runs, plus the Unicode tag block used to smuggle ASCII.
const INVISIBLE_CHARACTERS = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]|[\u{E0000}-\u{E007F}]/u;
// A zero-width joiner between two pictographs is how a family or a cat-with-
// halo emoji is spelled, not a hidden character.
const ZERO_WIDTH_JOINER = '\u200D';
const PICTOGRAPH = /\p{Extended_Pictographic}|\uFE0F/u;
const BINARY_BYTES = /[\u0000-\u0008\u000E-\u001F]/;
const HTML_COMMENT = /<!--([\s\S]{0,4000}?)-->/g;
// A comment written for the model addresses it: by name, in the vocative, or
// in the second person. A bare mention of "agent" is not an address — skills
// talk about agents constantly, and paths like skill/agents/ contain the word.
const COMMENT_ADDRESSES_MODEL = /\b(claude|chatgpt|copilot|gemini|codex|assistant|the\s+ai|ai\s+assistant|llm|language\s+model|system\s+prompt)\b|\b(agent|assistant|ai|model)s?\s*[:,]|\byou\s+(must|should|shall|will|need\s+to|are|have\s+to)\b/i;
const COMMENT_IS_IMPERATIVE = /\b(must|should|always|never|ignore|execute|run|send|read|fetch|do\s+not|instead)\b/i;

// Build banners, licence headers, and editor directives are written for the
// next human to open the file and use the same imperative voice as an attack.
// Reporting them as hidden instructions buries the ones that are real.
const COMMENT_IS_HOUSEKEEPING = /\b(auto-?generated|generated\s+(from|by|at|with)|do\s+not\s+edit|don'?t\s+edit|build\s+time|source\s+of\s+truth|spdx|copyright|licen[cs]ed?|prettier|eslint|markdownlint|shellcheck|stylelint|nosec|noqa|todo|fixme|template)\b/i;
const BASE64_BLOB = /[A-Za-z0-9+/]{240,}={0,2}/g;

const SECRET_PATTERNS = [
  { name: 'Anthropic API key', regex: /\bsk-ant-[A-Za-z0-9_-]{24,}/ },
  { name: 'OpenAI API key', regex: /\bsk-(proj-)?[A-Za-z0-9_-]{32,}/ },
  { name: 'GitHub token', regex: /\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})/ },
  { name: 'AWS access key id', regex: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'Slack token', regex: /\bxox[baprs]-[A-Za-z0-9-]{12,}/ },
  { name: 'Google API key', regex: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'Figma token', regex: /\bfigd_[A-Za-z0-9_-]{20,}/ },
  { name: 'Linear token', regex: /\blin_api_[A-Za-z0-9_-]{16,}/ },
  // A header alone is prose about PEM; a key carries a base64 body after it.
  { name: 'private key block', regex: /-----BEGIN\s+([A-Z]+\s+)?PRIVATE KEY-----\s*(\\n|\r?\n)\s*[A-Za-z0-9+/=\\nr\s]{40,}/ },
];
const PLACEHOLDER_VALUE = /(x{6,}|\.{3}|your[_-]?|example|replace|placeholder|redacted|dummy|<|\$\{)/i;

// Running whatever the registry serves today, unpinned.
const UNPINNED_PACKAGE_RUN = /\bnpx\s+(-y|--yes)\s+\S+|\b(bunx|uvx|pnpm\s+dlx|pipx\s+run)\s+\S+|\bpip3?\s+install\s+(git\+|https?:)\S+/i;

const RISKY_BASH_COMMANDS = /^(sudo|rm|chmod|chown|dd|eval|curl|wget|nc|ncat|osascript|launchctl|systemctl|security|defaults|kill|killall|pkill)\b/i;

// --- discovery ---------------------------------------------------------------

function safeRealpath(path) {
  try {
    return realpathSync(path);
  } catch {
    return null;
  }
}

function findSkillDirs(root, maxDepth, seen, limit) {
  const results = [];

  function walk(dir, depth) {
    if (results.length >= limit || depth > maxDepth) return;
    const real = safeRealpath(dir);
    if (!real || seen.has(real)) return;
    seen.add(real);

    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    // A skill directory owns everything beneath it, so bundled resources that
    // carry their own SKILL.md are not counted as separate skills.
    if (entries.some((entry) => entry.isFile() && isSkillFile(entry.name))) {
      results.push(dir);
      return;
    }

    for (const entry of entries) {
      if (!entry.isDirectory() || IGNORED_DIRS.has(entry.name)) continue;
      walk(join(dir, entry.name), depth + 1);
    }
  }

  walk(root, 0);
  return results;
}

function findProjectSkillRoots(startDirs, maxDepth) {
  const roots = [];
  const visited = new Set();

  // Resolved paths, not realpaths: this walk has unbounded breadth, and
  // realpathSync on every directory of a home folder costs tens of seconds.
  // The depth cap already rules out a symlink loop.
  function walk(dir, depth) {
    if (depth > maxDepth || visited.has(dir)) return;
    visited.add(dir);

    for (const parts of PROJECT_SKILL_DIRS) {
      const skillsDir = join(dir, ...parts);
      if (existsSync(skillsDir)) roots.push(skillsDir);
    }
    if (depth === maxDepth) return;

    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (!entry.isDirectory() || entry.name.startsWith('.') || IGNORED_DIRS.has(entry.name)) continue;
      walk(resolve(dir, entry.name), depth + 1);
    }
  }

  for (const dir of startDirs) walk(resolve(dir), 0);
  return roots;
}

// Machine-wide project coverage. Walking a home directory for skill folders
// takes minutes on a real machine, so this reads each agent's own registry of
// project directories instead: every project the user has actually opened,
// wherever it lives on disk, for the cost of one file read per agent.
function readRegistry(path) {
  try {
    if (statSync(path).size > MAX_PROJECT_REGISTRY_BYTES) return null;
    return readFileSync(path, 'utf8');
  } catch {
    return null;
  }
}

const isAbsoluteDir = (dir) => typeof dir === 'string' && (dir.startsWith('/') || /^[A-Za-z]:[\\/]/.test(dir));

export function registeredProjectDirs(home) {
  const dirs = new Set();

  // Claude Code: ~/.claude.json { projects: { "/abs/path": {...} } }
  const claude = readRegistry(join(home, '.claude.json'));
  if (claude) {
    try {
      const projects = JSON.parse(claude).projects;
      if (projects && typeof projects === 'object') for (const dir of Object.keys(projects)) if (isAbsoluteDir(dir)) dirs.add(dir);
    } catch {
      // Not JSON: local discovery still applies.
    }
  }

  // Codex: ~/.codex/config.toml [projects."/abs/path"] tables
  const codex = readRegistry(join(home, '.codex', 'config.toml'));
  if (codex) {
    for (const match of codex.matchAll(/^\s*\[projects\.["']([^"'\]]+)["']\]/gm)) if (isAbsoluteDir(match[1])) dirs.add(match[1]);
  }

  // Cursor and Gemini keep trusted-folder lists in JSON under their homes.
  for (const path of [join(home, '.cursor', 'trusted-folders.json'), join(home, '.gemini', 'trustedFolders.json')]) {
    const raw = readRegistry(path);
    if (!raw) continue;
    try {
      const parsed = JSON.parse(raw);
      const list = Array.isArray(parsed) ? parsed : Object.keys(parsed && typeof parsed === 'object' ? parsed : {});
      for (const dir of list) if (isAbsoluteDir(dir)) dirs.add(dir);
    } catch {
      // Ignore an unreadable registry.
    }
  }

  return [...dirs];
}

export function skillSearchRoots(options = {}) {
  const home = options.home || homedir();
  const workspaceDirs = options.workspaceDirs || [process.cwd()];
  const roots = [];
  const add = (dir, scope, maxDepth) => {
    if (existsSync(dir)) roots.push({ dir, scope, maxDepth });
  };

  // Priority order: what the reader asked about, then the project they are in,
  // then their own skills, then third-party plugins. The cap trims from the end.
  for (const dir of options.skillPaths || []) add(dir, 'explicit', 4);
  for (const dir of findProjectSkillRoots(workspaceDirs, options.maxProjectDepth ?? 2)) add(dir, 'project', 3);
  if (options.scanKnownProjects !== false) {
    for (const dir of registeredProjectDirs(home)) {
      for (const parts of PROJECT_SKILL_DIRS) add(join(dir, ...parts), 'project', 3);
    }
  }
  for (const parts of USER_SKILL_DIRS) add(join(home, ...parts), 'global', 3);
  // Plugin skills arrive from a marketplace, so they are third-party code that
  // was never reviewed one skill at a time.
  for (const parts of PLUGIN_SKILL_DIRS) add(join(home, ...parts), 'plugin', 8);
  // An older Claude Code layout kept installed plugins directly under plugins/.
  if (!existsSync(join(home, '.claude', 'plugins', 'cache'))) add(join(home, '.claude', 'plugins'), 'plugin', 8);

  const unique = new Map();
  for (const root of roots) {
    const real = safeRealpath(root.dir) || root.dir;
    if (!unique.has(real)) unique.set(real, root);
  }
  return [...unique.values()];
}

// --- skill reading -----------------------------------------------------------

export function parseSkillFrontmatter(raw) {
  const match = /^---\r?\n([\s\S]*?)\r?\n---[ \t]*\r?\n?/.exec(raw);
  if (!match) return { data: {}, body: raw };

  const data = {};
  let currentKey = null;
  for (const line of match[1].split('\n')) {
    const item = /^\s*-\s+(.*)$/.exec(line);
    if (item && currentKey) {
      if (!Array.isArray(data[currentKey])) data[currentKey] = [];
      data[currentKey].push(unquote(item[1]));
      continue;
    }
    const pair = /^([A-Za-z0-9_.-]+)\s*:\s*(.*)$/.exec(line);
    if (!pair) continue;
    currentKey = pair[1];
    const value = pair[2].trim();
    if (!value) {
      data[currentKey] = [];
    } else if (value.startsWith('[') && value.endsWith(']')) {
      data[currentKey] = value.slice(1, -1).split(',').map(unquote).filter(Boolean);
    } else {
      data[currentKey] = unquote(value);
    }
  }
  return { data, body: raw.slice(match[0].length) };
}

function allowedToolList(frontmatter) {
  const value = frontmatter['allowed-tools'] ?? frontmatter.allowedTools ?? frontmatter.allowed_tools;
  if (Array.isArray(value)) return value.map(String);
  if (typeof value === 'string') return value.split(',').map((entry) => entry.trim()).filter(Boolean);
  return [];
}

function readSkillFiles(skillDir) {
  const files = [];
  const problems = [];
  const skillReal = safeRealpath(skillDir);

  function walk(dir, depth) {
    if (files.length >= MAX_FILES_PER_SKILL || depth > 4) return;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (files.length >= MAX_FILES_PER_SKILL) return;
      const full = join(dir, entry.name);

      let link;
      try {
        link = lstatSync(full);
      } catch {
        continue;
      }

      if (link.isSymbolicLink()) {
        const target = safeRealpath(full);
        // A symlink out of the skill folder means the directory you reviewed is
        // not the content the agent loads.
        if (skillReal && (!target || !(target === skillReal || target.startsWith(skillReal + sep)))) {
          problems.push({ kind: 'symlink-escape', path: full, target: target || 'an unresolved target' });
        }
        continue;
      }

      if (link.isDirectory()) {
        if (!IGNORED_DIRS.has(entry.name)) walk(full, depth + 1);
        continue;
      }
      if (!link.isFile()) continue;

      if (link.mode & 0o022) problems.push({ kind: 'writable', path: full, mode: link.mode & 0o777 });
      if (!SCANNABLE_EXTENSIONS.has(extname(entry.name).toLowerCase()) || link.size > MAX_FILE_BYTES) continue;

      try {
        files.push({ path: full, raw: readFileSync(full, 'utf8') });
      } catch {
        // An unreadable bundled file should not abort the scan.
      }
    }
  }

  try {
    const dirStat = statSync(skillDir);
    if (dirStat.mode & 0o022) problems.push({ kind: 'writable', path: skillDir, mode: dirStat.mode & 0o777 });
  } catch {
    // An unreadable directory simply yields no files.
  }

  walk(skillDir, 0);
  return { files, problems };
}

function readSkill(dir, scope, root) {
  // Use the manifest's real name on disk. A case-insensitive filesystem would
  // happily open skill.md as SKILL.md, and the report should name the file
  // the reader will find.
  let skillFile;
  let raw;
  try {
    const actual = readdirSync(dir).find(isSkillFile);
    if (!actual) return null;
    skillFile = join(dir, actual);
    raw = readFileSync(skillFile, 'utf8');
  } catch {
    return null;
  }

  const { data } = parseSkillFrontmatter(raw);
  const { files, problems } = readSkillFiles(dir);
  if (!files.some((file) => file.path === skillFile)) files.unshift({ path: skillFile, raw });

  return {
    dir,
    scope,
    root,
    name: String(data.name || basename(dir)),
    description: String(data.description || ''),
    allowedTools: allowedToolList(data),
    files,
    problems,
  };
}

export function collectSkillInventory(options = {}) {
  const skills = [];
  const seen = new Set();
  const limit = options.maxSkills ?? MAX_SKILLS;
  for (const root of skillSearchRoots(options)) {
    for (const dir of findSkillDirs(root.dir, root.maxDepth, seen, limit - skills.length + 1)) {
      if (skills.length >= limit) {
        skills.truncated = true;
        return skills;
      }
      const skill = readSkill(dir, root.scope, root.dir);
      if (skill) skills.push(skill);
    }
  }
  return skills;
}

// --- evidence ----------------------------------------------------------------

function redact(text) {
  let output = String(text);
  for (const pattern of SECRET_PATTERNS) {
    output = output.replace(new RegExp(pattern.regex.source, 'g'), (match) => `${match.slice(0, 6)}...redacted`);
  }
  return output;
}

function evidenceAt(text, index, limit = 160) {
  const start = text.lastIndexOf('\n', index) + 1;
  const lineEnd = text.indexOf('\n', index);
  const line = text.slice(start, lineEnd === -1 ? text.length : lineEnd).trim();
  return redact(line.length > limit ? `${line.slice(0, limit)}...` : line);
}

// Security-aware skills quote the very patterns this scanner looks for, to warn
// an agent about them. A skill that says `blocked pattern: rm -rf /` is doing the
// right thing, and reporting it as an attack would bury the real findings. These
// two guards separate a quoted illustration from an instruction to act.
const EXAMPLE_CONTEXT = /\b(example|e\.g\.|for instance|pattern|blocked?|blocks|denied?|deny|reject|prevent|guard|test(ed|ing|s)?|adversarial|malicious|attack|injection|untrusted|refuse|forbidden|disallow|validat|never\s+run|do\s+not\s+run|never\s+follow|do\s+not\s+follow|beware|watch\s+for|match(es|ing)?|regex|sample|illustrat|suspicious|detect)/i;

function isDocumentedExample(text, index, length) {
  // Quoted in prose. Backticks are deliberately not treated this way, because a
  // command a skill wants run is normally written in backticks.
  const before = text[index - 1];
  const after = text.slice(index + length, index + length + 12);
  if ((before === '"' || before === "'" || before === '\u201c' || before === '\u2018')
    && (after === '' || /^[^"'\u201d\u2019\n]{0,10}["'\u201d\u2019]/.test(after))) return true;

  // A list of blocked patterns puts its heading a few lines above the entries,
  // so the lead-in has to be read, not just the line the match sits on.
  const lineEnd = text.indexOf('\n', index);
  const context = text.slice(Math.max(0, index - 200), lineEnd === -1 ? text.length : lineEnd);
  return EXAMPLE_CONTEXT.test(context);
}

function firstMatch(text, regex, guard = true) {
  const scanner = new RegExp(regex.source, `${regex.flags.replace('g', '')}g`);
  for (const match of text.matchAll(scanner)) {
    if (guard && isDocumentedExample(text, match.index, match[0].length)) continue;
    return { match: match[0], index: match.index, evidence: evidenceAt(text, match.index) };
  }
  return null;
}

// Two halves of an attack only mean something when they sit close together. A
// skill that posts to an API on line 5 and mentions .env on line 400 is not
// exfiltrating anything.
function matchesNearby(text, first, second, window = 400) {
  const scanner = new RegExp(first.source, `${first.flags.replace('g', '')}g`);
  for (const match of text.matchAll(scanner)) {
    if (isDocumentedExample(text, match.index, match[0].length)) continue;
    const zone = text.slice(Math.max(0, match.index - window), match.index + match[0].length + window);
    const partner = new RegExp(second.source, second.flags.replace('g', '')).exec(zone);
    if (partner) return { match: match[0], partner: partner[0], index: match.index, evidence: evidenceAt(text, match.index) };
  }
  return null;
}

// An invisible character hides something only when it sits inside visible
// text: between letters, or splitting a word. A stray zero-width space at the
// start of a line or beside a code fence is paste debris, and every editor
// leaves some. Bidirectional controls and Unicode tag characters always count,
// because they exist to make text read differently from how it is written.
const ALWAYS_HIDDEN = /[\u202A-\u202E\u2066-\u2069]|[\u{E0000}-\u{E007F}]/u;
const VISIBLE_NEIGHBOUR = /[\p{L}\p{N}\p{P}]/u;

function hiddenCharacter(text) {
  const scanner = new RegExp(INVISIBLE_CHARACTERS.source, 'gu');
  for (const match of text.matchAll(scanner)) {
    const before = text.slice(Math.max(0, match.index - 2), match.index).replace(INVISIBLE_CHARACTERS, '');
    const after = text.slice(match.index + match[0].length, match.index + match[0].length + 3).replace(INVISIBLE_CHARACTERS, '');
    if (match[0] === ZERO_WIDTH_JOINER && PICTOGRAPH.test(before) && PICTOGRAPH.test(after)) continue;
    if (!ALWAYS_HIDDEN.test(match[0])) {
      const touchesText = VISIBLE_NEIGHBOUR.test(before.slice(-1)) && VISIBLE_NEIGHBOUR.test(after.charAt(0));
      const fence = /`{3}|^\s*$/.test(before) || /^`{3}/.test(after);
      if (!touchesText || fence) continue;
    }
    return { match: match[0], index: match.index, evidence: evidenceAt(text, match.index) };
  }
  return null;
}

// A download only becomes an installer when the same file is executed nearby.
function downloadThenRun(text, window = 300) {
  // Case matters here: `grep -oP` is not `curl -o P`.
  const scanner = new RegExp(DOWNLOAD_TO_FILE.source, 'g');
  for (const match of text.matchAll(scanner)) {
    const target = match.groups?.target ?? '';
    const name = basename(target);
    if (!name || target === '/dev/null' || target === '-') continue;
    if (isDocumentedExample(text, match.index, match[0].length)) continue;
    const zone = text.slice(match.index + match[0].length, match.index + match[0].length + window);
    const file = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const boundary = String.raw`(?=\s|$|["'\`;&|)])`;
    // Either an interpreter is handed the file, or the file itself is the
    // command: at the start of a line or right after ; | && ||.
    const run = new RegExp(
      String.raw`\b(chmod\s+\+x|sh|bash|zsh|python3?|node|ruby|perl|osascript|source)\s+[^\s;|&]*${file}${boundary}`
      + String.raw`|(^|[;|&]\s*)\.?/?[^\s;|&]*${file}${boundary}`,
      'im',
    );
    const partner = run.exec(zone);
    if (partner) return { match: match[0], partner: partner[0], index: match.index, evidence: evidenceAt(text, match.index) };
  }
  return null;
}

// Script sources carry their instructions in code, not in comments. A comment
// that describes past behaviour ("the model did X without telling the user")
// is not an instruction to do it, so override rules skip comment lines there.
const CODE_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.py', '.rb', '.pl', '.sh', '.bash', '.zsh', '.fish', '.ps1']);
const COMMENT_LINE = /^\s*(\/\/|#|\*|\/\*)/;

function onCommentLine(text, index) {
  const start = text.lastIndexOf('\n', index) + 1;
  return COMMENT_LINE.test(text.slice(start, index));
}

function decodedPayload(text) {
  for (const match of text.matchAll(BASE64_BLOB)) {
    // An embedded image or font is a long base64 run too, and it is not a payload.
    if (/data:[\w.+-]+\/[\w.+-]+;base64,?\s*$/i.test(text.slice(Math.max(0, match.index - 48), match.index))) continue;
    let decoded;
    try {
      decoded = Buffer.from(match[0], 'base64').toString('utf8');
    } catch {
      continue;
    }
    if (!decoded || BINARY_BYTES.test(decoded)) continue;
    const suspicious = PIPE_TO_INTERPRETER.test(decoded)
      || SENSITIVE_PATH.test(decoded)
      || NETWORK_SEND.test(decoded)
      || INSTRUCTION_OVERRIDE.some((pattern) => pattern.test(decoded));
    if (suspicious) return { index: match.index, evidence: redact(decoded.replace(/\s+/g, ' ').slice(0, 160)) };
  }
  return null;
}

function hiddenComment(text) {
  for (const match of text.matchAll(HTML_COMMENT)) {
    const body = match[1];
    if (COMMENT_IS_HOUSEKEEPING.test(body)) continue;
    if (COMMENT_ADDRESSES_MODEL.test(body) && COMMENT_IS_IMPERATIVE.test(body)) {
      return { index: match.index, evidence: redact(body.trim().replace(/\s+/g, ' ').slice(0, 160)) };
    }
  }
  return null;
}

function embeddedSecret(text) {
  for (const pattern of SECRET_PATTERNS) {
    const match = pattern.regex.exec(text);
    if (!match || PLACEHOLDER_VALUE.test(match[0])) continue;
    return { detector: pattern.name, index: match.index, evidence: evidenceAt(text, match.index) };
  }
  return null;
}

// --- rules -------------------------------------------------------------------

// Each rule inspects one file of one skill and returns the evidence for a single
// finding, or null. Severity is fixed per rule so reports stay comparable across
// machines.
const FILE_RULES = [
  {
    key: 'remote-code-execution',
    severity: 'critical',
    confidence: 'high',
    title: 'A skill fetches remote code and runs it',
    detect: (text) => firstMatch(text, PIPE_TO_INTERPRETER)
      || firstMatch(text, DECODE_TO_INTERPRETER)
      || firstMatch(text, EVAL_ENCODED)
      || downloadThenRun(text),
    describe: (skill, hit) => `The skill "${skill.name}" downloads or decodes code and executes it in one step: ${hit.evidence}. Whoever controls that payload controls what runs on this machine, and it can change after you review the skill.`,
    recommendation: 'Remove the fetch-and-execute step. Pin the payload to a reviewed file inside the skill, or install the tool yourself so the code can be read before it runs.',
  },
  {
    key: 'data-exfiltration',
    severity: 'critical',
    confidence: 'medium',
    title: 'A skill reads credentials and sends data off this machine',
    detect: (text) => matchesNearby(text, SENSITIVE_PATH, NETWORK_SEND),
    describe: (skill, hit) => `The skill "${skill.name}" references a credential or environment file next to a command that transmits data: ${hit.evidence}. That is the shape of a credential-stealing skill.`,
    recommendation: 'Confirm what this skill sends and where. Remove the outbound call or scope it so it can never carry credential files, then rotate anything it could already have read.',
  },
  {
    key: 'hidden-instructions',
    severity: 'high',
    confidence: 'medium',
    title: 'A skill hides instructions from human review',
    detect: (text) => {
      const invisible = hiddenCharacter(text);
      if (invisible) return { ...invisible, kind: 'invisible characters' };
      const payload = decodedPayload(text);
      if (payload) return { ...payload, kind: 'an encoded payload' };
      const comment = hiddenComment(text);
      if (comment) return { ...comment, kind: 'a hidden HTML comment addressed to the agent' };
      return null;
    },
    describe: (skill, hit) => `The skill "${skill.name}" contains ${hit.kind} that an agent reads but a reviewer does not see: ${hit.evidence}. Hidden content is how a skill says one thing to you and another to the agent.`,
    recommendation: 'Open the raw file and read the hidden section. Remove it unless you can explain why it has to be invisible, and stop using the skill until you can.',
  },
  {
    key: 'instruction-override',
    severity: 'high',
    confidence: 'medium',
    title: 'A skill instructs the agent to override its own rules',
    detect: (text, file) => {
      const inCode = CODE_EXTENSIONS.has(extname(file.path).toLowerCase());
      for (const pattern of INSTRUCTION_OVERRIDE) {
        const scanner = new RegExp(pattern.source, 'gi');
        for (const match of text.matchAll(scanner)) {
          if (isDocumentedExample(text, match.index, match[0].length)) continue;
          if (inCode && onCommentLine(text, match.index)) continue;
          return { match: match[0], index: match.index, evidence: evidenceAt(text, match.index) };
        }
      }
      return null;
    },
    describe: (skill, hit) => `The skill "${skill.name}" tells the agent to ignore prior instructions or to act without telling you: ${hit.evidence}. A skill should describe a task, not rewrite the agent's safety rules.`,
    recommendation: 'Read the surrounding section and remove the override language. Treat a skill that needs it as untrusted until you know who wrote it and why.',
  },
  {
    key: 'destructive-command',
    severity: 'high',
    confidence: 'medium',
    title: 'A skill contains a destructive command',
    detect: (text) => {
      for (const { label, regex } of DESTRUCTIVE_COMMANDS) {
        const hit = firstMatch(text, regex);
        if (hit) return { ...hit, label };
      }
      return null;
    },
    describe: (skill, hit) => `The skill "${skill.name}" includes ${hit.label}: ${hit.evidence}. An agent following this skill can run it without a second look.`,
    recommendation: 'Replace the command with a narrower one, or put it behind an explicit confirmation step you control.',
  },
  {
    key: 'embedded-secret',
    severity: 'high',
    confidence: 'high',
    title: 'A skill contains a hardcoded credential',
    detect: (text) => embeddedSecret(text),
    describe: (skill, hit) => `A ${hit.detector} is written directly into the skill "${skill.name}": ${hit.evidence}. Skill folders get copied, synced, and shared as ordinary files.`,
    recommendation: 'Remove the credential from the skill, load it from the environment or a secret manager instead, and rotate it because it has been sitting in a readable file.',
  },
  {
    key: 'credential-access',
    severity: 'medium',
    confidence: 'medium',
    title: 'A skill reads credential files',
    detect: (text) => {
      for (const match of text.matchAll(new RegExp(CREDENTIAL_PATH.source, 'gi'))) {
        if (isDocumentedExample(text, match.index, match[0].length)) continue;
        const line = evidenceAt(text, match.index);
        if (READ_COMMAND.test(line)) return { match: match[0], index: match.index, evidence: line };
      }
      return null;
    },
    describe: (skill, hit) => `The skill "${skill.name}" reads a credential path: ${hit.evidence}. Anything the skill reads lands in the agent's context and in whatever it does next.`,
    recommendation: 'Confirm this access is necessary, narrow it to the single value the skill needs, and keep private keys and credential stores out of skill instructions.',
  },
  {
    key: 'unpinned-package',
    severity: 'low',
    confidence: 'medium',
    title: 'A skill runs an unpinned remote package',
    detect: (text) => firstMatch(text, UNPINNED_PACKAGE_RUN),
    describe: (skill, hit) => `The skill "${skill.name}" executes a package straight from a registry without pinning a version: ${hit.evidence}. What runs is whatever the registry serves that day.`,
    recommendation: 'Pin the version, or install the package as a reviewed dependency so an upstream change cannot alter what this skill runs.',
  },
];

function analyzeSkill(skill) {
  const findings = [];
  const reported = new Set();
  const skillKey = shortHash(skill.dir);
  const skillFile = skill.files.find((file) => isSkillFile(basename(file.path)))?.path ?? join(skill.dir, SKILL_FILE);

  const base = (key, input) => ({
    id: `skill-${key}-${skillKey}`,
    category: 'skill-risk',
    ...input,
    metadata: { skill: skill.name, scope: skill.scope, skillPath: skill.dir, ...input.metadata },
  });

  for (const file of skill.files) {
    for (const rule of FILE_RULES) {
      if (reported.has(rule.key)) continue;
      const hit = rule.detect(file.raw, file);
      if (!hit) continue;
      reported.add(rule.key);
      findings.push(createFinding(base(rule.key, {
        severity: rule.severity,
        confidence: rule.confidence,
        title: rule.title,
        description: rule.describe(skill, hit),
        path: file.path,
        recommendation: rule.recommendation,
        metadata: { evidence: hit.evidence },
      })));
    }
  }

  const unscopedShell = skill.allowedTools.filter((tool) => /^(bash|shell)$/i.test(tool) || /^bash\(\s*\*/i.test(tool) || /^bash\(\s*\)$/i.test(tool));
  const riskyScoped = skill.allowedTools.filter((tool) => {
    const scoped = /^bash\(\s*(.+?)\s*\)$/i.exec(tool);
    return scoped ? RISKY_BASH_COMMANDS.test(scoped[1]) : false;
  });

  if (unscopedShell.length) {
    findings.push(createFinding(base('unscoped-shell', {
      severity: 'high',
      confidence: 'high',
      title: 'A skill pre-approves unrestricted shell access',
      description: `The skill "${skill.name}" lists ${unscopedShell.join(', ')} in allowed-tools, so any command it asks for runs without the usual approval prompt.`,
      path: skillFile,
      recommendation: 'Scope the permission to what this skill actually needs, for example Bash(git status *), so an unexpected command still stops for approval.',
      metadata: { allowedTools: skill.allowedTools },
    })));
  } else if (riskyScoped.length) {
    findings.push(createFinding(base('risky-tool-scope', {
      severity: 'medium',
      confidence: 'high',
      title: 'A skill pre-approves a high-impact command',
      description: `The skill "${skill.name}" pre-approves ${riskyScoped.join(', ')} in allowed-tools. These commands can delete files, change permissions, or reach the network without prompting.`,
      path: skillFile,
      recommendation: 'Drop the pre-approval so these commands still require confirmation, or narrow the pattern to the exact arguments the skill needs.',
      metadata: { allowedTools: riskyScoped },
    })));
  }

  const writable = skill.problems.filter((problem) => problem.kind === 'writable');
  if (writable.length) {
    // World-writable is anyone; group-writable is usually the owner's own
    // primary group on a single-user machine, which package managers leave
    // behind routinely, so it is reported low and said plainly.
    const world = writable.some((problem) => problem.mode & 0o002);
    findings.push(createFinding(base('writable', {
      severity: world ? 'medium' : 'low',
      confidence: world ? 'high' : 'low',
      title: world ? 'A skill can be rewritten by any account on this machine' : 'A skill can be rewritten by other accounts in its group',
      description: `${writable.length} ${writable.length === 1 ? 'file or folder' : 'files or folders'} in the skill "${skill.name}" ${writable.length === 1 ? 'is' : 'are'} ${world ? 'world-writable' : 'group-writable'} (mode ${writable[0].mode.toString(8)}). Anything that can write here changes what the agent does next${world ? '' : '; on a single-user machine the group is usually only you'}.`,
      path: writable[0].path,
      recommendation: 'Restrict the skill to your own user with chmod -R go-w on the skill directory, then check whether the contents were already modified.',
      metadata: { paths: writable.slice(0, 10).map((problem) => problem.path) },
    })));
  }

  const escapes = skill.problems.filter((problem) => problem.kind === 'symlink-escape');
  if (escapes.length) {
    findings.push(createFinding(base('symlink-escape', {
      severity: 'medium',
      confidence: 'high',
      title: 'A skill links to files outside its own folder',
      description: `The skill "${skill.name}" contains a symlink that resolves outside the skill directory (${escapes[0].target}). Reviewing the skill folder does not show what the agent actually loads.`,
      path: escapes[0].path,
      recommendation: 'Replace the symlink with a copy you can review, or confirm the target is yours and is not writable by anything else.',
      metadata: { targets: escapes.slice(0, 10).map((problem) => problem.target) },
    })));
  }

  return findings;
}

// A marketplace commonly ships one skill once per agent runtime — .claude/,
// .cursor/, .gemini/, .github/, and so on — so a single problem in a single
// file gets found once per copy, and two rules can report thirty-six findings
// about one skill. Copies like that collapse into one finding that says how
// many carry it.
//
// The merge is deliberately narrow. Two findings are the same copy only when
// the rule, the skill name, and the evidence are identical AND their paths
// differ by nothing but the runtime segment. Two skills that merely share a
// name and content — ~/skills/helper and ~/other/helper — stay separate,
// because those are two installs a reader has to deal with one at a time.
const RUNTIME_SEGMENT = /^(\.[a-z][a-z0-9_.-]*|plugin|plugins)$/i;

function withoutRuntimeSegments(path) {
  return String(path ?? '')
    .split(sep)
    .filter((segment) => !RUNTIME_SEGMENT.test(segment))
    .join(sep);
}

function mergeRuntimeCopies(findings) {
  const first = new Map();
  const order = [];

  for (const finding of findings) {
    const key = [
      finding.id.replace(/-[0-9a-f]{10}$/, ''),
      finding.metadata?.skill ?? '',
      withoutRuntimeSegments(finding.path),
      finding.description,
    ].join('\u0000');

    const kept = first.get(key);
    if (!kept) {
      first.set(key, { finding, otherPaths: [] });
      order.push(key);
      continue;
    }
    if (finding.path && kept.otherPaths.length < 20) kept.otherPaths.push(finding.path);
  }

  return order.map((key) => {
    const { finding, otherPaths } = first.get(key);
    if (!otherPaths.length) return finding;
    return {
      ...finding,
      description: `${finding.description} The same file is present in ${otherPaths.length} other identical ${otherPaths.length === 1 ? 'copy' : 'copies'} of this skill, published for other agent runtimes and reported here once.`,
      metadata: { ...finding.metadata, copies: otherPaths.length + 1, otherPaths },
    };
  });
}

export function runSkillAudit(options = {}) {
  const skills = options.skills || collectSkillInventory(options);
  const findings = mergeRuntimeCopies(skills.flatMap(analyzeSkill));

  // The built-in pass above always runs, because it needs nothing but Node. The
  // deeper engine is opt-in: it is a separate Python install, so a scan cannot
  // depend on it being there.
  if (options.skillspector) findings.push(...runSkillSpectorAudit({ ...options, skills }));

  if (skills.length) {
    const byScope = {};
    for (const skill of skills) byScope[skill.scope] = (byScope[skill.scope] || 0) + 1;
    findings.push(createFinding({
      id: 'skill-inventory',
      category: 'skill-risk',
      severity: 'info',
      confidence: 'high',
      title: 'Agent skills were discovered',
      description: `Detected ${skills.length} agent skills (${Object.entries(byScope).map(([scope, count]) => `${count} ${scope}`).join(', ')}). Each one is instructions an agent will follow.${skills.truncated ? ` Discovery stopped at ${skills.length}; skills beyond that were not read. Point --skill-path= at a directory to audit it on its own.` : ''}`,
      recommendation: 'Review skills the way you review code an agent can run, especially any you did not write yourself.',
      metadata: {
        total: skills.length,
        truncated: Boolean(skills.truncated),
        byScope,
        // The dashboard lists every skill it read, so the inventory keeps them
        // all (a real machine has a few hundred) and marks the ones with findings.
        skills: skills.slice(0, 1500).map((skill) => ({
          name: skill.name,
          scope: skill.scope,
          root: skill.root,
          path: skill.dir,
          findings: findings.filter((finding) => finding.severity !== 'info' && finding.metadata?.skillPath === skill.dir).length,
        })),
      },
    }));
  }

  return findings;
}
