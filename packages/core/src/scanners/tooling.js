import { accessSync, constants, existsSync, readFileSync, readdirSync } from 'node:fs';
import { delimiter, join, resolve } from 'node:path';
import { homedir, tmpdir } from 'node:os';
import { createFinding } from '../schema.js';
import { shortHash } from '../id.js';
import { jsonCommand } from '../command.js';

// Resolving PATH directly avoids spawning a login shell per command. The old
// approach hardcoded /bin/zsh (absent on Linux) and interpolated the name into
// a shell string.
function commandExists(name) {
  const dirs = String(process.env.PATH || '').split(delimiter).filter(Boolean);
  const suffixes = process.platform === 'win32'
    ? String(process.env.PATHEXT || '.EXE;.CMD;.BAT').split(';')
    : [''];

  for (const dir of dirs) {
    for (const suffix of suffixes) {
      try {
        accessSync(join(dir, name + suffix), constants.X_OK);
        return true;
      } catch {
        // Not executable here; keep looking along PATH.
      }
    }
  }
  return false;
}

function npmListGlobalDetailed() {
  const parsed = jsonCommand('npm', ['ls', '-g', '--depth=0', '--json']) || {};
  return Object.entries(parsed.dependencies || {}).map(([name, info]) => ({
    name,
    version: info.version || 'unknown',
    location: info.path || null,
  }));
}

function isIgnoredProjectDir(dir) {
  const resolved = resolve(dir);
  const tmpRoot = resolve(tmpdir());
  return resolved === tmpRoot
    || resolved.startsWith(`${tmpRoot}/`)
    || resolved.startsWith('/private/var/folders/')
    || resolved.startsWith('/var/folders/');
}

function looksEphemeralProject(pkg, dir) {
  const fallbackName = dir.split('/').pop()?.toLowerCase() || '';
  const name = String(pkg.name || fallbackName).toLowerCase();
  return /^tmp([._-]|$)/.test(name) || /^temp([._-]|$)/.test(name);
}

function findPackageJsonDirs(startDirs, maxDepth = 2) {
  const seen = new Set();
  const results = [];
  // Build output (.next, .turbo, coverage) ships a package.json of its own and
  // is not a project anyone maintains. Hidden directories are skipped as a class.
  const ignoredDirs = new Set(['node_modules', 'dist', 'build', 'coverage', 'fixtures', 'test', 'tests', '__tests__']);

  function walk(dir, depth) {
    const resolvedDir = resolve(dir);
    if (depth > maxDepth || seen.has(resolvedDir) || !existsSync(resolvedDir) || isIgnoredProjectDir(resolvedDir)) return;
    seen.add(resolvedDir);
    let entries = [];
    try {
      entries = readdirSync(resolvedDir, { withFileTypes: true });
    } catch {
      return;
    }

    if (entries.some((entry) => entry.isFile() && entry.name === 'package.json')) {
      results.push(resolvedDir);
    }

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (ignoredDirs.has(entry.name) || entry.name.startsWith('.')) continue;
      walk(join(resolvedDir, entry.name), depth + 1);
    }
  }

  for (const dir of startDirs) walk(dir, 0);
  return results;
}

function detectNpxPackageUsage(projectDirs) {
  const found = new Set();
  for (const dir of projectDirs) {
    try {
      const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
      for (const script of Object.values(pkg.scripts || {})) {
        const matches = String(script).match(/\bnpx\s+([a-zA-Z0-9@/_-]+)/g) || [];
        for (const match of matches) {
          found.add(match.replace(/^\bnpx\s+/, '').trim());
        }
      }
    } catch {}
  }
  return [...found];
}

export function collectToolingInventory(options = {}) {
  const home = homedir();
  const workspaceDirs = options.workspaceDirs || [process.cwd()];
  const globalPackages = npmListGlobalDetailed();
  const projectDirs = findPackageJsonDirs(workspaceDirs, options.maxProjectDepth ?? 2);
  const localProjects = projectDirs.map((dir) => {
    try {
      const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
      if (looksEphemeralProject(pkg, dir)) return null;
      return {
        dir,
        name: pkg.name || dir.split('/').pop(),
        version: pkg.version || 'unknown',
        dependencies: Object.keys(pkg.dependencies || {}),
        devDependencies: Object.keys(pkg.devDependencies || {}),
      };
    } catch {
      return null;
    }
  }).filter(Boolean);

  const npxPackages = detectNpxPackageUsage(projectDirs);

  return {
    commands: {
      openclaw: commandExists('openclaw'),
      claude: commandExists('claude'),
      codex: commandExists('codex'),
      npm: commandExists('npm'),
      npx: commandExists('npx'),
    },
    globalPackages,
    localProjects,
    npxPackages,
    configPaths: [
      join(home, '.openclaw'),
      join(home, '.claude.json'),
      join(home, '.codex', 'config.toml'),
    ].filter(existsSync),
  };
}

export function runToolingDiscovery(options = {}) {
  const inventory = collectToolingInventory(options);
  const findings = [];

  const detectedCommands = Object.entries(inventory.commands).filter(([, present]) => present).map(([name]) => name);
  if (detectedCommands.length) {
    findings.push(createFinding({
      id: 'tooling-available-commands',
      category: 'tooling-discovery',
      severity: 'info',
      confidence: 'high',
      title: 'Local agent-related commands detected',
      description: `Detected ${detectedCommands.length} relevant commands available on this machine.`,
      recommendation: 'Keep these tools in regular inventory and dependency review.',
      metadata: { commands: detectedCommands },
    }));
  }

  for (const path of inventory.configPaths) {
    const pathKey = shortHash(path);
    findings.push(createFinding({
      id: `tooling-config-${pathKey}`,
      category: 'tooling-discovery',
      severity: 'info',
      confidence: 'high',
      title: 'Agent-related config path detected',
      description: 'A local agent-tool config path is present on this machine.',
      path,
      recommendation: 'Keep this path in regular scan coverage for secrets and risky settings.',
      metadata: { kind: 'config-path' },
    }));
  }

  if (inventory.globalPackages.length) {
    findings.push(createFinding({
      id: 'tooling-global-packages',
      category: 'tooling-discovery',
      severity: 'info',
      confidence: 'high',
      title: 'Global npm packages were discovered',
      description: `Detected ${inventory.globalPackages.length} globally installed npm packages.`,
      recommendation: 'Review globally installed tooling as part of dependency and update-risk audits.',
      metadata: { packages: inventory.globalPackages.slice(0, 50) },
    }));
  }

  if (inventory.localProjects.length) {
    findings.push(createFinding({
      id: 'tooling-local-projects',
      category: 'tooling-discovery',
      severity: 'info',
      confidence: 'medium',
      title: 'Local npm projects were discovered',
      description: `Detected ${inventory.localProjects.length} local project directories with package.json files.`,
      recommendation: 'Use local project discovery to expand dependency and secret scanning beyond global tooling.',
      metadata: { projects: inventory.localProjects.slice(0, 20) },
    }));
  }

  if (inventory.npxPackages.length) {
    findings.push(createFinding({
      id: 'tooling-npx-usage',
      category: 'tooling-discovery',
      severity: 'low',
      confidence: 'medium',
      title: 'npx-based tool usage detected in project scripts',
      description: `Detected ${inventory.npxPackages.length} packages referenced through npx in package scripts.`,
      recommendation: 'Review one-off npx tooling too, especially when it touches agent workflows or local secrets.',
      metadata: { packages: inventory.npxPackages },
    }));
  }

  return { inventory, findings };
}
