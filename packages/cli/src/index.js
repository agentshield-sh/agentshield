#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan, toJsonReport, toMarkdownReport, toTerminalReport, severities } from '../../core/src/index.js';
import { preupdatePackage, renderPreupdate } from '../../core/src/preupdate.js';
import { startDashboardServer } from '../../dashboard-server/src/index.js';

const CATEGORIES = ['secret-exposure', 'config-risk', 'skill-risk', 'network-exposure', 'dependency-audit', 'tooling-discovery'];

const HELP = `AgentShield — the security audit for your AI agents

Usage:
  agentshield scan [options]           Scan this machine and print a report
  agentshield preupdate <pkg> [opts]   Judge whether a package update is safe
  agentshield dashboard [options]      Serve the same results on localhost
  agentshield --version                Print the version
  agentshield --help                   Print this help

Scan options:
  --all                  Show every finding instead of the top priorities
  --json                 Print the machine-readable JSON report
  --format=md            Print a Markdown report
  --output=<file>        Write the report to a file instead of stdout
  --category=<name>      Limit to one category
  --severity=<level>     Limit to one severity
  --concise              Reduce each finding to its essential fields
  --secret-path=<path>   Also scan this path for exposed secrets
  --config-path=<path>   Also audit this config file for risky settings
  --skill-path=<path>    Also audit agent skills under this directory
  --audit-target=<path>  Also audit this npm project's dependencies

Deep skill analysis (optional, requires NVIDIA SkillSpector):
  --skillspector         Also analyse every discovered skill with SkillSpector
  --skillspector-llm     Add its LLM stage (needs a provider key; sends skill
                         content to that provider)
  --skillspector-bin=<p> Path to the skillspector executable
  --skillspector-limit=<n>  Skills to analyse deeply (default 40)

Preupdate options:
  --global               Check a globally installed package
  --path=<dir>           Check inside this project (default: current directory)
  --output=<file>        Write the advisor result to a file

Dashboard options:
  --port=<number>        Port to bind on 127.0.0.1 (default: 4173)

Categories:  ${CATEGORIES.slice(0, 5).join('  ')}
             ${CATEGORIES.slice(5).join('  ')}
Severities:  ${severities.join('  ')}

Exit codes:  0 nothing critical or high · 1 invalid usage · 2 critical or high
             findings present (for preupdate, 2 means the verdict is HOLD)

Examples:
  agentshield scan
  agentshield scan --category=secret-exposure --all
  agentshield scan --category=skill-risk --all
  agentshield scan --skillspector --category=skill-risk --all
  agentshield scan --format=md --output=agentshield-report.md
  agentshield preupdate --global npm
  agentshield dashboard --port=4180

AgentShield is an assessment tool. It reports known exposure patterns; it does
not block attacks and does not replace a firewall, antivirus, or EDR.`;

// Every flag each command accepts. A misspelt flag must fail loudly: a scan
// that silently ignores --severity=hgih and prints LOOKS CLEAR is worse than
// no scan at all.
const FLAGS = {
  scan: {
    bare: ['--all', '--json', '--concise', '--skillspector', '--skillspector-llm'],
    valued: ['--format', '--output', '--category', '--severity', '--secret-path', '--config-path', '--skill-path', '--audit-target', '--skillspector-bin', '--skillspector-limit'],
  },
  preupdate: { bare: ['--global'], valued: ['--path', '--output'] },
  dashboard: { bare: [], valued: ['--port'] },
};

class UsageError extends Error {}

// Nearest known flag by edit distance, for "did you mean" on a typo.
function closest(input, candidates) {
  const distance = (a, b) => {
    const row = Array.from({ length: b.length + 1 }, (_, index) => index);
    for (let i = 1; i <= a.length; i += 1) {
      let previous = row[0];
      row[0] = i;
      for (let j = 1; j <= b.length; j += 1) {
        const current = row[j];
        row[j] = Math.min(row[j] + 1, row[j - 1] + 1, previous + (a[i - 1] === b[j - 1] ? 0 : 1));
        previous = current;
      }
    }
    return row[b.length];
  };
  let best = null;
  for (const candidate of candidates) {
    const score = distance(input, candidate);
    if (score <= 3 && (!best || score < best.score)) best = { candidate, score };
  }
  return best?.candidate ?? null;
}

function readVersion() {
  if (typeof __AGENTSHIELD_VERSION__ === 'string') return __AGENTSHIELD_VERSION__;
  const here = dirname(fileURLToPath(import.meta.url));
  try {
    return JSON.parse(readFileSync(resolve(here, '../../../package.json'), 'utf8')).version;
  } catch {
    return 'unknown';
  }
}

function validateFlags(command, args) {
  const { bare, valued } = FLAGS[command];
  for (const arg of args) {
    if (!arg.startsWith('--')) continue;
    const name = arg.includes('=') ? arg.slice(0, arg.indexOf('=')) : arg;
    if (bare.includes(name)) {
      if (arg.includes('=')) throw new UsageError(`${name} does not take a value.`);
      continue;
    }
    if (valued.includes(name)) {
      if (!arg.includes('=') || arg.endsWith('=')) throw new UsageError(`${name} needs a value, for example ${name}=<value>.`);
      continue;
    }
    const suggestion = closest(name, [...bare, ...valued]);
    throw new UsageError(`Unknown option ${name} for "agentshield ${command}".${suggestion ? ` Did you mean ${suggestion}?` : ''} Run agentshield --help for the list.`);
  }
}

function flagValue(args, prefix) {
  const match = args.find((arg) => arg.startsWith(prefix));
  return match ? match.slice(prefix.length) : null;
}

function collectPaths(args, prefix) {
  return args.filter((arg) => arg.startsWith(prefix)).map((arg) => resolve(arg.slice(prefix.length)));
}

function oneOf(value, allowed, label) {
  if (value === null || allowed.includes(value)) return value;
  throw new UsageError(`Unknown ${label} "${value}". Choose one of: ${allowed.join(', ')}.`);
}

function filterFindings(result, args) {
  const category = oneOf(flagValue(args, '--category='), CATEGORIES, 'category');
  const severity = oneOf(flagValue(args, '--severity='), severities, 'severity');
  let findings = result.findings;
  if (category) findings = findings.filter((finding) => finding.category === category);
  if (severity) findings = findings.filter((finding) => finding.severity === severity);

  // The summary has to describe the findings actually being shown, not the
  // unfiltered scan, and the report has to say that a filter is in effect.
  const severityCounts = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const finding of findings) severityCounts[finding.severity] += 1;

  const filters = category || severity ? { category, severity } : null;
  const filtered = { ...result, filters, summary: { ...result.summary, findings: findings.length, severityCounts }, findings };
  if (!args.includes('--concise')) return filtered;

  return {
    ...filtered,
    findings: findings.map(({ id, severity: level, category: group, title, path, recommendation }) => ({
      id, severity: level, category: group, title, path, recommendation,
    })),
  };
}

// A scan that surfaces urgent findings should fail a pipeline it runs in.
function exitCodeFor(result) {
  const { critical, high } = result.summary.severityCounts;
  return critical + high > 0 ? 2 : 0;
}

function emit(report, outputPath) {
  if (!outputPath) {
    console.log(report);
    return;
  }
  writeFileSync(outputPath, report, 'utf8');
  console.log(`Report written to ${outputPath}`);
}

async function runScanCommand(args) {
  validateFlags('scan', args);
  const outputPath = flagValue(args, '--output=');
  const format = oneOf(flagValue(args, '--format='), ['md', 'markdown', 'json', 'terminal', 'text'], 'format');
  const limit = flagValue(args, '--skillspector-limit=');
  if (limit !== null && !(Number(limit) > 0)) throw new UsageError('--skillspector-limit needs a positive number.');

  const scanned = runScan({
    secretPaths: collectPaths(args, '--secret-path='),
    configPaths: collectPaths(args, '--config-path='),
    auditTargets: collectPaths(args, '--audit-target='),
    skillPaths: collectPaths(args, '--skill-path='),
    // --skillspector-llm implies the engine, so the flag reads the way it is
    // meant to: one flag, one decision.
    skillspector: args.includes('--skillspector') || args.includes('--skillspector-llm'),
    skillspectorLlm: args.includes('--skillspector-llm'),
    skillspectorBin: flagValue(args, '--skillspector-bin=') ?? undefined,
    skillspectorLimit: limit ?? undefined,
  });

  const result = filterFindings(scanned, args);

  const wantsJson = args.includes('--json') || format === 'json' || outputPath?.endsWith('.json');
  const wantsMarkdown = format === 'md' || format === 'markdown' || outputPath?.endsWith('.md');

  let report;
  if (wantsMarkdown) report = toMarkdownReport(result);
  else if (wantsJson) report = toJsonReport(result);
  // A file must never receive ANSI colour codes, whatever the terminal supports.
  else report = toTerminalReport(result, { all: args.includes('--all'), color: outputPath ? false : undefined });

  emit(report, outputPath);
  process.exitCode = exitCodeFor(result);
}

function runPreupdateCommand(args) {
  validateFlags('preupdate', args);
  const names = args.filter((arg) => !arg.startsWith('--'));
  if (!names.length) throw new UsageError('Provide a package name, for example: agentshield preupdate --global npm');
  if (names.length > 1) throw new UsageError(`preupdate checks one package at a time; got ${names.length}: ${names.join(', ')}`);

  const pathArg = flagValue(args, '--path=');
  const result = preupdatePackage({
    name: names[0],
    global: args.includes('--global'),
    projectPath: pathArg ? resolve(pathArg) : process.cwd(),
  });

  emit(renderPreupdate(result), flagValue(args, '--output='));
  if (!result.found) process.exitCode = 1;
  else if (result.verdict === 'hold') process.exitCode = 2;
}

async function runDashboardCommand(args) {
  validateFlags('dashboard', args);
  const raw = flagValue(args, '--port=') ?? process.env.AGENTSHIELD_PORT ?? '4173';
  const port = Number(raw);
  if (!/^\d+$/.test(String(raw).trim()) || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new UsageError(`Invalid port "${raw}". Use a number between 1 and 65535.`);
  }

  try {
    await startDashboardServer({ port });
  } catch (error) {
    if (error?.code === 'EADDRINUSE') {
      throw new UsageError(`Port ${port} is already in use. Try: agentshield dashboard --port=${port + 1}`);
    }
    if (error?.code === 'EACCES') {
      throw new UsageError(`Not allowed to bind port ${port}. Choose a port above 1024.`);
    }
    throw error;
  }

  console.log(`AgentShield dashboard running at http://127.0.0.1:${port}`);
  console.log('It binds to 127.0.0.1 only and re-scans on every page load.');
  console.log('Press Ctrl+C to stop.');
}

async function main() {
  const [command, ...args] = process.argv.slice(2);

  if (command === 'scan') return runScanCommand(args);
  if (command === 'preupdate') return runPreupdateCommand(args);
  if (command === 'dashboard') return runDashboardCommand(args);

  if (command === '--version' || command === '-v' || command === 'version') {
    console.log(readVersion());
    return;
  }

  if (!command || command === 'help' || command === '--help' || command === '-h') {
    console.log(HELP);
    return;
  }

  throw new UsageError(`Unknown command: ${command}\n\n${HELP}`);
}

main().catch((error) => {
  if (error instanceof UsageError) {
    console.error(error.message);
  } else {
    console.error(`AgentShield failed: ${error?.message ?? error}`);
  }
  process.exitCode = 1;
});
