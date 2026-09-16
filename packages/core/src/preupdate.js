import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { isValidNpmPackageName, jsonCommand } from './command.js';

function versionParts(version) {
  const cleaned = String(version || '0').match(/\d+/g) || ['0'];
  return cleaned.map((v) => Number(v));
}

function changeType(current, latest) {
  const [cMaj = 0, cMin = 0, cPatch = 0] = versionParts(current);
  const [lMaj = 0, lMin = 0, lPatch = 0] = versionParts(latest);
  if (lMaj !== cMaj) return 'major';
  if (lMin !== cMin) return 'minor';
  if (lPatch !== cPatch) return 'patch';
  return 'none';
}

function criticalPathForPackage(name) {
  return /(openclaw|claude|codex|cursor|mcp|figma|playwright|puppeteer|npm)/i.test(name);
}

function getGlobalPackageInfo(name) {
  const installed = jsonCommand('npm', ['ls', '-g', name, '--json', '--depth=0']) || {};
  const dependencies = installed.dependencies || {};
  if (!dependencies[name]) return null;
  const outdated = jsonCommand('npm', ['outdated', '-g', '--json']) || {};
  const latest = outdated[name]?.latest || dependencies[name].version;
  return {
    package: name,
    current: dependencies[name].version,
    latest,
    changeType: changeType(dependencies[name].version, latest),
    direct: true,
    global: true,
    criticalPath: criticalPathForPackage(name)
  };
}

function readManifest(projectPath) {
  try {
    return JSON.parse(readFileSync(join(projectPath, 'package.json'), 'utf8'));
  } catch {
    return {};
  }
}

function getLocalPackageInfo(projectPath, name) {
  const installed = jsonCommand('npm', ['ls', name, '--json'], projectPath) || {};
  const all = installed.dependencies || {};
  if (!all[name]) return null;
  const manifest = readManifest(projectPath);
  const direct = Boolean(manifest.dependencies?.[name] || manifest.devDependencies?.[name]);
  const outdated = jsonCommand('npm', ['outdated', '--json'], projectPath) || {};
  const latest = outdated[name]?.latest || all[name].version;
  return {
    package: name,
    current: all[name].version,
    latest,
    changeType: changeType(all[name].version, latest),
    direct,
    global: false,
    criticalPath: criticalPathForPackage(name)
  };
}

function getAdvisoryInfo(projectPath, name) {
  const audit = jsonCommand('npm', ['audit', '--json'], projectPath);
  const vuln = audit?.vulnerabilities?.[name];
  if (!vuln) return { hasAdvisory: false };
  return {
    hasAdvisory: true,
    severity: vuln.severity,
    direct: !!vuln.isDirect,
    fixAvailable: vuln.fixAvailable
  };
}

function verdictFor(info, advisory) {
  if (advisory.hasAdvisory && (advisory.severity === 'critical' || advisory.severity === 'high') && (info.criticalPath || info.direct)) return 'hold';
  if (advisory.hasAdvisory) return 'caution';
  if (info.changeType === 'major') return 'caution';
  if (info.changeType === 'minor' && info.criticalPath) return 'caution';
  return 'safe';
}

function whyLines(info, advisory) {
  const lines = [];
  lines.push(info.criticalPath ? 'affects a critical execution path' : 'package is outside the main execution/control path');
  lines.push(info.direct ? 'direct dependency impact is clearer and more immediate' : 'dependency impact is transitive or indirect');
  if (advisory.hasAdvisory) lines.push(`known advisory present (${advisory.severity})`);
  else lines.push('no known advisory found in current npm audit data');
  lines.push(`update type is ${info.changeType}`);
  return lines;
}

function recommendation(info, advisory, verdict) {
  if (verdict === 'hold') return 'Hold this update until you review the advisory and test the fix path in isolation.';
  if (verdict === 'caution' && advisory.hasAdvisory) return 'Review the advisory details first, then test the update in isolation before rolling it into regular use.';
  if (verdict === 'caution' && info.criticalPath) return 'Test this update in an isolated profile before changing your daily agent toolchain.';
  if (verdict === 'caution') return 'Review changelog and update in a controlled window rather than casually.';
  return 'This looks like a routine update; it is reasonable to batch it with normal maintenance.';
}

export function preupdatePackage({ name, global = false, projectPath = process.cwd() }) {
  if (!isValidNpmPackageName(name)) {
    return { found: false, package: name, scope: global ? 'global' : projectPath, error: 'invalid-package-name' };
  }
  const info = global ? getGlobalPackageInfo(name) : getLocalPackageInfo(projectPath, name);
  if (!info) {
    return { found: false, package: name, scope: global ? 'global' : projectPath };
  }
  const advisory = global ? { hasAdvisory: false } : getAdvisoryInfo(projectPath, name);
  const verdict = verdictFor(info, advisory);
  return {
    found: true,
    package: name,
    current: info.current,
    latest: info.latest,
    changeType: info.changeType,
    executionPath: info.criticalPath ? 'critical' : 'non-critical',
    dependencyType: info.direct ? 'direct' : 'transitive',
    knownAdvisories: advisory.hasAdvisory ? advisory.severity : 'none',
    verdict,
    why: whyLines(info, advisory),
    recommendation: recommendation(info, advisory, verdict),
    scope: global ? 'global' : projectPath
  };
}

export function renderPreupdate(result) {
  if (!result.found) {
    const reason = result.error === 'invalid-package-name'
      ? 'That is not a valid npm package name. Drop any version specifier, quoting, or shell syntax.'
      : 'This package is not installed in the selected scope.';
    return [
      `Package: ${result.package}`,
      `Scope: ${result.scope}`,
      'Found: no',
      '',
      reason,
    ].join('\n');
  }

  return [
    `Package: ${result.package}`,
    `Scope: ${result.scope}`,
    `Current: ${result.current}`,
    `Latest: ${result.latest}`,
    `Change type: ${result.changeType}`,
    `Execution path: ${result.executionPath}`,
    `Dependency type: ${result.dependencyType}`,
    `Known advisories: ${result.knownAdvisories}`,
    '',
    `Verdict: ${result.verdict.toUpperCase()}`,
    '',
    'Why:',
    ...result.why.map((line) => `- ${line}`),
    '',
    'Recommendation:',
    `- ${result.recommendation}`,
    '',
    'Pre-update advice is npm-only and based on installed versions plus npm advisory data.',
    'It cannot prove that a release is safe.',
  ].join('\n');
}
