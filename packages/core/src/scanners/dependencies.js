import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createFinding } from '../schema.js';
import { jsonCommand } from '../command.js';
import { shortHash } from '../id.js';

function readJson(path) {
  try {
    return existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : null;
  } catch {
    return null;
  }
}

function directDependencySpecs(packageJson = {}) {
  return Object.entries({
    ...(packageJson.dependencies || {}),
    ...(packageJson.devDependencies || {}),
    ...(packageJson.optionalDependencies || {}),
  });
}

function remoteSourceType(spec) {
  const value = String(spec || '');
  if (/^(git\+|git:|github:|gitlab:|bitbucket:|ssh:)/i.test(value)) return 'Git source';
  if (/^https?:/i.test(value)) return 'remote archive';
  return null;
}

function packageNameFromLockPath(path) {
  const marker = 'node_modules/';
  const index = path.lastIndexOf(marker);
  return index === -1 ? null : path.slice(index + marker.length);
}

function signaturePackageLabel(entry) {
  if (typeof entry === 'string') return entry;
  if (!entry || typeof entry !== 'object') return 'an installed package';
  return entry.name && entry.version ? `${entry.name}@${entry.version}` : entry.name || entry.package || 'an installed package';
}

function recommendationForOutdated(info, criticalPath = false) {
  const currentMajor = String(info.current).split('.')[0];
  const latestMajor = String(info.latest).split('.')[0];
  const majorJump = currentMajor !== latestMajor;
  if (criticalPath && majorJump) return 'Test this package update in isolation before upgrading globally.';
  if (criticalPath) return 'Schedule this update deliberately because the tool sits in an active agent workflow.';
  if (majorJump) return 'Review the changelog for breaking changes before updating.';
  return 'This looks like a routine update; batch it with other low-risk maintenance.';
}

function severityForOutdated(info, criticalPath = false) {
  const majorJump = String(info.current).split('.')[0] !== String(info.latest).split('.')[0];
  if (criticalPath && majorJump) return 'medium';
  if (criticalPath || majorJump) return 'low';
  return 'info';
}

function runPackageTrustAudit(target, command) {
  const findings = [];
  const packageJson = readJson(join(target, 'package.json')) || {};
  const lockfile = readJson(join(target, 'package-lock.json'));
  const directDependencies = new Map(directDependencySpecs(packageJson));

  for (const [name, spec] of directDependencies) {
    const sourceType = remoteSourceType(spec);
    if (!sourceType) continue;
    findings.push(createFinding({
      id: `dependency-external-source-${name}-${shortHash(target)}`,
      category: 'dependency-audit',
      severity: 'medium',
      confidence: 'high',
      title: `${name} is installed from a ${sourceType.toLowerCase()}`,
      description: `${name} is declared as ${spec}, so its contents are not pinned to a standard npm registry release.`,
      recommendation: 'Pin this dependency to an immutable commit or package version, review its source and release process, and keep a lockfile integrity record.',
      metadata: { package: name, spec, sourceType, target, advisoryType: 'external-source' },
    }));
  }

  for (const [lockPath, entry] of Object.entries(lockfile?.packages || {})) {
    const name = packageNameFromLockPath(lockPath);
    if (!name || !directDependencies.has(name)) continue;
    const resolved = String(entry?.resolved || '');
    if (resolved.startsWith('https://registry.npmjs.org/') && !entry?.integrity) {
      findings.push(createFinding({
        id: `dependency-missing-integrity-${name}-${shortHash(target)}`,
        category: 'dependency-audit',
        severity: 'medium',
        confidence: 'high',
        title: `${name} is missing a lockfile integrity hash`,
        description: `${name} resolves from the npm registry, but its direct lockfile entry has no integrity value to verify the downloaded artifact.`,
        recommendation: 'Regenerate the lockfile with a current npm CLI, inspect the resulting diff, and commit the integrity hash before installing this dependency again.',
        metadata: { package: name, target, advisoryType: 'missing-integrity' },
      }));
    }
  }

  const tree = command('npm', ['ls', '--all', '--json'], target) || {};
  for (const problem of tree.problems || []) {
    const invalid = /^invalid:/i.test(problem);
    findings.push(createFinding({
      id: `dependency-tree-${shortHash(`${target}:${problem}`)}`,
      category: 'dependency-audit',
      severity: invalid ? 'medium' : 'low',
      confidence: 'high',
      title: invalid ? 'Installed dependency does not satisfy its declared version' : 'Dependency tree has an unexpected package state',
      description: problem,
      recommendation: invalid ? 'Reinstall from the lockfile and investigate any manual edits or unexpected package replacement.' : 'Run npm ci or npm install after reviewing the package tree and lockfile changes.',
      metadata: { target, problem, advisoryType: 'tree-integrity' },
    }));
  }

  const signatures = command('npm', ['audit', 'signatures', '--json'], target) || {};
  for (const entry of signatures.invalid || []) {
    const label = signaturePackageLabel(entry);
    findings.push(createFinding({
      id: `dependency-invalid-signature-${shortHash(`${target}:${label}`)}`,
      category: 'dependency-audit',
      severity: 'high',
      confidence: 'high',
      title: `Registry signature verification failed for ${label}`,
      description: 'npm could not validate the registry signature or provenance data for this installed package.',
      recommendation: 'Stop relying on this installed copy, inspect the registry and lockfile source, then reinstall from a trusted registry after validating the package release.',
      metadata: { package: label, target, advisoryType: 'invalid-signature' },
    }));
  }
  for (const entry of signatures.missing || []) {
    const label = signaturePackageLabel(entry);
    findings.push(createFinding({
      id: `dependency-missing-signature-${shortHash(`${target}:${label}`)}`,
      category: 'dependency-audit',
      severity: 'medium',
      confidence: 'medium',
      title: `Registry signature is missing for ${label}`,
      description: 'The configured registry supports signatures, but npm could not find a signature or provenance record for this installed package.',
      recommendation: 'Treat this as a supply-chain review signal: verify the package source and version, prefer a signed release when available, and do not treat absence alone as proof of compromise.',
      metadata: { package: label, target, advisoryType: 'missing-signature' },
    }));
  }

  return findings;
}

export function runDependencyAudit(targets = [], options = {}) {
  const findings = [];
  const command = options.command || jsonCommand;
  const outdated = command('npm', ['outdated', '-g', '--json']) || {};
  const criticalPackages = ['openclaw', 'npm', 'claude', 'codex', 'figma-developer-mcp'];
  for (const [pkg, info] of Object.entries(outdated)) {
    const criticalPath = criticalPackages.includes(pkg);
    findings.push(createFinding({
      id: `dependency-outdated-${pkg}`,
      category: 'dependency-audit',
      severity: severityForOutdated(info, criticalPath),
      confidence: 'medium',
      title: `${pkg} is outdated`,
      description: `${pkg} is installed at ${info.current} and latest available is ${info.latest}.`,
      recommendation: recommendationForOutdated(info, criticalPath),
      metadata: { package: pkg, currentVersion: info.current, latestVersion: info.latest, criticalPath, advisoryType: 'outdated' }
    }));
  }

  const auditTargets = targets.length ? targets : [process.cwd()];
  for (const target of auditTargets) {
    const audit = command('npm', ['audit', '--json'], target);
    for (const [pkg, vuln] of Object.entries(audit?.vulnerabilities || {})) {
      const criticalPath = !!vuln.isDirect;
      const severity = vuln.severity === 'critical' ? 'critical' : vuln.severity === 'high' ? 'high' : vuln.severity === 'moderate' ? 'medium' : 'low';
      const recommendation = vuln.fixAvailable
        ? (criticalPath ? 'Apply the available fix soon because this vulnerable package is directly in the execution path.' : 'Apply the available fix after verifying the transitive dependency impact.')
        : (criticalPath ? 'This direct dependency needs manual review because npm audit has no automatic fix.' : 'Review the vulnerable transitive path and decide whether to patch, pin, or replace it.');
      findings.push(createFinding({
        id: `dependency-vuln-${pkg}-${shortHash(target)}`,
        category: 'dependency-audit',
        severity,
        confidence: 'high',
        title: `${pkg} has reported npm audit vulnerabilities`,
        description: `${pkg} is flagged by npm audit with ${vuln.severity} severity in ${target}.`,
        recommendation,
        metadata: { package: pkg, severity: vuln.severity, direct: vuln.isDirect, fixAvailable: vuln.fixAvailable, target }
      }));
    }
    findings.push(...runPackageTrustAudit(target, command));
  }

  return findings;
}
