import test from 'node:test';
import assert from 'node:assert/strict';
import { shortenPath, supportsColor, toTerminalReport } from '../src/reporters/terminal.js';

function scanResult(findings) {
  const severityCounts = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const finding of findings) severityCounts[finding.severity] += 1;
  return {
    product: 'AgentShield',
    scannedAt: '2026-08-24T17:00:00.000Z',
    scanRoot: '/projects/app',
    summary: { status: 'ready', findings: findings.length, severityCounts },
    findings,
    inventory: { globalPackages: [], localProjects: [], npxPackages: [] },
  };
}

function finding(overrides) {
  return {
    id: 'x', category: 'config-risk', severity: 'medium', confidence: 'high',
    title: 'Something to review', description: 'Details.', path: null,
    recommendation: 'Do the thing.', metadata: {},
    ...overrides,
  };
}

const plain = { color: false, width: 80 };

test('an urgent finding drives the headline status', () => {
  const report = toTerminalReport(scanResult([finding({ severity: 'critical' })]), plain);
  assert.match(report, /AT RISK/);
  assert.match(report, /1 critical or high finding needs attention now\./);
});

test('a clean scan says so plainly instead of showing an empty table', () => {
  const report = toTerminalReport(scanResult([finding({ severity: 'info' })]), plain);
  assert.match(report, /LOOKS CLEAR/);
  assert.match(report, /No secrets, exposed services, risky settings, risky skills, or package advisories/);
});

test('findings are ordered by severity and informational records stay out', () => {
  const report = toTerminalReport(scanResult([
    finding({ severity: 'low', title: 'Low item' }),
    finding({ severity: 'info', title: 'Informational note' }),
    finding({ severity: 'high', title: 'High item' }),
  ]), plain);

  assert.ok(report.indexOf('High item') < report.indexOf('Low item'));
  assert.ok(!report.includes('Informational note'));
});

test('the default view caps the list and points at --all', () => {
  const many = Array.from({ length: 12 }, (_, index) => finding({ id: `f${index}`, title: `Finding ${index}` }));
  const capped = toTerminalReport(scanResult(many), plain);
  assert.match(capped, /4 more findings\. Run with --all to see them\./);

  const full = toTerminalReport(scanResult(many), { ...plain, all: true });
  assert.ok(!full.includes('more findings.'));
  assert.match(full, /Finding 11/);
});

test('a home-relative path is shortened so output can be shared', () => {
  assert.equal(shortenPath('/Users/someone/.codex/config.toml', '/Users/someone'), '~/.codex/config.toml');
  assert.equal(shortenPath('/etc/hosts', '/Users/someone'), '/etc/hosts');
});

test('recommendations wrap without repeating the arrow marker', () => {
  const long = 'Rotate this credential, remove it from the file, and store it in a secret manager instead of a long-lived local file.';
  const report = toTerminalReport(scanResult([finding({ recommendation: long })]), plain);
  assert.equal(report.split('\n').filter((line) => line.includes('→')).length, 1);
});

test('every severity badge stays separated from the title', () => {
  // "CRITICAL" is exactly eight characters, so an eight-wide pad produced
  // "CRITICALminimist has reported...".
  for (const severity of ['critical', 'high', 'medium', 'low']) {
    const report = toTerminalReport(scanResult([finding({ severity, title: 'Readable title' })]), plain);
    assert.match(report, new RegExp(`${severity.toUpperCase()} +Readable title`));
  }
});

test('the global-package gap is stated without pretending it was covered', () => {
  const report = toTerminalReport(scanResult([]), plain);
  assert.match(report, /Not covered in this run/);
  assert.match(report, /Vulnerabilities in globally installed packages/);
  assert.doesNotMatch(report, /\bPro\b|agentshield login/);
});

test('the report never claims to be protection', () => {
  const report = toTerminalReport(scanResult([]), plain);
  assert.match(report, /Assessment only/);
  assert.match(report, /not a firewall, antivirus, or guarantee/);
});

test('colour follows NO_COLOR and FORCE_COLOR', () => {
  assert.equal(supportsColor({ isTTY: true }, { NO_COLOR: '1' }), false);
  assert.equal(supportsColor({ isTTY: false }, { FORCE_COLOR: '1' }), true);
  assert.equal(supportsColor({ isTTY: false }, {}), false);
  assert.equal(supportsColor({ isTTY: true }, { TERM: 'dumb' }), false);
  assert.equal(supportsColor({ isTTY: true }, {}), true);
});

import { relativeTime } from '../src/reporters/terminal.js';

test('relative time is human', () => {
  const now = Date.parse('2026-09-05T12:00:00Z');
  assert.equal(relativeTime('2026-09-05T11:59:50Z', now), 'moments ago');
  assert.equal(relativeTime('2026-09-05T11:15:00Z', now), '45 min ago');
  assert.equal(relativeTime('2026-09-05T03:00:00Z', now), '9 h ago');
  assert.equal(relativeTime('2026-09-04T11:00:00Z', now), 'yesterday');
  assert.equal(relativeTime('2026-08-30T12:00:00Z', now), '6 days ago');
  assert.equal(relativeTime('garbage', now), 'earlier');
});

test('a filtered view says which rows it is showing instead of calling the rest clear', () => {
  const result = { ...scanResult([finding({ severity: 'info', category: 'skill-risk' })]), filters: { category: 'skill-risk', severity: null } };
  const report = toTerminalReport(result, plain);
  assert.match(report, /Nothing actionable matched category skill-risk/);
  assert.match(report, /Secrets\s+not in this view/);
  assert.match(report, /Skills\s+clear/);
  assert.doesNotMatch(report, /Not covered in this run/);
  assert.doesNotMatch(report, /No secrets, exposed services/);
});

test('findings that share a title name the server, endpoint, or setting that differs', () => {
  const report = toTerminalReport(scanResult([
    finding({ id: 'a', title: 'A remote MCP server is configured', path: '/projects/app/.claude.json', metadata: { setting: 'mcpServers.linear.url', endpoint: 'https://mcp.linear.invalid/mcp' } }),
    finding({ id: 'b', title: 'A remote MCP server is configured', path: '/projects/app/.claude.json', metadata: { setting: 'mcpServers.notion.url', endpoint: 'https://mcp.notion.invalid/mcp' } }),
    finding({ id: 'c', title: 'An MCP server header contains a literal credential', metadata: { server: 'tickets', project: '/projects/app' } }),
  ]), plain);
  assert.match(report, /https:\/\/mcp\.linear\.invalid\/mcp/);
  assert.match(report, /https:\/\/mcp\.notion\.invalid\/mcp/);
  assert.match(report, /MCP server "tickets" in \/projects\/app/);
});
