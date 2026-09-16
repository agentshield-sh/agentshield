import test from 'node:test';
import assert from 'node:assert/strict';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runConfigRiskAudit } from '../src/scanners/config-risk.js';
import { runSkillAudit } from '../src/scanners/skills.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const fixtures = join(repoRoot, 'fixtures');

// These fixtures are what a new user is told to scan first. If they stop
// producing findings, the documented demo is broken.
test('the risky agent config fixture still demonstrates every config check', () => {
  const path = join(fixtures, 'risky-agent-home', 'config.toml');
  const findings = runConfigRiskAudit([path]).filter((finding) => finding.path === path);
  const titles = new Set(findings.map((finding) => finding.title));

  assert.ok(titles.has('Service is configured to listen on every network interface'));
  assert.ok(titles.has('A service surface is configured without authentication'));
  assert.ok(titles.has('An agent is configured to skip execution safeguards'));
  assert.ok(titles.has('A remote MCP server is configured'));
  assert.ok(findings.every((finding) => finding.recommendation.length > 0));
  assert.equal(new Set(findings.map((finding) => finding.id)).size, findings.length);
});

test('the risky skill fixture still demonstrates the skill-risk checks', () => {
  const path = join(fixtures, 'risky-skill');
  const findings = runSkillAudit({
    skillPaths: [path],
    workspaceDirs: [],
    scanKnownProjects: false,
    home: join(fixtures, 'absent-home'),
  }).filter((finding) => finding.severity !== 'info');
  const rules = new Set(findings.map((finding) => finding.id.replace(/-[0-9a-f]{10}$/, '')));

  assert.ok(rules.has('skill-remote-code-execution'));
  assert.ok(rules.has('skill-data-exfiltration'));
  assert.ok(rules.has('skill-instruction-override'));
  assert.ok(rules.has('skill-destructive-command'));
  assert.ok(rules.has('skill-unscoped-shell'));
  assert.ok(findings.every((finding) => finding.recommendation.length > 0));
  assert.equal(new Set(findings.map((finding) => finding.id)).size, findings.length);
});

test('the risky settings and MCP fixtures still demonstrate the structural config checks', () => {
  const settings = join(fixtures, 'risky-agent-settings', '.claude', 'settings.json');
  const mcp = join(fixtures, 'risky-mcp', 'mcp.json');
  const findings = runConfigRiskAudit([settings, mcp]).filter((finding) => finding.path === settings || finding.path === mcp);
  const rules = new Set(findings.map((finding) => finding.id.replace(/-[0-9a-f]{10}$/, '')));
  for (const expected of ['config-permission-mode', 'config-broad-allow', 'config-broad-directories', 'config-env-anthropic-base-url', 'config-helper-apikeyhelper', 'config-sandbox-escape', 'config-hook-auto-allow', 'config-hook-remote-code', 'config-hook-env-exfiltration', 'config-hook-http-plaintext', 'config-mcp-plaintext', 'config-mcp-url-credential', 'config-mcp-header-authorization', 'config-mcp-inline-shell', 'config-mcp-auto-approve', 'config-mcp-exfil-host', 'config-mcp-unpinned']) {
    assert.ok(rules.has(expected), `fixture should trigger ${expected}`);
  }
  assert.ok(findings.every((finding) => finding.recommendation.length > 0));
  assert.equal(new Set(findings.map((finding) => finding.id)).size, findings.length);
  assert.ok(!JSON.stringify(findings).includes('demo_bearer_1234567890ABCDEFGHIJ'), 'fixture credentials are redacted');
});
