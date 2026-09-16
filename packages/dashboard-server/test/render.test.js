import test from 'node:test';
import assert from 'node:assert/strict';
import { get } from 'node:http';
import { homedir } from 'node:os';
import { findPackageChecks, renderPage, startDashboardServer } from '../src/index.js';

test('dashboard escapes scan data before rendering HTML', () => {
  const page = renderPage({
    scannedAt: '<script>alert(1)</script>',
    summary: {
      findings: 1,
      severityCounts: { info: 0, low: 0, medium: 0, high: 1, critical: 0 },
    },
    findings: [{
      category: 'config-risk',
      severity: 'high',
      title: '<img src=x onerror=alert(1)>',
      description: 'bad <script>alert(1)</script>',
      path: '/tmp/<secret>',
      recommendation: 'escape "quotes" too',
    }],
    inventory: {
      globalPackages: [{ name: '<pkg>', version: '1.0.0' }],
      localProjects: [],
      npxPackages: ['<npx>'],
    },
  }, 'npm" autofocus onfocus="alert(1)', {
    found: false,
    package: '',
  });

  assert.doesNotMatch(page, /<script>alert\(1\)<\/script>/);
  assert.doesNotMatch(page, /<img src=x onerror=alert\(1\)>/);
  assert.doesNotMatch(page, /value="npm" autofocus/);
  assert.match(page, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(page, /&quot;quotes&quot;/);
  assert.match(page, /At risk/);
  assert.match(page, /1 critical or high risk needs attention now/);
});

test('dashboard gives medium findings a clear review verdict', () => {
  const page = renderPage({
    scannedAt: '2026-07-02T12:00:00.000Z',
    summary: {
      findings: 1,
      severityCounts: { info: 0, low: 0, medium: 1, high: 0, critical: 0 },
    },
    findings: [{
      category: 'network-exposure',
      severity: 'medium',
      title: 'Dev server visible on LAN',
      description: 'A development service is reachable.',
      path: '0.0.0.0:3000',
      recommendation: 'Bind it to loopback.',
    }],
    inventory: { globalPackages: [], localProjects: [], npxPackages: [] },
  }, '', { package: '' });

  assert.match(page, /Needs review/);
  assert.match(page, /No critical or high risks\. 1 medium finding should be checked/);
  assert.match(page, /Review these findings first/);
});

test('package checker stays on the page and searches discovered local projects', () => {
  const calls = [];
  const preupdate = (input) => {
    calls.push(input);
    if (input.global) return { found: false, package: input.name, scope: 'global' };
    return {
      found: true,
      package: input.name,
      current: '16.2.9',
      latest: '16.3.0',
      changeType: 'minor',
      verdict: 'safe',
      knownAdvisories: 'none',
      scope: input.projectPath,
      recommendation: 'Routine update.',
    };
  };
  const inventory = {
    localProjects: [
      { name: 'agentshield-next', version: '0.1.0', dir: '/projects/landing', dependencies: ['next'], devDependencies: [] },
      { name: 'demo-agent', version: '1.2.3', dir: '/projects/demo-agent', dependencies: [], devDependencies: [] },
    ],
  };

  const next = findPackageChecks({ name: 'next', inventory, preupdate });
  assert.equal(next.found, true);
  assert.equal(next.checks[0].location, 'agentshield-next');
  assert.equal(next.checks[0].scope, '/projects/landing');
  assert.deepEqual(calls, [
    { name: 'next', global: true },
    { name: 'next', projectPath: '/projects/landing' },
  ]);

  const project = findPackageChecks({ name: 'demo agent', inventory, preupdate });
  assert.equal(project.query, 'demo-agent');
  assert.equal(project.found, true);
  assert.equal(project.checks[0].kind, 'project');
  assert.equal(project.checks[0].current, '1.2.3');

  const page = renderPage({
    scannedAt: '2026-08-02T10:00:00.000Z',
    summary: { severityCounts: { info: 0, low: 0, medium: 0, high: 0, critical: 0 } },
    findings: [],
    inventory: { globalPackages: [], localProjects: [], npxPackages: [] },
  });
  assert.match(page, /id="package-check-form"/);
  assert.match(page, /event\.preventDefault\(\)/);
  assert.match(page, /\/api\/package-check/);
  assert.doesNotMatch(page, /<form method="GET"/);
});

test('dashboard surfaces a critical dependency first with an at-risk verdict', () => {
  const page = renderPage({
    scannedAt: '2026-07-03T08:00:00.000Z',
    summary: {
      findings: 2,
      severityCounts: { info: 0, low: 1, medium: 0, high: 0, critical: 1 },
    },
    findings: [
      {
        category: 'dependency-audit',
        severity: 'low',
        title: 'Routine package update',
        description: 'A low-risk update is available.',
        path: null,
        recommendation: 'Update during routine maintenance.',
      },
      {
        category: 'dependency-audit',
        severity: 'critical',
        title: 'form-data has reported npm audit vulnerabilities',
        description: 'npm audit reported a critical direct dependency.',
        path: null,
        recommendation: 'Apply the available fix soon.',
      },
    ],
    inventory: { globalPackages: [], localProjects: [], npxPackages: [] },
  }, '', { package: '' });

  assert.match(page, /At risk/);
  assert.match(page, /1 critical or high risk needs attention now/);
  assert.ok(page.indexOf('form-data has reported') < page.indexOf('Routine package update'));
});

test('dashboard binds to loopback by default', async () => {
  const server = await startDashboardServer({ port: 0 });
  try {
    const address = server.address();
    assert.equal(address.address, '127.0.0.1');
    const response = await new Promise((resolve, reject) => {
      get(`http://127.0.0.1:${address.port}`, resolve).once('error', reject);
    });
    response.resume();
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.match(response.headers['content-security-policy'], /frame-ancestors 'none'/);
    assert.match(response.headers['content-security-policy'], /script-src 'unsafe-inline'/);
    assert.equal(response.headers['x-content-type-options'], 'nosniff');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('dashboard keeps the username out of paths and caps a long path list', () => {
  const home = homedir();
  const paths = Array.from({ length: 7 }, (_, index) => `${home}/.claude/skills/copy-${index}/SKILL.md`);
  const page = renderPage({
    scannedAt: '2026-09-03T00:00:00Z',
    summary: { findings: paths.length, severityCounts: { info: 0, low: 0, medium: 0, high: paths.length, critical: 0 } },
    findings: paths.map((path) => ({
      id: `skill-x-${path}`,
      category: 'skill-risk',
      severity: 'high',
      title: 'A skill hides instructions from human review',
      description: 'hidden content',
      path,
      recommendation: 'read the raw file',
      metadata: {},
    })),
    inventory: { globalPackages: [], localProjects: [], npxPackages: [] },
  }, '', { found: false, package: '' });

  const actionRow = /<div class="action-path">([\s\S]*?)<\/div>/.exec(page)?.[1] ?? '';

  assert.ok(page.includes('~/.claude/skills/copy-0/SKILL.md'));
  assert.ok(!page.includes(`${home}/.claude/skills/copy-0/SKILL.md`), 'the real home path must not survive into the page');
  assert.ok(actionRow.includes('+ 4 more'), 'the action row must cap the path list');
  assert.ok(!actionRow.includes('copy-3'), 'only the first three paths belong in the action row');
  // The evidence section below still carries every finding in full, so nothing
  // is hidden by the cap - it only keeps the priority list readable.
  assert.ok(page.includes('~/.claude/skills/copy-6/SKILL.md'));
});

test('an absolute path quoted inside a description is shortened too', () => {
  const home = homedir();
  const page = renderPage({
    scannedAt: '2026-09-03T00:00:00Z',
    summary: { findings: 1, severityCounts: { info: 0, low: 0, medium: 1, high: 0, critical: 0 } },
    findings: [{
      id: 'config-remote-trust-1',
      category: 'config-risk',
      severity: 'medium',
      title: 'A remote MCP server is configured',
      description: `projects.${home}/workspace.mcpServers.figma.url points at https://mcp.example.invalid`,
      path: `${home}/.claude.json`,
      recommendation: `Review ${home}/.claude.json and remove endpoints you no longer use.`,
      metadata: {},
    }],
    inventory: { globalPackages: [], localProjects: [], npxPackages: [] },
  }, '', { found: false, package: '' });

  assert.ok(page.includes('projects.~/workspace.mcpServers'));
  assert.ok(page.includes('Review ~/.claude.json'));
  assert.ok(!page.includes(home), 'no part of the page may carry the real home path');
});

const base = () => ({
  scannedAt: '2026-09-05T10:00:00.000Z',
  summary: { findings: 0, severityCounts: { info: 0, low: 0, medium: 0, high: 0, critical: 0 } },
  findings: [],
  inventory: { globalPackages: [], localProjects: [], npxPackages: [] },
});

test('the dashboard states the global-package gap without an upsell', () => {
  const page = renderPage(base());
  assert.match(page, /Not covered in this run/);
  assert.match(page, /Project scope only/);
  assert.doesNotMatch(page, /\bPro\b|agentshield login|Since last scan/);
});

test('the dashboard lists every skill it read, grouped by scope, with flagged ones marked and first', () => {
  const result = base();
  result.findings.push({
    id: 'skill-inventory', category: 'skill-risk', severity: 'info', confidence: 'high', title: 'Agent skills were discovered', description: 'd', path: null, recommendation: 'r',
    metadata: { total: 3, byScope: { global: 1, plugin: 2 }, skills: [
      { name: 'tidy', scope: 'global', root: '/home/u/.claude/skills', path: '/home/u/.claude/skills/tidy', findings: 0 },
      { name: 'safe-plugin', scope: 'plugin', root: '/home/u/.claude/plugins/cache', path: '/home/u/.claude/plugins/cache/m/p/1.0.0/skills/safe-plugin', findings: 0 },
      { name: 'deploy-helper', scope: 'plugin', root: '/home/u/.claude/plugins/cache', path: '/home/u/.claude/plugins/cache/m/p/1.0.0/skills/deploy-helper', findings: 2 },
    ] },
  });
  const page = renderPage(result);
  assert.match(page, /3 skills an agent on this machine can load/);
  assert.match(page, /Personal skills · 1 <span class="state state-good">clear<\/span>/);
  assert.match(page, /Installed plugin skills · 2 <span class="state state-review">1 with findings<\/span>/);
  assert.ok(page.indexOf('deploy-helper') < page.indexOf('safe-plugin'), 'flagged skills come first in their group');
  assert.match(page, /deploy-helper <span class="badge"[^>]*>2<\/span>/);
  assert.match(page, /p 1\.0\.0<span class="skill-sub">from m · 2 skills<\/span>/, 'plugin skills are grouped by the plugin that shipped them');
  assert.match(page, /title="~\/\.claude\/skills\/tidy"|title="\/home\/u\/\.claude\/skills\/tidy"/, 'each name carries its path');
  assert.match(page, /<details class="skill-group" open>/, 'a group with findings starts expanded');
  assert.match(page, /href="#skills"/);
  assert.doesNotMatch(renderPage(base()), /Skill inventory/, 'no skills, no section');
});

test('skill containers follow the root each skill was found under, whatever the runtime layout', () => {
  const result = base();
  result.findings.push({
    id: 'skill-inventory', category: 'skill-risk', severity: 'info', confidence: 'high', title: 'Agent skills were discovered', description: 'd', path: null, recommendation: 'r',
    metadata: { total: 4, byScope: { global: 1, plugin: 2, project: 1 }, skills: [
      { name: 'codex-helper', scope: 'global', root: '/home/u/.codex/skills', path: '/home/u/.codex/skills/codex-helper', findings: 0 },
      { name: 'cached', scope: 'plugin', root: '/home/u/.claude/plugins/cache', path: '/home/u/.claude/plugins/cache/market/pack/2.0.0/skills/cached', findings: 0 },
      { name: 'vendor', scope: 'plugin', root: '/home/u/.codex/plugins', path: '/home/u/.codex/plugins/vendor-pack/skills/vendor', findings: 0 },
      { name: 'deep', scope: 'plugin', root: '/home/u/.codex/plugins', path: '/home/u/.codex/plugins/cache/curated/figma/2.0.21/skills/deep', findings: 0 },
      { name: 'nested', scope: 'plugin', root: '/home/u/.claude/plugins/cache', path: '/home/u/.claude/plugins/cache/market/seo/2.2.0/extensions/ahrefs/skills/nested', findings: 0 },
      { name: 'sha', scope: 'plugin', root: '/home/u/.cursor/plugins', path: '/home/u/.cursor/plugins/cursor-public/figma/54ad156019d7362a56d8024b9adbe99952aa29b6/skills/sha', findings: 0 },
      { name: 'repo-skill', scope: 'project', root: '/work/app/skills', path: '/work/app/skills/repo-skill', findings: 1 },
    ] },
  });
  const page = renderPage(result);
  assert.match(page, /pack 2\.0\.0<span class="skill-sub">from market · 1 skill<\/span>/);
  assert.match(page, /vendor-pack<span class="skill-sub">1 skill<\/span>/);
  assert.match(page, /figma 2\.0\.21<span class="skill-sub">from curated · 1 skill<\/span>/, 'a version segment is found under a cache folder');
  assert.match(page, /seo 2\.2\.0<span class="skill-sub">from market · 1 skill<\/span>/, 'skills nested below the version still belong to the plugin');
  assert.match(page, /figma 54ad156<span class="skill-sub">from cursor-public · 1 skill<\/span>/, 'a commit sha version is shortened');
  assert.match(page, /\/home\/u\/\.codex\/skills<span class="skill-sub">1 skill<\/span>|~\/\.codex\/skills<span class="skill-sub">1 skill<\/span>/);
  assert.match(page, /Project skills · 1 <span class="state state-review">1 with findings<\/span>/);
});
