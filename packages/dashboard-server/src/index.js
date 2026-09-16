import { createServer } from 'node:http';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, dirname, relative } from 'node:path';
import { runScan } from '../../core/src/index.js';
import { formatTimestamp } from '../../core/src/reporters/terminal.js';
import { preupdatePackage } from '../../core/src/preupdate.js';
import { collectToolingInventory } from '../../core/src/scanners/tooling.js';

const severityOrder = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function badgeColor(severity) {
  return { info: '#737373', low: '#9fe870', medium: '#f1b545', high: '#ff6464', critical: '#ff4646', safe: '#9fe870', caution: '#f1b545', hold: '#ff6464' }[severity] ?? '#737373';
}

function groupByCategory(findings) {
  const map = new Map();
  for (const finding of findings) {
    if (!map.has(finding.category)) map.set(finding.category, []);
    map.get(finding.category).push(finding);
  }
  return map;
}

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

// A path inside the scanned project reads best relative to it. Anything else
// gets $HOME collapsed to ~, the way the terminal report does it: the dashboard
// is the surface people screenshot, and a username does not belong in one.
function displayPath(path, home = homedir()) {
  const rel = relative(process.cwd(), path);
  if (!rel) return '.';
  if (!rel.startsWith('..')) return rel;
  return home && path.startsWith(home) ? `~${path.slice(home.length)}` : path;
}

// Scanner descriptions quote absolute paths inline, so the rule that keeps a
// username out of the path column has to apply to the prose beside it too.
function displayText(value, home = homedir()) {
  const text = String(value ?? '');
  return home ? text.replaceAll(home, '~') : text;
}

// One finding can name every copy of a skill on the machine. Three paths say
// where to look; twenty push the rest of the report off the screen.
const PATHS_SHOWN = 3;

function pathSummary(paths) {
  const shown = paths.slice(0, PATHS_SHOWN).map((path) => escapeHtml(displayPath(path))).join(' · ');
  const rest = paths.length - PATHS_SHOWN;
  return rest > 0 ? `${shown} · + ${rest} more` : shown;
}

function getStatus(counts) {
  const urgent = counts.critical + counts.high;
  if (urgent > 0) {
    return {
      tone: 'risk',
      label: 'At risk',
      summary: `${urgent} critical or high ${urgent === 1 ? 'risk needs' : 'risks need'} attention now.`,
    };
  }
  if (counts.medium > 0) {
    return {
      tone: 'review',
      label: 'Needs review',
      summary: `No critical or high risks. ${counts.medium} medium ${counts.medium === 1 ? 'finding should' : 'findings should'} be checked.`,
    };
  }
  return {
    tone: 'good',
    label: 'No urgent risks found',
    summary: counts.low > 0 ? `${counts.low} low-risk ${counts.low === 1 ? 'item remains' : 'items remain'} for routine review.` : 'Nothing actionable was found in this scan.',
  };
}

function getActionItems(findings) {
  const items = new Map();
  const actionable = findings
    .filter((finding) => finding.severity !== 'info')
    .sort((a, b) => severityOrder[b.severity] - severityOrder[a.severity]);

  // Findings that share a severity and title collapse into one row that
  // keeps every path they were found at.
  for (const finding of actionable) {
    const key = `${finding.severity}:${finding.title}`;
    if (!items.has(key)) items.set(key, { ...finding, paths: [] });
    const item = items.get(key);
    if (finding.path && !item.paths.includes(finding.path)) item.paths.push(finding.path);
  }
  return Array.from(items.values()).slice(0, 5);
}

function coverageState(findings, category) {
  const matches = findings.filter((finding) => finding.category === category);
  const actionable = matches.filter((finding) => finding.severity !== 'info');
  if (!actionable.length) return { label: 'Clear', tone: 'good', count: 0 };
  const highest = actionable.reduce((current, finding) => severityOrder[finding.severity] > severityOrder[current] ? finding.severity : current, 'info');
  return {
    label: highest === 'critical' || highest === 'high' ? 'Act now' : 'Review',
    tone: highest === 'critical' || highest === 'high' ? 'risk' : 'review',
    count: actionable.length,
  };
}

function categoryLabel(category) {
  return {
    'secret-exposure': 'Exposed secrets',
    'network-exposure': 'Network exposure',
    'dependency-audit': 'Package risk',
    'config-risk': 'Risky configuration',
    'skill-risk': 'Risky agent skills',
    'tooling-discovery': 'Detected tools',
  }[category] ?? category.replaceAll('-', ' ');
}

// Scan roots can be widened with AGENTSHIELD_SCAN_DIRS, a path-separator
// delimited list. The defaults stay close to where the CLI was started.
function dashboardWorkspaceDirs() {
  const extra = String(process.env.AGENTSHIELD_SCAN_DIRS || '')
    .split(delimiter)
    .map((entry) => entry.trim())
    .filter(Boolean);

  return [...new Set([
    process.cwd(),
    dirname(process.cwd()),
    ...extra,
  ].filter(existsSync))];
}

function baseHeaders(contentType) {
  return {
    'content-type': contentType,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  };
}

function normalizedPackageName(value) {
  return String(value || '').trim().toLowerCase().replace(/\s+/g, '-');
}

export function findPackageChecks({ name, inventory, preupdate = preupdatePackage }) {
  const query = normalizedPackageName(name);
  const projects = inventory?.localProjects || [];
  const checks = [];
  const global = preupdate({ name: query, global: true });
  if (global.found || global.error) checks.push({ ...global, location: 'Global npm packages', kind: 'global' });

  for (const project of projects) {
    if (project.name === query) {
      checks.push({
        found: true,
        package: query,
        current: project.version || 'unknown',
        latest: 'not checked',
        changeType: 'project source',
        executionPath: 'project',
        dependencyType: 'project root',
        knownAdvisories: 'scan this project',
        verdict: 'local',
        recommendation: 'This is a detected local project, not an installed dependency. Run an AgentShield scan against this project to review its dependency tree.',
        scope: project.dir,
        location: project.name,
        kind: 'project',
      });
      continue;
    }
    const declared = project.dependencies?.includes(query) || project.devDependencies?.includes(query);
    if (!declared) continue;
    const local = preupdate({ name: query, projectPath: project.dir });
    if (local.found) checks.push({ ...local, location: project.name, kind: 'local' });
  }

  return { query, found: checks.some((check) => check.found), checks };
}

const SCOPE_LABELS = {
  explicit: ['Passed with --skill-path', 'Directories you asked the scan to read'],
  project: ['Project skills', '.claude/skills of this project and every project the agent has opened'],
  global: ['Personal skills', '~/.claude/skills and the other user-level skill folders'],
  plugin: ['Installed plugin skills', 'Third-party code installed from a marketplace or extension catalog'],
};
const SCOPE_ORDER = ['explicit', 'project', 'global', 'plugin'];

// One collapsed group per scope, and inside it one row per container: the
// plugin a skill shipped in, or the skills folder it lives in. Names are
// listed inline, flagged ones first, so three hundred plugin skills read as a
// dozen rows rather than a wall of paths.
// The container is derived from where the skill sits relative to the root it
// was found under, so any runtime's layout works: a plugin root groups by the
// plugin folder beneath it (marketplace/plugin/version when that is the shape,
// otherwise the first folder), and a plain skills root is one container.
function skillContainer(skill) {
  const path = String(skill.path).replace(/\\/g, '/');
  const root = String(skill.root || '').replace(/\\/g, '/').replace(/\/$/, '');
  const below = root && path.startsWith(`${root}/`) ? path.slice(root.length + 1).split('/') : null;
  const isVersion = (segment) => /^v?\d+(\.\d+)*([-+.][\w.]+)?$/.test(segment) || /^[0-9a-f]{7,40}$/.test(segment);
  const shortVersion = (segment) => (/^[0-9a-f]{40}$/.test(segment) ? segment.slice(0, 7) : segment);
  if (skill.scope === 'plugin' && below && below.length > 1) {
    // Installed plugins are usually <market>/<plugin>/<version>/…, sometimes
    // under a cache/ folder first. Take the version as the container boundary
    // when one is present; otherwise stop at the first skills/ folder.
    const start = below[0].toLowerCase() === 'cache' ? 1 : 0;
    const versionIndex = below.findIndex((segment, index) => index >= start + 1 && index <= start + 3 && isVersion(segment));
    if (versionIndex !== -1) {
      const container = below.slice(0, versionIndex + 1);
      const key = `${root}/${container.join('/')}`;
      const label = `${below[versionIndex - 1]} ${shortVersion(below[versionIndex])}`;
      const market = versionIndex - 2 >= start ? below[versionIndex - 2] : null;
      return { key, label, sub: market ? `from ${market}` : '' };
    }
    const skillsIndex = below.findIndex((segment) => segment.toLowerCase() === 'skills');
    const container = skillsIndex > 0 ? below.slice(0, skillsIndex) : below.slice(0, 1);
    return { key: `${root}/${container.join('/')}`, label: container.join(' / '), sub: '' };
  }
  const dir = root || path.split('/').slice(0, -1).join('/');
  return { key: dir, label: displayPath(dir), sub: '' };
}

function renderSkillGroups(skills, total) {
  const groups = new Map();
  for (const skill of skills) {
    const scope = SCOPE_ORDER.includes(skill.scope) ? skill.scope : 'global';
    if (!groups.has(scope)) groups.set(scope, new Map());
    const container = skillContainer(skill);
    const byContainer = groups.get(scope);
    if (!byContainer.has(container.key)) byContainer.set(container.key, { ...container, skills: [] });
    byContainer.get(container.key).skills.push(skill);
  }
  const unlisted = total - skills.length;
  const blocks = SCOPE_ORDER.filter((scope) => groups.has(scope)).map((scope) => {
    const [label, sub] = SCOPE_LABELS[scope];
    const containers = [...groups.get(scope).values()]
      .sort((a, b) => b.skills.filter((skill) => skill.findings > 0).length - a.skills.filter((skill) => skill.findings > 0).length || a.label.localeCompare(b.label));
    const count = containers.reduce((sum, container) => sum + container.skills.length, 0);
    const flagged = containers.reduce((sum, container) => sum + container.skills.filter((skill) => skill.findings > 0).length, 0);
    const summary = `${escapeHtml(label)} · ${count}${flagged ? ` <span class="state state-review">${flagged} with findings</span>` : ' <span class="state state-good">clear</span>'}`;
    const rows = containers.map((container) => {
      const items = container.skills.slice().sort((a, b) => (b.findings || 0) - (a.findings || 0) || a.name.localeCompare(b.name));
      const names = items.map((skill) => `<span class="skill-chip${skill.findings ? ' flagged' : ''}" title="${escapeHtml(displayPath(skill.path))}">${escapeHtml(skill.name)}${skill.findings ? ` <span class="badge" style="background:${badgeColor('medium')}">${skill.findings}</span>` : ''}</span>`).join('');
      return `<li class="skill-row"><span class="skill-name">${escapeHtml(container.label)}${container.sub ? `<span class="skill-sub">${escapeHtml(container.sub)} · ${items.length} ${items.length === 1 ? 'skill' : 'skills'}</span>` : `<span class="skill-sub">${items.length} ${items.length === 1 ? 'skill' : 'skills'}</span>`}</span><span class="skill-chips">${names}</span></li>`;
    }).join('');
    return `<details class="skill-group"${flagged ? ' open' : ''}><summary>${summary}</summary><div class="details-content"><p class="coverage-sub">${escapeHtml(sub)}. Hover a name for its path; a number marks findings in the evidence above.</p><ul class="skill-list">${rows}</ul></div></details>`;
  });
  return `<div class="skill-groups">${blocks.join('')}${unlisted > 0 ? `<p class="coverage-sub">${unlisted} more ${unlisted === 1 ? 'skill was' : 'skills were'} read but not listed here. The JSON report carries the full inventory.</p>` : ''}</div>`;
}

export function renderPage(result) {
  const counts = result.summary.severityCounts;
  const status = getStatus(counts);
  const actionItems = getActionItems(result.findings);
  const actionableFindings = result.findings.filter((finding) => finding.severity !== 'info');
  const informationalFindings = result.findings.filter((finding) => finding.severity === 'info');
  const grouped = groupByCategory(actionableFindings);
  const inventory = result.inventory || { globalPackages: [], localProjects: [], npxPackages: [] };
  const skillInventory = result.findings.find((finding) => finding.id === 'skill-inventory');
  const skillsRead = Number(skillInventory?.metadata?.total) || 0;
  const skillList = Array.isArray(skillInventory?.metadata?.skills) ? skillInventory.metadata.skills : [];
  const coverage = [
    ['Secrets', 'Keys and tokens', coverageState(result.findings, 'secret-exposure')],
    ['Network', 'Ports and LAN', coverageState(result.findings, 'network-exposure')],
    ['Configuration', 'Agents and tools', coverageState(result.findings, 'config-risk')],
    ['Skills', skillsRead ? `${skillsRead} ${skillsRead === 1 ? 'skill' : 'skills'} read` : 'None found', coverageState(result.findings, 'skill-risk')],
    ['Packages', 'Project scope only', coverageState(result.findings, 'dependency-audit')],
  ];

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>AgentShield Security Status</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#000;--surface:#090909;--surface-2:#0d0d0d;--border:#202020;--text:#f5f5f5;--muted:#858585;--green:#9fe870;--amber:#f1b545;--red:#ff6464}
html{max-width:100%;overflow-x:hidden}@media(prefers-reduced-motion:no-preference){html{scroll-behavior:smooth}}a:focus-visible,button:focus-visible,input:focus-visible,summary:focus-visible{outline:2px solid var(--green);outline-offset:2px}.field-label{display:block;color:var(--muted);font-size:12px;margin-bottom:8px}body{font-family:'SF Mono',SFMono-Regular,ui-monospace,Menlo,Consolas,monospace;background:var(--bg);color:var(--text);line-height:1.5;font-size:14px;max-width:100%;overflow-x:hidden}.wrap{width:min(1180px,100%);margin:0 auto;padding:28px 24px 56px}.topbar{display:flex;align-items:center;justify-content:space-between;gap:24px;border-bottom:1px solid var(--border);padding-bottom:16px}.brand{font-size:13px;font-weight:700;text-transform:uppercase}.nav{display:flex;gap:24px}.nav a,.text-link{color:var(--muted);text-decoration:none;font-size:11px;text-transform:uppercase;padding:10px 0;display:inline-block}.nav a:hover,.text-link:hover{color:var(--text)}.section{margin-top:64px}.eyebrow{color:var(--muted);font-size:11px;font-weight:700;text-transform:uppercase;margin-bottom:12px}.section-title{font-size:32px;line-height:1.12;font-weight:700;max-width:720px}.section-copy{color:var(--muted);font-size:13px;line-height:1.7;max-width:650px;margin-top:12px}.status{margin-top:28px;border:1px solid var(--border);display:grid;grid-template-columns:1.35fr .65fr;background:var(--surface)}.status-main{padding:44px}.status-label{font-size:clamp(42px,7vw,82px);line-height:.95;font-weight:800;letter-spacing:-.055em;max-width:780px}.status-summary{font-size:14px;line-height:1.65;color:#b5b5b5;margin-top:22px}.status-risk .status-label{color:var(--red)}.status-review .status-label{color:var(--amber)}.status-good .status-label{color:var(--green)}.status-side{display:grid;grid-template-columns:1fr 1fr;border-left:1px solid var(--border)}.status-stat{padding:26px;border-bottom:1px solid var(--border)}.status-stat:nth-child(odd){border-right:1px solid var(--border)}.status-stat:nth-last-child(-n+2){border-bottom:0}.stat-number{font-size:36px;font-weight:700;line-height:1}.stat-name{font-size:11px;color:var(--muted);text-transform:uppercase;margin-top:9px}.scan-meta{display:flex;align-items:center;justify-content:space-between;gap:20px;border:1px solid var(--border);border-top:0;padding:14px 18px;color:var(--muted);font-size:12px}.actions{display:flex;gap:10px}.button,button{display:inline-flex;align-items:center;justify-content:center;min-height:42px;border:1px solid var(--text);background:var(--text);color:#000;padding:0 16px;font:700 11px inherit;text-transform:uppercase;text-decoration:none;cursor:pointer}.button.secondary{background:transparent;color:var(--text);border-color:var(--border)}.button:hover,button:hover{opacity:.85}.action-list{margin-top:24px;border-top:1px solid var(--border)}.action{display:grid;grid-template-columns:110px minmax(0,1fr) minmax(260px,.75fr);gap:24px;padding:22px 0;border-bottom:1px solid var(--border);align-items:start}.badge{display:inline-block;width:max-content;padding:4px 8px;color:#000;font-size:11px;font-weight:800;text-transform:uppercase}.action-title{font-size:14px;font-weight:700}.action-path{color:var(--muted);font-size:12px;margin-top:6px;overflow-wrap:anywhere}.action-rec{color:#b5b5b5;font-size:12px;line-height:1.65}.empty{border:1px dashed var(--border);padding:24px;color:var(--muted);font-size:12px;text-align:center}.coverage{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:1px;background:var(--border);border:1px solid var(--border);margin-top:24px}.coverage-item{background:var(--surface);padding:22px}.coverage-head{display:flex;align-items:center;justify-content:space-between;gap:12px}.coverage-name{font-size:13px;font-weight:700}.coverage-sub{color:var(--muted);font-size:12px;margin-top:7px}.state{font-size:11px;font-weight:800;text-transform:uppercase}.state-good{color:var(--green)}.state-review{color:var(--amber)}.state-risk{color:var(--red)}.details-list{margin-top:24px}.finding-group{border-top:1px solid var(--border);padding-top:24px;margin-top:30px}.finding-group h3{font-size:12px;text-transform:uppercase;color:var(--muted);margin-bottom:12px}.finding{display:grid;grid-template-columns:90px minmax(0,1fr);gap:18px;padding:16px;background:var(--surface);border:1px solid var(--border);margin-bottom:8px}.finding-title{font-size:12px;font-weight:700}.finding-desc,.finding-rec{font-size:12px;line-height:1.6;color:var(--muted);margin-top:5px;overflow-wrap:anywhere}.finding-rec{color:#b7b7b7}.tool-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:24px}.panel{border:1px solid var(--border);background:var(--surface);padding:22px}.panel h3{font-size:12px;text-transform:uppercase;margin-bottom:16px}.pre-form{display:flex;gap:8px}.pre-form input{min-width:0;flex:1;background:#000;border:1px solid var(--border);color:var(--text);padding:0 12px;font:12px inherit}.verdict{font-size:28px;font-weight:800;margin-top:18px}.muted{color:var(--muted)}.pre-info{font-size:12px;color:var(--muted);margin-top:9px;line-height:1.6;overflow-wrap:anywhere}.recommendation{margin-top:14px;border-left:2px solid var(--amber);background:#151005;padding:12px;font-size:11px;line-height:1.6}.compact-list{display:grid;gap:8px}.compact-item{border-top:1px solid var(--border);padding-top:10px;font-size:12px}.compact-item:first-child{border-top:0;padding-top:0}.compact-item strong{display:block}.compact-item span{display:block;color:var(--muted);font-size:12px;margin-top:3px;overflow-wrap:anywhere}details{margin-top:12px;border:1px solid var(--border);background:#050505}summary{cursor:pointer;padding:14px 16px;font-size:11px;font-weight:700;list-style:none}summary::-webkit-details-marker{display:none}summary::after{content:'+';float:right;color:var(--muted)}details[open] summary::after{content:'-'}details .details-content{padding:0 16px 16px}.skill-groups{margin-top:24px}.skill-group{margin-top:8px}.skill-list{list-style:none;margin-top:12px;display:grid;gap:6px}.skill-row{display:grid;grid-template-columns:minmax(0,.35fr) minmax(0,1fr);gap:16px;padding:10px 0;border-top:1px solid var(--border);font-size:12px}.skill-row:first-child{border-top:0}.skill-name{font-weight:700;overflow-wrap:anywhere}.skill-sub{display:block;font-weight:400;color:var(--muted);margin-top:3px}.skill-chips{display:flex;flex-wrap:wrap;gap:6px;align-content:flex-start}.skill-chip{display:inline-block;padding:3px 8px;background:#151515;border:1px solid var(--border);color:#c8c8c8;cursor:default}.skill-chip.flagged{border-color:var(--amber);color:var(--amber)}.skill-chip .badge{font-size:10px;padding:1px 5px;margin-left:4px}@media(max-width:560px){.skill-row{grid-template-columns:1fr;gap:6px}}code{background:#151515;padding:1px 5px;font:inherit;color:var(--text)}.scan-meta strong{color:var(--text)}.notice{margin-top:48px;border-top:1px solid #49380b;padding-top:18px;color:var(--muted);font-size:12px;line-height:1.6}.notice strong{color:var(--amber)}
@media(max-width:850px){.status{grid-template-columns:1fr}.status-side{border-left:0;border-top:1px solid var(--border)}.coverage{grid-template-columns:1fr 1fr}.action{grid-template-columns:90px minmax(0,1fr)}.action-rec{grid-column:2}.tool-grid{grid-template-columns:1fr}}
@media(max-width:560px){.wrap{padding:18px 16px 38px}.topbar{align-items:flex-start}.nav{gap:14px;overflow-x:auto}.nav a{font-size:11px}.section{margin-top:44px}.status{margin-top:20px}.status-main{padding:26px 20px}.status-label{font-size:46px;line-height:1}.status-summary{font-size:12px;margin-top:17px}.status-stat{padding:18px 16px}.stat-number{font-size:29px}.scan-meta{display:grid;gap:12px}.actions{display:grid;grid-template-columns:1fr 1fr}.button{width:100%;padding:0 10px}.section-title{font-size:28px}.action{grid-template-columns:1fr;gap:10px;padding:18px 0}.action-rec{grid-column:auto}.coverage{grid-template-columns:1fr}.coverage-item{padding:18px}.finding{grid-template-columns:1fr;gap:10px}.tool-grid{grid-template-columns:1fr}.pre-form{display:grid;grid-template-columns:minmax(0,1fr) auto}.notice{margin-top:36px}}
.check-results{display:grid;gap:10px;margin-top:14px}.check-result{border-left:2px solid var(--border);background:#050505;padding:12px}.check-result.safe{border-color:var(--green)}.check-result.caution,.check-result.local{border-color:var(--amber)}.check-result.hold{border-color:var(--red)}.check-result-head{display:flex;justify-content:space-between;gap:12px;font-size:11px;font-weight:700}.check-result-meta{margin-top:6px;color:var(--muted);font-size:12px;line-height:1.6;overflow-wrap:anywhere}
</style>
</head>
<body>
<div class="wrap">
  <header class="topbar">
    <div class="brand">AgentShield</div>
    <nav class="nav"><a href="#status">Status</a><a href="#actions">Actions</a><a href="#details">Details</a><a href="#skills">Skills</a><a href="#tools">Tools</a><a href="#coverage">Coverage</a></nav>
  </header>

  <main>
    <section id="status">
      <div class="status status-${status.tone}">
        <div class="status-main">
          <div class="eyebrow">Your security status</div>
          <h1 class="status-label">${escapeHtml(status.label)}</h1>
          <p class="status-summary">${escapeHtml(status.summary)}</p>
        </div>
        <div class="status-side">
          <div class="status-stat"><div class="stat-number" style="color:${counts.critical ? 'var(--red)' : 'var(--text)'}">${counts.critical}</div><div class="stat-name">Critical</div></div>
          <div class="status-stat"><div class="stat-number" style="color:${counts.high ? 'var(--red)' : 'var(--text)'}">${counts.high}</div><div class="stat-name">High</div></div>
          <div class="status-stat"><div class="stat-number" style="color:${counts.medium ? 'var(--amber)' : 'var(--text)'}">${counts.medium}</div><div class="stat-name">Medium</div></div>
          <div class="status-stat"><div class="stat-number">${counts.low}</div><div class="stat-name">Low</div></div>
        </div>
      </div>
      <div class="scan-meta">
        <span>Last scan: ${escapeHtml(formatTimestamp(result.scannedAt))}</span>
        <div class="actions"><a class="button" id="scan-again" href="/?refresh=1">Scan again</a><a class="button secondary" href="#actions">Review issues</a></div>
      </div>
    </section>

    <section class="section" id="actions">
      <div class="eyebrow">Do this next</div>
      <h2 class="section-title">${actionItems.length ? 'Review these findings first.' : 'No immediate action required.'}</h2>
      <p class="section-copy">Only actionable findings are shown here. Inventory records and scanner notes are kept out of the way.</p>
      ${actionItems.length ? `<div class="action-list">${actionItems.map((finding) => `<article class="action"><span class="badge" style="background:${badgeColor(finding.severity)}">${escapeHtml(finding.severity)}</span><div><div class="action-title">${escapeHtml(finding.title)}</div>${finding.paths.length ? `<div class="action-path">${pathSummary(finding.paths)}</div>` : ''}</div><div class="action-rec">${escapeHtml(displayText(finding.recommendation))}</div></article>`).join('')}</div>` : '<div class="empty" style="margin-top:24px">Nothing critical, high, medium, or low was found.</div>'}
    </section>

    <section class="section">
      <div class="eyebrow">Scan coverage</div>
      <h2 class="section-title">Where AgentShield looked.</h2>
      <div class="coverage">${coverage.map(([name, sub, state]) => `<div class="coverage-item"><div class="coverage-head"><span class="coverage-name">${name}</span><span class="state state-${state.tone}">${state.count ? `${state.count} ` : ''}${state.label}</span></div><div class="coverage-sub">${sub}</div></div>`).join('')}</div>
    </section>

    <section class="section" id="details">
      <div class="eyebrow">Evidence</div>
      <h2 class="section-title">All actionable findings.</h2>
      <p class="section-copy">Use this section when you need the evidence behind the status above.</p>
      <div class="details-list">${grouped.size ? Array.from(grouped.entries()).map(([category, findings]) => `<div class="finding-group"><h3>${escapeHtml(categoryLabel(category))} · ${findings.length}</h3>${findings.map((finding) => `<article class="finding"><div><span class="badge" style="background:${badgeColor(finding.severity)}">${escapeHtml(finding.severity)}</span></div><div><div class="finding-title">${escapeHtml(finding.title)}</div><div class="finding-desc">${escapeHtml(displayText(finding.description))}</div>${finding.path ? `<div class="finding-desc">${escapeHtml(displayPath(finding.path))}</div>` : ''}<div class="finding-rec">Fix: ${escapeHtml(displayText(finding.recommendation))}</div></div></article>`).join('')}</div>`).join('') : '<div class="empty">No actionable findings.</div>'}</div>
    </section>

    ${skillsRead ? `<section class="section" id="skills">
      <div class="eyebrow">Skill inventory</div>
      <h2 class="section-title">${skillsRead} ${skillsRead === 1 ? 'skill' : 'skills'} an agent on this machine can load.</h2>
      <p class="section-copy">Each skill is instructions an agent will follow. Grouped by where it was found; the ones with findings are marked and appear in the evidence above.</p>
      ${renderSkillGroups(skillList, skillsRead)}
    </section>` : ''}

    <section class="section" id="tools">
      <div class="eyebrow">Optional tools</div>
      <h2 class="section-title">Package checks and scan inventory.</h2>
      <div class="tool-grid">
        <div class="panel">
          <h3>Check before updating npm packages</h3>
          <form id="package-check-form"><label class="field-label" for="package-name">npm package name</label><div class="pre-form"><input id="package-name" name="package" autocomplete="off" placeholder="e.g. npm or react"/><button type="submit">Check</button></div></form>
          <div id="package-check-result" class="pre-info" aria-live="polite">Searches global packages and the detected local projects without leaving this page.</div>
        </div>
        <div class="panel">
          <h3>What was detected</h3>
          <div class="compact-list"><div class="compact-item"><strong>${inventory.globalPackages.length} global npm packages</strong><span>${escapeHtml(inventory.globalPackages.map((pkg) => pkg.name).join(', ') || 'None detected')}</span></div><div class="compact-item"><strong>${inventory.localProjects.length} local projects</strong><span>${escapeHtml(inventory.localProjects.map((project) => project.name).join(', ') || 'None detected')}</span></div></div>
          <details><summary>${informationalFindings.length} scanner notes</summary><div class="details-content compact-list">${informationalFindings.map((finding) => `<div class="compact-item"><strong>${escapeHtml(finding.title)}</strong><span>${escapeHtml(finding.path ? displayPath(finding.path) : finding.description)}</span></div>`).join('') || '<span class="muted">No scanner notes.</span>'}</div></details>
        </div>
      </div>
    </section>
  </main>

  <section class="section" id="coverage">
    <div class="eyebrow">Not covered in this run</div>
    <h2 class="section-title">Global package vulnerabilities.</h2>
    <p class="section-copy">Advisory data covers the project this scan ran from, not the tools installed globally on this machine; those are checked for being outdated only.</p>
  </section>

  <div class="notice"><strong>Assessment only.</strong> This is a point-in-time check for known exposure patterns. AgentShield is not a firewall, antivirus, EDR, or guarantee of security.</div>
</div>
<script>
const form = document.getElementById('package-check-form');
const input = document.getElementById('package-name');
const output = document.getElementById('package-check-result');
const button = form.querySelector('button');
function node(tag, value, className) { const element = document.createElement(tag); if (className) element.className = className; element.textContent = value; return element; }
function renderChecks(payload) {
  output.replaceChildren();
  output.className = 'check-results';
  if (!payload.found) { output.className = 'pre-info'; output.textContent = payload.query ? 'Not found in global npm packages or the detected local projects.' : 'Enter an npm package name.'; return; }
  for (const check of payload.checks.filter((item) => item.found)) {
    const card = node('article', '', 'check-result ' + (check.verdict || ''));
    const head = node('div', '', 'check-result-head');
    head.append(node('span', check.location || check.scope || 'Detected package'));
    head.append(node('span', (check.verdict || 'local').toUpperCase()));
    card.append(head);
    card.append(node('div', check.package + ' · ' + (check.current || 'unknown') + ' → ' + (check.latest || 'not checked') + ' · ' + (check.changeType || 'detected'), 'check-result-meta'));
    card.append(node('div', 'Scope: ' + (check.scope || 'unknown') + ' · Advisories: ' + (check.knownAdvisories || 'not checked'), 'check-result-meta'));
    card.append(node('div', check.recommendation || 'Review this package before changing it.', 'recommendation'));
    output.append(card);
  }
}
document.getElementById('scan-again').addEventListener('click', (event) => {
  // A full re-scan takes a few seconds; say so instead of looking stuck.
  event.currentTarget.textContent = 'Scanning…';
  event.currentTarget.setAttribute('aria-busy', 'true');
});
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const name = input.value.trim();
  output.className = 'pre-info'; output.textContent = 'Checking detected package locations…'; button.disabled = true;
  try {
    const response = await fetch('/api/package-check?package=' + encodeURIComponent(name), { headers: { accept: 'application/json' } });
    if (!response.ok) throw new Error('Package check failed');
    renderChecks(await response.json());
  } catch { output.className = 'pre-info'; output.textContent = 'Package check failed. Try again or run agentshield preupdate from the project directory.'; }
  finally { button.disabled = false; }
});
</script>
</body>
</html>`;
}

export async function startDashboardServer({ port, host = '127.0.0.1' }) {
  const server = createServer(async (req, res) => {
    const url = new URL(req.url || '/', `http://${host}:${port}`);

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { allow: 'GET, HEAD', ...baseHeaders('text/plain; charset=utf-8') });
      res.end('Method not allowed\n');
      return;
    }

    if (url.pathname === '/api/package-check') {
      const inventory = collectToolingInventory({ workspaceDirs: dashboardWorkspaceDirs() });
      const check = findPackageChecks({ name: url.searchParams.get('package'), inventory });
      res.writeHead(200, baseHeaders('application/json; charset=utf-8'));
      res.end(JSON.stringify(check));
      return;
    }

    // Only the dashboard route runs a scan. Without this, every stray request
    // (a favicon probe, a mistyped path) triggered another full scan.
    if (url.pathname !== '/') {
      res.writeHead(404, baseHeaders('text/plain; charset=utf-8'));
      res.end('Not found\n');
      return;
    }

    // Same engine as the CLI, so the two cannot disagree.
    const result = runScan({ workspaceDirs: dashboardWorkspaceDirs() });
    res.writeHead(200, {
      ...baseHeaders('text/html; charset=utf-8'),
      'content-security-policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'",
      'cross-origin-resource-policy': 'same-origin',
      'referrer-policy': 'no-referrer',
    });
    res.end(renderPage(result));
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      resolve();
    });
  });
  return server;
}
