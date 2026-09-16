import { homedir } from 'node:os';

const SEVERITY_ORDER = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const SEVERITY_COLOR = { critical: 'red', high: 'red', medium: 'amber', low: 'green', info: 'muted' };

const ESC = String.fromCharCode(27);
const CODES = {
  reset: `${ESC}[0m`,
  bold: `${ESC}[1m`,
  dim: `${ESC}[2m`,
  red: `${ESC}[38;5;203m`,
  amber: `${ESC}[38;5;179m`,
  green: `${ESC}[38;5;150m`,
  muted: `${ESC}[38;5;245m`,
};

// Colour is opt-out via NO_COLOR and opt-in via FORCE_COLOR, matching the
// conventions other CLIs already taught users.
export function supportsColor(stream = process.stdout, env = process.env) {
  if (env.NO_COLOR) return false;
  if (env.FORCE_COLOR && env.FORCE_COLOR !== '0') return true;
  return Boolean(stream?.isTTY) && env.TERM !== 'dumb';
}

function painter(enabled) {
  return (value, ...styles) => {
    if (!enabled || !styles.length) return String(value);
    return styles.map((style) => CODES[style] ?? '').join('') + value + CODES.reset;
  };
}

// Shortening $HOME keeps output readable and keeps a username out of pasted
// terminal screenshots.
export function shortenPath(path, home = homedir()) {
  if (!path) return '';
  return home && path.startsWith(home) ? `~${path.slice(home.length)}` : path;
}

function wrap(text, width) {
  const words = String(text).split(/\s+/).filter(Boolean);
  const lines = [];
  let line = '';
  for (const word of words) {
    if (line && line.length + 1 + word.length > width) {
      lines.push(line);
      line = word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  if (line) lines.push(line);
  return lines.length ? lines : [''];
}

export function formatTimestamp(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return `${date.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
}

function statusFor(counts) {
  const urgent = counts.critical + counts.high;
  if (urgent) {
    return {
      label: 'AT RISK',
      color: 'red',
      summary: `${urgent} critical or high ${urgent === 1 ? 'finding needs' : 'findings need'} attention now.`,
    };
  }
  if (counts.medium) {
    return {
      label: 'NEEDS REVIEW',
      color: 'amber',
      summary: `No critical or high risks. ${counts.medium} medium ${counts.medium === 1 ? 'finding is' : 'findings are'} worth checking.`,
    };
  }
  if (counts.low) {
    return {
      label: 'LOOKS CLEAR',
      color: 'green',
      summary: `${counts.low} low-risk ${counts.low === 1 ? 'item remains' : 'items remain'} for routine review.`,
    };
  }
  return { label: 'LOOKS CLEAR', color: 'green', summary: 'Nothing actionable was found in this scan.' };
}

const COVERAGE = [
  ['Secrets', 'secret-exposure'],
  ['Network', 'network-exposure'],
  ['Configuration', 'config-risk'],
  ['Skills', 'skill-risk'],
  ['Packages', 'dependency-audit'],
  ['Tooling', 'tooling-discovery'],
];

function coverageState(findings, category) {
  const actionable = findings.filter((finding) => finding.category === category && finding.severity !== 'info');
  if (!actionable.length) return { text: 'clear', color: 'green' };
  const worst = actionable.reduce(
    (current, finding) => (SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[current] ? finding.severity : current),
    'info',
  );
  return {
    text: `${actionable.length} to review`,
    color: SEVERITY_COLOR[worst] === 'red' ? 'red' : 'amber',
  };
}

export function relativeTime(iso, now = Date.now()) {
  const then = Date.parse(iso);
  if (!Number.isFinite(then)) return 'earlier';
  const minutes = Math.round((now - then) / 60000);
  if (minutes < 1) return 'moments ago';
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.round(hours / 24);
  return days === 1 ? 'yesterday' : `${days} days ago`;
}

function detailFor(finding) {
  const meta = finding.metadata ?? {};
  if (meta.server) return `MCP server "${meta.server}"${meta.project ? ` in ${meta.project}` : ''}`;
  if (meta.endpoint) return String(meta.endpoint);
  if (meta.package) return `${meta.package}${meta.version ? `@${meta.version}` : ''}`;
  if (meta.skill && meta.scope) return `skill "${meta.skill}" (${meta.scope})`;
  if (meta.setting && meta.setting !== 'sandbox') return String(meta.setting);
  return null;
}

function describeFilters(filters) {
  const parts = [];
  if (filters.category) parts.push(`category ${filters.category}`);
  if (filters.severity) parts.push(`severity ${filters.severity}`);
  return parts.join(' and ');
}

export function toTerminalReport(result, options = {}) {
  const color = painter(options.color ?? supportsColor());
  const width = Math.min(Math.max(options.width ?? process.stdout?.columns ?? 80, 60), 100);
  const counts = result.summary.severityCounts;
  const status = statusFor(counts);
  const showAll = Boolean(options.all);
  const indent = ' '.repeat(11);
  const filters = result.filters?.category || result.filters?.severity ? result.filters : null;

  const actionable = result.findings
    .filter((finding) => finding.severity !== 'info')
    .sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);

  const shown = showAll ? actionable : actionable.slice(0, 8);
  const lines = [];

  lines.push('');
  lines.push(`${color('AgentShield', 'bold')} ${color('· security audit', 'muted')}`);
  lines.push(color(`${shortenPath(result.scanRoot ?? process.cwd())} · ${formatTimestamp(result.scannedAt)}`, 'dim'));
  lines.push('');
  lines.push(`  ${color(status.label, 'bold', status.color)}`);
  lines.push(`  ${color(status.summary, 'muted')}`);
  lines.push('');
  lines.push(`  ${[
    color(`${counts.critical} critical`, counts.critical ? 'red' : 'dim'),
    color(`${counts.high} high`, counts.high ? 'red' : 'dim'),
    color(`${counts.medium} medium`, counts.medium ? 'amber' : 'dim'),
    color(`${counts.low} low`, counts.low ? 'green' : 'dim'),
    color(`${counts.info} info`, 'dim'),
  ].join('   ')}`);
  lines.push('');

  if (shown.length) {
    lines.push(color(showAll ? 'Findings' : 'Do this first', 'bold'));
    lines.push('');
    for (const finding of shown) {
      const badge = finding.severity.toUpperCase().padEnd(9);
      lines.push(`  ${color(badge, 'bold', SEVERITY_COLOR[finding.severity])}${finding.title}`);
      if (finding.path) lines.push(`${indent}${color(shortenPath(finding.path), 'dim')}`);
      // Several findings can share a title and a file (three remote MCP
      // servers in one config), so the thing that differs is named too.
      const detail = detailFor(finding);
      if (detail) lines.push(`${indent}${color(shortenPath(detail), 'dim')}`);
      const recommendation = wrap(finding.recommendation, width - indent.length - 2);
      recommendation.forEach((line, index) => {
        lines.push(`${indent}${color(index === 0 ? `→ ${line}` : `  ${line}`, 'muted')}`);
      });
      lines.push('');
    }
    if (actionable.length > shown.length) {
      lines.push(color(`  ${actionable.length - shown.length} more findings. Run with --all to see them.`, 'dim'));
      lines.push('');
    }
  } else if (filters) {
    lines.push(color(`  Nothing actionable matched ${describeFilters(filters)}.`, 'muted'));
    lines.push('');
  } else {
    lines.push(color('  No secrets, exposed services, risky settings, risky skills, or package advisories were found.', 'muted'));
    lines.push('');
  }

  lines.push(color('Coverage', 'bold'));
  if (filters) lines.push(color(`  Showing ${describeFilters(filters)}. Other rows were scanned but are not in this view.`, 'dim'));
  lines.push('');
  for (const [label, category] of COVERAGE) {
    if (filters?.category && filters.category !== category) {
      lines.push(`  ${label.padEnd(16)}${color('not in this view', 'dim')}`);
      continue;
    }
    const state = coverageState(result.findings, category);
    lines.push(`  ${label.padEnd(16)}${color(state.text, state.color)}`);
  }
  lines.push('');

  // npm audit resolves a project graph, so globally installed tools are only
  // checked for being outdated. The report says so rather than looking clean.
  if (filters?.category && filters.category !== 'dependency-audit') {
    // The package gap is not part of this view; skip the block and its spacer.
    lines.pop();
  } else {
    lines.push(color('Not covered in this run', 'bold'));
    lines.push('');
    lines.push(`  ${color('Vulnerabilities in globally installed packages.', 'muted')}`);
    lines.push(color('  Advisory data covers the project you scan from, not your global tooling;', 'dim'));
    lines.push(color('  those are checked for being outdated only.', 'dim'));
  }
  lines.push('');

  lines.push(color('Assessment only. This is a point-in-time check for known exposure patterns,', 'dim'));
  lines.push(color('not a firewall, antivirus, or guarantee that this machine is secure.', 'dim'));
  lines.push('');
  lines.push(`  ${color('agentshield dashboard', 'bold')}${color('    open the same results in a local dashboard', 'muted')}`);
  lines.push(`  ${color('agentshield scan --json', 'bold')}${color('  machine-readable output', 'muted')}`);
  lines.push('');

  return lines.join('\n');
}
