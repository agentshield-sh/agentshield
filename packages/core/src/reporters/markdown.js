export function toMarkdownReport(result, options = {}) {
  const lines = [];
  lines.push('# AgentShield Report');
  lines.push('');
  lines.push(`Generated: **${result.scannedAt}**  `);
  lines.push(`Status: **${result.summary.status}**  `);
  lines.push(`Findings: **${result.findings.length}**`);
  lines.push('');
  lines.push('## Posture Summary');
  lines.push('');
  for (const [severity, count] of Object.entries(result.summary.severityCounts)) {
    lines.push(`- **${severity}**: ${count}`);
  }
  if (options.preupdate) {
    lines.push('');
    lines.push('## Pre-update advisor (v1, npm-only)');
    lines.push('');
    lines.push(`- Package: **${options.preupdate.package}**`);
    lines.push(`- Current: **${options.preupdate.current ?? 'not installed'}**`);
    lines.push(`- Latest: **${options.preupdate.latest ?? 'n/a'}**`);
    lines.push(`- Change type: **${options.preupdate.changeType ?? 'n/a'}**`);
    lines.push(`- Verdict: **${String(options.preupdate.verdict || 'n/a').toUpperCase()}**`);
    lines.push(`- Recommendation: ${options.preupdate.recommendation || 'n/a'}`);
  }
  const grouped = new Map();
  for (const finding of result.findings) {
    if (!grouped.has(finding.category)) grouped.set(finding.category, []);
    grouped.get(finding.category).push(finding);
  }
  for (const [category, findings] of grouped.entries()) {
    lines.push('');
    lines.push(`## ${category}`);
    lines.push('');
    for (const finding of findings) {
      lines.push(`### ${finding.title}`);
      lines.push(`- Severity: **${finding.severity}**`);
      lines.push(`- Confidence: **${finding.confidence}**`);
      if (finding.path) lines.push(`- Path: \`${finding.path}\``);
      lines.push(`- Why it matters: ${finding.description}`);
      lines.push(`- What to do: ${finding.recommendation}`);
      lines.push('');
    }
  }
  return lines.join('\n');
}
