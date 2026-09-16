import { summarizeFindings } from './schema.js';
import { runToolingDiscovery } from './scanners/tooling.js';
import { runSecretExposureScan } from './scanners/secrets.js';
import { runConfigRiskAudit } from './scanners/config-risk.js';
import { runDependencyAudit } from './scanners/dependencies.js';
import { runNetworkExposureScan } from './scanners/network.js';
import { runSkillAudit } from './scanners/skills.js';
import { toJsonReport } from './reporters/json.js';
import { toMarkdownReport } from './reporters/markdown.js';
import { toTerminalReport } from './reporters/terminal.js';

export function runScan(options = {}) {
  const tooling = runToolingDiscovery(options);
  const findings = [
    ...tooling.findings,
    ...runSecretExposureScan(options.secretPaths, options),
    ...runConfigRiskAudit(options.configPaths, options),
    ...runSkillAudit(options),
    ...runNetworkExposureScan(options),
    ...runDependencyAudit(options.auditTargets, options),
  ];

  return {
    product: 'AgentShield',
    scannedAt: new Date().toISOString(),
    scanRoot: (options.workspaceDirs || [process.cwd()])[0],
    summary: {
      status: 'ready',
      findings: findings.length,
      severityCounts: summarizeFindings(findings),
    },
    findings,
    inventory: tooling.inventory,
  };
}

export { toJsonReport, toMarkdownReport, toTerminalReport };
export { severities } from './schema.js';
