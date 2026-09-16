import { isAbsolute, join } from 'node:path';
import { textCommand } from '../command.js';
import { createFinding, severities } from '../schema.js';
import { shortHash, slug } from '../id.js';

// SkillSpector is NVIDIA's open-source skill scanner: 71 detection
// patterns across 17 categories, plus Python AST, taint-tracking, and YARA
// passes, and live CVE lookups. AgentShield neither vendors it nor reimplements
// it. When the engine is installed on this machine, every skill discovery found
// is handed to it and its findings are reported beside AgentShield's own.
//
// The split of work is deliberate. AgentShield knows which skills a machine has
// actually loaded — personal, plugin, and per project — which is the half
// SkillSpector does not do: it answers "is this one skill safe?" about a target
// you point it at. The engine stays optional because it is a Python install,
// and the default scan has to keep working with nothing but Node.
//
// Upstream: https://github.com/NVIDIA/SkillSpector
// Contract: `skillspector scan <dir> --format json` — documented as stable, with
// exit code 1 meaning "scored above 50", not "failed".

const DEFAULT_BIN = 'skillspector';
const SKILL_FILE = 'SKILL.md';

const VERSION_TIMEOUT_MS = 10_000;
const STATIC_TIMEOUT_MS = 60_000;
const LLM_TIMEOUT_MS = 300_000;

// Each skill costs one Python process, so a machine with hundreds of skills
// would turn a seconds-long scan into a coffee break. The cap is generous
// enough for a normal machine and is reported when it truncates.
const DEFAULT_SKILL_LIMIT = 40;
const MAX_ISSUES_PER_SKILL = 30;
const EVIDENCE_LIMIT = 160;
const INSTALL_HINT = 'uv tool install git+https://github.com/NVIDIA/skillspector.git';

const SEVERITY_BY_LABEL = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  moderate: 'medium',
  low: 'low',
  info: 'info',
  informational: 'info',
};

// A rule reported with a severity this adapter has not seen before still has to
// land somewhere a reader will look, so it goes to the middle of the scale
// rather than being dropped or promoted to the top of the report.
const FALLBACK_SEVERITY = 'medium';

// Evidence quoted out of a skill can carry the very credential the engine
// flagged, and a finding is meant to be pasteable into a ticket.
const SECRET_SHAPES = /\b(sk-[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{12,}|github_pat_[A-Za-z0-9_]{12,}|AKIA[0-9A-Z]{12,}|xox[abpsr]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,})/g;

function redact(text) {
  return String(text).replace(SECRET_SHAPES, (match) => `${match.slice(0, 6)}...redacted`);
}

function clean(value) {
  const text = String(value ?? '').replace(/\s+/g, ' ').trim();
  return text || '';
}

function evidence(value, limit = EVIDENCE_LIMIT) {
  const text = clean(value);
  if (!text) return '';
  return redact(text.length > limit ? `${text.slice(0, limit)}...` : text);
}

function humanize(value) {
  const text = clean(String(value ?? '').replace(/[_-]+/g, ' '));
  if (!text) return '';
  const capped = text.length > 90 ? `${text.slice(0, 90)}...` : text;
  return capped.charAt(0).toUpperCase() + capped.slice(1);
}

function severityFor(value) {
  const label = clean(value).toLowerCase();
  const mapped = SEVERITY_BY_LABEL[label];
  if (mapped) return mapped;
  return severities.includes(label) ? label : FALLBACK_SEVERITY;
}

// SkillSpector reports confidence as a probability; AgentShield reports it as a
// band, because a reader deciding what to do tonight does not act differently
// on 0.88 than on 0.91.
function confidenceFor(value) {
  const score = Number(value);
  if (!Number.isFinite(score)) return 'medium';
  if (score >= 0.8) return 'high';
  if (score >= 0.5) return 'medium';
  return 'low';
}

// The engine prints occasional advisory lines to stdout ahead of its report, so
// the JSON is sliced out of the stream rather than parsed from all of it.
export function parseSkillSpectorReport(raw) {
  if (!raw) return null;
  const text = String(raw);
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start === -1 || end <= start) return null;
  try {
    const report = JSON.parse(text.slice(start, end + 1));
    return report && typeof report === 'object' ? report : null;
  } catch {
    return null;
  }
}

export function resolveSkillSpector(options = {}) {
  const bin = options.skillspectorBin || process.env.AGENTSHIELD_SKILLSPECTOR_BIN || DEFAULT_BIN;
  const banner = textCommand(bin, ['--version'], process.cwd(), { timeoutMs: VERSION_TIMEOUT_MS });
  if (!banner) return null;
  // A wrapper script is a legitimate way to reach the engine, so an
  // unrecognised banner is accepted with the version left unclaimed.
  const version = /skillspector\s+v?(\S+)/i.exec(banner);
  return { bin, version: version ? version[1] : 'unknown' };
}

function scanOneSkill(engine, dir, options) {
  const args = ['scan', dir, '--format', 'json'];
  if (!options.skillspectorLlm) args.push('--no-llm');
  const timeoutMs = options.skillspectorTimeoutMs
    ?? (options.skillspectorLlm ? LLM_TIMEOUT_MS : STATIC_TIMEOUT_MS);
  // Exit code 1 only means the skill scored above 50. The report is still on
  // stdout, and textCommand returns it either way.
  return parseSkillSpectorReport(textCommand(engine.bin, args, process.cwd(), { timeoutMs }));
}

function issuePath(skill, issue) {
  const file = clean(issue?.location?.file) || SKILL_FILE;
  return isAbsolute(file) ? file : join(skill.dir, file);
}

function normalizeIssue(skill, issue) {
  const path = issuePath(skill, issue);
  const line = Number(issue?.location?.start_line);
  const rule = clean(issue?.id) || 'unknown-rule';
  const name = humanize(issue?.pattern) || humanize(issue?.category) || rule;
  const explanation = clean(issue?.explanation) || clean(issue?.message)
    || `SkillSpector rule ${rule} matched this skill.`;
  const snippet = evidence(issue?.finding || issue?.code_snippet);
  const scope = clean(skill.scope);

  return createFinding({
    id: `skillspector-${slug(rule)}-${shortHash(`${skill.dir}:${path}:${Number.isFinite(line) ? line : 0}:${rule}`)}`,
    category: 'skill-risk',
    severity: severityFor(issue?.severity),
    confidence: confidenceFor(issue?.confidence),
    title: `SkillSpector: ${name}`,
    description: `In the ${scope ? `${scope} ` : ''}skill "${skill.name}": ${redact(explanation)}${snippet ? ` Evidence: ${snippet}` : ''}`,
    path,
    recommendation: clean(issue?.remediation)
      || 'Review this rule against the skill before an agent loads it again, then fix or remove the skill if the finding is real.',
    metadata: {
      engine: 'skillspector',
      rule,
      pattern: clean(issue?.pattern) || null,
      ruleCategory: clean(issue?.category) || null,
      skill: skill.name,
      scope: skill.scope,
      skillPath: skill.dir,
      line: Number.isFinite(line) ? line : null,
      reportedSeverity: clean(issue?.severity) || null,
      reportedConfidence: Number.isFinite(Number(issue?.confidence)) ? Number(issue.confidence) : null,
      tags: Array.isArray(issue?.tags) ? issue.tags.slice(0, 10).map(clean) : [],
    },
  });
}

function unavailableFinding(options) {
  const bin = options.skillspectorBin || process.env.AGENTSHIELD_SKILLSPECTOR_BIN || DEFAULT_BIN;
  return createFinding({
    id: 'skillspector-unavailable',
    category: 'skill-risk',
    severity: 'info',
    confidence: 'high',
    title: 'Deep skill analysis was requested but SkillSpector is not installed',
    description: `AgentShield looked for the SkillSpector engine as "${bin}" and did not find a working one on PATH. The built-in skill checks still ran; the deeper pattern, AST, taint, and YARA analysis did not.`,
    recommendation: `Install the engine with: ${INSTALL_HINT} — or drop the flag to scan with the built-in skill checks alone.`,
    metadata: { engine: 'skillspector', bin, available: false },
  });
}

export function runSkillSpectorAudit(options = {}) {
  const skills = options.skills || [];
  if (!skills.length) return [];

  const engine = resolveSkillSpector(options);
  if (!engine) return [unavailableFinding(options)];

  const limit = Number(options.skillspectorLimit) > 0
    ? Math.floor(Number(options.skillspectorLimit))
    : DEFAULT_SKILL_LIMIT;
  const selected = skills.slice(0, limit);

  const findings = [];
  const scanned = [];
  const failed = [];

  for (const skill of selected) {
    let report = null;
    try {
      report = scanOneSkill(engine, skill.dir, options);
    } catch {
      report = null;
    }

    // A skill the engine could not read must not silently look clean, so it is
    // counted and reported rather than skipped.
    if (!report) {
      failed.push(skill.name);
      continue;
    }

    const assessment = report.risk_assessment || {};
    scanned.push({
      name: skill.name,
      scope: skill.scope,
      path: skill.dir,
      score: Number.isFinite(Number(assessment.score)) ? Number(assessment.score) : null,
      severity: clean(assessment.severity) || null,
      recommendation: clean(assessment.recommendation) || null,
    });

    const issues = Array.isArray(report.issues) ? report.issues.slice(0, MAX_ISSUES_PER_SKILL) : [];
    for (const issue of issues) findings.push(normalizeIssue(skill, issue));
  }

  const blocked = scanned.filter((entry) => entry.recommendation === 'DO_NOT_INSTALL');
  const skipped = skills.length - selected.length;
  const notes = [];
  if (skipped > 0) notes.push(`${skipped} further ${skipped === 1 ? 'skill was' : 'skills were'} left unscanned by the limit of ${limit}.`);
  if (failed.length) notes.push(`${failed.length} ${failed.length === 1 ? 'skill' : 'skills'} could not be analysed and ${failed.length === 1 ? 'was' : 'were'} not judged either way.`);

  findings.push(createFinding({
    id: 'skillspector-engine',
    category: 'skill-risk',
    severity: 'info',
    confidence: 'high',
    title: 'Deep skill analysis ran with SkillSpector',
    description: `NVIDIA SkillSpector ${engine.version} analysed ${scanned.length} of ${skills.length} discovered ${skills.length === 1 ? 'skill' : 'skills'} and reported ${findings.length} ${findings.length === 1 ? 'finding' : 'findings'}${blocked.length ? `, rating ${blocked.length} of them DO NOT INSTALL` : ''}.${notes.length ? ` ${notes.join(' ')}` : ''}`,
    recommendation: blocked.length
      ? `Start with the ${blocked.length === 1 ? 'skill' : 'skills'} the engine rates DO NOT INSTALL: ${blocked.slice(0, 5).map((entry) => entry.name).join(', ')}.`
      : 'No skill scored high enough for the engine to advise against it. The findings above are still worth reading.',
    metadata: {
      engine: 'skillspector',
      version: engine.version,
      mode: options.skillspectorLlm ? 'static+llm' : 'static',
      discovered: skills.length,
      analyzed: scanned.length,
      skipped,
      unreadable: failed.slice(0, 20),
      skills: scanned.slice(0, 60),
    },
  }));

  return findings;
}
