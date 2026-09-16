# AgentShield Command Reference

## Help

```bash
agentshield
agentshield --help
agentshield --version
```

Prints the command list, options, and examples. Every command rejects a flag it
does not know (with a suggestion when the typo is close), a `--category=` or
`--severity=` value outside the documented lists, and an out-of-range port, so a
misspelt option can never produce a silently clean report. Usage errors exit `1`.

## Scan

```bash
agentshield scan
```

Runs the local scanner and prints a readable report.

`scan` exits `0` when nothing critical or high was found and `2` when something
needs attention, so it can gate a script or CI job. Invalid usage exits `1`.

Supported options:

| Option | Example | Purpose |
| --- | --- | --- |
| `--all` | `agentshield scan --all` | Show every finding instead of the top eight |
| `--json` | `agentshield scan --json` | Print the machine-readable JSON report |
| `--concise` | `agentshield scan --concise` | Reduce finding output to the most important fields |
| `--category=` | `agentshield scan --category=secret-exposure` | Show one category |
| `--severity=` | `agentshield scan --severity=high` | Show one severity |
| `--format=md` | `agentshield scan --format=md` | Print a Markdown report (`json` is accepted too) |
| `--output=` | `agentshield scan --output=report.json` | Write report to a file; format is inferred from the extension |
| `--secret-path=` | `agentshield scan --secret-path=~/Projects/app` | Add a path for secret scanning |
| `--config-path=` | `agentshield scan --config-path=~/.config/tool` | Add a path for config-risk scanning |
| `--skill-path=` | `agentshield scan --skill-path=~/team-skills` | Add a directory of agent skills to audit |
| `--audit-target=` | `agentshield scan --audit-target=~/Projects/app` | Add an npm project for dependency audit |
| `--skillspector` | `agentshield scan --skillspector` | Also analyse discovered skills with SkillSpector |
| `--skillspector-llm` | `agentshield scan --skillspector-llm` | Add SkillSpector's LLM stage (sends skill content to your provider) |
| `--skillspector-bin=` | `agentshield scan --skillspector-bin=/opt/bin/skillspector` | Path to the SkillSpector executable |
| `--skillspector-limit=` | `agentshield scan --skillspector --skillspector-limit=10` | How many skills to analyse deeply (default 40) |

Skill discovery needs no flag. Every scan reads the skill folders of the agent runtimes it knows (Claude Code, Codex, the shared `.agents` layout, OpenClaw, Cursor, Gemini, Copilot, OpenCode, Windsurf, Kiro, Continue): the user's own skills under each runtime home, installed plugin and extension skills, the skills of the project you scan from, and the skills of every project registered with a local agent. The full list is in the threat catalog under Skill Scanning Scope. `--skill-path=` adds a directory that discovery would not reach on its own, and explicit paths are always read first.

When a filter is in place the report says so, and the coverage table marks the other areas `not in this view` instead of calling them clear.

`--config-path=` accepts TOML, JSON, env, and shell-profile files. JSON files are
also read structurally: a Claude Code `settings.json` gets the permission, env,
helper, sandbox, and hook checks, and any file with an `mcpServers` block gets
the MCP server checks. Without the flag, every scan reads `~/.claude/settings.json`,
`~/.claude/settings.local.json`, `~/.claude.json`, `~/.codex/config.toml`, the
Cursor and OpenCode configs, and the `.claude/settings*.json` and `.mcp.json` of
the project you scan from.

For each audit target, AgentShield runs npm's vulnerability audit and signature/provenance verification, then inspects local manifest and lockfile trust signals. It detects direct Git/archive dependencies, missing integrity hashes for direct npm-registry dependencies, and npm-reported invalid or extraneous dependency-tree states. See [`PACKAGE-SOURCES.md`](PACKAGE-SOURCES.md) for the exact sources and privacy boundary.

### Deep skill analysis with SkillSpector

The built-in skill checks always run and need nothing but Node. `--skillspector`
additionally hands every discovered skill to
[SkillSpector](https://github.com/NVIDIA/SkillSpector), NVIDIA's open-source
skill scanner, and merges its findings into the same report: 71 detection
patterns across 17 categories, plus Python AST, taint-tracking, and YARA passes.

Install it once, then pass the flag:

```bash
uv tool install git+https://github.com/NVIDIA/skillspector.git
agentshield scan --skillspector --category=skill-risk --all
```

- Findings from the engine are titled `SkillSpector: …` and carry
  `metadata.engine`, `metadata.rule`, `metadata.line`, and the severity and
  confidence the engine itself reported.
- One `info` finding, `skillspector-engine`, records the engine version, the
  mode it ran in, how many skills were analysed, and each skill's verdict
  (`SAFE`, `CAUTION`, `DO_NOT_INSTALL`). If the flag is passed and no engine is
  installed, `skillspector-unavailable` says so — a missing engine never reads
  as a clean result.
- AgentShield runs it with `--no-llm` so the scan stays local. `--skillspector-llm`
  enables the semantic stage, which sends skill content to whichever LLM provider
  SkillSpector is configured for. That is the only part of a scan that leaves
  your machine, and only when you ask for it.
- Each skill costs one process, so the deep pass is capped at 40 skills;
  `--skillspector-limit=` changes that, and the report says what it skipped.

## Categories

Common categories:

```text
tooling-discovery
secret-exposure
config-risk
skill-risk
network-exposure
dependency-audit
```

Examples:

```bash
agentshield scan --category=secret-exposure
agentshield scan --category=config-risk --concise
agentshield scan --category=skill-risk --all
agentshield scan --category=dependency-audit --format=md
```

## Severities

Supported severities:

```text
info
low
medium
high
critical
```

Examples:

```bash
agentshield scan --severity=high
agentshield scan --severity=medium --concise
agentshield scan --severity=critical --format=md --output=critical-findings.md
```

## Dashboard

```bash
agentshield dashboard
```

Default URL:

```text
http://127.0.0.1:4173
```

Use a different port:

```bash
agentshield dashboard --port=4180
AGENTSHIELD_PORT=4180 agentshield dashboard
```

The dashboard binds to `127.0.0.1` only and runs a fresh scan on every page
load — the same engine as the CLI. Set `AGENTSHIELD_SCAN_DIRS` to a
`:`-separated list of paths to widen the scan roots beyond the working
directory and its parent.

The dashboard also lists every skill the scan read under **Skill inventory**,
grouped by scope (explicit path, project, personal, installed plugin) and, inside
each, by the plugin or folder that contains it. Groups with findings open by
default; hover a name for its path. The same list is in the JSON report under the
`skill-inventory` finding's `metadata.skills`.

The dashboard package checker does not reload the page. It looks at global npm packages and direct dependencies declared by the local projects discovered in its scan roots; a local project can also be identified by its own package name.

## Pre-update Advisor

Global package:

```bash
agentshield preupdate --global npm
```

Project package:

```bash
agentshield preupdate react --path=/path/to/project
```

Write output to a file:

```bash
agentshield preupdate --global npm --output=npm-preupdate.md
```

Current verdicts:

```text
safe
caution
hold
```

## Repository Scripts

When working from the cloned repo:

```bash
npm run scan
npm run scan:concise
npm run report:json
npm run report:md
npm run dashboard
npm run preupdate -- --global npm
npm run check
```

`npm run check` runs the Node test suite. `npm run verify:e2e` drives the real
CLI and dashboard end to end and asserts on their output.
