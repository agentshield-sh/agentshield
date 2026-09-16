<div align="center">

<img src="assets/banner.png" alt="AgentShield" width="820">

<p>
  <a href="https://github.com/agentshield-sh/agentshield/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/agentshield-sh/agentshield/ci.yml?branch=main&style=flat-square&label=CI&labelColor=0d0d0d&color=9fe870"></a>
  <a href="https://www.npmjs.com/package/agent-shield"><img alt="npm" src="https://img.shields.io/npm/v/agent-shield?style=flat-square&labelColor=0d0d0d&color=f1b545"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square&labelColor=0d0d0d&color=8ab4f8"></a>
  <img alt="Node" src="https://img.shields.io/badge/node-%3E%3D20.9-brightgreen?style=flat-square&labelColor=0d0d0d&color=9fe870">
  <img alt="Platform" src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey?style=flat-square&labelColor=0d0d0d&color=8a8a8a">
</p>

<p>
  <a href="#quick-start"><b>Quick start</b></a> ·
  <a href="#what-it-checks"><b>What it checks</b></a> ·
  <a href="#commands"><b>Commands</b></a> ·
  <a href="#try-it-safely"><b>Try it safely</b></a> ·
  <a href="#faq"><b>FAQ</b></a>
</p>

</div>

---

You gave your AI tools your API keys, your files, and permission to run commands.
**AgentShield tells you what that left open.**

It is a local-first security audit for the machine you run agents on —
OpenClaw, Claude Code, Codex, Cursor, and the MCP servers around them — plus the
secrets, ports, and npm packages sitting next to them.

```bash
npx agent-shield scan
```

```text
AgentShield · security audit
~/Projects/agent-workspace · 2026-08-24 17:39 UTC

  AT RISK
  1 critical or high finding needs attention now.

  0 critical   1 high   3 medium   3 low   5 info

Do this first

  HIGH    An agent is configured to skip execution safeguards
          ~/.codex/config.toml
          → Keep the default permission mode for daily use and reserve
            full-access modes for disposable, isolated environments.

  MEDIUM  A remote MCP server is configured
          ~/.claude.json
          → Confirm you control or trust this endpoint, review what the agent is
            allowed to send it, and remove endpoints you no longer use.

  MEDIUM  A skill pre-approves a high-impact command
          ~/.claude/skills/deploy/SKILL.md
          → Drop the pre-approval so these commands still require confirmation,
            or narrow the pattern to the exact arguments the skill needs.

Coverage

  Secrets         clear
  Network         clear
  Configuration   3 to review
  Skills          1 to review
  Packages        3 to review
  Tooling         clear
```

> [!IMPORTANT]
> AgentShield is an **assessment** tool. It reports known exposure patterns at a
> point in time. It does not block attacks, cannot prove a package is safe, and
> does not replace a firewall, antivirus, or EDR. See [Limitations](#limitations).

---

## Table of contents

- [Why](#why)
- [Quick start](#quick-start)
- [What it checks](#what-it-checks)
  - [Package scanning scope](#package-scanning-scope)
  - [Deep skill analysis (optional)](#deep-skill-analysis-optional)
- [Commands](#commands)
  - [`scan`](#agentshield-scan)
  - [`preupdate`](#agentshield-preupdate-package)
  - [`dashboard`](#agentshield-dashboard)
- [Output formats](#output-formats)
- [Exit codes](#exit-codes)
- [Environment variables](#environment-variables)
- [Try it safely](#try-it-safely)
- [How it works](#how-it-works)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [FAQ](#faq)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

---

## Why

An agent runtime is a program you deliberately handed broad permissions, a set of
tokens, and a list of servers to trust. That configuration accumulates quietly:

- a permission flag flipped during one debugging session and never flipped back
- a token pasted into a dotfile two months ago
- an MCP server added for one experiment and never removed
- a dev server still bound to `0.0.0.0` on the café Wi-Fi
- a dependency that picked up a published advisory since you installed it

Most people can tell that a package is outdated. Almost nobody can tell whether
their agent setup is currently safe. AgentShield answers that in one command,
without uploading anything.

## Quick start

**Run it without installing:**

```bash
npx agent-shield scan
```

**Or install globally:**

```bash
npm install -g agent-shield
agentshield scan
```

**Then open the visual report:**

```bash
agentshield dashboard
# → http://127.0.0.1:4173
```

> [!NOTE]
> Requires **Node.js >= 20.9**. Network exposure checks use `lsof` (macOS, Linux)
> or `ss` (Linux) when available; everything else works without them.
> A misspelt flag or an unknown category is an error (exit `1`), never a
> silently clean scan.

## What it checks

| Area | What AgentShield looks for |
| :--- | :--- |
| 🔑 **Secrets** | 24 credential shapes (Anthropic, OpenAI, GitHub, GitLab, AWS, Google, Stripe, Slack, npm, Hugging Face, database connection strings, and more) in `.env` files, shell profiles, and agent configs — placeholders and `${VAR}` references are skipped, and every value is redacted in output |
| 🛡️ **Agent config** | Claude Code and Codex settings: bypass permission modes, wildcard and `sudo` grants in the allow list, sensitive directory grants, environment overrides that redirect API traffic or disable TLS, helper commands that run at session start, and sandbox escape hatches |
| 🪝 **Hooks** | Hooks that auto-approve every tool call, fetch and run remote code, post session data over plain HTTP, or send credentials from the environment |
| 🧩 **Skills** | Agent skills for Claude Code, Codex, Cursor, Gemini, Copilot, OpenCode, Windsurf, Kiro, and the shared `.agents` layout — personal, installed plugins, and per project — read as executable content: fetch-and-run installers, credential reads paired with uploads, hidden or invisible instructions, and pre-approved shell access |
| 📡 **MCP servers** | Remote endpoints your agents talk to, plus plaintext transports, credentials in URLs and headers, servers launched through `sh -c`, proxy and TLS overrides in their environment, wholesale auto-approval, and unpinned `npx` packages |
| 🌐 **Network** | TCP services bound beyond `localhost` and reachable from your network |
| 📦 **Packages** | npm advisories, registry signature/provenance failures, unpinned Git/archive sources, missing lockfile integrity, and invalid dependency trees — **for the project you scan from** ([see below](#package-scanning-scope)) |
| ⏱️ **Update risk** | Whether updating a given package is `SAFE`, `CAUTION`, or `HOLD`, with the reasoning shown |

Every finding carries a **severity**, a **confidence**, the **evidence** behind it,
and a **recommendation**. Nothing is a bare score.

### Package scanning scope

> [!IMPORTANT]
> Vulnerability data comes from `npm audit`, which resolves a **project** dependency
> graph. Globally installed packages are checked for being **outdated**, not for known
> vulnerabilities — npm cannot audit the global install set as a graph.
>
> The report says so in its own output rather than looking clean. Closing that
> gap is on the [roadmap](#roadmap) as a hosted advisory lookup (AgentShield
> Pro, not yet available).

### Deep skill analysis (optional)

The built-in skill checks always run and need nothing but Node. For a much deeper
read of the same skills, AgentShield can hand each one to
**[SkillSpector](https://github.com/NVIDIA/SkillSpector)** — NVIDIA's open-source
skill scanner — and report its findings alongside its own:
71 detection patterns across 17 categories, plus Python AST, taint-tracking, and
YARA passes, and live CVE lookups.

The two tools answer different halves of the question. AgentShield knows *which*
skills a machine has actually loaded — personal, plugin, and every project you
have opened. SkillSpector judges whether one of them is safe, in far more depth
than a pattern library of our own would.

```bash
# Install the engine once (Python 3.12+)
uv tool install git+https://github.com/NVIDIA/skillspector.git

# Then ask any scan to use it
agentshield scan --skillspector --category=skill-risk --all
```

Notes worth knowing before you turn it on:

- **It is opt-in, and stays that way.** SkillSpector is a separate Python
  install, so a default `npx agent-shield scan` must not depend on it. Without
  the flag, nothing changes. With the flag and no engine installed, the report
  says so rather than looking clean.
- **Static by default.** AgentShield runs it with `--no-llm`, so the deep scan
  stays local like the rest of the report. `--skillspector-llm` adds its
  semantic stage, which **sends skill content to whichever LLM provider you
  configured** — the one part of AgentShield that leaves your machine, and only
  when you ask for it.
- **It costs time.** Each skill is one process, so the scan is capped at 40
  skills by default (`--skillspector-limit=`).
- **Findings are attributed.** Every finding from the engine is titled
  `SkillSpector: …` and carries `metadata.engine`, `metadata.rule`, and the
  confidence the engine reported, so a false positive can be filed against the
  right project.

## Commands

### `agentshield scan`

Scans this machine and prints a readable report.

```bash
agentshield scan
```

| Option | Purpose |
| :--- | :--- |
| `--all` | Show every finding instead of the top eight |
| `--json` | Print the machine-readable JSON report |
| `--format=md` | Print a Markdown report (`--format=json` also works) |
| `--output=<file>` | Write to a file (format inferred from the extension) |
| `--category=<name>` | Limit to one category |
| `--severity=<level>` | Limit to one severity |
| `--concise` | Reduce each finding to its essential fields |
| `--secret-path=<path>` | Also scan this path for exposed secrets |
| `--config-path=<path>` | Also audit this config file for risky settings |
| `--skill-path=<path>` | Also audit agent skills under this directory |
| `--audit-target=<path>` | Also audit this npm project's dependencies |
| `--skillspector` | Also analyse every discovered skill with [SkillSpector](#deep-skill-analysis-optional) |
| `--skillspector-llm` | Add SkillSpector's LLM stage (needs a provider key, and sends skill content to it) |
| `--skillspector-bin=<path>` | Path to the `skillspector` executable |
| `--skillspector-limit=<n>` | How many skills to analyse deeply (default `40`) |

**Categories:** `secret-exposure` · `config-risk` · `skill-risk` · `network-exposure` · `dependency-audit` · `tooling-discovery`
**Severities:** `info` · `low` · `medium` · `high` · `critical`

With a filter in place, the coverage table marks the other areas `not in this
view` rather than calling them clear.

<details>
<summary><b>Examples</b></summary>

```bash
# Everything, not just the top priorities
agentshield scan --all

# Just the secrets, with full detail
agentshield scan --category=secret-exposure --all

# Just the agent skills on this machine
agentshield scan --category=skill-risk --all

# Only what is urgent
agentshield scan --severity=critical

# Share a report with someone
agentshield scan --format=md --output=agentshield-report.md

# Feed another tool
agentshield scan --json | jq '.findings[] | select(.severity=="high")'

# Widen the scan to specific projects
agentshield scan \
  --secret-path=~/Projects/app-one \
  --audit-target=~/Projects/app-one
```

</details>

### `agentshield preupdate <package>`

Tells you whether updating a package is safe **before** you do it.

```bash
agentshield preupdate --global npm
agentshield preupdate react --path=~/Projects/app
```

| Option | Purpose |
| :--- | :--- |
| `--global` | Check a globally installed package |
| `--path=<dir>` | Check inside this project (default: current directory) |
| `--output=<file>` | Write the advisor result to a file |

<details>
<summary><b>Example output</b></summary>

```text
Package: npm
Scope: global
Current: 11.9.0
Latest: 11.19.0
Change type: minor
Execution path: critical
Dependency type: direct
Known advisories: none

Verdict: CAUTION

Why:
- affects a critical execution path
- direct dependency impact is clearer and more immediate
- no known advisory found in current npm audit data
- update type is minor

Recommendation:
- Test this update in an isolated profile before changing your daily agent toolchain.
```

</details>

### `agentshield dashboard`

Serves the same scan results as a local web page.

```bash
agentshield dashboard            # http://127.0.0.1:4173
agentshield dashboard --port=4180
```

> [!TIP]
> The dashboard binds to `127.0.0.1` only and serves nothing but its own routes.
> It is a local control surface, not a hosted panel — there is no cloud backend.
> It runs the same scan as the CLI on every page load, so the two never disagree.

## Output formats

| Format | Flag | Use it for |
| :--- | :--- | :--- |
| Terminal | *(default)* | Reading it yourself |
| JSON | `--json` | Scripting, diffing runs, feeding other tools |
| Markdown | `--format=md` | Sharing a report, pasting into an issue |
| Dashboard | `agentshield dashboard` | Looking at it visually |

All four come from **one scan engine** — the CLI and dashboard cannot disagree.

<details>
<summary><b>JSON shape</b></summary>

```jsonc
{
  "schemaVersion": "0.1.0",
  "generatedAt": "2026-08-24T17:39:00.000Z",
  "product": "AgentShield",
  "posture": {
    "status": "ready",
    "findings": 11,
    "severityCounts": { "info": 5, "low": 3, "medium": 2, "high": 1, "critical": 0 }
  },
  "filters": null,          // { "category": "...", "severity": "..." } when a filter was applied
  "findings": [
    {
      "id": "config-dangerous-exec-a1b2c3d4e5",
      "category": "config-risk",
      "severity": "high",
      "confidence": "high",
      "title": "An agent is configured to skip execution safeguards",
      "description": "...",
      "path": "/Users/you/.codex/config.toml",
      "recommendation": "...",
      "metadata": { "setting": "execution.yolo", "value": "true" }
    }
  ]
}
```

</details>

## Exit codes

`scan` is designed to gate a script or CI job.

| Code | Meaning |
| :---: | :--- |
| `0` | No critical or high findings |
| `1` | Invalid usage (unknown flag, category, severity, or port), or the package was not found |
| `2` | **Critical or high findings present** |

```bash
# Fail the job when something urgent shows up
agentshield scan --concise || exit 1
```

## Environment variables

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `AGENTSHIELD_PORT` | `4173` | Dashboard port (`--port=` takes precedence) |
| `AGENTSHIELD_SCAN_DIRS` | — | Extra dashboard scan roots, `:`-separated |
| `AGENTSHIELD_SKILLSPECTOR_BIN` | `skillspector` | Path to the SkillSpector executable (`--skillspector-bin=` takes precedence) |
| `NO_COLOR` | — | Disable coloured terminal output |
| `FORCE_COLOR` | — | Force colour when piping |

## Try it safely

You do not have to point AgentShield at your own machine to see what it does.
The repository ships deliberately bad fixtures:

```bash
agentshield scan --config-path=fixtures/risky-agent-home/config.toml \
                 --category=config-risk --all
```

That single config triggers a wildcard bind, a surface with no authentication,
an agent allowed to skip execution safeguards, and a remote MCP endpoint.
`fixtures/risky-agent-settings` and `fixtures/risky-mcp` do the same for Claude
Code settings, hooks, and MCP server configs. See
[`fixtures/README.md`](fixtures/README.md) for the rest.

> [!NOTE]
> Normal scans skip directories named `fixtures`, so these never inflate a real scan.

## How it works

```text
                    ┌──────────────────────┐
                    │   packages/core      │   one scan engine
                    │  ──────────────────  │
                    │  secrets             │
                    │  config risk         │
   your machine ──► │  skill risk          │ ──► normalized findings
                    │  network exposure    │     (severity, confidence,
                    │  dependency audit    │      evidence, remediation)
                    │  tooling discovery   │
                    └──────────┬───────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
         terminal         JSON / MD        dashboard
      (packages/cli)     (reporters)  (dashboard-server)
```

| Path | Role |
| :--- | :--- |
| `packages/core/src/scanners` | The six scanners, plus the optional SkillSpector adapter |
| `packages/core/src/reporters` | Terminal, JSON, and Markdown output |
| `packages/core/src/preupdate.js` | Update-safety advisor |
| `packages/cli/src` | Argument parsing and command dispatch |
| `packages/dashboard-server/src` | Loopback dashboard over the same engine |
| `fixtures` | Safe demo inputs |

**Design rules:** the scan engine is the single source of truth, it works with no
cloud backend, and output schemas stay stable so anything built on top keeps working.

Deeper reading: [Command reference](docs/COMMANDS.md) ·
[Threat catalog](docs/THREAT-CATALOG.md) ·
[Package intelligence sources](docs/PACKAGE-SOURCES.md) ·
[First-run onboarding](docs/ONBOARDING.md)

## Limitations

> [!WARNING]
> Read this before relying on a clean result.

- **Assessment, not protection.** No blocking, no live monitoring, no remediation.
- **A clean scan is not proof of safety.** It means no *known* pattern matched.
- **npm only.** No other package ecosystem yet.
- **Global packages are not vulnerability-scanned.** They are checked for being
  outdated only, because `npm audit` resolves a project graph. See the [roadmap](#roadmap).
- **Advisory data can be stale or absent.** A brand-new malicious package has no advisory.
- **Missing signatures are a review signal, not proof of compromise.**
- **Heuristics produce false positives.** Critical-path detection in particular.
- **Coverage is strongest for known agent/tool patterns** — unusual setups get less.
- **Network checks focus on listening TCP services** where `lsof` or `ss` exists.

Some networked npm checks disclose package names and versions to your configured
registry. See [`docs/PACKAGE-SOURCES.md`](docs/PACKAGE-SOURCES.md) for exactly what
leaves the machine and when.

## Roadmap

Everything above exists today and runs on your machine alone. Nothing below
does yet, and none of it has a date. The free scanner stays complete on its
own; the roadmap adds to it and never gates it.

**Scanner (open source, this repository)**

- Package ecosystems beyond npm.
- More agent runtimes and config formats as they appear, and new detections
  for the [threat catalog](docs/THREAT-CATALOG.md).
- A Homebrew tap. The formula is rendered on every release but not yet
  published.

**Hosted services (AgentShield Pro, not yet available)**

- Vulnerability checks for globally installed packages. `npm audit` resolves a
  project graph, so the global tool set is only checked for being outdated
  today; closing that gap needs a maintained advisory service the scanner
  can call.
- Scan history per machine: a *since last scan* line and `NEW` tags on
  findings that were not there before.
- Email alerts when a new critical or high finding appears.
- One view across several machines.

Pro will be a set of services, not withheld scanner features; no finding will
ever be held back from the free scan. [LICENSING.md](LICENSING.md) records that
boundary. Progress lands in the [changelog](CHANGELOG.md), and there is a
waitlist at [agentshield.sh](https://agentshield.sh).

## FAQ

<details>
<summary><b>Does anything get uploaded?</b></summary>

Not by default. The scan reads local files and shells out to `npm` for advisory
data; there is no telemetry and no account is needed. The npm calls go to your
configured registry and disclose package names and versions — documented in
[`docs/PACKAGE-SOURCES.md`](docs/PACKAGE-SOURCES.md).

One thing is opt-in and says so in the report: with `--skillspector-llm`,
SkillSpector sends skill content to the LLM provider you configured for it.

</details>

<details>
<summary><b>Will it show my actual API keys?</b></summary>

No. Secret values are redacted everywhere — terminal, JSON, Markdown, and dashboard.
You see the detector name, the file, the key name, and a masked value like `sk-p…F4vQ`.

</details>

<details>
<summary><b>Is the dashboard exposed to my network?</b></summary>

No. It binds to `127.0.0.1` only, rejects non-`GET` requests, and serves only its own
routes. To reach it from another device, put it behind something you control.

</details>

<details>
<summary><b>Why did it flag something that is fine?</b></summary>

Several checks are heuristic and say so via their `confidence` field. Findings are a
prioritized review list, not a verdict. If a check is noisy in a way that looks wrong,
[open an issue](https://github.com/agentshield-sh/agentshield/issues) with the shape of the
config — please redact real values.

</details>

<details>
<summary><b>Can I run it in CI?</b></summary>

Yes. `scan` exits `2` when critical or high findings exist. Use `--json` for machine
output and `--audit-target=` to point it at the project.

</details>

<details>
<summary><b>Does it work on Windows?</b></summary>

Untested. The scanners avoid shelling out to a specific shell, but path conventions
and the `lsof`/`ss` network checks assume macOS or Linux.

</details>

## Contributing

Issues and pull requests are welcome — especially **real false positives**, since
noise reduction is the top priority for the scanners.

```bash
git clone https://github.com/agentshield-sh/agentshield.git
cd agentshield
npm install
npm run check      # runs the test suite
```

| Script | Does |
| :--- | :--- |
| `npm test` | Run the test suite |
| `npm run check` | Full verification (used by CI and `prepublishOnly`) |
| `npm run scan` | Run the CLI from source |
| `npm run dashboard` | Run the dashboard from source |

New scanner rules should ship with a test that proves the detection **and** a test
that proves it stays quiet on a benign input. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Found a vulnerability in AgentShield itself? Please report it privately — see
[SECURITY.md](SECURITY.md). Do not open a public issue for a security defect.

If AgentShield finds a real leaked credential on your machine, **rotate it first**,
then remove it from the file. Assume anything committed to git or synced to cloud
storage is already exposed.

## License

[AGPL-3.0-or-later](LICENSE) © AgentShield

You can run, read, modify, and share AgentShield freely. If you distribute a
modified version, or offer one to others over a network, that version must be
released under the AGPL too.

If you want to use AgentShield inside a proprietary product or service without
that obligation, a **commercial license** is available — see
[LICENSING.md](LICENSING.md), which also explains why the scanner is AGPL and
where any future paid service would sit.

Several settings, hook, and MCP detection patterns draw on the MIT-licensed
[ecc-agentshield](https://github.com/affaan-m/agentshield) rule set by Affaan M,
reimplemented against this scanner's finding model; that project is unrelated to
this one despite the shared name, and its binary is also called `agentshield`,
so installing both globally leaves one shadowed.

Use is also subject to the [Terms of Use](TERMS.md), which cover the
assessment-not-protection boundary in more detail.

<div align="center">
<sub>Built for people who gave an agent shell access and would like to know how that went.</sub>
</div>
