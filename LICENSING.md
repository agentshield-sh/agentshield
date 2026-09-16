# Licensing And The Open-Core Boundary

AgentShield is an open-core project. The scanner is free software under the
[AGPL-3.0-or-later](LICENSE). The hosted services planned around it (see the
README roadmap) will be commercial; none of them exist yet. This document says
exactly where the line will fall, and why, so the answer does not have to be
reinvented for every new feature.

## The short version

| | |
| --- | --- |
| **The scanner** — CLI, core, scanners, reporters, dashboard server, threat catalog | AGPL-3.0-or-later, in this repository |
| **AgentShield Pro** — planned hosted services: advisory lookup, scan history, alerts, fleet view | Commercial, not yet available, never in this repository |
| **Using the scanner at work, on client machines, in CI** | Free. No licence needed. |
| **Shipping the scanner inside a proprietary product** | Needs a commercial licence |

## What the AGPL means for you

**If you run AgentShield** — on your laptop, across your company, on client
machines, in CI, as part of paid consulting work — you need nothing from us. Run
it, read it, change it, scan whatever you are authorised to scan. The AGPL puts
no conditions on use.

**If you distribute a modified AgentShield**, or offer one to others as a network
service, the AGPL asks one thing in return: release your modified version under
the AGPL too, so the people using it get the same rights you got.

**If that does not suit you** — you want AgentShield's detection engine inside a
closed-source product, a proprietary DevSecOps platform, or a commercial service,
without releasing your own source — that is what the commercial licence is for.
See [Commercial licensing](#commercial-licensing).

This is a deliberate trade. A tool that reads `~/.ssh`, `~/.aws/credentials`, and
`~/.claude.json` has no business being unauditable. The scanner is open so that
anyone can verify what it touches and what it sends. The AGPL is what keeps it
open downstream as well.

## What is open source

Everything in this repository, and this is not a teaser tier:

- the `agentshield` CLI and every command it exposes
- every scanner: secrets, configuration risk, skills, network exposure,
  dependencies, tooling discovery, pre-update risk
- every reporter: terminal, JSON, Markdown
- the local dashboard server
- the full [threat catalog](docs/THREAT-CATALOG.md) — every finding, every
  trigger, every recommendation, documented in the open
- the fixtures and the test suite

**No finding is ever withheld from a free user.** If AgentShield detects that
your machine is exposed, it tells you, in full, with the evidence and the fix.
Paywalling a security finding from someone who is currently at risk is not a
business model we will run. Where free coverage genuinely stops, the scanner says
so in its own output rather than staying quiet and looking clean.

## What is not open source

AgentShield Pro does not exist yet. When it does, it will be a set of
**services**, not withheld scanner features. Its code will live in a separate
private repository and never be distributed to users, so the AGPL will not
reach it. What is planned:

- **Advisory API** — vulnerability coverage across every globally and locally
  installed package, which needs a maintained advisory service rather than a
  local `npm audit` graph
- **Fleet** — many machines reporting to one view, configuration drift over
  time, policy enforcement, alerting
- **History and evidence** — retained scan history, baselining and suppression
  in CI, exportable compliance evidence
- **Continuously updated detection intelligence** — new agent and MCP attack
  patterns, malicious skill signatures, and known-bad publisher lists, delivered
  as a feed rather than as a release

## Deciding where a new feature goes

Apply this test before writing the code, not after:

> **Free is complete for one machine, at one moment in time.**
> **Paid is scale, continuity, and intelligence.**

- Does it make a **single scan of a single machine** more correct, clearer, or
  better explained? → **Open source.** This includes new detections, better
  severity calibration, fewer false positives, and new agent runtimes.
- Does it only have value across **many machines, many people, or many points in
  time**? → **Pro.** Fleet views, drift, history, baselining, alerting.
- Does it require **infrastructure we run and keep current** — an API, a
  maintained dataset, a feed? → **Pro**, because the ongoing work is the product.

If a feature seems to fail all three, it is almost always the first one. Default
to open.

Two consequences worth stating plainly. A new scanner is open source, always —
detection breadth is the reason anyone trusts this tool, and it is not the moat.
And the moat is not the code: this repository is a few thousand lines of readable
JavaScript and the threat catalog explains every rule in prose. Anyone can
reimplement it. What is hard to copy is a maintained advisory service, a current
detection feed, and the trust that comes from having been auditable the whole
time.

## Enforcement lives on the server

There are no licence keys, no phone-home checks, and no disabled code paths in
this repository. Client-side enforcement in an open codebase is theatre — it is
removed in five minutes, under any licence.

Paid capability will be gated where it actually lives: an API key that the
services validate. No key, no data. That boundary cannot be forked out, because
the value is on the other side of it.

## Keeping the boundary clean

Pro must not be linked into this codebase. If proprietary code is `import`ed into
an AGPL program, there is a strong argument that the combination is a derivative
work and must itself be AGPL — which would give away the thing the boundary
exists to protect.

The safe pattern is already in use here. The optional
[SkillSpector](https://github.com/NVIDIA/SkillSpector) integration runs as a
**separate process** behind an opt-in flag, and the scanner is fully functional
without it. Pro will integrate the same way: a separate executable or a network API
the open CLI knows how to call, never a library it imports. An HTTP client for a
proprietary API is fine and stays open; the API behind it is not distributed at
all.

## Commercial licensing

A commercial licence removes the AGPL's reciprocal obligations. It is intended
for organisations that want to embed AgentShield in a proprietary product or
service, or to redistribute a modified version without publishing their source.

Enquiries go through the [AgentShield repository](https://github.com/agentshield-sh/agentshield).

This is only possible because AgentShield holds the rights to the whole codebase,
which is why contributions require a CLA — see [CONTRIBUTING.md](CONTRIBUTING.md).
A single contribution accepted without one would permanently remove the ability
to offer a commercial licence covering that code.

## Third-party components

Detection patterns for Claude Code settings, hooks, and MCP server configs
draw on [ecc-agentshield](https://github.com/affaan-m/agentshield) by Affaan M,
MIT licensed, reimplemented here rather than copied. That project is unrelated
to this one.

## Trademark

The AGPL covers the code. It does not grant rights to the **AgentShield** name,
logo, or brand. A fork is free to use the code and must use a different name.
