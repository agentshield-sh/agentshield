# Contributing

## Setup

```bash
git clone https://github.com/agentshield-sh/agentshield.git
cd agentshield
npm install
npm run check
```

## Useful Commands

```bash
npm run scan:concise
npm run dashboard
npm run report:json
npm run report:md
npm run check
```

## Licensing And The CLA

AgentShield is licensed under the [AGPL-3.0-or-later](LICENSE), and AgentShield
also offers it under a separate commercial license to organisations the AGPL
does not suit. Funding the project that way is only possible while a single
party holds the rights to the whole codebase.

So before a first pull request can be merged, contributors sign a Contributor
License Agreement granting AgentShield the right to license their contribution
under both the AGPL and a commercial license. You keep the copyright in your own
work; the CLA grants rights, it does not take them.

Contributions are accepted only under those terms. Do not submit code you do not
have the right to license this way, including code copied from a project under an
incompatible licence or written for an employer who owns it.

## Pull Requests

- keep changes scoped
- add focused tests for scanner/parser changes
- do not commit real tokens, private paths, or personal configuration
- use synthetic fixtures for secret/config tests
- keep JSON output machine-readable
- document new CLI flags in `docs/COMMANDS.md`
- update `CHANGELOG.md` for user-visible changes

## Scanner Findings

Every finding should include a stable ID, category, severity, confidence, plain-language explanation, actionable recommendation, and redacted metadata only.

Avoid high-severity findings based only on weak heuristics.

## Security Reports

Follow [`SECURITY.md`](SECURITY.md). Do not disclose exploitable issues or real secrets in public issues.
