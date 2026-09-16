# Security Policy

## Supported Version

AgentShield is currently in an early `0.1.x` release line. Security fixes are applied to the latest published version.

## Report A Vulnerability

Do not open a public issue for a vulnerability that could expose secrets, enable command execution, bypass scan boundaries, or affect package users.

Use GitHub's private security advisory flow:

<https://github.com/agentshield-sh/agentshield/security/advisories/new>

Include the affected version or commit, operating system, Node.js version, reproduction steps, impact, and suggested mitigation if known.

Do not include real API keys, tokens, private configuration, or personal data. Use synthetic fixtures.

## Response Expectations

This is an early open-source project. Reports will be triaged as quickly as practical, but no formal response SLA is offered yet.

## Scope

Relevant reports include:

- command injection or unsafe subprocess use
- secret leakage in CLI, reports, or dashboard output
- dashboard injection or unintended remote exposure
- unsafe default scan scope
- dependency vulnerabilities affecting the shipped runtime
- incorrect handling that can damage local files

General scanner false positives and feature requests can use normal GitHub issues.
