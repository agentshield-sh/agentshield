# AgentShield Messaging Guide

This document keeps README, landing page, package metadata, and future docs aligned.

## Tagline

The security audit for your AI agents.

Use this wording on the banner, the landing page title, and the CLI header. Say "audit", not "monitor": the free tool is a point-in-time check. Monitoring language is reserved for the hosted services on the README roadmap, which do not exist yet.

## One-liner

AgentShield finds local security risks before somebody else does.

## Short Description

Security audit for your AI agents and the machine they run on: exposed API keys, risky agent and MCP config, untrusted skills, vulnerable packages, and update risk.

## What To Emphasize

- One leaked key is enough.
- Local machines collect risk quietly.
- The product is useful without a cloud account.
- The dashboard is a visual layer over the same local scan.
- Reports are explainable and exportable.
- Pre-update is intentionally scoped and honest: v1 is npm-only.

## What Not To Overclaim

Avoid saying AgentShield is:

- an antivirus
- an EDR
- a SIEM
- a full vulnerability management platform
- a guarantee that a machine is safe
- an automatic remediation system

## Primary Audience

People building and running local software/tooling who may not have deep security experience but still need practical protection.

That includes:

- solo builders
- junior and mid-level developers
- power users running AI tools locally
- people using MCP servers, browser automation, and shell-capable agents
- small teams that need a quick local posture report

Do not narrow public messaging to one slang term or one subculture. Keep it accessible to anyone who needs local machine security clarity.

## Tone

Use short, direct, high-stakes language:

- "Your machine is easier to expose than you think."
- "One leaked key is enough."
- "Find it before somebody else does."
- "Check the stuff attackers actually use."

Avoid vague enterprise language:

- "holistic posture platform"
- "next-generation security fabric"
- "AI-powered cyber resilience"
- "shift-left security transformation"

## Feature Phrases

Use these names consistently:

- Secret scan
- Package audit
- Config risk audit
- Skill audit
- Tooling discovery
- Local dashboard
- Pre-update advisor
- JSON and Markdown reports

## Current Scope Language

Good:

> AgentShield is early, local-first, and intentionally scoped. It surfaces practical local risk and gives clear next steps.

Bad:

> AgentShield fully secures your machine.

## Pre-update Advisor Language

Good:

> Pre-update advisor is v1 and npm-only. It gives explainable safe/caution/hold guidance for package updates.

Bad:

> AgentShield knows whether every dependency update is safe.
