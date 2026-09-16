# AgentShield Onboarding

This guide is for someone installing AgentShield for the first time and trying to understand what to do with the results.

## 1. Install

Global install:

```bash
npm install -g agentshield-sh
```

No-install run:

```bash
npx agentshield-sh scan
```

Repository/dev install:

```bash
git clone https://github.com/agentshield-sh/agentshield.git
cd agentshield
npm install
npm run scan
```

## 2. Run The First Scan

Start with concise output:

```bash
agentshield scan --concise
```

If you are running from the repo:

```bash
npm run scan:concise
```

## 3. Open The Dashboard

```bash
agentshield dashboard
```

Open:

```text
http://127.0.0.1:4173
```

If the port is busy:

```bash
agentshield dashboard --port=4180
```

## 4. Read Findings In The Right Order

Review findings by practical risk:

1. `critical` and `high`
2. exposed secrets
3. risky config and trust boundaries
4. risky agent skills
5. dependency and update risk
6. informational tooling inventory

Do not treat every finding equally. A leaked API key usually matters more than a low-severity package update.

## 5. Fix Common Findings

### Exposed API keys

Recommended actions:

- rotate the key if it is real
- remove it from long-lived files
- move it into a secret manager or injected runtime environment
- re-run AgentShield after cleanup

### Remote MCP or automation trust boundary

Recommended actions:

- verify the endpoint is expected
- remove unused remote servers
- keep browser automation scoped to local use
- avoid combining broad shell access with remote trust unless you understand the boundary

### Risky agent skill

A skill is instructions an agent will act on, so treat it like code you are about to run.

Recommended actions:

- open the reported file and read the flagged section, including any bundled scripts
- remove fetch-and-execute steps and outbound calls that can carry credential files
- scope `allowed-tools` to the commands the skill actually needs instead of bare `Bash`
- delete skills you did not install deliberately, and re-run the scan afterwards

### Outdated package

Recommended actions:

- run the pre-update advisor first
- update in an isolated profile or test project if the package controls core tooling
- re-run the scan after updating

### Local service exposure

Recommended actions:

- bind dev services to `127.0.0.1` when possible
- close services you are not actively using
- avoid `0.0.0.0` unless LAN access is intentional

## 6. Export A Report

Markdown:

```bash
agentshield scan --format=md --output=agentshield-report.md
```

JSON:

```bash
agentshield scan --output=agentshield-report.json
```

Use Markdown for human review. Use JSON when another tool or future automation needs the raw finding model.

## 7. Re-run After Fixes

```bash
agentshield scan --concise
```

Keep the before/after report if you want proof that the local posture improved.

## Current Mental Model

AgentShield is a local review tool. It does not claim that your machine is compromised, and it does not automatically repair anything. It gives you a prioritized list of things worth checking before they become expensive.
