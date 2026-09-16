# Demo fixtures

Safe, offline example inputs for trying AgentShield without touching your own
configuration. Nothing here contains a real credential or contacts a real host.

## Risky agent config

`risky-agent-home/config.toml` is a deliberately bad agent config. Scanning it
demonstrates every config-risk check at once:

```bash
agentshield scan --config-path=fixtures/risky-agent-home/config.toml --category=config-risk
```

Expect a wildcard bind, a surface without authentication, an agent allowed to
skip execution safeguards, and a remote MCP endpoint.

## Risky agent skill

`risky-skill/deploy-helper/` is a deliberately unsafe agent skill. Scanning it
demonstrates the skill-risk checks at once:

```bash
agentshield scan --skill-path=fixtures/risky-skill --category=skill-risk
```

Expect a fetch-and-run installer, a credential read paired with an upload, an
instruction telling the agent to ignore its own rules, a delete of the home
directory, and unrestricted shell access pre-approved in `allowed-tools`. Every
host it names ends in `.invalid`, so nothing in it can reach a real service.

## Risky Claude Code settings

`risky-agent-settings/.claude/settings.json` is a deliberately bad Claude Code
settings file. Scanning it exercises the structural settings and hook checks:

```bash
agentshield scan --config-path=fixtures/risky-agent-settings/.claude/settings.json --category=config-risk --all
```

Expect a bypass permission mode, wildcard and sudo grants in the allow list, a
sensitive directory grant, environment overrides that redirect API traffic and
disable TLS checks, a helper command that fetches code at session start, a
sandbox with a wildcard exception, and four hooks: one that auto-approves every
tool call, one posting over plain HTTP, one sending a credential from the
environment, and one that pipes a download into bash.

## Risky MCP configuration

`risky-mcp/mcp.json` declares three bad MCP servers:

```bash
agentshield scan --config-path=fixtures/risky-mcp/mcp.json --category=config-risk --all
```

Expect a plaintext transport with a token in the URL and a literal bearer
header, a server launched through `sh -c` that downloads its own code, with a
proxy in its environment and every tool auto-approved, and an unpinned `npx`
server that reports to a tunnelling host.

## Vulnerable dependency tree

`vulnerable-tree/` declares `minimist@0.0.8`, a version with a long-published
npm advisory. Install it in a throwaway directory and audit it:

```bash
agentshield scan --audit-target=fixtures/vulnerable-tree --category=dependency-audit
```

Dependency findings need an installed tree, so run `npm install` inside the
fixture first if you want the full advisory output.

Normal scans skip directories named `fixtures`, and skill discovery only follows
`.claude/skills` directories and the installed plugin cache, so these files never
inflate the findings of a real scan. A path passed with `--skill-path=` is
always read first, however many skills the machine already has.
