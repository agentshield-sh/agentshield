# Changelog

All notable changes to AgentShield are documented here.

## 0.1.0 - 2026-09-16

First public release.

### Added

- 17 more secret detectors (Anthropic, xAI, GitLab, Slack, AWS, Google, Stripe,
  npm, Hugging Face, DigitalOcean, SendGrid, Databricks, Sentry, Shopify,
  Twilio, JSON Web Tokens, and database connection strings with passwords);
  known prefixes are detected under any key, placeholders such as `<your key>`,
  `sk-...`, and `${VAR}` references are never reported, and connection-string
  passwords are redacted in place
- structural checks for Claude Code settings: bypass permission modes, broad or
  dangerous `permissions.allow` entries (including the `Bash(sudo:*)` and
  path-prefixed spellings), sensitive `additionalDirectories`, `env` overrides
  that redirect API traffic or weaken TLS, helper commands that run at session
  start, and sandbox escape hatches
- hook checks: unconditional `permissionDecision: allow`, plaintext or
  transcript-carrying HTTP hooks, credential-plus-network commands, pipe-to-shell
  downloads, tunnelling and request-capture hosts, and credential path reads
- MCP server checks wherever an `mcpServers` block appears: plaintext
  transports, credentials in URLs and headers, servers launched through `sh -c`
  or `node -e`, proxy and TLS overrides in the server env, exfiltration hosts,
  wholesale auto-approval, and unpinned `npx` packages
- `~/.claude/settings.json`, `settings.local.json`, and the scanned project's
  `.claude/settings*.json` and `.mcp.json` are read by every scan
- `fixtures/risky-agent-settings` and `fixtures/risky-mcp` demo the new checks
- the dashboard lists every skill it read, grouped by scope, with the ones that
  carry findings marked
- AGPL-3.0-or-later licensing for the scanner, with the open-core boundary
  documented in `LICENSING.md` and a contributor CLA covering commercial licensing
- CLI-first local security scan with a readable terminal report
- secret exposure checks across env files, shell profiles, and agent configs
- local agent and MCP tooling discovery
- config-risk checks for wildcard binds, missing auth, permissive execution, and remote MCP trust boundaries
- skill-risk audit of agent skills, globally and per project, covering fetch-and-run installers, credential reads paired with uploads, hidden or encoded instructions, destructive commands, hardcoded credentials, pre-approved shell access, and writable or symlinked skill folders
- npm dependency audit and pre-update advisor
- optional deep skill analysis through NVIDIA SkillSpector (`--skillspector`), merging its findings into the same report, with `--skillspector-llm`, `--skillspector-bin=`, and `--skillspector-limit=`
- package trust audit for registry signature/provenance failures, direct Git/archive dependencies, missing direct-dependency integrity hashes, and invalid dependency trees
- TCP listener and LAN exposure checks using `lsof` or `ss`
- JSON and Markdown reports
- local dashboard on `127.0.0.1`
- `--all`, `--json`, and `--port` flags, plus `--help` and `--version`
- scan exit code `2` when critical or high findings are present, so a scan can gate CI
- `AGENTSHIELD_SCAN_DIRS` for widening dashboard scan roots
- safe demo fixtures for the config-risk, skill-risk, and dependency checks
- onboarding, command reference, and security policy

### Changed

- skill findings that differ only by agent-runtime directory (`.claude/`, `.cursor/`, `.gemini/`, `plugin/`, …) are reported once, with the other copies named in `metadata.otherPaths`
- the instruction-override rule no longer treats `do not show the user <output>` as concealment; `do not show this to the user`, `do not tell the user`, and `without telling the user` still fire
- the hidden-instructions rule requires an HTML comment to address the model directly, and skips build banners, licence headers, and editor directives
- the dashboard shortens `$HOME` to `~` in paths, descriptions, and recommendations, and caps a finding's path list at three with a `+ N more` count

### Security

- subprocess execution uses argument-safe command APIs
- invalid package names are rejected before npm execution
- dashboard output escapes scanned data before HTML rendering
- dashboard serves only its own routes and rejects non-GET requests
- normal scans skip fixture/test directories and placeholder `.env` files
- secret values are always redacted in output

### Fixed

- skill discovery read plugin skills first and stopped at 400, so on a machine
  with a large plugin cache a `--skill-path=` was never reached and the
  documented fixture demo produced nothing; explicit and project roots are now
  read first, the cap is 1,500, and the inventory record says when it truncates
- installed plugin skills were read twice, once from `plugins/cache` and once
  from the `plugins/marketplaces` clone, and reported twice
- five skill-rule false positives: `curl --output /dev/null` near `python3 -c`
  as remote code execution, `grep -oP` read as `curl -o P`, a zero-width joiner
  inside a compound emoji as a hidden character, a PEM header quoted in prose
  as a hardcoded private key, and override wording in a script comment as an
  instruction
- an unknown flag, category, severity, or port was silently ignored, so a typo
  such as `--severity=hgih` printed LOOKS CLEAR with exit code 0; every command
  now rejects it with exit code 1 and a suggestion
- a category filter showed every other coverage row as `clear`; they now read
  `not in this view`
- `--output=<file>` wrote ANSI colour codes into the file when run from a TTY
- `.next` and other hidden build directories were counted as local projects
- macOS daemons such as `siriactionsd` were reported as exposed TCP services
- a Figma token containing `_` or `-` was classed as a generic token

- the CRITICAL severity badge ran into the finding title, because "CRITICAL" is
  exactly as wide as the column it was padded to
- finding ids were derived from a truncated hex encoding of the file path, so any
  two configs sharing a file extension collided; ids are now content-addressed
- config risk was matched against raw file text, which flagged prose in
  `~/.claude.json` conversation history as real settings; configs are now parsed
  structurally
- filtering a scan by category or severity left the summary counts describing the
  unfiltered run
- command detection shelled out to a hardcoded `/bin/zsh`, which does not exist on
  Linux; PATH is now resolved directly
- a non-JSON subprocess response could throw out of the scanner instead of
  degrading to "no data"
- every dashboard request ran a full scan, including favicon and 404 probes
- the Markdown reporter emitted a malformed path line

### Known Limitations

- globally installed packages are checked for being outdated, not for known
  vulnerabilities; `npm audit` resolves a project graph, not the global install
  set. Closing that gap is on the README roadmap under the planned hosted services
- pre-update advisor is npm-only
- network checks focus on TCP listeners
- config and secret coverage is strongest for known agent/tool patterns
- AgentShield is assessment software, not live protection
