# AgentShield Threat Catalog

This catalog describes every actionable CRITICAL, HIGH, MEDIUM, and LOW finding emitted by AgentShield v0.1.0. Informational inventory records are intentionally excluded.

Severity describes priority, not proof of compromise. A finding means the detected condition needs review within the scanner's current scope.

## Severity Behavior

| Severity | Dashboard verdict | Review expectation |
| --- | --- | --- |
| CRITICAL | `At risk` | Act immediately. Confirm exposure, contain it, and apply the recommended fix. |
| HIGH | `At risk` | Treat as urgent. Validate and remediate before continuing normal use. |
| MEDIUM | `Needs review` | Review soon. The condition expands attack surface or trust. |
| LOW | Does not create an urgent verdict by itself | Handle during routine security maintenance. |

## CRITICAL

### Agent skill that fetches remote code and runs it

- **Finding:** `A skill fetches remote code and runs it`
- **Trigger:** A skill file or a bundled script pipes `curl`/`wget` output into a shell or interpreter, decodes a payload into a shell, evaluates encoded data, or downloads a file and executes it a few lines later.
- **Why it matters:** A skill is instructions an agent acts on. Whoever controls the fetched payload controls what runs on this machine, and the payload can change after the skill was reviewed.
- **Action:** Remove the fetch-and-execute step, pin the payload to a reviewed file inside the skill, or install the tool separately so the code can be read before it runs.
- **Tested:** Yes, against `fixtures/risky-skill`.

### Agent skill that reads credentials and sends data off the machine

- **Finding:** `A skill reads credentials and sends data off this machine`
- **Trigger:** A credential or environment path (`~/.ssh/id_*`, `~/.aws/credentials`, `.npmrc`, `.netrc`, `~/.claude.json`, `.env`, and similar) appears within 400 characters of an outbound transfer such as `curl -X POST`, `requests.post(`, `scp`, or a netcat pipe.
- **Why it matters:** This is the shape of a credential-stealing skill. The proximity requirement is what separates it from a skill that reads a config and, elsewhere, calls an API.
- **Action:** Confirm what the skill sends and where, remove or scope the outbound call, and rotate anything it could already have read.
- **Tested:** Yes, against `fixtures/risky-skill`.

### npm package with a critical vulnerability

- **Finding:** `<package> has reported npm audit vulnerabilities`
- **Trigger:** `npm audit` reports the package as `critical`.
- **Why it matters:** A known critical vulnerability exists in the scanned dependency graph.
- **Action:** Apply the available fix promptly. If no automatic fix exists, patch, pin, replace, or remove the dependency after reviewing whether it is direct or transitive.
- **Tested:** Yes. The release E2E test used a temporary direct dependency with a current critical npm advisory.

### Hook that auto-approves every tool call

- **Finding:** `A hook auto-approves every tool call`
- **Trigger:** A `PreToolUse` or `PermissionRequest` hook command emits `permissionDecision: "allow"` with no `if`, `case`, `[[ ]]`, `grep`, or `jq` condition around it.
- **Why it matters:** The approval prompt still appears to exist, but nothing is ever stopped. This is the quietest way to turn a guarded agent into an unguarded one.
- **Action:** Remove the hook, or make it decide per call and return `deny` or `ask` for anything it does not recognise.
- **Tested:** Yes, against `fixtures/risky-agent-settings`.

### Hook that fetches remote code and runs it

- **Finding:** `A hook fetches remote code and runs it`
- **Trigger:** A hook command pipes `curl`/`wget` output into a shell or interpreter, or decodes base64 into a shell.
- **Why it matters:** Hooks run on every session or tool call without a prompt; whoever controls the URL controls the machine.
- **Action:** Replace the fetch with a reviewed local script, or remove the hook.
- **Tested:** Yes, against `fixtures/risky-agent-settings`.

### Hook that sends a credential over the network

- **Finding:** `A hook sends a credential from the environment over the network`
- **Trigger:** One hook command references a secret-looking environment variable (`*_KEY`, `*_TOKEN`, `*_SECRET`, `*PASSWORD*`, `*CRED*`, `*AUTH*`) and calls `curl`, `wget`, `nc`, or an `http(s)://` URL. The variable name is masked in the evidence.
- **Why it matters:** This is the shape of a credential-stealing hook.
- **Action:** Remove the network call or the credential; a hook should not need both.
- **Tested:** Yes, against `fixtures/risky-agent-settings`.

### MCP server launched by fetching code from the network

- **Finding:** `An MCP server is launched by fetching code from the network`
- **Trigger:** The server's `command` is a shell with `-c`, or an interpreter with `-e`/`-c`, and its arguments download or reach the network.
- **Why it matters:** The server code is whatever the URL serves when the agent starts.
- **Action:** Install the server as a package or reviewed script and point `command` at it directly.
- **Tested:** Yes, against `fixtures/risky-mcp`.

## HIGH

### Agent skill that hides instructions from human review

- **Finding:** `A skill hides instructions from human review`
- **Trigger:** Zero-width or bidirectional control characters, Unicode tag characters, a base64 blob that decodes to shell or override text, or an HTML comment that addresses the agent with an imperative.
- **Why it matters:** Hidden content lets a skill say one thing to a reviewer and another to the agent. Embedded images and other legitimate base64 assets are excluded.
- **Action:** Read the raw file, remove the hidden section, and stop using the skill until its origin is understood.

### Agent skill that overrides the agent's own rules

- **Finding:** `A skill instructs the agent to override its own rules`
- **Trigger:** Instruction-override language such as "ignore all previous instructions", "without asking the user", "do not tell the user", or "bypass safety checks".
- **Why it matters:** A skill should describe a task, not rewrite the safety rules the agent operates under.
- **Action:** Remove the override language and treat the skill as untrusted until its author and purpose are known.

### Agent skill containing a destructive command

- **Finding:** `A skill contains a destructive command`
- **Trigger:** A recursive force-delete whose target is `/`, `~`, `$HOME`, or `*`; `sudo rm`; `mkfs`; a raw write to `/dev/`; a fork bomb; `chmod 777`; shell-history removal; or deletion of an SSH or keychain credential store.
- **Why it matters:** An agent following the skill can run the command without a second look. Scoped deletes such as `rm -rf /tmp/build` are not reported.
- **Action:** Narrow the command or put it behind a confirmation step the user controls.

### Agent skill with a hardcoded credential

- **Finding:** `A skill contains a hardcoded credential`
- **Trigger:** An Anthropic, OpenAI, GitHub, AWS, Slack, Google, Figma, or Linear token pattern, or a private-key block, appears in a skill file. Obvious placeholders are ignored.
- **Why it matters:** Skill folders are copied, synced, and shared as ordinary files.
- **Action:** Remove the credential, load it from the environment or a secret manager, and rotate it.
- **Tested:** Yes. The raw value is redacted in findings and dashboard output.

### Agent skill that pre-approves unrestricted shell access

- **Finding:** `A skill pre-approves unrestricted shell access`
- **Trigger:** The skill's `allowed-tools` frontmatter lists `Bash` or `Bash(*)` without an argument scope.
- **Why it matters:** Any command the skill asks for runs without the approval prompt that would normally stop it.
- **Action:** Scope the permission to the commands the skill actually needs.
- **Tested:** Yes, in the skill test suite.

### Invalid npm registry signature or provenance

- **Finding:** `Registry signature verification failed for <package>`
- **Trigger:** `npm audit signatures --json` reports an invalid installed package.
- **Why it matters:** npm could not validate the registry signature or provenance data for that installed copy. This is a supply-chain integrity signal, not a generic vulnerability score.
- **Action:** Stop relying on that copy, inspect its registry and lockfile source, then reinstall from a trusted registry after validating the release.

### Plaintext secret in an environment or shell file

- **Finding:** `<secret type> appears to be stored in plaintext`
- **Trigger:** A key-like field contains a recognized token pattern in a path containing `.env`, `.zshrc`, or `.bashrc`.
- **Recognized types:** Anthropic, OpenAI, xAI, AgentShield, GitHub, GitLab, Figma, Linear, Slack, AWS, Google, Stripe, npm, Hugging Face, DigitalOcean, SendGrid, Databricks, Sentry, Shopify, and Twilio tokens; JSON Web Tokens; database connection strings with a password; bearer tokens; and generic token-like values. Known prefixes are detected under any key; bearer and generic values only under a credential-looking key. Placeholders (`<your key>`, `sk-...`, `xxxx`, `REPLACE_ME`) and `${VAR}` references are never reported.
- **Why it matters:** Environment and shell files are commonly copied, synced, committed, logged, or exposed to local tools.
- **Action:** Move the credential to a secret manager or runtime injection, remove it from the file, and rotate it if it may have been shared.
- **Tested:** Yes. Raw values are redacted in findings and dashboard output.

### Service configured to listen on every interface

- **Finding:** `Service is configured to listen on every network interface`
- **Trigger:** A host, bind, listen, address, or interface setting in a scanned config is `0.0.0.0`, `::`, `[::]`, or `*`, with or without a port. Configs are parsed structurally (JSON, TOML, env, shell profiles), so a value quoted in conversation history or prose does not count.
- **Why it matters:** The service accepts connections from other devices on the network instead of only from this machine.
- **Action:** Bind to `127.0.0.1` unless remote access is intentional, authenticated, and firewalled.
- **Tested:** Yes, against `fixtures/risky-agent-home`.

### Service surface configured without authentication

- **Finding:** `A service surface is configured without authentication`
- **Trigger:** An `auth`, `authentication`, `auth_mode`, `auth_type`, or `require_auth` setting is `none`, `false`, `off`, `no`, `disabled`, or `0`; or a `no_auth`, `disable_auth`, `auth_disabled`, `skip_auth`, or `allow_anonymous` setting is truthy.
- **Why it matters:** A reachable administrative, agent, browser, or development surface may be usable without proving identity.
- **Action:** Enable authentication before exposing the service to anything beyond a tightly controlled local-only environment.
- **Tested:** Yes, against `fixtures/risky-agent-home`.

### Agent configured to skip execution safeguards

- **Finding:** `An agent is configured to skip execution safeguards`
- **Trigger:** A permission, sandbox, approval, or full-access setting (`yolo`, `sandbox_mode`, `permission_mode`, `approval_policy`, `shell_full_access`, `full_access`, `dangerously_skip_permissions`, and their camel-case forms) is truthy or set to `danger-full-access`, `bypassPermissions`, or `never`; or any value is the literal flag `--dangerously-skip-permissions` or `--yolo`.
- **Why it matters:** The agent runs commands without the normal approval or sandbox boundary.
- **Action:** Keep the default permission mode for daily use and reserve full-access modes for disposable, isolated environments.
- **Tested:** Yes, against `fixtures/risky-agent-home`.

### npm package with a high vulnerability

- **Finding:** `<package> has reported npm audit vulnerabilities`
- **Trigger:** `npm audit` reports the package as `high`.
- **Why it matters:** A known high-severity vulnerability exists in the scanned dependency graph.
- **Action:** Apply the available fix soon or manually review the dependency path if no fix is available.

## MEDIUM

### Agent skill that pre-approves a high-impact command

- **Finding:** `A skill pre-approves a high-impact command`
- **Trigger:** `allowed-tools` scopes Bash to a command that can delete files, change permissions, or reach the network: `sudo`, `rm`, `chmod`, `chown`, `dd`, `eval`, `curl`, `wget`, `nc`, `osascript`, `launchctl`, `systemctl`, `security`, `defaults`, or a kill command.
- **Why it matters:** The scope is narrower than unrestricted shell, but these specific commands still run without confirmation.
- **Action:** Drop the pre-approval or narrow the pattern to the exact arguments needed.
- **Tested:** Yes, in the skill test suite.

### Agent skill that reads credential files

- **Finding:** `A skill reads credential files`
- **Trigger:** A credential path appears on a line that also contains a read or copy command, without an accompanying outbound transfer.
- **Why it matters:** Anything a skill reads enters the agent's context and influences what it does next.
- **Action:** Confirm the access is necessary and narrow it to the single value the skill needs.

### Agent skill writable by other accounts

- **Finding:** `A skill can be rewritten by any account on this machine` (MEDIUM) or `A skill can be rewritten by other accounts in its group` (LOW)
- **Trigger:** A file or directory in the skill is world-writable (MEDIUM), or only group-writable (LOW, low confidence: on a single-user machine the group is usually the owner's own, and package managers leave `664` files behind routinely).
- **Why it matters:** Anything that can write to the skill changes what the agent does next, after any review.
- **Action:** Run `chmod -R go-w` on the skill directory and check whether the contents were already modified.

### Agent skill linking outside its own folder

- **Finding:** `A skill links to files outside its own folder`
- **Trigger:** A symlink inside the skill directory resolves outside it.
- **Why it matters:** Reviewing the skill folder does not show the content the agent actually loads.
- **Action:** Replace the symlink with a reviewed copy, or confirm the target is yours and not writable by anything else.

### Missing npm registry signature or provenance

- **Finding:** `Registry signature is missing for <package>`
- **Trigger:** npm reports a missing signature where the configured registry supports signature verification.
- **Why it matters:** Missing signing data is not proof of compromise, but it removes an integrity signal and deserves source review.
- **Action:** Verify the package source and version, prefer a signed release when available, and keep the lockfile integrity record.

### Direct Git or archive dependency

- **Finding:** `<package> is installed from a Git source` or `remote archive`
- **Trigger:** A direct dependency uses a Git, GitHub, GitLab, Bitbucket, SSH, or HTTP(S) specifier instead of a normal registry version.
- **Why it matters:** Source and release controls differ from a pinned npm registry artifact.
- **Action:** Pin to an immutable commit or package version, review the source and release process, and preserve a lockfile integrity record.

### Direct registry dependency missing an integrity hash

- **Finding:** `<package> is missing a lockfile integrity hash`
- **Trigger:** A direct npm-registry dependency lacks `integrity` in `package-lock.json`.
- **Why it matters:** The lockfile cannot verify the downloaded artifact against the expected content hash.
- **Action:** Regenerate the lockfile with current npm, inspect the diff, and commit the recovered integrity hash.

### Invalid dependency tree

- **Finding:** `Installed dependency does not satisfy its declared version`
- **Trigger:** `npm ls --all --json` reports an invalid package.
- **Why it matters:** The installed tree may not match the declared and locked dependency state.
- **Action:** Review unexpected changes, then use `npm ci` or `npm install` deliberately to restore a known dependency tree.

### Sandbox enabled with an escape hatch

- **Finding:** `The sandbox is enabled with an escape hatch`
- **Trigger:** `sandbox.enabled` is on but `excludedCommands` contains `*` or a shell, interpreter, `curl`, or `wget`, or `network.allowedDomains` contains `*`.
- **Action:** Exclude only the specific command that needs it and list the exact domains the project talks to.

### Hook that makes network calls or reads a credential path

- **Finding:** `A hook makes network calls` or `A hook reads a credential path`
- **Trigger:** A hook command calls `curl`, `wget`, `nc`, or a non-loopback URL without the credential-plus-network shape above; or it references `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `.netrc`, `.npmrc`, `.env`, an SSH key file, or `/etc/passwd`.
- **Action:** Confirm what the hook sends and where; narrow it to the single value it needs.

### MCP server environment that enables interception

- **Finding:** `An MCP server environment enables traffic interception`
- **Trigger:** The server `env` sets `HTTP(S)_PROXY`, `ALL_PROXY`, `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, or `NODE_OPTIONS`.
- **Action:** Remove these unless you own the proxy and need it for this server.
- **Tested:** Yes, against `fixtures/risky-mcp`.

### Recognized plaintext secret in a config file

- **Finding:** `<secret type> appears to be stored in plaintext`
- **Trigger:** A high-confidence OpenAI, GitHub, Figma, or Linear token appears under a key-like field in a scanned JSON, TOML, profile, or other supported non-`.env` config.
- **Why it matters:** The credential is stored in readable local configuration and may be exposed to backups, sync, or local tooling.
- **Action:** Move it to a dedicated secret store or runtime injection and rotate it if the file has been shared.

### Browser automation alongside a remote MCP server

- **Finding:** `Browser automation runs alongside a remote MCP server`
- **Trigger:** The same config names a browser-driving tool (`playwright`, `puppeteer`, `browserbase`, `browser-use`, `chrome-devtools`, `browser_automation`, `browsermcp`) and also configures a remote MCP endpoint.
- **Why it matters:** Content fetched by the browser can influence what the agent does next, and a remote tool server can read what the agent sends it. Together they widen the trust boundary in both directions.
- **Action:** Keep browser automation scoped to sites you trust, and avoid combining it with remote MCP servers you do not control.
- **Tested:** Yes.

### Agent that pre-approves broad or dangerous commands

- **Finding:** `An agent pre-approves broad or dangerous commands`
- **Trigger:** `permissions.allow` in a Claude Code settings file grants `Bash`, `Bash(*)`, a shell interpreter, `sudo`/`su`/`doas`, `eval`/`exec`/`source`, or an interpreter with inline code (`node -e`, `python -c`). The colon-prefix spelling (`Bash(sudo:*)`) and a leading binary path are normalised first. Unrestricted `Write(*)`/`Edit(*)`, destructive file and git commands, unrestricted network tools, and container execution are MEDIUM; process termination is LOW. One finding per file lists every matching entry.
- **Why it matters:** Each listed entry runs without a confirmation prompt.
- **Action:** Replace wildcard and interpreter grants with the exact commands the project needs, and move `sudo`, `rm`, and `curl` to the deny list.
- **Tested:** Yes, against `fixtures/risky-agent-settings`.

### Agent granted a sensitive directory

- **Finding:** `An agent is granted a sensitive directory`
- **Trigger:** `permissions.additionalDirectories` includes `/`, a home directory, `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.config`, `/etc`, `/usr`, or `/var`.
- **Action:** Grant only the project directories the agent needs.

### Agent setting that overrides a security-sensitive variable

- **Finding:** `An agent setting overrides a security-sensitive variable`
- **Trigger:** The settings `env` block sets `ANTHROPIC_BASE_URL` (to a non-loopback host), `NODE_TLS_REJECT_UNAUTHORIZED=0`, `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, or `ENV` (HIGH); `ANTHROPIC_AUTH_TOKEN`, `PYTHONSTARTUP`, `NODE_OPTIONS`, a non-loopback `HTTP(S)_PROXY`/`ALL_PROXY`, `PATH`, or `SHELL` (MEDIUM). Token values are redacted.
- **Why it matters:** Each of these can reroute or intercept every model request, or run code in every process the agent starts, from a file that is easy to overlook.
- **Action:** Remove the variable unless you put it there deliberately and know where the traffic goes.
- **Tested:** Yes, against `fixtures/risky-agent-settings`.

### Helper command that fetches or evaluates code at session start

- **Finding:** `A helper command fetches or evaluates code every time the agent starts` (HIGH) or `A helper command runs every time the agent starts` (MEDIUM)
- **Trigger:** `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `gcpAuthRefresh`, `otelHeadersHelper`, `statusLine.command`, or `processWrapper` is set. HIGH when the command reaches a non-loopback URL, pipes a download into a shell, or uses `sh -c`, `node -e`, `python -c`, or `eval`.
- **Why it matters:** These run automatically, with your credentials, before you type a word.
- **Action:** Point the helper at a reviewed local script with no network fetch, or remove it.

### Hook that posts session data over plain HTTP, or ships conversation data off the machine

- **Finding:** `A hook posts session data over plain HTTP` or `A hook ships conversation data off this machine`
- **Trigger:** An `http`-type hook whose URL is `http://` on a non-loopback host, or an `https://` hook on an event that carries transcript or tool output (`PostToolUse`, `Stop`, `UserPromptSubmit`, `SessionEnd`, `MessageDisplay`, `SubagentStop`).
- **Action:** Use an https endpoint you control and want to receive full session content, or remove the hook.
- **Tested:** Yes, against `fixtures/risky-agent-settings`.

### Hook or MCP server that talks to a data-collection endpoint

- **Finding:** `A hook talks to a data-collection endpoint` or `An MCP server points at a data-collection endpoint`
- **Trigger:** A hook command, or an MCP server's URL, arguments, or environment, references a tunnelling or request-capture host: `ngrok`, `webhook.site`, `requestbin`, `requestcatcher`, `pipedream.net`, `beeceptor`, `hookbin`, `burpcollaborator`, `interact.sh`, `oast.*`, or a path such as `/exfil`, `/steal`, or `collect?data=`.
- **Action:** Remove it unless you set that endpoint up yourself, and take it out when the experiment ends.

### MCP server reached over an unencrypted connection

- **Finding:** `An MCP server is reached over an unencrypted connection`
- **Trigger:** An MCP server `url` uses `http://` or `ws://` to a non-loopback host.
- **Action:** Switch to `https://` or `wss://`, or remove the server.
- **Tested:** Yes, against `fixtures/risky-mcp`.

### MCP server with a credential in its URL or headers

- **Finding:** `An MCP server URL carries a credential` or `An MCP server header contains a literal credential`
- **Trigger:** The URL has userinfo or a `token`, `api_key`, `key`, `auth`, `secret`, or `password` query parameter with a non-placeholder value; or an `Authorization`, `X-API-Key`, cookie, or similarly named header holds a literal value that matches a credential shape rather than a `${VAR}` reference. Values are redacted.
- **Why it matters:** Config files are copied, synced, and pasted into issues; URLs additionally land in logs and shell history.
- **Action:** Reference the credential from the environment and rotate the value that was in the file.
- **Tested:** Yes, against `fixtures/risky-mcp`.

### MCP server launched through an inline shell command

- **Finding:** `An MCP server is launched through an inline shell command`
- **Trigger:** The server `command` is a shell with `-c`, or `node -e`, `python -c`, `ruby -e`, and the arguments do not reach the network (that case is CRITICAL, above).
- **Action:** Install the server and point `command` at it directly.

### MCP server with every tool pre-approved

- **Finding:** `Every tool from an MCP server is pre-approved`
- **Trigger:** `autoApprove`, `alwaysAllow`, or their snake-case forms is `true` or contains `*`. A named list is LOW.
- **Why it matters:** Anything the server exposes runs without a prompt, including tools it adds after you configured it.
- **Action:** List the specific tools you want to run unattended, or drop auto-approval.
- **Tested:** Yes, against `fixtures/risky-mcp`.

### Remote MCP server or tool endpoint

- **Finding:** `A remote MCP server is configured` or `An agent tool points at a remote endpoint`
- **Trigger:** A URL setting under an `mcpServers`, `mcp_servers`, or `mcp` key (the first title), or any `url`, `endpoint`, `remote_url`, `server_url`, or `base_url` setting (the second), points at an `http(s)://` host other than `localhost`, `127.0.0.1`, or `::1`.
- **Why it matters:** A remote tool server can read what the agent sends it and can return content the agent will act on, which extends the trust boundary off this machine.
- **Action:** Confirm you control or trust the endpoint, review what the agent is allowed to send it, and remove endpoints you no longer use.
- **Tested:** Yes, against `fixtures/risky-agent-home`.

### Development service reachable beyond localhost

- **Finding:** `Development service is reachable beyond localhost`
- **Trigger:** A non-loopback TCP listener belongs to a recognized development process or common development port.
- **Recognized processes:** Node, npm, npx, Bun, Deno, Python, Ruby, PHP, Java, Vite, Next, Webpack, OpenClaw, Claude, Codex, and MCP-prefixed processes.
- **Recognized ports:** `3000`, `3001`, `4173`, `4180`, `4200`, `5000`, `5173`, `8000`, `8080`, `8888`, and `9222`.
- **Excluded:** operating-system daemons that listen on every interface by design (`launchd`, `mDNSResponder`, `rapportd`, `sharingd`, `ControlCenter`, `siriactionsd`, `AirPlayXPCHelper`, `identityservicesd`, `remoted`, `bluetoothd`, `cupsd`, `systemd`, `avahi-daemon`, and similar).
- **Why it matters:** Development services often lack production authentication and may expose source, debugging controls, or local data.
- **Action:** Bind to `127.0.0.1` unless network access is intentional, authenticated, and restricted.
- **Tested:** Yes, with a temporary Node listener on `0.0.0.0:8088`.

### npm package with a moderate vulnerability

- **Finding:** `<package> has reported npm audit vulnerabilities`
- **Trigger:** `npm audit` reports the package as `moderate`.
- **Action:** Apply the available fix after checking direct or transitive impact. Manually review packages without a fix.

### Major update available for critical-path global tooling

- **Finding:** `<package> is outdated`
- **Trigger:** A globally installed critical-path package has a newer major version.
- **Critical-path packages:** OpenClaw, npm, Claude, Codex, and `figma-developer-mcp`.
- **Why it matters:** The tool is active in agent workflows, while a major upgrade may also contain breaking changes.
- **Action:** Test the update in isolation before upgrading globally.

## LOW

### Agent skill running an unpinned remote package

- **Finding:** `A skill runs an unpinned remote package`
- **Trigger:** `npx -y`, `bunx`, `uvx`, `pnpm dlx`, `pipx run`, or a `pip install` from a URL or Git source.
- **Why it matters:** What executes is whatever the registry serves that day, not a reviewed version.
- **Action:** Pin the version or install the package as a reviewed dependency.

### MCP server running an unpinned package, or with a named auto-approve list

- **Finding:** `An MCP server runs an unpinned package` or `Some tools from an MCP server are pre-approved`
- **Trigger:** The server is launched with `npx`, `bunx`, `pnpx`, `uvx`, or `pipx` and the package has no `@version`; or `autoApprove`/`alwaysAllow` names specific tools.
- **Action:** Pin the version; keep the approved list to read-only tools and review it when the server updates.

### Lower-confidence plaintext token in config

- **Finding:** `Bearer token appears to be stored in plaintext` or `Generic API token appears to be stored in plaintext`
- **Trigger:** A bearer or generic token-like value appears under a key-like field in a supported non-`.env` config.
- **Why it matters:** The value may be a real credential, but the pattern is less specific and has a higher false-positive risk.
- **Action:** Validate the value, move confirmed secrets to safer storage, and rotate them if shared.

### Generic TCP service reachable beyond localhost

- **Finding:** `TCP service is reachable beyond localhost`
- **Trigger:** A non-loopback TCP listener is not recognized as a development process or common development port.
- **Why it matters:** Another device or network interface may be able to connect to the service.
- **Action:** Bind to `127.0.0.1` unless exposure is intentional, authenticated, and restricted.
- **Tested:** Yes, with a temporary `nc` listener on `*:8090`.

### npm package with a low vulnerability

- **Finding:** `<package> has reported npm audit vulnerabilities`
- **Trigger:** `npm audit` reports the package as `low`.
- **Action:** Apply the fix during routine maintenance or manually review the dependency path.

### Outdated critical-path global tooling

- **Finding:** `<package> is outdated`
- **Trigger:** OpenClaw, npm, Claude, Codex, or `figma-developer-mcp` is outdated without a major-version jump.
- **Why it matters:** These tools sit in active agent workflows and should not drift indefinitely.
- **Action:** Schedule the update deliberately.

### Major update available for other global tooling

- **Finding:** `<package> is outdated`
- **Trigger:** A globally installed package outside the critical-path list has a newer major version.
- **Action:** Review the changelog for breaking changes before updating.

### npx tool usage in project scripts

- **Finding:** `npx-based tool usage detected in project scripts`
- **Trigger:** A discovered `package.json` script executes a package through `npx`. Build output such as `.next` and hidden directories are not treated as projects.
- **Why it matters:** One-off package execution can introduce code that is not represented by a stable installed dependency.
- **Action:** Review the package, pin versions where practical, and pay extra attention when it can access agent workflows or local secrets.

## Skill Scanning Scope

Skill checks read, in this order: directories passed with `--skill-path=`; the skill folders of the project you scan from and of every project registered with a local agent (Claude Code's `~/.claude.json`, Codex's `config.toml` project tables, Cursor and Gemini trusted-folder lists) — `.claude/skills`, `.codex/skills`, `.agents/skills`, `.cursor/skills`, `.gemini/skills`, `.github/skills`, `.opencode/skills`, `.windsurf/skills`, `.kiro/skills`, and a top-level `skills/`; the user's own skills under the same runtime homes (`~/.claude`, `~/.config/claude`, `~/.codex`, `~/.agents`, `~/.openclaw`, `~/.cursor`, `~/.gemini`, `~/.copilot`, `~/.opencode`, `~/.codeium/windsurf`, `~/.windsurf`, `~/.kiro`, `~/.continue`); and finally installed plugin and extension skills (`~/.claude/plugins/cache`, `~/.codex/plugins`, `~/.cursor/plugins`, `~/.gemini/extensions`, `~/.opencode/plugins`). A skill is any directory holding a `SKILL.md` (case-insensitive). Marketplace clones such as `~/.claude/plugins/marketplaces` are not read: they hold every catalogued plugin whether installed or not, and the installed ones are already covered. Discovery stops at 1,500 skills; when that happens the inventory record says so, and because explicit and project roots come first, a `--skill-path=` is never the part that gets cut.

A marketplace often publishes one skill once per agent runtime, so the same file can be found under `.claude/`, `.cursor/`, `.gemini/`, `plugin/`, and more. Findings whose rule, skill name, evidence, and path agree on everything but that runtime segment are reported once, with `metadata.copies` and `metadata.otherPaths` naming the rest. Two separate installs of a similarly named skill are never merged, because the path outside the runtime segment differs.

Text-pattern skill rules deliberately skip matches that read as documentation rather than instruction: a value quoted in prose, or one preceded by wording such as "blocked", "example", "adversarial", or "never run". Security-aware skills quote these exact patterns to warn an agent about them, and reporting those would bury real findings. The tradeoff is that a skill which wraps a real payload in that wording can evade the text rules; the permission, ownership, and symlink checks do not depend on file text.

Further exclusions come from the same tradeoff:

- `Do not show the user the JSON output` is a formatting instruction, so `show`/`display`/`reveal` only count as an override when the object is the thing being hidden (`do not show this to the user`); `do not tell the user` and `without telling the user` still fire on their own. In script sources (`.js`, `.py`, `.sh`, and similar) override language on a comment line is skipped, because a comment describing past behaviour is not an instruction; the same words in a string literal or in a Markdown file still count.
- An HTML comment is only treated as a hidden instruction when it addresses the model — by name, in the vocative (`agent:`), or in the second person (`you must`) — and is not a build banner, licence header, or editor directive (`Generated from …`, `Do not edit`, `SPDX`, `eslint`). A bare mention of the word "agent" is not an address; skills use it constantly.
- An invisible character only counts when it sits inside visible text — between letters, digits, or punctuation. A zero-width joiner between two pictographs is how a compound emoji is spelled, and a stray zero-width space at the start of a line or beside a code fence is paste debris that every editor leaves behind. Bidirectional controls and Unicode tag characters always fire, because they exist to make text read differently from how it is written.
- A pattern quoted in prose — `("ignore previous instructions…")`, with an ellipsis or other punctuation before the closing quote — is an illustration, not an instruction.
- A download only becomes a fetch-and-run installer when the same file is executed within a few hundred characters — handed to an interpreter, marked executable, or run as a command. `curl --output /dev/null` next to `python3 -c` is a health check, and `grep -oP` is not `curl -o P`.
- A `-----BEGIN PRIVATE KEY-----` header only counts as a hardcoded credential when a base64 body follows it. Prose that names the PEM format, and `...` placeholders, do not.

## Findings From the Optional SkillSpector Engine

Every finding in this catalog comes from AgentShield's own rules. `--skillspector`
adds a second engine — [SkillSpector](https://github.com/NVIDIA/SkillSpector),
from NVIDIA — and its findings are titled `SkillSpector: …` and carry
`metadata.engine: "skillspector"` and the rule id the engine reported. Those rules
are documented upstream, not here, and their severities are the engine's own,
mapped onto the scale above: `CRITICAL`, `HIGH`, `MEDIUM`, and `LOW` pass through
unchanged, and a severity this catalog's version does not recognise is reported
as MEDIUM rather than dropped. Findings from the two engines can overlap; neither
suppresses the other.

## Current Scope Limits

This catalog is not a complete security threat model. AgentShield does not currently claim detection of malware, active intrusion, compromised accounts, UDP exposure, firewall-rule errors, every secret format, every package ecosystem, or every unsafe application configuration. See the main README and Terms of Use for the full product boundary.
