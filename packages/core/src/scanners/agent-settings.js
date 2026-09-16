// Structural checks for agent settings files: Claude Code settings.json, the
// hooks block inside it, and mcpServers blocks wherever they appear
// (~/.claude.json, .mcp.json, Cursor and OpenCode configs). These need the
// parsed object rather than flattened key/value pairs, because the meaning of
// an entry depends on where it sits: "allow" under permissions is a grant,
// "command" under a PreToolUse hook is code that runs before every tool call.
//
// Pattern coverage here draws on the MIT-licensed ecc-agentshield rule set by
// Affaan M (https://github.com/affaan-m/agentshield); the checks are
// reimplemented against this scanner's finding model.

import { createFinding } from '../schema.js';
import { shortHash, slug } from '../id.js';
import { isPlaceholderValue, classifyValue } from './secrets.js';

// --- permissions -------------------------------------------------------------

const BYPASS_MODES = new Set(['bypasspermissions', 'dontask', 'auto']);

// Allow-list entries that hand the agent more than a scoped command.
const BROAD_ALLOW = [
  { regex: /^bash$|^bash\(\s*(\*|\*\*)?\s*\)$/i, severity: 'high', reason: 'unrestricted shell' },
  { regex: /^bash\(\s*(sh|bash|zsh|fish|dash|ksh|csh|tcsh|pwsh|powershell|cmd)(\s|:|\)|$)/i, severity: 'high', reason: 'a shell interpreter, which is unrestricted shell by another name' },
  { regex: /^bash\(\s*(sudo|su|doas)(\s|:|\)|$)/i, severity: 'high', reason: 'privilege escalation' },
  { regex: /^bash\(\s*(eval|exec|source)(\s|:|\)|$)/i, severity: 'high', reason: 'arbitrary code through eval or exec' },
  { regex: /^bash\(\s*(python\d?|node|nodejs|ruby|perl|php|deno|bun|tsx|ts-node)\s+(-[ce]|:\*|\*)/i, severity: 'high', reason: 'an interpreter with inline code' },
  { regex: /^(write|edit|multiedit|notebookedit)\(\s*(\*|\*\*|\/\*|~\/\*)?\s*\)$/i, severity: 'medium', reason: 'unrestricted file writes' },
  { regex: /^bash\(\s*(rm|chmod|chown|dd|mkfs)(\s|:|\)|$)/i, severity: 'medium', reason: 'a destructive file command' },
  { regex: /^bash\(\s*(curl|wget|nc|ncat|netcat|socat|ssh|scp|rsync)(\s|:|\)|$)/i, severity: 'medium', reason: 'unrestricted network access' },
  { regex: /^bash\(\s*(docker|podman|nerdctl)\s+(run|exec|:\*|\*)/i, severity: 'medium', reason: 'container execution that can reach the host' },
  { regex: /^bash\(\s*(git\s+push\s+(-f|--force)(?!-with-lease)|git\s+reset\s+--hard|git\s+clean\s+-[a-z]*f)/i, severity: 'medium', reason: 'a destructive git command' },
  { regex: /^bash\(\s*(kill|killall|pkill)(\s|:|\)|$)/i, severity: 'low', reason: 'process termination' },
];

const SENSITIVE_DIRECTORY = /^(\/|~|\$HOME|\$\{HOME\}|\/etc|\/usr|\/var|\/private|\/(Users|home)\/[^/]+|~\/\.(ssh|aws|gnupg|kube|config|claude|codex))\/?$/i;

// --- env overrides -----------------------------------------------------------

const ENV_OVERRIDES = [
  { name: 'ANTHROPIC_BASE_URL', severity: 'high', effect: 'redirects every model request, including the API key, to another endpoint', loopbackOk: true },
  { name: 'ANTHROPIC_AUTH_TOKEN', severity: 'medium', effect: 'replaces the token used for model calls' },
  { name: 'NODE_TLS_REJECT_UNAUTHORIZED', severity: 'high', effect: 'disables TLS certificate checks so traffic can be intercepted', onlyWhen: /^\s*0\s*$/ },
  { name: 'NODE_EXTRA_CA_CERTS', severity: 'high', effect: 'trusts an extra certificate authority, which lets a proxy terminate TLS for API traffic' },
  { name: 'SSL_CERT_FILE', severity: 'high', effect: 'replaces the CA bundle, letting an attacker-issued certificate pass verification' },
  { name: 'LD_PRELOAD', severity: 'high', effect: 'injects a shared library into every process the agent starts' },
  { name: 'DYLD_INSERT_LIBRARIES', severity: 'high', effect: 'injects a dylib into every process the agent starts' },
  { name: 'BASH_ENV', severity: 'high', effect: 'sources a file in every non-interactive bash shell, including hook and tool commands' },
  { name: 'ENV', severity: 'high', effect: 'sources a file in every sh shell, including hook and tool commands' },
  { name: 'PYTHONSTARTUP', severity: 'medium', effect: 'runs a script whenever an interactive python starts' },
  { name: 'NODE_OPTIONS', severity: 'medium', effect: 'can preload modules into every node process with --require or --import' },
  { name: 'HTTPS_PROXY', severity: 'medium', effect: 'routes API traffic through a proxy that can read it', loopbackOk: true },
  { name: 'HTTP_PROXY', severity: 'medium', effect: 'routes HTTP traffic through a proxy that can read it', loopbackOk: true },
  { name: 'ALL_PROXY', severity: 'medium', effect: 'routes all traffic through a proxy that can read it', loopbackOk: true },
  { name: 'PATH', severity: 'medium', effect: 'changes which binaries commands resolve to, so trusted tool names can be shadowed' },
  { name: 'SHELL', severity: 'medium', effect: 'changes the shell used to run every command' },
];

// Settings whose value is a command the agent runs on its own, without a tool call.
const HELPER_COMMANDS = [
  ['apiKeyHelper', ['apiKeyHelper']],
  ['awsAuthRefresh', ['awsAuthRefresh']],
  ['awsCredentialExport', ['awsCredentialExport']],
  ['gcpAuthRefresh', ['gcpAuthRefresh']],
  ['otelHeadersHelper', ['otelHeadersHelper']],
  ['statusLine.command', ['statusLine', 'command']],
  ['processWrapper', ['processWrapper']],
];

// --- command content ---------------------------------------------------------

const PIPE_TO_SHELL = /\b(curl|wget|iwr)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|da|k)?sh\b|\b(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(python3?|node|ruby|perl)\b|\bbase64\s+(-d|-D|--decode)\b[^\n|]{0,120}\|\s*(ba|z)?sh\b/i;
const INLINE_CODE = /\b(ba|z|da)?sh\s+-c\b|\bnode\s+-e\b|\bpython\d?\s+-c\b|\beval\b/i;
const NETWORK_CALL = /\b(curl|wget|nc|ncat|netcat|socat)\b|https?:\/\//i;
const SECRET_ENV_REF = /\$\{?[A-Za-z_]*(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CRED|AUTH)[A-Za-z_]*\}?/i;
const CREDENTIAL_PATH = /~\/\.(ssh|aws|gnupg|kube|netrc|npmrc|claude\.json|codex\/auth\.json)\b|\/\.ssh\/|\/\.aws\/|\bid_(rsa|ed25519)\b|\.env\b|\/etc\/(passwd|shadow|sudoers)/i;
const ALLOW_DECISION = /permissionDecision\\?["']?\s*[:=]\s*\\?["']?allow\b/i;
const CONDITIONAL = /\bif\b|\bcase\b|\[\[|(^|\s)\[\s|&&|\|\||\bgrep\b|\bjq\b|\btest\b|\bmatch\b/;
const EXFIL_HOST = /\b(ngrok\.(io|app|dev)|webhook\.site|requestbin\.(com|net)|requestcatcher\.com|pipedream\.net|beeceptor\.com|hookbin\.com|burpcollaborator\.net|interact\.sh|interactsh\.com|oast\.(fun|live|me|pro|site|online))\b|\/(exfil|steal|leak)\b|collect\?data=/i;

// Hook events whose payload carries the conversation, not just a tool call.
const TRANSCRIPT_EVENTS = new Set(['PostToolUse', 'Stop', 'UserPromptSubmit', 'SessionEnd', 'MessageDisplay', 'SubagentStop']);

const SHELL_BINARIES = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'pwsh', 'powershell', 'cmd', 'cmd.exe']);
const INTERPRETER_EVAL = [
  { names: new Set(['node', 'nodejs', 'bun', 'deno']), flag: /^(-e|--eval|-p|--print|eval)$/ },
  { names: new Set(['python', 'python3', 'python2']), flag: /^-c$/ },
  { names: new Set(['ruby', 'perl', 'php']), flag: /^-[er]$/ },
];
const LAUNCHERS = new Set(['npx', 'npx.cmd', 'bunx', 'pnpx', 'uvx', 'pipx']);
const PROXY_ENV = /^(https?_proxy|all_proxy|node_extra_ca_certs|ssl_cert_file|requests_ca_bundle|curl_ca_bundle|node_tls_reject_unauthorized|dyld_insert_libraries|ld_preload|node_options)$/i;
const CREDENTIAL_HEADER = /authorization|api[-_]?key|token|secret|cookie|credential|password/i;
const URL_CREDENTIAL_PARAM = /(^|[&?;])(token|api_key|apikey|api-key|access_token|key|auth|auth_token|secret|password|pwd)=([^&#;]+)/i;

// --- helpers -----------------------------------------------------------------

function isRecord(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function readPath(record, path) {
  let current = record;
  for (const segment of path) {
    if (!isRecord(current)) return undefined;
    current = current[segment];
  }
  return current;
}

function hostOf(url) {
  try {
    return new URL(String(url)).hostname.replace(/^\[|\]$/g, '').toLowerCase();
  } catch {
    return null;
  }
}

function isLoopback(url) {
  const host = hostOf(url);
  return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '0.0.0.0';
}

function isRemoteUrl(value) {
  return /^(https?|wss?):\/\//i.test(String(value)) && !isLoopback(value);
}

function normalizeAllowEntry(entry) {
  // Bash(sudo:*) is the colon-prefix spelling of Bash(sudo *); a leading path
  // does not change what runs.
  return String(entry).trim().replace(/^Bash\(\s*[^\s():]*\/([^\s():]+)/i, 'Bash($1').replace(/:\*\)$/, ' *)');
}

function literalCredential(value) {
  const text = String(value ?? '').trim().replace(/^(bearer|basic|token|apikey|api-key)\s+/i, '');
  if (!text || isPlaceholderValue(text) || /\$\{|\{env:|\{file:|^\$[A-Za-z_]/.test(text)) return null;
  const hit = classifyValue('token', text);
  return hit ? hit.redactedValue : null;
}

function hookCommands(hooks) {
  const out = [];
  if (!isRecord(hooks)) return out;
  for (const [event, groups] of Object.entries(hooks)) {
    if (!Array.isArray(groups)) continue;
    for (const group of groups) {
      if (!isRecord(group)) continue;
      const entries = Array.isArray(group.hooks) ? group.hooks : [group];
      for (const entry of entries) {
        if (!isRecord(entry)) continue;
        const command = typeof entry.command === 'string' ? entry.command : typeof entry.hook === 'string' ? entry.hook : null;
        const url = typeof entry.url === 'string' ? entry.url : null;
        const type = entry.type ?? (url ? 'http' : 'command');
        if (command || url) out.push({ event, type, command, url, matcher: group.matcher ?? null, entry });
      }
    }
  }
  return out;
}

// --- rules -------------------------------------------------------------------

export function inspectAgentSettings(config, path) {
  const findings = [];
  if (!isRecord(config)) return findings;
  const id = (suffix) => `config-${suffix}-${shortHash(path)}`;
  const add = (input) => {
    if (!findings.some((existing) => existing.id === input.id)) {
      findings.push(createFinding({ category: 'config-risk', path, ...input }));
    }
  };

  const permissions = isRecord(config.permissions) ? config.permissions : null;

  if (permissions && BYPASS_MODES.has(String(permissions.defaultMode ?? '').toLowerCase())) {
    add({
      id: id('permission-mode'), severity: 'high', confidence: 'high',
      title: 'An agent is configured to skip execution safeguards',
      description: `permissions.defaultMode is "${permissions.defaultMode}", so tool calls run without the approval prompt that would normally stop an unexpected command.`,
      recommendation: 'Remove defaultMode or set it to "default" or "acceptEdits", and reserve bypass modes for disposable, isolated environments.',
      metadata: { setting: 'permissions.defaultMode', value: String(permissions.defaultMode) },
    });
  }

  const allow = Array.isArray(permissions?.allow) ? permissions.allow.filter((entry) => typeof entry === 'string') : [];
  const broad = [];
  for (const entry of allow) {
    const normalized = normalizeAllowEntry(entry);
    const match = BROAD_ALLOW.find((rule) => rule.regex.test(normalized));
    if (match) broad.push({ entry, severity: match.severity, reason: match.reason });
  }
  if (broad.length) {
    const worst = ['high', 'medium', 'low'].find((level) => broad.some((item) => item.severity === level));
    add({
      id: id('broad-allow'), severity: worst, confidence: 'high',
      title: 'An agent pre-approves broad or dangerous commands',
      description: `permissions.allow grants ${broad.map((item) => `${item.entry} (${item.reason})`).join(', ')}. Each of these runs without a confirmation prompt.`,
      recommendation: 'Replace wildcard and interpreter grants with the exact commands the project needs, for example Bash(npm test) or Bash(git status *), and move sudo, rm, and curl to the deny list.',
      metadata: { setting: 'permissions.allow', entries: broad.map((item) => item.entry) },
    });
  }

  const directories = Array.isArray(permissions?.additionalDirectories)
    ? permissions.additionalDirectories.filter((dir) => typeof dir === 'string' && SENSITIVE_DIRECTORY.test(dir.trim()))
    : [];
  if (directories.length) {
    add({
      id: id('broad-directories'), severity: 'high', confidence: 'high',
      title: 'An agent is granted a sensitive directory',
      description: `permissions.additionalDirectories includes ${directories.join(', ')}, which puts credentials or the whole account inside the agent's working set.`,
      recommendation: 'Grant only the project directories the agent needs; never a home directory, a credential folder, or a system path.',
      metadata: { setting: 'permissions.additionalDirectories', entries: directories },
    });
  }

  const env = isRecord(config.env) ? config.env : {};
  for (const [name, rawValue] of Object.entries(env)) {
    const value = String(rawValue ?? '');
    const rule = ENV_OVERRIDES.find((candidate) => candidate.name === name.toUpperCase());
    if (!rule) continue;
    if (rule.onlyWhen && !rule.onlyWhen.test(value)) continue;
    if (rule.loopbackOk && isLoopback(value)) continue;
    add({
      id: id(`env-${slug(name)}`), severity: rule.severity, confidence: 'high',
      title: 'An agent setting overrides a security-sensitive variable',
      description: `env.${name} is set in ${path}, which ${rule.effect}.`,
      recommendation: `Remove ${name} from the settings env block unless you put it there deliberately and know where the traffic goes.`,
      metadata: { setting: `env.${name}`, value: rule.name.includes('TOKEN') ? '***redacted***' : value.slice(0, 120) },
    });
  }

  for (const [label, keyPath] of HELPER_COMMANDS) {
    const command = readPath(config, keyPath);
    if (typeof command !== 'string' || !command.trim()) continue;
    const remote = PIPE_TO_SHELL.test(command) || (NETWORK_CALL.test(command) && !isLoopback(command.match(/https?:\/\/\S+/)?.[0] ?? '')) || INLINE_CODE.test(command);
    add({
      id: id(`helper-${slug(label)}`), severity: remote ? 'high' : 'medium', confidence: remote ? 'high' : 'medium',
      title: remote ? 'A helper command fetches or evaluates code every time the agent starts' : 'A helper command runs every time the agent starts',
      description: `${label} is set to "${command.slice(0, 160)}". It runs automatically, without a tool call or a prompt${remote ? ', and it reaches the network or evaluates inline code' : ''}.`,
      recommendation: 'Point the helper at a reviewed local script with no network fetch, or remove it. Anything here runs with your credentials before you type a word.',
      metadata: { setting: label, command: command.slice(0, 200) },
    });
  }

  const sandbox = isRecord(config.sandbox) ? config.sandbox : null;
  if (sandbox && sandbox.enabled !== false) {
    const excluded = Array.isArray(sandbox.excludedCommands) ? sandbox.excludedCommands.filter((entry) => /^(\*|(bash|sh|zsh|python\d*|node|curl|wget)(\s|\*|$))/i.test(String(entry))) : [];
    const domains = Array.isArray(sandbox.network?.allowedDomains) ? sandbox.network.allowedDomains.filter((entry) => /^\*$|^\*\.\*$|^\*\.[a-z]{2,}$/i.test(String(entry))) : [];
    if (excluded.length || domains.length) {
      add({
        id: id('sandbox-escape'), severity: 'medium', confidence: 'high',
        title: 'The sandbox is enabled with an escape hatch',
        description: `sandbox is on, but ${excluded.length ? `excludedCommands lets ${excluded.join(', ')} run outside it` : ''}${excluded.length && domains.length ? ' and ' : ''}${domains.length ? `network.allowedDomains includes ${domains.join(', ')}` : ''}. The exception is as wide as the protection.`,
        recommendation: 'Exclude only the specific command that needs it, and list the exact domains the project talks to.',
        metadata: { setting: 'sandbox', excludedCommands: excluded, allowedDomains: domains },
      });
    }
  }

  findings.push(...inspectHooks(config.hooks, path));
  findings.push(...inspectMcpServers(config.mcpServers, path));

  // ~/.claude.json keeps a per-project mcpServers block too.
  if (isRecord(config.projects)) {
    for (const [project, settings] of Object.entries(config.projects)) {
      if (!isRecord(settings)) continue;
      findings.push(...inspectMcpServers(settings.mcpServers, path, project));
    }
  }

  return findings;
}

export function inspectHooks(hooks, path) {
  const findings = [];
  const seen = new Set();
  const add = (suffix, input) => {
    const id = `config-hook-${suffix}-${shortHash(path)}`;
    if (seen.has(id)) return;
    seen.add(id);
    findings.push(createFinding({ id, category: 'config-risk', path, ...input }));
  };

  for (const hook of hookCommands(hooks)) {
    const text = hook.command ?? '';
    const where = `${hook.event}${hook.matcher ? ` (${hook.matcher})` : ''}`;

    if (hook.type === 'http' || hook.url) {
      const url = hook.url ?? '';
      if (/^http:\/\//i.test(url) && !isLoopback(url)) {
        add('http-plaintext', {
          severity: 'high', confidence: 'high',
          title: 'A hook posts session data over plain HTTP',
          description: `The ${where} hook sends its payload to ${url}, unencrypted. Anyone on the path can read tool inputs, outputs, and file contents.`,
          recommendation: 'Use an https:// endpoint, or remove the hook.',
          metadata: { event: hook.event, url },
        });
      } else if (isRemoteUrl(url) && TRANSCRIPT_EVENTS.has(hook.event)) {
        add('http-transcript', {
          severity: 'high', confidence: 'medium',
          title: 'A hook ships conversation data off this machine',
          description: `The ${where} hook posts to ${url}. This event carries transcript or tool-output content, so everything the agent sees leaves the machine on every call.`,
          recommendation: 'Confirm you control the endpoint and want it to receive full session content; otherwise remove the hook.',
          metadata: { event: hook.event, url },
        });
      }
      continue;
    }

    if (ALLOW_DECISION.test(text) && !CONDITIONAL.test(text)) {
      add('auto-allow', {
        severity: 'critical', confidence: 'high',
        title: 'A hook auto-approves every tool call',
        description: `The ${where} hook emits permissionDecision "allow" unconditionally: ${text.slice(0, 160)}. The approval prompt still appears to exist, but nothing is ever stopped.`,
        recommendation: 'Remove the hook, or make it decide per call and return "deny" or "ask" for anything it does not recognise.',
        metadata: { event: hook.event, command: text.slice(0, 200) },
      });
    }

    if (PIPE_TO_SHELL.test(text)) {
      add('remote-code', {
        severity: 'critical', confidence: 'high',
        title: 'A hook fetches remote code and runs it',
        description: `The ${where} hook runs: ${text.slice(0, 160)}. Whoever controls that URL controls what runs on this machine, on every session.`,
        recommendation: 'Replace the fetch with a reviewed local script, or remove the hook.',
        metadata: { event: hook.event, command: text.slice(0, 200) },
      });
    } else if (SECRET_ENV_REF.test(text) && NETWORK_CALL.test(text)) {
      add('env-exfiltration', {
        severity: 'critical', confidence: 'medium',
        title: 'A hook sends a credential from the environment over the network',
        description: `The ${where} hook references a secret-looking variable and makes a network call in the same command: ${text.replace(SECRET_ENV_REF, '$***').slice(0, 160)}.`,
        recommendation: 'Remove the network call or the credential from the hook; a hook should not need both.',
        metadata: { event: hook.event, command: text.replace(SECRET_ENV_REF, '$***').slice(0, 200) },
      });
    } else if (EXFIL_HOST.test(text)) {
      add('exfil-host', {
        severity: 'high', confidence: 'high',
        title: 'A hook talks to a data-collection endpoint',
        description: `The ${where} hook references ${text.match(EXFIL_HOST)?.[0]}, a tunnelling or request-capture service that is a common exfiltration drop.`,
        recommendation: 'Remove the hook unless you set up that endpoint yourself for debugging, and take it out when you are done.',
        metadata: { event: hook.event, command: text.slice(0, 200) },
      });
    } else if (NETWORK_CALL.test(text) && !isLoopback(text.match(/https?:\/\/\S+/)?.[0] ?? '')) {
      add('network', {
        severity: 'medium', confidence: 'medium',
        title: 'A hook makes network calls',
        description: `The ${where} hook runs ${text.slice(0, 160)}, which reaches the network on every event${TRANSCRIPT_EVENTS.has(hook.event) ? ' and has access to conversation content' : ''}.`,
        recommendation: 'Confirm what the hook sends and where. Hooks run silently, so a network call here is easy to forget about.',
        metadata: { event: hook.event, command: text.slice(0, 200) },
      });
    }

    if (CREDENTIAL_PATH.test(text)) {
      add('credential-access', {
        severity: 'medium', confidence: 'medium',
        title: 'A hook reads a credential path',
        description: `The ${where} hook references ${text.match(CREDENTIAL_PATH)?.[0]}: ${text.slice(0, 160)}.`,
        recommendation: 'Narrow the hook to the single value it needs, and keep private keys and credential stores out of hook commands.',
        metadata: { event: hook.event, command: text.slice(0, 200) },
      });
    }
  }

  return findings;
}

export function inspectMcpServers(servers, path, project = null) {
  const findings = [];
  if (!isRecord(servers)) return findings;
  const add = (name, suffix, input) => {
    const id = `config-mcp-${suffix}-${shortHash(`${path}:${project ?? ''}:${name}`)}`;
    if (findings.some((existing) => existing.id === id)) return;
    findings.push(createFinding({ id, category: 'config-risk', path, ...input, metadata: { server: name, ...(project ? { project } : {}), ...input.metadata } }));
  };

  for (const [name, server] of Object.entries(servers)) {
    if (!isRecord(server)) continue;
    const url = typeof server.url === 'string' ? server.url : typeof server.serverUrl === 'string' ? server.serverUrl : null;
    const command = typeof server.command === 'string' ? server.command.trim() : '';
    const args = Array.isArray(server.args) ? server.args.map(String) : [];
    const env = isRecord(server.env) ? server.env : {};
    const headers = isRecord(server.headers) ? server.headers : {};

    if (url && /^(http|ws):\/\//i.test(url) && !isLoopback(url)) {
      add(name, 'plaintext', {
        severity: 'high', confidence: 'high',
        title: 'An MCP server is reached over an unencrypted connection',
        description: `The MCP server "${name}" uses ${url.split('?')[0]}. Everything the agent sends it, and every header on the request, crosses the network in the clear.`,
        recommendation: 'Switch the URL to https:// or wss://, or remove the server.',
        metadata: { url: url.split('?')[0] },
      });
    }

    if (url) {
      let parsed = null;
      try { parsed = new URL(url); } catch { parsed = null; }
      const param = parsed && URL_CREDENTIAL_PARAM.exec(parsed.search);
      if ((parsed && parsed.password) || (param && !isPlaceholderValue(param[3]))) {
        add(name, 'url-credential', {
          severity: 'high', confidence: 'high',
          title: 'An MCP server URL carries a credential',
          description: `The MCP server "${name}" puts a ${parsed?.password ? 'password' : param[2]} inside its URL. URLs end up in logs, shell history, and error messages.`,
          recommendation: 'Move the credential into a header that references an environment variable, and rotate it because it has been sitting in a config file.',
          metadata: { url: url.replace(/(\/\/[^:@/]+:)[^@/]+@/, '$1***@').replace(URL_CREDENTIAL_PARAM, '$1$2=***') },
        });
      }
    }

    for (const [header, value] of Object.entries(headers)) {
      if (!CREDENTIAL_HEADER.test(header)) continue;
      const redacted = literalCredential(value);
      if (!redacted) continue;
      add(name, `header-${slug(header)}`, {
        severity: 'high', confidence: 'high',
        title: 'An MCP server header contains a literal credential',
        description: `The MCP server "${name}" sends ${header} with a value written directly into the config (${redacted}). This file is copied, synced, and pasted into issues.`,
        recommendation: 'Reference the credential from the environment, for example "Bearer ${MCP_TOKEN}", and rotate the value that was in the file.',
        metadata: { header, redactedValue: redacted },
      });
    }

    const base = command.split(/[\\/]/).pop()?.toLowerCase() ?? '';
    const inlineFlag = INTERPRETER_EVAL.find((rule) => rule.names.has(base));
    const argsText = args.join(' ');
    if ((SHELL_BINARIES.has(base) && args.some((arg) => /^-l?c$/.test(arg))) || (inlineFlag && args.some((arg) => inlineFlag.flag.test(arg)))) {
      const fetches = PIPE_TO_SHELL.test(argsText) || NETWORK_CALL.test(argsText);
      add(name, 'inline-shell', {
        severity: fetches ? 'critical' : 'high', confidence: 'high',
        title: fetches ? 'An MCP server is launched by fetching code from the network' : 'An MCP server is launched through an inline shell command',
        description: `The MCP server "${name}" starts with ${command} ${argsText.slice(0, 140)}. A server entry should name a program, not a script written into the config${fetches ? ', and this one downloads what it runs' : ''}.`,
        recommendation: 'Install the server as a package or a reviewed script and point command at it directly.',
        metadata: { command, args: args.slice(0, 10) },
      });
    }

    const exfil = [...args, ...Object.values(env).map(String), url ?? ''].find((value) => EXFIL_HOST.test(value));
    if (exfil) {
      add(name, 'exfil-host', {
        severity: 'high', confidence: 'high',
        title: 'An MCP server points at a data-collection endpoint',
        description: `The MCP server "${name}" references ${exfil.match(EXFIL_HOST)?.[0]}, a tunnelling or request-capture service that is a common exfiltration drop.`,
        recommendation: 'Remove the server unless you set that endpoint up yourself, and take it out when the experiment ends.',
        metadata: { value: exfil.slice(0, 160) },
      });
    }

    const proxyKeys = Object.entries(env).filter(([key, value]) => PROXY_ENV.test(key) && !(/^node_tls_reject_unauthorized$/i.test(key) && !/^\s*0\s*$/.test(String(value)))).map(([key]) => key);
    if (proxyKeys.length) {
      add(name, 'env-interception', {
        severity: 'medium', confidence: 'high',
        title: 'An MCP server environment enables traffic interception',
        description: `The MCP server "${name}" sets ${proxyKeys.join(', ')} in its env, which routes its traffic through a proxy, replaces the trusted certificate authorities, or disables TLS checks.`,
        recommendation: 'Remove these variables from the server env unless you own the proxy and need it for this server.',
        metadata: { keys: proxyKeys },
      });
    }

    const approve = server.autoApprove ?? server.alwaysAllow ?? server.auto_approve ?? server.always_allow;
    if (approve === true || (Array.isArray(approve) && approve.some((entry) => String(entry) === '*'))) {
      add(name, 'auto-approve', {
        severity: 'high', confidence: 'high',
        title: 'Every tool from an MCP server is pre-approved',
        description: `The MCP server "${name}" has its tools auto-approved wholesale, so anything it exposes runs without a prompt, including tools it adds after you configured it.`,
        recommendation: 'List the specific tools you want to run unattended, or drop auto-approval for this server.',
        metadata: { setting: 'autoApprove' },
      });
    } else if (Array.isArray(approve) && approve.length) {
      add(name, 'auto-approve-list', {
        severity: 'low', confidence: 'high',
        title: 'Some tools from an MCP server are pre-approved',
        description: `The MCP server "${name}" pre-approves ${approve.length} ${approve.length === 1 ? 'tool' : 'tools'}: ${approve.slice(0, 6).map(String).join(', ')}.`,
        recommendation: 'Keep the list to read-only tools, and review it when the server updates.',
        metadata: { tools: approve.slice(0, 20).map(String) },
      });
    }

    if (LAUNCHERS.has(base)) {
      const spec = args.find((arg) => !arg.startsWith('-'));
      if (spec && !/@\d/.test(spec)) {
        add(name, 'unpinned', {
          severity: 'low', confidence: 'medium',
          title: 'An MCP server runs an unpinned package',
          description: `The MCP server "${name}" starts with ${command} ${spec}, so what runs is whatever the registry serves that day.`,
          recommendation: `Pin the version (${spec}@x.y.z) or install the server as a reviewed dependency.`,
          metadata: { command, spec },
        });
      }
    }
  }

  return findings;
}
